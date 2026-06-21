package net.tokenprotector.alert;

import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.components.toasts.SystemToast;
import net.minecraft.network.chat.Component;
import net.tokenprotector.config.Config;
import net.tokenprotector.monitor.SessionAccessMonitor;
import net.tokenprotector.util.Log;
import net.tokenprotector.util.MinecraftCompat;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Manages all user-facing alerts when protected field access is blocked.
 * Deferred alerts are queued until the client can show toast and chat output.
 */
public final class AlertManager {

    private static long lastToastTime;
    private static boolean flushed;
    private static final ThreadLocal<Boolean> deliveringAlert =
            ThreadLocal.withInitial(() -> false);

    // Deferred alerts (accumulated before Minecraft client is ready)
    private static final List<PendingAlert> deferred = new ArrayList<>();
    private static final List<PendingOsLeak> deferredOsLeaks = new ArrayList<>();

    private AlertManager() {}

    // ── Public API ────────────────────────────────────────────────

    public static void triggerAlert(SessionAccessMonitor.AccessInfo info, String field) {
        if (isDeliveringAlert()) {
            return;
        }

        // Spin-race alerts always fire regardless of whitelist
        boolean isSpinRace = field != null && field.startsWith("SpinRace");

        // Keep this guard consistent if another call site triggers alerts directly.
        if (!isSpinRace && info.modId() != null && Config.get().isFieldAllowed(info.modId(), configField(field))) {
            return;
        }

        long now = System.currentTimeMillis();
        Minecraft client = Minecraft.getInstance();

        if (client == null || MinecraftCompat.getToastManager(client) == null) {
            // Defer - client not ready yet
            synchronized (deferred) {
                if (deferred.size() < 20) {
                    deferred.add(new PendingAlert(info.modName(), field, now));
                }
            }
            return;
        }

        deliveringAlert.set(true);
        try {
            // Flush any deferred alerts first
            if (!flushed) {
                flushDeferred(client);
            }

            // Toast (rate-limited, config-aware)
            if (Config.get().showToasts && now - lastToastTime >= Config.get().toastCooldownMs) {
                lastToastTime = now;
                showToast(client, info.modName(), field);
            }

            // Chat
            if (Config.get().showChatMessages) {
                sendChatMessage(client, info.modName(), field);
            }

        } finally {
            deliveringAlert.remove();
        }
    }

    public static boolean isDeliveringAlert() {
        return deliveringAlert.get();
    }

    private static final Set<String> ignoredThisSession = java.util.Collections.synchronizedSet(new HashSet<>());

    public static void ignoreThisSession(String modId, String field) {
        if (modId != null && field != null) {
            ignoredThisSession.add(modId + "|" + field);
            Log.info("[TokenProtector] Ignoring {} -> {} for this session", modId, field);
        }
    }

    public static boolean isIgnoredThisSession(String modId, String field) {
        return modId != null && field != null && ignoredThisSession.contains(modId + "|" + field);
    }

    /**
     * Call once after game load to flush any alerts that fired too early.
     */
    public static void flushIfNeeded() {
        if (flushed || isDeliveringAlert()) return;
        Minecraft client = Minecraft.getInstance();
        if (client != null && MinecraftCompat.getToastManager(client) != null) {
            deliveringAlert.set(true);
            try {
                flushDeferred(client);
            } finally {
                deliveringAlert.remove();
            }
        }
    }

    // ── Deferred flushing ─────────────────────────────────────────

    private static void flushDeferred(Minecraft client) {
        flushed = true;
        synchronized (deferred) {
            if (!deferred.isEmpty()) {
                Log.info("[TokenProtector] Flushing {} deferred alert(s)", deferred.size());
                for (PendingAlert a : deferred) {
                    try {
                        if (Config.get().showToasts) {
                            showToast(client, a.modName, a.field);
                        }
                    } catch (Exception ignored) {}
                }
                deferred.clear();
            }
        }
        synchronized (deferredOsLeaks) {
            if (!deferredOsLeaks.isEmpty()) {
                Log.info("[TokenProtector] Flushing {} deferred OS leak alert(s)", deferredOsLeaks.size());
                for (PendingOsLeak a : deferredOsLeaks) {
                    try {
                        deliverOsLeakAlert(client, a.source, a.details);
                    } catch (Exception ignored) {}
                }
                deferredOsLeaks.clear();
            }
        }
    }

    // ── OS leak alert (not a block - we cannot intercept native calls) ──

    public static void triggerOsLeakAlert(String leakSource, String details) {
        Minecraft client = Minecraft.getInstance();
        if (client == null || MinecraftCompat.getToastManager(client) == null) {
            synchronized (deferredOsLeaks) {
                if (deferredOsLeaks.size() < 5) {
                    deferredOsLeaks.add(new PendingOsLeak(leakSource, details));
                }
            }
            return;
        }
        deliverOsLeakAlert(client, leakSource, details);
    }

    private static void deliverOsLeakAlert(Minecraft client, String leakSource, String details) {
        if (MinecraftCompat.getToastManager(client) != null) {
            try {
                SystemToast.add(MinecraftCompat.getToastManager(client),
                        SystemToast.SystemToastId.PERIODIC_NOTIFICATION,
                        Component.literal("§e⚠ OS Token Leak Detected!"),
                        Component.literal("§6" + leakSource + " §7(cannot block OS calls)")
                );
            } catch (Exception ignored) {}
        }
        if (client.player != null) {
            try {
                sendPlayerMessage(
                        Component.literal("§e[TokenProtector] §6⚠ Detected §etoken exposed at OS level (§4"
                                + leakSource + "§e). §7Your launcher is leaking your token.")
                );
            } catch (Exception ignored) {}
        }
    }

    // ── Toast ─────────────────────────────────────────────────────

    private static void showToast(Minecraft client, String modName, String field) {
        if (MinecraftCompat.getToastManager(client) == null) return;
        try {
            SystemToast.add(
                    MinecraftCompat.getToastManager(client),
                    SystemToast.SystemToastId.PERIODIC_NOTIFICATION,
                    Component.literal("§c⚠ Protected Field Access!"),
                    Component.literal("§6" + modName + " §7→ §c" + field)
            );
        } catch (Exception ignored) {}
    }

    // ── Chat ──────────────────────────────────────────────────────

    private static void sendChatMessage(Minecraft client, String modName, String field) {
        if (client.player == null) return;
        try {
            sendPlayerMessage(
                    Component.literal("§c[TokenProtector] §4⚠ Protected §cfield access by §6"
                            + modName + " §7(" + field + ")")
            );
        } catch (Exception ignored) {}
    }

    private static void sendPlayerMessage(Component message) throws ReflectiveOperationException {
        Minecraft client = Minecraft.getInstance();
        if (client == null || client.player == null) return;

        Object player = client.player;

        try {
            player.getClass().getMethod("sendSystemMessage", Component.class).invoke(player, message);
            return;
        } catch (NoSuchMethodException ignored) {
            // 1.21.11 uses a different chat helper on LocalPlayer.
        }

        try {
            player.getClass().getMethod("displayClientMessage", Component.class, boolean.class)
                    .invoke(player, message, false);
        } catch (NoSuchMethodException ignored) {
            player.getClass().getMethod("sendMessage", Component.class, boolean.class)
                    .invoke(player, message, false);
        }
    }

    private static String configField(String field) {
        return switch (field) {
            case "AccessToken" -> "accessToken";
            case "SessionId" -> "sessionId";
            case "ProfileId" -> "profileId";
            case "XUID" -> "xuid";
            case "ClientId" -> "clientId";
            case "Name" -> "name";
            default -> field;
        };
    }

    // ── Record ────────────────────────────────────────────────────

    private record PendingAlert(String modName, String field, long timestamp) {}
    private record PendingOsLeak(String source, String details) {}
}
