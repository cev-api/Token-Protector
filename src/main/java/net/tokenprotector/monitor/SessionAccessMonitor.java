package net.tokenprotector.monitor;

import net.fabricmc.loader.api.FabricLoader;
import net.fabricmc.loader.api.ModContainer;
import net.tokenprotector.TokenProtectorMod;
import net.tokenprotector.config.Config;
import net.tokenprotector.util.Log;

import java.net.URL;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

public final class SessionAccessMonitor {
    private static final int MAX_RECENT_DETECTIONS = 50;
    private static final Deque<Detection> RECENT_DETECTIONS = new ArrayDeque<>();
    private static final Deque<AlertLine> RECENT_ALERTS = new ArrayDeque<>();
    private static final Map<String, Long> LAST_DETECTION_BY_KEY = new HashMap<>();
    private static final Set<String> SEEN_OS_LEAK_KEYS = new HashSet<>();
    private static final Set<String> WARNED_UNKNOWN_CLASSES = new HashSet<>();
    private static int unreadAlerts;

    private SessionAccessMonitor() {}

    public static AccessInfo detectCaller() {
        boolean seenOurCode = false;

        for (StackTraceElement element : Thread.currentThread().getStackTrace()) {
            String className = element.getClassName();

            if (className.startsWith("net.tokenprotector.")) {
                seenOurCode = true;
                continue;
            }
            if (!seenOurCode || isInfrastructure(className)) continue;

            ModIdentity mod = identifyMod(className);
            return new AccessInfo(
                    className,
                    element.getMethodName(),
                    element.getLineNumber(),
                    mod.displayName(),
                    mod.modId(),
                    true
            );
        }

        return new AccessInfo("internal", "internal", -1, "Minecraft/Internal", null, false);
    }

    public static void recordBlockedAccess(AccessInfo info, String field) {
        synchronized (RECENT_DETECTIONS) {
            RECENT_DETECTIONS.addFirst(new Detection(Instant.now(), field, info, null));
            while (RECENT_DETECTIONS.size() > MAX_RECENT_DETECTIONS) {
                RECENT_DETECTIONS.removeLast();
            }
        }

        Log.alert(
                "[TokenProtector] BLOCKED protected field access | Field: {} | Mod: {} | Class: {}.{}() line {}",
                field,
                info.modName(),
                info.className(),
                info.methodName(),
                info.lineNumber()
        );
    }

    public static void recordAlertLine(String line) {
        synchronized (RECENT_ALERTS) {
            RECENT_ALERTS.addFirst(new AlertLine(Instant.now(), line));
            unreadAlerts++;
            while (RECENT_ALERTS.size() > 200) {
                RECENT_ALERTS.removeLast();
            }
        }
    }

    public static void recordOsLeak(String source, String details) {
        String key = (source == null ? "unknown" : source) + "|" + (details == null ? "" : details);
        synchronized (RECENT_DETECTIONS) {
            if (!SEEN_OS_LEAK_KEYS.add(key)) {
                return;
            }
            AccessInfo info = new AccessInfo("os.environment", "scan", -1, "OS Environment", null, true);
            RECENT_DETECTIONS.addFirst(new Detection(Instant.now(), "OSLeak", info, source + " (" + details + ")"));
            while (RECENT_DETECTIONS.size() > MAX_RECENT_DETECTIONS) {
                RECENT_DETECTIONS.removeLast();
            }
        }
    }

    public static boolean shouldSuppressDuplicate(AccessInfo info, String field) {
        long now = System.currentTimeMillis();
        int dedupeMs = Math.max(0, Config.get().detectionDedupMs);
        if (dedupeMs == 0) return false;

        String key = (info.modId() == null ? "unknown" : info.modId()) + "|" + field + "|"
                + info.className() + "|" + info.methodName() + "|" + info.lineNumber();
        synchronized (LAST_DETECTION_BY_KEY) {
            Long last = LAST_DETECTION_BY_KEY.get(key);
            LAST_DETECTION_BY_KEY.put(key, now);
            return last != null && now - last < dedupeMs;
        }
    }

    public static List<Detection> recentDetections() {
        synchronized (RECENT_DETECTIONS) {
            return new ArrayList<>(RECENT_DETECTIONS);
        }
    }

    public static int detectionCount() {
        synchronized (RECENT_ALERTS) {
            return unreadAlerts;
        }
    }

    public static void acknowledgeAlerts() {
        synchronized (RECENT_ALERTS) {
            unreadAlerts = 0;
        }
    }

    public static List<AlertLine> recentAlertLines() {
        synchronized (RECENT_ALERTS) {
            return new ArrayList<>(RECENT_ALERTS);
        }
    }

    public static void clearDetections() {
        synchronized (RECENT_DETECTIONS) {
            RECENT_DETECTIONS.clear();
            SEEN_OS_LEAK_KEYS.clear();
        }
        synchronized (RECENT_ALERTS) {
            RECENT_ALERTS.clear();
            unreadAlerts = 0;
        }
    }

    private static boolean isInfrastructure(String className) {
        return className.startsWith("org.spongepowered.")
                || className.startsWith("java.")
                || className.startsWith("jdk.")
                || className.startsWith("sun.")
                || className.startsWith("net.minecraft.")
                || className.startsWith("com.mojang.")
                || className.startsWith("net.fabricmc.loader.")
                || className.startsWith("net.fabricmc.api.")
                || className.startsWith("net.fabricmc.fabric.")
                || className.startsWith("org.prismlauncher.")
                || className.startsWith("org.lwjgl.")
                || className.startsWith("net.fabricmc.loader.impl.launch.");
    }

    private static ModIdentity identifyMod(String className) {
        // Step 1: match by class resource URL against mod jar paths
        String resourceName = className.replace('.', '/') + ".class";
        URL resource = Thread.currentThread().getContextClassLoader().getResource(resourceName);
        String resourceUrl = resource != null ? resource.toString().replace('\\', '/').toLowerCase(Locale.ROOT) : "";

        if (!resourceUrl.isEmpty()) {
            for (ModContainer container : FabricLoader.getInstance().getAllMods()) {
                try {
                    for (Path origin : container.getOrigin().getPaths()) {
                        Path fileName = origin.getFileName();
                        if (fileName != null && resourceUrl.contains(fileName.toString().toLowerCase(Locale.ROOT))) {
                            return identity(container);
                        }
                    }
                } catch (UnsupportedOperationException ignored) {
                    // Nested origins do not expose filesystem paths.
                }
            }
        }

        // Step 2: fallback - match by class package containing mod id
        String lowerClass = className.toLowerCase(Locale.ROOT);
        // Try exact package-segment match first (e.g. net.wurstclient.xxx matches "wurstclient")
        for (ModContainer container : FabricLoader.getInstance().getAllMods()) {
            String modId = container.getMetadata().getId();
            String normalizedId = modId.toLowerCase(Locale.ROOT).replace("-", "").replace("_", "");
            if (normalizedId.isEmpty()) continue;

            // Check if any package segment matches the mod id exactly
            String[] parts = lowerClass.split("\\.");
            for (String part : parts) {
                if (part.equals(normalizedId)) {
                    return identity(container);
                }
            }
        }

        // Step 3: looser fallback - substring match (with minimum length guard to avoid false positives)
        for (ModContainer container : FabricLoader.getInstance().getAllMods()) {
            String modId = container.getMetadata().getId();
            String normalizedId = modId.toLowerCase(Locale.ROOT).replace("-", "").replace("_", "");
            if (normalizedId.length() < 3) continue;
            String normalizedClass = lowerClass.replace(".", "").replace("-", "").replace("_", "");
            if (normalizedClass.contains(normalizedId)) {
                return identity(container);
            }
        }

        synchronized (WARNED_UNKNOWN_CLASSES) {
            if (WARNED_UNKNOWN_CLASSES.add(className)) {
                Log.info("[TokenProtector] Could not identify mod for class: {}", className);
            }
        }
        return new ModIdentity("Unknown Mod", null);
    }

    private static ModIdentity identity(ModContainer container) {
        String modId = container.getMetadata().getId();
        return new ModIdentity(container.getMetadata().getName() + " (" + modId + ")", modId);
    }

    public record AccessInfo(
            String className,
            String methodName,
            int lineNumber,
            String modName,
            String modId,
            boolean externalCaller
    ) {}

    public record Detection(Instant timestamp, String field, AccessInfo caller, String summary) {}
    public record AlertLine(Instant timestamp, String message) {}

    private record ModIdentity(String displayName, String modId) {}
}
