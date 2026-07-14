package net.tokenprotector;

import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.fabric.api.client.event.lifecycle.v1.ClientTickEvents;
import net.tokenprotector.alert.AlertManager;
import net.tokenprotector.config.Config;
import net.tokenprotector.monitor.SessionAccessMonitor;
import net.tokenprotector.util.Log;
import net.tokenprotector.util.MinecraftCompat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TokenProtectorMod implements ClientModInitializer {
    public static final String MOD_ID = "tokenprotector";
    public static final Logger LOGGER = LoggerFactory.getLogger(MOD_ID);

    private static volatile boolean osScanDone;

    @Override
    public void onInitializeClient() {
        Log.info("TokenProtector initialized - session-token hardening is active.");

        ClientTickEvents.END_CLIENT_TICK.register(client -> {
            AlertManager.flushIfNeeded();
            if (!osScanDone && MinecraftCompat.getToastManager(client) != null) {
                osScanDone = true;
                scanForOsLeaks();
            }
        });
    }

    private static void scanForOsLeaks() {
        Config cfg = Config.get();
        java.util.concurrent.atomic.AtomicInteger found = new java.util.concurrent.atomic.AtomicInteger();

        // Env vars
        if (cfg.monitorEnvironmentVariables) {
            try {
                for (var entry : System.getenv().entrySet()) {
                    String key = entry.getKey();
                    String upperKey = key.toUpperCase();
                    String val = entry.getValue();

                    if (shouldFlagEnvironmentVariable(upperKey, val)) {
                        boolean isJwt = looksLikeJwt(val);
                        found.incrementAndGet();
                        SessionAccessMonitor.recordOsLeak("env:" + key, isJwt ? "REAL JWT" : "possible token");
                        Log.alert(
                                "[TokenProtector] ⚠ OS LEAK! env '{}' = {} ({})",
                                key,
                                isJwt ? "REAL JWT" : "possible token",
                                diagnosticPreview(val));
                    }
                }
            } catch (Exception e) {
                Log.warn("[TokenProtector] env scan failed: {}", e.getMessage());
            }
        }

        // System properties
        if (cfg.monitorSystemProperties) {
            try {
                for (var entry : System.getProperties().entrySet()) {
                    String key = entry.getKey().toString().toLowerCase();
                    if (key.contains("token") || key.contains("access") || key.contains("session")) {
                        String val = entry.getValue().toString();
                        if (looksLikeTokenValue(val)) {
                            found.incrementAndGet();
                            SessionAccessMonitor.recordOsLeak("sysprop:" + entry.getKey(), "possible token");
                            Log.alert("[TokenProtector] ⚠ OS LEAK! sysprop '{}' appears to contain a token", entry.getKey());
                        }
                    }
                }
            } catch (Exception e) {
                Log.warn("[TokenProtector] sysprop scan failed: {}", e.getMessage());
            }
        }

        // Process args
        if (cfg.monitorProcessArgs) {
            try {
                var cmdLine = ProcessHandle.current().info().commandLine();
                cmdLine.ifPresent(line -> {
                    if (line.toLowerCase().contains("--accesstoken")) {
                        found.incrementAndGet();
                        SessionAccessMonitor.recordOsLeak("process:args", "--accessToken");
                        Log.alert("[TokenProtector] ⚠ OS LEAK! Process args contain --accessToken");
                    }
                });
            } catch (Exception e) {
                Log.warn("[TokenProtector] process arg scan failed: {}", e.getMessage());
            }
        }

        int total = found.get();
        if (total > 0) {
            Log.alert(
                    "[TokenProtector] ⚠ {} OS-level token leak(s) detected! Your launcher exposes your token.",
                    total);
            AlertManager.triggerOsLeakAlert(
                    "Environment / System",
                    total + " token leak(s) found (env var, sysprop, or process args)");
        } else {
            Log.info("[TokenProtector] OS leak scan complete: no token leaks found.");
        }
    }

    private static boolean shouldFlagEnvironmentVariable(String upperKey, String value) {
        if (looksLikePathValue(value) || looksLikeVersionValue(value)) {
            return false;
        }

        if (looksLikeTokenValue(value)) {
            return true;
        }

        return looksLikeSensitiveKey(upperKey) && looksLikeCredentialValue(value);
    }

    private static boolean looksLikeSensitiveKey(String upperKey) {
        return upperKey.contains("TOKEN")
                || upperKey.contains("API_KEY")
                || upperKey.contains("OPENAI")
                || upperKey.contains("SECRET")
                || upperKey.contains("SESSION")
                || upperKey.contains("BEARER")
                || upperKey.contains("JWT")
                || upperKey.contains("OAUTH")
                || upperKey.contains("MINECRAFT")
                || upperKey.contains("MOJANG")
                || upperKey.contains("MSA")
                || upperKey.contains("XBL")
                || upperKey.contains("XSTS")
                || upperKey.contains("AUTH");
    }

    private static boolean looksLikeTokenValue(String value) {
        if (value == null || value.isBlank()) return false;
        String v = value.trim();

        if (looksLikePathValue(v) || looksLikeVersionValue(v)) {
            return false;
        }

        if (looksLikeJwt(v)) return true;
        if (looksLikeOpenAiKey(v)) return true;

        // Long opaque secrets are suspicious, but avoid flagging ordinary prose,
        // paths, and JVM argument lists.
        return v.length() >= 80
                && !v.contains(" ")
                && !v.contains("\\")
                && !v.contains("/")
                && !v.contains("=")
                && v.matches("^[A-Za-z0-9._\\-]+$");
    }

    private static boolean looksLikeJwt(String value) {
        if (value == null) return false;
        String v = value.trim();
        if (!v.startsWith("eyJ")) {
            return false;
        }

        String[] parts = v.split("\\.");
        if (parts.length != 3) {
            return false;
        }

        // JWTs are three substantial base64url-ish segments, not short version numbers like 26.1.2.
        return parts[0].length() >= 8
                && parts[1].length() >= 8
                && parts[2].length() >= 8
                && parts[0].matches("^[A-Za-z0-9_\\-]+$")
                && parts[1].matches("^[A-Za-z0-9_\\-]+$")
                && parts[2].matches("^[A-Za-z0-9_\\-]+$");
    }

    private static boolean looksLikeOpenAiKey(String value) {
        String v = value.trim();
        return v.startsWith("sk-") && v.length() >= 20;
    }

    private static boolean looksLikeCredentialValue(String value) {
        if (value == null || value.isBlank()) return false;
        String v = value.trim();
        return looksLikeJwt(v)
                || looksLikeOpenAiKey(v)
                || (v.length() >= 24
                && !looksLikePathValue(v)
                && !looksLikeVersionValue(v)
                && !v.contains(" ")
                && v.matches("^[A-Za-z0-9._\\-]+$"));
    }

    private static boolean looksLikePathValue(String value) {
        if (value == null) return false;
        String v = value.trim();
        return v.contains("\\")
                || v.contains(":/")
                || v.matches("^[A-Za-z]:\\\\.*")
                || v.contains(";")
                || v.startsWith("-Duser.")
                || v.startsWith("-X")
                || v.startsWith("--");
    }

    private static boolean looksLikeVersionValue(String value) {
        if (value == null) return false;
        String v = value.trim();
        return v.matches("^\\d+(\\.\\d+){1,3}$");
    }

    /**
     * Enough information to distinguish a likely false positive without writing a usable
     * credential into the game log. Never return a contiguous long prefix.
     */
    private static String diagnosticPreview(String value) {
        if (value == null) return "null";
        int length = value.length();
        if (length <= 8) return "<redacted; len=" + length + ">";
        return value.substring(0, 4) + "…" + value.substring(length - 4)
                + " (redacted; len=" + length + ")";
    }
}
