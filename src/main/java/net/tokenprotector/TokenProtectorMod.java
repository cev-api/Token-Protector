package net.tokenprotector;

import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.fabric.api.client.event.lifecycle.v1.ClientTickEvents;
import net.tokenprotector.alert.AlertManager;
import net.tokenprotector.config.Config;
import net.tokenprotector.monitor.SessionAccessMonitor;
import net.tokenprotector.util.Log;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TokenProtectorMod implements ClientModInitializer {
    public static final String MOD_ID = "tokenprotector";
    public static final Logger LOGGER = LoggerFactory.getLogger(MOD_ID);

    private static volatile boolean osScanDone;

    @Override
    public void onInitializeClient() {
        Log.info("TokenProtector initialized - your session tokens are now protected!");

        ClientTickEvents.END_CLIENT_TICK.register(client -> {
            AlertManager.flushIfNeeded();
            if (!osScanDone && client.getToastManager() != null) {
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
                    String key = entry.getKey().toUpperCase();
                    if (looksLikeSensitiveKey(key) || looksLikeTokenValue(entry.getValue())) {
                        String val = entry.getValue();
                        boolean isJwt = looksLikeJwt(val);
                        found.incrementAndGet();
                        SessionAccessMonitor.recordOsLeak("env:" + entry.getKey(), isJwt ? "REAL JWT" : "possible token");
                        Log.alert(
                                "[TokenProtector] ⚠ OS LEAK! env '{}' = {} ({})",
                                entry.getKey(),
                                isJwt ? "REAL JWT" : "possible token",
                                val != null ? val.substring(0, Math.min(30, val.length())) + "..." : "null");
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

    private static boolean looksLikeSensitiveKey(String upperKey) {
        return upperKey.contains("TOKEN")
                || upperKey.contains("ACCESS")
                || upperKey.contains("MINECRAFT")
                || upperKey.contains("MOJANG")
                || upperKey.contains("MSA")
                || upperKey.contains("XBL")
                || upperKey.contains("XSTS")
                || upperKey.contains("BEARER")
                || upperKey.contains("AUTH");
    }

    private static boolean looksLikeTokenValue(String value) {
        if (value == null || value.isBlank()) return false;
        if (looksLikeJwt(value)) return true;
        String v = value.trim();
        return (v.length() >= 80 && (v.contains(".") || v.matches("^[A-Za-z0-9_\\-]+$")));
    }

    private static boolean looksLikeJwt(String value) {
        if (value == null) return false;
        String v = value.trim();
        return v.startsWith("eyJ") || v.matches("^[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-]+$");
    }
}
