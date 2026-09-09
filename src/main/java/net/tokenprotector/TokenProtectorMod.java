package net.tokenprotector;

import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.fabric.api.client.event.lifecycle.v1.ClientTickEvents;
import net.tokenprotector.alert.AlertManager;
import net.tokenprotector.config.Config;
import net.tokenprotector.monitor.SessionAccessMonitor;
import net.tokenprotector.monitor.LaunchSecretScanner;
import net.tokenprotector.monitor.MixinPostureProbe;
import net.tokenprotector.monitor.InstrumentationPostureProbe;
import net.tokenprotector.util.Log;
import net.tokenprotector.util.MinecraftCompat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TokenProtectorMod implements ClientModInitializer {
    public static final String MOD_ID = "tokenprotector";
    public static final Logger LOGGER = LoggerFactory.getLogger(MOD_ID);

    private static volatile boolean osScanDone;
    private static volatile boolean postureScanDone;

    @Override
    public void onInitializeClient() {
        Log.info("TokenProtector initialized - session-token hardening is active.");

        ClientTickEvents.END_CLIENT_TICK.register(client -> {
            AlertManager.flushIfNeeded();
            if (!osScanDone && MinecraftCompat.getToastManager(client) != null) {
                osScanDone = true;
                scanForOsLeaks();
            }
            if (!postureScanDone && MinecraftCompat.getToastManager(client) != null) {
                postureScanDone = true;
                MixinPostureProbe.runStartupScan();
                InstrumentationPostureProbe.runClientScan();
            }
        });
    }

    private static void scanForOsLeaks() {
        Config cfg = Config.get();
        java.util.concurrent.atomic.AtomicInteger found = new java.util.concurrent.atomic.AtomicInteger();
        boolean processScanIncomplete = false;

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
                        SessionAccessMonitor.recordOsLeak("env:" + key, isJwt ? "JWT-shaped value (unverified)" : "possible token");
                        Log.alert(
                                "[TokenProtector] ⚠ OS LEAK! env '{}' = {} ({})",
                                key,
                                isJwt ? "JWT-shaped value (unverified)" : "possible token",
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
                    if (key.contains("token") || key.contains("access") || key.contains("session")
                            || LaunchSecretScanner.containsJwtLikeValue(entry.getValue().toString())) {
                        String val = entry.getValue().toString();
                        if (looksLikeTokenValue(val) || LaunchSecretScanner.containsJwtLikeValue(val)) {
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
                var processInfo = ProcessHandle.current().info();
                var cmdLine = processInfo.commandLine();
                var arguments = processInfo.arguments();
                processScanIncomplete = cmdLine.isEmpty() || arguments.isEmpty();

                // Classify the launch arguments. A lone standard --accessToken
                // is the expected launcher form (OS-level exposure no mod can
                // retract) and is reported as informational, not as an
                // unexpected credential copy.
                LaunchSecretScanner.Scan scan = arguments
                        .map(a -> LaunchSecretScanner.scan(a, "process arguments"))
                        .or(() -> cmdLine.map(LaunchSecretScanner::scan))
                        .orElse(null);

                if (scan != null && scan.unexpectedSecret()) {
                    found.incrementAndGet();
                    SessionAccessMonitor.recordOsLeak("process:args", "unexpected credential copy; reader unknown");
                    Log.alert("[TokenProtector] Process arguments contain an unexpected credential copy ({}); validity unverified; reader unknown.", scan.detail());
                } else if (scan != null && scan.standardAccessTokenArgs() > 0) {
                    Log.info("[TokenProtector] Standard Minecraft launch arguments include --accessToken at the OS process level (normal launcher exposure; validity unverified; reader unknown). This is informational, not an unexpected copy; a Fabric mod cannot retract OS-visible process arguments.");
                }

                if (processScanIncomplete) {
                    Log.alert("[TokenProtector] Process argument scan incomplete: commandLine available={}, arguments available={}. Unavailable data cannot be checked.",
                            cmdLine.isPresent(), arguments.isPresent());
                }
            } catch (Exception e) {
                processScanIncomplete = true;
                Log.alert("[TokenProtector] Process argument scan unavailable: {}", e.getClass().getSimpleName());
            }
        }

        int total = found.get();
        if (total > 0) {
            Log.alert(
                    "[TokenProtector] {} possible credential exposure(s) found in environment, properties, or process arguments; validity and reader unknown.",
                    total);
            AlertManager.triggerOsLeakAlert(
                    "Environment / System",
                    total + " possible credential exposure(s); validity and reader unknown");
        } else {
            Log.info("[TokenProtector] No possible credentials found in inspected sources. Process argument inspection: {}.",
                    !cfg.monitorProcessArgs ? "disabled" : processScanIncomplete ? "incomplete" : "available");
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
