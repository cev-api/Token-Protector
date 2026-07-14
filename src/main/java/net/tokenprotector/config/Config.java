package net.tokenprotector.config;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import net.tokenprotector.TokenProtectorMod;
import net.tokenprotector.fake.TokenFaker;
import net.tokenprotector.util.Log;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * JSON-backed configuration for TokenProtector.
 * Stored at {@code config/tokenprotector.json} in the Minecraft game directory.
 */
public final class Config {
    public static final Set<String> READ_FIELDS = Set.of(
            "accessToken", "sessionId", "profileId", "xuid", "clientId", "name"
    );

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    private static Config instance;

    // ── Blocked fields ────────────────────────────────────────────

    public boolean blockAccessToken = true;
    public boolean blockSessionId = true;
    public boolean blockProfileId = false;
    public boolean blockXuid = true;
    public boolean blockClientId = true;
    public boolean blockName = false;

    // ── Replacement mode per field ───────────────────────────────

    public enum ReplaceMode { FAKE, CUSTOM, NONE }

    public ReplaceMode accessTokenMode = ReplaceMode.FAKE;
    public ReplaceMode sessionIdMode = ReplaceMode.FAKE;
    public ReplaceMode profileIdMode = ReplaceMode.FAKE;
    public ReplaceMode xuidMode = ReplaceMode.FAKE;
    public ReplaceMode clientIdMode = ReplaceMode.FAKE;
    public ReplaceMode nameMode = ReplaceMode.FAKE;

    // ── Custom replacement values ─────────────────────────────────

    public String customAccessToken = "";
    public String customSessionId = "";
    public String customProfileId = "";
    public String customXuid = "";
    public String customClientId = "";
    public String customName = "";

    // ── Allowed mods (whitelist) ──────────────────────────────────

    public Set<String> allowedMods = new HashSet<>();
    public Map<String, Set<String>> allowedModFields = new HashMap<>();

    // ── General ───────────────────────────────────────────────────

    public boolean showToasts = true;
    public boolean showChatMessages = true;
    public boolean showTopRightAlerts = true;
    public int toastCooldownMs = 3_000;
    public int detectionDedupMs = 10_000;

    // ── OS-level monitoring ───────────────────────────────────────

    public boolean monitorEnvironmentVariables = true;
    public boolean monitorSystemProperties = true;
    public boolean monitorProcessArgs = true;
    public boolean monitorClassSweeps = true;

    private Config() {}

    // ── Singleton ─────────────────────────────────────────────────

    public static Config get() {
        if (instance == null) {
            instance = load();
        }
        return instance;
    }

    public static void save() {
        if (instance == null) return;
        Path path = getConfigPath();
        try {
            Files.createDirectories(path.getParent());
            Files.writeString(path, GSON.toJson(instance));
        } catch (IOException e) {
            Log.error("[TokenProtector] Failed to save config: {}", e.getMessage());
        }
    }

    private static Config load() {
        Path path = getConfigPath();
        if (Files.exists(path)) {
            try {
                String json = Files.readString(path);
                Config cfg = GSON.fromJson(json, Config.class);
                if (cfg != null) {
                    if (cfg.allowedMods == null) cfg.allowedMods = new HashSet<>();
                    if (cfg.allowedModFields == null) cfg.allowedModFields = new HashMap<>();
                    if (cfg.detectionDedupMs == 500) cfg.detectionDedupMs = 10_000;
                    cfg.normalizeCredentialModes();
                    return cfg;
                }
            } catch (Exception e) {
                Log.warn("[TokenProtector] Failed to load config, using defaults: {}", e.getMessage());
            }
        }
        Config cfg = new Config();
        cfg.allowedMods = new HashSet<>();
        cfg.allowedModFields = new HashMap<>();
        save(); // write defaults
        return cfg;
    }

    private static Path getConfigPath() {
        return Paths.get("config", "tokenprotector.json");
    }

    // ── Helpers ───────────────────────────────────────────────────

    public boolean isModAllowed(String modId) {
        return allowedMods.contains(modId);
    }

    public boolean isFieldAllowed(String modId, String field) {
        if (modId == null) return false;
        return allowedMods.contains(modId)
                || allowedModFields.getOrDefault(modId, Set.of()).contains(field);
    }

    public void setModAllowed(String modId, boolean allowed) {
        if (allowed) {
            allowedMods.add(modId);
        } else {
            allowedMods.remove(modId);
        }
        allowedModFields.remove(modId);
    }

    public void setFieldAllowed(String modId, String field, boolean allowed) {
        Set<String> fields;
        if (allowedMods.remove(modId)) {
            fields = new HashSet<>(READ_FIELDS);
        } else {
            fields = new HashSet<>(allowedModFields.getOrDefault(modId, Set.of()));
        }

        if (allowed) fields.add(field);
        else fields.remove(field);

        if (fields.containsAll(READ_FIELDS)) {
            allowedMods.add(modId);
            allowedModFields.remove(modId);
        } else if (fields.isEmpty()) {
            allowedModFields.remove(modId);
        } else {
            allowedModFields.put(modId, fields);
        }
    }

    public String permissionSummary(String modId) {
        if (allowedMods.contains(modId)) return "ALL";
        int count = allowedModFields.getOrDefault(modId, Set.of()).size();
        return count == 0 ? "NONE" : count + "/6";
    }

    /**
     * Returns the replacement value for a field based on the current
     * replace mode (FAKE, CUSTOM, or NONE).
     */
    public String getReplacement(String field, String realValue, String fakeValue) {
        ReplaceMode mode;
        String customVal;
        switch (field) {
            case "accessToken" -> { mode = accessTokenMode; customVal = customAccessToken; }
            case "sessionId"   -> { mode = sessionIdMode;   customVal = customSessionId;   }
            case "profileId"   -> { mode = profileIdMode;   customVal = customProfileId;   }
            case "xuid"        -> { mode = xuidMode;        customVal = customXuid;        }
            case "clientId"    -> { mode = clientIdMode;    customVal = customClientId;    }
            case "name"        -> { mode = nameMode;        customVal = customName;        }
            default -> { return fakeValue; }
        }
        return switch (mode) {
            case CUSTOM -> (customVal != null && !customVal.isEmpty()) ? customVal : fakeValue;
            // A disabled replacement is valid for identity metadata, but never for a
            // reusable credential. Whitelisting remains the explicit opt-in path.
            case NONE   -> isCredentialField(field) ? fakeValue : realValue;
            default     -> fakeValue;
        };
    }

    private static boolean isCredentialField(String field) {
        return "accessToken".equals(field) || "sessionId".equals(field);
    }

    private void normalizeCredentialModes() {
        if (accessTokenMode == ReplaceMode.NONE) accessTokenMode = ReplaceMode.FAKE;
        if (sessionIdMode == ReplaceMode.NONE) sessionIdMode = ReplaceMode.FAKE;
    }
}
