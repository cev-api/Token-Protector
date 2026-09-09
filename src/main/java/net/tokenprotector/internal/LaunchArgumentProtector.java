package net.tokenprotector.internal;

import net.tokenprotector.config.Config;
import net.tokenprotector.fake.TokenFaker;
import net.tokenprotector.util.Log;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Replaces the launcher-supplied access token at the earliest game-code entry
 * point, scrubbing both the Main.main argument array and Fabric's retained
 * Arguments. Code that runs before this entrypoint (a launcher javaagent or a
 * modified loader) is outside the boundary.
 */
public final class LaunchArgumentProtector {
    private static final String ACCESS_TOKEN_KEY = "accesstoken";

    private LaunchArgumentProtector() {}

    /**
     * Captures and replaces every access-token value in the game launch array.
     * This method is deliberately called from a high-priority HEAD injection
     * into {@code Main.main}, before Minecraft constructs {@code User}. When
     * the pre-launch boundary already scrubbed the retained arguments this
     * method detects the issued replacement and leaves the array untouched so
     * the stored authentication credential is never overwritten with a fake.
     */
    public static void captureAndSanitize(String[] args) {
        if (!Config.get().blockAccessToken || args == null) {
            return;
        }
        if (containsOnlyIssuedReplacement(args)) {
            // preLaunch already captured the real token and scrubbed the
            // retained Arguments from which this array was built.
            return;
        }

        String replacement = null;
        Map<String, String> replacements = new LinkedHashMap<>();
        boolean[] sanitizedArguments = new boolean[args.length];

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (arg == null) continue;

            int equalsIndex = arg.indexOf('=');
            String key = equalsIndex >= 0 ? arg.substring(0, equalsIndex) : arg;
            if (!isAccessTokenKey(key)) continue;

            if (replacement == null) {
                replacement = Config.get().getReplacement("accessToken", "", TokenFaker.fakeAccessToken());
                TokenAccess.registerReplacement(replacement);
            }

            if (equalsIndex >= 0) {
                String token = arg.substring(equalsIndex + 1);
                if (!token.isBlank()) {
                    TokenAccess.captureFromUserConstructor(token);
                    replacements.put(token, replacement);
                }
                args[i] = key + "=" + replacement;
                sanitizedArguments[i] = true;
            } else if (i + 1 < args.length && args[i + 1] != null && !args[i + 1].startsWith("--")) {
                TokenAccess.captureFromUserConstructor(args[i + 1]);
                if (!args[i + 1].isBlank()) replacements.put(args[i + 1], replacement);
                args[++i] = replacement;
                sanitizedArguments[i] = true;
            }
        }

        if (replacements.isEmpty()) return;

        // Replace copies under unknown keys or inside wrapper payloads as well.
        for (int i = 0; i < args.length; i++) {
            if (!sanitizedArguments[i]) args[i] = replaceCopies(args[i], replacements);
        }
        boolean retainedSafe = poisonFabricArguments(replacements);
        Log.info("[TokenProtector] Sanitized game launch token before User construction; Fabric retained copies sanitized={}. This is startup hardening, not a detected read or OS command-line rewrite.", retainedSafe);
    }

    /**
     * Pre-launch boundary: captures and scrubs the token from the live game
     * provider's retained {@code Arguments} object. The provider later builds
     * {@code Main.main}'s array from this object, so the whole pre-{@code main}
     * surface - including bytecode advice placed at the top of
     * {@code Main.main} by a dynamic agent - observes the replacement.
     *
     * @return true when a launcher token was captured and replaced.
     */
    public static boolean captureAndSanitizeRetainedArguments() {
        if (!Config.get().blockAccessToken) {
            return false;
        }
        try {
            Object arguments = liveGameProviderArguments();
            if (arguments == null) {
                return false;
            }
            boolean captured = captureAndSanitizeRetainedObject(arguments);
            if (captured) {
                Log.info("[TokenProtector] Pre-launch hardening active: launcher access token captured and scrubbed from Fabric retained arguments before Main.main.");
            }
            return captured;
        } catch (ReflectiveOperationException | RuntimeException | LinkageError e) {
            Log.alert("[TokenProtector] Pre-launch retained-argument sanitization failed: {}. The Main.main sanitizer remains as a fallback; retained copies may remain visible to pre-main observers.", e.getClass().getSimpleName());
            return false;
        }
    }

    /**
     * Core pre-launch sanitizer operating directly on a Fabric
     * {@code Arguments} instance (reflected for loader-version tolerance and
     * unit-test injection). Package-private so the regression suite can drive
     * it with a standalone {@code Arguments} object.
     */
    @SuppressWarnings("unchecked")
    static boolean captureAndSanitizeRetainedObject(Object arguments) throws ReflectiveOperationException {
        Field valuesField = arguments.getClass().getDeclaredField("values");
        Field extrasField = arguments.getClass().getDeclaredField("extraArgs");
        valuesField.setAccessible(true);
        extrasField.setAccessible(true);
        Map<String, String> values = (Map<String, String>) valuesField.get(arguments);
        List<String> extras = (List<String>) extrasField.get(arguments);

        String replacement = null;
        Map<String, String> replacements = new LinkedHashMap<>();   // real -> fake
        Map<String, String> directValues = new LinkedHashMap<>();   // parsed key -> fake
        Map<Integer, String> directExtras = new LinkedHashMap<>();  // extra index -> exact rewrite

        // Phase 1: locate every launcher token, capture the real value, and
        // record the exact replacement targets.
        for (Map.Entry<String, String> entry : values.entrySet()) {
            String value = entry.getValue();
            if (value != null && !value.isBlank() && isAccessTokenName(entry.getKey())) {
                if (replacement == null) {
                    replacement = Config.get().getReplacement("accessToken", "", TokenFaker.fakeAccessToken());
                    TokenAccess.registerReplacement(replacement);
                }
                TokenAccess.captureFromUserConstructor(value);
                replacements.putIfAbsent(value, replacement);
                directValues.put(entry.getKey(), replacement);
            }
        }
        for (int i = 0; i < extras.size(); i++) {
            String arg = extras.get(i);
            if (arg == null || !arg.startsWith("--")) continue;
            int equals = arg.indexOf('=');
            String name = equals >= 0 ? arg.substring(0, equals) : arg;
            if (!isAccessTokenName(name)) continue;

            String token = null;
            int mode = 0; // 1 = rewrite this extra, 2 = rewrite the following extra
            if (equals >= 0) {
                token = arg.substring(equals + 1);
                mode = 1;
            } else if (i + 1 < extras.size()) {
                String next = extras.get(i + 1);
                if (next != null && !next.startsWith("--")) {
                    token = next;
                    mode = 2;
                }
            }
            if (token == null || token.isBlank()) continue;

            if (replacement == null) {
                replacement = Config.get().getReplacement("accessToken", "", TokenFaker.fakeAccessToken());
                TokenAccess.registerReplacement(replacement);
            }
            TokenAccess.captureFromUserConstructor(token);
            replacements.putIfAbsent(token, replacement);
            if (mode == 1) {
                directExtras.put(i, name + "=" + replacement);
            } else {
                directExtras.put(i + 1, replacement);
            }
        }

        if (replacements.isEmpty() && directValues.isEmpty() && directExtras.isEmpty()) {
            return false;
        }

        // Phase 2: apply direct replacements, then scrub residual copies inside
        // every remaining key, value, and extra argument.
        Map<String, String> sanitizedValues = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : values.entrySet()) {
            String direct = directValues.get(entry.getKey());
            sanitizedValues.put(replaceCopies(entry.getKey(), replacements),
                    direct != null ? direct : replaceCopies(entry.getValue(), replacements));
        }
        values.clear();
        values.putAll(sanitizedValues);

        List<String> sanitizedExtras = new ArrayList<>(extras.size());
        for (int i = 0; i < extras.size(); i++) {
            String direct = directExtras.get(i);
            sanitizedExtras.add(direct != null ? direct : replaceCopies(extras.get(i), replacements));
        }
        extras.clear();
        extras.addAll(sanitizedExtras);
        return true;
    }

    /** True when the array's only access-token value is one of our own fakes. */
    private static boolean containsOnlyIssuedReplacement(String[] args) {
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (arg == null) continue;
            int equalsIndex = arg.indexOf('=');
            String key = equalsIndex >= 0 ? arg.substring(0, equalsIndex) : arg;
            if (!isAccessTokenKey(key)) continue;

            String value = equalsIndex >= 0 ? arg.substring(equalsIndex + 1)
                    : (i + 1 < args.length && args[i + 1] != null && !args[i + 1].startsWith("--")
                            ? args[i + 1] : null);
            return value != null && !value.isBlank() && TokenAccess.isIssuedReplacement(value);
        }
        return false;
    }

    private static boolean isAccessTokenKey(String argument) {
        return argument.startsWith("--")
                && ACCESS_TOKEN_KEY.equals(argument.substring(2).toLowerCase(Locale.ROOT));
    }

    /** Normalizes a key or option name (with or without "--") for comparison. */
    private static boolean isAccessTokenName(String keyOrName) {
        String name = keyOrName.startsWith("--") ? keyOrName.substring(2) : keyOrName;
        return ACCESS_TOKEN_KEY.equals(name.replace("-", "").replace("_", "").toLowerCase(Locale.ROOT));
    }

    /** Resolves the live game provider's retained Arguments, if any. */
    private static Object liveGameProviderArguments() throws ReflectiveOperationException {
        Class<?> implClass = Class.forName("net.fabricmc.loader.impl.FabricLoaderImpl");
        Object loader = implClass.getField("INSTANCE").get(null);
        Object provider = implClass.getMethod("getGameProvider").invoke(loader);
        if (provider == null) return null;
        return provider.getClass().getMethod("getArguments").invoke(provider);
    }

    /**
     * {@code FabricLoader.getLaunchArguments(false)} reads this backing map,
     * rather than the already-delivered {@code Main.main} array. Reflection
     * keeps this optional across Fabric Loader versions and avoids baking an
     * implementation class into the mod's public linkage.
     */
    private static boolean poisonFabricArguments(Map<String, String> replacements) {
        try {
            Object arguments = liveGameProviderArguments();
            if (arguments == null) return false;
            sanitizeRetainedArguments(arguments, replacements);
            return true;
        } catch (ReflectiveOperationException | RuntimeException | LinkageError e) {
            // The main argument is already safe. Keep startup working if a
            // future loader changes these internal implementation details.
            Log.alert("[TokenProtector] Could not sanitize Fabric's retained launch arguments: {}. Retained copies may remain exposed; no reader identified.", e.getClass().getSimpleName());
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    static void sanitizeRetainedArguments(Object arguments, Map<String, String> replacements)
            throws ReflectiveOperationException {
        // Fabric's parser retains equals-form options in keys or extraArgs.
        // Replacing only values.get("accessToken") leaves those copies intact.
        Field valuesField = arguments.getClass().getDeclaredField("values");
        Field extrasField = arguments.getClass().getDeclaredField("extraArgs");
        valuesField.setAccessible(true);
        extrasField.setAccessible(true);
        Map<String, String> values = (Map<String, String>) valuesField.get(arguments);
        List<String> extras = (List<String>) extrasField.get(arguments);
        Map<String, String> sanitized = new LinkedHashMap<>();
        values.forEach((key, value) -> sanitized.put(replaceCopies(key, replacements),
                isAccessTokenKey("--" + key) && replacements.containsKey(value)
                        ? replacements.get(value) : replaceCopies(value, replacements)));
        values.clear();
        values.putAll(sanitized);
        extras.replaceAll(value -> replaceCopies(value, replacements));
    }

    private static String replaceCopies(String value, Map<String, String> replacements) {
        if (value == null) return null;
        // Avoid rescanning replacements themselves (including custom values).
        StringBuilder result = new StringBuilder();
        for (int offset = 0; offset < value.length();) {
            String match = null;
            for (String candidate : replacements.keySet()) {
                // Short offline placeholders (e.g. "0") are not credentials;
                // replacing their substrings would corrupt unrelated options.
                if (candidate.length() >= 24 && value.startsWith(candidate, offset)
                        && (match == null || candidate.length() > match.length())) {
                    match = candidate;
                }
            }
            if (match == null) result.append(value.charAt(offset++));
            else {
                result.append(replacements.get(match));
                offset += match.length();
            }
        }
        return result.toString();
    }
}
