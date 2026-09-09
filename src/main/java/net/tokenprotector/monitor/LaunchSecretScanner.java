package net.tokenprotector.monitor;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Exposure heuristics only: the single standard launch --accessToken is treated
 * as normal exposure, while duplicated tokens, unknown-key copies, and stray
 * JWT-shaped values are flagged as findings.
 */
public final class LaunchSecretScanner {
    private static final Pattern JWT_RUN = Pattern.compile("eyJ[A-Za-z0-9_.-]{37,}");

    /**
     * Keys that are credentials when present on a process command line.
     * Deliberately excludes non-credential identity/profile launcher values
     * such as {@code xuid}, {@code clientid}, {@code userproperties}, and
     * {@code profileproperties}: a non-empty value under those keys is a
     * normal authenticated launch, not a credential.
     */
    private static final Set<String> CREDENTIAL_KEYS = Set.of(
            "token", "msatoken", "refreshtoken", "idtoken", "usertoken",
            "xbltoken", "xststoken");

    /** The one option the vanilla/third-party launchers use for the session token. */
    private static final String STANDARD_ACCESS_TOKEN_KEY = "accesstoken";

    private LaunchSecretScanner() {}

    public static boolean containsJwtLikeValue(String text) {
        if (text == null) return false;
        var matcher = JWT_RUN.matcher(text);
        while (matcher.find()) {
            if (matcher.group().indexOf('.') >= 0) return true;
        }
        return false;
    }

    /**
     * True when the launch arguments contain an unexpected secret: a duplicated
     * or unknown-key access token, another credential key, or a stray
     * JWT-shaped value.
     */
    public static boolean containsSecret(String[] args) {
        if (args == null) return false;
        return scan(args, "arguments").unexpectedSecret();
    }

    /**
     * True when the raw command line contains an unexpected secret. A lone
     * standard --accessToken value is not a finding.
     */
    public static boolean containsSecret(String rawCommandLine) {
        if (rawCommandLine == null) return false;
        return scan(rawCommandLine).unexpectedSecret();
    }

    /** Classification of a raw command line (no source label). */
    public static Scan scan(String rawCommandLine) {
        if (rawCommandLine == null) return new Scan("command line", 0, false, null);
        return scan(splitQuoted(rawCommandLine), "command line");
    }

    /** Result of scanning one source of launch arguments. */
    public record Scan(String source, int standardAccessTokenArgs, boolean unexpectedSecret, String detail) {}

    public static Scan scan(String[] args, String source) {
        if (args == null) return new Scan(source, 0, false, null);

        int standardAccessTokenArgs = 0;
        String firstFinding = null;

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (arg == null) continue;

            String key = null;
            String value = null;

            int equals = arg.indexOf('=');
            if (arg.startsWith("--") && equals > 2) {
                // Equals form: --key=value
                key = arg.substring(0, equals);
                value = arg.substring(equals + 1);
            } else if (arg.startsWith("--")) {
                // Pair form: --key value  (the value must not look like another option).
                key = arg;
                if (i + 1 < args.length && args[i + 1] != null && !args[i + 1].startsWith("--")) {
                    value = args[++i];
                }
            } else {
                // Bare/positional token: the whole token is the inspected value.
                value = arg;
            }

            boolean hasValue = value != null && !value.isBlank();

            if (key != null && hasValue) {
                String normalized = normalizeKey(key);
                if (STANDARD_ACCESS_TOKEN_KEY.equals(normalized)) {
                    standardAccessTokenArgs++;
                    continue; // the standard launch token; never a finding by itself
                }
                if (CREDENTIAL_KEYS.contains(normalized)) {
                    if (firstFinding == null) {
                        firstFinding = "credential-shaped option '" + key + "' with a value";
                    }
                    continue;
                }
            }

            // Inspect the value (or the bare token) for embedded/unknown secrets.
            String inspected = value != null ? value : arg;
            if (containsJwtLikeValue(inspected)) {
                if (firstFinding == null) {
                    firstFinding = "JWT-shaped value in '" + preview(inspected) + "'";
                }
                continue;
            }
            if (inspected.length() >= 80
                    && !inspected.startsWith("--")
                    && inspected.matches("[A-Za-z0-9_.\\-]+")
                    && inspected.chars().anyMatch(Character::isLetter)
                    && inspected.chars().anyMatch(Character::isDigit)) {
                if (firstFinding == null) {
                    firstFinding = "long opaque value";
                }
            }
        }

        // A single standard token is expected; more than one means a copy exists somewhere.
        if (standardAccessTokenArgs > 1 && firstFinding == null) {
            firstFinding = standardAccessTokenArgs + " copies of the standard access token";
        }

        return new Scan(source, standardAccessTokenArgs, firstFinding != null, firstFinding);
    }

    private static String normalizeKey(String keyWithDashes) {
        if (!keyWithDashes.startsWith("--")) return keyWithDashes.toLowerCase(Locale.ROOT);
        return keyWithDashes.substring(2)
                .replace("-", "")
                .replace("_", "")
                .toLowerCase(Locale.ROOT);
    }

    private static String preview(String text) {
        if (text == null) return "<null>";
        return text.length() <= 32 ? text : text.substring(0, 29) + "...";
    }

    private static String[] splitQuoted(String line) {
        List<String> args = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        char quote = 0;
        boolean started = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if ((c == '"' || c == '\'') && (quote == 0 || quote == c)) {
                quote = quote == 0 ? c : 0;
                started = true;
            } else if (Character.isWhitespace(c) && quote == 0) {
                if (started) args.add(current.toString());
                current.setLength(0);
                started = false;
            } else {
                current.append(c);
                started = true;
            }
        }
        if (started) args.add(current.toString());
        return args.toArray(String[]::new);
    }
}
