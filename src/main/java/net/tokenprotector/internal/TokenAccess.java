package net.tokenprotector.internal;

import net.tokenprotector.monitor.SessionAccessMonitor;
import org.spongepowered.asm.mixin.transformer.meta.MixinMerged;

import java.lang.reflect.Method;
import java.security.SecureRandom;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Internal holder for the token used by TokenProtector's authentication
 * redirects. Public only because transformed callbacks live in Minecraft and
 * authlib classes; access is call-context gated and the value is stored masked,
 * never as plaintext.
 */
public final class TokenAccess {
    /** Our own package prefix; frames here are trusted as internal code. */
    private static final String OWN_PREFIX = "net.tokenprotector.";

    /** Game/authlib/loader prefixes where mixin places our transformed callbacks. */
    private static final Set<String> PLATFORM_PREFIXES = Set.of(
            "net.minecraft.", "com.mojang.", "net.fabricmc.");

    /** JVM machinery frames inserted between a caller and the callee (reflection, method handles). */
    private static final Set<String> MACHINERY_PREFIXES = Set.of(
            "jdk.internal.reflect.", "java.lang.reflect.", "sun.reflect.",
            "jdk.internal.invoke.", "java.lang.invoke.");

    private static final int MAX_UNWRAP_FRAMES = 64;

    /**
     * The authentication token is never kept as a plaintext {@code String}.
     * It is stored masked against a per-capture random pad so a
     * {@code getDeclaredField("accessToken")} read or a blind scan for
     * JWT-shaped static String fields finds nothing. The pair is published
     * atomically through a single {@code volatile} reference.
     */
    private static final SecureRandom RANDOM = new SecureRandom();
    private static volatile AuthToken authToken;

    /** Masked token characters plus the random pad used to mask them. */
    private record AuthToken(char[] masked, char[] pad) {}

    private static final Set<String> issuedReplacements = ConcurrentHashMap.newKeySet();

    /** Deduplicates blocked-access reports so hostile spin loops cannot flood the log. */
    private static final Set<String> reportedDirectCalls = ConcurrentHashMap.newKeySet();
    /** Caches the platform-frame authorization decision per (class, method). */
    private static final Set<String> allowedPlatformFrames = ConcurrentHashMap.newKeySet();
    private static final Set<String> deniedPlatformFrames = ConcurrentHashMap.newKeySet();

    private static final StackWalker WALKER =
            StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE);

    private TokenAccess() {}

    /**
     * Captures a token supplied to {@code User.<init>} unless it is a value
     * that this mod previously supplied as a replacement. This prevents a
     * later construction using an already-sanitized User value from replacing
     * the authentication token with a fake.
     */
    public static void captureFromUserConstructor(String token) {
        if (!gatePermits("captureFromUserConstructor")) return;
        if (token != null && !token.isBlank() && !issuedReplacements.contains(token)) {
            // Mask immediately; never leave the plaintext in a static field.
            char[] chars = token.toCharArray();
            char[] pad = new char[chars.length];
            char[] masked = new char[chars.length];
            for (int i = 0; i < chars.length; i++) {
                pad[i] = (char) RANDOM.nextInt(Character.MAX_VALUE + 1);
                masked[i] = (char) (chars[i] ^ pad[i]);
            }
            authToken = new AuthToken(masked, pad);
        }
    }

    /** Records a fake/custom replacement before it reaches game code. */
    public static void registerReplacement(String token) {
        if (!gatePermits("registerReplacement")) return;
        if (token != null && !token.isBlank()) {
            issuedReplacements.add(token);
        }
    }

    /**
     * Returns whether {@code value} is a replacement this mod previously
     * issued. Used to detect launch arguments that were already sanitized by
     * the pre-launch boundary so later startup hooks do not re-sanitize them.
     * This intentionally does not gate on the caller: it reveals only whether
     * a value the caller already holds is one of TokenProtector's own fakes,
     * which is not a credential disclosure.
     */
    public static boolean isIssuedReplacement(String value) {
        return value != null && issuedReplacements.contains(value);
    }

    /**
     * Returns the real token for TokenProtector's own auth call sites; foreign
     * callers get null and are reported. The gate check is deliberately inline so a
     * retransformer that disables one shared helper cannot silently reopen the read
     * path.
     */
    public static String forAuthentication() {
        // Local pair {className, methodName}; mutated inside the walker lambda.
        String[] caller = {null, null};
        boolean found = WALKER.walk(stream -> {
            var it = stream.iterator();
            int unwrapped = 0;
            while (it.hasNext()) {
                StackWalker.StackFrame frame = it.next();
                String cls = frame.getClassName();
                if (cls.equals(TokenAccess.class.getName()) || isMachinery(cls)) {
                    if (++unwrapped > MAX_UNWRAP_FRAMES) break;
                    continue;
                }
                caller[0] = cls;
                caller[1] = frame.getMethodName();
                return true;
            }
            return false;
        });
        if (!found || caller[0] == null) return null;

        boolean allowed = caller[0].startsWith(OWN_PREFIX)
                || (isPlatform(caller[0]) && platformMethodAuthorized(caller[0], caller[1]));
        if (!allowed) {
            reportDirectCall("forAuthentication", caller[0], caller[1]);
            return null;
        }

        // Materialise the token only here, after the gate passed, so the only
        // reflectively reachable member that returns the secret is this gated
        // method itself (the masked fields alone yield no usable value).
        AuthToken secret = authToken;
        if (secret == null) return null;
        char[] masked = secret.masked();
        char[] pad = secret.pad();
        if (masked == null || pad == null || masked.length != pad.length) return null;
        char[] out = new char[masked.length];
        for (int i = 0; i < out.length; i++) {
            out[i] = (char) (masked[i] ^ pad[i]);
        }
        return new String(out);
    }

    /**
     * Shared gate for the state-mutating helpers
     * ({@link #captureFromUserConstructor(String)},
     * {@link #registerReplacement(String)}). Compromising this helper alone
     * only allows a hostile caller to poison replacement state (a denial of
     * service); the credential read path performs its own independent inline
     * check in {@link #forAuthentication()}.
     */
    private static boolean gatePermits(String operation) {
        String[] caller = {null, null};
        boolean found = WALKER.walk(stream -> {
            var it = stream.iterator();
            int unwrapped = 0;
            while (it.hasNext()) {
                StackWalker.StackFrame frame = it.next();
                String cls = frame.getClassName();
                if (cls.equals(TokenAccess.class.getName()) || isMachinery(cls)) {
                    if (++unwrapped > MAX_UNWRAP_FRAMES) break;
                    continue;
                }
                caller[0] = cls;
                caller[1] = frame.getMethodName();
                return true;
            }
            return false;
        });
        if (!found || caller[0] == null) return false;

        if (caller[0].startsWith(OWN_PREFIX)) return true;
        if (isPlatform(caller[0])) return platformMethodAuthorized(caller[0], caller[1]);
        reportDirectCall(operation, caller[0], caller[1]);
        return false;
    }

    /**
     * For frames that live in game classes we allow the call unless the method
     * is a handler that a foreign mod's mixin merged into that class. Mixin
     * marks every method it merges into a target with {@link MixinMerged};
     * our own handlers carry {@code net.tokenprotector.*} owners. Methods with
     * no merge annotation (plain game methods that mixin has rewritten in
     * place) are treated as platform code and allowed.
     */
    private static boolean platformMethodAuthorized(String className, String methodName) {
        String key = className + "#" + methodName;
        if (allowedPlatformFrames.contains(key)) return true;
        if (deniedPlatformFrames.contains(key)) return false;

        boolean allowed = true;
        try {
            Class<?> target = Class.forName(className, false,
                    TokenAccess.class.getClassLoader());
            for (Method method : target.getDeclaredMethods()) {
                if (!method.getName().equals(methodName)) continue;
                MixinMerged merged = method.getAnnotation(MixinMerged.class);
                if (merged != null && !merged.mixin().startsWith(OWN_PREFIX)) {
                    allowed = false;
                }
                break;
            }
        } catch (Throwable ignored) {
            // Never fail closed on a metadata lookup problem; the calling code
            // is still physically located inside a platform class.
            allowed = true;
        }

        (allowed ? allowedPlatformFrames : deniedPlatformFrames).add(key);
        return allowed;
    }

    private static void reportDirectCall(String operation, String className, String methodName) {
        String key = operation + "|" + className + "." + methodName;
        if (!reportedDirectCalls.add(key)) return;
        SessionAccessMonitor.AccessInfo info =
                SessionAccessMonitor.foreignAccessInfo(className, methodName);
        SessionAccessMonitor.recordBlockedAccess(info, "TokenAccess." + operation);
    }

    private static boolean isMachinery(String className) {
        for (String prefix : MACHINERY_PREFIXES) {
            if (className.startsWith(prefix)) return true;
        }
        return false;
    }

    private static boolean isPlatform(String className) {
        for (String prefix : PLATFORM_PREFIXES) {
            if (className.startsWith(prefix)) return true;
        }
        return false;
    }
}
