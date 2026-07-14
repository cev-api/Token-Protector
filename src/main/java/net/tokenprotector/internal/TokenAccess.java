package net.tokenprotector.internal;

/**
 * Internal holder used only by TokenProtector's authentication redirects.
 *
 * <p>The class has to be public because transformed mixin callbacks live in Minecraft and
 * authlib classes. It deliberately exposes no mutable token field. This is exposure
 * reduction, not a trust boundary: a hostile peer in the same JVM can still target or
 * instrument TokenProtector.</p>
 */
public final class TokenAccess {
    private static volatile String accessToken;

    private TokenAccess() {}

    public static void capture(String token) {
        if (token != null && !token.isBlank()) {
            accessToken = token;
        }
    }

    public static String forAuthentication() {
        return accessToken;
    }
}
