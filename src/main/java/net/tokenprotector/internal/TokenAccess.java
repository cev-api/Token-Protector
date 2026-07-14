package net.tokenprotector.internal;

/**
 * Internal holder for the token used by TokenProtector's authentication
 * redirects. Public because transformed callbacks live in Minecraft and
 * authlib classes.
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
