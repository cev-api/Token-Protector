package net.tokenprotector.config;

/**
 * Thread-safe holder shared between {@code MainMixin} and
 * {@code MinecraftMixin} for the real access token.
 */
public final class TokenStash {
    private TokenStash() {}

    public static volatile String realAccessToken;
}
