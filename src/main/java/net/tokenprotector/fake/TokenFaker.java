package net.tokenprotector.fake;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;

public final class TokenFaker {

    private static final SecureRandom RANDOM = new SecureRandom();

    private TokenFaker() {}

    /**
     * Realistic-looking fake RS256 JWT with random kid, xuid, sub, and
     * 256 bytes of random signature.  Looks like a real Xbox auth token.
     */
    public static String fakeAccessToken() {
        byte[] sig = new byte[256];
        RANDOM.nextBytes(sig);

        String header = b64("{\"alg\":\"RS256\",\"x5u\":\"https://login.live.com/realms/consumer\","
                + "\"kid\":\"" + randomHex(16) + "\",\"typ\":\"JWT\"}");
        String payload = b64("{\"xuid\":\"" + randomDigits(16) + "\","
                + "\"agg\":\"Adult\",\"sub\":\"" + UUID.randomUUID() + "\","
                + "\"auth\":\"XBOX\",\"ns\":\"default\",\"roles\":[],"
                + "\"iat\":" + (System.currentTimeMillis() / 1000) + ","
                + "\"exp\":" + (System.currentTimeMillis() / 1000 + 86400) + ","
                + "\"iss\":\"tokenprotector\"}");

        return header + "." + payload + "." + b64url(sig);
    }

    /**
     * Returns a fake session ID in the format {@code token:<hex>:<uuid>}.
     */
    public static String fakeSessionId() {
        byte[] randomBytes = new byte[16];
        RANDOM.nextBytes(randomBytes);

        StringBuilder hex = new StringBuilder(32);
        for (byte b : randomBytes) {
            hex.append(String.format("%02x", b));
        }

        return "token:" + hex + ":" + UUID.randomUUID().toString().replace("-", "");
    }

    /**
     * Returns a fake client ID (random 32-char hex string, no dashes).
     */
    public static String fakeClientId() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    /**
     * Returns a fake Xbox User ID (XUID) - a 16-digit numeric string.
     */
    public static String fakeXuid() {
        long xuid = Math.abs(RANDOM.nextLong()) % 10_000_000_000_000_000L;
        return String.format("%016d", xuid);
    }

    /**
     * Returns a random {@link UUID} to replace the real profile ID.
     */
    public static UUID fakeProfileId() {
        return UUID.randomUUID();
    }

    public static String fakeName() {
        return "ProtectedPlayer";
    }

    // ── helpers ──────────────────────────────────────────────────

    private static String b64(String s) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    private static String b64url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String randomHex(int len) {
        byte[] b = new byte[len / 2];
        RANDOM.nextBytes(b);
        StringBuilder sb = new StringBuilder(len);
        for (byte v : b) sb.append(String.format("%02x", v));
        return sb.toString();
    }

    private static String randomDigits(int len) {
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) sb.append(RANDOM.nextInt(10));
        return sb.toString();
    }
}
