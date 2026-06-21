package net.tokenprotector.fake;

import net.minecraft.client.User;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.WeakHashMap;

/**
 * Keeps the original session values outside User so direct reads of User's
 * fields only expose replacements.
 */
public final class TokenVault {
    private static final Map<User, SessionValues> VALUES =
            Collections.synchronizedMap(new WeakHashMap<>());

    private TokenVault() {}

    public static void store(User user, String name, UUID profileId, String accessToken,
                             Optional<String> xuid, Optional<String> clientId) {
        VALUES.put(user, new SessionValues(name, profileId, accessToken, xuid, clientId));
    }

    public static SessionValues get(User user, String name, UUID profileId, String accessToken,
                                    Optional<String> xuid, Optional<String> clientId) {
        return VALUES.getOrDefault(user, new SessionValues(name, profileId, accessToken, xuid, clientId));
    }

    public static SessionValues getStored(User user) {
        return VALUES.get(user);
    }

    public record SessionValues(
            String name,
            UUID profileId,
            String accessToken,
            Optional<String> xuid,
            Optional<String> clientId
    ) {}
}
