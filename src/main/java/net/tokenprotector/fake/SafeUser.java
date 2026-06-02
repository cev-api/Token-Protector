package net.tokenprotector.fake;

import net.minecraft.client.User;
import net.tokenprotector.config.Config;
import net.tokenprotector.monitor.SessionAccessMonitor;

import java.util.Optional;
import java.util.UUID;

/**
 * A User wrapper that keeps sensitive token fields fake on the surface while
 * retaining the real values internally for TokenProtector's checks.
 */
public final class SafeUser extends User {

    private final String realAccessToken;
    private final Optional<String> realXuid;
    private final Optional<String> realClientId;

    public SafeUser(User original) {
        super(
                original.getName(),
                Config.get().blockProfileId ? TokenFaker.fakeProfileId() : original.getProfileId(),
                Config.get().getReplacement("accessToken", original.getAccessToken(), TokenFaker.fakeAccessToken()),
                Config.get().blockXuid ? Optional.of(
                        Config.get().getReplacement("xuid", original.getXuid().orElse(""), TokenFaker.fakeXuid()))
                        : original.getXuid(),
                Config.get().blockClientId ? Optional.of(
                        Config.get().getReplacement("clientId", original.getClientId().orElse(""), TokenFaker.fakeClientId()))
                        : original.getClientId()
        );
        this.realAccessToken = original.getAccessToken();
        this.realXuid = original.getXuid();
        this.realClientId = original.getClientId();
    }

    public String getRealAccessToken() {
        return realAccessToken;
    }

    public Optional<String> getRealXuid() {
        return realXuid;
    }

    public Optional<String> getRealClientId() {
        return realClientId;
    }
}
