package net.tokenprotector.mixin;

import net.minecraft.client.User;
import net.minecraft.client.multiplayer.ClientHandshakePacketListenerImpl;
import net.tokenprotector.fake.TokenVault;
import net.tokenprotector.internal.TokenAccess;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Redirect;

import java.util.UUID;

/**
 * Keeps multiplayer login working without relying on public User getters to
 * return sensitive data to arbitrary callers.
 */
@Mixin(ClientHandshakePacketListenerImpl.class)
public class ClientHandshakePacketListenerImplMixin {

    @Redirect(
            method = "authenticateServer",
            at = @At(
                    value = "INVOKE",
                    target = "Lnet/minecraft/client/User;getProfileId()Ljava/util/UUID;"
            ),
            require = 1
    )
    private UUID tokenprotector$useStoredProfileId(User user) {
        TokenVault.SessionValues stored = TokenVault.getStored(user);
        return stored != null ? stored.profileId() : user.getProfileId();
    }

    @Redirect(
            method = "authenticateServer",
            at = @At(
                    value = "INVOKE",
                    target = "Lnet/minecraft/client/User;getAccessToken()Ljava/lang/String;"
            ),
            require = 1
    )
    private String tokenprotector$useStoredAccessToken(User user) {
        String real = TokenAccess.forAuthentication();
        return real != null ? real : user.getAccessToken();
    }
}
