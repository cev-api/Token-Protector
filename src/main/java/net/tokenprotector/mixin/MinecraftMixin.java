package net.tokenprotector.mixin;

import net.minecraft.client.Minecraft;
import net.tokenprotector.config.TokenStash;
import net.tokenprotector.util.Log;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.ModifyArg;

/**
 * Single-role: feeds the real token to authlib so multiplayer works.
 * Mod-facing protection is handled by UserMixin's caller-aware getters.
 */
@Mixin(Minecraft.class)
public class MinecraftMixin {

    @ModifyArg(
            method = "createUserApiService",
            at = @At(
                    value = "INVOKE",
                    target = "Lcom/mojang/authlib/yggdrasil/YggdrasilAuthenticationService;"
                            + "createUserApiService(Ljava/lang/String;)"
                            + "Lcom/mojang/authlib/minecraft/UserApiService;"
            ),
            index = 0
    )
    private String restoreRealTokenForAuthlib(String poisonedToken) {
        String real = TokenStash.realAccessToken;
        if (real != null && !real.equals(poisonedToken)) {
            Log.info(
                    "[TokenProtector] Restoring real token for authlib (len={})", real.length());
            return real;
        }
        return poisonedToken;
    }
}
