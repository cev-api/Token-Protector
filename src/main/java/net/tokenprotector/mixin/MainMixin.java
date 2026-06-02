package net.tokenprotector.mixin;

import net.tokenprotector.config.TokenStash;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.ModifyArg;

/**
 * Captures the real access token for authlib use. Does NOT modify
 * the User object - UserMixin handles caller-aware value serving.
 */
@Mixin(net.minecraft.client.main.Main.class)
public class MainMixin {

    @ModifyArg(
            method = "main",
            at = @At(
                    value = "INVOKE",
                    target = "Lnet/minecraft/client/User;<init>"
                            + "(Ljava/lang/String;Ljava/util/UUID;Ljava/lang/String;"
                            + "Ljava/util/Optional;Ljava/util/Optional;)V"
            ),
            index = 2
    )
    private static String stashAndPassThrough(String realAccessToken) {
        TokenStash.realAccessToken = realAccessToken;
        return realAccessToken; // pass through unchanged - UserMixin handles blocking
    }
}
