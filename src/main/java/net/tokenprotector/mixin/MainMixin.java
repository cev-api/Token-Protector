package net.tokenprotector.mixin;

import net.tokenprotector.config.TokenStash;
import net.tokenprotector.config.Config;
import net.tokenprotector.fake.TokenFaker;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.ModifyArg;

/**
 * Captures the real access token and poisons the User constructor argument
 * before any constructor-head mixin can observe the real JWT.
 */
@Mixin(net.minecraft.client.main.Main.class)
public class MainMixin {

    private static String fakeAccessToken() {
        return Config.get().getReplacement("accessToken", "", TokenFaker.fakeAccessToken());
    }

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
    private static String stashAndPoisonUserArg(String realAccessToken) {
        TokenStash.realAccessToken = realAccessToken;
        return fakeAccessToken();
    }
}
