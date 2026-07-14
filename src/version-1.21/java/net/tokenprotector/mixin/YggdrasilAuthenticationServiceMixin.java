package net.tokenprotector.mixin;

import com.mojang.authlib.yggdrasil.YggdrasilAuthenticationService;
import net.tokenprotector.config.Config;
import net.tokenprotector.fake.TokenFaker;
import net.tokenprotector.util.Log;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.ModifyArg;

/** Authlib 7.0.x used by Minecraft 1.21.x has no FriendsService factory. */
@Mixin(YggdrasilAuthenticationService.class)
public class YggdrasilAuthenticationServiceMixin {

    private static String fakeAuthToken() {
        return Config.get().getReplacement("accessToken", "", TokenFaker.fakeAccessToken());
    }

    @ModifyArg(
            method = "createUserApiService",
            at = @At(
                    value = "INVOKE",
                    target = "Lcom/mojang/authlib/yggdrasil/YggdrasilUserApiService;<init>(Ljava/lang/String;Ljava/net/Proxy;Lcom/mojang/authlib/Environment;)V"
            ),
            index = 0,
            require = 1
    )
    private String tokenprotector$fakeUserApiServiceToken(String originalToken) {
        String fake = fakeAuthToken();
        if (!fake.equals(originalToken)) {
            Log.info("[TokenProtector] Replaced authlib UserApiService constructor token.");
        }
        return fake;
    }
}
