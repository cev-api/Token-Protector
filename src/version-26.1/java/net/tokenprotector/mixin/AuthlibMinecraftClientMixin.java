package net.tokenprotector.mixin;

import com.mojang.authlib.minecraft.client.MinecraftClient;
import net.tokenprotector.config.Config;
import net.tokenprotector.fake.TokenFaker;
import net.tokenprotector.internal.TokenAccess;
import net.tokenprotector.util.Log;
import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Mutable;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.Redirect;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/** Authlib 9.x implementation used by Minecraft 26.x. */
@Mixin(MinecraftClient.class)
public class AuthlibMinecraftClientMixin {
    @Shadow @Final @Mutable private String accessToken;

    private static String fakeAuthToken() {
        return Config.get().getReplacement("accessToken", "", TokenFaker.fakeAccessToken());
    }

    @Inject(method = "<init>", at = @At("RETURN"))
    private void onConstructed(CallbackInfo ci) {
        this.accessToken = fakeAuthToken();
        Log.info("[TokenProtector] Authlib access token field protected.");
    }

    @Redirect(method = "prepareRequest", at = @At(value = "INVOKE",
            target = "Ljava/net/HttpURLConnection;setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V"), require = 1)
    private void redirectPrepareRequestHeader(java.net.HttpURLConnection connection, String key, String value) {
        if (!"Authorization".equalsIgnoreCase(key)) {
            connection.setRequestProperty(key, value);
            return;
        }
        String real = TokenAccess.forAuthentication();
        connection.setRequestProperty(key, real == null || real.isBlank() ? value : "Bearer " + real);
    }
}
