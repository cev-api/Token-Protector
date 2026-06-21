package net.tokenprotector.mixin;

import com.mojang.authlib.minecraft.client.MinecraftClient;
import net.tokenprotector.config.Config;
import net.tokenprotector.config.TokenStash;
import net.tokenprotector.fake.TokenFaker;
import net.tokenprotector.util.Log;
import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Mutable;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.Redirect;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/**
 * Keeps authlib's accessToken field fake at rest and injects the real token
 * only into the outgoing Authorization header at request time.
 */
@Mixin(MinecraftClient.class)
public class AuthlibMinecraftClientMixin {

    @Shadow @Final @Mutable private String accessToken;

    private static String fakeAuthToken() {
        return Config.get().getReplacement("accessToken", "", TokenFaker.fakeAccessToken());
    }

    @Inject(method = "<init>", at = @At("RETURN"))
    private void onConstructed(CallbackInfo ci) {
        this.accessToken = fakeAuthToken();
        Log.info(
                "[TokenProtector] Authlib MinecraftClient.accessToken protected (len={}) - real token swapped during HTTP calls only",
                this.accessToken != null ? this.accessToken.length() : 0);
    }

    @Redirect(
            method = "prepareRequest",
            at = @At(
                    value = "INVOKE",
                    target = "Ljava/net/HttpURLConnection;setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V"
            ),
            require = 0
    )
    private void tokenprotector$redirectPrepareRequestHeader(java.net.HttpURLConnection connection, String key, String value) {
        connection.setRequestProperty(key, protectHeaderValue(key, value));
    }

    @Redirect(
            method = "get",
            at = @At(
                    value = "INVOKE",
                    target = "Ljava/net/HttpURLConnection;setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V"
            ),
            require = 0
    )
    private void tokenprotector$redirectGetHeader(java.net.HttpURLConnection connection, String key, String value) {
        connection.setRequestProperty(key, protectHeaderValue(key, value));
    }

    @Redirect(
            method = "postInternal",
            at = @At(
                    value = "INVOKE",
                    target = "Ljava/net/HttpURLConnection;setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V"
            ),
            require = 0
    )
    private void tokenprotector$redirectPostInternalHeader(java.net.HttpURLConnection connection, String key, String value) {
        connection.setRequestProperty(key, protectHeaderValue(key, value));
    }

    private String protectHeaderValue(String key, String value) {
        if (!"Authorization".equalsIgnoreCase(key)) {
            return value;
        }

        String real = TokenStash.realAccessToken;
        if (real == null || real.isBlank()) {
            return value;
        }

        return "Bearer " + real;
    }
}
