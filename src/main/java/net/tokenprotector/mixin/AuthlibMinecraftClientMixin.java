package net.tokenprotector.mixin;

import com.mojang.authlib.minecraft.client.MinecraftClient;
import net.tokenprotector.TokenProtectorMod;
import net.tokenprotector.alert.AlertManager;
import net.tokenprotector.config.Config;
import net.tokenprotector.fake.TokenFaker;
import net.tokenprotector.monitor.SessionAccessMonitor;
import net.tokenprotector.util.Log;
import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Mutable;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfoReturnable;

import java.net.HttpURLConnection;

/**
 * Time-window protection and spin-race detection for authlib's
 * MinecraftClient.accessToken.
 * The field stays fake at rest and is swapped to the real token only during
 * HTTP calls.
 */
@Mixin(MinecraftClient.class)
public class AuthlibMinecraftClientMixin {

    @Shadow @Final @Mutable private String accessToken;

    // spin-race detection - counts field state changes
    private static volatile int lastSwapThreadHash;
    private static volatile long swapRealsSinceAlert;

    private static String fakeAuthToken() {
        return Config.get().getReplacement("accessToken", "", TokenFaker.fakeAccessToken());
    }

    @Inject(method = "<init>", at = @At("RETURN"))
    private void onConstructed(CallbackInfo ci) {
        this.accessToken = fakeAuthToken();
        Log.info(
                "[TokenProtector] Authlib MinecraftClient.accessToken poisoned (len={})",
                this.accessToken != null ? this.accessToken.length() : 0);
    }

    // ── get() ────────────────────────────────────────────────────

    @Inject(method = "get", at = @At("HEAD"))
    private void onGetEntry(CallbackInfoReturnable<?> cir) {
        detectSpinRace();
        swapToReal();
    }

    @Inject(method = "get", at = @At("RETURN"))
    private void onGetExit(CallbackInfoReturnable<?> cir) {
        swapToFake();
    }

    // ── postInternal ─────────────────────────────────────────────

    @Inject(method = "postInternal", at = @At("HEAD"))
    private void onPostInternalEntry(CallbackInfoReturnable<HttpURLConnection> cir) {
        detectSpinRace();
        swapToReal();
    }

    @Inject(method = "postInternal", at = @At("RETURN"))
    private void onPostInternalExit(CallbackInfoReturnable<HttpURLConnection> cir) {
        swapToFake();
    }

    // ── Spin-race detection ──────────────────────────────────────

    /**
     * If the HTTP-calling thread keeps seeing the real token across many rapid
     * swaps, treat it as spin-polling and raise an alert.
     */
    private void detectSpinRace() {
        long now = System.nanoTime();
        swapRealsSinceAlert++;
        if (swapRealsSinceAlert > 500) {
            // A few hundred swaps in a short period usually means someone is
            // polling this field at a very high rate.
            String real = net.tokenprotector.config.TokenStash.realAccessToken;
            if (real != null && real.equals(this.accessToken)) {
                SessionAccessMonitor.AccessInfo info = SessionAccessMonitor.detectCaller();
                Log.alert(
                        "[TokenProtector] 🔥 SPIN-RACE DETECTED! {} reads/sec on authlib field by {} ({})",
                        swapRealsSinceAlert, info.modName(), info.className());
                AlertManager.triggerAlert(info, "SpinRace-Authlib");
                swapRealsSinceAlert = 0;
            }
        }
    }

    // ── Swap helpers ─────────────────────────────────────────────

    private void swapToReal() {
        String real = net.tokenprotector.config.TokenStash.realAccessToken;
        if (real != null && !real.equals(this.accessToken)) {
            this.accessToken = real;
        }
    }

    private void swapToFake() {
        this.accessToken = fakeAuthToken();
        // Reset the spin counter on normal returns.
        if (swapRealsSinceAlert < 100) swapRealsSinceAlert = 0;
    }
}
