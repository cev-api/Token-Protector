package net.tokenprotector.mixin;

import net.tokenprotector.internal.LaunchArgumentProtector;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/**
 * Captures the real access token and poisons it before Minecraft starts using
 * the launch arguments or constructs User.
 */
@Mixin(value = net.minecraft.client.main.Main.class, priority = 100000)
public class MainMixin {

    @Inject(method = "main", at = @At("HEAD"))
    private static void captureAndSanitizeLaunchArguments(String[] args, CallbackInfo ci) {
        LaunchArgumentProtector.captureAndSanitize(args);
    }
}
