package net.tokenprotector.mixin;

import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.events.GuiEventListener;
import net.minecraft.client.gui.narration.NarratableEntry;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.client.gui.screens.TitleScreen;
import net.minecraft.client.gui.GuiGraphicsExtractor;
import net.minecraft.network.chat.Component;
import net.tokenprotector.config.Config;
import net.tokenprotector.config.ConfigScreen;
import net.tokenprotector.monitor.SessionAccessMonitor;
import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.Unique;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

@Mixin(Screen.class)
public abstract class ScreenMixin {
    @Shadow public int width;
    @Shadow @Final protected net.minecraft.client.Minecraft minecraft;
    @Shadow protected abstract <T extends GuiEventListener & NarratableEntry> T addWidget(T widget);

    @Unique private Button tokenprotector$bannerButton;

    @Inject(method = "init(II)V", at = @At("TAIL"))
    private void tokenprotector$addBannerButton(int width, int height, CallbackInfo ci) {
        tokenprotector$ensureBannerButton();
    }

    @Inject(method = "rebuildWidgets", at = @At("TAIL"))
    private void tokenprotector$rebuildBannerButton(CallbackInfo ci) {
        tokenprotector$bannerButton = null;
        tokenprotector$ensureBannerButton();
    }

    @Unique
    private void tokenprotector$ensureBannerButton() {
        Screen self = (Screen) (Object) this;
        if (!Config.get().showTopRightAlerts) return;
        if (!(self instanceof TitleScreen)) return;
        if (tokenprotector$bannerButton != null) return;

        int count = SessionAccessMonitor.detectionCount();
        if (count <= 0) return;
        int bannerWidth = Math.max(120, minecraft.font.width("TokenProtector Detections: 0000") + 10);
        int x = this.width - bannerWidth - 6;

        tokenprotector$bannerButton = Button.builder(
                        Component.literal("TokenProtector Detections: " + count),
                        b -> {
                            SessionAccessMonitor.acknowledgeAlerts();
                            minecraft.setScreenAndShow(ConfigScreen.openDetections(null));
                        })
                .bounds(x, 4, bannerWidth, 14)
                .build();
        tokenprotector$bannerButton.active = true;
        addWidget(tokenprotector$bannerButton);
    }

    @Inject(method = "extractRenderState", at = @At("TAIL"))
    private void tokenprotector$renderBannerButton(GuiGraphicsExtractor g, int mouseX, int mouseY, float delta, CallbackInfo ci) {
        if (tokenprotector$bannerButton != null && tokenprotector$bannerButton.visible) {
            tokenprotector$bannerButton.extractRenderState(g, mouseX, mouseY, delta);
        }
    }

    @Inject(method = "tick", at = @At("TAIL"))
    private void tokenprotector$updateBannerButton(CallbackInfo ci) {
        tokenprotector$ensureBannerButton();
        if (tokenprotector$bannerButton == null) return;
        int count = SessionAccessMonitor.detectionCount();
        tokenprotector$bannerButton.setMessage(Component.literal("TokenProtector Detections: " + count));
        tokenprotector$bannerButton.visible = count > 0;
    }
}
