package net.tokenprotector.mixin;

import net.minecraft.client.User;
import net.tokenprotector.TokenProtectorMod;
import net.tokenprotector.alert.AlertManager;
import net.tokenprotector.config.Config;
import net.tokenprotector.fake.TokenFaker;
import net.tokenprotector.fake.TokenVault;
import net.tokenprotector.monitor.SessionAccessMonitor;
import net.tokenprotector.util.Log;
import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Mutable;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.Unique;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfoReturnable;

import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

@Mixin(User.class)
public class UserMixin {

    @Shadow @Final @Mutable private String accessToken;
    @Shadow @Final @Mutable private String name;
    @Shadow @Final @Mutable private UUID uuid;
    @Shadow @Final @Mutable private Optional<String> xuid;
    @Shadow @Final @Mutable private Optional<String> clientId;

    @Inject(method = "<init>", at = @At("RETURN"))
    private void onConstruct(String name, UUID profileId, String accessToken, Optional<String> xuid, Optional<String> clientId, CallbackInfo ci) {
        User self = (User) (Object) this;
        TokenVault.store(self, name, profileId, accessToken, xuid, clientId);

        // Sync TokenStash so authlib picks up the real token for this session.
        // Only do this when the caller is trusted (Minecraft itself or a whitelisted mod).
        // A non-whitelisted mod that creates a User must not be able to poison TokenStash.
        SessionAccessMonitor.AccessInfo caller = SessionAccessMonitor.detectCaller();
        if (!shouldProtect(caller, "accessToken")) {
            net.tokenprotector.config.TokenStash.realAccessToken = accessToken;
        }

        int blockedCount = 0;
        if (Config.get().blockAccessToken) {
            this.accessToken = Config.get().getReplacement("accessToken", accessToken, TokenFaker.fakeAccessToken());
            blockedCount++;
        }
        if (Config.get().blockProfileId) {
            this.uuid = profileReplacement(profileId);
            blockedCount++;
        }
        if (Config.get().blockXuid) {
            String replacement = Config.get().getReplacement("xuid", xuid.orElse(""), TokenFaker.fakeXuid());
            this.xuid = Optional.ofNullable(replacement).filter(value -> !value.isBlank());
            blockedCount++;
        }
        if (Config.get().blockClientId) {
            String replacement = Config.get().getReplacement("clientId", clientId.orElse(""), TokenFaker.fakeClientId());
            this.clientId = Optional.ofNullable(replacement).filter(value -> !value.isBlank());
            blockedCount++;
        }
        if (Config.get().blockName) {
            this.name = Config.get().getReplacement("name", name, TokenFaker.fakeName());
            blockedCount++;
        }

        if (blockedCount > 0) {
            Log.info("[TokenProtector] Protected {} User field(s) at construction (real values stored, fakes served to unauthorized mods)", blockedCount);
        }
    }

    @Inject(method = "getAccessToken", at = @At("RETURN"), cancellable = true)
    private void onGetAccessToken(CallbackInfoReturnable<String> cir) {
        User self = (User) (Object) this;
        String real = realValues(self).accessToken();

        SessionAccessMonitor.AccessInfo info = SessionAccessMonitor.detectCaller();
        if (!Config.get().blockAccessToken || !shouldProtect(info, "accessToken")) {
            cir.setReturnValue(real);
            return;
        }

        String replacement = Config.get().getReplacement("accessToken", real, TokenFaker.fakeAccessToken());
        if (Objects.equals(real, replacement)) {
            cir.setReturnValue(real);
            return;
        }

        cir.setReturnValue(replacement);
        blocked(info, "AccessToken");
    }

    @Inject(method = "getSessionId", at = @At("RETURN"), cancellable = true)
    private void onGetSessionId(CallbackInfoReturnable<String> cir) {
        SessionAccessMonitor.AccessInfo info = SessionAccessMonitor.detectCaller();
        User self = (User) (Object) this;
        TokenVault.SessionValues values = realValues(self);
        String real = "token:" + values.accessToken() + ":" + values.profileId().toString().replace("-", "");

        if (!Config.get().blockSessionId || !shouldProtect(info, "sessionId")) {
            cir.setReturnValue(real);
            return;
        }

        String replacement = Config.get().getReplacement("sessionId", real, TokenFaker.fakeSessionId());
        if (Objects.equals(real, replacement)) return;

        cir.setReturnValue(replacement);
        blocked(info, "SessionId");
    }

    @Inject(method = "getClientId", at = @At("RETURN"), cancellable = true)
    private void onGetClientId(CallbackInfoReturnable<Optional<String>> cir) {
        SessionAccessMonitor.AccessInfo info = SessionAccessMonitor.detectCaller();
        Optional<String> realOptional = realValues((User) (Object) this).clientId();
        if (!Config.get().blockClientId || !shouldProtect(info, "clientId")) {
            cir.setReturnValue(realOptional);
            return;
        }

        String real = realOptional.orElse("");
        String replacement = Config.get().getReplacement("clientId", real, TokenFaker.fakeClientId());
        if (Objects.equals(real, replacement)) return;

        cir.setReturnValue(Optional.ofNullable(replacement).filter(v -> !v.isBlank()));
        blocked(info, "ClientId");
    }

    @Inject(method = "getXuid", at = @At("RETURN"), cancellable = true)
    private void onGetXuid(CallbackInfoReturnable<Optional<String>> cir) {
        SessionAccessMonitor.AccessInfo info = SessionAccessMonitor.detectCaller();
        Optional<String> realOptional = realValues((User) (Object) this).xuid();
        if (!Config.get().blockXuid || !shouldProtect(info, "xuid")) {
            cir.setReturnValue(realOptional);
            return;
        }

        String real = realOptional.orElse("");
        String replacement = Config.get().getReplacement("xuid", real, TokenFaker.fakeXuid());
        if (Objects.equals(real, replacement)) return;

        cir.setReturnValue(Optional.ofNullable(replacement).filter(v -> !v.isBlank()));
        blocked(info, "XUID");
    }

    @Inject(method = "getProfileId", at = @At("RETURN"), cancellable = true)
    private void onGetProfileId(CallbackInfoReturnable<UUID> cir) {
        SessionAccessMonitor.AccessInfo info = SessionAccessMonitor.detectCaller();
        UUID real = realValues((User) (Object) this).profileId();
        if (!Config.get().blockProfileId || !shouldProtect(info, "profileId")) {
            cir.setReturnValue(real);
            return;
        }

        UUID replacement = profileReplacement(real);
        if (Objects.equals(real, replacement)) return;

        cir.setReturnValue(replacement);
        blocked(info, "ProfileId");
    }

    @Inject(method = "getName", at = @At("RETURN"), cancellable = true)
    private void onGetName(CallbackInfoReturnable<String> cir) {
        SessionAccessMonitor.AccessInfo info = SessionAccessMonitor.detectCaller();
        String real = realValues((User) (Object) this).name();
        if (!Config.get().blockName || !shouldProtect(info, "name")) {
            cir.setReturnValue(real);
            return;
        }

        String replacement = Config.get().getReplacement("name", real, TokenFaker.fakeName());
        if (Objects.equals(real, replacement)) return;

        cir.setReturnValue(replacement);
        blocked(info, "Name");
    }

    @Unique
    private boolean shouldProtect(SessionAccessMonitor.AccessInfo info, String field) {
        if (!info.externalCaller()) return false;
        if (info.modId() == null) return true;
        return !Config.get().isFieldAllowed(info.modId(), field);
    }

    @Unique
    private TokenVault.SessionValues realValues(User self) {
        return TokenVault.get(self, this.name, this.uuid, this.accessToken, this.xuid, this.clientId);
    }

    @Unique
    private void blocked(SessionAccessMonitor.AccessInfo info, String field) {
        if (AlertManager.isDeliveringAlert()) {
            return;
        }
        if (SessionAccessMonitor.shouldSuppressDuplicate(info, field)) {
            return;
        }
        SessionAccessMonitor.recordBlockedAccess(info, field);
        AlertManager.triggerAlert(info, field);
    }

    @Unique
    private UUID profileReplacement(UUID real) {
        return switch (Config.get().profileIdMode) {
            case NONE -> real;
            case CUSTOM -> {
                try {
                    yield UUID.fromString(Config.get().customProfileId);
                } catch (Exception ignored) {
                    yield TokenFaker.fakeProfileId();
                }
            }
            case FAKE -> TokenFaker.fakeProfileId();
        };
    }
}
