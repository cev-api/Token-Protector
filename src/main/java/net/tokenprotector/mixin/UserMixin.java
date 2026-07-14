package net.tokenprotector.mixin;

import net.minecraft.client.User;
import net.tokenprotector.alert.AlertManager;
import net.tokenprotector.config.Config;
import net.tokenprotector.fake.TokenFaker;
import net.tokenprotector.fake.TokenVault;
import net.tokenprotector.internal.TokenAccess;
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
        SessionAccessMonitor.AccessInfo caller = SessionAccessMonitor.detectCaller();

        // Capture a trusted alt-account token when one constructs its own User.
        if (!shouldProtect(caller, "accessToken") && caller.externalCaller()
                && this.accessToken != null && !this.accessToken.isEmpty()) {
            TokenAccess.capture(this.accessToken);
        }
        TokenVault.store(self, name, profileId, xuid, clientId);

        int blockedCount = 0;
        if (Config.get().blockAccessToken && shouldProtect(caller, "accessToken")) {
            this.accessToken = Config.get().getReplacement("accessToken", accessToken, TokenFaker.fakeAccessToken());
            blockedCount++;
        }
        if (Config.get().blockProfileId && shouldProtect(caller, "profileId")) {
            this.uuid = profileReplacement(profileId);
            blockedCount++;
        }
        if (Config.get().blockXuid && shouldProtect(caller, "xuid")) {
            String replacement = Config.get().getReplacement("xuid", xuid.orElse(""), TokenFaker.fakeXuid());
            this.xuid = Optional.ofNullable(replacement).filter(value -> !value.isBlank());
            blockedCount++;
        }
        if (Config.get().blockClientId && shouldProtect(caller, "clientId")) {
            String replacement = Config.get().getReplacement("clientId", clientId.orElse(""), TokenFaker.fakeClientId());
            this.clientId = Optional.ofNullable(replacement).filter(value -> !value.isBlank());
            blockedCount++;
        }
        if (Config.get().blockName && shouldProtect(caller, "name")) {
            this.name = Config.get().getReplacement("name", name, TokenFaker.fakeName());
            blockedCount++;
        }

        if (blockedCount > 0) {
            Log.info("[TokenProtector] Protected {} User field(s) at construction.", blockedCount);
        }
    }

    @Inject(method = "getAccessToken", at = @At("RETURN"), cancellable = true)
    private void onGetAccessToken(CallbackInfoReturnable<String> cir) {
        User self = (User) (Object) this;
        String real = TokenAccess.forAuthentication();
        if (real == null) real = this.accessToken;

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
        String token = TokenAccess.forAuthentication();
        if (token == null) token = this.accessToken;
        String real = "token:" + token + ":" + values.profileId().toString().replace("-", "");

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
        return TokenVault.get(self, this.name, this.uuid, this.xuid, this.clientId);
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
