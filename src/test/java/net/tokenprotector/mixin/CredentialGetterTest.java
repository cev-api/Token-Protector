package net.tokenprotector.mixin;

import net.tokenprotector.alert.AlertManager;
import net.tokenprotector.config.Config;
import net.tokenprotector.internal.TokenAccess;
import net.tokenprotector.monitor.SessionAccessMonitor;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfoReturnable;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class CredentialGetterTest {
    @Test
    void blockedGettersNeverDecodeCredentialEvenWhenPolled() throws Exception {
        Config config = mock(Config.class);
        config.blockAccessToken = true;
        config.blockSessionId = true;
        when(config.getReplacement(eq("accessToken"), anyString(), anyString())).thenReturn("custom-token");
        when(config.getReplacement(eq("sessionId"), anyString(), anyString())).thenReturn("custom-session");
        var caller = new SessionAccessMonitor.AccessInfo("hostile.Mod", "poll", 1, "Hostile", "hostile", true);
        try (MockedStatic<Config> configs = mockStatic(Config.class);
             MockedStatic<TokenAccess> tokens = mockStatic(TokenAccess.class);
             MockedStatic<SessionAccessMonitor> monitor = mockStatic(SessionAccessMonitor.class);
             MockedStatic<AlertManager> alerts = mockStatic(AlertManager.class)) {
            configs.when(Config::get).thenReturn(config);
            monitor.when(SessionAccessMonitor::detectCaller).thenReturn(caller);
            monitor.when(() -> SessionAccessMonitor.shouldSuppressDuplicate(any(), anyString())).thenReturn(true);
            UserMixin user = userWithFieldToken("field-decoy");
            for (int i = 0; i < 100; i++) {
                assertEquals("custom-token", invoke(user, "onGetAccessToken"));
                assertEquals("custom-session", invoke(user, "onGetSessionId"));
            }
            tokens.verify(TokenAccess::forAuthentication, never());
            tokens.verify(() -> TokenAccess.registerReplacement("custom-token"), times(100));
        }
    }

    @Test
    void defaultAndNoneCredentialModesReturnFakesWithoutDecoding() throws Exception {
        for (Config.ReplaceMode mode : new Config.ReplaceMode[] {Config.ReplaceMode.FAKE, Config.ReplaceMode.NONE}) {
            var constructor = Config.class.getDeclaredConstructor();
            constructor.setAccessible(true);
            Config config = constructor.newInstance();
            config.accessTokenMode = mode;
            config.sessionIdMode = mode;
            var caller = new SessionAccessMonitor.AccessInfo("hostile.Mod", "read", 1, "Hostile", null, true);
            try (MockedStatic<Config> configs = mockStatic(Config.class);
                 MockedStatic<TokenAccess> tokens = mockStatic(TokenAccess.class);
                 MockedStatic<SessionAccessMonitor> monitor = mockStatic(SessionAccessMonitor.class);
                 MockedStatic<AlertManager> alerts = mockStatic(AlertManager.class)) {
                configs.when(Config::get).thenReturn(config);
                monitor.when(SessionAccessMonitor::detectCaller).thenReturn(caller);
                monitor.when(() -> SessionAccessMonitor.shouldSuppressDuplicate(any(), anyString())).thenReturn(true);
                UserMixin user = userWithFieldToken("field-decoy");
                String token = invoke(user, "onGetAccessToken");
                String session = invoke(user, "onGetSessionId");
                org.junit.jupiter.api.Assertions.assertTrue(token.startsWith("eyJ"));
                org.junit.jupiter.api.Assertions.assertTrue(session.startsWith("token:"));
                tokens.verify(TokenAccess::forAuthentication, never());
            }
        }
    }

    @Test
    void allowedAndDisabledGettersStillReturnAuthenticationTokenOrFieldFallback() throws Exception {
        for (boolean blocking : new boolean[] {true, false}) {
            Config config = mock(Config.class);
            config.blockAccessToken = blocking;
            when(config.isFieldAllowed("trusted", "accessToken")).thenReturn(true);
            var caller = new SessionAccessMonitor.AccessInfo("trusted.Mod", "read", 1, "Trusted", "trusted", true);
            try (MockedStatic<Config> configs = mockStatic(Config.class);
                 MockedStatic<TokenAccess> tokens = mockStatic(TokenAccess.class);
                 MockedStatic<SessionAccessMonitor> monitor = mockStatic(SessionAccessMonitor.class)) {
                configs.when(Config::get).thenReturn(config);
                monitor.when(SessionAccessMonitor::detectCaller).thenReturn(caller);
                UserMixin user = userWithFieldToken("field-value");
                tokens.when(TokenAccess::forAuthentication).thenReturn("synthetic-auth-token");
                assertEquals("synthetic-auth-token", invoke(user, "onGetAccessToken"));
                tokens.when(TokenAccess::forAuthentication).thenReturn(null);
                assertEquals("field-value", invoke(user, "onGetAccessToken"));
            }
        }
    }

    @Test
    void maskingRoundTripsUnicodeAndReplacementDoesNotOverwriteCapturedToken() {
        // This test's package is an internal trusted caller; no real credential is used.
        String synthetic = "synthetic-\u0000-\u20ac-\ud83d\ude00-token";
        TokenAccess.captureFromUserConstructor(synthetic);
        assertEquals(synthetic, TokenAccess.forAuthentication());
        TokenAccess.registerReplacement("test-decoy");
        TokenAccess.captureFromUserConstructor("test-decoy");
        assertEquals(synthetic, TokenAccess.forAuthentication());
    }

    @Test
    void sessionHookCancelsBeforeVanillaCanBuildCredentialString() throws Exception {
        Method method = UserMixin.class.getDeclaredMethod("onGetSessionId", CallbackInfoReturnable.class);
        var inject = method.getAnnotation(org.spongepowered.asm.mixin.injection.Inject.class);
        assertEquals("HEAD", inject.at()[0].value());
        org.junit.jupiter.api.Assertions.assertTrue(inject.cancellable());
    }

    private static UserMixin userWithFieldToken(String value) throws Exception {
        UserMixin user = new UserMixin();
        Field field = UserMixin.class.getDeclaredField("accessToken");
        field.setAccessible(true);
        field.set(user, value);
        return user;
    }

    private static String invoke(UserMixin user, String methodName) throws Exception {
        Method method = UserMixin.class.getDeclaredMethod(methodName, CallbackInfoReturnable.class);
        method.setAccessible(true);
        CallbackInfoReturnable<String> callback = new CallbackInfoReturnable<>(methodName, true, "vanilla-decoy");
        method.invoke(user, callback);
        assertNotNull(callback.getReturnValue());
        return callback.getReturnValue();
    }
}
