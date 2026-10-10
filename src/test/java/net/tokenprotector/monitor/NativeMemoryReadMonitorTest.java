package net.tokenprotector.monitor;

import net.tokenprotector.alert.AlertManager;
import net.tokenprotector.internal.TokenAccess;
import net.tokenprotector.util.Log;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class NativeMemoryReadMonitorTest {
    private static final String TOKEN = "synthetic-long-token-for-memory-evidence-only";

    @Test
    void matchesAsciiUtf16AndOddOffsetsWithoutChangingTheReadBuffer() {
        TokenAccess.captureFromUserConstructor(TOKEN);
        for (var encoding : new java.nio.charset.Charset[] {StandardCharsets.US_ASCII, StandardCharsets.UTF_16LE}) {
            byte[] token = TOKEN.getBytes(encoding);
            byte[] window = new byte[token.length + 9];
            System.arraycopy(token, 0, window, 3, token.length);
            byte[] unchanged = window.clone();
            assertTrue(NativeMemoryReadMonitor.containsCapturedToken(window, window.length));
            assertArrayEquals(unchanged, window);
        }
    }

    @Test
    void ignoresDecoysDifferentTokensTruncationAndBytesOutsideValidLength() {
        TokenAccess.captureFromUserConstructor(TOKEN);
        byte[] bytes = TOKEN.getBytes(StandardCharsets.US_ASCII);
        assertFalse(NativeMemoryReadMonitor.containsCapturedToken(bytes, bytes.length - 1));
        assertFalse(NativeMemoryReadMonitor.containsCapturedToken(bytes, 0));
        assertFalse(NativeMemoryReadMonitor.containsCapturedToken(bytes, -1));
        assertFalse(NativeMemoryReadMonitor.containsCapturedToken(bytes, bytes.length + 1));
        assertFalse(NativeMemoryReadMonitor.containsCapturedToken(null, 0));
        byte[] changed = bytes.clone();
        changed[changed.length - 1] ^= 1;
        assertFalse(NativeMemoryReadMonitor.containsCapturedToken(changed, changed.length));
        assertFalse(NativeMemoryReadMonitor.containsCapturedToken("FAKE_TOKEN".getBytes(StandardCharsets.US_ASCII), 10));
        byte[] badUtf16 = TOKEN.getBytes(StandardCharsets.UTF_16LE);
        badUtf16[badUtf16.length - 1] = 1;
        assertFalse(NativeMemoryReadMonitor.containsCapturedToken(badUtf16, badUtf16.length));
    }

    @Test
    void overlapWindowMatchesButAnIsolatedFragmentDoesNot() {
        TokenAccess.captureFromUserConstructor(TOKEN);
        byte[] token = TOKEN.getBytes(StandardCharsets.US_ASCII);
        int split = token.length / 2;
        byte[] fragment = Arrays.copyOf(token, split);
        assertFalse(NativeMemoryReadMonitor.containsCapturedToken(fragment, fragment.length));
        byte[] windowWithCarry = new byte[token.length + 12];
        System.arraycopy(fragment, 0, windowWithCarry, 7, split);
        System.arraycopy(token, split, windowWithCarry, 7 + split, token.length - split);
        assertTrue(NativeMemoryReadMonitor.containsCapturedToken(windowWithCarry, windowWithCarry.length));
    }

    @Test
    void recaptureChangesFingerprintAndIssuedDecoyDoesNotOverwriteIt() {
        TokenAccess.captureFromUserConstructor(TOKEN);
        TokenAccess.registerReplacement("issued-memory-test-decoy");
        TokenAccess.captureFromUserConstructor("issued-memory-test-decoy");
        byte[] old = TOKEN.getBytes(StandardCharsets.US_ASCII);
        assertTrue(NativeMemoryReadMonitor.containsCapturedToken(old, old.length));
        TokenAccess.captureFromUserConstructor("new-synthetic-memory-test-token");
        assertFalse(NativeMemoryReadMonitor.containsCapturedToken(old, old.length));
        byte[] next = "new-synthetic-memory-test-token".getBytes(StandardCharsets.US_ASCII);
        assertTrue(NativeMemoryReadMonitor.containsCapturedToken(next, next.length));
        NativeMemoryReadMonitor.captureFingerprint("direct-call-must-not-reset-fingerprint");
        assertTrue(NativeMemoryReadMonitor.containsCapturedToken(next, next.length));
    }

    @Test
    void unrelatedCallerCannotFabricateAttributedReadEvidence() {
        TokenAccess.captureFromUserConstructor(TOKEN);
        try (MockedStatic<SessionAccessMonitor> monitor = mockStatic(SessionAccessMonitor.class);
             MockedStatic<Log> logs = mockStatic(Log.class)) {
            byte[] bytes = TOKEN.getBytes(StandardCharsets.US_ASCII);
            NativeMemoryReadMonitor.observeWindow("net.tokenreader.MemoryScanner", bytes, bytes.length, 0);
            NativeMemoryReadMonitor.observeWindow(getClass().getName(), bytes, bytes.length, 0);
            monitor.verifyNoInteractions();
            logs.verifyNoInteractions();
        }
    }

    @Test
    void sameReaderReportsRecoveryAgainAfterAccountSwitch() {
        String reader = "test.scanner.AccountSwitchReader";
        var info = new SessionAccessMonitor.AccessInfo(reader, "scanWindow", 1, "Switch scanner", "switchscanner", true);
        try (MockedStatic<SessionAccessMonitor> monitor = mockStatic(SessionAccessMonitor.class);
             MockedStatic<Log> logs = mockStatic(Log.class);
             MockedStatic<AlertManager> alerts = mockStatic(AlertManager.class)) {
            monitor.when(() -> SessionAccessMonitor.foreignAccessInfo(reader, "scanWindow")).thenReturn(info);
            for (String token : new String[] {"synthetic-account-A-memory-token", "synthetic-account-B-memory-token"}) {
                TokenAccess.captureFromUserConstructor(token);
                byte[] bytes = token.getBytes(StandardCharsets.US_ASCII);
                NativeMemoryReadMonitor.observeHookWindow(reader, bytes, bytes.length, 0);
                NativeMemoryReadMonitor.observeHookWindow(reader, bytes, bytes.length, 0);
            }
            monitor.verify(() -> SessionAccessMonitor.recordMemoryRead(eq(info), eq(true), anyString()), times(2));
            alerts.when(() -> AlertManager.triggerMemoryReadAlert(anyString(), anyString(), anyString(), anyString())).thenReturn(true);
            NativeMemoryReadMonitor.flushAlerts();
        }
    }

    @Test
    void scanWarningDoesNotSuppressRecoveryAndUiWaitsForClientReadiness() {
        TokenAccess.captureFromUserConstructor(TOKEN);
        String reader = "test.scanner.NativeReader";
        var info = new SessionAccessMonitor.AccessInfo(reader, "scanWindow", 1, "Test scanner", "testscanner", true);
        try (MockedStatic<SessionAccessMonitor> monitor = mockStatic(SessionAccessMonitor.class);
             MockedStatic<Log> logs = mockStatic(Log.class);
             MockedStatic<AlertManager> alerts = mockStatic(AlertManager.class)) {
            monitor.when(() -> SessionAccessMonitor.foreignAccessInfo(reader, "scanWindow")).thenReturn(info);
            byte[] decoy = "FAKE_TOKEN".getBytes(StandardCharsets.US_ASCII);
            NativeMemoryReadMonitor.observeHookWindow(reader, decoy, decoy.length, 0x1000);
            byte[] token = TOKEN.getBytes(StandardCharsets.US_ASCII);
            NativeMemoryReadMonitor.observeHookWindow(reader, token, token.length, 0x2000);
            NativeMemoryReadMonitor.observeHookWindow(reader, token, token.length, 0x2000);
            monitor.verify(() -> SessionAccessMonitor.recordMemoryRead(eq(info), eq(false), anyString()), times(1));
            monitor.verify(() -> SessionAccessMonitor.recordMemoryRead(eq(info), eq(true), anyString()), times(1));
            NativeMemoryReadMonitor.flushAlerts(); // unavailable client: do not lose queued events
            alerts.verify(() -> AlertManager.triggerMemoryReadAlert(eq("Test scanner"), eq("Native Memory Scan Observed"), anyString(), anyString()), times(1));
            alerts.when(() -> AlertManager.triggerMemoryReadAlert(anyString(), anyString(), anyString(), anyString())).thenReturn(true);
            NativeMemoryReadMonitor.flushAlerts();
            alerts.verify(() -> AlertManager.triggerMemoryReadAlert(eq("Test scanner"), eq("Session Token Read From Memory"), anyString(), anyString()), times(1));
            NativeMemoryReadMonitor.flushAlerts();
            alerts.verify(() -> AlertManager.triggerMemoryReadAlert(eq("Test scanner"), eq("Session Token Read From Memory"), anyString(), anyString()), times(1));
        }
    }
}
