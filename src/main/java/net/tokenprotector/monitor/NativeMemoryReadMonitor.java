package net.tokenprotector.monitor;

import net.tokenprotector.alert.AlertManager;
import net.tokenprotector.internal.TokenAccess;
import net.tokenprotector.util.Log;
import net.fabricmc.loader.api.FabricLoader;
import org.spongepowered.asm.mixin.transformer.meta.MixinMerged;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;

/** Evidence from optional scanner hooks, not a universal native-read interceptor. */
public final class NativeMemoryReadMonitor {
    private record Fingerprint(byte[] digest, byte[] prefix, int length, long generation) {}
    private record Alert(String modName, String title, String summary, String details) {}

    private static volatile Fingerprint fingerprint;
    private static final Set<String> REPORTED = ConcurrentHashMap.newKeySet();
    private static final ConcurrentLinkedQueue<Alert> PENDING = new ConcurrentLinkedQueue<>();
    private static final StackWalker WALKER = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE);
    private static long nextGeneration;

    private NativeMemoryReadMonitor() {}

    /** Called only after TokenAccess accepts a capture; retains no plaintext token. */
    public static synchronized void captureFingerprint(String token) {
        if (WALKER.getCallerClass() != TokenAccess.class) return;
        byte[] bytes = token.getBytes(StandardCharsets.UTF_8);
        try {
            byte[] digest = sha256().digest(bytes);
            Fingerprint previous = fingerprint;
            if (previous == null || !MessageDigest.isEqual(previous.digest(), digest)) {
                fingerprint = new Fingerprint(digest,
                        Arrays.copyOf(bytes, Math.min(8, bytes.length)), bytes.length, ++nextGeneration);
            }
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    /**
     * Observes a scanner's copied native-read window before its token parser.
     * The supplied reader and address describe this specific instrumented hook.
     * A fingerprint match proves that this window contains the captured value;
     * it does not prove live validity, exfiltration, or the target process identity.
     */
    public static void observeWindow(String readerClass, byte[] bytes, int length, long address) {
        StackWalker.StackFrame caller = WALKER.walk(stream -> stream.skip(1).findFirst().orElse(null));
        if (caller == null || !caller.getClassName().equals(readerClass)) return;
        boolean ourHandler = false;
        for (var method : caller.getDeclaringClass().getDeclaredMethods()) {
            if (!method.getName().equals(caller.getMethodName())) continue;
            MixinMerged merged = method.getAnnotation(MixinMerged.class);
            if (merged != null && merged.mixin().equals(NativeMemoryMixinPlugin.HOOK_MIXIN)) ourHandler = true;
        }
        if (ourHandler) observeHookWindow(readerClass, bytes, length, address);
    }

    // Package-private evidence core, also driven by unit tests. Production enters through
    // observeWindow, which checks the actual transformed callback's class and owner.
    static void observeHookWindow(String readerClass, byte[] bytes, int length, long address) {
        if (bytes == null || length <= 0 || length > bytes.length) return;
        report(readerClass, false, 0, "Native memory scan buffer observed; token recovery not yet confirmed.");
        Fingerprint expected = fingerprint;
        if (expected == null || REPORTED.contains(readerClass + "|true|" + expected.generation())) return;
        int offset = matchingOffset(bytes, length, expected);
        if (offset >= 0) {
            report(readerClass, true, expected.generation(), "Scanner's memory-read buffer contains the captured session token "
                    + "(SHA-256 match), at scan address 0x" + Long.toHexString(address + offset)
                    + ". Reading was observed, not blocked; target process and live validity were not checked.");
        }
    }

    static boolean containsCapturedToken(byte[] bytes, int length) {
        Fingerprint expected = fingerprint;
        return expected != null && matchingOffset(bytes, length, expected) >= 0;
    }

    private static int matchingOffset(byte[] bytes, int length, Fingerprint expected) {
        if (bytes == null || length < 0 || length > bytes.length || expected.length() == 0) return -1;
        MessageDigest digest = sha256();
        for (int i = 0; i <= length - expected.length(); i++) {
            if (!prefixMatches(bytes, length, i, expected.prefix(), 1)) continue;
            digest.update(bytes, i, expected.length());
            if (MessageDigest.isEqual(expected.digest(), digest.digest())) return i;
        }
        // ASCII credentials can also be retained in UTF-16LE JVM/native buffers.
        if (expected.length() > length / 2) return -1;
        byte[] candidate = new byte[expected.length()];
        try {
            for (int i = 0; i <= length - expected.length() * 2; i++) {
                if (!prefixMatches(bytes, length, i, expected.prefix(), 2)) continue;
                boolean ascii = true;
                for (int j = 0; j < candidate.length; j++) {
                    candidate[j] = bytes[i + j * 2];
                    if (bytes[i + j * 2 + 1] != 0 || candidate[j] < 0) {
                        ascii = false;
                        break;
                    }
                }
                if (ascii && MessageDigest.isEqual(expected.digest(), digest.digest(candidate))) return i;
            }
        } finally {
            Arrays.fill(candidate, (byte) 0);
        }
        return -1;
    }

    private static boolean prefixMatches(byte[] bytes, int length, int offset, byte[] prefix, int stride) {
        if (offset + prefix.length * stride > length) return false;
        for (int j = 0; j < prefix.length; j++) {
            if (bytes[offset + j * stride] != prefix[j]) return false;
            if (stride == 2 && bytes[offset + j * stride + 1] != 0) return false;
        }
        return true;
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    private static void report(String readerClass, boolean recovered, long generation, String details) {
        if (!REPORTED.add(readerClass + "|" + recovered + "|" + generation)) return;
        SessionAccessMonitor.AccessInfo info = SessionAccessMonitor.foreignAccessInfo(readerClass, "scanWindow");
        SessionAccessMonitor.recordMemoryRead(info, recovered, details);
        Log.alert("[TokenProtector] {} | Mod: {} ({}) | Reader: {} | {}",
                recovered ? "SESSION TOKEN RECOVERED FROM MEMORY" : "NATIVE MEMORY SCAN OBSERVED",
                info.modName(), info.modId(), readerClass, details);
        PENDING.add(new Alert(info.modName(),
                recovered ? "Session Token Read From Memory" : "Native Memory Scan Observed",
                recovered ? "token recovery confirmed" : "read not blocked", details));
    }

    /** Absence or an incompatible scanner must not silently look like active coverage. */
    public static void checkHookCoverage() {
        if (!FabricLoader.getInstance().isModLoaded("tokenreader")) return;
        boolean installed = false;
        try {
            Class.forName("net.tokenreader.MemoryScanner", false,
                    NativeMemoryReadMonitor.class.getClassLoader());
            installed = NativeMemoryMixinPlugin.isHookInserted();
        } catch (ReflectiveOperationException | LinkageError | RuntimeException ignored) {}
        if (installed) {
            Log.info("[TokenProtector] TokenReader native-memory scanner evidence hook installed. Coverage is specific to its scanWindow path; arbitrary native reads are not monitored.");
        } else {
            String details = "TokenReader is installed but its optional scanWindow evidence hook is unavailable. "
                    + "Native token reads on this path cannot be confirmed; verify reader/mod compatibility.";
            Log.alert("[TokenProtector] {}", details);
            PENDING.add(new Alert("TokenReader", "Memory Read Detector Unavailable", "coverage unavailable", details));
        }
    }

    /** Called on the client thread; scanner threads never touch Minecraft UI. */
    public static void flushAlerts() {
        Alert alert;
        while ((alert = PENDING.peek()) != null) {
            if (!AlertManager.triggerMemoryReadAlert(alert.modName(), alert.title(), alert.summary(), alert.details())) return;
            PENDING.poll();
        }
    }
}
