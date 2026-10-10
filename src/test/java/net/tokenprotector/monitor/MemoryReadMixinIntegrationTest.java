package net.tokenprotector.monitor;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class MemoryReadMixinIntegrationTest {
    @TempDir Path temporary;

    @Test void optionalHookTransformsAndDetectsActualFixtureBuffer() throws Exception { run("present"); }
    @Test void missingReaderDoesNotBreakStartup() throws Exception { run("absent"); }
    @Test void incompatibleReaderDoesNotFalselyClaimHookCoverage() throws Exception { run("incompatible"); }
    @Test void actualWindowsNativeReadTriggersEvidenceHook() throws Exception {
        org.junit.jupiter.api.Assumptions.assumeTrue(Runtime.version().feature() >= 22
                && System.getProperty("os.name").startsWith("Windows"));
        run("native");
    }

    private void run(String mode) throws Exception {
        String classpath = System.getProperty("memoryReadTestClasspath");
        assertNotNull(classpath);
        Path arguments = temporary.resolve(mode + ".args");
        Files.writeString(arguments, "-cp\n\"" + classpath.replace('\\', '/') + "\"\n"
                + MemoryReadMixinHarness.class.getName() + "\n" + mode + "\n", StandardCharsets.UTF_8);
        Path output = temporary.resolve(mode + ".log");
        String javaName = System.getProperty("os.name").startsWith("Windows") ? "java.exe" : "java";
        Process process = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", javaName).toString(),
                "@" + arguments).directory(temporary.toFile()).redirectErrorStream(true).redirectOutput(output.toFile()).start();
        if (!process.waitFor(30, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            fail("Mixin harness timed out");
        }
        String log = Files.readString(output);
        assertEquals(0, process.exitValue(), log);
        assertTrue(log.contains("MEMORY_READ_MIXIN_" + mode + "_PASS"), log);
    }
}
