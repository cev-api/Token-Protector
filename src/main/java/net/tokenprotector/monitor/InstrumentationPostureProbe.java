package net.tokenprotector.monitor;

import net.fabricmc.loader.api.FabricLoader;
import net.fabricmc.loader.api.ModContainer;
import net.fabricmc.loader.api.entrypoint.EntrypointContainer;
import net.fabricmc.loader.api.entrypoint.PreLaunchEntrypoint;
import net.tokenprotector.util.Log;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;

/**
 * Best-effort posture checks for code that runs earlier or more privileged than
 * TokenProtector's mixin hooks: preLaunch entrypoints and dynamically attached
 * agents. Heuristic only, and blind to launcher-supplied agents or native
 * instrumentation.
 */
public final class InstrumentationPostureProbe {
    /** Mods expected to declare preLaunch entrypoints without it being suspicious. */
    private static final Set<String> TRUSTED_PRELAUNCH_MODS = Set.of(
            "tokenprotector", "fabricloader", "minecraft");

    private static final Set<String> AGENT_CLASSES = Set.of(
            "net.bytebuddy.agent.ByteBuddyAgent",
            "net.bytebuddy.agent.Installer",
            "net.bytebuddy.agent.VirtualMachineAttachmentProvider");

    private static final Set<String> REPORTED_PRELAUNCH_MODS = ConcurrentHashMap.newKeySet();
    private static final Set<String> REPORTED_AGENT_CLASSES = ConcurrentHashMap.newKeySet();
    private static final Set<String> REPORTED_AGENT_JARS = ConcurrentHashMap.newKeySet();
    private static final Set<String> REPORTED_STRIPPED_TARGETS = ConcurrentHashMap.newKeySet();

    private InstrumentationPostureProbe() {}

    /**
     * Runs during Fabric {@code preLaunch}: lists mods that declare
     * {@code preLaunch} entrypoints and checks whether known agent tooling is
     * already present in the JVM. This is the earliest moment TokenProtector
     * code runs, so anything already loaded here is by definition earlier.
     */
    public static void runPreLaunchScan() {
        scanPreLaunchEntrypoints();
        scanAgentClasses("pre-launch");
    }

    /**
     * Runs once the client is available: rescans for agent classes, scans the
     * temporary directory for dynamic-attach artifacts, and verifies that
     * loaded protected classes still carry TokenProtector's merged handlers.
     */
    public static void runClientScan() {
        scanPreLaunchEntrypoints();
        scanAgentClasses("client");
        scanAgentJarArtifacts();
        verifyProtectedTargetIntegrity();
        NativeMemoryReadMonitor.checkHookCoverage();
    }

    private static void scanPreLaunchEntrypoints() {
        try {
            for (EntrypointContainer<PreLaunchEntrypoint> container
                    : FabricLoader.getInstance().getEntrypointContainers("preLaunch", PreLaunchEntrypoint.class)) {
                ModContainer provider = container.getProvider();
                String modId = provider.getMetadata().getId();
                if (modId == null || TRUSTED_PRELAUNCH_MODS.contains(modId)) continue;
                if (!REPORTED_PRELAUNCH_MODS.add(modId)) continue;
                Log.alert("[TokenProtector] ⚠ Mod '{}' ({}) declares a Fabric preLaunch entrypoint. preLaunch runs before TokenProtector's startup hooks and is a common place for Java-agent self-attachment or early argument capture. Verify this mod or remove it.",
                        provider.getMetadata().getName(), modId);
            }
        } catch (Throwable t) {
            Log.info("[TokenProtector] preLaunch entrypoint scan unavailable: {}", t.getClass().getSimpleName());
        }
    }

    private static void scanAgentClasses(String phase) {
        ClassLoader loader = InstrumentationPostureProbe.class.getClassLoader();
        for (String agentClass : AGENT_CLASSES) {
            // Presence check via class-file resource avoids force-loading the
            // agent's classes (which would run nothing but would still touch
            // code we do not control). Dynamic attach appends the agent jar to
            // the system class loader's search path, so its resources become
            // visible here after a self-attach.
            if (isClassResourcePresent(agentClass, loader)) {
                if (!REPORTED_AGENT_CLASSES.add(agentClass)) continue;
                Log.alert("[TokenProtector] ⚠ Agent tooling class '{}' is present in this JVM's class path (checked during {}). A dynamic Java agent or Byte Buddy self-attach may have run. TokenProtector cannot remove code a Java agent has already instrumented.",
                        agentClass, phase);
            }
        }
    }

    private static boolean isClassResourcePresent(String className, ClassLoader loader) {
        String resourceName = className.replace('.', '/') + ".class";
        try {
            return loader != null && loader.getResource(resourceName) != null;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static void scanAgentJarArtifacts() {
        String tmp = System.getProperty("java.io.tmpdir");
        if (tmp == null) return;
        Path dir;
        try {
            dir = Paths.get(tmp);
        } catch (RuntimeException e) {
            return;
        }
        if (!Files.isDirectory(dir)) return;

        try (Stream<Path> entries = Files.list(dir)) {
            entries.filter(path -> {
                        String name = path.getFileName() == null ? "" : path.getFileName().toString().toLowerCase(Locale.ROOT);
                        return name.endsWith(".jar")
                                && (name.startsWith("byte-buddy-agent")
                                || name.contains("byte-buddy-agent-"));
                    })
                    .forEach(path -> {
                        String name = path.getFileName().toString();
                        if (!REPORTED_AGENT_JARS.add(name)) return;
                        Log.alert("[TokenProtector] ⚠ Dynamic-attach artifact '{}' found in the temp directory. This is characteristic of a Byte Buddy agent that self-attached to this JVM; it may have run before TokenProtector could act.",
                                name);
                    });
        } catch (IOException | RuntimeException e) {
            Log.info("[TokenProtector] Agent artifact scan unavailable: {}", e.getClass().getSimpleName());
        }
    }

    /**
     * A protected class that is loaded but carries no TokenProtector Mixin
     * handlers has very likely been replaced or stripped after the initial
     * transform. Classes that are not yet loaded are skipped.
     */
    private static void verifyProtectedTargetIntegrity() {
        ClassLoader loader = InstrumentationPostureProbe.class.getClassLoader();
        for (String target : MixinPostureProbe.PROTECTED_TARGETS) {
            if (!isClassPresent(target, loader)) continue;
            boolean hasOwnHandlers = MixinPostureProbe.scanTarget(target).stream()
                    .anyMatch(entry -> entry.ownerMixin().startsWith("net.tokenprotector."));
            if (hasOwnHandlers) continue;
            if (!REPORTED_STRIPPED_TARGETS.add(target)) continue;
            Log.alert("[TokenProtector] ⚠ Protected class '{}' is loaded but carries no TokenProtector mixin handlers. A redefinition or transform may have removed protection on this class.", target);
        }
    }

    private static boolean isClassPresent(String name, ClassLoader loader) {
        try {
            Class.forName(name, false, loader);
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }
}