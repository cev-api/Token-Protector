package net.tokenprotector.monitor;

import net.fabricmc.api.EnvType;
import net.fabricmc.loader.impl.launch.FabricLauncher;
import net.fabricmc.loader.impl.launch.FabricLauncherBase;
import net.fabricmc.loader.impl.launch.MappingConfiguration;
import net.tokenprotector.internal.TokenAccess;
import org.spongepowered.asm.launch.MixinBootstrap;
import org.spongepowered.asm.mixin.MixinEnvironment;
import org.spongepowered.asm.mixin.Mixins;
import org.spongepowered.asm.mixin.transformer.IMixinTransformer;

import java.io.InputStream;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;

/** Forked test only: exercises Mixin without starting Minecraft or native APIs. */
public final class MemoryReadMixinHarness {
    public static void main(String[] args) throws Exception {
        boolean present = !args[0].equals("absent");
        boolean incompatible = args[0].equals("incompatible");
        FixtureLoader loader = new FixtureLoader(present, incompatible);
        FabricLauncher launcher = (FabricLauncher) Proxy.newProxyInstance(
                MemoryReadMixinHarness.class.getClassLoader(), new Class<?>[] {FabricLauncher.class},
                (proxy, method, arguments) -> switch (method.getName()) {
                    case "getEnvironmentType" -> EnvType.CLIENT;
                    case "isDevelopment" -> false;
                    case "getTargetClassLoader" -> loader;
                    case "isClassLoaded" -> loader.alreadyLoaded((String) arguments[0]);
                    case "getResourceAsStream" -> loader.getResourceAsStream((String) arguments[0]);
                    case "getClassByteArray" -> loader.raw((String) arguments[0]);
                    case "loadIntoTarget" -> loader.loadClass((String) arguments[0]);
                    case "getMappingConfiguration" -> new MappingConfiguration();
                    case "getClassPath" -> List.of();
                    case "getEntrypoint" -> MemoryReadMixinHarness.class.getName();
                    case "toString" -> "Memory-read Mixin test launcher";
                    default -> null;
                });
        FabricLauncherBase.setLauncher(launcher);
        var properties = FabricLauncherBase.class.getDeclaredMethod("setProperties", java.util.Map.class);
        properties.setAccessible(true);
        properties.invoke(null, new HashMap<String, Object>());
        System.setProperty("mixin.bootstrapService", "net.fabricmc.loader.impl.launch.knot.MixinServiceKnotBootstrap");
        System.setProperty("mixin.service", "net.fabricmc.loader.impl.launch.knot.MixinServiceKnot");
        MixinBootstrap.init();
        Mixins.addConfiguration("memory-read-hook-test.mixins.json");
        var phase = MixinEnvironment.class.getDeclaredMethod("gotoPhase", MixinEnvironment.Phase.class);
        phase.setAccessible(true);
        phase.invoke(null, MixinEnvironment.Phase.INIT);
        phase.invoke(null, MixinEnvironment.Phase.DEFAULT);
        loader.transformer = (IMixinTransformer) MixinEnvironment.getCurrentEnvironment().getActiveTransformer();
        if (loader.transformer == null) throw new AssertionError("No actual Mixin transformer");

        if (present && !incompatible) {
            Class<?> scanner = loader.loadClass("net.tokenreader.MemoryScanner");
            if (!NativeMemoryMixinPlugin.isHookInserted()) throw new AssertionError("Actual callback insertion not recorded");
            Class<?> region = loader.loadClass("net.tokenreader.Win32Api$Region");
            Class<?> sink = loader.loadClass("net.tokenreader.MemoryScanner$Sink");
            var scan = scanner.getDeclaredMethod("scanWindow", byte[].class, int.class, long.class, region, sink);
            scan.setAccessible(true);
            TokenAccess.captureFromUserConstructor("synthetic-mixin-test-session-token");
            byte[] bytes = "synthetic-mixin-test-session-token".getBytes(StandardCharsets.US_ASCII);
            if (args[0].equals("native")) bytes = nativeReadOwnAllocation(bytes);
            scan.invoke(null, bytes, bytes.length, 0x1234L, region.getConstructor().newInstance(), sink.getConstructor().newInstance());
            if (scanner.getField("originalCalls").getInt(null) != 1) throw new AssertionError("Scanner body changed");
            var detections = SessionAccessMonitor.recentDetections();
            if (detections.stream().noneMatch(d -> d.field().equals("MemoryTokenRecovery"))) {
                throw new AssertionError("Actual transformed hook did not report token recovery: " + detections);
            }
            if (detections.stream().noneMatch(d -> d.field().equals("NativeMemoryScan"))) {
                throw new AssertionError("Actual transformed hook did not report scan");
            }
        } else if (incompatible) {
            loader.loadClass("net.tokenreader.MemoryScanner");
            if (NativeMemoryMixinPlugin.isHookInserted()) throw new AssertionError("Unused merged handler falsely reported as coverage");
            if (!SessionAccessMonitor.recentDetections().isEmpty()) throw new AssertionError("Incompatible reader produced fabricated evidence");
        } else {
            // Force config preparation with an unrelated class while hiding the optional target.
            String name = UnrelatedFixture.class.getName();
            byte[] transformed = loader.transformer.transformClassBytes(name, name, loader.raw(name));
            if (transformed == null || transformed.length == 0) throw new AssertionError("Unrelated transform failed");
            if (!SessionAccessMonitor.recentDetections().isEmpty()) throw new AssertionError("Absent reader produced an alert");
        }
        System.out.println("MEMORY_READ_MIXIN_" + args[0] + "_PASS");
    }

    /** JDK 22+ reflection keeps the JDK 21 build compatible; reads only our own allocation. */
    private static byte[] nativeReadOwnAllocation(byte[] bytes) throws Exception {
        Class<?> arenaType = Class.forName("java.lang.foreign.Arena");
        Class<?> segment = Class.forName("java.lang.foreign.MemorySegment");
        Class<?> layout = Class.forName("java.lang.foreign.MemoryLayout");
        Class<?> value = Class.forName("java.lang.foreign.ValueLayout");
        Class<?> descriptor = Class.forName("java.lang.foreign.FunctionDescriptor");
        Class<?> lookupType = Class.forName("java.lang.foreign.SymbolLookup");
        Class<?> linkerType = Class.forName("java.lang.foreign.Linker");
        Class<?> option = Class.forName("java.lang.foreign.Linker$Option");
        Object address = value.getField("ADDRESS").get(null);
        Object longLayout = value.getField("JAVA_LONG").get(null);
        Object intLayout = value.getField("JAVA_INT").get(null);
        Object arena = arenaType.getMethod("ofConfined").invoke(null);
        try (AutoCloseable close = (AutoCloseable) arena) {
            Object linker = linkerType.getMethod("nativeLinker").invoke(null);
            Object lookup = lookupType.getMethod("libraryLookup", String.class, arenaType).invoke(null, "kernel32", arena);
            Object noOptions = java.lang.reflect.Array.newInstance(option, 0);
            var downcall = linkerType.getMethod("downcallHandle", segment, descriptor, noOptions.getClass());
            var of = descriptor.getMethod("of", layout, java.lang.reflect.Array.newInstance(layout, 0).getClass());
            Object noLayouts = java.lang.reflect.Array.newInstance(layout, 0);
            Object currentDescriptor = of.invoke(null, address, noLayouts);
            Object currentSymbol = ((java.util.Optional<?>) lookupType.getMethod("find", String.class).invoke(lookup, "GetCurrentProcess")).orElseThrow();
            var current = (java.lang.invoke.MethodHandle) downcall.invoke(linker, currentSymbol, currentDescriptor, noOptions);
            Object process;
            try { process = current.invokeWithArguments(); }
            catch (Throwable t) { throw new IllegalStateException(t); }
            Object readLayouts = java.lang.reflect.Array.newInstance(layout, 5);
            Object[] layouts = {address, address, address, longLayout, address};
            for (int i = 0; i < layouts.length; i++) java.lang.reflect.Array.set(readLayouts, i, layouts[i]);
            Object readDescriptor = of.invoke(null, intLayout, readLayouts);
            Object readSymbol = ((java.util.Optional<?>) lookupType.getMethod("find", String.class).invoke(lookup, "ReadProcessMemory")).orElseThrow();
            var read = (java.lang.invoke.MethodHandle) downcall.invoke(linker, readSymbol, readDescriptor, noOptions);
            Object source = arenaType.getMethod("allocate", long.class).invoke(arena, (long) bytes.length);
            Object destination = arenaType.getMethod("allocate", long.class).invoke(arena, (long) bytes.length);
            Object count = arenaType.getMethod("allocate", long.class).invoke(arena, 8L);
            Object input = segment.getMethod("ofArray", byte[].class).invoke(null, (Object) bytes);
            segment.getMethod("copyFrom", segment).invoke(source, input);
            int result;
            try { result = (int) read.invokeWithArguments(process, source, destination, (long) bytes.length, count); }
            catch (Throwable t) { throw new IllegalStateException(t); }
            long got = (long) segment.getMethod("get", Class.forName("java.lang.foreign.ValueLayout$OfLong"), long.class)
                    .invoke(count, longLayout, 0L);
            if (result != 1 || got != bytes.length) throw new AssertionError("ReadProcessMemory failed or returned partial data");
            return (byte[]) segment.getMethod("toArray", Class.forName("java.lang.foreign.ValueLayout$OfByte"))
                    .invoke(destination, value.getField("JAVA_BYTE").get(null));
        }
    }

    private static final class FixtureLoader extends ClassLoader {
        private final boolean present;
        private final boolean incompatible;
        private IMixinTransformer transformer;

        FixtureLoader(boolean present, boolean incompatible) {
            super(MemoryReadMixinHarness.class.getClassLoader());
            this.present = present;
            this.incompatible = incompatible;
        }

        boolean alreadyLoaded(String name) { return findLoadedClass(name) != null; }

        byte[] raw(String name) throws java.io.IOException {
            try (InputStream stream = getResourceAsStream(name.replace('.', '/') + ".class")) {
                if (stream == null) return null;
                byte[] bytes = stream.readAllBytes();
                if (incompatible && name.equals("net.tokenreader.MemoryScanner")) {
                    var node = new org.objectweb.asm.tree.ClassNode();
                    new org.objectweb.asm.ClassReader(bytes).accept(node, 0);
                    for (var method : node.methods) {
                        if (method.name.equals("scanWindow")) method.desc = method.desc.replace("[BIJ", "[BID");
                    }
                    var writer = new org.objectweb.asm.ClassWriter(0);
                    node.accept(writer);
                    bytes = writer.toByteArray();
                }
                return bytes;
            }
        }

        @Override
        public InputStream getResourceAsStream(String name) {
            if (!present && name.startsWith("net/tokenreader/")) return null;
            return super.getResourceAsStream(name);
        }

        @Override
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            if (!name.startsWith("net.tokenreader.")) return super.loadClass(name, resolve);
            if (!present) throw new ClassNotFoundException(name);
            synchronized (getClassLoadingLock(name)) {
                Class<?> loaded = findLoadedClass(name);
                if (loaded == null) {
                    try {
                        byte[] bytes = raw(name);
                        if (bytes == null) throw new ClassNotFoundException(name);
                        if (name.equals("net.tokenreader.MemoryScanner")) {
                            bytes = transformer.transformClassBytes(name, name, bytes);
                        }
                        loaded = defineClass(name, bytes, 0, bytes.length);
                    } catch (java.io.IOException e) {
                        throw new ClassNotFoundException(name, e);
                    }
                }
                if (resolve) resolveClass(loaded);
                return loaded;
            }
        }
    }
}
