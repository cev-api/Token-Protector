package net.tokenprotector.monitor;

import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.spongepowered.asm.mixin.extensibility.IMixinConfigPlugin;
import org.spongepowered.asm.mixin.extensibility.IMixinInfo;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Records actual callback insertion, not merely a merged but unused handler. */
public final class NativeMemoryMixinPlugin implements IMixinConfigPlugin {
    public static final String HOOK_MIXIN = "net.tokenprotector.mixin.TokenReaderMemoryScannerMixin";
    private static volatile boolean inserted;

    public static boolean isHookInserted() { return inserted; }

    @Override public void onLoad(String mixinPackage) {}
    @Override public String getRefMapperConfig() { return null; }
    @Override public boolean shouldApplyMixin(String targetClassName, String mixinClassName) { return true; }
    @Override public void acceptTargets(Set<String> myTargets, Set<String> otherTargets) {}
    @Override public List<String> getMixins() { return null; }
    @Override public void preApply(String targetClassName, ClassNode targetClass, String mixinClassName, IMixinInfo info) {}

    @Override
    public void postApply(String targetClassName, ClassNode targetClass, String mixinClassName, IMixinInfo info) {
        if (!mixinClassName.equals(HOOK_MIXIN)) return;
        inserted = false;
        Set<String> handlers = new HashSet<>();
        for (var method : targetClass.methods) {
            if (!method.name.contains("tokenprotector$observeNativeRead") || method.visibleAnnotations == null) continue;
            for (var annotation : method.visibleAnnotations) {
                if (!annotation.desc.equals("Lorg/spongepowered/asm/mixin/transformer/meta/MixinMerged;")) continue;
                if (annotation.values != null && annotation.values.contains(HOOK_MIXIN)) handlers.add(method.name);
            }
        }
        for (var method : targetClass.methods) {
            if (!method.name.equals("scanWindow") || !method.desc.equals(
                    "([BIJLnet/tokenreader/Win32Api$Region;Lnet/tokenreader/MemoryScanner$Sink;)V")) continue;
            for (var instruction : method.instructions) {
                if (instruction instanceof MethodInsnNode call && call.owner.equals(targetClass.name)
                        && handlers.contains(call.name)) {
                    inserted = true;
                    return;
                }
            }
        }
    }
}
