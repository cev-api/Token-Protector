package net.tokenprotector.monitor;

import net.tokenprotector.util.Log;
import org.spongepowered.asm.mixin.transformer.meta.MixinMerged;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Reports other mods whose mixins were merged into the same protected game
 * classes as TokenProtector's. Detector only: mixin priority is cooperative
 * metadata, so a hostile peer can still arrange to run first.
 */
public final class MixinPostureProbe {
    /** All TokenProtector mixins declare at least this priority on protected targets. */
    public static final int TOKENPROTECTOR_PRIORITY = 100_000;

    /** The game classes whose injection points matter for token protection. */
    public static final Set<String> PROTECTED_TARGETS = Set.of(
            "net.minecraft.client.User",
            "net.minecraft.client.main.Main",
            "net.minecraft.client.Minecraft",
            "net.minecraft.client.multiplayer.ClientHandshakePacketListenerImpl",
            "com.mojang.authlib.minecraft.client.MinecraftClient",
            "com.mojang.authlib.yggdrasil.YggdrasilAuthenticationService"
    );

    private static final String OWN_PREFIX = "net.tokenprotector.";
    private static final Set<String> REPORTED = ConcurrentHashMap.newKeySet();

    private MixinPostureProbe() {}

    /** One merged mixin handler discovered on a protected target. */
    public record MergeEntry(String targetClass, String ownerMixin, int priority) {}

    /**
     * Runs the startup scan over every protected target. Alerts when a foreign
     * mixin merged into a protected class at a priority at least as high as
     * TokenProtector's, and records lower-priority merges as informational.
     */
    public static void runStartupScan() {
        for (String target : PROTECTED_TARGETS) {
            List<MergeEntry> merges = scanTarget(target);
            for (MergeEntry merge : merges) {
                if (merge.ownerMixin().startsWith(OWN_PREFIX)) continue;
                if (!REPORTED.add(target + "|" + merge.ownerMixin())) continue;

                String owner = friendlyOwner(merge.ownerMixin());
                if (merge.priority() >= TOKENPROTECTOR_PRIORITY) {
                    Log.alert("[TokenProtector] ⚠ '{}' merges mixin handlers into protected class {} at priority {} (TokenProtector uses {}). It could pre-empt or cancel TokenProtector's injections on this target; verify this mod or remove it.",
                            owner, target, merge.priority(), TOKENPROTECTOR_PRIORITY);
                } else {
                    Log.info("[TokenProtector] '{}' also merges mixin handlers into protected class {} (priority {}; below TokenProtector's {}).",
                            owner, target, merge.priority(), TOKENPROTECTOR_PRIORITY);
                }
            }
        }
    }

    /**
     * Lists the mixin owners merged into {@code targetClass}. Loading with
     * {@code initialize=false} applies pending mixin transforms without
     * running static initializers. Never throws: unavailable classes just
     * yield an empty list.
     */
    public static List<MergeEntry> scanTarget(String targetClass) {
        List<MergeEntry> entries = new ArrayList<>();
        try {
            // Use the loader that defines the mod (and, in the real game, the
            // loader that applied the mixin transforms), never the raw thread
            // context loader: in a dev/test JVM the parent class loader can
            // hold an untransformed copy of the game class.
            ClassLoader loader = MixinPostureProbe.class.getClassLoader();
            if (loader == null) loader = Thread.currentThread().getContextClassLoader();
            Class<?> target = Class.forName(targetClass, false, loader);
            for (Method method : target.getDeclaredMethods()) {
                MixinMerged merged = method.getAnnotation(MixinMerged.class);
                if (merged == null) continue;
                entries.add(new MergeEntry(targetClass, merged.mixin(), merged.priority()));
            }
        } catch (Throwable ignored) {
            // Target not present on this Minecraft version or not transformable.
        }
        return entries;
    }

    private static String friendlyOwner(String ownerMixin) {
        SessionAccessMonitor.AccessInfo info = SessionAccessMonitor.foreignAccessInfo(ownerMixin, "<merged>");
        return info.modName();
    }
}
