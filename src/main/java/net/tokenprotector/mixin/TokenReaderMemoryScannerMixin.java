package net.tokenprotector.mixin;

import net.tokenprotector.monitor.NativeMemoryReadMonitor;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Pseudo;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Coerce;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/** Optional evidence hook for the tested reader, absent when TokenReader is absent. */
@Pseudo
@Mixin(targets = "net.tokenreader.MemoryScanner", remap = false)
public class TokenReaderMemoryScannerMixin {
    @Inject(method = "scanWindow([BIJLnet/tokenreader/Win32Api$Region;Lnet/tokenreader/MemoryScanner$Sink;)V", at = @At("HEAD"), require = 0, remap = false)
    private static void tokenprotector$observeNativeRead(byte[] bytes, int length, long address,
                                                       @Coerce Object region, @Coerce Object sink,
                                                       CallbackInfo ci) {
        NativeMemoryReadMonitor.observeWindow("net.tokenreader.MemoryScanner", bytes, length, address);
    }
}
