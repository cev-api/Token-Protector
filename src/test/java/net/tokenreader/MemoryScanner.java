package net.tokenreader;

/** Compatible scanner fixture for a real optional Mixin transformation. */
public final class MemoryScanner {
    public static final class Sink {}
    public static int originalCalls;

    private static void scanWindow(byte[] bytes, int length, long address,
                                   Win32Api.Region region, Sink sink) {
        originalCalls++;
    }
}
