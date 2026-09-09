package net.tokenprotector.util;

import net.fabricmc.loader.api.FabricLoader;
import net.tokenprotector.TokenProtectorMod;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Appends every TokenProtector console line to tokenprotector.log (next to
 * config/tokenprotector.json) so alerts survive a closed launcher console.
 * File failures never affect the game.
 */
public final class LogFile {
    /** File name of the dedicated TokenProtector log. */
    public static final String FILE_NAME = "tokenprotector.log";

    private static final DateTimeFormatter STAMP =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");
    private static final ReentrantLock LOCK = new ReentrantLock();

    private static volatile boolean failed;
    private static PrintWriter writer;

    private LogFile() {}

    /** Writes one fully formatted log line. Safe to call from any thread. */
    public static void append(String level, String message) {
        if (failed) return;
        initOnce();
        if (failed) return;

        LOCK.lock();
        try {
            if (writer != null) {
                writer.printf("[%s] [%-5s] %s%n",
                        LocalDateTime.now().format(STAMP),
                        level,
                        message == null ? "" : message);
                writer.flush();
            }
        } finally {
            LOCK.unlock();
        }
    }

    private static void initOnce() {
        if (writer != null || failed) return;

        LOCK.lock();
        try {
            if (writer != null || failed) return;
            Path path = resolvePath();
            try {
                PrintWriter out = new PrintWriter(new OutputStreamWriter(
                        Files.newOutputStream(path,
                                StandardOpenOption.CREATE,
                                StandardOpenOption.WRITE,
                                StandardOpenOption.APPEND),
                        StandardCharsets.UTF_8), true);
                out.printf("%n==== TokenProtector log session %s ====%n",
                        LocalDateTime.now().format(STAMP));
                String context = sessionContext();
                if (context != null) {
                    out.println(context);
                }
                out.flush();
                writer = out;
            } catch (IOException e) {
                failed = true;
                TokenProtectorMod.LOGGER.warn("[TokenProtector] Could not open {} for logging: {}", FILE_NAME, e.getMessage());
            }
        } finally {
            LOCK.unlock();
        }
    }

    private static Path resolvePath() {
        try {
            Path gameDir = FabricLoader.getInstance().getGameDir();
            if (gameDir != null) return gameDir.resolve(FILE_NAME);
        } catch (RuntimeException | LinkageError ignored) {
            // Loader not initialized yet; fall back to the working directory.
        }
        return Paths.get(FILE_NAME);
    }

    private static String sessionContext() {
        StringBuilder context = new StringBuilder();
        try {
            FabricLoader loader = FabricLoader.getInstance();
            loader.getModContainer("minecraft")
                    .ifPresent(mc -> context.append("Minecraft ").append(mc.getMetadata().getVersion()));
            loader.getModContainer("fabricloader")
                    .ifPresent(fl -> context.append(" | Fabric Loader ").append(fl.getMetadata().getVersion()));
        } catch (RuntimeException | LinkageError ignored) {
            return context.length() == 0 ? null : context.toString();
        }
        return context.length() == 0 ? null : context.toString();
    }
}
