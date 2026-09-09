package net.tokenprotector.util;

import net.tokenprotector.TokenProtectorMod;
import net.tokenprotector.monitor.SessionAccessMonitor;
import org.slf4j.helpers.MessageFormatter;

/**
 * Central logging entry point. Every line reaches the SLF4J console, the
 * in-game activity log, and tokenprotector.log; only ALERT lines bump the
 * unread banner counter.
 */
public final class Log {
    private Log() {}

    public static void alert(String message, Object... args) {
        publish("ALERT", message, args);
    }

    public static void info(String message, Object... args) {
        publish("INFO", message, args);
    }

    public static void warn(String message, Object... args) {
        publish("WARN", message, args);
    }

    public static void error(String message, Object... args) {
        publish("ERROR", message, args);
    }

    private static void publish(String level, String message, Object... args) {
        String rendered = MessageFormatter.arrayFormat(message, args).getMessage();
        SessionAccessMonitor.recordLine(level, rendered);
        LogFile.append(level, rendered);
        // The Minecraft console/launcher log already stamps and buffers lines;
        // keep using a warn-level SLF4J call so all levels reach the console
        // even when only the warn threshold is configured.
        TokenProtectorMod.LOGGER.warn("[" + level + "] " + message, args);
    }
}
