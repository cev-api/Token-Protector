package net.tokenprotector.util;

import net.tokenprotector.TokenProtectorMod;
import net.tokenprotector.monitor.SessionAccessMonitor;
import org.slf4j.helpers.MessageFormatter;

public final class Log {
    private Log() {}

    public static void alert(String message, Object... args) {
        String rendered = MessageFormatter.arrayFormat(message, args).getMessage();
        SessionAccessMonitor.recordAlertLine(rendered);
        TokenProtectorMod.LOGGER.error("[ALERT] " + message, args);
    }

    public static void info(String message, Object... args) {
        TokenProtectorMod.LOGGER.warn("[INFO] " + message, args);
    }

    public static void warn(String message, Object... args) {
        TokenProtectorMod.LOGGER.warn("[WARN] " + message, args);
    }

    public static void error(String message, Object... args) {
        TokenProtectorMod.LOGGER.warn("[ERROR] " + message, args);
    }
}
