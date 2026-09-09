package net.tokenprotector;

import net.fabricmc.loader.api.entrypoint.PreLaunchEntrypoint;
import net.tokenprotector.internal.LaunchArgumentProtector;
import net.tokenprotector.monitor.InstrumentationPostureProbe;
import net.tokenprotector.util.Log;

/**
 * Earliest Fabric hook TokenProtector can use. Scrubbing the retained launch
 * Arguments here means Main.main and any pre-main observers see the
 * replacement rather than the real token.
 */
public final class PreLaunchProtector implements PreLaunchEntrypoint {
    @Override
    public void onPreLaunch() {
        try {
            LaunchArgumentProtector.captureAndSanitizeRetainedArguments();
        } catch (Throwable t) {
            Log.alert("[TokenProtector] Pre-launch hardening failed: {}. The Main.main sanitizer remains as a fallback.", t.getClass().getSimpleName());
        }
        InstrumentationPostureProbe.runPreLaunchScan();
    }
}
