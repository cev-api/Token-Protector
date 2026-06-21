package net.tokenprotector.util;

import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.components.toasts.ToastManager;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

public final class MinecraftCompat {
    private MinecraftCompat() {}

    public static ToastManager getToastManager(Minecraft client) {
        if (client == null) {
            return null;
        }

        try {
            Method method = client.getClass().getMethod("getToastManager");
            return (ToastManager) method.invoke(client);
        } catch (ReflectiveOperationException ignored) {
            // 26.2 moved toast access onto the Gui object.
        }

        try {
            Field guiField = client.getClass().getField("gui");
            Object gui = guiField.get(client);
            if (gui == null) {
                return null;
            }

            Method method = gui.getClass().getMethod("toastManager");
            return (ToastManager) method.invoke(gui);
        } catch (ReflectiveOperationException ignored) {
            return null;
        }
    }
}
