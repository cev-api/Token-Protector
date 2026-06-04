package net.tokenprotector.alert;

import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.Checkbox;
import net.minecraft.client.gui.components.StringWidget;
import net.minecraft.client.gui.GuiGraphicsExtractor;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.network.chat.Component;

public class DetectionAlertScreen extends Screen {
    private final String title;
    private final String body;
    private final String modId;
    private final String field;
    private boolean ignoreThisSession;

    public DetectionAlertScreen(String title, String body, String modId, String field) {
        super(Component.literal("TokenProtector Alert"));
        this.title = title;
        this.body = body;
        this.modId = modId;
        this.field = field;
    }

    @Override
    protected void init() {
        int cx = width / 2;

        addRenderableWidget(new StringWidget(cx - 170, height / 2 - 40, 340, 12,
                Component.literal(title), font));
        addRenderableWidget(new StringWidget(cx - 220, height / 2 - 20, 440, 24,
                Component.literal(body), font));

        if (modId != null && field != null) {
            Checkbox ignoreCheckbox = Checkbox.builder(
                    Component.literal("Ignore this detection for this session"), font)
                    .pos(cx - 150, height / 2 + 18)
                    .selected(false)
                    .onValueChange((checkbox, value) -> ignoreThisSession = value)
                    .build();
            addRenderableWidget(ignoreCheckbox);
        }

        addRenderableWidget(Button.builder(Component.literal("OK"), b -> {
            if (ignoreThisSession && modId != null && field != null) {
                AlertManager.ignoreThisSession(modId, field);
            }
            onClose();
        }).bounds(cx - 60, height / 2 + 44, 120, 20).build());
    }

    @Override
    public void extractRenderState(GuiGraphicsExtractor g, int mouseX, int mouseY, float delta) {
        g.fill(0, 0, width, height, 0xCC000000);
        super.extractRenderState(g, mouseX, mouseY, delta);
    }

    @Override
    public boolean isPauseScreen() {
        return false;
    }
}
