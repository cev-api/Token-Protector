package net.tokenprotector.config;

import net.fabricmc.loader.api.FabricLoader;
import net.fabricmc.loader.api.ModContainer;
import net.minecraft.client.gui.GuiGraphicsExtractor;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.Checkbox;
import net.minecraft.client.gui.components.EditBox;
import net.minecraft.client.gui.components.StringWidget;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.client.gui.screens.TitleScreen;
import net.minecraft.client.input.MouseButtonEvent;
import net.minecraft.network.chat.Component;
import net.tokenprotector.monitor.SessionAccessMonitor;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Consumer;

public class ConfigScreen extends Screen {
    private static final int ROW_H = 18;
    private static final int PANEL_W = 600;
    private static final DateTimeFormatter TIME_FORMAT =
            DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());

    private final Screen parent;
    private final Config config;
    private final Map<String, Boolean> expandedGroups = new HashMap<>();
    private final List<Object> pageWidgets = new ArrayList<>();
    private final List<Group> modGroups;

    private Tab tab;
    private int listTop;
    private int listBottom;
    private int scrollOffset;
    private int contentHeight;
    private boolean draggingScrollbar;
    private ModLine permissionEditorMod;

    public ConfigScreen(Screen parent) {
        this(parent, Tab.PROTECTION);
    }

    private ConfigScreen(Screen parent, Tab initialTab) {
        super(Component.literal("TokenProtector Settings"));
        this.parent = parent;
        this.config = Config.get();
        this.modGroups = collectGroups();
        this.tab = initialTab;
    }

    public static ConfigScreen openDetections(Screen parent) {
        return new ConfigScreen(parent, Tab.DETECTIONS);
    }

    @Override
    protected void init() {
        int cx = width / 2;
        int tabX = cx - 225;
        addRenderableWidget(tabButton(Tab.PROTECTION, tabX, "Protection"));
        addRenderableWidget(tabButton(Tab.ALLOWED_MODS, tabX + 152, "Allowed Mods"));
        addRenderableWidget(tabButton(Tab.DETECTIONS, tabX + 304, "Recent Detections"));

        addRenderableWidget(Button.builder(Component.literal("Done"), b -> onClose())
                .bounds(cx - 100, height - 26, 200, 20).build());

        rebuildPage();
    }

    private Button tabButton(Tab target, int x, String label) {
        String text = tab == target ? "[" + label + "]" : label;
        return Button.builder(Component.literal(text), b -> {
            tab = target;
            permissionEditorMod = null;
            scrollOffset = 0;
            rebuildWidgets();
        }).bounds(x, 24, 146, 20).build();
    }

    private void rebuildPage() {
        removePageWidgets();
        if (tab == Tab.PROTECTION) buildProtectionPage();
        if (tab == Tab.ALLOWED_MODS && permissionEditorMod == null) buildAllowedModsPage();
        if (tab == Tab.ALLOWED_MODS && permissionEditorMod != null) buildPermissionEditor();
        if (tab == Tab.DETECTIONS) buildDetectionsPage();
    }

    private void buildProtectionPage() {
        int left = width / 2 - 300;
        int y = 54;
        addPageLabel(left, y, 600, "Choose what external mods receive. Token/session NONE is disabled while protection is enabled.");
        y += 18;
        y = addProtectionRow(left, y, "Access Token", config.blockAccessToken, v -> config.blockAccessToken = v,
                config.accessTokenMode, m -> config.accessTokenMode = m, config.customAccessToken, v -> config.customAccessToken = v);
        y = addProtectionRow(left, y, "Session Id", config.blockSessionId, v -> config.blockSessionId = v,
                config.sessionIdMode, m -> config.sessionIdMode = m, config.customSessionId, v -> config.customSessionId = v);
        y = addProtectionRow(left, y, "Profile Id", config.blockProfileId, v -> config.blockProfileId = v,
                config.profileIdMode, m -> config.profileIdMode = m, config.customProfileId, v -> config.customProfileId = v);
        y = addProtectionRow(left, y, "XUID", config.blockXuid, v -> config.blockXuid = v,
                config.xuidMode, m -> config.xuidMode = m, config.customXuid, v -> config.customXuid = v);
        y = addProtectionRow(left, y, "Client Id", config.blockClientId, v -> config.blockClientId = v,
                config.clientIdMode, m -> config.clientIdMode = m, config.customClientId, v -> config.customClientId = v);
        y = addProtectionRow(left, y, "Player Name", config.blockName, v -> config.blockName = v,
                config.nameMode, m -> config.nameMode = m, config.customName, v -> config.customName = v);

        y += 8;
        Checkbox toasts = Checkbox.builder(Component.literal("Show toast alerts"), font)
                .pos(left + 4, y)
                .selected(config.showToasts)
                .onValueChange((cb, value) -> config.showToasts = value)
                .build();
        addPageWidget(toasts);
        y += 20;

        Checkbox chatMessages = Checkbox.builder(Component.literal("Show chat alerts"), font)
                .pos(left + 4, y)
                .selected(config.showChatMessages)
                .onValueChange((cb, value) -> config.showChatMessages = value)
                .build();
        addPageWidget(chatMessages);
        y += 20;

        Checkbox topRightAlert = Checkbox.builder(Component.literal("Show top-right alert button"), font)
                .pos(left + 320, y - 20)
                .selected(config.showTopRightAlerts)
                .onValueChange((cb, value) -> config.showTopRightAlerts = value)
                .build();
        addPageWidget(topRightAlert);

        y += 8;
        Checkbox envMonitor = Checkbox.builder(Component.literal("Warn on env-var token leaks"), font)
                .pos(left + 4, y)
                .selected(config.monitorEnvironmentVariables)
                .onValueChange((cb, value) -> config.monitorEnvironmentVariables = value)
                .build();
        addPageWidget(envMonitor);

        Checkbox propMonitor = Checkbox.builder(Component.literal("Warn on sysprop token leaks"), font)
                .pos(left + 320, y)
                .selected(config.monitorSystemProperties)
                .onValueChange((cb, value) -> config.monitorSystemProperties = value)
                .build();
        addPageWidget(propMonitor);
        y += 20;

        Checkbox argMonitor = Checkbox.builder(Component.literal("Warn on process-arg token leaks"), font)
                .pos(left + 4, y)
                .selected(config.monitorProcessArgs)
                .onValueChange((cb, value) -> config.monitorProcessArgs = value)
                .build();
        addPageWidget(argMonitor);
    }

    private int addProtectionRow(int left, int y, String label, boolean blocked, Consumer<Boolean> blockSetter,
                                 Config.ReplaceMode mode, Consumer<Config.ReplaceMode> modeSetter,
                                 String customValue, Consumer<String> customSetter) {
        Checkbox checkbox = Checkbox.builder(Component.literal(label), font)
                .pos(left + 4, y)
                .selected(blocked)
                .onValueChange((cb, value) -> blockSetter.accept(value))
                .build();
        addPageWidget(checkbox);

        int bx = left + 160;
        for (Config.ReplaceMode candidate : Config.ReplaceMode.values()) {
            if ((label.equals("Access Token") || label.equals("Session Id"))
                    && candidate == Config.ReplaceMode.NONE) continue;
            String text = candidate == mode ? "[" + candidate.name() + "]" : candidate.name();
            Button button = Button.builder(Component.literal(text), b -> {
                modeSetter.accept(candidate);
                rebuildWidgets();
            }).bounds(bx, y, 72, 16).build();
            addPageWidget(button);
            bx += 76;
        }

        addPageLabel(left + 4, y + 20, 148, "Custom value:");
        EditBox input = new EditBox(font, left + 160, y + 18, 260, 18, Component.literal(label + " custom value"));
        input.setMaxLength(512);
        input.setValue(customValue != null ? customValue : "");
        input.setResponder(value -> {
            customSetter.accept(value);
            if (!value.isBlank()) modeSetter.accept(Config.ReplaceMode.CUSTOM);
        });
        input.setHint(Component.literal("Used when CUSTOM is selected"));
        addPageWidget(input);
        return y + 40;
    }

    private void buildAllowedModsPage() {
        int left = panelLeft();
        this.listTop = 66;
        this.listBottom = height - 36;
        addPageLabel(left, 52, PANEL_W, "Checkbox = allow all. Fields... = choose individual field permissions.");

        List<ModRow> rows = flattenModRows();
        this.contentHeight = rows.size() * ROW_H;
        int first = firstVisibleRow(rows.size());
        int visibleRows = visibleRowCount();

        for (int i = 0; i < visibleRows && first + i < rows.size(); i++) {
            ModRow row = rows.get(first + i);
            int y = listTop + i * ROW_H;
                if (row.group() != null) {
                    Group group = row.group();
                    boolean expanded = expandedGroups.getOrDefault(group.key(), false);
                    String prefix = expanded ? "- " : "+ ";
                    Button button = Button.builder(Component.literal(prefix + group.label() + " (" + group.mods().size() + ")"), b -> {
                        expandedGroups.put(group.key(), !expanded);
                        rebuildPage();
                    }).bounds(left + 6, y, PANEL_W - 112, 16).build();
                    addPageWidget(button);
                    String allLabel = isGroupFullyAllowed(group) ? "Clear" : "Select all";
                    Button allButton = Button.builder(Component.literal(allLabel), b -> {
                        setGroupAllowed(group, !isGroupFullyAllowed(group));
                        rebuildPage();
                    }).bounds(left + PANEL_W - 102, y, 90, 16).build();
                    addPageWidget(allButton);
                } else {
                ModLine mod = row.mod();
                String label = truncate(mod.name() + " (" + mod.id() + ") [" + config.permissionSummary(mod.id()) + "]", 58);
                Checkbox checkbox = Checkbox.builder(Component.literal(label), font)
                        .pos(left + 10 + row.indent() * 12, y)
                        .selected(config.allowedMods.contains(mod.id()))
                        .onValueChange((cb, allowed) -> {
                            config.setModAllowed(mod.id(), allowed);
                            rebuildPage();
                        })
                        .build();
                addPageWidget(checkbox);
                Button fields = Button.builder(Component.literal("Fields..."), b -> {
                    permissionEditorMod = mod;
                    scrollOffset = 0;
                    rebuildPage();
                }).bounds(left + PANEL_W - 90, y, 78, 16).build();
                addPageWidget(fields);
            }
        }
    }

    private void buildPermissionEditor() {
        int left = panelLeft();
        int y = 56;
        int contentWidth = 520;
        int contentLeft = width / 2 - contentWidth / 2;
        ModLine mod = permissionEditorMod;

        String header = "Field permissions for " + mod.name() + " (" + mod.id() + ")";
        addPageLabel(contentLeft, y, contentWidth, truncateToWidth(header, contentWidth));
        y += 16;
        addPageLabel(contentLeft, y, contentWidth, "Direct field, reflection, and Unsafe reads stay globally replaced for every mod.");
        y += 22;

        addPageWidget(Button.builder(Component.literal("Back to mod list"), b -> {
            permissionEditorMod = null;
            rebuildPage();
        }).bounds(contentLeft, y, 160, 18).build());
        addPageWidget(Button.builder(Component.literal("Allow all"), b -> {
            config.setModAllowed(mod.id(), true);
            rebuildPage();
        }).bounds(contentLeft + 178, y, 150, 18).build());
        addPageWidget(Button.builder(Component.literal("Block all"), b -> {
            config.setModAllowed(mod.id(), false);
            rebuildPage();
        }).bounds(contentLeft + 346, y, 150, 18).build());
        y += 28;

        for (PermissionField field : PermissionField.values()) {
            Checkbox checkbox = Checkbox.builder(Component.literal(field.label), font)
                    .pos(contentLeft + 12, y)
                    .selected(config.isFieldAllowed(mod.id(), field.key))
                    .onValueChange((cb, allowed) -> {
                        config.setFieldAllowed(mod.id(), field.key, allowed);
                        rebuildPage();
                    })
                    .build();
            addPageWidget(checkbox);
            y += 22;
        }
    }

    private void buildDetectionsPage() {
        int left = panelLeft();
        this.listTop = 66;
        this.listBottom = height - 36;
        addPageLabel(left, 52, PANEL_W, "All TokenProtector alerts (newest first).");

        List<SessionAccessMonitor.AlertLine> alerts = SessionAccessMonitor.recentAlertLines();
        this.contentHeight = alerts.size() * ROW_H;
        if (alerts.isEmpty()) {
            addPageLabel(left + 8, listTop + 8, PANEL_W - 16, "No alerts recorded yet.");
            return;
        }

        int first = firstVisibleRow(alerts.size());
        int visibleRows = visibleRowCount();
        for (int i = 0; i < visibleRows && first + i < alerts.size(); i++) {
            SessionAccessMonitor.AlertLine alert = alerts.get(first + i);
            String text = TIME_FORMAT.format(alert.timestamp()) + "  " + alert.message();
            addPageLabel(left + 8, listTop + i * ROW_H + 3, PANEL_W - 20, truncate(text, 94));
        }
    }

    @Override
    public boolean mouseScrolled(double mouseX, double mouseY, double horizontalAmount, double verticalAmount) {
        if (isListTab() && mouseY >= listTop && mouseY <= listBottom) {
            setScrollOffset(scrollOffset - (int) (verticalAmount * ROW_H));
            rebuildPage();
            return true;
        }
        return super.mouseScrolled(mouseX, mouseY, horizontalAmount, verticalAmount);
    }

    @Override
    public boolean mouseClicked(MouseButtonEvent event, boolean doubleClick) {
        if (isListTab() && isOverScrollbar(event.x(), event.y())) {
            draggingScrollbar = true;
            updateScrollFromMouse(event.y());
            rebuildPage();
            return true;
        }
        return super.mouseClicked(event, doubleClick);
    }

    @Override
    public boolean mouseDragged(MouseButtonEvent event, double dragX, double dragY) {
        if (draggingScrollbar) {
            updateScrollFromMouse(event.y());
            rebuildPage();
            return true;
        }
        return super.mouseDragged(event, dragX, dragY);
    }

    @Override
    public boolean mouseReleased(MouseButtonEvent event) {
        if (draggingScrollbar) {
            draggingScrollbar = false;
            return true;
        }
        return super.mouseReleased(event);
    }

    @Override
    public void extractRenderState(GuiGraphicsExtractor g, int mouseX, int mouseY, float delta) {
        String title = "TokenProtector Configuration";
        g.text(font, title, (width - font.width(title)) / 2, 8, 0xFFFFFF, false);
        if (isListTab()) {
            g.fill(panelLeft(), listTop - 2, panelRight(), listBottom, 0xAA111111);
        }
        super.extractRenderState(g, mouseX, mouseY, delta);
        if (isListTab()) drawScrollbar(g);
    }

    @Override
    public void onClose() {
        Config.save();
        if (minecraft == null) return;
        if (parent != null) {
            minecraft.setScreenAndShow(parent);
        } else {
            minecraft.setScreenAndShow(new TitleScreen());
        }
    }

    @Override
    public boolean isPauseScreen() {
        return false;
    }

    private List<Group> collectGroups() {
        List<ModLine> fabric = new ArrayList<>();
        Map<String, List<ModLine>> nested = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        Map<String, List<ModLine>> regular = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

        for (ModContainer container : FabricLoader.getInstance().getAllMods()) {
            String id = container.getMetadata().getId();
            if (id.equals("tokenprotector") || id.equals("minecraft") || id.equals("java") || id.equals("fabricloader")) continue;

            ModLine line = new ModLine(id, container.getMetadata().getName());
            if (id.startsWith("fabric-")) {
                fabric.add(line);
            } else if (container.getContainingMod().isPresent()) {
                String parentName = container.getContainingMod().get().getMetadata().getName();
                nested.computeIfAbsent("Nested: " + parentName, ignored -> new ArrayList<>()).add(line);
            } else {
                regular.computeIfAbsent(line.name(), ignored -> new ArrayList<>()).add(line);
            }
        }

        List<Group> groups = new ArrayList<>();
        if (!fabric.isEmpty()) groups.add(group("fabric", "Fabric modules", fabric, true));
        for (Map.Entry<String, List<ModLine>> entry : nested.entrySet()) {
            boolean collapsible = entry.getValue().size() > 1;
            groups.add(group("nested:" + entry.getKey(), entry.getKey(), entry.getValue(), collapsible));
        }
        for (Map.Entry<String, List<ModLine>> entry : regular.entrySet()) {
            boolean collapsible = entry.getValue().size() > 1;
            groups.add(group("mod:" + entry.getKey(), entry.getKey(), entry.getValue(), collapsible));
        }
        return groups;
    }

    private Group group(String key, String label, List<ModLine> mods, boolean collapsible) {
        mods.sort(Comparator.comparing(ModLine::id));
        expandedGroups.putIfAbsent(key, false);
        return new Group(key, label, mods, collapsible);
    }

    private List<ModRow> flattenModRows() {
        List<ModRow> rows = new ArrayList<>();
        List<Group> ordered = new ArrayList<>(modGroups);
        ordered.sort(Comparator
                .comparing(Group::collapsible).reversed()
                .thenComparing(Group::label, String.CASE_INSENSITIVE_ORDER));
        for (Group group : ordered) {
            if (group.collapsible()) {
                rows.add(new ModRow(group, null, 0));
                if (expandedGroups.getOrDefault(group.key(), false)) {
                    for (ModLine mod : group.mods()) rows.add(new ModRow(null, mod, 1));
                }
            } else {
                rows.add(new ModRow(null, group.mods().get(0), 0));
            }
        }
        return rows;
    }

    private void removePageWidgets() {
        for (Object widget : pageWidgets) {
            if (widget instanceof Button button) removeWidget(button);
            if (widget instanceof Checkbox checkbox) removeWidget(checkbox);
            if (widget instanceof EditBox input) removeWidget(input);
            if (widget instanceof StringWidget label) removeWidget(label);
        }
        pageWidgets.clear();
    }

    private void addPageLabel(int x, int y, int width, String text) {
        addPageWidget(new StringWidget(x, y, width, 10, Component.literal(text), font));
    }

    private <T> T addPageWidget(T widget) {
        if (widget instanceof Button button) addRenderableWidget(button);
        if (widget instanceof Checkbox checkbox) addRenderableWidget(checkbox);
        if (widget instanceof EditBox input) addRenderableWidget(input);
        if (widget instanceof StringWidget label) addRenderableWidget(label);
        pageWidgets.add(widget);
        return widget;
    }

    private boolean isListTab() {
        return tab == Tab.ALLOWED_MODS || tab == Tab.DETECTIONS;
    }

    private int panelLeft() {
        return width / 2 - PANEL_W / 2;
    }

    private int panelRight() {
        return width / 2 + PANEL_W / 2;
    }

    private int visibleRowCount() {
        return Math.max(1, (listBottom - listTop) / ROW_H);
    }

    private int firstVisibleRow(int size) {
        return Math.max(0, Math.min(size, scrollOffset / ROW_H));
    }

    private int maxScroll() {
        return Math.max(0, contentHeight - visibleRowCount() * ROW_H);
    }

    private void setScrollOffset(int value) {
        scrollOffset = Math.clamp(value, 0, maxScroll());
    }

    private boolean isOverScrollbar(double mouseX, double mouseY) {
        return mouseX >= panelRight() - 12 && mouseX <= panelRight()
                && mouseY >= listTop && mouseY <= listBottom;
    }

    private void updateScrollFromMouse(double mouseY) {
        int trackHeight = listBottom - listTop;
        int thumbHeight = thumbHeight(trackHeight);
        int travel = Math.max(1, trackHeight - thumbHeight);
        double relative = Math.clamp(mouseY - listTop - thumbHeight / 2.0, 0, travel);
        setScrollOffset((int) Math.round(relative * maxScroll() / travel));
    }

    private void drawScrollbar(GuiGraphicsExtractor g) {
        if (contentHeight <= listBottom - listTop) return;
        int trackHeight = listBottom - listTop;
        int thumbHeight = thumbHeight(trackHeight);
        int travel = trackHeight - thumbHeight;
        int thumbY = listTop + (maxScroll() > 0 ? scrollOffset * travel / maxScroll() : 0);
        int x = panelRight() - 10;
        g.fill(x, listTop, x + 8, listBottom, 0x55444444);
        g.fill(x, thumbY, x + 8, thumbY + thumbHeight, 0xFFBBBBBB);
    }

    private int thumbHeight(int trackHeight) {
        return Math.max(12, trackHeight * trackHeight / Math.max(trackHeight, contentHeight));
    }

    private static String truncate(String value, int maxLength) {
        return value.length() <= maxLength ? value : value.substring(0, maxLength - 3) + "...";
    }

    private String truncateToWidth(String value, int maxWidth) {
        if (font.width(value) <= maxWidth) return value;
        String ellipsis = "...";
        int available = Math.max(0, maxWidth - font.width(ellipsis));
        String out = value;
        while (!out.isEmpty() && font.width(out) > available) {
            out = out.substring(0, out.length() - 1);
        }
        return out + ellipsis;
    }

    private boolean isGroupFullyAllowed(Group group) {
        for (ModLine mod : group.mods()) {
            if (!config.allowedMods.contains(mod.id())) return false;
        }
        return !group.mods().isEmpty();
    }

    private void setGroupAllowed(Group group, boolean allowed) {
        for (ModLine mod : group.mods()) {
            config.setModAllowed(mod.id(), allowed);
        }
    }

    private enum Tab { PROTECTION, ALLOWED_MODS, DETECTIONS }

    private enum PermissionField {
        NAME("name", "Player Name"),
        PROFILE_ID("profileId", "Profile Id / UUID"),
        XUID("xuid", "XUID"),
        CLIENT_ID("clientId", "Client Id"),
        SESSION_ID("sessionId", "Session Id"),
        ACCESS_TOKEN("accessToken", "Access Token");

        private final String key;
        private final String label;

        PermissionField(String key, String label) {
            this.key = key;
            this.label = label;
        }
    }

    private record ModLine(String id, String name) {}

    private record Group(String key, String label, List<ModLine> mods, boolean collapsible) {}

    private record ModRow(Group group, ModLine mod, int indent) {}
}
