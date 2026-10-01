import { beforeEach, describe, expect, it, vi } from "vitest";
import { binding, bindingsFor, conflictsFor, eventBinding, matchesBinding, sanitizeOverrides, SHORTCUTS } from "./keybindings";
import { shortcutGroups } from "./shortcuts";
import { en } from "@/i18n/locales/en";
import { ru } from "@/i18n/locales/ru";
import { useShortcuts } from "@/store/shortcuts";
import { handleAppShortcut } from "./appShortcuts";
import { handleTerminalShortcut } from "@/shell/useTerminalShortcuts";

const { state, openLocalTerminal, platform, dialogs } = vi.hoisted(() => ({
  platform: { mac: false },
  dialogs: { open: false },
  openLocalTerminal: vi.fn(),
  state: {
    unlocked: true, route: "terminal", settingsOpen: false, palette: false, shortcuts: false,
    modal: null as unknown, confirm: null, device: "desktop", importing: false, groupsModal: false,
    terminals: [{ id: "one", activePaneId: "p1", layout: {} }, { id: "two", activePaneId: "p2", layout: {} }], activeTermId: "one",
    setSettingsOpen: vi.fn(), go: vi.fn(), setPalette: vi.fn(), setShortcuts: vi.fn(),
    setDevice: vi.fn(), bumpTermZoom: vi.fn(), resetTermZoom: vi.fn(), setActiveTerm: vi.fn(),
    closePane: vi.fn(), splitPane: vi.fn(), requestNewTab: vi.fn(), setActivePane: vi.fn(),
  },
}));
vi.mock("@/components/a11y", () => ({ hasOpenDialog: () => dialogs.open }));
vi.mock("@/store/app", () => ({ useApp: { getState: () => state }, layoutPaneOrder: () => ["p1", "p2"] }));
vi.mock("@/store/ctx", () => ({ openLocalTerminal }));
vi.mock("@/bridge/platform", () => ({ isMac: () => platform.mac }));
const ctx = { go: vi.fn(), onNewHost: vi.fn(), onLock: vi.fn() };
function event(code: string, mods: Partial<KeyboardEvent> = {}): KeyboardEvent {
  const e = { key: code, code, ctrlKey: false, altKey: false, shiftKey: false, metaKey: false,
    defaultPrevented: false, ...mods, preventDefault: () => { e.defaultPrevented = true; }, stopPropagation: vi.fn() };
  return e as unknown as KeyboardEvent;
}
const ctrlShift = { ctrlKey: true, shiftKey: true };
beforeEach(() => {
  vi.clearAllMocks();
  platform.mac = false;
  dialogs.open = false; state.importing = false; state.groupsModal = false;
  state.route = "terminal"; state.unlocked = true; state.settingsOpen = false; state.modal = null;
  useShortcuts.setState({ overrides: {}, recording: false, storageError: false });
  vi.stubGlobal("localStorage", { setItem: vi.fn(), getItem: vi.fn() });
});

describe("binding catalog", () => {
  it.each([true, false])("has no conflicting defaults (mac=%s)", (mac) => {
    for (const s of SHORTCUTS) expect(conflictsFor(s.id, s.defaults(mac), {}, mac), s.id).toEqual([]);
  });
  it("translates every action in both languages", () => {
    for (const catalog of [en, ru]) for (const s of SHORTCUTS) {
      const value = s.labelKey.split(".").reduce<unknown>((o, k) => (o as Record<string, unknown>)?.[k], catalog);
      expect(typeof value, s.labelKey).toBe("string");
    }
  });
  it("uses physical keys and exact modifiers; excludes IME and AltGr", () => {
    const b = binding("KeyL", { ctrl: true, shift: true });
    expect(matchesBinding(event("KeyL", { ...ctrlShift, key: "Д" }), b)).toBe(true);
    expect(matchesBinding(event("KeyL", { ...ctrlShift, altKey: true }), b)).toBe(false);
    expect(matchesBinding(event("KeyL", { ...ctrlShift, isComposing: true }), b)).toBe(false);
    expect(matchesBinding(event("KeyL", { ...ctrlShift, getModifierState: () => true }), b)).toBe(false);
    expect(eventBinding(event("", { key: ",", ctrlKey: true })).code).toBe("Comma");
  });
  it("validates persisted data without losing intentional disabled bindings", () => {
    expect(sanitizeOverrides({ lock: [], palette: [binding("F8"), binding("F8")], settings: [{ code: "KeyA" }], unknown: [] }))
      .toEqual({ lock: [], palette: [binding("F8")] });
    expect(sanitizeOverrides({ palette: [binding("Escape", { ctrl: true })], lock: [binding("KeyL")] })).toEqual({});
  });
  it("allows the same keys only in mutually exclusive scopes", () => {
    const keys = [binding("KeyF", { ctrl: true, shift: true })];
    expect(conflictsFor("editorSave", keys, {}, false)).toEqual([]);
    expect(conflictsFor("palette", keys, {}, false).map((s) => s.id)).toEqual(["find"]);
  });
});

describe("editing and persistence", () => {
  it("rejects collisions until explicitly reassigned, removing only matching aliases", () => {
    const keys = [binding("KeyV", { ctrl: true })];
    expect(useShortcuts.getState().assign("find", keys)).toBe(false);
    expect(useShortcuts.getState().assign("find", keys, true)).toBe(true);
    const overrides = useShortcuts.getState().overrides;
    expect(overrides.paste).toEqual([binding("KeyV", { ctrl: true, shift: true })]);
    expect(localStorage.setItem).toHaveBeenCalledWith("unissh.shortcuts.v1.pc", JSON.stringify(overrides));
  });
  it("resets one action and all actions, reporting failed persistence", () => {
    useShortcuts.getState().assign("lock", []);
    expect(bindingsFor("lock", useShortcuts.getState().overrides, false)).toEqual([]);
    useShortcuts.getState().assign("lock", null);
    expect(useShortcuts.getState().overrides).toEqual({});
    vi.mocked(localStorage.setItem).mockImplementation(() => { throw new Error("quota"); });
    useShortcuts.getState().assign("palette", [binding("F8")]);
    expect(useShortcuts.getState().storageError).toBe(true);
    useShortcuts.getState().resetAll();
    expect(useShortcuts.getState().overrides).toEqual({});
  });
  it("updates the sheet from current assignments including disabled commands", () => {
    const groups = shortcutGroups(false, { palette: [binding("F8")], lock: [] });
    expect(groups[0].rows.find((r) => r.labelKey.endsWith("commandPalette"))?.keys).toBe("F8");
    expect(groups[0].rows.find((r) => r.labelKey.endsWith("lockInstance"))?.keysKey).toBe("keybindings.disabled");
  });
});

describe("live dispatch", () => {
  it("applies remaps immediately and releases the old key", () => {
    useShortcuts.getState().assign("lock", [binding("F8")]);
    handleAppShortcut(event("KeyL", ctrlShift), ctx);
    expect(ctx.onLock).not.toHaveBeenCalled();
    handleAppShortcut(event("F8"), ctx);
    expect(ctx.onLock).toHaveBeenCalledOnce();
  });
  it("does not execute commands while recording, locked or composing", () => {
    useShortcuts.setState({ recording: true });
    handleAppShortcut(event("KeyL", ctrlShift), ctx);
    handleTerminalShortcut(event("KeyD", ctrlShift));
    useShortcuts.setState({ recording: false });
    state.unlocked = false;
    handleAppShortcut(event("KeyL", ctrlShift), ctx);
    handleTerminalShortcut(event("KeyD", ctrlShift));
    state.unlocked = true;
    handleAppShortcut(event("KeyL", { ...ctrlShift, isComposing: true }), ctx);
    expect(ctx.onLock).not.toHaveBeenCalled();
    expect(state.splitPane).not.toHaveBeenCalled();
  });
  it("never switches sections while selecting terminal tabs", () => {
    const e = event("Digit2", ctrlShift);
    handleAppShortcut(e, ctx); handleTerminalShortcut(e);
    expect(ctx.go).not.toHaveBeenCalled();
    expect(state.setActiveTerm).toHaveBeenCalledWith("two");
  });
  it("opens one new tab and respects remapped split actions", () => {
    const e = event("KeyT", ctrlShift);
    handleAppShortcut(e, ctx); handleTerminalShortcut(e);
    expect(state.requestNewTab).toHaveBeenCalledOnce();
    expect(ctx.go).not.toHaveBeenCalled();
    useShortcuts.getState().assign("splitRight", [binding("F8")]);
    handleTerminalShortcut(event("KeyD", ctrlShift));
    expect(state.splitPane).not.toHaveBeenCalled();
    handleTerminalShortcut(event("F8"));
    expect(state.splitPane).toHaveBeenCalledWith("one", "p1", "row");
  });
  it("keeps terminal actions behind Settings and input fields inactive", () => {
    state.settingsOpen = true;
    handleTerminalShortcut(event("KeyW", ctrlShift));
    state.settingsOpen = false;
    handleTerminalShortcut(event("KeyW", { ...ctrlShift, target: { tagName: "INPUT" } as unknown as EventTarget }));
    expect(state.closePane).not.toHaveBeenCalled();
  });
  it.each(["importing", "groupsModal"] as const)("leaves %s dialogs in control", (flag) => {
    state[flag] = true;
    handleTerminalShortcut(event("KeyW", ctrlShift));
    handleAppShortcut(event("KeyN", ctrlShift), ctx);
    expect(state.closePane).not.toHaveBeenCalled();
    expect(ctx.onNewHost).not.toHaveBeenCalled();
  });
  it("does not run terminal commands behind a component-owned dialog", () => {
    dialogs.open = true;
    handleTerminalShortcut(event("KeyW", ctrlShift));
    handleTerminalShortcut(event("KeyS", ctrlShift));
    expect(state.closePane).not.toHaveBeenCalled();
    expect(openLocalTerminal).not.toHaveBeenCalled();
  });
  it("leaves a focused auth/approval dialog in control of application keys", () => {
    const target = { closest: () => ({}) } as unknown as EventTarget;
    handleAppShortcut(event("KeyN", { ...ctrlShift, target }), ctx);
    expect(ctx.onNewHost).not.toHaveBeenCalled();
  });
  it("does not repeat destructive or tab creation actions", () => {
    handleTerminalShortcut(event("KeyW", { ...ctrlShift, repeat: true }));
    handleTerminalShortcut(event("KeyT", { ...ctrlShift, repeat: true }));
    expect(state.closePane).not.toHaveBeenCalled();
    expect(state.requestNewTab).not.toHaveBeenCalled();
  });
});
