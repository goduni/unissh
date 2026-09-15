import { beforeEach, describe, expect, it, vi } from "vitest";
import { handleAppShortcut } from "./appShortcuts";
import { isAppChord } from "./hotkeys";

const { state, platform } = vi.hoisted(() => ({
  platform: { mac: false },
  state: {
    unlocked: true, route: "terminal", settingsOpen: false, palette: false,
    shortcuts: false, device: "desktop",
    setSettingsOpen: vi.fn(), go: vi.fn(), setPalette: vi.fn(),
    setShortcuts: vi.fn(), setDevice: vi.fn(), bumpTermZoom: vi.fn(), resetTermZoom: vi.fn(),
  },
}));
vi.mock("@/store/app", () => ({ useApp: { getState: () => state } }));
vi.mock("@/bridge/platform", () => ({ isMac: () => platform.mac }));

const ctx = { go: vi.fn(), onNewHost: vi.fn(), onLock: vi.fn() };
function event(key: string, code: string, mods: Partial<KeyboardEvent> = {}) {
  return { key, code, ctrlKey: false, metaKey: false, shiftKey: false, altKey: false,
    preventDefault: vi.fn(), ...mods } as unknown as KeyboardEvent;
}

beforeEach(() => { vi.clearAllMocks(); state.route = "terminal"; state.unlocked = true; });

for (const os of ["windows", "linux", "macos"]) {
  describe(os, () => {
    beforeEach(() => { platform.mac = os === "macos"; });

    it.each("abcdefghijklmnopqrstuvwxyz".split(""))("leaves bare Ctrl+%s to the terminal", (key) => {
      const e = event(key, `Key${key.toUpperCase()}`, { ctrlKey: true });
      handleAppShortcut(e, ctx);
      expect(e.preventDefault).not.toHaveBeenCalled();
      expect(ctx.onLock).not.toHaveBeenCalled();
      expect(isAppChord(e)).toBe(false);
    });

    it("locks only with the platform application modifier", () => {
      const e = event("L", "KeyL", platform.mac ? { metaKey: true } : { ctrlKey: true, shiftKey: true });
      handleAppShortcut(e, ctx);
      expect(ctx.onLock).toHaveBeenCalledOnce();
      expect(e.preventDefault).toHaveBeenCalledOnce();
      expect(isAppChord(e)).toBe(true);
    });

    it("leaves Alt/AltGr combinations alone", () => {
      const e = event("l", "KeyL", { ctrlKey: true, shiftKey: true, altKey: true, metaKey: platform.mac });
      handleAppShortcut(e, ctx);
      expect(e.preventDefault).not.toHaveBeenCalled();
    });

    it("keeps Settings' explicit preferences exception, except while locked", () => {
      const mods = platform.mac ? { metaKey: true } : { ctrlKey: true };
      handleAppShortcut(event(",", "Comma", mods), ctx);
      expect(state.go).toHaveBeenCalledWith("settings");
      state.unlocked = false;
      const locked = event(",", "Comma", mods);
      handleAppShortcut(locked, ctx);
      expect(locked.preventDefault).not.toHaveBeenCalled();
    });

    it("handles shifted help/zoom/digits and non-Latin letters consistently with xterm", () => {
      const mods = platform.mac ? { metaKey: true, shiftKey: true } : { ctrlKey: true, shiftKey: true };
      for (const [key, code] of [["?", "Slash"], [")", "Digit0"], ["!", "Digit1"], ["Д", "KeyL"]]) {
        const e = event(key, code, mods);
        state.route = "hosts";
        handleAppShortcut(e, ctx);
        expect(e.preventDefault, code).toHaveBeenCalled();
        expect(isAppChord(e), code).toBe(true);
      }
      expect(state.setShortcuts).toHaveBeenCalled();
      expect(state.resetTermZoom).toHaveBeenCalled();
      expect(ctx.go).toHaveBeenCalledWith("hosts");
      expect(ctx.onLock).toHaveBeenCalled();
    });

    it("does not route away from the terminal when switching tabs", () => {
      const e = event("!", "Digit1", platform.mac ? { metaKey: true } : { ctrlKey: true, shiftKey: true });
      handleAppShortcut(e, ctx);
      expect(ctx.go).not.toHaveBeenCalled();
    });
  });
}
