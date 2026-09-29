// Regression checks for platform defaults and physical keyboard layouts.
import { describe, expect, it } from "vitest";
import { bindingsFor, matchesBinding } from "./keybindings";
function matches(id: string, mac: boolean, init: Partial<KeyboardEvent>): boolean {
  const e = { key: "", code: "", ctrlKey: false, altKey: false, shiftKey: false, metaKey: false, ...init } as KeyboardEvent;
  return bindingsFor(id, {}, mac).some((b) => matchesBinding(e, b));
}
for (const mac of [true, false]) describe(mac ? "macOS defaults" : "Linux/Windows defaults", () => {
  const mods = mac ? { metaKey: true } : { ctrlKey: true, shiftKey: true };
  it("keeps bare Ctrl letters for the shell", () => {
    for (const [id, code] of [["palette", "KeyK"], ["lock", "KeyL"], ["terminal", "KeyT"], ["closePane", "KeyW"], ["splitRight", "KeyD"]]) {
      expect(matches(id, mac, { code, ctrlKey: true })).toBe(false);
      expect(matches(id, mac, { code, ...mods })).toBe(true);
    }
  });
  it("matches Cyrillic and shifted digits by physical position", () => {
    expect(matches("lock", mac, { code: "KeyL", key: "Д", ...mods })).toBe(true);
    expect(matches("tab.1", mac, { code: "Digit1", key: "!", ...mods, shiftKey: true })).toBe(true);
  });
  it("never confuses horizontal pane navigation with prompt jumping", () => {
    expect(matches("panePrev", mac, { code: "ArrowLeft", ...mods })).toBe(true);
    expect(matches("panePrev", mac, { code: "ArrowUp", ...mods, shiftKey: true })).toBe(false);
    expect(matches("promptPrev", mac, { code: "ArrowUp", ...mods, shiftKey: true })).toBe(true);
  });
  it("keeps the preferences exception exact and physical", () => {
    const settingsMods = mac ? { metaKey: true } : { ctrlKey: true };
    expect(matches("settings", mac, { code: "Comma", key: "б", ...settingsMods })).toBe(true);
    expect(matches("settings", mac, { code: "Comma", ...settingsMods, shiftKey: true })).toBe(false);
    expect(matches("settings", mac, { code: "KeyM", key: ",", ...settingsMods })).toBe(false);
    expect(matches("settings", mac, { code: "Comma" })).toBe(false);
  });
});
