import { beforeEach, describe, expect, it, vi } from "vitest";
import { binding, sanitizeOverrides, type KeyBinding, type SftpAction } from "@/support/keybindings";
import { useShortcuts } from "@/store/shortcuts";
import type { Entry } from "@/store/sftp-types";
import { actionTargets, fileListShortcut, menuKeys } from "./shortcuts";

const { platform } = vi.hoisted(() => ({ platform: { mac: false } }));
vi.mock("@/bridge/platform", () => ({ isMac: () => platform.mac }));

const list = { id: "list" };
/** A key pressed with focus on the list itself, unless `init` says otherwise. */
function press(b: KeyBinding, init: Record<string, unknown> = {}) {
  const nativeEvent = { key: b.code, code: b.code, ctrlKey: b.ctrl, altKey: b.alt, shiftKey: b.shift, metaKey: b.meta };
  return fileListShortcut({ target: list, currentTarget: list, defaultPrevented: false, nativeEvent, ...init } as unknown as Parameters<typeof fileListShortcut>[0]);
}
const file = (name: string): Entry => ({ name, isDir: false, size: 1 });

beforeEach(() => {
  platform.mac = false;
  useShortcuts.setState({ overrides: {}, recording: false, storageError: false });
});

describe("file list shortcuts", () => {
  const alt = { alt: true };
  it.each<[string, KeyBinding, SftpAction, boolean?]>([
    ["Tab", binding("Tab"), "switchPane"],
    ["Backspace", binding("Backspace"), "parentDir"],
    ["Ctrl+A", binding("KeyA", { ctrl: true }), "selectAll"],
    ["⌘A", binding("KeyA", { meta: true }), "selectAll", true],
    ["PageUp", binding("PageUp"), "pageUp"],
    ["PageDown", binding("PageDown"), "pageDown"],
    ["F2", binding("F2"), "rename"],
    ["Shift+F6", binding("F6", { shift: true }), "rename"],
    ["Alt+2", binding("Digit2", alt), "rename"],
    ["F3", binding("F3"), "edit"],
    ["Alt+3", binding("Digit3", alt), "edit"],
    ["F4", binding("F4"), "edit"],
    ["Alt+4", binding("Digit4", alt), "edit"],
    ["F5", binding("F5"), "copy"],
    ["Alt+5", binding("Digit5", alt), "copy"],
    ["F7", binding("F7"), "newFolder"],
    ["Alt+7", binding("Digit7", alt), "newFolder"],
    ["F8", binding("F8"), "delete"],
    ["Delete", binding("Delete"), "delete"],
    ["Alt+8", binding("Digit8", alt), "delete"],
    ["⌘⌫", binding("Backspace", { meta: true }), "delete", true],
  ])("binds %s by default", (_keys, key, action, mac = false) => {
    platform.mac = mac;
    expect(press(key)).toBe(action);
  });

  it("ignores keys that are not the list's own", () => {
    expect(press(binding("F8"), { target: { id: "row-button" } })).toBeNull();
    expect(press(binding("F8"), { defaultPrevented: true })).toBeNull();
    useShortcuts.setState({ recording: true });
    expect(press(binding("F8"))).toBeNull();
  });

  it("never takes Shift+Tab, so the list can always be left", () => {
    const back = binding("Tab", { shift: true });
    expect(press(back)).toBeNull();
    expect(sanitizeOverrides({ "sftp.switchPane": [back] })).toEqual({});
  });

  it("applies an action to the whole selection only when its row belongs to it", () => {
    const [a, b, c] = ["a", "b", "c"].map(file);
    const slot = (...names: string[]) => ({ selection: new Set(names), selectedEntries: () => [a, b, c].filter((e) => names.includes(e.name)) });
    expect(actionTargets(a, slot("a", "b"))).toEqual([a, b]);
    expect(actionTargets(c, slot("a", "b"))).toEqual([c]);
    expect(actionTargets(a, slot("a"))).toEqual([a]);
    expect(actionTargets(null, slot("a", "b"))).toEqual([a, b]);
    expect(actionTargets(null, slot())).toEqual([]);
  });

  it("prints the key that is bound now in menus, and nothing for an unbound action", () => {
    expect(menuKeys("rename", { "sftp.rename": [binding("KeyR", alt), binding("F2")] })).toEqual({ keys: "Alt+R", ariaKeys: "Alt+R F2" });
    expect(menuKeys("rename", { "sftp.rename": [] })).toEqual({});
  });
});
