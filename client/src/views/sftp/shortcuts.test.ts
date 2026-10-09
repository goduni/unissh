import { beforeEach, describe, expect, it, vi } from "vitest";
import { binding, sanitizeOverrides, SHORTCUTS, type KeyBinding } from "@/support/keybindings";
import { shortcutAria, shortcutLabel, useShortcuts } from "@/store/shortcuts";
import type { Entry } from "@/store/sftp-types";
import { actionTargets, fileListShortcut, runFileListShortcut, type ListCursor, type ListShortcutHandler } from "./shortcuts";
import { shownNames } from "./sortfilter";

const { platform } = vi.hoisted(() => ({ platform: { mac: false } }));
vi.mock("@/bridge/platform", () => ({ isMac: () => platform.mac }));

const list = { id: "list" };
/** A key event with focus on the list itself, unless `init` says otherwise. */
function keyEvent(b: KeyBinding, init: Record<string, unknown> = {}) {
  const nativeEvent = { key: b.code, code: b.code, ctrlKey: b.ctrl, altKey: b.alt, shiftKey: b.shift, metaKey: b.meta };
  return { target: list, currentTarget: list, defaultPrevented: false, repeat: false, preventDefault: vi.fn(), nativeEvent, ...init } as unknown as Parameters<typeof runFileListShortcut>[0];
}
const press = (b: KeyBinding, init?: Record<string, unknown>) => fileListShortcut(keyEvent(b, init));
const cursor = () => ({}) as ListCursor;
const file = (name: string): Entry => ({ name, isDir: false, size: 1 });
const [a, b, c] = ["a", "b", "c"].map(file);
const slot = (filter: string, ...names: string[]) =>
  ({ entries: [a, b, c], filter, selection: new Set(names), selectedEntries: () => [a, b, c].filter((e) => names.includes(e.name)) });

beforeEach(() => {
  platform.mac = false;
  useShortcuts.setState({ overrides: {}, recording: false, storageError: false });
});

describe("file list shortcuts", () => {
  const alt = { alt: true };

  it("resolves a key to its action through the registry, user overrides included", () => {
    expect(press(binding("F2"))).toBe("rename");
    useShortcuts.setState({ overrides: { "sftp.rename": [binding("KeyR", alt)] } });
    expect(press(binding("KeyR", alt))).toBe("rename");
    expect(press(binding("F2"))).toBeNull();
  });

  it("gives every action bound on the F-row a default key off it, on each platform", () => {
    const onFRow = (k: KeyBinding) => /^F\d+$/.test(k.code);
    for (const mac of [true, false]) {
      const fRow = SHORTCUTS.filter((s) => s.scope === "sftp" && s.defaults(mac).some(onFRow));
      expect(fRow.length).toBeGreaterThan(0);
      for (const s of fRow) expect(s.defaults(mac).some((k) => !onFRow(k)), `${s.id} mac=${mac}`).toBe(true);
    }
  });

  it("ignores keys that are not the list's own", () => {
    expect(press(binding("F8"), { target: { id: "row-button" } })).toBeNull();
    expect(press(binding("F8"), { defaultPrevented: true })).toBeNull();
  });

  it("never takes Shift+Tab, so the list can always be left", () => {
    const back = binding("Tab", { shift: true });
    expect(press(back)).toBeNull();
    expect(sanitizeOverrides({ "sftp.switchPane": [back] })).toEqual({});
  });

  it("swallows a held key without running it again, except paging", () => {
    const handler = vi.fn<ListShortcutHandler>();
    const held = keyEvent(binding("F5"), { repeat: true });
    expect(runFileListShortcut(held, handler, cursor)).toBe(true);
    expect(handler).not.toHaveBeenCalled();
    expect(held.preventDefault).toHaveBeenCalledOnce();
    runFileListShortcut(keyEvent(binding("PageDown"), { repeat: true }), handler, cursor);
    expect(handler).toHaveBeenCalledWith("pageDown", expect.anything());
  });

  it("leaves a key to the browser when its handler declines it (Tab with no other list)", () => {
    const tab = keyEvent(binding("Tab"));
    expect(runFileListShortcut(tab, () => false, cursor)).toBe(true);
    expect(tab.preventDefault).not.toHaveBeenCalled();
  });

  it("applies an action to the whole selection only when its row belongs to it", () => {
    expect(actionTargets(a, slot("", "a", "b"))).toEqual([a, b]);
    expect(actionTargets(c, slot("", "a", "b"))).toEqual([c]);
    expect(actionTargets(a, slot("", "a"))).toEqual([a]);
  });

  it("on \"..\" acts on the selected entries the filter still shows, or on nothing", () => {
    expect(actionTargets(null, slot("", "a", "b"))).toEqual([a, b]);
    expect(actionTargets(null, slot("b", "a", "b"))).toEqual([b]);
    expect(actionTargets(null, slot("c", "a", "b"))).toEqual([]);
  });

  it("selects all of what the filter shows and nothing it hides", () => {
    expect(shownNames([a, b, c], " B ")).toEqual(new Set(["b"]));
    expect(shownNames([a, b, c], "")).toEqual(new Set(["a", "b", "c"]));
  });

  it("prints the key that is bound now in menus, and nothing for an unbound action", () => {
    const overrides = { "sftp.rename": [binding("KeyR", alt), binding("F2")], "sftp.delete": [] };
    expect([shortcutLabel("sftp.rename", overrides), shortcutAria("sftp.rename", overrides)]).toEqual(["Alt+R", "Alt+R F2"]);
    expect([shortcutLabel("sftp.delete", overrides), shortcutAria("sftp.delete", overrides)]).toEqual(["", undefined]);
  });
});
