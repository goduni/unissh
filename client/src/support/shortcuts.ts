// The sheet and Settings share the same live binding catalog.
import { SHORTCUTS, SHORTCUT_SCOPES, bindingsFor, formatBinding, type ShortcutOverrides } from "./keybindings";

/** One printed line: a keycap and what it does.
 *
 *  `keys` is a literal (chords are the same in every language); the mouse rows
 *  use `keysKey` instead, because their caps are words ("drag") rather than
 *  symbols. Exactly one of the two is set. */
export interface ShortcutRow {
  keys?: string;
  keysKey?: string;
  /** Interpolation for `keysKey` — the modifier that forces a selection. */
  keysVars?: Record<string, string>;
  labelKey: string;
}

export interface ShortcutGroup {
  titleKey: string;
  rows: ShortcutRow[];
}

export function shortcutGroups(mac: boolean, overrides: ShortcutOverrides = {}): ShortcutGroup[] {
  return [
    ...SHORTCUT_SCOPES.map((scope) => ({
      titleKey: `keybindings.scopes.${scope}`,
      rows: SHORTCUTS.filter((s) => s.scope === scope).map((s) => {
        const bindings = bindingsFor(s.id, overrides, mac);
        return {
          labelKey: s.labelKey,
          ...(bindings.length ? { keys: bindings.map((b) => formatBinding(b, mac)).join(" / ") } : { keysKey: "keybindings.disabled" }),
        };
      }),
    })),
    {
      // The half of issue #40 that was already implemented and undiscoverable:
      // a selection copies itself, and inside an app that has taken the mouse
      // you hold a modifier to select at all.
      titleKey: "feedback.shortcutGroup.mouse",
      rows: [
        { keysKey: "feedback.mouse.drag", labelKey: "feedback.shortcut.selectCopies" },
        {
          keysKey: "feedback.mouse.modDrag",
          keysVars: { mod: mac ? "⌥" : "⇧" },
          labelKey: "feedback.shortcut.forceSelect",
        },
        { keysKey: "feedback.mouse.rightClick", labelKey: "feedback.shortcut.paneMenu" },
      ],
    },
  ];
}
