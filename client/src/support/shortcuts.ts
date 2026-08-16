// What the cheat-sheet (⌘/ · Ctrl+Shift+/) prints, as data.
//
// A *description* of bindings implemented elsewhere — App.tsx (global chords),
// shell/useTerminalShortcuts.ts (tabs and panes), ViewTerminal's xterm key
// handler (copy/paste/find/prompt jump) and its mouse handlers. Nothing here
// binds anything; changing a binding means changing both places.
//
// Kept out of the overlay component so it can be read without mounting React —
// support/shortcuts.test.ts asserts every key below exists in both catalogs.

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

/**
 * The sheet for one platform. `mac` decides the modifier: ⌘ on macOS, Ctrl+Shift
 * elsewhere — not a bare Ctrl, which belongs to readline (see support/hotkeys).
 */
export function shortcutGroups(mac: boolean): ShortcutGroup[] {
  const mod = mac ? "⌘" : "Ctrl+Shift+";
  return [
    {
      titleKey: "feedback.shortcutGroup.global",
      rows: [
        { keys: `${mod}K`, labelKey: "feedback.shortcut.commandPalette" },
        { keys: `${mod}N`, labelKey: "feedback.shortcut.newHost" },
        // One row, not two: outside the terminal this routes there, inside it
        // useTerminalShortcuts takes the same chord for a new tab. The label
        // says both — printing ⌘T twice with two meanings would read as a bug.
        { keys: `${mod}T`, labelKey: "feedback.shortcut.goToTerminal" },
        // Carries its own Shift on macOS too: a bare ⌘S saves in the SFTP editor.
        { keys: mac ? "⌘⇧S" : "Ctrl+Shift+S", labelKey: "feedback.shortcut.localTerminal" },
        { keys: `${mod}L`, labelKey: "feedback.shortcut.lockInstance" },
        // Bare Ctrl off macOS, and NOT documented as "terminal tabs when already
        // there" the way ⌘T is. App.tsx matches sections by e.key with no e.code
        // fallback, and Shift turns a digit into "!@#$%^&*(" on the usual
        // layouts, so Ctrl+Shift+2 reaches nothing there. Inside the terminal
        // that same Ctrl+Shift+2 jumps to tab 2 (useTerminalShortcuts reads
        // e.code) — a second meaning this row deliberately does not promise.
        { keys: mac ? "⌘1–9" : "Ctrl+1–9", labelKey: "feedback.shortcut.switchSections" },
        // Bare Ctrl off macOS for the same reason: Shift+/ is "?", which neither
        // App.tsx nor APP_CHORD_KEYS accepts. A sheet that misprints the chord
        // opening the sheet is the one row nobody would forgive.
        { keys: mac ? "⌘/" : "Ctrl+/", labelKey: "feedback.shortcut.thisHelp" },
      ],
    },
    {
      titleKey: "feedback.shortcutGroup.terminal",
      rows: [
        // macOS leaves ⌘C/⌘V to the webview's native clipboard path. Elsewhere
        // Ctrl+Shift+C always copies (a bare Ctrl+C stays SIGINT unless there is
        // a selection), and paste is bound on both Ctrl+V and Ctrl+Shift+V — the
        // shorter one is printed.
        { keys: mac ? "⌘C" : "Ctrl+Shift+C", labelKey: "feedback.shortcut.copy" },
        { keys: mac ? "⌘V" : "Ctrl+V", labelKey: "feedback.shortcut.paste" },
        { keys: `${mod}F`, labelKey: "feedback.shortcut.find" },
        { keys: `${mod}D`, labelKey: "feedback.shortcut.splitRight" },
        { keys: `${mod}E`, labelKey: "feedback.shortcut.splitDown" },
        { keys: `${mod}W`, labelKey: "feedback.shortcut.closePane" },
        // Horizontal only, and that is the whole rule: ← → move between panes,
        // ↑ ↓ move between prompts. They used to be four aliases for two
        // directions, which left the prompt jump below unreachable in any split
        // tab — see paneFocusStep in shell/useTerminalShortcuts.
        { keys: `${mod}←→`, labelKey: "feedback.shortcut.focusPane" },
        { keys: "Ctrl+Tab", labelKey: "feedback.shortcut.cycleTabs" },
        // Bare Ctrl off macOS, not the Ctrl+Shift the rest of the sheet prints:
        // App.tsx binds zoom on meta||ctrl and matches by e.key, and Shift turns
        // 0 into ")" on most layouts — so Ctrl+Shift+0 would not reset anything.
        { keys: mac ? "⌘ +/−/0" : "Ctrl +/−/0", labelKey: "feedback.shortcut.termZoom" },
        // Only bound when the shell emits OSC 133 marks, hence the caveat in the
        // label — otherwise these keys keep whatever meaning the shell gives them.
        { keys: mac ? "⌘⇧↑↓" : "Ctrl+Shift+↑↓", labelKey: "feedback.shortcut.promptJump" },
      ],
    },
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
