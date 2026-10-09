// One catalog for dispatch, settings, hints and the shortcut sheet. Bindings use
// physical KeyboardEvent.code so switching keyboard layouts keeps them usable.
export interface KeyBinding {
  code: string;
  ctrl: boolean;
  alt: boolean;
  shift: boolean;
  meta: boolean;
}
/** Display order of the scopes in Settings and on the shortcut sheet. */
export const SHORTCUT_SCOPES = ["global", "navigation", "terminal", "editor", "sftp"] as const;
export type ShortcutScope = typeof SHORTCUT_SCOPES[number];
export interface ShortcutDefinition {
  id: string;
  labelKey: string;
  scope: ShortcutScope;
  defaults: (mac: boolean) => KeyBinding[];
}
export type ShortcutOverrides = Record<string, KeyBinding[]>;
export const binding = (code: string, mods: Partial<Omit<KeyBinding, "code">> = {}): KeyBinding =>
  ({ code, ctrl: false, alt: false, shift: false, meta: false, ...mods });
const app = (code: string) => (mac: boolean) => [binding(code, mac ? { meta: true } : { ctrl: true, shift: true })];
// Preserve the existing shifted macOS aliases, but represent them explicitly so
// recording and conflict detection agree on the exact modifier set.
const legacyApp = (code: string) => (mac: boolean) => mac
  ? [binding(code, { meta: true }), binding(code, { meta: true, shift: true })] : app(code)(false);
const def = (id: string, labelKey: string, scope: ShortcutScope, defaults: ShortcutDefinition["defaults"]): ShortcutDefinition =>
  ({ id, labelKey, scope, defaults });
const label = (name: string) => `feedback.shortcut.${name}`;
// File-list actions, orthodox file manager style. Each F-key action also answers
// to Alt+<the same digit>, because the F-row needs Fn on macOS and is often
// remapped on laptops. An entry here is the whole registration: Settings, the
// sheet and menu hints read it, and ViewSftp must supply a handler of the same name.
const fkeys = (digits: number[], ...extra: KeyBinding[]) => () =>
  [...digits.map((n) => binding(`F${n}`)), ...extra, ...digits.map((n) => binding(`Digit${n}`, { alt: true }))];
// Each entry: the label (the menu item's own string where the action has one)
// and the default keys.
const SFTP_SHORTCUTS = {
  switchPane: ["keybindings.actions.sftpSwitchPane", () => [binding("Tab")]],
  parentDir: ["keybindings.actions.sftpParentDir", () => [binding("Backspace")]],
  selectAll: ["keybindings.actions.sftpSelectAll", (mac) => [binding("KeyA", mac ? { meta: true } : { ctrl: true })]],
  pageUp: ["keybindings.actions.sftpPageUp", () => [binding("PageUp")]],
  pageDown: ["keybindings.actions.sftpPageDown", () => [binding("PageDown")]],
  rename: ["sftp.menu.rename", fkeys([2], binding("F6", { shift: true }))],
  // View (F3) and edit (F4) are one action: the built-in editor has no read-only mode.
  edit: ["sftp.menu.openInApp", fkeys([4, 3])],
  copy: ["sftp.send", fkeys([5])],
  move: ["sftp.move", fkeys([6])],
  newFolder: ["sftp.menu.newFolder", fkeys([7])],
  // A Mac laptop has no Delete key without Fn either; ⌘⌫ is what Finder uses.
  delete: ["sftp.menu.delete", (mac) => [...fkeys([8], binding("Delete"))(), ...(mac ? [binding("Backspace", { meta: true })] : [])]],
  // Alt+Enter is "properties" in every desktop file manager, and the size of a
  // folder is the property this answers. Never Space: that key selects.
  folderSize: ["sftp.menu.folderSize", (mac) => [binding("Enter", { alt: true }), binding("Enter", mac ? { meta: true, shift: true } : { ctrl: true, shift: true })]],
} satisfies Record<string, [labelKey: string, defaults: ShortcutDefinition["defaults"]]>;
export type SftpAction = keyof typeof SFTP_SHORTCUTS;
export const SFTP_ACTIONS = Object.keys(SFTP_SHORTCUTS) as SftpAction[];
export const sftpShortcutId = (action: SftpAction) => `sftp.${action}`;
export const SHORTCUTS: ShortcutDefinition[] = [
  def("palette", label("commandPalette"), "global", legacyApp("KeyK")),
  def("newHost", label("newHost"), "global", legacyApp("KeyN")),
  def("terminal", label("goToTerminal"), "global", legacyApp("KeyT")),
  def("localTerminal", label("localTerminal"), "global", (mac) => [binding("KeyS", mac ? { meta: true, shift: true } : { ctrl: true, shift: true })]),
  def("lock", label("lockInstance"), "global", legacyApp("KeyL")),
  def("settings", label("openSettings"), "global", (mac) => [binding("Comma", mac ? { meta: true } : { ctrl: true })]),
  def("help", "keybindings.showHelp", "global", (mac) => [...legacyApp("Slash")(mac), ...legacyApp("Period")(mac)]),
  def("device", "keybindings.actions.device", "global", legacyApp("KeyM")),
  def("zoomIn", "keybindings.actions.zoomIn", "global", legacyApp("Equal")),
  def("zoomOut", "keybindings.actions.zoomOut", "global", legacyApp("Minus")),
  def("zoomReset", "keybindings.actions.zoomReset", "global", legacyApp("Digit0")),
  ...["hosts", "terminal", "fleet", "broadcast", "sftp", "tunnels", "known", "recordings", "snippets"].map((route, i) =>
    def(`nav.${route}`, `nav.${route === "hosts" ? "allHosts" : route}`, "navigation", legacyApp(`Digit${i + 1}`))),
  ...Array.from({ length: 9 }, (_, i) => def(`tab.${i + 1}`, `keybindings.actions.tab${i + 1}`, "terminal", legacyApp(`Digit${i + 1}`))),
  def("closePane", label("closePane"), "terminal", legacyApp("KeyW")),
  def("splitRight", label("splitRight"), "terminal", legacyApp("KeyD")),
  def("splitDown", label("splitDown"), "terminal", legacyApp("KeyE")),
  def("panePrev", "keybindings.actions.panePrev", "terminal", legacyApp("ArrowLeft")),
  def("paneNext", "keybindings.actions.paneNext", "terminal", legacyApp("ArrowRight")),
  def("tabNext", "keybindings.actions.tabNext", "terminal", () => [binding("Tab", { ctrl: true })]),
  def("tabPrev", "keybindings.actions.tabPrev", "terminal", () => [binding("Tab", { ctrl: true, shift: true })]),
  def("find", label("find"), "terminal", legacyApp("KeyF")),
  def("promptPrev", "keybindings.actions.promptPrev", "terminal", (mac) => [binding("ArrowUp", mac ? { meta: true, shift: true } : { ctrl: true, shift: true })]),
  def("promptNext", "keybindings.actions.promptNext", "terminal", (mac) => [binding("ArrowDown", mac ? { meta: true, shift: true } : { ctrl: true, shift: true })]),
  def("copy", label("copy"), "terminal", app("KeyC")),
  def("copySelection", "keybindings.actions.copySelection", "terminal", (mac) => mac ? [] : [binding("KeyC", { ctrl: true })]),
  def("paste", label("paste"), "terminal", (mac) => mac ? [binding("KeyV", { meta: true })] : [binding("KeyV", { ctrl: true }), binding("KeyV", { ctrl: true, shift: true })]),
  def("editorSave", "keybindings.actions.editorSave", "editor", (mac) => [binding("KeyS", mac ? { meta: true } : { ctrl: true })]),
  ...SFTP_ACTIONS.map((action) => def(sftpShortcutId(action), SFTP_SHORTCUTS[action][0], "sftp", SFTP_SHORTCUTS[action][1])),
];
export const shortcutDefinition = (id: string) => SHORTCUTS.find((s) => s.id === id)!;
export function bindingsFor(id: string, overrides: ShortcutOverrides, mac: boolean): KeyBinding[] {
  return overrides[id] ?? shortcutDefinition(id).defaults(mac);
}
export function sameBinding(a: KeyBinding, b: KeyBinding): boolean {
  return a.code === b.code && a.ctrl === b.ctrl && a.alt === b.alt && a.shift === b.shift && a.meta === b.meta;
}
export function eventBinding(e: Pick<KeyboardEvent, "code" | "key" | "ctrlKey" | "altKey" | "shiftKey" | "metaKey">): KeyBinding {
  const fallback: Record<string, string> = { ",": "Comma", "/": "Slash", ".": "Period", "=": "Equal", "+": "Equal", "-": "Minus", "_": "Minus", " ": "Space" };
  const key = e.key.toUpperCase();
  const code = e.code || (/^[A-Z]$/.test(key) ? `Key${key}` : /^\d$/.test(key) ? `Digit${key}` : fallback[e.key] ?? e.key);
  return binding(code, { ctrl: e.ctrlKey, alt: e.altKey, shift: e.shiftKey, meta: e.metaKey });
}
export function matchesBinding(e: KeyboardEvent, b: KeyBinding): boolean {
  return !e.isComposing && !e.getModifierState?.("AltGraph") && sameBinding(eventBinding(e), b);
}
// Two scopes conflict only if both can be live at once. The terminal owns its
// route, and the SFTP editor covers the file lists it was opened from.
export function scopesOverlap(a: ShortcutScope, b: ShortcutScope): boolean {
  if (a === b || a === "global" || b === "global") return true;
  return a !== "terminal" && b !== "terminal" && (a === "navigation" || b === "navigation");
}
export function conflictsFor(id: string, proposed: KeyBinding[], overrides: ShortcutOverrides, mac: boolean): ShortcutDefinition[] {
  const own = shortcutDefinition(id);
  return SHORTCUTS.filter((other) => other.id !== id && scopesOverlap(own.scope, other.scope)
    && bindingsFor(other.id, overrides, mac).some((b) => proposed.some((p) => sameBinding(b, p))));
}
const validCode = /^(Key[A-Z]|Digit[0-9]|F([1-9]|1[0-9]|2[0-4])|Arrow(Up|Down|Left|Right)|Comma|Period|Slash|Backslash|Semicolon|Quote|BracketLeft|BracketRight|Minus|Equal|Backquote|Space|Tab|Enter|Backspace|Delete|Insert|Home|End|PageUp|PageDown|Numpad[0-9]|Numpad(Add|Subtract|Multiply|Divide|Decimal|Enter))$/;
// A focused file list takes no text, so there these keys may stand alone. Tab
// only unshifted: Shift+Tab is the keyboard's way back out of the list.
const bareListKey = /^(Tab|Backspace|Delete|Insert|PageUp|PageDown)$/;
export function validBinding(b: KeyBinding, scope?: ShortcutScope): boolean {
  return validCode.test(b.code) && (b.ctrl || b.alt || b.meta || /^F\d+$/.test(b.code)
    || (scope === "sftp" && bareListKey.test(b.code) && !(b.code === "Tab" && b.shift)));
}
export function sanitizeOverrides(value: unknown): ShortcutOverrides {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  const out: ShortcutOverrides = {};
  for (const { id, scope } of SHORTCUTS) {
    const list = (value as Record<string, unknown>)[id];
    if (!Array.isArray(list)) continue;
    if (!list.every((v) => v && typeof v === "object" && typeof v.code === "string"
      && [v.ctrl, v.alt, v.shift, v.meta].every((m) => typeof m === "boolean") && validBinding(v, scope))) continue;
    out[id] = list.map((v) => binding(v.code, { ctrl: v.ctrl, alt: v.alt, shift: v.shift, meta: v.meta }))
      .filter((v, i, all) => all.findIndex((b) => sameBinding(v, b)) === i);
  }
  return out;
}
const keyNames: Record<string, string> = { ArrowLeft: "←", ArrowRight: "→", ArrowUp: "↑", ArrowDown: "↓", Comma: ",", Period: ".", Slash: "/", Backslash: "\\", Semicolon: ";", Quote: "'", BracketLeft: "[", BracketRight: "]", Equal: "=", Minus: "−", Backquote: "`" };
// Printed names only: aria-keyshortcuts wants these codes exactly as they are.
const editKeyNames: Record<string, [mac: string, other: string]> = { Backspace: ["⌫", "Backspace"], Delete: ["⌦", "Delete"], PageUp: ["⇞", "PgUp"], PageDown: ["⇟", "PgDn"] };
export function formatBinding(b: KeyBinding, mac: boolean): string {
  const key = keyNames[b.code] ?? editKeyNames[b.code]?.[mac ? 0 : 1] ?? b.code.replace(/^Key|^Digit/, "");
  return mac ? `${b.ctrl ? "⌃" : ""}${b.alt ? "⌥" : ""}${b.shift ? "⇧" : ""}${b.meta ? "⌘" : ""}${key}`
    : [...(b.ctrl ? ["Ctrl"] : []), ...(b.alt ? ["Alt"] : []), ...(b.shift ? ["Shift"] : []), ...(b.meta ? ["Meta"] : []), key].join("+");
}

/** WAI-ARIA uses modifier names and spaces between alternative shortcuts. */
export function ariaBinding(b: KeyBinding): string {
  const key = b.code === "Space" ? "Space" : keyNames[b.code]?.replace("−", "-") ?? b.code.replace(/^Key|^Digit/, "");
  const ariaKey = b.code.startsWith("Arrow") ? b.code : key;
  return [...(b.ctrl ? ["Control"] : []), ...(b.alt ? ["Alt"] : []), ...(b.shift ? ["Shift"] : []), ...(b.meta ? ["Meta"] : []), ariaKey].join("+");
}
