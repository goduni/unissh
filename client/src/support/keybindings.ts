// One catalog for dispatch, settings, hints and the shortcut sheet. Bindings use
// physical KeyboardEvent.code so switching keyboard layouts keeps them usable.
export interface KeyBinding {
  code: string;
  ctrl: boolean;
  alt: boolean;
  shift: boolean;
  meta: boolean;
}
export type ShortcutScope = "global" | "navigation" | "terminal" | "editor";
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
export function scopesOverlap(a: ShortcutScope, b: ShortcutScope): boolean {
  return a === b || a === "global" || b === "global" || (a !== "terminal" && b !== "terminal");
}
export function conflictsFor(id: string, proposed: KeyBinding[], overrides: ShortcutOverrides, mac: boolean): ShortcutDefinition[] {
  const own = shortcutDefinition(id);
  return SHORTCUTS.filter((other) => other.id !== id && scopesOverlap(own.scope, other.scope)
    && bindingsFor(other.id, overrides, mac).some((b) => proposed.some((p) => sameBinding(b, p))));
}
const validCode = /^(Key[A-Z]|Digit[0-9]|F([1-9]|1[0-9]|2[0-4])|Arrow(Up|Down|Left|Right)|Comma|Period|Slash|Backslash|Semicolon|Quote|BracketLeft|BracketRight|Minus|Equal|Backquote|Space|Tab|Enter|Backspace|Delete|Insert|Home|End|PageUp|PageDown|Numpad[0-9]|Numpad(Add|Subtract|Multiply|Divide|Decimal|Enter))$/;
export function validBinding(b: KeyBinding): boolean {
  return validCode.test(b.code) && (b.ctrl || b.alt || b.meta || /^F\d+$/.test(b.code));
}
export function sanitizeOverrides(value: unknown): ShortcutOverrides {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  const out: ShortcutOverrides = {};
  for (const { id } of SHORTCUTS) {
    const list = (value as Record<string, unknown>)[id];
    if (!Array.isArray(list)) continue;
    if (!list.every((v) => v && typeof v === "object" && typeof v.code === "string"
      && [v.ctrl, v.alt, v.shift, v.meta].every((m) => typeof m === "boolean") && validBinding(v))) continue;
    out[id] = list.map((v) => binding(v.code, { ctrl: v.ctrl, alt: v.alt, shift: v.shift, meta: v.meta }))
      .filter((v, i, all) => all.findIndex((b) => sameBinding(v, b)) === i);
  }
  return out;
}
const keyNames: Record<string, string> = { ArrowLeft: "←", ArrowRight: "→", ArrowUp: "↑", ArrowDown: "↓", Comma: ",", Period: ".", Slash: "/", Backslash: "\\", Semicolon: ";", Quote: "'", BracketLeft: "[", BracketRight: "]", Equal: "=", Minus: "−", Backquote: "`" };
export function formatBinding(b: KeyBinding, mac: boolean): string {
  const key = keyNames[b.code] ?? b.code.replace(/^Key|^Digit/, "");
  return mac ? `${b.ctrl ? "⌃" : ""}${b.alt ? "⌥" : ""}${b.shift ? "⇧" : ""}${b.meta ? "⌘" : ""}${key}`
    : [...(b.ctrl ? ["Ctrl"] : []), ...(b.alt ? ["Alt"] : []), ...(b.shift ? ["Shift"] : []), ...(b.meta ? ["Meta"] : []), key].join("+");
}

/** WAI-ARIA uses modifier names and spaces between alternative shortcuts. */
export function ariaBinding(b: KeyBinding): string {
  const key = b.code === "Space" ? "Space" : keyNames[b.code]?.replace("−", "-") ?? b.code.replace(/^Key|^Digit/, "");
  const ariaKey = b.code.startsWith("Arrow") ? b.code : key;
  return [...(b.ctrl ? ["Control"] : []), ...(b.alt ? ["Alt"] : []), ...(b.shift ? ["Shift"] : []), ...(b.meta ? ["Meta"] : []), ariaKey].join("+");
}
