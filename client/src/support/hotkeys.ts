// The chords the app claims globally, in one place because two files need them.
//
// App.tsx binds them on `window`. The terminal has to know the same set: xterm
// cancels every key it recognises with preventDefault + stopPropagation, so a
// chord it happens to recognise never reaches the window listener at all — the
// shortcut simply does nothing while the terminal has focus, which is where
// most of these are for. ViewTerminal's custom key handler returns false for
// exactly these, which makes xterm hand the event back untouched.

import { isMac } from "@/bridge/platform";

/** Keys App.tsx binds with Cmd/Ctrl. Deliberately not "every letter": ⌘A is
 *  xterm's select-all and ⌘C/⌘V are the browser's clipboard, so claiming those
 *  would trade one broken shortcut for three. */
const APP_CHORD_KEYS = new Set([
  "k", // command palette
  "n", // new host
  "t", // go to terminal
  "l", // lock
  // New local terminal, ⌘⇧S / Ctrl+Shift+S. S for shell: L is lock, and lock
  // keeps its key. Listed unqualified because this set is about which *letters*
  // the app claims — the Shift is checked where the shortcut is handled.
  "s",
  "m", // desktop/mobile preview
  "/",
  ".", // shortcuts help
  "=",
  "+",
  "-",
  "_",
  "0", // terminal zoom
  "1",
  "2",
  "3",
  "4",
  "5",
  "6",
  "7",
  "8",
  "9", // sections
]);

/** The modifier half of an app chord, without asking which key it is.
 *
 *  ⌘ on macOS; Ctrl+**Shift** everywhere else. Not a bare Ctrl: Ctrl+K, Ctrl+L
 *  and Ctrl+T are readline's kill-line, clear and transpose, and a terminal
 *  that ate them to open a palette would be a worse terminal. Same rule the
 *  find bar already uses (⌘F / Ctrl+Shift+F).
 *
 *  `mac` is a parameter rather than a call to isMac() so the rule can be tested
 *  for both platforms from one process. */
export function hasAppModifier(ev: KeyboardEvent, mac = isMac()): boolean {
  if (ev.altKey) return false;
  return mac ? ev.metaKey && !ev.ctrlKey : ev.ctrlKey && ev.shiftKey && !ev.metaKey;
}

/** ⌘, on macOS, Ctrl+, elsewhere — every desktop's own "open preferences" chord,
 *  and the one people press before looking for a menu.
 *
 *  A bare Ctrl here, not the app's usual Ctrl+Shift: with Shift held, `,` is `<`
 *  on the common layouts, so Ctrl+Shift+, is a chord nobody types and no terminal
 *  loses anything — unlike Ctrl+K/L/T, which is why the general rule exists.
 *
 *  Matched on `code` first so a Cyrillic or Dvorak layout, where `key` is not
 *  "," on that physical key, still opens Settings. */
export function opensSettings(ev: KeyboardEvent, mac = isMac()): boolean {
  if (ev.altKey || ev.shiftKey) return false;
  // The PHYSICAL key when the browser reports one, falling back to `key` only
  // when it doesn't. Matching either way would claim AZERTY's comma — which sits
  // on `code: "KeyM"` — and quietly take ⌘M's device-preview toggle with it.
  if (ev.code ? ev.code !== "Comma" : ev.key !== ",") return false;
  return mac ? ev.metaKey && !ev.ctrlKey : ev.ctrlKey && !ev.metaKey;
}

/** Whether a key event is an app-level chord the terminal must let through. */
export function isAppChord(ev: KeyboardEvent): boolean {
  // Settings carries the platform's preferences modifier rather than the app's,
  // so it is asked before the general rule would reject it.
  if (opensSettings(ev)) return true;
  if (!hasAppModifier(ev)) return false;
  return APP_CHORD_KEYS.has(ev.key.toLowerCase());
}

/** Whether a digit chord belongs to the terminal's tabs rather than to the
 *  app's sections.
 *
 *  Both listeners sit on `window` in the capture phase, and stopPropagation
 *  cannot silence a sibling on the same node — so on macOS ⌘1 used to jump to
 *  terminal tab 1 *and* route the app to Hosts, whichever ran first. App.tsx
 *  asks this before routing and stands down while the terminal is on screen.
 *
 *  Matched on `e.code`, the way useTerminalShortcuts matches it: with Shift
 *  held, `e.key` is "!@#$%^&*(" on the usual layouts. */
export function terminalOwnsTabDigits(route: string, ev: KeyboardEvent, mac = isMac()): boolean {
  return route === "terminal" && hasAppModifier(ev, mac) && /^Digit[1-9]$/.test(ev.code);
}
