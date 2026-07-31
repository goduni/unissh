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

/** Whether a key event is an app-level chord the terminal must let through.
 *
 *  ⌘ on macOS; Ctrl+**Shift** everywhere else. Not a bare Ctrl: Ctrl+K, Ctrl+L
 *  and Ctrl+T are readline's kill-line, clear and transpose, and a terminal
 *  that ate them to open a palette would be a worse terminal. Same rule the
 *  find bar already uses (⌘F / Ctrl+Shift+F). */
export function isAppChord(ev: KeyboardEvent): boolean {
  if (ev.altKey) return false;
  const modifier = isMac() ? ev.metaKey && !ev.ctrlKey : ev.ctrlKey && ev.shiftKey;
  if (!modifier) return false;
  return APP_CHORD_KEYS.has(ev.key.toLowerCase());
}
