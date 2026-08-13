// Clearing what a dead session's app left switched on. A pane deliberately
// keeps its xterm across reconnects (scrollback survives), so the terminal-side
// half of every private DEC mode survives too — but the fresh shell on the
// other end starts from defaults and never asked for any of it. The mismatch
// is user-visible: stale bracketed paste wraps pastes in ^[[200~ that an old
// readline prints as text (issue #30), stale mouse tracking eats clicks, a
// stale alt screen hides the scrollback, stale synchronized output looks like
// a hang. term.reset() would fix all of that by destroying the scrollback we
// kept the terminal for; instead, write the DECRST for each app-owned mode —
// exactly what a well-behaved app would have sent on exit.

import type { Terminal } from "@xterm/xterm";

/** Resolves once xterm has processed the resets (term.write is async). */
export function resetStaleAppModes(term: Terminal): Promise<void> {
  // Leave the alternate screen first, and only when actually in it: DECRST 1049
  // also restores a saved cursor, which on the normal buffer would move the
  // cursor for no reason.
  const seq =
    (term.buffer.active.type === "alternate" ? "\x1b[?1049l" : "") +
    "\x1b[?2004l" + // bracketed paste
    "\x1b[?9l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l" + // mouse tracking + its SGR encoding
    "\x1b[?1l" + // application cursor keys
    "\x1b[?1004l" + // focus reporting
    "\x1b[?2026l" + // synchronized output
    "\x1b[4l" + // insert mode
    "\x1b[?25h" + // cursor visible again
    "\x1b[0m"; // dangling SGR attributes
  return new Promise((resolve) => term.write(seq, () => resolve()));
}
