// A pane keeps its xterm instance across reconnects so scrollback survives —
// but the dead session's app may have left private DEC modes switched on
// (bracketed paste, mouse reporting, alt screen, …), and the fresh shell that
// replaces it never asked for any of them. Issue #30 is the visible symptom:
// xterm still believes bracketed paste is on, wraps every paste in ^[[200~,
// and a server whose readline never enabled the mode prints the marker as
// text. These tests drive a real (headless) Terminal, not a fake — the whole
// point is what xterm's own mode tracking does.

import { describe, expect, it } from "vitest";
import { Terminal } from "@xterm/xterm";
import { resetStaleAppModes } from "./staleModes";

const write = (term: Terminal, data: string): Promise<void> =>
  new Promise((r) => term.write(data, r));

/** What a session that died inside a TUI leaves behind. */
const MESS =
  "\x1b[?2004h" + // bracketed paste
  "\x1b[?1002h\x1b[?1006h" + // mouse drag tracking, SGR encoding
  "\x1b[?1h" + // application cursor keys
  "\x1b[?2026h" + // synchronized output (stale = output looks frozen)
  "\x1b[?25l" + // cursor hidden
  "\x1b[31m"; // dangling SGR

describe("resetStaleAppModes", () => {
  it("returns every app-owned mode to its default", async () => {
    const term = new Terminal({ allowProposedApi: true });
    await write(term, MESS + "\x1b[?1049h");
    expect(term.modes.bracketedPasteMode).toBe(true);
    expect(term.buffer.active.type).toBe("alternate");

    await resetStaleAppModes(term);

    expect(term.modes.bracketedPasteMode).toBe(false);
    expect(term.modes.mouseTrackingMode).toBe("none");
    expect(term.modes.applicationCursorKeysMode).toBe(false);
    expect(term.modes.synchronizedOutputMode).toBe(false);
    expect(term.buffer.active.type).toBe("normal");
  });

  it("leaves screen content and cursor alone — this is not term.reset()", async () => {
    const term = new Terminal({ allowProposedApi: true });
    await write(term, "abc" + MESS);

    await resetStaleAppModes(term);

    expect(term.buffer.active.getLine(0)?.translateToString(true)).toBe("abc");
    expect(term.buffer.active.cursorX).toBe(3);
    expect(term.buffer.active.type).toBe("normal");
  });
});
