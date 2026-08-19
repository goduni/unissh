// Two window listeners in the capture phase decide these keys between them —
// App.tsx's global chords and shell/useTerminalShortcuts' tabs and panes — and
// neither can silence the other, because stopPropagation does not reach a
// sibling on the same node. Both collisions that came out of that are pinned
// here, at the only two points where the decision is a pure function.

import { describe, expect, it } from "vitest";
import { hasAppModifier, isAppChord, opensSettings, terminalOwnsTabDigits } from "./hotkeys";
import { paneFocusStep } from "@/shell/useTerminalShortcuts";

/** A keydown event with only the fields these predicates read. */
function ev(init: { key?: string; code?: string } & Partial<Record<"metaKey" | "ctrlKey" | "shiftKey" | "altKey", boolean>>) {
  return {
    key: "",
    code: "",
    metaKey: false,
    ctrlKey: false,
    shiftKey: false,
    altKey: false,
    ...init,
  } as KeyboardEvent;
}

describe("hasAppModifier", () => {
  it("is ⌘ on macOS and Ctrl+Shift elsewhere", () => {
    expect(hasAppModifier(ev({ key: "k", metaKey: true }), true)).toBe(true);
    expect(hasAppModifier(ev({ key: "k", ctrlKey: true, shiftKey: true }), false)).toBe(true);
    // A bare Ctrl belongs to readline off macOS; ⌘ means nothing on Linux.
    expect(hasAppModifier(ev({ key: "k", ctrlKey: true }), false)).toBe(false);
    expect(hasAppModifier(ev({ key: "k", metaKey: true }), false)).toBe(false);
  });

  it("never claims a chord carrying Alt", () => {
    expect(hasAppModifier(ev({ key: "k", metaKey: true, altKey: true }), true)).toBe(false);
    expect(hasAppModifier(ev({ key: "k", ctrlKey: true, shiftKey: true, altKey: true }), false)).toBe(false);
  });

  it("still backs isAppChord's key set", () => {
    // isAppChord reads the real platform, which is "unknown" outside Tauri —
    // i.e. the non-mac rule. Both halves have to hold: modifier AND key.
    expect(isAppChord(ev({ key: "k", ctrlKey: true, shiftKey: true }))).toBe(true);
    expect(isAppChord(ev({ key: "j", ctrlKey: true, shiftKey: true }))).toBe(false);
    expect(isAppChord(ev({ key: "k", ctrlKey: true }))).toBe(false);
  });
});

describe("terminalOwnsTabDigits", () => {
  it("stands App.tsx down for ⌘1 while the terminal is on screen", () => {
    expect(terminalOwnsTabDigits("terminal", ev({ key: "1", code: "Digit1", metaKey: true }), true)).toBe(true);
  });

  it("leaves the digits to the sections everywhere else", () => {
    expect(terminalOwnsTabDigits("hosts", ev({ key: "1", code: "Digit1", metaKey: true }), true)).toBe(false);
  });

  it("reads e.code, because Shift makes e.key '!'", () => {
    const shifted = ev({ key: "!", code: "Digit1", ctrlKey: true, shiftKey: true });
    expect(terminalOwnsTabDigits("terminal", shifted, false)).toBe(true);
  });

  it("keeps a bare Ctrl+1 off macOS routing to the sections", () => {
    // The terminal never claims it (its chord needs Shift), so App.tsx must not
    // stand down — this is the one way to reach a section from the terminal there.
    expect(terminalOwnsTabDigits("terminal", ev({ key: "1", code: "Digit1", ctrlKey: true }), false)).toBe(false);
  });

  it("ignores 0 and the letters", () => {
    expect(terminalOwnsTabDigits("terminal", ev({ key: "0", code: "Digit0", metaKey: true }), true)).toBe(false);
    expect(terminalOwnsTabDigits("terminal", ev({ key: "k", code: "KeyK", metaKey: true }), true)).toBe(false);
  });
});

describe("paneFocusStep", () => {
  it("moves focus on ← and →", () => {
    expect(paneFocusStep("ArrowLeft")).toBe(-1);
    expect(paneFocusStep("ArrowRight")).toBe(1);
  });

  // The whole point of the change: ↑ ↓ have to reach xterm, where ViewTerminal
  // jumps between OSC 133 prompts. Claiming them here swallowed the jump in
  // every split tab, on both platforms.
  it("leaves ↑ and ↓ to prompt jumping", () => {
    expect(paneFocusStep("ArrowUp")).toBe(null);
    expect(paneFocusStep("ArrowDown")).toBe(null);
  });

  it("ignores everything else", () => {
    expect(paneFocusStep("a")).toBe(null);
    expect(paneFocusStep("Tab")).toBe(null);
  });
});

describe("opensSettings", () => {
  it("is ⌘, on macOS and a BARE Ctrl+, elsewhere", () => {
    expect(opensSettings(ev({ key: ",", code: "Comma", metaKey: true }), true)).toBe(true);
    expect(opensSettings(ev({ key: ",", code: "Comma", ctrlKey: true }), false)).toBe(true);
    // The app's usual Ctrl+Shift cannot be used here: Shift makes this key "<".
    expect(opensSettings(ev({ key: "<", code: "Comma", ctrlKey: true, shiftKey: true }), false)).toBe(
      false,
    );
    expect(opensSettings(ev({ key: ",", code: "Comma", ctrlKey: true }), true)).toBe(false);
    expect(opensSettings(ev({ key: ",", code: "Comma", metaKey: true }), false)).toBe(false);
  });

  it("needs a modifier, so typing a comma is still typing a comma", () => {
    expect(opensSettings(ev({ key: ",", code: "Comma" }), true)).toBe(false);
    expect(opensSettings(ev({ key: ",", code: "Comma", altKey: true, metaKey: true }), true)).toBe(
      false,
    );
  });

  it("matches the physical key, so a non-Latin layout still opens Settings", () => {
    // Cyrillic: that key reports "б", not ",".
    expect(opensSettings(ev({ key: "б", code: "Comma", metaKey: true }), true)).toBe(true);
  });

  it("counts as an app chord, so the terminal hands the keys back", () => {
    // Without this xterm would swallow the chord — the sibling-listener problem
    // hasAppModifier alone does not cover, since this one carries no Shift.
    // isAppChord reads the real platform, "unknown" (i.e. not mac) outside Tauri,
    // so the bare-Ctrl form is the one to assert here.
    expect(isAppChord(ev({ key: ",", code: "Comma", ctrlKey: true }))).toBe(true);
    expect(isAppChord(ev({ key: ",", code: "Comma" }))).toBe(false);
  });
});
