// termOptions() is the ONE place terminal options are built. Both the live settings
// preview and every real pane call it, which is what makes the preview honest — a
// preview constructed separately drifts, and then it is worse than none.
//
// The first test is a regression lock: the defaults must reproduce exactly what the
// app shipped before these settings existed, so turning a knob is the only way to
// change anyone's terminal.

import { describe, expect, it } from "vitest";
import {
  DEFAULT_TERM_PREFS,
  MONO,
  TERM_THEMES,
  termFontStack,
  termOptions,
  type TermPrefs,
} from "./tokens";

const THEME = TERM_THEMES[0]; // UniSSH Nebula
const prefs = (over: Partial<TermPrefs> = {}): TermPrefs => ({ ...DEFAULT_TERM_PREFS, ...over });

describe("termOptions", () => {
  it("defaults reproduce the pre-settings behaviour", () => {
    const o = termOptions(DEFAULT_TERM_PREFS, THEME, 13.5);
    expect(o.fontFamily).toBe(MONO);
    expect(o.fontSize).toBe(13.5);
    expect(o.lineHeight).toBe(1.2);
    expect(o.letterSpacing).toBe(0);
    expect(o.cursorBlink).toBe(true);
    expect(o.cursorStyle).toBe("block");
    expect(o.minimumContrastRatio).toBe(1.1);
    expect(o.drawBoldTextInBrightColors).toBe(true);
    expect(o.macOptionClickForcesSelection).toBe(true);
  });

  it("uses the theme's own colours when there is no override", () => {
    const o = termOptions(DEFAULT_TERM_PREFS, THEME, 14);
    expect(o.theme.foreground).toBe(THEME.fg);
    expect(o.theme.background).toBe(THEME.bg);
    expect(o.theme.cursor).toBe(THEME.fg);
  });

  it("the fg override recolours text and cursor but not the ANSI palette", () => {
    const o = termOptions(prefs({ fg: "#ff0000" }), THEME, 14);
    expect(o.theme.foreground).toBe("#ff0000");
    expect(o.theme.cursor).toBe("#ff0000");
    expect(o.theme.background).toBe(THEME.bg);
    expect(o.theme.green).toBe(THEME.green);
    expect(o.theme.red).toBe(THEME.red);
  });

  it("raises the contrast floor to AA when asked", () => {
    expect(termOptions(prefs({ minContrast: true }), THEME, 14).minimumContrastRatio).toBe(4.5);
  });

  it("passes cursor style and blink through", () => {
    const o = termOptions(prefs({ cursor: "bar", cursorBlink: false }), THEME, 14);
    expect(o.cursorStyle).toBe("bar");
    expect(o.cursorBlink).toBe(false);
  });
});

describe("termFontStack", () => {
  it("always ends in the bundled stack, so nothing can render in a proportional font", () => {
    for (const id of ["jetbrains", "fira", "cascadia", "sfmono", "menlo", "system"] as const) {
      expect(termFontStack(prefs({ fontId: id }))).toContain("monospace");
    }
  });

  it("quotes a custom family name", () => {
    expect(termFontStack(prefs({ fontId: "custom", fontCustom: "Iosevka Term" }))).toContain(
      "'Iosevka Term'",
    );
  });

  // An empty custom box would otherwise emit `font-family: , ui-monospace…`, which is a
  // parse error that silently drops the whole declaration.
  it("falls back to the bundled stack when the custom name is blank", () => {
    expect(termFontStack(prefs({ fontId: "custom", fontCustom: "   " }))).toBe(MONO);
  });

  // A family name is user input that lands in a CSS declaration. Anything that could
  // close the quote and inject a second property must not survive.
  it("rejects a custom name containing quotes or semicolons", () => {
    expect(termFontStack(prefs({ fontId: "custom", fontCustom: "a'; color: red; x:'" }))).toBe(
      MONO,
    );
  });
});
