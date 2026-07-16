// WCAG AA contrast gate for every shipped palette.
//
// PRODUCT.md promises AA "in every theme family and accent preset, dark and light".
// That promise had no enforcement, so it drifted: `accent` is near-ink in the mono
// family (where it reads fine as text) but saturated in nebula/candy — and text
// coloured with `accent` quietly fails there. This runs the real palettes through
// the app's own contrastRatio() so a palette or role can't regress unnoticed.
//
// Thresholds are WCAG 2.1: 4.5:1 for body text, 3:1 for large text (>=18px, or
// >=14px bold) and for UI-component/graphical boundaries.

import { describe, expect, it } from "vitest";
import {
  ACCENT_KEYS,
  contrastRatio,
  hexToRgb,
  resolveAppPalette,
  type AccentKey,
  type AppThemeFamily,
  type EffMode,
  type Palette,
} from "./tokens";

const AA_BODY = 4.5;
const AA_LARGE = 3;

/** Hue (deg) + saturation (0..1) — the axes `contrastRatio` is blind to. Without
 *  these, "is accentText still the brand colour?" cannot be asked: contrast is a
 *  luminance ratio, so a grey of the right lightness satisfies it perfectly. */
function hsv(hex: string): { h: number; s: number } {
  const [r, g, b] = hexToRgb(hex).map((x) => x / 255);
  const mx = Math.max(r, g, b);
  const d = mx - Math.min(r, g, b);
  let h = 0;
  if (d > 0) {
    if (mx === r) h = 60 * (((g - b) / d) % 6);
    else if (mx === g) h = 60 * ((b - r) / d + 2);
    else h = 60 * ((r - g) / d + 4);
  }
  return { h: (h + 360) % 360, s: mx === 0 ? 0 : d / mx };
}

/** Shortest distance between two hues on the colour wheel. */
const hueGap = (a: number, b: number): number => {
  const d = Math.abs(a - b) % 360;
  return d > 180 ? 360 - d : d;
};

/** Every palette the app can actually resolve. mono/candy own a full palette per
 *  mode and ignore the accent axis; nebula is the base+accent machinery, so only it
 *  multiplies out across the presets. */
function allPalettes(): { name: string; p: Palette }[] {
  const out: { name: string; p: Palette }[] = [];
  const modes: EffMode[] = ["light", "dark"];
  for (const mode of modes) {
    for (const family of ["mono", "candy"] as AppThemeFamily[]) {
      out.push({ name: `${family}-${mode}`, p: resolveAppPalette(family, mode) });
    }
    for (const accent of ACCENT_KEYS as AccentKey[]) {
      out.push({ name: `nebula-${mode}-${accent}`, p: resolveAppPalette("nebula", mode, accent) });
    }
  }
  return out;
}

const PALETTES = allPalettes();

describe("palette contrast (WCAG AA)", () => {
  it("resolves every shipped family x mode x accent", () => {
    // mono(2) + candy(2) + nebula(2 modes x 5 accents) = 14
    expect(PALETTES).toHaveLength(14);
  });

  describe.each(PALETTES)("$name", ({ p }) => {
    // The text ramp is the load-bearing one: these were hand-tuned per palette and
    // must not regress. txt3 is the usual casualty — it is the "muted" end.
    it.each(["txt", "txt2", "txt3"] as const)("%s reads on bg0/bg1/bg2", (role) => {
      for (const surface of ["bg0", "bg1", "bg2"] as const) {
        expect(
          contrastRatio(p[role], p[surface]),
          `${role} on ${surface}`,
        ).toBeGreaterThanOrEqual(AA_BODY);
      }
    });

    // Chrome ink: the label sitting ON a filled accent / danger button.
    it("accentInk reads on the accent fill", () => {
      expect(contrastRatio(p.accentInk ?? "#ffffff", p.accent)).toBeGreaterThanOrEqual(AA_BODY);
    });

    it("dangerInk reads on the red fill", () => {
      expect(contrastRatio(p.dangerInk ?? "#ffffff", p.red)).toBeGreaterThanOrEqual(AA_BODY);
    });

    // Status colours carry meaning (online / warning / error). They are always
    // paired with a word or shape, so they are graphical indicators, not body text.
    it.each(["green", "amber", "red"] as const)("%s is a legible indicator on bg0", (role) => {
      expect(contrastRatio(p[role], p.bg0)).toBeGreaterThanOrEqual(AA_LARGE);
    });

    // `accentText` is the AA-safe text-weight variant of the brand accent. Plain
    // `accent` is a FILL/tick colour and is not required to clear body contrast —
    // that distinction is exactly what this token exists to keep honest.
    // Every tier, including the bg3/bg4 hover/selected ones where a highlighted
    // row puts an accent label or check glyph.
    it("accentText reads as body text on every surface tier", () => {
      for (const surface of ["bg0", "bg1", "bg2", "bg3", "bg4"] as const) {
        expect(
          contrastRatio(p.accentText, p[surface]),
          `accentText on ${surface}`,
        ).toBeGreaterThanOrEqual(AA_BODY);
      }
    });

    // The other half of the token's job, and the half contrast cannot see: it must
    // still BE the brand colour. Checking this with contrastRatio is a trap — that
    // is a luminance ratio with no hue term, so a grey of the same lightness scores
    // identically to the pink it replaced. Hue and saturation are the real test.
    it("accentText keeps the accent's hue", () => {
      const a = hsv(p.accent);
      const t = hsv(p.accentText);
      // `darken` scales R/G/B uniformly, so hue is preserved exactly; 2 degrees is
      // pure 8-bit rounding slack.
      expect(hueGap(a.h, t.h), `hue ${a.h.toFixed(0)} -> ${t.h.toFixed(0)}`).toBeLessThanOrEqual(2);
    });

    it("accentText does not wash out to grey", () => {
      const a = hsv(p.accent);
      const t = hsv(p.accentText);
      // Keep at least 85% of the accent's saturation. mono is the deliberate
      // low-saturation case (its accent IS ink, S≈0.23) and passes untouched
      // because it never iterates.
      expect(t.s, `saturation ${a.s.toFixed(2)} -> ${t.s.toFixed(2)}`).toBeGreaterThanOrEqual(
        a.s * 0.85,
      );
    });
  });
});
