// The interface-scale contract.
//
// This feature is a broad, mechanical migration of ~550 inline pixel sizes to
// `rem`, and the promise that makes it safe to land is a narrow one: at 100 %
// nothing moves. That promise is what these tests hold. They deliberately assert
// the CONTRACT — a stored value resolves to the right root size, every type token
// round-trips to the pixel it was before, the accessibility floors do not follow
// the scale down — and not how any component looks, because there is no
// component-rendering harness here and this feature is not the place to add one.
// Visual correctness is checked by eye, per area, against a 100 % baseline.

import { describe, expect, it } from "vitest";
import {
  DEFAULT_UI_SCALE,
  detectUiScale,
  HAIRLINE,
  nearestUiScale,
  rem,
  ROOT_FONT_PX,
  rootFontPx,
  sanitizeUiScale,
  SIZE,
  TEXT,
  TEXT_PX,
  UI_SCALES,
  type UiScale,
} from "./tokens";

/** What a token is worth on screen at a given scale. The whole point of the
 *  px/rem split is that this function behaves differently for the two: a `rem`
 *  length follows the root font size, a bare number is device pixels and does
 *  not. Everything below is really an assertion about which side a token is on. */
function cssPxAt(value: string | number, scale: UiScale): number {
  if (typeof value === "number") return value;
  const m = /^(-?[\d.]+)rem$/.exec(value);
  if (!m) throw new Error(`not a rem length: ${value}`);
  return Number(m[1]) * rootFontPx(scale);
}

describe("interface scale — stored value → root font size", () => {
  it("maps every offered step to its root size", () => {
    expect(UI_SCALES.map(rootFontPx)).toEqual([14.4, 16, 17.6, 20, 24]);
  });

  it("is the browser default at 100 %, so an untouched app is untouched", () => {
    expect(rootFontPx(DEFAULT_UI_SCALE)).toBe(ROOT_FONT_PX);
    expect(ROOT_FONT_PX).toBe(16);
  });

  it("round-trips every offered step through storage", () => {
    for (const s of UI_SCALES) expect(sanitizeUiScale(String(s))).toBe(s);
  });

  it.each([
    ["unknown", "175"],
    ["a value from a schema this build does not know", "200"],
    ["empty", ""],
    ["hand-edited nonsense", "big"],
    ["a stale word from another axis", "compact"],
    ["null", null],
    ["undefined", undefined],
    ["an object", { scale: 125 }],
    ["a float between steps", 112.5],
    ["negative", -100],
    ["zero", 0],
    ["NaN", NaN],
    ["Infinity", Infinity],
  ])("falls back to 100 %% for %s", (_label, raw) => {
    expect(sanitizeUiScale(raw)).toBe(100);
  });

  it("never yields a root size that could strand the user", () => {
    // The failure this guards is specific: this value becomes the document's
    // font-size, so a 0 or a NaN is an interface with no way back to Settings.
    for (const raw of ["", "0", "NaN", "-1", "1e9", "125px", "{}"]) {
      const px = rootFontPx(sanitizeUiScale(raw));
      expect(px).toBeGreaterThanOrEqual(14.4);
      expect(px).toBeLessThanOrEqual(24);
    }
  });
});

describe("interface scale — first-launch detection", () => {
  // The input is the gap between what the desktop asked for and what the webview
  // actually applied — NOT the raw scale factor. Every "agreed" case below is a
  // machine where the interface is already the right physical size.
  it.each([
    ["standard-DPI desktop", 1, 1],
    ["Retina Mac (webview already at 2x)", 2, 2],
    ["Windows at 150 % (webview already at 1.5x)", 1.5, 1.5],
    ["a fractional 1.25 the webview honoured", 1.25, 1.25],
  ])("leaves %s at 100 %%", (_label, factor, dpr) => {
    expect(detectUiScale(factor, dpr)).toBe(100);
  });

  it.each([
    ["1.25 asked, 1 applied", 1.25, 1, 125],
    ["1.5 asked, 1 applied", 1.5, 1, 150],
    ["2 asked, 1 applied — capped at the largest step", 2, 1, 150],
    ["1.1 asked, 1 applied", 1.1, 1, 110],
    ["2 asked, 1.5 applied", 2, 1.5, 125],
    ["1.75 asked, 1 applied — nearest step", 1.75, 1, 150],
  ])("corrects %s", (_label, factor, dpr, want) => {
    expect(detectUiScale(factor, dpr)).toBe(want);
  });

  it("never shrinks an interface nobody complained about", () => {
    // A webview reporting MORE than the desktop asked for is not an invitation to
    // make the type smaller than the default; 90 % is a choice, never a guess.
    for (const [factor, dpr] of [
      [1, 2],
      [1, 1.5],
      [1.5, 2],
    ]) {
      expect(detectUiScale(factor, dpr)).toBe(100);
    }
  });

  it.each([
    ["zero factor", 0, 1],
    ["zero ratio", 1.5, 0],
    ["negative", -2, 1],
    ["NaN", NaN, 1],
    ["Infinity", Infinity, 1],
    ["missing ratio", 1.5, NaN],
  ])("falls back to 100 %% on %s", (_label, factor, dpr) => {
    expect(detectUiScale(factor, dpr)).toBe(100);
  });

  it("snaps to an offered step and only ever an offered step", () => {
    for (let pct = 50; pct <= 300; pct += 1) {
      expect(UI_SCALES).toContain(nearestUiScale(pct));
    }
  });

  it("resolves ties towards the larger step", () => {
    // Erring small on a display that is already too small reproduces the report.
    expect(nearestUiScale(95)).toBe(100);
    expect(nearestUiScale(105)).toBe(110);
    expect(nearestUiScale(117.5)).toBe(125);
    expect(nearestUiScale(137.5)).toBe(150);
  });
});

describe("type scale", () => {
  // The golden list. Spelled out here rather than derived from TEXT_PX on
  // purpose: this is the assertion that the migration is invisible, so it has to
  // fail when someone "improves" a step, not follow them.
  const PIXELS_AT_100 = {
    micro: 11,
    small: 12,
    base: 13,
    body: 14,
    lead: 16,
    h3: 19,
    h2: 24,
    h1: 28,
  } as const;

  it("has a rem twin for every role and no more", () => {
    expect(Object.keys(TEXT).sort()).toEqual(Object.keys(PIXELS_AT_100).sort());
    expect(Object.keys(TEXT_PX).sort()).toEqual(Object.keys(PIXELS_AT_100).sort());
  });

  it.each(Object.entries(PIXELS_AT_100))("%s is still %dpx at 100 %%", (role, px) => {
    expect(cssPxAt(TEXT[role as keyof typeof TEXT], 100)).toBe(px);
    expect(TEXT_PX[role as keyof typeof TEXT_PX]).toBe(px);
  });

  it("scales every role with the root, and exactly", () => {
    for (const scale of UI_SCALES) {
      for (const [role, px] of Object.entries(PIXELS_AT_100)) {
        const got = cssPxAt(TEXT[role as keyof typeof TEXT], scale);
        expect(got, `${role} at ${scale}%`).toBeCloseTo((px * scale) / 100, 10);
      }
    }
  });

  it("expresses every step without a repeating fraction", () => {
    // Design pixels divide into 16, so the rem string is exact and nothing is
    // left to a browser's rounding. A step that broke this (say 13.3) would land
    // differently in two engines.
    for (const px of Object.values(TEXT_PX)) {
      expect(rem(px)).toMatch(/^\d+(\.\d{1,6})?rem$/);
    }
  });

  it("converts halves exactly too — the off-scale sizes the migration preserves", () => {
    // 10.5 / 11.5 / 12.5 exist in a handful of places and must round-trip
    // unchanged; snapping them to a token would be a typography redesign, which
    // this is not.
    for (const px of [10.5, 11.5, 12.5, 13.5]) {
      expect(cssPxAt(rem(px), 100)).toBe(px);
    }
  });
});

describe("floors that must not follow the scale", () => {
  it("keeps the touch minimum at 44 CSS px at every scale", () => {
    // WCAG 2.5.5. As a `rem` this would be 39.6px at 90 % — on the one setting a
    // user picks precisely to fit more on screen, i.e. exactly when they can
    // least afford a smaller target.
    for (const scale of UI_SCALES) expect(cssPxAt(SIZE.tapMin, scale)).toBe(44);
  });

  it("keeps hairlines one device pixel at every scale", () => {
    for (const scale of UI_SCALES) expect(cssPxAt(HAIRLINE, scale)).toBe(1);
  });

  it("states both floors in device pixels, not rem", () => {
    // The unit IS the contract here, so assert it directly: a later edit turning
    // either into a rem string would pass every numeric check above.
    expect(typeof SIZE.tapMin).toBe("number");
    expect(typeof HAIRLINE).toBe("number");
  });
});

// ── Migration guard ────────────────────────────────────────────
// A scan, not a render: the areas already migrated must not quietly grow a new
// hard-coded pixel type size. The list is explicit and grows as stages land —
// that keeps the guard's scope legible and keeps it from failing on code nobody
// has migrated yet.
//
// Deliberately NOT the whole tree: the mobile shell is out of scope by design
// (phones scale through the OS), so a numeric size there is correct, not debt.
//
// `?raw` through Vite rather than node:fs, for the reason spelled out in
// src/vite-env.d.ts: @types/node would make `process` and `Buffer` typecheck
// everywhere in src, and neither exists inside a Tauri webview.
const SOURCES = import.meta.glob("../**/*.tsx", {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;

const MIGRATED_AREAS: string[] = [
  // Shared primitives — these carry most of the app's type on their own.
  "../components/LogoMark.tsx",
  "../components/mono.tsx",
  "../components/primitives.tsx",
  // Shell and title bar.
  "../App.tsx",
  "../components/ContextMenu.tsx",
  "../components/Modal.tsx",
  "../components/ReconnectBanner.tsx",
  "../components/UpdateBanner.tsx",
  "../shell/Shell.tsx",
  "../shell/WindowChrome.tsx",
  // Hosts view and host picker.
  "../views/ViewHosts.tsx",
  "../views/sftp/hostpicker.tsx",
  // Settings.
  "../overlays/SettingsOverlay.tsx",
  "../views/ServerVaultsSection.tsx",
  "../views/SettingsSupport.tsx",
  "../views/ViewSettings.tsx",
  // SFTP.
  "../views/sftp/Breadcrumb.tsx",
  "../views/sftp/ExternalEdits.tsx",
  "../views/sftp/FileList.tsx",
  "../views/sftp/FileRow.tsx",
  "../views/sftp/PaneSlot.tsx",
  "../views/sftp/TabStrip.tsx",
  "../views/sftp/TextEditor.tsx",
  "../views/sftp/TransferQueue.tsx",
  "../views/sftp/ViewSftp.tsx",
  "../views/sftp/dialogs.tsx",
  "../views/sftp/volumes.tsx",
];

describe("migrated areas keep their type sizes scalable", () => {
  it("names files that exist", () => {
    // A typo in the list would silently scan nothing and pass forever.
    for (const rel of MIGRATED_AREAS) expect(Object.keys(SOURCES)).toContain(rel);
  });

  it.each(MIGRATED_AREAS)("%s has no numeric fontSize", (rel) => {
    const src = SOURCES[rel];
    // The style-object form only. `fontSize={13}` on a primitive, and a
    // `fontSize = 13.5` default parameter, are DESIGN pixels that the primitive
    // itself converts — those are the convention, not the debt.
    const hits = [...src.matchAll(/fontSize:\s*-?\d/g)].map(
      (m) => `line ${src.slice(0, m.index).split("\n").length}`,
    );
    expect(hits, `${rel}: use TEXT.* or rem(px) instead of a pixel number`).toEqual([]);
  });
});
