// Responsive helpers. The phone shell is selected by the `device` flag (set on
// iOS/Android at boot, or via the desktop⇄mobile preview toggle). Embedded
// desktop views read this to switch to single-column, touch-friendly layouts
// instead of their fixed-width desktop grids/tables.

import { useEffect, useState } from "react";
import { useApp } from "./app";
import { isDesktopOs } from "@/bridge/platform";
import { useTheme } from "@/theme/ThemeProvider";
import { ROOT_FONT_PX, rootFontPx } from "@/theme/tokens";

/** True when the app is rendering the mobile/phone shell. */
export function useIsMobile(): boolean {
  return useApp((s) => s.device === "mobile");
}

/** True when the LAYOUT is narrow — the phone shell OR a desktop window shrunk
 *  below `bp`. `useIsMobile()` only tracks the boot/preview device flag, so on a
 *  resizable desktop window it never fires; label+control rows that should stack
 *  (Settings, two-up modal bodies) must gate on this instead so narrowing the
 *  window actually triggers the column fallback. Default 720px ≈ the width below
 *  which a two-column label/control row starts to crowd.
 *
 *  `bp` is in DESIGN pixels, so the question stays "is there room for two columns
 *  of THIS type?" rather than "how many CSS pixels wide is the window?". At 150 %
 *  a 1440px window holds 960 design pixels of interface, and the rows that crowd
 *  below 720 crowd there too; a breakpoint blind to the scale would keep
 *  insisting the window was roomy while the content spilled out of it. At 100 %
 *  the two are the same number and nothing moves. */
export function useNarrow(bp = 720): boolean {
  const mobile = useApp((s) => s.device === "mobile");
  const { uiScale } = useTheme();
  // The ANSWER in state, never the width — the same rule App.tsx spells out for
  // its own sidebar question, and for the same reason: the width changes on every
  // pixel of an interactive resize, so holding it here would re-render all
  // sixteen callers on every frame of a drag, where a boolean changes twice.
  // The scale belongs in the effect's deps rather than the comparison, so the
  // answer is re-asked when the interface grows without the window moving.
  const bpCss = (bp * rootFontPx(uiScale)) / ROOT_FONT_PX;
  const [narrow, setNarrow] = useState(
    typeof window !== "undefined" ? window.innerWidth < bpCss : false,
  );
  useEffect(() => {
    const on = () => setNarrow(window.innerWidth < (bp * rootFontPx(uiScale)) / ROOT_FONT_PX);
    on();
    window.addEventListener("resize", on);
    return () => window.removeEventListener("resize", on);
  }, [bp, uiScale]);
  return mobile || narrow;
}

/** True when the viewport is in landscape (wider than tall). On a phone this is
 *  the cramped case — the fixed header + tab bar leave little content height — so
 *  the shell compacts its chrome. */
export function useLandscape(): boolean {
  const [land, setLand] = useState(
    typeof window !== "undefined" ? window.innerWidth > window.innerHeight : false,
  );
  useEffect(() => {
    const on = () => setLand(window.innerWidth > window.innerHeight);
    window.addEventListener("resize", on);
    window.addEventListener("orientationchange", on);
    return () => {
      window.removeEventListener("resize", on);
      window.removeEventListener("orientationchange", on);
    };
  }, []);
  return land;
}

/** One reading of the two viewports. Named rather than passed loose because the
 *  whole difficulty here is which of the two moved. */
export interface ViewportSample {
  innerHeight: number;
  vvHeight: number;
}

/** The viewport as it stands with no keyboard up, for the current orientation. */
export interface KeyboardBaseline {
  height: number;
  /** The largest visual-viewport height seen since the last recalibration. */
  rest: number;
}

/** Below this, a difference is rounding, momentum scroll or a home indicator —
 *  not a keyboard. */
const KB_JITTER = 80;

/** How long the viewport must hold still before its reading is believed. */
const SETTLE_MS = 120;

export function keyboardBaselineFrom(s: ViewportSample): KeyboardBaseline {
  return { height: s.innerHeight, rest: s.vvHeight };
}

/** How far the software keyboard overlaps the layout, given a reading and the
 *  baseline it is measured against. Returns the inset AND the baseline to carry
 *  forward, so the caller holds no logic of its own.
 *
 *  The calibration is unchanged and deliberate: `innerHeight - vvHeight` is
 *  non-zero at rest on a real WebView (safe area, home indicator, sub-pixel
 *  rounding), and a fixed threshold on it was tried and is device-dependent — too
 *  low and the residual becomes permanent bottom padding. So the keyboard-closed
 *  visual viewport is taken as the tallest one seen, and the keyboard is whatever
 *  shrinks it below that.
 *
 *  What is new is the second condition, and it is a SUPPRESSION only — it can
 *  turn an inset into zero and can never create one:
 *
 *  A keyboard we are able to pad for is one drawn OVER the layout, and that is
 *  visible as the layout viewport standing taller than the visual one. **iOS**
 *  works this way. **Android** does not: its WebView is created with
 *  `adjustResize`, so the system shortens the layout itself and the two
 *  viewports stay the same height. There the shell has already been made room
 *  for, padding it again pushes the bottom bar up by a second keyboard, and the
 *  baseline — recalibrated by that same height change — disagrees from one frame
 *  of the animation to the next. That is the bar and the keyboard chasing each
 *  other. With no gap between the viewports there is nothing to pad, whatever
 *  the baseline currently believes. */
export function keyboardInsetStep(
  base: KeyboardBaseline,
  s: ViewportSample,
): { base: KeyboardBaseline; inset: number } {
  let next = base;
  // A layout-height change is an orientation change, a resized window, or (on
  // Android) the keyboard itself: in all three the baseline is stale.
  if (s.innerHeight !== base.height) {
    next = keyboardBaselineFrom(s);
  }
  const rest = Math.max(next.rest, s.vvHeight);
  next = { ...next, rest };
  const overlap = rest - s.vvHeight;
  const gap = s.innerHeight - s.vvHeight;
  return {
    base: next,
    inset: overlap > KB_JITTER && gap > KB_JITTER ? Math.round(overlap) : 0,
  };
}

/** Height (px) the software keyboard currently overlaps the layout viewport.
 *  Apply the returned value as bottom padding on the fixed shell to lift content
 *  clear of it. The decision itself is [`keyboardInsetStep`]; this is the wiring.
 *
 *  Always 0 on a desktop binary, the phone-shell preview included: there is no
 *  software keyboard there, and every height change is the user resizing the
 *  window. */
export function useKeyboardInset(): number {
  const [inset, setInset] = useState(0);
  useEffect(() => {
    if (isDesktopOs()) return;
    const vv = window.visualViewport;
    if (!vv) return;
    const read = (): ViewportSample => ({
      innerHeight: window.innerHeight,
      vvHeight: vv.height,
    });
    let base = keyboardBaselineFrom(read());
    let settle: ReturnType<typeof setTimeout> | undefined;
    // The keyboard ANIMATES, and the two viewports do not necessarily update on
    // the same frame while it does — so a run of intermediate readings describes
    // a viewport that exists only mid-flight. Padding the shell from each of them
    // in turn is the bar visibly chasing the keyboard; the settled reading is the
    // only one that describes anything real. Well inside the ~250ms a keyboard
    // takes to arrive, so nothing waits on this.
    const onResize = () => {
      base = keyboardInsetStep(base, read()).base;
      clearTimeout(settle);
      settle = setTimeout(() => setInset(keyboardInsetStep(base, read()).inset), SETTLE_MS);
    };
    vv.addEventListener("resize", onResize);
    vv.addEventListener("scroll", onResize);
    onResize();
    return () => {
      clearTimeout(settle);
      vv.removeEventListener("resize", onResize);
      vv.removeEventListener("scroll", onResize);
    };
  }, []);
  return inset;
}
