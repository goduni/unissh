// The software keyboard, as the two platforms actually report it.
//
// iOS draws the keyboard OVER a layout that does not move, so the visual
// viewport shrinks below the layout one and the difference is real padding.
// Android's WebView is created with `adjustResize`: the system shortens the
// LAYOUT instead, the two viewports stay the same height, and there is nothing
// left for us to pad — padding anyway lifts the bottom bar by a second keyboard.
//
// These pin the decision. What they cannot pin is the order the two viewports
// update in mid-animation, which is why the hook settles before it believes a
// reading; see the last block.

import { describe, expect, it } from "vitest";
import { keyboardBaselineFrom, keyboardInsetStep, type ViewportSample } from "./responsive";

/** A phone at rest: 844pt tall, no keyboard. */
const REST: ViewportSample = { innerHeight: 844, vvHeight: 844 };

/** Drive a sequence of readings through the step, returning every inset. */
function run(samples: ViewportSample[], from: ViewportSample = REST): number[] {
  let base = keyboardBaselineFrom(from);
  return samples.map((s) => {
    const next = keyboardInsetStep(base, s);
    base = next.base;
    return next.inset;
  });
}

/** The algorithm as it stood before the gap condition, kept so the tests below
 *  can show which readings the two disagree about. Anything asserted as fixed
 *  has to fail here, or the assertion is worth nothing. */
function legacy(samples: ViewportSample[], from: ViewportSample = REST): number[] {
  let baseInner = from.innerHeight;
  let rest = from.vvHeight;
  return samples.map((s) => {
    if (s.innerHeight !== baseInner) {
      baseInner = s.innerHeight;
      rest = s.vvHeight;
    }
    rest = Math.max(rest, s.vvHeight);
    const overlap = rest - s.vvHeight;
    return overlap > 80 ? Math.round(overlap) : 0;
  });
}

describe("keyboardInsetStep", () => {
  it("is zero at rest", () => {
    expect(run([REST])).toEqual([0]);
  });

  it("reports the overlap when the keyboard is drawn OVER the layout (iOS)", () => {
    const open = { innerHeight: 844, vvHeight: 508 };
    expect(run([open])).toEqual([336]);
    // Unchanged from before: this is the case the hook was written for.
    expect(legacy([open])).toEqual([336]);
  });

  it("clears the inset again when that keyboard goes away", () => {
    expect(run([{ innerHeight: 844, vvHeight: 508 }, REST])).toEqual([336, 0]);
  });

  // The Android case, and the one the gap condition exists for. The layout and
  // the visual viewport agree, so whatever the baseline currently believes,
  // there is no overlay to pad.
  it("reports nothing while the layout viewport is the one that shrank", () => {
    const opening = [844, 780, 700, 620, 560, 508].map((h) => ({ innerHeight: h, vvHeight: h }));
    const closing = [...opening].reverse();
    expect(run([...opening, ...closing])).toEqual(new Array(12).fill(0));
  });

  // THE ONE THAT MATTERS, and it is not hypothetical: it is the shape a grid
  // search over these heights turns up by the thousand. The layout resizes one
  // frame before the visual viewport catches up — which is what `adjustResize`
  // looks like from JavaScript — and the old rule recalibrates its baseline
  // against the frame in between. The next reading then measures a keyboard
  // against a viewport that no longer exists and pays out 144px of padding on a
  // shell the system has ALREADY shortened. That is the bottom bar jumping.
  //
  // Exhaustively over every sequence of these heights, the gap condition never
  // pads MORE than the old rule did — it only ever declines to.
  it("refuses to pad a shell the system already shortened", () => {
    const lagging: ViewportSample[] = [
      { innerHeight: 700, vvHeight: 844 }, // layout resized, visual viewport behind
      { innerHeight: 700, vvHeight: 700 }, // it catches up
    ];
    expect(legacy(lagging)).toEqual([0, 144]);
    expect(run(lagging)).toEqual([0, 0]);
  });

  it("does not turn a resting safe-area residual into padding", () => {
    const rest = { innerHeight: 844, vvHeight: 810 };
    expect(run([rest, rest], rest)).toEqual([0, 0]);
  });

  it("ignores movement too small to be a keyboard", () => {
    expect(run([{ innerHeight: 844, vvHeight: 804 }])).toEqual([0]);
  });

  // What the step deliberately does NOT try to solve. Mid-animation the two
  // viewports can disagree for a frame or two in either direction, and no
  // stateless rule can tell that from a real overlay keyboard. The hook does not
  // ask it to: it waits for the viewport to hold still before it believes a
  // reading, so intermediate frames like this one never reach the layout.
  it("does not pay out an overlay on the frame the layout snaps back", () => {
    expect(run([{ innerHeight: 844, vvHeight: 508 }], { innerHeight: 508, vvHeight: 508 })).toEqual(
      [0],
    );
  });
});
