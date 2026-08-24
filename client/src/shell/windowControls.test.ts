// The one question this module exists to answer: given the platform, what the
// user stored, and whether we draw the title bar at all — where do close /
// minimize / maximize go, and in what order.
//
// Worth pinning because the three consumers (the controls component, the title
// bar's placement, the macOS spacer) would otherwise each re-derive it and be
// free to disagree — and the failure mode of disagreeing is a hole where the
// buttons used to be, or two sets of them.

import { describe, expect, it } from "vitest";
import { windowControlsLayout, LEFT_ORDER, RIGHT_ORDER } from "./windowControls";

const layout = (platform: string, stored: string | null, customChrome = true) =>
  windowControlsLayout({ platform, stored, customChrome });

describe("windowControlsLayout", () => {
  it("puts them on the right, in minimize/maximize/close order, on an untouched Windows", () => {
    expect(layout("windows", null)).toEqual({ kind: "custom", side: "right", order: RIGHT_ORDER });
  });

  it("puts them on the right on an untouched Linux", () => {
    expect(layout("linux", null)).toEqual({ kind: "custom", side: "right", order: RIGHT_ORDER });
  });

  it("honours an explicit left on Windows, and flips the order back with it", () => {
    expect(layout("windows", "left")).toEqual({ kind: "custom", side: "left", order: LEFT_ORDER });
  });

  it("honours an explicit left on Linux", () => {
    expect(layout("linux", "left")).toEqual({ kind: "custom", side: "left", order: LEFT_ORDER });
  });

  it("honours an explicit right even where right is already the default", () => {
    // A stored value that happens to match the default is still the user's
    // answer, not an unset one — nothing may treat the two as the same state.
    expect(layout("windows", "right")).toEqual({ kind: "custom", side: "right", order: RIGHT_ORDER });
  });

  it("orders left as close/minimize/maximize and right as minimize/maximize/close", () => {
    // The order is tied to the side and never chosen separately, so that close
    // cannot end up in the middle of the three.
    expect(LEFT_ORDER).toEqual(["close", "minimize", "maximize"]);
    expect(RIGHT_ORDER).toEqual(["minimize", "maximize", "close"]);
  });

  it("falls back to the platform default on a stored value that isn't a side", () => {
    // Hand-edited or written by a newer build: anything but a side is treated as
    // no answer at all, never thrown over.
    for (const junk of ["middle", "", "RIGHT", "true", "0", "{}"]) {
      expect(layout("windows", junk)).toEqual({ kind: "custom", side: "right", order: RIGHT_ORDER });
    }
  });

  it("draws no controls of ours on macOS, whatever is stored", () => {
    // The traffic lights are the OS's, drawn over our bar; all the bar does is
    // reserve their strip. `native` is what tells it to.
    for (const stored of [null, "left", "right", "junk"]) {
      expect(layout("macos", stored)).toEqual({ kind: "native" });
    }
  });

  it("draws nothing at all with the system title bar on, on every platform", () => {
    // The two settings must not be able to combine into a doubled set of
    // buttons: with a real frame, the frame's buttons are the only ones.
    for (const platform of ["windows", "linux", "macos"]) {
      for (const stored of [null, "left", "right"]) {
        expect(layout(platform, stored, false)).toEqual({ kind: "none" });
      }
    }
  });

  it("draws nothing where there is no window to decorate", () => {
    // Phones have no window chrome, and a plain browser preview reports
    // "unknown" — neither may get controls, and neither may throw.
    for (const platform of ["android", "ios", "unknown", ""]) {
      expect(layout(platform, null)).toEqual({ kind: "none" });
    }
  });
});
