import { describe, it, expect } from "vitest";
import { keyRowRotationActions } from "./keyRotation";

// The plan, the run and the steps are the core's, tested there
// (rust-core/crates/ffi/src/key_rotation_plan.rs).

describe("key row rotation actions", () => {
  it("offers a key in a rotation only the way back into the dialog or abandon, never finish or replace", () => {
    expect([
      keyRowRotationActions(undefined),
      keyRowRotationActions({ startedElsewhere: false }),
      keyRowRotationActions({ startedElsewhere: true }),
    ]).toEqual([["start", "replace"], ["continue", "abandon"], ["abandon"]]);
  });
});
