// The highlight arithmetic both the host picker and the Hosts search count on:
// which row Enter acts upon after the list has changed under it.

import { describe, expect, it } from "vitest";
import { nextRow } from "./listNav";

describe("nextRow", () => {
  it("steps forward and back", () => {
    expect(nextRow(0, 1, 3)).toBe(1);
    expect(nextRow(2, -1, 3)).toBe(1);
  });

  it("wraps at both ends, so the keyboard never dead-ends", () => {
    expect(nextRow(2, 1, 3)).toBe(0);
    expect(nextRow(0, -1, 3)).toBe(2);
  });

  it("stays at zero when there is nothing to move through", () => {
    expect(nextRow(0, 1, 0)).toBe(0);
  });

  it("comes back to the nearest edge when the list shrank under the highlight", () => {
    // Typing narrows the list while the highlight sits past its new end. That is
    // not a position to step from, so the next key lands on an edge rather than
    // wherever the arithmetic happens to fall.
    expect(nextRow(7, 1, 3)).toBe(0);
    expect(nextRow(7, -1, 3)).toBe(2);
  });
});
