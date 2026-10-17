import { describe, expect, it } from "vitest";
import { fillBarSide } from "./fillBar";

describe("fillBarSide", () => {
  it("keeps the bar on the half of the pane the cursor is not in", () => {
    expect(fillBarSide(23, 24)).toBe("top");
    expect(fillBarSide(12, 24)).toBe("top");
    expect(fillBarSide(11, 24)).toBe("bottom");
    expect(fillBarSide(0, 24)).toBe("bottom");
  });
});
