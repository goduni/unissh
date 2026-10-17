import { describe, expect, it } from "vitest";
import { fillBarSide, fillItemLabel } from "./fillBar";

describe("fillBarSide", () => {
  it("keeps the bar on the half of the pane the cursor is not in", () => {
    expect(fillBarSide(23, 24)).toBe("top");
    expect(fillBarSide(12, 24)).toBe("top");
    expect(fillBarSide(11, 24)).toBe("bottom");
    expect(fillBarSide(0, 24)).toBe("bottom");
  });
});

describe("fillItemLabel", () => {
  it("names a chosen item id, and the host for a generated one", () => {
    expect(fillItemLabel("db-admin", "Prod DB")).toBe("db-admin");
    expect(fillItemLabel("prod-db-pw-1760000000000", "Prod DB")).toBe("Prod DB");
  });
});
