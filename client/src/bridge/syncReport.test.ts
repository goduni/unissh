import { describe, it, expect } from "vitest";
import { tooLargeSummary } from "./syncReport";
import type { TooLargeItem } from "./types";

const item = (itemId: string, over: Partial<TooLargeItem> = {}): TooLargeItem => ({
  vaultId: "ab12",
  vaultName: "Ops",
  itemId,
  bytes: 3 * 1024 * 1024,
  ...over,
});

describe("tooLargeSummary", () => {
  it("names each refused item with its vault and size", () => {
    expect(tooLargeSummary([item("rec-1"), item("rec-2", { vaultName: "", bytes: 1_572_864 })])).toBe(
      "“rec-1” (Ops, 3.0 MB), “rec-2” (ab12, 1.5 MB)",
    );
  });

  it("counts the items past the first three instead of listing them", () => {
    expect(tooLargeSummary(["a", "b", "c", "d", "e"].map((id) => item(id)))).toMatch(/“c” \(Ops, 3\.0 MB\) \+2$/);
  });

  it("is empty when nothing was refused", () => {
    expect(tooLargeSummary([])).toBe("");
  });
});
