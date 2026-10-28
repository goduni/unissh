import { describe, it, expect } from "vitest";
import { syncLeftBehind, tooLargeSummary } from "./syncReport";
import { ItemType, type SyncReport, type TooLargeItem } from "./types";

const item = (itemId: string, over: Partial<TooLargeItem> = {}): TooLargeItem => ({
  vaultId: "ab12",
  vaultName: "Ops",
  itemId,
  itemType: ItemType.Recording,
  bytes: 3 * 1024 * 1024,
  ...over,
});

describe("tooLargeSummary", () => {
  it("names each refused item by kind, with its vault and size", () => {
    const items = [item("rec-1"), item("runbook", { itemType: ItemType.Note, vaultName: "", bytes: 1_572_864 })];
    expect(tooLargeSummary(items, "en")).toBe("session recording “rec-1” (Ops, 3 MB), note “runbook” (ab12, 1.5 MB)");
  });

  it("formats the line in the language asked for", () => {
    expect(tooLargeSummary([item("rec-1", { bytes: 1_572_864 })], "ru")).toBe("запись сессии «rec-1» (Ops, 1,5 МБ)");
  });

  it("counts the items past the first three instead of listing them", () => {
    expect(tooLargeSummary(["a", "b", "c", "d", "e"].map((id) => item(id)), "en")).toMatch(
      /“c” \(Ops, 3 MB\) and 2 more$/,
    );
  });

  it("is empty when nothing was refused", () => {
    expect(tooLargeSummary([])).toBe("");
  });
});

describe("syncLeftBehind", () => {
  it("names the edits the server will not take and the way to restore its copy", () => {
    const report: SyncReport = {
      applied: 0,
      skippedStale: 0,
      conflicts: 0,
      rejected: 0,
      pushed: 3,
      tooLarge: [],
      unpushable: [
        { vaultId: "ab12", vaultName: "Ops", itemId: "web", itemType: ItemType.Connection, mine: true, reason: "notAuthorized" },
      ],
    };
    expect(syncLeftBehind(report, "en")).toBe(
      "Not uploaded — the server won't take these changes made on this device: host “web” (Ops). " +
        "Everything else is synced. Use “Discard unsent changes” to restore the server's copy.",
    );
  });
});
