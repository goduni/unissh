import { describe, it, expect } from "vitest";
import { syncLeftBehind, tooLargeSummary } from "./syncReport";
import {
  ItemType,
  type SyncReport,
  type TooLargeItem,
  type UnpushableItem,
} from "./types";

const item = (
  itemId: string,
  over: Partial<TooLargeItem> = {},
): TooLargeItem => ({
  vaultId: "ab12",
  vaultName: "Ops",
  itemId,
  itemType: ItemType.Recording,
  bytes: 3 * 1024 * 1024,
  ...over,
});

describe("tooLargeSummary", () => {
  it("names each refused item by kind, with its vault and size", () => {
    const items = [
      item("rec-1"),
      item("runbook", {
        itemType: ItemType.Note,
        vaultName: "",
        bytes: 1_572_864,
      }),
    ];
    expect(tooLargeSummary(items, "en")).toBe(
      "session recording “rec-1” (Ops, 3 MB), note “runbook” (ab12, 1.5 MB)",
    );
  });

  it("formats the line in the language asked for", () => {
    expect(tooLargeSummary([item("rec-1", { bytes: 1_572_864 })], "ru")).toBe(
      "запись сессии «rec-1» (Ops, 1,5 МБ)",
    );
  });

  it("counts the items past the first three instead of listing them", () => {
    expect(
      tooLargeSummary(
        ["a", "b", "c", "d", "e"].map((id) => item(id)),
        "en",
      ),
    ).toMatch(/“c” \(Ops, 3 MB\) and 2 more$/);
  });

  it("is empty when nothing was refused", () => {
    expect(tooLargeSummary([])).toBe("");
  });
});

describe("syncLeftBehind", () => {
  const report = (over: Partial<SyncReport>): SyncReport => ({
    applied: 0,
    skippedStale: 0,
    conflicts: 0,
    rejected: 0,
    pushed: 3,
    tooLarge: [],
    unpushable: [],
    ...over,
  });
  const unsent = (
    itemId: string,
    mine: boolean,
    reason: UnpushableItem["reason"] = "notAuthorized",
  ): UnpushableItem => ({
    vaultId: "ab12",
    vaultName: "Ops",
    itemId,
    itemType: ItemType.Connection,
    mine,
    reason,
  });

  it("says this account may not change the edits it may not make, and how to restore the server's copy", () => {
    expect(
      syncLeftBehind(report({ unpushable: [unsent("web", true)] }), "en"),
    ).toBe(
      "Not uploaded — this account may not change these: host “web” (Ops). " +
        "Everything else is synced. “Discard unsent changes” replaces the edits with the server's copy.",
    );
  });

  it("names this account's edits the server refused", () => {
    const line =
      syncLeftBehind(
        report({ unpushable: [unsent("web", true, "serverRefused")] }),
        "en",
      ) ?? "";
    expect(line).toContain(
      "the server refused these edits by this account: host “web” (Ops)",
    );
  });

  it("does not call other members' edits this account's, nor offer to restore them", () => {
    const line =
      syncLeftBehind(report({ unpushable: [unsent("db", false)] }), "en") ?? "";
    expect(line).toContain("host “db” (Ops)");
    expect(line).not.toContain("by this account");
    expect(line).not.toContain("Discard");
  });

  it("names both what is too large and what the server will not take", () => {
    const line =
      syncLeftBehind(
        report({
          tooLarge: [item("rec-1")],
          unpushable: [unsent("web", true)],
        }),
        "en",
      ) ?? "";
    expect(line).toContain(
      "too large for this server: session recording “rec-1”",
    );
    expect(line).toContain("may not change these: host “web”");
  });

  it("is null when the sync left nothing behind", () => {
    expect(syncLeftBehind(report({}))).toBeNull();
  });
});
