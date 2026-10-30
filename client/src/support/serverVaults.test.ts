import { describe, expect, it, vi } from "vitest";
import type { PendingSharedVault, PendingSharedVaults, ServerVault } from "@/bridge/types";
import { catalogRows, loadServerVaults } from "./serverVaults";

const vault = (vaultId: string, isLocal = false): ServerVault =>
  ({ vaultId, isLocal, bound: isLocal, tombstone: false, localName: null }) as ServerVault;

const waiting = (vaultId: string): PendingSharedVault => ({
  vaultId,
  state: "waiting",
  fingerprint: null,
  role: "editor",
  claimedHandle: null,
  claimedName: null,
  error: null,
});

describe("on this server", () => {
  it("lists a vault that waits for its owner to be trusted in its own group, not with a Pull", () => {
    const rows = catalogRows([vault("aa"), vault("BB"), vault("cc", true)], [waiting("bb")]);
    expect(rows.map((v) => v.vaultId)).toEqual(["aa", "cc"]);
  });

  it("shows the vault list without waiting for the shared-vault check, and keeps it when that check fails", async () => {
    let failShared!: (e: unknown) => void;
    const sink = { rows: vi.fn(), rowsFailed: vi.fn(), shared: vi.fn(), sharedFailed: vi.fn() };
    const done = loadServerVaults(
      {
        listVaults: async () => [vault("aa")],
        pendingShared: () =>
          new Promise<PendingSharedVaults>((_, reject) => {
            failShared = reject;
          }),
      },
      sink,
    );
    await vi.waitFor(() => expect(sink.rows).toHaveBeenCalledWith([vault("aa")]));
    failShared(new Error("offline"));
    await done;
    expect(sink.sharedFailed).toHaveBeenCalledTimes(1);
    expect(sink.rowsFailed).not.toHaveBeenCalled();
    expect(sink.shared).not.toHaveBeenCalled();
  });
});
