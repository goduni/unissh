import { describe, expect, it, vi } from "vitest";
import type { SyncReport, TrustOutcome } from "@/bridge/types";
import { expectedFingerprint, normalizeFingerprint, verifyAndFetch, type TrustDeps } from "./sharedVaultTrust";

const FP = "0123456789abcdef".repeat(4);
const GROUPED = FP.match(/.{4}/g)!.join(" ");
const VAULT = "ab".repeat(16);

function deps(outcome: TrustOutcome, here = true) {
  return {
    trust: vi.fn<TrustDeps["trust"]>(async () => outcome),
    pull: vi.fn<TrustDeps["pull"]>(async () => ({ applied: 3, rejected: 0, tooLarge: [] }) as unknown as SyncReport),
    isHere: vi.fn<TrustDeps["isHere"]>(async () => here),
  };
}

describe("trusting a shared vault's owner", () => {
  it("reads a fingerprint the way the core does: separators and case ignored, a prefix refused", () => {
    expect(normalizeFingerprint(` ${GROUPED.toUpperCase().replace(/ /g, ":")} `)).toBe(FP);
    expect(normalizeFingerprint(FP.slice(0, 63))).toBeNull();
    expect(normalizeFingerprint(`${FP.slice(0, 63)}g`)).toBeNull();
  });

  it("passes the displayed fingerprint as expected only once the user confirmed it matches", () => {
    expect(expectedFingerprint({ kind: "confirmed", displayed: GROUPED, matches: false })).toBeNull();
    expect(expectedFingerprint({ kind: "confirmed", displayed: GROUPED, matches: true })).toBe(FP);
    expect(expectedFingerprint({ kind: "typed", typed: "" })).toBeNull();
  });

  it("never calls trust without a fingerprint", async () => {
    const d = deps("trusted");
    await expect(verifyAndFetch(VAULT, "", d)).rejects.toThrow();
    expect(d.trust).not.toHaveBeenCalled();
  });

  it("hands the core the expected fingerprint, then fetches the vault", async () => {
    const d = deps("trusted");
    const result = await verifyAndFetch(VAULT, GROUPED, d);
    expect(d.trust).toHaveBeenCalledWith(VAULT, GROUPED);
    expect(d.pull).toHaveBeenCalledWith(VAULT);
    expect(result).toEqual({ kind: "fetched", applied: 3, rejected: 0, tooLarge: [], already: false });
  });

  it("on a mismatch pulls nothing", async () => {
    const d = deps("fingerprintMismatch");
    expect(await verifyAndFetch(VAULT, FP, d)).toEqual({ kind: "mismatch" });
    expect(d.pull).not.toHaveBeenCalled();
  });

  it("when another owner is pinned pulls nothing and says so", async () => {
    const d = deps("pinnedToAnotherOwner");
    expect(await verifyAndFetch(VAULT, FP, d)).toEqual({ kind: "ownerChanged" });
    expect(d.pull).not.toHaveBeenCalled();
  });

  it("says when the owner is pinned but the pull did not bring the vault", async () => {
    expect(await verifyAndFetch(VAULT, FP, deps("alreadyTrusted", false))).toEqual({ kind: "notFetched", already: true });
  });

  // The owner is pinned, so this is not a verification failure: the dialog
  // closes and the vault waits under "Pull".
  it("reports a pull that fails after a successful trust as a failed fetch, not a refusal", async () => {
    const d = deps("trusted");
    d.pull.mockRejectedValueOnce(new Error("connection reset"));
    const result = await verifyAndFetch(VAULT, FP, d);
    expect(result).toMatchObject({ kind: "fetchFailed", already: false });
    expect(result.kind === "fetchFailed" && result.message).toContain("connection reset");
  });

  it("does not let an invisible character pass as a separator", () => {
    expect(normalizeFingerprint(`\uFEFF${FP}`)).toBeNull();
    expect(normalizeFingerprint(`${GROUPED.replace(/ /g, "\t")}\r\n`)).toBe(FP);
  });
});
