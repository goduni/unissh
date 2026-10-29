// Trusting the owner of a vault a teammate shared with this account.
//
// The core compares and pins (`server_trust_shared_vault`); what lives here is the
// app's half of the rule: a trust call always carries an expected fingerprint —
// the one the owner gave the user, or the one shown and explicitly confirmed —
// and a vault is fetched only after the core said the owner is pinned.

import { apiErrorMessage, type SyncReport, type TooLargeItem, type TrustOutcome } from "@/bridge/types";

/** Hex digits in a fingerprint (`member_fingerprint`: hex SHA-256). */
export const FINGERPRINT_DIGITS = 64;

/** The separators a typed fingerprint may carry. An explicit class, not `\s`:
 *  that would also drop invisible characters such as U+FEFF without a word. */
const SEPARATORS = /[ \t\r\n:-]/g;

/** A fingerprint as typed or pasted, in the core's form (64 lowercase hex
 *  digits): spaces, tabs, line breaks, `:` and `-` dropped, case ignored. `null` when what is left
 *  is not exactly 64 hex digits — a prefix is not a fingerprint. Mirrors
 *  `normalize_fingerprint` in the core, which checks again. */
export function normalizeFingerprint(typed: string): string | null {
  const digits = typed.replace(SEPARATORS, "");
  return digits.length === FINGERPRINT_DIGITS && /^[0-9a-fA-F]+$/.test(digits) ? digits.toLowerCase() : null;
}

/** How many fingerprint characters the user has typed so far (separators not counted). */
export function typedDigits(typed: string): number {
  return typed.replace(SEPARATORS, "").length;
}

/** The two ways the dialog lets the user vouch for the owner. */
export type VerifyMode =
  /** Type or paste the fingerprint the owner gave out of band (the strong check). */
  | { kind: "typed"; typed: string }
  /** Compare the displayed fingerprint with the owner and confirm it matches. */
  | { kind: "confirmed"; displayed: string; matches: boolean };

/** The fingerprint to pass as `expected`, or `null` while there is none yet (the
 *  action stays disabled). Never empty, never "whatever the server says": the
 *  displayed one counts only once the user ticked that it matches. */
export function expectedFingerprint(mode: VerifyMode): string | null {
  if (mode.kind === "typed") return normalizeFingerprint(mode.typed);
  return mode.matches ? normalizeFingerprint(mode.displayed) : null;
}

/** What pulling a vault whose owner is pinned came to. */
export type FetchResult =
  /** The vault is on this device now. `rejected` objects failed verification;
   *  `tooLarge` items stayed off the server. */
  | { kind: "fetched"; applied: number; rejected: number; tooLarge: TooLargeItem[] }
  /** The pull did not bring the vault (yet). */
  | { kind: "notFetched" };

/** What verifying came to, for the UI to word. */
export type TrustResult =
  /** The owner is pinned (`already`: it was before this call) and the pull
   *  ran: see the fetch result. */
  | (FetchResult & { already: boolean })
  /** The owner is pinned, but the pull failed or was cut short. Not a
   *  verification failure: the vault waits under "Pull". */
  | { kind: "fetchFailed"; message: string; already: boolean }
  /** The fingerprint is not the creator's. Nothing pinned, nothing pulled. */
  | { kind: "mismatch" }
  /** Another owner is pinned here. Nothing changed, nothing pulled. */
  | { kind: "ownerChanged" };

export interface TrustDeps {
  trust: (vaultId: string, expected: string) => Promise<TrustOutcome>;
  pull: (vaultId: string) => Promise<SyncReport>;
  /** Is the vault on this device now (after the pull)? */
  isHere: (vaultId: string) => Promise<boolean>;
}

/** Pulls a vault whose owner is pinned here, and says whether it arrived. */
export async function fetchShared(vaultId: string, deps: Pick<TrustDeps, "pull" | "isHere">): Promise<FetchResult> {
  const report = await deps.pull(vaultId);
  return (await deps.isHere(vaultId))
    ? { kind: "fetched", applied: report.applied, rejected: report.rejected, tooLarge: report.tooLarge }
    : { kind: "notFetched" };
}

/** Has the core compare `expected` and pin the owner, then pulls the vault.
 *  Refuses (throws, before any call) without a real fingerprint. A failed
 *  trust call throws; a pull that fails once the owner is pinned is
 *  `fetchFailed`, since the trust itself held. */
export async function verifyAndFetch(vaultId: string, expected: string, deps: TrustDeps): Promise<TrustResult> {
  if (normalizeFingerprint(expected) === null) throw new Error("not a fingerprint");
  const outcome = await deps.trust(vaultId, expected);
  switch (outcome) {
    case "fingerprintMismatch":
      return { kind: "mismatch" };
    case "pinnedToAnotherOwner":
      return { kind: "ownerChanged" };
    case "trusted":
    case "alreadyTrusted": {
      const already = outcome === "alreadyTrusted";
      try {
        return { ...(await fetchShared(vaultId, deps)), already };
      } catch (e) {
        return { kind: "fetchFailed", message: apiErrorMessage(e), already };
      }
    }
  }
}

/** The i18n key (under `sharedVaults.reason`) for why the core could not
 *  verify a vault; `generic` for a reason it words in a way not known here. */
export type UnverifiableReason =
  | "twoCreators"
  | "noGenesis"
  | "crowded"
  | "brokenChain"
  | "noGrant"
  | "unreadable"
  | "generic";

const REASONS: [string, UnverifiableReason][] = [
  ["two different creators", "twoCreators"],
  ["no valid genesis manifest", "noGenesis"],
  ["serves too many", "crowded"],
  ["membership chain", "brokenChain"],
  ["grants this account nothing", "noGrant"],
  ["could not be read in full", "unreadable"],
];

/** Maps the core's (English) refusal to a reason the app words itself. */
export function unverifiableReason(error: string | null): UnverifiableReason {
  if (!error) return "generic";
  return REASONS.find(([needle]) => error.includes(needle))?.[1] ?? "generic";
}
