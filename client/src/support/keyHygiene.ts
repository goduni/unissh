// Key hygiene: how many things use a vault key or password, and whether a key
// is old enough to deserve a nudge. What uses an item is the core's answer
// (`api.keyUsage`, shared with the CLI); `keyMatcher` stays for the rotation
// planner until that moves into the core too.

import type { ConnectionProfile, JumpHost, KeyUsage } from "@/bridge/types";

/** Predicates for "does this log in with key `keyItemId` of vault `vaultId`".
 *  A hop is either inline (its own auth) or a reference to a saved profile
 *  (`hopRef`), which the core resolves by vault + uid and then logs in with THAT
 *  profile's auth — so a ref hop uses the key when it points into this vault at
 *  a profile whose own login is the key. A ref hop's inline auth is a
 *  placeholder and is ignored. Key ids are unique only per vault, so an inline
 *  hop counts only when its auth names this vault. `hosts` are the vault's own. */
export function keyMatcher(hosts: readonly ConnectionProfile[], vaultId: string, keyItemId: string) {
  const usesKey = (h: ConnectionProfile) => h.auth.type === "key" && h.auth.keyItemId === keyItemId;
  const byUid = new Map(hosts.map((h) => [h.uid, h]));
  /** The saved profile a ref hop resolves to, when it is in this vault. */
  const refProfile = (j: JumpHost): ConnectionProfile | undefined =>
    j.hopRef && j.hopRef.vaultId === vaultId ? byUid.get(j.hopRef.profileUid) : undefined;
  const hopUsesKey = (j: JumpHost): boolean => {
    if (j.hopRef) {
      const ref = refProfile(j);
      return ref !== undefined && usesKey(ref);
    }
    return j.auth.type === "agent" && j.auth.vaultId === vaultId && j.auth.keyItemId === keyItemId;
  };
  return { usesKey, hopUsesKey, refProfile };
}

/** What "used by N" counts: distinct hosts plus identities. */
export function keyUsageCount(u: KeyUsage): number {
  return u.hosts.length + u.identities.length;
}

/** Out-of-the-box age (days) past which a key is marked old. */
export const KEY_AGE_DAYS_DEFAULT = 365;

/** The stored threshold, or the default when nothing (or garbage) is stored.
 *  0 is a real answer — "never mark" — not a missing one. */
export function parseKeyAgeDays(raw: string | null): number {
  const n = raw === null ? NaN : parseInt(raw, 10);
  return Number.isFinite(n) && n >= 0 ? n : KEY_AGE_DAYS_DEFAULT;
}

/** Whether a key created at `createdAt` (epoch seconds) is older than
 *  `thresholdDays` at `nowMs`. A 0 threshold disables the mark; so does an
 *  unknown (0) creation time, rather than calling every such key ancient. */
export function isKeyOld(createdAt: number, thresholdDays: number, nowMs: number): boolean {
  if (thresholdDays <= 0 || !createdAt) return false;
  return nowMs - createdAt * 1000 > thresholdDays * 86_400_000;
}
