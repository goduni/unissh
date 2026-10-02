// Key hygiene: which hosts use a vault key, and whether the key is old enough to
// deserve a nudge. Pure — the Secrets view feeds it the store's hosts and items.

import type { ConnectionProfile, JumpHost } from "@/bridge/types";

export interface KeyUsage {
  /** Hosts that log in with the key themselves. */
  direct: ConnectionProfile[];
  /** Hosts that reach their target through a jump hop authenticated by the key. */
  jump: ConnectionProfile[];
}

/** Hosts of vault `vaultId` (the list's own vault) using its key `keyItemId`,
 *  split by how. A hop is either inline (its own auth) or a reference to a saved
 *  profile (`hopRef`), which the core resolves by vault + uid and then logs in
 *  with THAT profile's auth — so a ref hop uses the key when it points into this
 *  vault at a profile whose own login is the key. A ref hop's inline auth is a
 *  placeholder and is ignored. A host appears at most once per list; one that
 *  logs in with the key AND hops with it is in both. */
export function keyUsage(
  hosts: readonly ConnectionProfile[],
  vaultId: string,
  keyItemId: string,
): KeyUsage {
  const usesKey = (h: ConnectionProfile) => h.auth.type === "key" && h.auth.keyItemId === keyItemId;
  const byUid = new Map(hosts.map((h) => [h.uid, h]));
  const hopUsesKey = (j: JumpHost): boolean => {
    if (j.hopRef) {
      if (j.hopRef.vaultId !== vaultId) return false;
      const ref = byUid.get(j.hopRef.profileUid);
      return ref !== undefined && usesKey(ref);
    }
    return j.auth.type === "agent" && j.auth.keyItemId === keyItemId;
  };
  const direct: ConnectionProfile[] = [];
  const jump: ConnectionProfile[] = [];
  for (const h of hosts) {
    if (usesKey(h)) direct.push(h);
    if (h.jumps.some(hopUsesKey)) jump.push(h);
  }
  return { direct, jump };
}

/** Distinct hosts in a usage — what "used by N hosts" counts. */
export function keyUsageCount(u: KeyUsage): number {
  return new Set([...u.direct, ...u.jump].map((h) => h.profileId)).size;
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
