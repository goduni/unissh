// Key hygiene: which hosts use a vault key, and whether the key is old enough to
// deserve a nudge. Pure — the Secrets view feeds it the store's hosts and items.

import type { ConnectionProfile } from "@/bridge/types";

export interface KeyUsage {
  /** Hosts that log in with the key themselves. */
  direct: ConnectionProfile[];
  /** Hosts that reach their target through a jump hop authenticated by the key. */
  jump: ConnectionProfile[];
}

/** Hosts using `keyItemId`, split by how. A host appears at most once per list;
 *  one that logs in with the key AND hops with it is in both. Hops that point at
 *  another saved profile (`hopRef`) carry no inline key and are not followed. */
export function keyUsage(hosts: readonly ConnectionProfile[], keyItemId: string): KeyUsage {
  const direct: ConnectionProfile[] = [];
  const jump: ConnectionProfile[] = [];
  for (const h of hosts) {
    if (h.auth.type === "key" && h.auth.keyItemId === keyItemId) direct.push(h);
    if (h.jumps.some((j) => !j.hopRef && j.auth.type === "agent" && j.auth.keyItemId === keyItemId))
      jump.push(h);
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
