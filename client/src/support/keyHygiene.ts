// Key hygiene: how many things use a vault key or password, and whether a key
// is old enough to deserve a nudge. What uses an item is the core's answer
// (`api.keyUsage`, shared with the CLI and the core's rotation planner).

import type { KeyUsage } from "@/bridge/types";

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
