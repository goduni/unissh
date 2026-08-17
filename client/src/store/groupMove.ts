// Which group items a "put these hosts in this group" has to rewrite.
//
// Membership is EXCLUSIVE everywhere it is edited: the host modal picks one
// group and, on save, drops the host from every other one. So an operation that
// only unions member ids can leave a host listed under two groups — a state the
// editor then silently repairs by evicting it from one of them, at the next save
// of an unrelated field. A move keeps that invariant.

import type { ServerGroup } from "@/bridge/types";

/** The groups that need saving to move `profileIds` into `targetGroupId`, with
 *  their new member lists. Empty when nothing would change — a caller can skip
 *  the writes and the reload entirely.
 *
 *  A missing target returns no writes at all rather than a half-move: evicting
 *  hosts from where they were and putting them nowhere is worse than leaving
 *  them alone. */
export function planGroupMove(
  groups: ServerGroup[],
  targetGroupId: string,
  profileIds: string[],
): ServerGroup[] {
  const target = groups.find((g) => g.groupId === targetGroupId);
  if (!target || profileIds.length === 0) return [];

  const moving = new Set(profileIds);
  const writes: ServerGroup[] = [];
  for (const g of groups) {
    if (g.groupId === targetGroupId) continue;
    const memberIds = g.memberIds.filter((m) => !moving.has(m));
    if (memberIds.length !== g.memberIds.length) writes.push({ ...g, memberIds });
  }

  const memberIds = Array.from(new Set([...target.memberIds, ...profileIds]));
  if (memberIds.length !== target.memberIds.length) writes.push({ ...target, memberIds });
  return writes;
}
