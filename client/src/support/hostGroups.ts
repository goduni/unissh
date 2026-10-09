// Which group(s) a host is filed under, as the Hosts screen reads it. One place
// so the "Ungrouped" filter, the group sort and the list's Group column cannot
// disagree about a host — the same reason the search lives in hostsSearch.ts.

/** The fields read here. Structural rather than `ServerGroup` so the rules are
 *  testable without building whole vault items. */
export interface GroupLike {
  groupId: string;
  label: string;
  memberIds: string[];
}

/** profileId → the groups listing it. A host absent from the map is ungrouped. */
export type HostGroupIndex<G extends GroupLike = GroupLike> = ReadonlyMap<string, G[]>;

// Label order, with the id as a tie-break: two groups may share a label, and
// without it their hosts would interleave under the group sort.
const byLabel = (a: GroupLike, b: GroupLike): number =>
  a.label.localeCompare(b.label) || (a.groupId < b.groupId ? -1 : a.groupId > b.groupId ? 1 : 0);

/** Build the index once per render; scanning every group's members per row is
 *  hosts × groups × members.
 *
 *  Membership is exclusive wherever it is edited one host at a time, but the
 *  bulk "add to group" unions, so a host can sit in several. Each entry is
 *  therefore in label order and `[0]` is THE group of that host — what it sorts
 *  under and what the column names — independent of the order groups are stored
 *  in. */
export function indexHostGroups<G extends GroupLike>(groups: G[]): HostGroupIndex<G> {
  const index = new Map<string, G[]>();
  for (const g of [...groups].sort(byLabel)) {
    for (const id of g.memberIds) {
      const list = index.get(id);
      if (!list) index.set(id, [g]);
      else if (!list.includes(g)) list.push(g);
    }
  }
  return index;
}

/** A host no group lists. */
export const isUngrouped = (index: HostGroupIndex, profileId: string): boolean =>
  !index.has(profileId);

/** Comparator for the group sort: one contiguous block per group in label order,
 *  ungrouped hosts last, name within a block. */
export function compareByGroup(
  index: HostGroupIndex,
): (a: { profileId: string; label: string }, b: { profileId: string; label: string }) => number {
  return (a, b) => {
    const ga = index.get(a.profileId)?.[0];
    const gb = index.get(b.profileId)?.[0];
    if (ga && gb) return byLabel(ga, gb) || a.label.localeCompare(b.label);
    if (ga) return -1;
    if (gb) return 1;
    return a.label.localeCompare(b.label);
  };
}
