// Where an ~/.ssh/config import lands. Kept out of the overlay because the rule
// is not "whatever the sidebar has selected": hostFilter carries a group id, a
// tag, or a sentinel in ONE field, and only two of those name somewhere hosts
// can be put.

import { HOST_FILTER_ALL } from "@/store/app";

/** The group an import should default to, or null for the vault root.
 *
 *  @param hostFilter the Hosts sidebar selection (`HOST_FILTER_ALL`, a tag, a
 *                    group id, or `__untagged`)
 *  @param groups     the vault's groups — the only thing that can tell a group
 *                    id apart from a tag with the same text */
export function defaultImportGroup(
  hostFilter: string,
  groups: { groupId: string }[],
): string | null {
  if (hostFilter === HOST_FILTER_ALL || hostFilter === "__untagged") return null;
  return groups.some((g) => g.groupId === hostFilter) ? hostFilter : null;
}
