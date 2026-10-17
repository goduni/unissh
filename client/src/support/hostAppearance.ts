// Which colour tag a host shows (#134). One place for the rule, so the sidebar,
// the hosts screen, the host editor and the terminal tabs cannot disagree about
// which colour production is. Pure: drawing a tag (swatches, glyphs) lives in
// components/appearance.ts.

import { TAG_COLORS, type TagColor } from "@/theme/tokens";
import { indexHostGroups, type GroupLike, type HostGroupIndex } from "@/support/hostGroups";

export const isKnownColor = (id: string | null | undefined): id is TagColor =>
  !!id && (TAG_COLORS as readonly string[]).includes(id);

/** The fields read here, on top of what the group index reads. */
export interface AppearanceGroup extends GroupLike {
  parentId?: string | null;
  color?: string | null;
}

/** Built once per render from the loaded groups; every lookup below reads it
 *  instead of re-scanning the groups per host. */
export interface AppearanceIndex {
  byId: ReadonlyMap<string, AppearanceGroup>;
  byHost: HostGroupIndex<AppearanceGroup>;
}

export function indexAppearance(groups: readonly AppearanceGroup[]): AppearanceIndex {
  return { byId: new Map(groups.map((g) => [g.groupId, g])), byHost: indexHostGroups([...groups]) };
}

/** The colour id in force for a group: its own, else its nearest coloured
 *  ancestor's along `parentId`; null when none is set. The id may be one this
 *  build does not know (a newer client's) — that is still a colour that was SET,
 *  and stops the walk, so it is returned as-is rather than folded into "none".
 *  Cycle-safe: the core does not stop a parent loop across two groups, and a
 *  render must not hang on one. */
export function groupColor(groupId: string, index: AppearanceIndex): string | null {
  const seen = new Set<string>();
  for (
    let g = index.byId.get(groupId);
    g && !seen.has(g.groupId);
    g = g.parentId ? index.byId.get(g.parentId) : undefined
  ) {
    seen.add(g.groupId);
    if (g.color) return g.color;
  }
  return null;
}

/** The colour a host shows: its own, else the one the groups directly listing
 *  it agree on. When they disagree there is no inherited colour — picking one
 *  would claim the host is "red" while it is just as much "green", which is
 *  exactly the wrong-terminal mistake this feature exists to prevent. A colour
 *  this build does not know counts as a colour in that vote (and draws as none):
 *  "lime" next to "red" is a disagreement, not a red host. An unknown OWN colour
 *  likewise blocks inheritance instead of falling through to the folder's.
 *
 *  Icons are NOT inherited: a folder's icon says what the folder is, not what
 *  each machine in it is. */
export function effectiveHostColor(
  host: { profileId: string; color?: string | null },
  index: AppearanceIndex,
): TagColor | null {
  if (host.color) return isKnownColor(host.color) ? host.color : null;
  const inherited = new Set<string>();
  for (const g of index.byHost.get(host.profileId) ?? []) {
    const c = groupColor(g.groupId, index);
    if (c) inherited.add(c);
  }
  const [only] = inherited;
  return inherited.size === 1 && isKnownColor(only) ? only : null;
}

const NO_GROUPS: AppearanceIndex = { byId: new Map(), byHost: new Map() };

interface LiveHostLike {
  uid: string;
  profileId: string;
  color?: string | null;
  icon?: string | null;
}

/** The colour tag and icon id of the host behind an OPEN pane. A pane keeps the
 *  profile it was opened with, so recolouring a host — the moment someone
 *  notices the production tab looks like staging — must reach tabs already open.
 *  Matched by the immutable `uid`, not `profileId`: a pane may come from another
 *  vault, where the same id (an ssh-config alias) can name a different host, and
 *  that host's groups are not the ones loaded here. Unmatched → only the pane's
 *  own snapshot. The icon id is raw; the caller decides whether it can draw it. */
export function liveHost(
  profile: LiveHostLike,
  hosts: readonly LiveHostLike[],
  index: AppearanceIndex,
): { color: TagColor | null; icon: string | null } {
  const live = profile.uid ? hosts.find((h) => h.uid === profile.uid) : undefined;
  return live
    ? { color: effectiveHostColor(live, index), icon: live.icon ?? null }
    : { color: effectiveHostColor(profile, NO_GROUPS), icon: profile.icon ?? null };
}
