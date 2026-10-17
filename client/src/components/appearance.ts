// Host and group appearance (#134): a colour tag and an icon, picked from fixed
// sets and stored as ids. One place for what the ids mean and how a host ends up
// with a colour, so the sidebar, the hosts screen and the terminal tabs cannot
// disagree about which colour production is.

import type { IconName } from "@/components/primitives";
import { TAG_COLORS, type Palette, type TagColor } from "@/theme/tokens";

export { TAG_COLORS, type TagColor };

/** The icons a host or group may wear. A curated subset of the app's glyphs:
 *  things a machine or a fleet can BE (a database, an edge, a container), not
 *  the app's own controls — a host shown as a pencil or a trash can would read
 *  as an action. */
export const APPEARANCE_ICONS = [
  "server",
  "database",
  "globe",
  "cloud",
  "shield",
  "terminal",
  "drive",
  "box",
  "layers",
  "branch",
  "zap",
  "home",
  "users",
  "lock",
  "activity",
  "radio",
  "grid",
  "star",
  "heart",
] as const satisfies readonly IconName[];
export type AppearanceIcon = (typeof APPEARANCE_ICONS)[number];

export const isKnownColor = (id: string | null | undefined): id is TagColor =>
  !!id && (TAG_COLORS as readonly string[]).includes(id);

export const isKnownIcon = (id: string | null | undefined): id is AppearanceIcon =>
  !!id && (APPEARANCE_ICONS as readonly string[]).includes(id);

/** The swatch for a colour id in this palette; null for none — and for an id
 *  this build does not know (written by a newer client), which draws as no
 *  colour rather than a guess. */
export const swatchColor = (id: string | null | undefined, p: Palette): string | null =>
  isKnownColor(id) ? p.tags[id] : null;

/** The glyph to draw: the chosen icon if this build knows it, else `fallback`. */
export const appearanceIcon = (id: string | null | undefined, fallback: IconName): IconName =>
  isKnownIcon(id) ? id : fallback;

/** The fields read here. Structural so the rules are testable without whole
 *  vault items. */
export interface AppearanceGroup {
  groupId: string;
  memberIds: string[];
  parentId?: string | null;
  color?: string | null;
}

/** A colour as set on one item: absent → undefined (look further up), an
 *  unknown id → null (set, but nothing this build can draw — stop here, so a
 *  host a newer client painted "lime" never shows its folder's red instead). */
const own = (color: string | null | undefined): TagColor | null | undefined =>
  color ? (isKnownColor(color) ? color : null) : undefined;

/** A group's colour: its own, else its nearest coloured ancestor's along
 *  `parentId`. Cycle-safe — the core does not stop a parent loop across two
 *  groups, and a render must not hang on one. */
export function groupColor(
  groupId: string,
  byId: ReadonlyMap<string, AppearanceGroup>,
): TagColor | null {
  const seen = new Set<string>();
  for (let g = byId.get(groupId); g && !seen.has(g.groupId); g = g.parentId ? byId.get(g.parentId) : undefined) {
    seen.add(g.groupId);
    const c = own(g.color);
    if (c !== undefined) return c;
  }
  return null;
}

/** The colour a host shows: its own, else the one the groups directly listing
 *  it agree on. When they disagree there is no inherited colour — picking one
 *  would claim the host is "red" while it is just as much "green", which is
 *  exactly the wrong-terminal mistake this feature exists to prevent.
 *
 *  Icons are NOT inherited: a folder's icon says what the folder is, not what
 *  each machine in it is. */
export function effectiveHostColor(
  host: { profileId: string; color?: string | null },
  groups: readonly AppearanceGroup[],
): TagColor | null {
  const mine = own(host.color);
  if (mine !== undefined) return mine;
  const byId = new Map(groups.map((g) => [g.groupId, g]));
  const inherited = new Set<TagColor>();
  for (const g of groups) {
    if (!g.memberIds.includes(host.profileId)) continue;
    const c = groupColor(g.groupId, byId);
    if (c) inherited.add(c);
  }
  return inherited.size === 1 ? [...inherited][0] : null;
}

/** The colour of a host as an OPEN pane holds it. A pane keeps the profile it
 *  was opened with, so recolouring a host — the moment someone notices the
 *  production tab looks like staging — must reach tabs already open. Matched by
 *  the immutable `uid`, not `profileId`: a pane may come from another vault,
 *  where the same id (an ssh-config alias) can name a different host, and that
 *  host's groups are not the ones loaded here. Unmatched → only its own colour. */
export function liveHostColor(
  profile: { uid: string; profileId: string; color?: string | null },
  hosts: readonly { uid: string; profileId: string; color?: string | null }[],
  groups: readonly AppearanceGroup[],
): TagColor | null {
  const live = profile.uid ? hosts.find((h) => h.uid === profile.uid) : undefined;
  return live ? effectiveHostColor(live, groups) : effectiveHostColor(profile, []);
}
