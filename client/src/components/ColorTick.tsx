// ColorTick — the one mark that draws a host's or group's colour tag (#134)
// wherever it is listed, plus the hooks and names that go with it.

import { usePalette } from "@/theme/ThemeProvider";
import { RADIUS, rem } from "@/theme/tokens";
import { useApp } from "@/store/app";
import { useTranslation, tDyn } from "@/i18n";
import { isKnownColor, type TagColor } from "@/components/appearance";
import { hostTag, indexAppearance, liveHost, type AppearanceIndex, type HostTag } from "@/support/hostAppearance";
import type { ConnectionProfile, ServerGroup } from "@/bridge/types";

/** The localized name of a colour tag ("Red"), for labels and screen readers. */
export const colorName = (id: TagColor): string => tDyn(`appearance.colors.${id}`);

/** A thin rounded bar in the tag colour, beside a host or group label. A bar,
 *  not a dot, on purpose: the round dot next to a host already means "a live
 *  session", and two dots one glance apart would make colour the only thing
 *  telling them apart. Named for assistive tech, so the tag is never sight-only.
 *  Renders nothing for no colour / an id this build does not know. */
export function ColorTick({ color, height = 14 }: { color: string | null | undefined; height?: number }) {
  const p = usePalette();
  const { t } = useTranslation();
  if (!isKnownColor(color)) return null;
  return (
    <span
      role="img"
      aria-label={t("appearance.tagged", { color: colorName(color) })}
      title={colorName(color)}
      style={{
        display: "inline-block",
        width: rem(3),
        height: rem(height),
        borderRadius: RADIUS.tick,
        background: p.tags[color],
        flexShrink: 0,
      }}
    />
  );
}

// One index for the loaded groups, shared by every caller: the store hands all
// of them the same `groups` array, so a sidebar, a hosts screen and a dozen
// terminal panes build it once per change instead of once each.
let indexed: { groups: readonly ServerGroup[]; index: AppearanceIndex<ServerGroup> } | null = null;
function appearanceIndexOf(groups: readonly ServerGroup[]): AppearanceIndex<ServerGroup> {
  if (indexed?.groups !== groups) indexed = { groups, index: indexAppearance(groups) };
  return indexed.index;
}

/** The appearance index of the loaded groups, rebuilt only when they change. */
export function useAppearanceIndex(): AppearanceIndex<ServerGroup> {
  return appearanceIndexOf(useApp((s) => s.groups));
}

// The tag each host showed while it was loaded, by uid: an open pane of a host
// that is not loaded now (another vault opened) keeps the colour it inherited
// from a folder instead of dropping to its own. Refreshed whenever the loaded
// hosts or groups change; emptied on lock, which closes every pane anyway.
const remembered = new Map<string, HostTag>();
function remember(hosts: readonly ConnectionProfile[], groups: readonly ServerGroup[]) {
  const index = appearanceIndexOf(groups);
  for (const h of hosts) if (h.uid) remembered.set(h.uid, hostTag(h, index));
}
remember(useApp.getState().hosts, useApp.getState().groups);
useApp.subscribe((s, prev) => {
  if (!s.unlocked) remembered.clear();
  else if (s.hosts !== prev.hosts || s.groups !== prev.groups) remember(s.hosts, s.groups);
});

type PaneHost = { uid: string; profileId: string; color?: string | null; icon?: string | null };

/** The current colour tag and icon of the host behind an open pane (see liveHost). */
export const paneHostTag = (profile: PaneHost, hosts: readonly PaneHost[], index: AppearanceIndex): HostTag =>
  liveHost(profile, hosts, index, remembered);

/** {@link paneHostTag} as a hook, for one pane. */
export function useLiveHost(profile: PaneHost | null): HostTag {
  const hosts = useApp((s) => s.hosts);
  const index = useAppearanceIndex();
  return profile ? paneHostTag(profile, hosts, index) : { color: null, icon: null };
}
