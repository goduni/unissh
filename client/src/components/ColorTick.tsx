// ColorTick — the one mark that draws a host's or group's colour tag (#134)
// wherever it is listed, plus the hooks and names that go with it.

import { useMemo } from "react";
import { usePalette } from "@/theme/ThemeProvider";
import { RADIUS, rem } from "@/theme/tokens";
import { useApp } from "@/store/app";
import { useTranslation, tDyn } from "@/i18n";
import { isKnownColor, type TagColor } from "@/components/appearance";
import { indexAppearance, liveHost, type AppearanceIndex } from "@/support/hostAppearance";

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

/** The appearance index of the loaded groups, rebuilt only when they change. */
export function useAppearanceIndex(): AppearanceIndex {
  const groups = useApp((s) => s.groups);
  return useMemo(() => indexAppearance(groups), [groups]);
}

/** The current colour tag and icon of the host behind an open pane (see liveHost). */
export function useLiveHost(
  profile: { uid: string; profileId: string; color?: string | null; icon?: string | null } | null,
): { color: TagColor | null; icon: string | null } {
  const hosts = useApp((s) => s.hosts);
  const index = useAppearanceIndex();
  return profile ? liveHost(profile, hosts, index) : { color: null, icon: null };
}
