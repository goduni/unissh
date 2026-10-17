// Host and group appearance (#134): a colour tag and an icon, picked from fixed
// sets and stored as ids. What the ids draw as lives here; which colour a host
// ends up with is the pure rule in support/hostAppearance.ts.

import type { IconName } from "@/components/primitives";
import { TAG_COLORS, type Palette, type TagColor } from "@/theme/tokens";
import { isKnownColor } from "@/support/hostAppearance";

export { TAG_COLORS, isKnownColor, type TagColor };

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
