import { ImageAddon } from "@xterm/addon-image";

/** Megapixels in the addon's own unit (its default limit is 16 × 2^20). */
const MP = 1024 * 1024;

/** The one definition of the inline-image addon (sixel + iTerm2), shared by live
 *  panes and the recording player so the two cannot drift. The pixel budget bounds
 *  what a hostile or runaway program can make the app hold: 16 MP on desktop, 4 MP
 *  on phones and in playback. An evicted image leaves a placeholder rather than
 *  blank space. Load it after the renderer addon. */
export function newImageAddon(budget: "desktop" | "mobile"): ImageAddon {
  return new ImageAddon({
    pixelLimit: (budget === "desktop" ? 16 : 4) * MP,
    showPlaceholder: true,
  });
}
