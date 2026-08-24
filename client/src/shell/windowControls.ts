// Where the window controls live, and in what order — one decision, lifted out
// of the title bar so the pieces that have to agree about it cannot drift apart.
//
// Three things ask: the controls component (which buttons, in what order), the
// title bar (which end of the bar to put them at), and the macOS spacer (whether
// to reserve the traffic lights' strip instead). Each of them used to read
// `isMac()` and lay itself out; that was fine while there was exactly one
// layout, and stops being fine the moment the side is a setting.
//
// The side is a TRI-STATE for the same reason the custom-chrome flag is: "right,
// because that is what this platform does" and "right, because the user said so"
// are different states, and only the first may be moved by a later release. A
// plain boolean cannot hold that distinction. Anything stored that is not a side
// — hand-edited, or written by a build that knew a value this one doesn't — is
// treated as no answer rather than as an error.
//
// The order is tied to the side rather than chosen separately: right means the
// platform's own minimize / maximize / close, left means the close / minimize /
// maximize this app has drawn until now. Offering the two axes independently
// would let someone put close between the other two, which is the one
// arrangement nobody wants and every accidental quit comes from.

/** Which end of the title bar our controls sit at. */
export type ControlsSide = "left" | "right";

/** One of the three buttons we draw ourselves. */
export type ControlButton = "close" | "minimize" | "maximize";

/** The layout this app has drawn since the beginning — macOS-shaped, kept so an
 *  upgrade never permanently moves the buttons of someone used to them. */
export const LEFT_ORDER: readonly ControlButton[] = ["close", "minimize", "maximize"];

/** What Windows and every mainstream Linux desktop do: close in the corner. */
export const RIGHT_ORDER: readonly ControlButton[] = ["minimize", "maximize", "close"];

/** What the title bar should draw.
 *  - `custom` — our three buttons, at `side`, in `order`.
 *  - `native`  — macOS: the OS draws the traffic lights over our bar, and the
 *    bar's only job is to reserve their default strip (we never move them).
 *  - `none`   — nothing of ours: the system frame owns the buttons, or there is
 *    no window here at all (phone, browser preview). */
export type ControlsLayout =
  | { kind: "custom"; side: ControlsSide; order: readonly ControlButton[] }
  | { kind: "native" }
  | { kind: "none" };

/** How tall the title bar we draw is, in design px.
 *
 *  macOS runs it shorter on purpose: the traffic lights sit on the OS's own
 *  line, which we never move, and 38 puts the bar's centreline on that line
 *  instead of 5px below it.
 *
 *  It lives here because the bar is no longer the only thing that has to know:
 *  anything covering the window has to start below the bar, or it covers the
 *  window controls with it — which on macOS merely puts the traffic lights on
 *  top of someone's content, and on Windows and Linux takes away the only way
 *  to close the window. */
export function chromeBarHeight(platform: string): number {
  return platform === "macos" ? 38 : 44;
}

/** Platforms where we draw the controls ourselves. macOS is deliberately absent
 *  — it is the `native` case, not a side we get to choose. */
const CUSTOM_PLATFORMS = ["windows", "linux"];

export function windowControlsLayout({
  platform,
  stored,
  customChrome,
}: {
  /** `osPlatform()` — "windows" | "linux" | "macos" | "android" | "ios" | "unknown". */
  platform: string;
  /** The user's stored side, raw and unsanitised; `null` = never answered. */
  stored: string | null;
  /** Whether WE draw the title bar, rather than the window manager. */
  customChrome: boolean;
}): ControlsLayout {
  // First, and before the platform: with a real frame the frame's buttons are
  // the window's buttons. This is what keeps the two settings from combining
  // into two sets of controls, on every platform including macOS.
  if (!customChrome) return { kind: "none" };
  if (platform === "macos") return { kind: "native" };
  if (!CUSTOM_PLATFORMS.includes(platform)) return { kind: "none" };
  const side: ControlsSide = stored === "left" || stored === "right" ? stored : "right";
  return { kind: "custom", side, order: side === "left" ? LEFT_ORDER : RIGHT_ORDER };
}
