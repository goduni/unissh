// Frameless-window support (tauri decorations: false). Maximized-state tracking
// for the custom controls, plus — Linux only — invisible edge zones that hand
// resizing to the compositor: an undecorated GTK window has no native resize
// borders, while Windows resizes undecorated frames natively and macOS keeps
// real decorations (overlay traffic lights).

import React, { useEffect, useState } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { isDesktopOs, isTauri, osPlatform } from "@/bridge/platform";
import { useApp } from "@/store/app";
import { chromeBarHeight, windowControlsLayout, type ControlsLayout } from "@/shell/windowControls";

/** The window-controls layout, live: it moves the moment either setting changes,
 *  with no restart. The decision itself is `windowControlsLayout` — everything
 *  that has to agree about the buttons' corner asks through here, so the
 *  controls, the bar's placement and the macOS spacer cannot disagree. */
export function useWindowControls(): ControlsLayout {
  const customChrome = useApp((s) => s.customChrome);
  const stored = useApp((s) => s.windowControlsSide);
  return windowControlsLayout({ platform: osPlatform(), stored, customChrome });
}

/** The strip at the top of the window that the title bar occupies, in design
 *  px — 0 when the window manager owns the frame, and 0 where there is no
 *  window at all. A full-window overlay uses it as its `top`.
 *
 *  Gated on the BINARY's platform, not the device flag: the phone-shell preview
 *  on a desktop OS is still a frameless window with our bar on it. Same
 *  reasoning as the unlock overlay's drag strip. */
export function useChromeInset(): number {
  const customChrome = useApp((s) => s.customChrome);
  return isDesktopOs() && customChrome ? chromeBarHeight(osPlatform()) : 0;
}

type ResizeDirection = Parameters<ReturnType<typeof getCurrentWindow>["startResizeDragging"]>[0];

export function useMaximized(): boolean {
  const [max, setMax] = useState(false);
  useEffect(() => {
    if (!isTauri()) return; // plain browser preview: nothing to subscribe to
    const win = getCurrentWindow();
    let alive = true;
    let t: ReturnType<typeof setTimeout> | undefined;
    const update = () =>
      void win.isMaximized().then((m) => {
        if (alive) setMax(m);
      });
    // onResized fires once per frame during an interactive resize, but the
    // maximized flag only flips at the ends — coalesce the IPC round-trips.
    const lazy = () => {
      clearTimeout(t);
      t = setTimeout(update, 120);
    };
    update();
    const unlisten = win.onResized(lazy);
    return () => {
      alive = false;
      clearTimeout(t);
      void unlisten.then((f) => f());
    };
  }, []);
  return max;
}

/** macOS hides its overlay traffic lights in native fullscreen (they live in the
 *  auto-revealed menu bar there), so the toolbar must collapse the space it
 *  reserves for them — pass enabled=isMac() and skip the subscription elsewhere. */
export function useFullscreen(enabled: boolean = true): boolean {
  const [fs, setFs] = useState(false);
  useEffect(() => {
    if (!enabled || !isTauri()) return;
    const win = getCurrentWindow();
    let alive = true;
    const update = () =>
      void win.isFullscreen().then((f) => {
        if (alive) setFs(f);
      });
    update();
    const unlisten = win.onResized(update);
    return () => {
      alive = false;
      void unlisten.then((f) => f());
    };
  }, [enabled]);
  return fs;
}

const EDGE = 4;
const CORNER = 12;

const ZONES: { dir: ResizeDirection; cursor: string; at: React.CSSProperties }[] = [
  { dir: "North", cursor: "n-resize", at: { top: 0, left: CORNER, right: CORNER, height: EDGE } },
  { dir: "South", cursor: "s-resize", at: { bottom: 0, left: CORNER, right: CORNER, height: EDGE } },
  { dir: "West", cursor: "w-resize", at: { left: 0, top: CORNER, bottom: CORNER, width: EDGE } },
  { dir: "East", cursor: "e-resize", at: { right: 0, top: CORNER, bottom: CORNER, width: EDGE } },
  { dir: "NorthWest", cursor: "nw-resize", at: { top: 0, left: 0, width: CORNER, height: CORNER } },
  { dir: "NorthEast", cursor: "ne-resize", at: { top: 0, right: 0, width: CORNER, height: CORNER } },
  { dir: "SouthWest", cursor: "sw-resize", at: { bottom: 0, left: 0, width: CORNER, height: CORNER } },
  { dir: "SouthEast", cursor: "se-resize", at: { bottom: 0, right: 0, width: CORNER, height: CORNER } },
];

/** Mounted once at the app root, above every overlay (lock screen included) so
 *  the window stays resizable while locked. Hidden when maximized, and absent
 *  whenever the window manager owns the frame — these zones exist only to
 *  replace native resize borders an undecorated GTK window does not have, and
 *  with a real frame they would sit on top of the WM's own edges and steal the
 *  drag from a compositor that does it better. */
export function ResizeEdges() {
  const maximized = useMaximized();
  const customChrome = useApp((s) => s.customChrome);
  if (osPlatform() !== "linux" || maximized || !customChrome) return null;
  const win = getCurrentWindow();
  return (
    <>
      {ZONES.map((z) => (
        <div
          key={z.dir}
          onMouseDown={(e) => {
            if (e.buttons === 1) void win.startResizeDragging(z.dir);
          }}
          style={{ position: "fixed", zIndex: 9500, cursor: z.cursor, ...z.at }}
        />
      ))}
    </>
  );
}
