// Frameless-window support (tauri decorations: false). Maximized-state tracking
// for the custom controls, plus — Linux only — invisible edge zones that hand
// resizing to the compositor: an undecorated GTK window has no native resize
// borders, while Windows resizes undecorated frames natively and macOS keeps
// real decorations (overlay traffic lights).

import React, { useEffect, useState } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { isTauri, osPlatform } from "@/bridge/platform";

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
 *  the window stays resizable while locked. Hidden when maximized. */
export function ResizeEdges() {
  const maximized = useMaximized();
  if (osPlatform() !== "linux" || maximized) return null;
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
