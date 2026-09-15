import { useApp } from "@/store/app";
import type { Ctx } from "@/store/ctx";
import { appShortcutKey, hasAppModifier, opensSettings, terminalOwnsTabDigits } from "./hotkeys";

const ROUTES = ["hosts", "terminal", "fleet", "broadcast", "sftp", "tunnels", "known", "recordings", "snippets", "keys"] as const;

// The handler registered by App on window in the capture phase.
export function handleAppShortcut(e: KeyboardEvent, ctx: Pick<Ctx, "go" | "onNewHost" | "onLock">): void {
  // ⌘, / Ctrl+, — the platform's own preferences chord, so it is asked before
  // the app-modifier gate below, which wants Ctrl+Shift off macOS.
  if (opensSettings(e)) {
    const s = useApp.getState();
    // Nothing to configure behind the lock screen — and setting the flag there
    // would pop Settings open by itself the moment the vault unlocks.
    if (!s.unlocked) return;
    e.preventDefault();
    // A toggle: the same chord that opened it puts it away, which is what a
    // panel over a running terminal has to do to stay out of the way. On a
    // phone Settings is a screen, so the way back is the shell's own Back.
    if (s.settingsOpen) s.setSettingsOpen(false);
    else s.go("settings");
    return;
  }
  if (!hasAppModifier(e)) return;
  const k = appShortcutKey(e);
  if (k === "k" || e.code === "KeyK") {
    e.preventDefault();
    useApp.getState().setPalette(!useApp.getState().palette);
  } else if (k === "n" || e.code === "KeyN") {
    e.preventDefault();
    ctx.onNewHost();
  } else if (k === "t" || e.code === "KeyT") {
    e.preventDefault();
    ctx.go("terminal");
  } else if (k === "l" || e.code === "KeyL") {
    e.preventDefault();
    ctx.onLock();
  } else if (k === "/" || k === ".") {
    e.preventDefault();
    useApp.getState().setShortcuts(!useApp.getState().shortcuts);
  } else if (k === "m" || e.code === "KeyM") {
    // preview toggle: desktop <-> mobile shell
    e.preventDefault();
    const cur = useApp.getState().device;
    useApp.getState().setDevice(cur === "mobile" ? "desktop" : "mobile");
  } else if (k === "=" || k === "+") {
    // Cmd / Ctrl+Shift + (=/+): zoom the terminal font in
    e.preventDefault();
    useApp.getState().bumpTermZoom(1);
  } else if (k === "-" || k === "_") {
    // Cmd / Ctrl+Shift + -: zoom the terminal font out
    e.preventDefault();
    useApp.getState().bumpTermZoom(-1);
  } else if (k === "0") {
    // Cmd / Ctrl+Shift + 0: reset terminal font zoom
    e.preventDefault();
    useApp.getState().resetTermZoom();
  } else if (/^[1-9]$/.test(k)) {
    // While the terminal is on screen these digits are its tab switcher, and
    // both listeners are capture-phase on window — stopPropagation over there
    // cannot silence this one. Routing anyway is how ⌘1 in a terminal used to
    // switch to tab 1 and then throw the user out to Hosts.
    if (terminalOwnsTabDigits(useApp.getState().route, e)) return;
    const r = ROUTES[parseInt(k, 10) - 1];
    if (r) {
      e.preventDefault();
      ctx.go(r);
    }
  }
}
