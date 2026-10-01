import { useApp } from "@/store/app";
import type { Ctx } from "@/store/ctx";
import { matchesShortcut, useShortcuts } from "@/store/shortcuts";

const ROUTES = ["hosts", "terminal", "fleet", "broadcast", "sftp", "tunnels", "known", "recordings", "snippets"] as const;

// Capture phase: consume handled events before xterm can send them to the shell.
export function handleAppShortcut(e: KeyboardEvent, ctx: Pick<Ctx, "go" | "onNewHost" | "onLock">): void {
  const s = useApp.getState();
  if (e.defaultPrevented || e.isComposing || useShortcuts.getState().recording || !s.unlocked) return;
  const run = (id: string, action: () => void) => {
    if (!matchesShortcut(e, id)) return false;
    e.preventDefault();
    e.stopPropagation?.();
    if (!e.repeat) action();
    return true;
  };
  if (run("settings", () => s.settingsOpen ? s.setSettingsOpen(false) : s.go("settings"))) return;
  if (run("lock", ctx.onLock)) return;
  // A foreground dialog owns its controls. Settings and lock remain reachable.
  if (s.modal || s.confirm || s.settingsOpen || s.importing || s.groupsModal) return;
  if (s.palette && run("palette", () => s.setPalette(false))) return;
  if (s.shortcuts && run("help", () => s.setShortcuts(false))) return;
  const target = e.target as HTMLElement | null;
  if (target?.closest?.('[role="dialog"], [role="alertdialog"]')) return;
  if (run("palette", () => s.setPalette(!s.palette))) return;
  if (run("help", () => s.setShortcuts(!s.shortcuts))) return;
  if (s.palette || s.shortcuts) return;
  if (run("newHost", ctx.onNewHost)) return;
  // The terminal listener owns this action while the terminal is visible.
  if ((s.route !== "terminal" || s.device === "mobile") && run("terminal", () => ctx.go("terminal"))) return;
  if (run("device", () => s.setDevice(s.device === "mobile" ? "desktop" : "mobile"))) return;
  if (run("zoomIn", () => s.bumpTermZoom(1))) return;
  if (run("zoomOut", () => s.bumpTermZoom(-1))) return;
  if (run("zoomReset", () => s.resetTermZoom())) return;
  if (s.route !== "terminal") {
    for (const route of ROUTES) if (run(`nav.${route}`, () => ctx.go(route))) return;
  }
}
