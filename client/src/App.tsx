import { useEffect, useRef, useState } from "react";
import { platform } from "@tauri-apps/plugin-os";
import { usePalette } from "@/theme/ThemeProvider";
import { useApp } from "@/store/app";
import { useCtx } from "@/store/ctx";
import { useTranslation } from "@/i18n";
import { Icon } from "@/components/primitives";
import { Sidebar, TitleBar } from "@/shell/Shell";

import { ViewHosts } from "@/views/ViewHosts";
import { ViewTerminal } from "@/views/ViewTerminal";
import { ViewFleet } from "@/views/ViewFleet";
import { ViewBroadcast } from "@/views/ViewBroadcast";
import { ViewSftp } from "@/views/sftp/ViewSftp";
import { ViewTunnels } from "@/views/ViewTunnels";
import { ViewKnown } from "@/views/ViewKnown";
import { ViewSecrets } from "@/views/ViewSecrets";
import { ViewSettings } from "@/views/ViewSettings";

import { EntryOverlays } from "@/overlays/Entry";
import { Modals } from "@/overlays/Modals";
import { CommandPalette } from "@/overlays/CommandPalette";
import { ImportPreview } from "@/overlays/ImportPreview";
import { GroupsModal } from "@/overlays/GroupsModal";
import { ConfirmDialog, ShortcutsHelp, ToastHost } from "@/overlays/Feedback";
import { MobileApp } from "@/mobile/MobileApp";

const ROUTES = ["hosts", "terminal", "fleet", "broadcast", "sftp", "tunnels", "known", "keys"] as const;

function RenderView() {
  const route = useApp((s) => s.route);
  switch (route) {
    case "hosts":
      return <ViewHosts />;
    case "terminal":
      return null; // rendered persistently in App() so sessions/scrollback survive navigation
    case "fleet":
      return <ViewFleet />;
    case "broadcast":
      return <ViewBroadcast />;
    case "sftp":
      return null; // rendered persistently in App() so panes/cwd/selection survive navigation
    case "tunnels":
      return <ViewTunnels />;
    case "known":
      return <ViewKnown />;
    case "keys":
    case "passwords":
    case "notes":
    case "identities":
      return <ViewSecrets />;
    case "settings":
      return <ViewSettings />;
    default:
      return <ViewHosts />;
  }
}

/** Pre-lock warning: appears ~60s before an idle auto-lock with a live countdown
 *  and a one-click "Stay unlocked" that re-arms the timer. Any real activity
 *  (mouse/key) also dismisses it, so it only lingers for a genuinely idle user. */
function LockWarnBanner({ sec, onStay }: { sec: number; onStay: () => void }) {
  const p = usePalette();
  const { t } = useTranslation();
  return (
    <div
      role="alert"
      aria-live="assertive"
      style={{
        position: "fixed",
        top: 56,
        left: "50%",
        transform: "translateX(-50%)",
        zIndex: 9000,
        display: "flex",
        alignItems: "center",
        gap: 12,
        padding: "10px 14px",
        borderRadius: 12,
        background: p.bg1,
        border: `1px solid ${p.amber}`,
        boxShadow: "0 8px 28px rgba(0,0,0,0.35)",
        maxWidth: "calc(100% - 32px)",
      }}
    >
      <Icon name="lock" size={15} color={p.amber} />
      <span style={{ fontSize: 12.5, color: p.txt }}>{t("autolock.warn", { sec })}</span>
      <button
        onClick={onStay}
        style={{
          background: p.accent,
          color: p.accentInk ?? "#fff",
          border: "none",
          borderRadius: 8,
          padding: "6px 12px",
          fontSize: 12,
          fontWeight: 600,
          cursor: "pointer",
          whiteSpace: "nowrap",
        }}
      >
        {t("autolock.stay")}
      </button>
    </div>
  );
}

export function App() {
  const p = usePalette();
  const { t } = useTranslation();
  const route = useApp((s) => s.route);
  const device = useApp((s) => s.device);
  const overlay = useApp((s) => s.overlay);
  const unlocked = useApp((s) => s.unlocked);
  const autolockMin = useApp((s) => s.autolockMin);
  const booted = useApp((s) => s.booted);
  const boot = useApp((s) => s.boot);
  const ctx = useCtx();
  // Seconds left before an idle auto-lock, or null when no warning is showing.
  const [lockWarnSec, setLockWarnSec] = useState<number | null>(null);
  const rearmLockRef = useRef<() => void>(() => {});
  const [winW, setWinW] = useState(typeof window !== "undefined" ? window.innerWidth : 1200);
  const [sbCollapsed, setSbCollapsed] = useState(() => {
    try {
      return localStorage.getItem("unissh.sidebarCollapsed") === "1";
    } catch {
      return false;
    }
  });
  const [sbW, setSbW] = useState(() => {
    try {
      const v = parseInt(localStorage.getItem("unissh.sidebarW") || "220", 10);
      return Number.isFinite(v) ? Math.min(360, Math.max(180, v)) : 220;
    } catch {
      return 220;
    }
  });
  const toggleSidebar = () =>
    setSbCollapsed((c) => {
      const n = !c;
      try {
        localStorage.setItem("unissh.sidebarCollapsed", n ? "1" : "0");
      } catch {
        /* ignore */
      }
      return n;
    });
  const resizeSidebar = (clientX: number) => {
    const w = Math.min(360, Math.max(180, Math.round(clientX)));
    setSbW(w);
    try {
      localStorage.setItem("unissh.sidebarW", String(w));
    } catch {
      /* ignore */
    }
  };

  useEffect(() => {
    void boot();
    // auto-select the native mobile shell on phones
    try {
      const pf = platform();
      if (pf === "android" || pf === "ios") useApp.getState().setDevice("mobile");
    } catch {
      /* not in a Tauri context */
    }
  }, [boot]);

  useEffect(() => {
    const on = () => setWinW(window.innerWidth);
    window.addEventListener("resize", on);
    return () => window.removeEventListener("resize", on);
  }, []);

  // Auto-lock on idle. Re-arms whenever the instance unlocks or the setting
  // changes (store-backed), so a Settings change applies without a restart.
  // "never" (autolockMin === null) and the locked state both disable it.
  useEffect(() => {
    if (!unlocked || autolockMin === null) {
      setLockWarnSec(null);
      return;
    }
    const ms = autolockMin * 60_000;
    // Warn ~60s before locking; for short windows warn at the halfway mark so a
    // 1-minute setting still gets a heads-up rather than locking without notice.
    const warnLead = Math.min(60_000, Math.floor(ms / 2));
    let lockTimer: ReturnType<typeof setTimeout>;
    let warnTimer: ReturnType<typeof setTimeout>;
    let countdown: ReturnType<typeof setInterval> | undefined;
    const clearAll = () => {
      clearTimeout(lockTimer);
      clearTimeout(warnTimer);
      if (countdown) clearInterval(countdown);
    };
    const arm = () => {
      clearAll();
      setLockWarnSec(null);
      lockTimer = setTimeout(() => void useApp.getState().lockInstance(), ms);
      warnTimer = setTimeout(() => {
        let left = Math.round(warnLead / 1000);
        setLockWarnSec(left);
        countdown = setInterval(() => {
          left -= 1;
          setLockWarnSec(left > 0 ? left : 0);
        }, 1000);
      }, ms - warnLead);
    };
    rearmLockRef.current = arm;
    const events = ["mousemove", "mousedown", "keydown", "touchstart", "wheel"] as const;
    events.forEach((e) => window.addEventListener(e, arm, { passive: true }));
    arm(); // start the clock immediately
    return () => {
      clearAll();
      setLockWarnSec(null);
      events.forEach((e) => window.removeEventListener(e, arm));
    };
  }, [unlocked, autolockMin]);

  // Confirm-on-quit: intercept the window close when the setting is on and any
  // session (terminal / tunnel / broadcast / sftp) is still live, so closing the
  // window doesn't silently drop live work. Native dialog (blocks the close);
  // `confirmedClose` lets our own re-close pass straight through.
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let disposed = false;
    const confirmedClose = { current: false };
    void (async () => {
      try {
        const { getCurrentWindow } = await import("@tauri-apps/api/window");
        const win = getCurrentWindow();
        const u = await win.onCloseRequested(async (event) => {
          if (confirmedClose.current) return; // our own close — let it through
          let wantConfirm = true;
          try {
            wantConfirm = localStorage.getItem("unissh.confirmquit") !== "0";
          } catch {
            /* default on */
          }
          const s = useApp.getState();
          const live =
            s.terminals.length + s.tunnels.length + s.broadcasts.length + s.sftpSessions.length;
          if (!wantConfirm || live === 0) return; // nothing to lose — close normally
          event.preventDefault();
          let ok = false;
          try {
            const { confirm } = await import("@tauri-apps/plugin-dialog");
            ok = await confirm(t("quit.body", { count: live }), {
              title: t("quit.title"),
              kind: "warning",
              okLabel: t("quit.confirm"),
              cancelLabel: t("common.cancel"),
            });
          } catch {
            // If the dialog can't be shown, fail open: we already prevented the
            // close, so not re-closing would trap the user in an unquittable window.
            ok = true;
          }
          if (ok) {
            confirmedClose.current = true;
            void win.close();
          }
        });
        if (disposed) u();
        else unlisten = u;
      } catch {
        /* not in a Tauri context */
      }
    })();
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [t]);

  // global keyboard shortcuts (desktop)
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!(e.metaKey || e.ctrlKey)) return;
      const k = e.key.toLowerCase();
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
        // Cmd/Ctrl + (=/+): zoom the terminal font in
        e.preventDefault();
        useApp.getState().bumpTermZoom(1);
      } else if (k === "-" || k === "_") {
        // Cmd/Ctrl + -: zoom the terminal font out
        e.preventDefault();
        useApp.getState().bumpTermZoom(-1);
      } else if (k === "0") {
        // Cmd/Ctrl + 0: reset terminal font zoom
        e.preventDefault();
        useApp.getState().resetTermZoom();
      } else if (/[1-9]/.test(k)) {
        const r = ROUTES[parseInt(k, 10) - 1];
        if (r) {
          e.preventDefault();
          ctx.go(r);
        }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [ctx]);

  if (!booted) {
    return <div style={{ width: "100%", height: "100%", background: p.desk }} />;
  }

  const showApp = unlocked && !overlay;

  // Mobile shell — native experience. The entry overlays (onboarding / unlock /
  // Emergency Kit / repair / retry) and the modal/confirm/palette hosts must be
  // mounted here too, otherwise their store-driven actions (add host, search,
  // groups, import, delete-confirm, unlock) would silently no-op on a phone.
  if (device === "mobile") {
    return (
      <>
        {showApp && <MobileApp />}
        <EntryOverlays />
        {showApp && <Modals />}
        {showApp && <CommandPalette />}
        {showApp && <ImportPreview />}
        {showApp && <GroupsModal />}
        {showApp && lockWarnSec !== null && (
          <LockWarnBanner sec={lockWarnSec} onStay={() => rearmLockRef.current()} />
        )}
        <ConfirmDialog />
        <ShortcutsHelp />
        <ToastHost />
      </>
    );
  }

  return (
    <div
      style={{
        width: "100%",
        height: "100%",
        background: p.bg0,
        color: p.txt,
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
      }}
    >
      {/* in-app toolbar — window chrome is native (tauri decorations: true) */}
      <div
        style={{
          height: 44,
          flexShrink: 0,
          display: "flex",
          alignItems: "center",
          padding: "0 16px",
          gap: 14,
          borderBottom: `1px solid ${p.line}`,
          background: p.bg1,
        }}
      >
        <TitleBar />
      </div>

      {/* body */}
      <div style={{ flex: 1, display: "flex", minHeight: 0 }}>
        {showApp && (
          <Sidebar
            winW={winW}
            collapsed={sbCollapsed}
            width={sbW}
            onToggleCollapse={toggleSidebar}
            onResize={resizeSidebar}
          />
        )}
        {showApp && (
          <div className="uh-view" style={{ flex: 1, display: "flex", minWidth: 0, position: "relative" }}>
            {/* ViewTerminal stays mounted across navigation so open SSH sessions and
                their scrollback survive — switching routes must never reopen them */}
            <div style={{ display: route === "terminal" ? "flex" : "none", flex: 1, minWidth: 0 }}>
              <ViewTerminal />
            </div>
            {/* ViewSftp also stays mounted so open panes, current dirs, selection and
                in-flight transfers survive switching to the terminal (or any) tab */}
            <div style={{ display: route === "sftp" ? "flex" : "none", flex: 1, minWidth: 0 }}>
              <ViewSftp />
            </div>
            {route !== "terminal" && route !== "sftp" && <RenderView />}
          </div>
        )}
      </div>

      {/* overlays */}
      <EntryOverlays />
      {showApp && <Modals />}
      {showApp && <CommandPalette />}
      {showApp && <ImportPreview />}
      {showApp && <GroupsModal />}
      {showApp && lockWarnSec !== null && (
        <LockWarnBanner sec={lockWarnSec} onStay={() => rearmLockRef.current()} />
      )}
      <ConfirmDialog />
      <ShortcutsHelp />
      <ToastHost />
    </div>
  );
}
