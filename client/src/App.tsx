import { useEffect, useRef, useState } from "react";
import { platform } from "@tauri-apps/plugin-os";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { listen } from "@tauri-apps/api/event";
import {
  purgeExternalEditScratch,
  resumeExternalEdits,
  setSourceResolver,
  stopAllExternalEdits,
  useExternalEdits,
} from "@/sftp/external-edit";
import { sourceFor } from "@/bridge/sources";
import { confirm } from "@tauri-apps/plugin-dialog";
import { usePalette, useTheme } from "@/theme/ThemeProvider";
import { designPx, rem, ROOT_FONT_PX, rootFontPx, TEXT } from "@/theme/tokens";
import * as api from "@/bridge/api";
import { useApp } from "@/store/app";
import { useCtx } from "@/store/ctx";
import { useTranslation } from "@/i18n";
import { Icon } from "@/components/primitives";
import { UpdateBanner } from "@/components/UpdateBanner";
import { Sidebar, TitleBar, WindowControls } from "@/shell/Shell";
import { ResizeEdges } from "@/shell/WindowChrome";
import { isDesktopOs, isMac } from "@/bridge/platform";
import { opensSettings, terminalOwnsTabDigits } from "@/support/hotkeys";
import { createSystemLockWatcher, handleSystemLockEvent } from "@/support/systemLock";
import type { SystemLockEventPayload, SystemLockWatcher } from "@/support/systemLock";
import { useUpdate } from "@/store/update";
import { BOOT_CHECK_DELAY_MS, PERIODIC_CHECK_MS } from "@/bridge/updater";

import { ViewHosts } from "@/views/ViewHosts";
import { ViewTerminal } from "@/views/ViewTerminal";
import { shouldRetryOnResume } from "@/views/terminal/paneSession";
import { ViewRun } from "@/views/ViewRun";
import { ViewSftp } from "@/views/sftp/ViewSftp";
import { ViewTunnels } from "@/views/ViewTunnels";
import { ViewKnown } from "@/views/ViewKnown";
import { ViewSecrets } from "@/views/ViewSecrets";
import { ViewSettings } from "@/views/ViewSettings";

import { EntryOverlays } from "@/overlays/Entry";
import { Modals } from "@/overlays/Modals";
import { ViewRecordings } from "@/views/ViewRecordings";
import { ViewSnippets } from "@/views/ViewSnippets";
import { AuthPrompt } from "@/overlays/AuthPrompt";
import { AgentApproval } from "@/overlays/AgentApproval";
import { CommandPalette } from "@/overlays/CommandPalette";
import { SettingsOverlay } from "@/overlays/SettingsOverlay";
import { ImportPreview } from "@/overlays/ImportPreview";
import { GroupsModal } from "@/overlays/GroupsModal";
import { ConfirmDialog, ShortcutsHelp, ToastHost } from "@/overlays/Feedback";
import { MobileApp } from "@/mobile/MobileApp";

const ROUTES = ["hosts", "terminal", "fleet", "broadcast", "sftp", "tunnels", "known", "recordings", "snippets", "keys"] as const;

function RenderView() {
  const route = useApp((s) => s.route);
  switch (route) {
    case "hosts":
      return <ViewHosts />;
    case "terminal":
      return null; // rendered persistently in App() so sessions/scrollback survive navigation
    case "run":
    case "fleet":
    case "broadcast":
      return <ViewRun />;
    case "sftp":
      return null; // rendered persistently in App() so panes/cwd/selection survive navigation
    case "tunnels":
      return <ViewTunnels />;
    case "known":
      return <ViewKnown />;
    case "recordings":
      return <ViewRecordings />;
    case "snippets":
      return <ViewSnippets />;
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
        top: rem(56),
        left: "50%",
        transform: "translateX(-50%)",
        zIndex: 9000,
        display: "flex",
        alignItems: "center",
        gap: rem(12),
        padding: `${rem(10)} ${rem(14)}`,
        borderRadius: 12,
        background: p.bg1,
        border: `1px solid ${p.amber}`,
        boxShadow: "0 8px 28px rgba(0,0,0,0.35)",
        maxWidth: "calc(100% - 32px)",
      }}
    >
      <Icon name="lock" size={15} color={p.amber} />
      <span style={{ fontSize: TEXT.base, color: p.txt }}>{t("autolock.warn", { sec })}</span>
      <button
        onClick={onStay}
        style={{
          background: p.accent,
          color: p.accentInk ?? "#fff",
          border: "none",
          borderRadius: 8,
          padding: `${rem(6)} ${rem(12)}`,
          fontSize: TEXT.small,
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
  const { uiScale } = useTheme();
  const { t } = useTranslation();
  const route = useApp((s) => s.route);
  const device = useApp((s) => s.device);
  const customChrome = useApp((s) => s.customChrome);
  const overlay = useApp((s) => s.overlay);
  const unlocked = useApp((s) => s.unlocked);
  const autolockMin = useApp((s) => s.autolockMin);
  const osLockGrace = useApp((s) => s.osLockGrace);
  const booted = useApp((s) => s.booted);
  const boot = useApp((s) => s.boot);
  const ctx = useCtx();
  // Seconds left before an idle auto-lock, or null when no warning is showing.
  const [lockWarnSec, setLockWarnSec] = useState<number | null>(null);
  const rearmLockRef = useRef<() => void>(() => {});
  // Owns the OS-lock grace decision; created once so the Tauri subscription
  // below is set up once too (see the effect).
  const sysLockRef = useRef<SystemLockWatcher | null>(null);
  // The BOOLEAN, not the width. Only one question is ever asked of the window
  // width (Shell.tsx Sidebar: is there room for the full sidebar, or the rail?),
  // and holding the raw pixel value in root state answered it at a ruinous price:
  // the number changes on every pixel, so every frame of an interactive resize
  // re-rendered App and with it the entire tree. A boolean changes twice in the
  // life of a drag, and React drops the rest. This was felt as resize lag, and
  // felt worst under tiling compositors, where windows are resized constantly
  // rather than only when someone grabs an edge.
  // 880 DESIGN pixels, not CSS: the sidebar and the view beside it both grow
  // with the interface scale, so the width at which they stop fitting grows too.
  const [wide, setWide] = useState(
    typeof window !== "undefined"
      ? window.innerWidth >= (880 * rootFontPx(uiScale)) / ROOT_FONT_PX
      : true,
  );
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
  // Stored in DESIGN pixels, not device pixels: the drag reports where the
  // pointer is on screen, and at 150 % that is 1.5x the number the layout is
  // written in. Converting here keeps a width the user chose meaning the same
  // proportion of the interface at every scale, instead of shrinking back to a
  // truncating sliver the moment they scale up.
  const resizeSidebar = (clientX: number) => {
    const w = Math.min(360, Math.max(180, Math.round(designPx(clientX, uiScale))));
    setSbW(w);
    try {
      localStorage.setItem("unissh.sidebarW", String(w));
    } catch {
      /* ignore */
    }
  };

  // Returning from the background is not a network blip.
  //
  // A phone suspends the app: timers stop, the TCP connections die, and on the
  // way down the pane burns retries against a machine that was never going to
  // answer. Coming back, the user then waits out an exponential backoff that was
  // computed for a flaky link — or finds the retry budget already spent and the
  // pane simply dead.
  //
  // So a resume is treated as what it is: a deliberate act, equivalent to the
  // user pressing reconnect. That resets the budget and retries at once. Only
  // panes that are actually dead are touched; a session that survived is left
  // alone rather than being torn down and rebuilt for no reason.
  useEffect(() => {
    const onVisible = () => {
      if (document.visibilityState !== "visible") return;
      const st = useApp.getState();
      if (!st.unlocked) return;
      for (const tab of st.terminals) {
        for (const pane of tab.panes) {
          if (shouldRetryOnResume(pane)) st.reconnectPane(tab.id, pane.id, true);
        }
      }
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => document.removeEventListener("visibilitychange", onVisible);
  }, []);

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

  // Re-asked when the interface scale changes, not only on resize: the window
  // did not move, but the number of design pixels it holds did.
  useEffect(() => {
    const on = () => setWide(window.innerWidth >= (880 * rootFontPx(uiScale)) / ROOT_FONT_PX);
    on();
    window.addEventListener("resize", on);
    return () => window.removeEventListener("resize", on);
  }, [uiScale]);

  // Desktop auto-update. One check a few seconds after boot — late enough that it
  // never competes with unlock and session restore — then a slow tick for windows
  // left open for days. Both go through the same one-per-hour throttle and the
  // user's preference (see bridge/updater), so this schedule is an upper bound on
  // how often UniSSH talks to github.com, not a promise that it will.
  useEffect(() => {
    if (device === "mobile") return; // sideload targets have no updater at all
    const run = () => void useUpdate.getState().check(false);
    const first = setTimeout(run, BOOT_CHECK_DELAY_MS);
    const tick = setInterval(run, PERIODIC_CHECK_MS);
    return () => {
      clearTimeout(first);
      clearInterval(tick);
    };
  }, [device]);

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
      lockTimer = setTimeout(() => void useApp.getState().lockInstance("idle"), ms);
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

  // Lock when the OS does. The idle timer only ever watched this window, so
  // locking the screen — the single clearest "I am leaving" a user gives — did
  // nothing, and closing the lid suspended the machine with the vault open and
  // an idle timer that does not tick while asleep. The native listeners emit one
  // `system-lock` event; every decision about it lives in the grace module, and
  // the lock itself is the same `lockInstance()` the manual and idle paths call,
  // so there is exactly one place zeroize can be got wrong.
  //
  // Subscribed ONCE, on mount: the setting and the vault state are pushed into
  // the watcher by the effects below rather than re-subscribing, so there is no
  // window during which a screen lock lands between an unsubscribe and the next
  // `listen()` resolving. Absent signals (a phone, a plain browser preview, a
  // desktop whose session emits neither) are a no-op, not an error.
  useEffect(() => {
    const watcher = createSystemLockWatcher({
      // The watcher names the cause, and it is not always the signal that armed
      // the timer: a suspend overtakes a screen lock still inside its grace.
      lock: (cause) => useApp.getState().lockInstance(cause),
      grace: useApp.getState().osLockGrace,
      unlocked: useApp.getState().unlocked,
    });
    sysLockRef.current = watcher;
    let dispose: (() => void) | undefined;
    let alive = true;
    void (async () => {
      try {
        const un = await listen<SystemLockEventPayload>("system-lock", (e) =>
          handleSystemLockEvent(e.payload, {
            watcher,
            releaseSuspend: api.systemLockAck,
          }),
        );
        if (alive) dispose = un;
        else un();
      } catch {
        /* no Tauri context, or no listener registered on this platform */
      }
    })();
    return () => {
      alive = false;
      dispose?.();
      watcher.dispose();
      sysLockRef.current = null;
    };
  }, []);

  useEffect(() => {
    sysLockRef.current?.setGrace(osLockGrace);
  }, [osLockGrace]);

  useEffect(() => {
    sysLockRef.current?.setUnlocked(unlocked);
  }, [unlocked]);

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
        const win = getCurrentWindow();
        // EVERYTHING below runs inside Tauri's close path, which is unforgiving:
        // window.js does `await handler(evt)` and only then
        // `if (!evt.isPreventDefault()) await this.destroy()`, with no catch and
        // no timeout. So a handler that throws, or that simply never settles,
        // does not merely skip the confirmation — it permanently disables closing
        // the window, by our own button, by the WM hotkey and by the compositor
        // alike, leaving Ctrl+C in the launching terminal as the only way out.
        // Hence: no bare property access, no unbounded await. Every failure here
        // fails OPEN, because a lost confirmation dialog is survivable and an
        // unquittable window is not.
        const u = await win.onCloseRequested(async (event) => {
          if (confirmedClose.current) return; // our own close — let it through
          // Deleting the external-edit copies is irreversible, so it may only
          // happen once the close is certain — a user who cancels the quit
          // dialog must still find the file their editor has open. Bounded and
          // caught, like everything on this path: a cleanup that hangs must not
          // be what makes the window unquittable, and the startup purge is the
          // backstop if it does.
          const cleanup = async () => {
            try {
              await Promise.race([
                stopAllExternalEdits(),
                new Promise<void>((resolve) => setTimeout(resolve, 2_000)),
              ]);
            } catch {
              /* ignore */
            }
          };
          let wantConfirm = true;
          try {
            wantConfirm = localStorage.getItem("unissh.confirmquit") !== "0";
          } catch {
            /* default on */
          }
          let live = 0;
          try {
            const s = useApp.getState();
            live =
              s.terminals.length +
              s.tunnels.length +
              s.broadcasts.length +
              s.sftpSessions.length +
              // External edits count as something to lose: quitting deletes
              // their copies, and an edit whose session already died is exactly
              // the case where that copy holds the only version of the work —
              // while contributing nothing to any of the counts above.
              useExternalEdits.getState().edits.length;
          } catch {
            live = 0; // store unreadable — treat as nothing to lose, never trap
          }
          // "Confirm quit" is an opt-out of the SESSION prompt. It is not
          // consent to delete files, so an outstanding edit still asks — that
          // copy can be the only place a change exists.
          let editCount = 0;
          try {
            editCount = useExternalEdits.getState().edits.length;
          } catch {
            editCount = 0; // unreadable — never trap the window over a count
          }
          if (editCount === 0 && (!wantConfirm || live === 0)) {
            await cleanup();
            return;
          }
          event.preventDefault();
          let ok = false;
          let answered = false;
          try {
            // Race the dialog against a deadline. A native dialog that never
            // resolves is not hypothetical on Linux — an undecorated window under
            // a compositor that declines to map the transient would hang this
            // await forever, and the close is already prevented by this point.
            const edits = editCount;
            // Both, not one instead of the other: the sessions explain the
            // prompt, the edits explain what confirming destroys.
            const sessions = live - edits;
            const body = [
              sessions > 0 ? t("quit.body", { count: sessions }) : "",
              edits > 0 ? t("quit.bodyEdits", { count: edits }) : "",
            ]
              .filter(Boolean)
              .join("\n\n");
            // `answered` is set by the DIALOG's own resolution, never by the
            // deadline — the difference decides whether we may delete anything.
            const dialog = confirm(body, {
              title: t("quit.title"),
              kind: "warning",
              okLabel: t("quit.confirm"),
              cancelLabel: t("common.cancel"),
            }).then((v) => {
              answered = true;
              return v;
            });
            ok = await Promise.race([
              dialog,
              new Promise<boolean>((resolve) => setTimeout(() => resolve(true), 10_000)),
            ]);
          } catch {
            // If the dialog can't be shown, fail open: we already prevented the
            // close, so not re-closing would trap the user in an unquittable window.
            ok = true;
          }
          if (ok) {
            // The 10s deadline exists so an unshowable dialog cannot trap the
            // user in an unquittable window — it is not an answer. Closing on it
            // is survivable; DELETING on it is not, because a copy can hold the
            // only version of a change. So the timeout closes and leaves the
            // copies for the next start to collect.
            if (answered) await cleanup();
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

  // Locking stops the external-edit poll but keeps the copies; this is what
  // starts it again. Driven from the unlocked flag rather than from the unlock
  // screen, so every path that unlocks — keychain, password, repair — resumes.
  useEffect(() => {
    if (unlocked) resumeExternalEdits();
  }, [unlocked]);

  // Registered HERE rather than in the SFTP view: an overlay (the recovery kit,
  // say) unmounts that view while the sessions behind it are perfectly alive,
  // and a resolver that disappeared with it would strand every live edit in
  // "session closed" a minute later.
  const sftpSessions = useApp((s) => s.sftpSessions);
  useEffect(() => {
    setSourceResolver((sessionId, profileId) => {
      const session =
        sftpSessions.find((s) => s.id === sessionId) ??
        sftpSessions.find((s) => s.profileId === profileId && profileId);
      if (!session) return null;
      try {
        return { source: sourceFor({ kind: "remote", sessionId: session.id }, sftpSessions), sessionId: session.id };
      } catch {
        return null;
      }
    });
  }, [sftpSessions]);

  // Anything left in the external-edit scratch directory is from a previous run
  // — a crash, a kill -9, a close that timed out — and holds decrypted remote
  // file contents. Nothing can be watching it yet, so it all goes.
  useEffect(() => {
    // Deliberately not awaited anywhere: it samples other runs' heartbeats
    // across an interval, so it takes half a minute by design. Nothing depends
    // on its result.
    void purgeExternalEditScratch();
  }, []);

  // global keyboard shortcuts (desktop)
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
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
    };
    // Capture phase, so no descendant can swallow a global shortcut before it is
    // seen. xterm is the reason: it cancels the keys it recognises with
    // stopPropagation, and a bubble-phase listener on window never runs for
    // those — which is how ⌘K opened the palette everywhere except the terminal.
    // The terminal ALSO hands these back untouched (support/hotkeys.ts), so the
    // key does not reach the shell as well; this half only guarantees the app
    // sees it at all.
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
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
        {/* Phone-shell PREVIEW on a desktop OS (Ctrl/Cmd+Shift+M): a real phone
            has no window chrome, but the frameless desktop window still needs
            drag + controls — without this strip the toggled window could be
            neither moved nor closed. MobileApp shifts down 36px to match.
            Also gated on customChrome: with a real frame the window manager
            already provides both, and MobileApp's 36px offset is keyed to the
            same condition. */}
        {isDesktopOs() && customChrome && (
          <div
            data-tauri-drag-region
            style={{
              position: "fixed",
              top: 0,
              left: 0,
              right: 0,
              height: rem(36),
              display: "flex",
              alignItems: "center",
              padding: `0 ${rem(10)}`,
              background: p.bg1,
              borderBottom: `1px solid ${p.line}`,
              zIndex: 10,
            }}
          >
            {!isMac() && <WindowControls />}
          </div>
        )}
        {showApp && <MobileApp />}
        <EntryOverlays />
        {showApp && <Modals />}
        {showApp && <AuthPrompt />}
        {showApp && <AgentApproval />}
        {showApp && <CommandPalette />}
        {showApp && <ImportPreview />}
        {showApp && <GroupsModal />}
        {showApp && lockWarnSec !== null && (
          <LockWarnBanner sec={lockWarnSec} onStay={() => rearmLockRef.current()} />
        )}
        <ConfirmDialog />
        <ShortcutsHelp />
        <ToastHost />
        <ResizeEdges />
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
      {/* in-app toolbar doubling as the title bar — the window is frameless
          (tauri decorations: false; macOS overlays its traffic lights here).
          data-tauri-drag-region gives back dragging + dblclick-maximize.
          macOS runs the bar slightly shorter: the native lights sit on the OS's
          own line (we never move them), and 38px puts the bar's centerline on
          that line instead of 5px below it. */}
      {/* Gone entirely when the window manager owns the frame — not hidden, not
          collapsed to zero height. A tiling WM gives the window every pixel it
          has and expects the app to use them; leaving a 44px strip of our own
          chrome up there would be the exact thing the setting exists to remove. */}
      {customChrome && (
        <div
          data-tauri-drag-region
          style={{
            height: isMac() ? rem(38) : rem(44),
            flexShrink: 0,
            display: "flex",
            alignItems: "center",
            padding: `0 ${rem(16)}`,
            gap: rem(14),
            borderBottom: `1px solid ${p.line}`,
            background: p.bg1,
          }}
        >
          <TitleBar />
        </div>
      )}

      {/* body */}
      <div style={{ flex: 1, display: "flex", minHeight: 0 }}>
        {showApp && (
          <Sidebar
            wide={wide}
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
      {showApp && <AuthPrompt />}
      {showApp && <CommandPalette />}
      {showApp && <SettingsOverlay />}
      {showApp && <ImportPreview />}
      {showApp && <GroupsModal />}
      {showApp && lockWarnSec !== null && (
        <LockWarnBanner sec={lockWarnSec} onStay={() => rearmLockRef.current()} />
      )}
      {showApp && <UpdateBanner />}
      <ConfirmDialog />
      <ShortcutsHelp />
      <ToastHost />
      <ResizeEdges />
    </div>
  );
}
