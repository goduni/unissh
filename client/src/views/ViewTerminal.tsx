// Interactive PTY terminal — real xterm.js bound to the core's open_session via
// a Tauri Channel. Tabs come from the store; each tab holds one or more panes in
// a recursive split layout, and each pane owns its own session.

import { useEffect, useRef, useState, type CSSProperties } from "react";
import { Terminal as Xterm } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { SearchAddon } from "@xterm/addon-search";
import { WebLinksAddon } from "@xterm/addon-web-links";
import { openUrl } from "@tauri-apps/plugin-opener";
import { WebglAddon } from "@xterm/addon-webgl";
import { Unicode11Addon } from "@xterm/addon-unicode11";
import "@xterm/xterm/css/xterm.css";
import { usePalette, useTheme } from "@/theme/ThemeProvider";
import { MONO, rgba, termToXterm } from "@/theme/tokens";
import { Btn, Icon, NO_AUTOCORRECT, StatusDot } from "@/components/primitives";
import { ReconnectBanner } from "@/components/ReconnectBanner";
import { useTranslation, Trans } from "@/i18n";
import { useApp, type PendingMismatch, type TerminalPaneState, type TermLayout } from "@/store/app";
import { useIsMobile } from "@/store/responsive";
import { useCtx } from "@/store/ctx";
import * as api from "@/bridge/api";
import { apiErrorMessage, isApiError, type TermEvent } from "@/bridge/types";
import { writeText, readText } from "@tauri-apps/plugin-clipboard-manager";
import { isMac } from "@/bridge/platform";
import { ContextMenu } from "@/components/ContextMenu";
import { TermTabStrip } from "@/views/TermTabStrip";
import { useTerminalShortcuts } from "@/shell/useTerminalShortcuts";

// True only when the terminal host has a real layout box. A hidden ancestor
// (display:none on a route/tab switch) makes offsetParent null and the client
// dimensions 0; fitting then collapses the buffer to FitAddon's 2×1 minimum.
const hostLaidOut = (el: HTMLElement | null): boolean =>
  !!el && el.offsetParent !== null && el.clientWidth > 0 && el.clientHeight > 0;

// Base terminal font size before the user's zoom offset (phones a touch larger
// for legibility). Effective size = base + store `termZoom`.
const baseFontSize = (isMobile: boolean): number => (isMobile ? 14.5 : 13.5);

// Auto-reconnect backoff: cap the attempts so a host that's genuinely down can't
// loop forever (the manual Reconnect button gives a fresh budget afterwards).
const MAX_AUTO_RECONNECTS = 6;
// Online at least this long ⇒ treat the next drop as a fresh incident (reset the
// backoff budget), so a usable-but-flaky link that reconnects and runs for a bit
// keeps recovering, while a connect-then-instantly-drop loop still hits the cap.
const STABLE_ONLINE_MS = 10_000;
const backoffMs = (attempt: number): number => Math.min(15_000, 1_000 * 2 ** (attempt - 1));

function PasswordGate({ onSubmit }: { onSubmit: (pw: string) => void }) {
  const p = usePalette();
  const { t } = useTranslation();
  const isMobile = useIsMobile();
  const [pw, setPw] = useState("");
  return (
    <div
      style={{
        position: "absolute",
        inset: 0,
        display: "flex",
        // desktop keeps the original centered dialog; mobile top-anchors so the
        // software keyboard can't cover the field.
        alignItems: isMobile ? "flex-start" : "center",
        justifyContent: "center",
        paddingTop: isMobile ? "12vh" : 0,
        background: "rgba(0,0,0,0.4)",
        zIndex: 5,
      }}
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          onSubmit(pw);
        }}
        style={{
          background: p.bg1,
          border: `1px solid ${p.line2}`,
          borderRadius: 14,
          padding: 20,
          width: "min(320px, calc(100vw - 32px))",
          boxShadow: p.shadow,
        }}
      >
        <div style={{ fontWeight: 700, marginBottom: 10 }}>{t("terminal.passwordHeading")}</div>
        <input
          autoFocus
          {...NO_AUTOCORRECT}
          type="password"
          value={pw}
          onChange={(e) => setPw(e.target.value)}
          placeholder="••••••••"
          style={{
            width: "100%",
            padding: "10px 12px",
            borderRadius: 9,
            border: `1px solid ${p.line2}`,
            background: p.bg0,
            color: p.txt,
            fontFamily: MONO,
            fontSize: 14,
          }}
        />
        <button
          type="submit"
          style={{
            marginTop: 12,
            width: "100%",
            padding: "10px",
            borderRadius: 10,
            border: "none",
            background: p.accent,
            color: p.accentInk,
            fontWeight: 700,
            cursor: "pointer",
          }}
        >
          {t("terminal.connect")}
        </button>
      </form>
    </div>
  );
}

/** Key material part of a stored host key ("ssh-ed25519 AAAA…") — the same
 *  "stored" column the Known hosts ceremony shows next to the presented print. */
const storedKeyFp = (key: string): string => {
  const parts = key.trim().split(/\s+/);
  return parts.length >= 2 ? parts.slice(1).join(" ") : key;
};

/** In-pane host-key mismatch card — the security stop a failed connect surfaces.
 *  Deliberately sober in every theme (plain danger red, no accent/gradient): the
 *  two realities are named (key rotation vs MITM) and the only ways out are an
 *  explicit Reject or the full Verify & accept ceremony in Known hosts. Accepting
 *  the new key there clears this card (ViewKnown patches the stopped panes). Reject
 *  only dismisses the card and restores the pane's normal Reconnect affordance —
 *  it does NOT pin anything, so a re-dial to a still-mismatched host fails the same
 *  way and re-raises this card. Pinning still only happens in the Known ceremony. */
function HostKeyMismatchCard({
  mismatch,
  onReject,
}: {
  mismatch: PendingMismatch;
  onReject: () => void;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const knownHosts = useApp((s) => s.knownHosts);
  const stored = knownHosts.find((k) => k.host === mismatch.host && k.port === mismatch.port);
  const storedFp = stored ? storedKeyFp(stored.key) : "";
  const review = () => useApp.getState().reviewMismatch(mismatch);
  const label = mismatch.port !== 22 ? `${mismatch.host}:${mismatch.port}` : mismatch.host;
  return (
    <div
      style={{
        position: "absolute",
        inset: 0,
        zIndex: 6,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "rgba(0,0,0,0.5)",
        padding: 16,
      }}
    >
      <div
        style={{
          width: "min(460px, 100%)",
          borderRadius: 14,
          overflow: "hidden",
          background: p.bg1,
          border: `1px solid ${rgba(p.red, 0.55)}`,
          boxShadow: p.shadow,
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 11,
            padding: "13px 16px",
            background: rgba(p.red, 0.07),
            borderBottom: `1px solid ${rgba(p.red, 0.3)}`,
          }}
        >
          <span
            style={{
              width: 34,
              height: 34,
              borderRadius: 10,
              background: rgba(p.red, 0.18),
              border: `1px solid ${rgba(p.red, 0.5)}`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              flexShrink: 0,
            }}
          >
            <Icon name="alert" size={18} color={p.red} />
          </span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 14.5, fontWeight: 800, color: p.red }}>
              {t("known.mismatchTitle")}
            </div>
            <div style={{ fontFamily: MONO, fontSize: 12, color: p.txt2 }}>{label}</div>
          </div>
        </div>
        <div style={{ padding: "13px 16px", display: "flex", flexDirection: "column", gap: 12 }}>
          <div style={{ fontSize: 12.5, color: p.txt2, lineHeight: 1.5 }}>
            <Trans
              i18nKey="known.mismatchBody"
              values={{ host: mismatch.host }}
              components={{ b: <b style={{ color: p.txt }} /> }}
            />
          </div>
          <div>
            <div style={{ fontSize: 11, color: p.txt3, marginBottom: 3 }}>
              {t("known.stored")}
            </div>
            <div style={{ fontFamily: MONO, fontSize: 12, color: p.txt2, wordBreak: "break-all" }}>
              {storedFp || "—"}
            </div>
          </div>
          <div>
            <div style={{ fontSize: 11, color: p.txt3, marginBottom: 3 }}>
              {t("known.presentedNow")}
            </div>
            <div style={{ fontFamily: MONO, fontSize: 12, color: p.red, wordBreak: "break-all" }}>
              {mismatch.fingerprint || "—"}
            </div>
          </div>
          {/* Wrap the footer + let the danger label wrap so the full security review action stays readable in a narrow split pane. */}
          <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", flexWrap: "wrap" }}>
            <Btn variant="ghost" size="sm" onClick={onReject}>
              {t("known.reject")}
            </Btn>
            <Btn variant="danger" size="sm" icon="fingerprint" wrap onClick={review}>
              {t("known.review")}
            </Btn>
          </div>
        </div>
      </div>
    </div>
  );
}

function TerminalPane({
  tabId,
  pane,
  visible,
  focused,
  multi,
}: {
  tabId: string;
  pane: TerminalPaneState;
  visible: boolean;
  focused: boolean;
  multi: boolean;
}) {
  const { termTheme } = useTheme();
  const { t } = useTranslation();
  const p = usePalette();
  const hostRef = useRef<HTMLDivElement | null>(null);
  const xtermRef = useRef<Xterm | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const searchRef = useRef<SearchAddon | null>(null);
  const searchOpenRef = useRef(false);
  const searchInputRef = useRef<HTMLInputElement | null>(null);
  const sessionIdRef = useRef<string | null>(null);
  // Last cols/rows pushed to the PTY — so a divider drag (many ResizeObserver
  // fires per second) only sends window-change when the grid actually changes.
  const lastSentSizeRef = useRef<{ cols: number; rows: number } | null>(null);
  // The pane.gen the open-effect last acted on — lets a reconnect (gen bump) know
  // to forget the previous session id the store can't reach (see the open effect).
  const openedGenRef = useRef(-1);
  // In-terminal find (xterm SearchAddon). Cmd+F (macOS) / Ctrl+Shift+F opens it.
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  const [matches, setMatches] = useState<{ current: number; total: number } | null>(null);
  // Right-click Copy/Paste/Split menu position (null when closed). hasSel snapshots
  // whether there was a selection at open time, so Copy can disable itself.
  const [menu, setMenu] = useState<{ x: number; y: number; hasSel: boolean } | null>(null);
  // The pending auto-reconnect timer (transient, per-pane). The attempt *budget*
  // and last-online time live on the pane (store) so they survive a pane remount
  // and stay consistent across shells — see store TerminalPaneState.reconnects.
  const autoTimerRef = useRef<number | null>(null);
  const previewBufRef = useRef("");
  const previewTimerRef = useRef<number | null>(null);
  const decoderRef = useRef<TextDecoder | null>(null);
  const previewLinesRef = useRef<string[]>([]);
  const updatePane = useApp((s) => s.updatePane);
  const reconnectPane = useApp((s) => s.reconnectPane);
  const setActivePane = useApp((s) => s.setActivePane);
  const splitPane = useApp((s) => s.splitPane);
  const closePane = useApp((s) => s.closePane);
  const termZoom = useApp((s) => s.termZoom);
  const isMobile = useIsMobile();
  const needsPassword =
    pane.profile?.auth.type === "promptPassword" &&
    !pane.sessionId &&
    (pane.status === "connecting" || pane.status === "error");
  const [pw, setPw] = useState<string | null>(null);
  // Hover state so a split pane can offer an obvious close (✕) affordance.
  const [paneHover, setPaneHover] = useState(false);

  // init xterm once
  useEffect(() => {
    if (!hostRef.current) return;
    const isMobile = useApp.getState().device === "mobile";
    const term = new Xterm({
      fontFamily: MONO,
      fontSize: baseFontSize(isMobile) + useApp.getState().termZoom,
      lineHeight: 1.2,
      cursorBlink: true,
      theme: termToXterm(termTheme),
      // Render bold text in the (now distinct) bright palette and nudge any
      // too-low-contrast glyph so nothing comes out unreadable.
      drawBoldTextInBrightColors: true,
      minimumContrastRatio: 1.1,
      allowProposedApi: true,
      // When a TUI turns on mouse reporting (zellij/tmux/vim/htop), xterm forwards
      // drags to the app, so a plain drag no longer selects text — leaving nothing to
      // copy. xterm still lets you force a local selection with a modifier+drag: Shift
      // works out of the box on Linux/Windows, but on macOS the Option+drag override
      // is gated behind this flag (default false). Enable it so ⌥-drag selects inside
      // zellij (then ⌘C copies it) instead of being swallowed by the remote app.
      macOptionClickForcesSelection: true,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    try {
      // Open clicked hyperlinks in the system browser (webview default would
      // navigate the app frame itself). opener:default covers http(s)/mailto/tel.
      term.loadAddon(
        new WebLinksAddon((_event, uri) => {
          void openUrl(uri).catch(() => {});
        }),
      );
    } catch {
      /* ignore */
    }
    // Unicode 11 width tables so emoji and other post-Unicode-6 wide graphemes
    // advance the cursor by 2 cells like they paint — without this xterm's default
    // (v6) tables measure them as width 1 and pasted emoji overlap the next glyph.
    try {
      term.loadAddon(new Unicode11Addon());
      term.unicode.activeVersion = "11";
    } catch {
      /* fall back to built-in width tables */
    }
    term.open(hostRef.current);
    // The xterm helper <textarea> drives all keyboard input; stop the WebView from
    // spell-checking / auto-correcting / auto-capitalizing what gets typed into the
    // remote shell. xterm exposes no option for these, so set the DOM attrs directly.
    {
      const ta = term.textarea;
      if (ta) {
        ta.setAttribute("autocorrect", "off");
        ta.setAttribute("autocapitalize", "off");
        ta.setAttribute("autocomplete", "off");
        ta.setAttribute("spellcheck", "false");
      }
    }
    // GPU renderer for smoother scrolling on phones. The DOM renderer is fine on
    // desktop, so we leave the desktop path untouched (no renderer change there).
    // Mobile-only, feature-detected, and context-loss-safe → falls back to DOM.
    if (isMobile) {
      try {
        const probe = document.createElement("canvas");
        if (probe.getContext("webgl2") || probe.getContext("webgl")) {
          const webgl = new WebglAddon();
          webgl.onContextLoss(() => {
            try {
              webgl.dispose();
            } catch {
              /* ignore */
            }
          });
          term.loadAddon(webgl);
        }
      } catch {
        /* DOM renderer remains */
      }
    }
    try {
      fit.fit();
    } catch {
      /* ignore */
    }
    xtermRef.current = term;
    fitRef.current = fit;

    // Copy-on-select: mirror a *freshly made* mouse selection to the clipboard on
    // release (the familiar PuTTY/xterm behaviour). Gated on the primary button AND
    // an actual selection change, because when a TUI has mouse reporting on (zellij/
    // tmux) xterm keeps the old selection through bare/right clicks — without these
    // guards a later click (incl. the right-click that opens the Copy menu) would
    // re-copy stale text and clobber whatever the user copied elsewhere.
    const hostEl = hostRef.current;
    let selDirty = false;
    const selSub = term.onSelectionChange(() => {
      selDirty = true;
    });
    const onSelectionMouseUp = (e: MouseEvent) => {
      if (e.button !== 0 || !selDirty) return;
      selDirty = false;
      const sel = term.getSelection();
      if (sel) void writeText(sel);
    };
    hostEl?.addEventListener("mouseup", onSelectionMouseUp);

    // In-terminal search (find in scrollback).
    const search = new SearchAddon();
    term.loadAddon(search);
    searchRef.current = search;
    const resultsSub = search.onDidChangeResults((e) => {
      setMatches(
        e.resultCount === 0
          ? { current: 0, total: 0 }
          : { current: e.resultIndex >= 0 ? e.resultIndex + 1 : 0, total: e.resultCount },
      );
    });
    // Cmd+F (macOS) / Ctrl+Shift+F opens find; plain Ctrl+F is left to the shell
    // (readline forward-char). Escape closes it. attachCustomKeyEventHandler runs
    // only while THIS terminal has focus, so other panes/tabs are unaffected.
    term.attachCustomKeyEventHandler((ev) => {
      if (ev.type !== "keydown") return true;
      const isF = ev.key === "f" || ev.key === "F";
      if (isF && ((ev.metaKey && !ev.ctrlKey) || (ev.ctrlKey && ev.shiftKey))) {
        setSearchOpen(true);
        setTimeout(() => searchInputRef.current?.select(), 0);
        return false;
      }
      if (ev.key === "Escape" && searchOpenRef.current) {
        setSearchOpen(false);
        return false;
      }
      // Keyboard copy. macOS keeps ⌘C (the browser's native copy event handles it)
      // and leaves Ctrl+C as interrupt. On Linux/Windows, Ctrl+Shift+C always copies
      // the selection, and a bare Ctrl+C copies *only when something is selected* —
      // with no selection it falls through below as the SIGINT ^C, then clears the
      // selection so a second Ctrl+C interrupts.
      if (!isMac() && (ev.key === "c" || ev.key === "C") && ev.ctrlKey && !ev.altKey && !ev.metaKey) {
        const sel = term.getSelection();
        if (ev.shiftKey) {
          if (sel) void writeText(sel);
          return false;
        }
        if (sel) {
          void writeText(sel);
          term.clearSelection();
          return false;
        }
      }
      return true;
    });

    term.onData((data) => {
      const id = sessionIdRef.current;
      if (id) void api.sessionWrite(id, Array.from(new TextEncoder().encode(data)));
    });

    // While the pane is hidden (display:none on a route/tab switch) its host box
    // collapses to 0×0. FitAddon then clamps to its 2×1 minimum and rewraps the
    // whole scrollback to 2 columns — lossily, so returning leaves the last line
    // truncated; it also pushes that bogus 2×1 size to the PTY, which makes the
    // remote line editor's redraw (e.g. on Right-arrow) duplicate text. Skip the
    // fit entirely while not laid out; the ResizeObserver fires again with the real
    // size once the pane is visible, so a correct fit still runs exactly once.
    const refit = () => {
      if (!hostLaidOut(hostRef.current)) return;
      try {
        fit.fit();
        const id = sessionIdRef.current;
        if (id && term.cols > 0 && term.rows > 0) {
          const last = lastSentSizeRef.current;
          if (!last || last.cols !== term.cols || last.rows !== term.rows) {
            lastSentSizeRef.current = { cols: term.cols, rows: term.rows };
            void api.sessionResize(id, term.cols, term.rows);
          }
        }
      } catch {
        /* ignore */
      }
    };
    const ro = new ResizeObserver(refit);
    ro.observe(hostRef.current);

    // iOS doesn't always fire the ResizeObserver on rotation / keyboard changes,
    // so re-fit explicitly on those too (debounced past the layout settling).
    // Mobile-only so the desktop path registers no extra listeners.
    const onOrient = () => window.setTimeout(refit, 150);
    if (isMobile) {
      window.addEventListener("orientationchange", onOrient);
      window.visualViewport?.addEventListener("resize", refit);
    }

    return () => {
      ro.disconnect();
      hostEl?.removeEventListener("mouseup", onSelectionMouseUp);
      selSub.dispose();
      window.removeEventListener("orientationchange", onOrient);
      window.visualViewport?.removeEventListener("resize", refit);
      resultsSub.dispose();
      term.dispose();
      if (previewTimerRef.current != null) {
        clearTimeout(previewTimerRef.current);
        previewTimerRef.current = null;
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // live-apply terminal theme changes
  useEffect(() => {
    if (xtermRef.current) xtermRef.current.options.theme = termToXterm(termTheme);
  }, [termTheme]);

  // live-apply font zoom: resize the glyphs, then re-fit + push the new geometry
  // to the PTY so cols/rows stay in sync (same path the ResizeObserver uses).
  useEffect(() => {
    const term = xtermRef.current;
    const fit = fitRef.current;
    if (!term || !fit) return;
    const isMobile = useApp.getState().device === "mobile";
    term.options.fontSize = baseFontSize(isMobile) + termZoom;
    if (!hostLaidOut(hostRef.current)) return;
    try {
      fit.fit();
      const id = sessionIdRef.current;
      if (id && term.cols > 0 && term.rows > 0) void api.sessionResize(id, term.cols, term.rows);
    } catch {
      /* ignore */
    }
  }, [termZoom]);

  // open the session (once we have auth). Re-runs on a reconnect (pane.gen bumped),
  // re-opening in the SAME pane so the xterm scrollback is preserved.
  useEffect(() => {
    if (!pane.profile) return;
    if (pane.profile.auth.type === "promptPassword" && pw == null) return;
    const term = xtermRef.current;
    if (!term) return;
    // A reconnect bumps pane.gen; the store has already closed the previous backend
    // session, so forget the id this component still holds (a ref the store can't
    // reach) — otherwise the guard below would wrongly block the reopen and leave
    // the pane stuck in "connecting" (e.g. a "Reconnect" on an already-online tab).
    if (openedGenRef.current !== pane.gen) sessionIdRef.current = null;
    // This component already owns the live session for this pane → don't double-open.
    if (sessionIdRef.current) return;
    // The store carries a session id this FRESH component never opened — a genuine
    // remount (e.g. the desktop⇄mobile device toggle disposes and re-creates the
    // terminal). We can't re-attach to that backend Channel, so reconnect once to
    // give the new xterm a live session instead of leaving the pane permanently dead.
    if (pane.sessionId) {
      if (openedGenRef.current !== pane.gen) {
        openedGenRef.current = pane.gen; // one-shot until the reconnect bumps gen
        reconnectPane(tabId, pane.id, false);
      }
      return;
    }
    openedGenRef.current = pane.gen;
    // If this run is superseded (another gen bump) or the pane is torn down while a
    // connect is in flight, `cancelled` tells the resolving promise to abandon and
    // close its session so it never leaks or double-opens.
    let cancelled = false;
    // We're (re)connecting now: cancel any pending auto-reconnect timer so an
    // auto-retry and a manual/store-driven reconnect can't both fire.
    if (autoTimerRef.current != null) {
      clearTimeout(autoTimerRef.current);
      autoTimerRef.current = null;
    }
    if (pane.gen > 0) {
      term.writeln("");
      term.writeln(`\x1b[2m— ${t("terminal.reconnecting")} —\x1b[0m`);
    }
    // Schedule the next auto-reconnect attempt (backoff + cap), with the budget
    // read/written on the pane. Used by both a drop and a failed reopen.
    const scheduleAutoReconnect = () => {
      if (!useApp.getState().autoReconnect) return;
      const lt = useApp.getState().terminals.flatMap((x) => x.panes).find((x) => x.id === pane.id);
      if (!lt || lt.reconnects >= MAX_AUTO_RECONNECTS) return;
      const attempt = lt.reconnects + 1;
      updatePane(tabId, pane.id, { reconnects: attempt });
      const delay = backoffMs(attempt);
      term.writeln(`\x1b[2m${t("terminal.reconnectingIn", { s: Math.round(delay / 1000) })}\x1b[0m`);
      autoTimerRef.current = window.setTimeout(() => {
        autoTimerRef.current = null;
        useApp.getState().reconnectPane(tabId, pane.id);
      }, delay);
    };
    const profile = pane.profile;
    const vaultId = useApp.getState().vaultId || "";
    // Keep a rolling window of recent output lines so the hosts-rail shows a
    // stable multi-line preview (real output, debounced — not just the latest
    // tail, which at an idle prompt would collapse to one line).
    const stripAnsi = (str: string) =>
      str
        .replace(/\x1b\][\s\S]*?(?:\x07|\x1b\\)/g, "") // OSC
        .replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, "") // CSI
        .replace(/\x1b[@-Z\\-_]/g, "") // other escapes
        .replace(/[\x00-\x08\x0b-\x1f\x7f]/g, ""); // stray controls
    const lastLine = (s: string) => (s.includes("\r") ? s.slice(s.lastIndexOf("\r") + 1) : s);
    const capturePreview = (bytes: Uint8Array) => {
      if (!decoderRef.current) decoderRef.current = new TextDecoder();
      const parts = (
        previewBufRef.current + decoderRef.current.decode(bytes, { stream: true })
      )
        .replace(/\r\n/g, "\n") // PTY uses CRLF; normalize so lines aren't lost
        .split("\n");
      previewBufRef.current = (parts.pop() ?? "").slice(-2000); // incomplete trailing line
      for (const raw of parts) {
        const clean = stripAnsi(lastLine(raw)).replace(/\s+$/, "");
        if (clean.trim().length) {
          previewLinesRef.current.push(clean);
          if (previewLinesRef.current.length > 6) previewLinesRef.current.shift();
        }
      }
      if (previewTimerRef.current != null) return;
      previewTimerRef.current = window.setTimeout(() => {
        previewTimerRef.current = null;
        const partial = stripAnsi(lastLine(previewBufRef.current)).replace(/\s+$/, "");
        const all = partial.trim().length
          ? [...previewLinesRef.current, partial]
          : previewLinesRef.current;
        updatePane(tabId, pane.id, { preview: all.slice(-3) });
      }, 500);
    };
    const onEvent = (e: TermEvent) => {
      if (cancelled) return; // superseded / torn-down pane — ignore late events
      if (e.type === "data") {
        const bytes = new Uint8Array(e.bytes);
        term.write(bytes);
        capturePreview(bytes);
      } else {
        // exit < 0 ⇒ no clean exit status (peer died / keepalive gave up) ⇒ a drop
        // we can auto-recover. A clean shell `exit` (code ≥ 0) stays closed.
        const dropped = e.exit < 0;
        term.writeln("");
        term.writeln(`\x1b[2m${t("terminal.sessionClosed", { code: e.exit })}\x1b[0m`);
        const old = sessionIdRef.current;
        sessionIdRef.current = null;
        // Evict the now-dead session from the core's map so reconnects don't leak it.
        if (old) void api.sessionClose(old).catch(() => {});
        updatePane(tabId, pane.id, { status: "closed", sessionId: null });
        if (dropped) {
          // A session that stayed online a while earns a fresh attempt budget.
          const lt = useApp.getState().terminals.flatMap((x) => x.panes).find((x) => x.id === pane.id);
          if (lt?.lastOnlineAt && Date.now() - lt.lastOnlineAt > STABLE_ONLINE_MS)
            updatePane(tabId, pane.id, { reconnects: 0 });
          scheduleAutoReconnect();
        }
      }
    };
    // Personal profiles resolve their credential in-core (binding + anti-redirect)
    // before connecting; everything else uses the stored ProfileAuth.
    void api
      .resolveConnectAuth(profile, vaultId, pw ?? undefined)
      .then(({ user, auth }) =>
        api.sessionOpen(
          {
            host: profile.host,
            port: profile.port,
            user,
            auth,
            jumps: profile.jumps,
            term: "xterm-256color",
            cols: term.cols || 80,
            rows: term.rows || 24,
          },
          onEvent,
        ),
      )
      .then((id) => {
        // The pane was torn down or superseded by another reconnect while this
        // connect was in flight → close the just-opened session instead of leaking
        // it (and don't adopt it into a stale component).
        if (cancelled) {
          void api.sessionClose(id).catch(() => {});
          return;
        }
        sessionIdRef.current = id;
        lastSentSizeRef.current = { cols: term.cols || 80, rows: term.rows || 24 };
        updatePane(tabId, pane.id, { sessionId: id, status: "online", lastOnlineAt: Date.now() });
        // Refresh the host's "recently connected" timestamp on every (re)connect.
        if (profile) useApp.getState().markConnected(profile.profileId);
        term.focus();
      })
      .catch((err) => {
        if (cancelled) return;
        term.writeln(`\x1b[31m${apiErrorMessage(err)}\x1b[0m`);
        sessionIdRef.current = null;
        const lt = useApp.getState().terminals.flatMap((x) => x.panes).find((x) => x.id === pane.id);
        // Host-key mismatch is a security stop, not a connectivity failure: surface
        // the Accept/Reject ceremony (in-pane card + the Known hosts banner) instead
        // of the generic dead-pane, and never auto-retry — a retry can't succeed and
        // would keep re-offering a possibly hostile key.
        const mismatch: PendingMismatch | undefined =
          isApiError(err) && err.kind === "hostKeyMismatch"
            ? {
                host: err.host ?? profile.host,
                port: err.port ?? profile.port,
                fingerprint: err.fingerprint ?? "",
              }
            : undefined;
        updatePane(tabId, pane.id, { status: "error", error: apiErrorMessage(err), mismatch });
        if (mismatch) {
          useApp.getState().setPendingMismatch(mismatch);
          return;
        }
        // A Personal host whose FIRST connect fails is almost always unbound / has
        // no personal vault yet (resolve_personal_auth rejected). Open the
        // link-identity modal so the user can fix it, instead of being stranded at
        // a raw error in a dead terminal. (Only on the first attempt — never on
        // reconnect blips of an already-working bound host.)
        if (
          profile.auth.type === "personal" &&
          !lt?.lastOnlineAt &&
          (lt?.reconnects ?? 0) === 0
        ) {
          useApp.getState().openModal({ kind: "bindHost", host: profile, vaultId });
        }
        // A promptPassword host that never once connected likely got a wrong password
        // → clear it so the PasswordGate reappears for a fresh attempt, instead of the
        // pane silently retrying the same bad password on every reconnect.
        if (profile.auth.type === "promptPassword" && !lt?.lastOnlineAt) setPw(null);
        // A failed REOPEN mid-reconnect (host still unreachable) keeps retrying with
        // backoff; an initial connect failure (reconnects===0, e.g. bad auth) does not.
        if ((lt?.reconnects ?? 0) > 0) scheduleAutoReconnect();
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pw, pane.gen]);

  // When this tab becomes visible, (re)fit to the now-real box and realign the PTY;
  // focus the terminal if this is the tab's active pane.
  useEffect(() => {
    if (visible && xtermRef.current) {
      setTimeout(() => {
        try {
          const term = xtermRef.current;
          if (!term || !hostLaidOut(hostRef.current)) return;
          fitRef.current?.fit();
          // Re-align the PTY to the now-correct size too: if a stale width slipped
          // through earlier, resizing xterm alone wouldn't fix the remote's wrapping.
          const id = sessionIdRef.current;
          if (id && term.cols > 0 && term.rows > 0) void api.sessionResize(id, term.cols, term.rows);
          if (focused) term.focus();
        } catch {
          /* ignore */
        }
      }, 30);
    }
  }, [visible, focused]);

  // Cancel a pending auto-reconnect if the pane goes away.
  useEffect(
    () => () => {
      if (autoTimerRef.current != null) clearTimeout(autoTimerRef.current);
    },
    [],
  );

  // Keep the (stable) xterm key handler's view of search-open current.
  useEffect(() => {
    searchOpenRef.current = searchOpen;
  }, [searchOpen]);

  const findDecor = {
    matchBackground: p.accentSoft,
    activeMatchBackground: p.accent,
    matchOverviewRuler: p.accent,
    activeMatchColorOverviewRuler: p.accent,
  };

  // Run/refresh the find as the query or open-state changes; clear on close.
  useEffect(() => {
    const sa = searchRef.current;
    if (!sa) return;
    if (!searchOpen) {
      sa.clearDecorations();
      setMatches(null);
      xtermRef.current?.focus();
      return;
    }
    const q = searchTerm.trim();
    if (q) sa.findNext(q, { decorations: findDecor });
    else {
      sa.clearDecorations();
      setMatches(null);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchOpen, searchTerm]);

  const runFind = (dir: "next" | "prev") => {
    const sa = searchRef.current;
    const q = searchTerm.trim();
    if (!sa || !q) return;
    if (dir === "next") sa.findNext(q, { decorations: findDecor });
    else sa.findPrevious(q, { decorations: findDecor });
  };

  const searchBtnStyle = {
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    width: 24,
    height: 24,
    background: "transparent",
    border: "none",
    borderRadius: 6,
    color: p.txt3,
    cursor: "pointer",
  } as const;

  // Manual reconnect: a fresh attempt budget (manual=true) and start now. The open
  // effect cancels any pending auto-retry timer when it re-runs.
  const manualReconnect = () => reconnectPane(tabId, pane.id, true);

  // Copy the current selection (plain text, not a secret → no auto-clear). Used by
  // the right-click menu; the keyboard/copy-on-select paths write inline.
  const copySelection = () => {
    const sel = xtermRef.current?.getSelection();
    if (sel) void writeText(sel);
  };
  // Paste clipboard text into the PTY. xterm.paste handles bracketed-paste mode.
  const pasteClipboard = async () => {
    const term = xtermRef.current;
    if (!term) return;
    try {
      const txt = await readText();
      if (txt) term.paste(txt);
    } catch {
      /* clipboard empty or unavailable */
    }
    term.focus();
  };

  return (
    <div
      onMouseDown={() => {
        if (!focused) setActivePane(tabId, pane.id);
      }}
      onMouseEnter={() => setPaneHover(true)}
      onMouseLeave={() => setPaneHover(false)}
      style={{
        position: "absolute",
        inset: 0,
        background: termTheme.bg,
        // Inner breathing room so the shell text isn't flush against the chrome
        // edges. Same colour as the terminal, so it reads as padding, not a frame.
        padding: 8,
        // Focus ring: only when this pane shares its tab with others, so a single
        // terminal isn't boxed for no reason.
        boxShadow: focused && multi ? `inset 0 0 0 2px ${p.accent}` : "none",
      }}
      onContextMenu={(e) => {
        e.preventDefault();
        setMenu({ x: e.clientX, y: e.clientY, hasSel: !!xtermRef.current?.getSelection() });
      }}
    >
      <div ref={hostRef} style={{ width: "100%", height: "100%" }} />
      {/* Split panes get an explicit ✕ on hover so closing one is discoverable
          (the right-click menu and Ctrl/Cmd+W still work too). */}
      {multi && paneHover && !searchOpen && (
        <button
          onMouseDown={(e) => {
            e.preventDefault(); // keep keyboard focus on the active pane's terminal
            e.stopPropagation();
          }}
          onClick={() => closePane(tabId, pane.id)}
          title={t("terminal.menu.closePane")}
          aria-label={t("terminal.menu.closePane")}
          style={{
            position: "absolute",
            top: 6,
            right: 6,
            zIndex: 7,
            width: 20,
            height: 20,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            borderRadius: 6,
            border: `1px solid ${p.line2}`,
            background: p.bg1,
            color: p.txt2,
            cursor: "pointer",
          }}
        >
          <Icon name="x" size={12} />
        </button>
      )}
      {visible && searchOpen && (
        <div
          style={{
            position: "absolute",
            top: 10,
            right: 12,
            zIndex: 6,
            display: "flex",
            alignItems: "center",
            gap: 4,
            padding: "4px 5px 4px 8px",
            borderRadius: 9,
            background: p.bg1,
            border: `1px solid ${p.line2}`,
            boxShadow: "0 6px 20px rgba(0,0,0,0.28)",
          }}
        >
          <input
            ref={searchInputRef}
            autoFocus
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                runFind(e.shiftKey ? "prev" : "next");
              } else if (e.key === "Escape") {
                e.preventDefault();
                setSearchOpen(false);
              }
            }}
            placeholder={t("terminal.search.placeholder")}
            {...NO_AUTOCORRECT}
            style={{
              width: 150,
              background: p.bg2,
              border: `1px solid ${p.line2}`,
              borderRadius: 6,
              color: p.txt,
              fontFamily: MONO,
              fontSize: 12,
              padding: "4px 7px",
              outline: "none",
            }}
          />
          <span
            style={{
              minWidth: 40,
              textAlign: "center",
              fontSize: 11,
              color: p.txt3,
              fontVariantNumeric: "tabular-nums",
            }}
          >
            {searchTerm.trim() === ""
              ? ""
              : matches && matches.total > 0
                ? `${matches.current}/${matches.total}`
                : t("terminal.search.noMatches")}
          </span>
          <button
            onClick={() => runFind("prev")}
            title={t("terminal.search.prev")}
            aria-label={t("terminal.search.prev")}
            style={searchBtnStyle}
          >
            <span style={{ display: "inline-flex", transform: "rotate(180deg)" }}>
              <Icon name="cd" size={13} />
            </span>
          </button>
          <button
            onClick={() => runFind("next")}
            title={t("terminal.search.next")}
            aria-label={t("terminal.search.next")}
            style={searchBtnStyle}
          >
            <Icon name="cd" size={13} />
          </button>
          <button
            onClick={() => setSearchOpen(false)}
            title={t("terminal.search.close")}
            aria-label={t("terminal.search.close")}
            style={searchBtnStyle}
          >
            <Icon name="x" size={13} />
          </button>
        </div>
      )}
      {needsPassword && pw == null && <PasswordGate onSubmit={(v) => setPw(v)} />}
      {/* Host-key mismatch: the security card replaces the reconnect affordance on
          BOTH shells (it renders inside the shared pane) — a mismatch must never
          offer a plain Reconnect. */}
      {pane.mismatch && (
        <HostKeyMismatchCard
          mismatch={pane.mismatch}
          onReject={() => {
            const m = pane.mismatch;
            // Clear the global banner ONLY if it's still THIS pane's mismatch — a
            // different pane may have raised a different one meanwhile, and we
            // must not silently dismiss its security stop.
            const g = useApp.getState().pendingMismatch;
            if (m && g && g.host === m.host && g.port === m.port)
              useApp.getState().setPendingMismatch(null);
            updatePane(tabId, pane.id, { mismatch: undefined });
          }}
        />
      )}
      {/* Desktop reconnect bar for a dropped/failed session. The mobile shell renders
          the same banner (strip variant) in MTerminal, so this is desktop-only. */}
      {!isMobile && (pane.status === "closed" || pane.status === "error") && !pane.mismatch && (
        <ReconnectBanner pane={pane} onReconnect={manualReconnect} variant="float" />
      )}
      {menu && (
        <ContextMenu
          x={menu.x}
          y={menu.y}
          onClose={() => setMenu(null)}
          items={[
            {
              icon: "copy",
              label: t("terminal.menu.copy"),
              disabled: !menu.hasSel,
              onClick: copySelection,
            },
            { icon: "clipboard", label: t("terminal.menu.paste"), onClick: () => void pasteClipboard() },
            { icon: "grid", label: t("terminal.menu.splitRight"), onClick: () => splitPane(tabId, pane.id, "row") },
            { icon: "list", label: t("terminal.menu.splitDown"), onClick: () => splitPane(tabId, pane.id, "col") },
            { icon: "x", label: t("terminal.menu.closePane"), danger: true, onClick: () => closePane(tabId, pane.id) },
          ]}
        />
      )}
    </div>
  );
}

// Flattened layout geometry. We render every pane in a single keyed, absolutely-
// positioned list (rects computed from the split tree) instead of a nested
// component tree — so splitting/closing a pane never changes another pane's
// position in the React tree, and its xterm instance (scrollback + live session)
// survives untouched. All values are percentages of the tab viewport.
interface Rect {
  left: number;
  top: number;
  width: number;
  height: number;
}
interface PaneRect {
  paneId: string;
  rect: Rect;
}
interface SplitRect {
  splitId: string;
  dir: "row" | "col";
  region: Rect; // the area this split occupies (for divider-drag ratio math)
  boundary: number; // divider position along the split axis (percent)
}

function collectLayout(node: TermLayout, rect: Rect, panes: PaneRect[], splits: SplitRect[]): void {
  if (node.kind === "pane") {
    panes.push({ paneId: node.paneId, rect });
    return;
  }
  if (node.dir === "row") {
    const wA = rect.width * node.ratio;
    collectLayout(node.a, { left: rect.left, top: rect.top, width: wA, height: rect.height }, panes, splits);
    collectLayout(
      node.b,
      { left: rect.left + wA, top: rect.top, width: rect.width - wA, height: rect.height },
      panes,
      splits,
    );
    splits.push({ splitId: node.id, dir: "row", region: rect, boundary: rect.left + wA });
  } else {
    const hA = rect.height * node.ratio;
    collectLayout(node.a, { left: rect.left, top: rect.top, width: rect.width, height: hA }, panes, splits);
    collectLayout(
      node.b,
      { left: rect.left, top: rect.top + hA, width: rect.width, height: rect.height - hA },
      panes,
      splits,
    );
    splits.push({ splitId: node.id, dir: "col", region: rect, boundary: rect.top + hA });
  }
}

/** Draggable split divider. Positioned absolutely over the seam; drag adjusts the
 *  split's ratio relative to its own region (nested splits resize correctly). */
function Divider({ tabId, split, lineColor }: { tabId: string; split: SplitRect; lineColor: string }) {
  const setSplitRatio = useApp((s) => s.setSplitRatio);
  const ref = useRef<HTMLDivElement>(null);
  const rafRef = useRef<number | null>(null);
  const ratioRef = useRef(0.5);
  const movedRef = useRef(false);
  const row = split.dir === "row";

  const startDrag = (e: React.MouseEvent) => {
    e.preventDefault();
    movedRef.current = false;
    // offsetParent is the tab viewport (nearest positioned ancestor) → its pixel
    // box lets us map a pointer position back to a ratio within this split's region.
    const container = ref.current?.offsetParent as HTMLElement | null;
    if (!container) return;
    const flush = () => {
      rafRef.current = null;
      setSplitRatio(tabId, split.splitId, ratioRef.current);
    };
    const move = (ev: MouseEvent) => {
      const cr = container.getBoundingClientRect();
      const r = row
        ? (ev.clientX - (cr.left + (split.region.left / 100) * cr.width)) /
          ((split.region.width / 100) * cr.width)
        : (ev.clientY - (cr.top + (split.region.top / 100) * cr.height)) /
          ((split.region.height / 100) * cr.height);
      ratioRef.current = Math.min(0.9, Math.max(0.1, r));
      movedRef.current = true;
      if (rafRef.current == null) rafRef.current = requestAnimationFrame(flush);
    };
    const up = () => {
      window.removeEventListener("mousemove", move);
      window.removeEventListener("mouseup", up);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      if (rafRef.current != null) {
        cancelAnimationFrame(rafRef.current);
        rafRef.current = null;
      }
      // Only commit if the pointer actually moved — a bare click must not snap the
      // split back to the ratioRef default.
      if (movedRef.current) setSplitRatio(tabId, split.splitId, ratioRef.current);
    };
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseup", up);
    document.body.style.cursor = row ? "col-resize" : "row-resize";
    document.body.style.userSelect = "none";
  };

  const style: CSSProperties = row
    ? {
        position: "absolute",
        left: `${split.boundary}%`,
        top: `${split.region.top}%`,
        height: `${split.region.height}%`,
        width: 6,
        transform: "translateX(-3px)",
        cursor: "col-resize",
      }
    : {
        position: "absolute",
        top: `${split.boundary}%`,
        left: `${split.region.left}%`,
        width: `${split.region.width}%`,
        height: 6,
        transform: "translateY(-3px)",
        cursor: "row-resize",
      };
  return (
    <div ref={ref} onMouseDown={startDrag} style={{ ...style, zIndex: 4 }}>
      {/* the visible 1px seam, centred in the wider hit area */}
      <div
        style={
          row
            ? { position: "absolute", left: 2.5, top: 0, bottom: 0, width: 1, background: lineColor }
            : { position: "absolute", top: 2.5, left: 0, right: 0, height: 1, background: lineColor }
        }
      />
    </div>
  );
}

type DropDir = "left" | "right" | "top" | "bottom";

/** Which edge of a pane the pointer is nearest — picks the split direction when a
 *  tab is dragged onto it. Four triangular zones meeting at the centre. */
function dropDir(rect: DOMRect, x: number, y: number): DropDir {
  const fx = (x - rect.left) / rect.width;
  const fy = (y - rect.top) / rect.height;
  const dl = fx;
  const dr = 1 - fx;
  const dt = fy;
  const db = 1 - fy;
  const m = Math.min(dl, dr, dt, db);
  return m === dl ? "left" : m === dr ? "right" : m === dt ? "top" : "bottom";
}

/** Highlight the half a dropped tab would take, so the split direction is obvious. */
function DropOverlay({ dir, accent }: { dir: DropDir; accent: string }) {
  const half: CSSProperties =
    dir === "left"
      ? { left: 0, top: 0, width: "50%", height: "100%" }
      : dir === "right"
        ? { left: "50%", top: 0, width: "50%", height: "100%" }
        : dir === "top"
          ? { left: 0, top: 0, width: "100%", height: "50%" }
          : { left: 0, top: "50%", width: "100%", height: "50%" };
  return (
    <div
      style={{
        position: "absolute",
        ...half,
        background: rgba(accent, 0.22),
        border: `2px solid ${accent}`,
        borderRadius: 6,
        pointerEvents: "none",
        zIndex: 8,
      }}
    />
  );
}

export function ViewTerminal() {
  const p = usePalette();
  const { termTheme } = useTheme();
  const { t } = useTranslation();
  const ctx = useCtx();
  const isMobile = useIsMobile();
  const terminals = useApp((s) => s.terminals);
  const activeTermId = useApp((s) => s.activeTermId);
  const hosts = useApp((s) => s.hosts);
  const setActiveTerm = useApp((s) => s.setActiveTerm);
  const closeTerminal = useApp((s) => s.closeTerminal);
  const closeOtherTerminals = useApp((s) => s.closeOtherTerminals);
  const closeTerminalsToRight = useApp((s) => s.closeTerminalsToRight);
  const duplicateTerminal = useApp((s) => s.duplicateTerminal);
  const renameTerminal = useApp((s) => s.renameTerminal);
  const moveTerminal = useApp((s) => s.moveTerminal);
  const reconnectPane = useApp((s) => s.reconnectPane);
  const splitPane = useApp((s) => s.splitPane);
  const draggingTabId = useApp((s) => s.draggingTabId);
  const mergeTabIntoPane = useApp((s) => s.mergeTabIntoPane);
  const active = terminals.find((tb) => tb.id === activeTermId) || terminals[terminals.length - 1];
  const focusedPane = active?.panes.find((pp) => pp.id === active.activePaneId) ?? active?.panes[0];
  // Which pane + edge a dragged tab would drop onto (for the highlight overlay).
  const [dropZone, setDropZone] = useState<{ paneId: string; dir: DropDir } | null>(null);

  // Desktop keyboard shortcuts (new/close/split/jump/cycle/focus).
  useTerminalShortcuts(!isMobile);

  // A drag that ends anywhere (dropped on a tab, cancelled, …) clears the overlay.
  useEffect(() => {
    if (!draggingTabId) setDropZone(null);
  }, [draggingTabId]);

  // Every pane across ALL tabs is rendered in ONE flat list keyed by paneId, so a
  // pane keeps its React identity (xterm + live session) when it moves between tabs
  // (drag-merge) — only its rect/visibility change. Dividers are rendered only for
  // the active tab (they carry no session state).
  const paneEntries = terminals.flatMap((tab) => {
    const panes: PaneRect[] = [];
    const splits: SplitRect[] = [];
    collectLayout(tab.layout, { left: 0, top: 0, width: 100, height: 100 }, panes, splits);
    const tabActive = tab.id === active?.id;
    return panes.map((pr) => ({ tab, rect: pr.rect, paneId: pr.paneId, tabActive }));
  });
  const activeSplits: SplitRect[] = [];
  if (active) collectLayout(active.layout, { left: 0, top: 0, width: 100, height: 100 }, [], activeSplits);

  // Visible connection word paired with the status dot, so the colour is never the
  // sole carrier of the connection state (the dot alone would be).
  const statusWord =
    focusedPane?.status === "online"
      ? t("terminal.status.online")
      : focusedPane?.status === "connecting"
        ? t("terminal.status.connecting")
        : focusedPane?.status === "error"
          ? t("terminal.status.error")
          : focusedPane?.status === "closed"
            ? t("terminal.status.closed")
            : null;

  const statusBtn = {
    display: "inline-flex",
    alignItems: "center",
    justifyContent: "center",
    width: 22,
    height: 22,
    background: "transparent",
    border: "none",
    borderRadius: 6,
    color: p.txt3,
    cursor: "pointer",
  } as const;

  return (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", background: p.bg0, minWidth: 0 }}>
      {/* tab bar — desktop only; the mobile shell (MTerminal) provides its own
          session switcher + status, so this multi-tab chrome is hidden there */}
      {!isMobile && (
        <TermTabStrip
          terminals={terminals}
          activeId={active?.id ?? null}
          hosts={hosts}
          // App chrome, not terminal colours — the tab strip isn't the PTY yet.
          bg={p.bg0}
          onActivate={setActiveTerm}
          onClose={closeTerminal}
          onCloseOthers={closeOtherTerminals}
          onCloseRight={closeTerminalsToRight}
          onDuplicate={duplicateTerminal}
          onRename={renameTerminal}
          onReconnect={(id) => {
            const tab = useApp.getState().terminals.find((x) => x.id === id);
            if (tab) reconnectPane(id, tab.activePaneId, true);
          }}
          onReorder={moveTerminal}
          onPickHost={(h) => ctx.connect(h)}
        />
      )}

      {/* viewport */}
      <div style={{ flex: 1, position: "relative", minHeight: 0 }}>
        {terminals.length === 0 && (
          <div
            style={{
              position: "absolute",
              inset: 0,
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              justifyContent: "center",
              gap: 10,
              color: p.txt3,
              // App chrome, not terminal colours — there is no PTY yet.
              background: p.bg0,
            }}
          >
            <Icon name="terminal" size={34} color={p.txt3} />
            <div style={{ fontSize: 14 }}>{t("terminal.noSessions")}</div>
            <div
              onClick={() => ctx.go("hosts")}
              style={{ fontSize: 13, color: p.accent, cursor: "pointer" }}
            >
              {t("terminal.openHost")}
            </div>
          </div>
        )}
        {/* One flat keyed list across ALL tabs (see paneEntries): a pane keeps its
            React identity — and thus its xterm scrollback + live session — across
            tab switches, splits AND drag-merges into another tab. Only the active
            tab's panes are laid out; the rest are display:none. */}
        {paneEntries.map(({ tab, rect, paneId, tabActive }) => {
          const pane = tab.panes.find((pp) => pp.id === paneId);
          if (!pane) return null;
          return (
            <div
              key={paneId}
              onDragOver={(e) => {
                // Accept a tab dragged from the strip → merge it in as a split.
                if (!draggingTabId || draggingTabId === tab.id) return;
                e.preventDefault();
                const dir = dropDir(e.currentTarget.getBoundingClientRect(), e.clientX, e.clientY);
                setDropZone((prev) =>
                  prev && prev.paneId === paneId && prev.dir === dir ? prev : { paneId, dir },
                );
              }}
              onDragLeave={(e) => {
                if (e.currentTarget.contains(e.relatedTarget as Node)) return;
                setDropZone((prev) => (prev?.paneId === paneId ? null : prev));
              }}
              onDrop={(e) => {
                const src = useApp.getState().draggingTabId;
                setDropZone(null);
                if (!src || src === tab.id) return;
                e.preventDefault();
                const dir = dropDir(e.currentTarget.getBoundingClientRect(), e.clientX, e.clientY);
                mergeTabIntoPane(src, tab.id, paneId, dir);
              }}
              style={{
                position: "absolute",
                left: `${rect.left}%`,
                top: `${rect.top}%`,
                width: `${rect.width}%`,
                height: `${rect.height}%`,
                display: tabActive ? "block" : "none",
              }}
            >
              <TerminalPane
                tabId={tab.id}
                pane={pane}
                visible={tabActive}
                focused={tab.activePaneId === paneId}
                multi={tab.panes.length > 1}
              />
              {dropZone?.paneId === paneId && <DropOverlay dir={dropZone.dir} accent={p.accent} />}
            </div>
          );
        })}
        {active &&
          activeSplits.map((s) => (
            <Divider key={s.splitId} tabId={active.id} split={s} lineColor={p.line} />
          ))}
      </div>

      {/* status bar — desktop only (mobile keeps chrome minimal) */}
      {!isMobile && (
        <div
          style={{
            height: 30,
            flexShrink: 0,
            // App chrome stays neutral mono (bg0); a single hairline separates it
            // from the PTY body, which keeps its own terminal theme. Only the
            // terminal itself is tinted by the active colour scheme.
            background: p.bg0,
            borderTop: `1px solid ${p.line}`,
            display: "flex",
            alignItems: "center",
            gap: 10,
            padding: "0 14px",
            fontFamily: MONO,
            fontSize: 11.5,
            color: p.txt3,
          }}
        >
          <StatusDot
            status={
              focusedPane?.status === "online"
                ? "online"
                : focusedPane?.status === "connecting"
                  ? "connecting"
                  : focusedPane?.status === "error"
                    ? "error"
                    : "unknown"
            }
            size={8}
            label={statusWord}
            srLabel={focusedPane?.status}
          />
          {focusedPane?.profile && (
            // Ellipsize the host so a long user@host token can't push the theme/settings control off the fixed-height bar.
            <span
              style={{
                color: p.txt2,
                minWidth: 0,
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
            >
              {focusedPane.profile.user
                ? `${focusedPane.profile.user}@${focusedPane.profile.host}`
                : focusedPane.profile.host}
            </span>
          )}
          {active && focusedPane && (
            <>
              <button
                onClick={() => splitPane(active.id, focusedPane.id, "row")}
                title={t("terminal.splitRight")}
                aria-label={t("terminal.splitRight")}
                style={statusBtn}
              >
                <Icon name="grid" size={12} />
              </button>
              <button
                onClick={() => splitPane(active.id, focusedPane.id, "col")}
                title={t("terminal.splitDown")}
                aria-label={t("terminal.splitDown")}
                style={statusBtn}
              >
                <Icon name="list" size={12} />
              </button>
            </>
          )}
          <div style={{ flex: 1 }} />
          <span
            onClick={() => ctx.go("settings")}
            // Keep the rightmost theme control intact; the host span ellipsizes first.
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 5,
              cursor: "pointer",
              whiteSpace: "nowrap",
              flexShrink: 0,
            }}
            title={t("terminal.themeTitle")}
          >
            {t("terminal.theme", { name: termTheme.name })}
            <Icon name="sliders" size={12} />
          </span>
        </div>
      )}
    </div>
  );
}
