// Interactive PTY terminal — real xterm.js bound to the core's open_session via
// a Tauri Channel. Tabs come from the store; each tab holds one or more panes in
// a recursive split layout, and each pane owns its own session.

import { useEffect, useRef, useState, type CSSProperties } from "react";
import { Terminal as Xterm, type IDisposable, type IMarker } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { SearchAddon } from "@xterm/addon-search";
import { WebLinksAddon } from "@xterm/addon-web-links";
import { openUrl } from "@tauri-apps/plugin-opener";
import { WebglAddon } from "@xterm/addon-webgl";
import { Unicode11Addon } from "@xterm/addon-unicode11";
import "@xterm/xterm/css/xterm.css";
import { usePalette, useTheme } from "@/theme/ThemeProvider";
import { MONO, rem, rgba, termOptions, TEXT } from "@/theme/tokens";
import { Btn, Icon, NO_AUTOCORRECT, StatusDot, type IconName } from "@/components/primitives";
import { ReconnectBanner } from "@/components/ReconnectBanner";
import { useTranslation, Trans } from "@/i18n";
import {
  paneProfile,
  useApp,
  type PendingMismatch,
  type TerminalPaneState,
  type TermLayout,
} from "@/store/app";
import { useIsMobile } from "@/store/responsive";
import { splitLocalTerminal, useCtx } from "@/store/ctx";
import { localRecordingRequest, useLocalMachine } from "@/store/localShell";
import { createPaneEvents, type PaneEvents } from "@/views/terminal/paneSession";
import { parseOsc52 } from "@/views/terminal/osc52";
import { resetStaleAppModes } from "@/views/terminal/staleModes";
import * as api from "@/bridge/api";
import { apiErrorMessage, isApiError, type ConnectionProfile } from "@/bridge/types";
import { writeText, readText } from "@tauri-apps/plugin-clipboard-manager";
import { isMac } from "@/bridge/platform";
import { isAppChord } from "@/support/hotkeys";
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
          borderRadius: 16,
          padding: rem(20),
          width: `min(${rem(320)}, calc(100vw - 32px))`,
          boxShadow: p.shadow,
        }}
      >
        <div style={{ fontWeight: 700, marginBottom: rem(10) }}>{t("terminal.passwordHeading")}</div>
        <input
          autoFocus
          {...NO_AUTOCORRECT}
          type="password"
          value={pw}
          onChange={(e) => setPw(e.target.value)}
          placeholder="••••••••"
          style={{
            width: "100%",
            padding: `${rem(10)} ${rem(12)}`,
            borderRadius: 8,
            border: `1px solid ${p.line2}`,
            background: p.bg0,
            color: p.txt,
            fontFamily: MONO,
            fontSize: TEXT.body,
          }}
        />
        <button
          type="submit"
          style={{
            marginTop: rem(12),
            width: "100%",
            padding: rem(10),
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
        padding: rem(16),
      }}
    >
      <div
        style={{
          width: `min(${rem(460)}, 100%)`,
          borderRadius: 16,
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
            gap: rem(11),
            padding: `${rem(13)} ${rem(16)}`,
            background: rgba(p.red, 0.07),
            borderBottom: `1px solid ${rgba(p.red, 0.3)}`,
          }}
        >
          <span
            style={{
              width: rem(34),
              height: rem(34),
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
            <div style={{ fontSize: TEXT.body, fontWeight: 800, color: p.red }}>
              {t("known.mismatchTitle")}
            </div>
            <div style={{ fontFamily: MONO, fontSize: TEXT.small, color: p.txt2 }}>{label}</div>
          </div>
        </div>
        <div style={{ padding: `${rem(13)} ${rem(16)}`, display: "flex", flexDirection: "column", gap: rem(12) }}>
          <div style={{ fontSize: TEXT.base, color: p.txt2, lineHeight: 1.5 }}>
            <Trans
              i18nKey="known.mismatchBody"
              values={{ host: mismatch.host }}
              components={{ b: <b style={{ color: p.txt }} /> }}
            />
          </div>
          <div>
            <div style={{ fontSize: TEXT.micro, color: p.txt3, marginBottom: rem(3) }}>
              {t("known.stored")}
            </div>
            <div style={{ fontFamily: MONO, fontSize: TEXT.small, color: p.txt2, wordBreak: "break-all" }}>
              {storedFp || "—"}
            </div>
          </div>
          <div>
            <div style={{ fontSize: TEXT.micro, color: p.txt3, marginBottom: rem(3) }}>
              {t("known.presentedNow")}
            </div>
            <div style={{ fontFamily: MONO, fontSize: TEXT.small, color: p.red, wordBreak: "break-all" }}>
              {mismatch.fingerprint || "—"}
            </div>
          </div>
          {/* Wrap the footer + let the danger label wrap so the full security review action stays readable in a narrow split pane. */}
          <div style={{ display: "flex", gap: rem(8), justifyContent: "flex-end", flexWrap: "wrap" }}>
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
  const { termTheme, termPrefs } = useTheme();
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
  // The live session's event plumbing (preview accumulation + its debounce), so
  // an unmount can drop a pending preview push into a pane that no longer exists.
  const eventsRef = useRef<PaneEvents | null>(null);
  // Held outside the init effect so the cleanup can reach it; the effect owns the
  // array's contents.
  const shellMarksRef = useRef<
    { marker: IMarker; exit?: number; decoration?: IDisposable }[] | null
  >(null);
  const updatePane = useApp((s) => s.updatePane);
  const reconnectPane = useApp((s) => s.reconnectPane);
  const setActivePane = useApp((s) => s.setActivePane);
  const splitPane = useApp((s) => s.splitPane);
  const setPaneTitle = useApp((s) => s.setPaneTitle);
  const closePane = useApp((s) => s.closePane);
  const termZoom = useApp((s) => s.termZoom);
  const isMobile = useIsMobile();
  const needsPassword =
    paneProfile(pane)?.auth.type === "promptPassword" &&
    !pane.sessionId &&
    (pane.status === "connecting" || pane.status === "error");
  const [pw, setPw] = useState<string | null>(null);
  // Hover state so a split pane can offer an obvious close (✕) affordance.
  const [paneHover, setPaneHover] = useState(false);

  /** Types a host's startup snippets into a freshly opened session.
 *
 * Typed, not executed: each snippet is sent followed by a newline, because a
 * startup command that never runs is useless — unlike the palette, where the
 * user is choosing one interactively and Enter must stay theirs. The list is
 * ordered, so they are sent in sequence.
 *
 * Failures are swallowed on purpose: a missing snippet (deleted on another
 * device, not yet synced) must not turn a working connection into an error.
 */
async function runStartupSnippets(
  sessionId: string,
  profile: ConnectionProfile | null,
  vaultId: string,
) {
  const ids = profile?.startupSnippetIds ?? [];
  if (!ids.length || !vaultId) return;
  try {
    const library = await api.listSnippets(vaultId);
    const byId = new Map(library.map((s) => [s.snippetId, s]));
    const enc = new TextEncoder();
    for (const id of ids) {
      const snippet = byId.get(id);
      if (!snippet) continue;
      await api.sessionWrite(sessionId, Array.from(enc.encode(snippet.command + "\n")));
    }
  } catch {
    /* a startup snippet must never break the session it was meant to set up */
  }
}

// init xterm once
  useEffect(() => {
    if (!hostRef.current) return;
    const isMobile = useApp.getState().device === "mobile";
    // Read once at mount, like every other option here: switching renderer on a
    // live pane means tearing down and rebuilding it, which would drop the
    // scrollback. The setting takes effect on the next pane.
    const gpuRendering = useApp.getState().gpuRendering;
    // Every xterm option comes from termOptions() — the same function the live settings
    // preview uses — so the preview can never drift from a real pane. termPrefs is read
    // once at mount; later changes reach the pane through the live-apply effect below,
    // NOT by re-running this effect (that would destroy the scrollback and session).
    const term = new Xterm(
      termOptions(termPrefs, termTheme, baseFontSize(isMobile) + useApp.getState().termZoom),
    );
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
    // GPU renderer. Always on for phones (scrolling is visibly smoother there);
    // opt-in on desktop, where the DOM renderer is already adequate and the WebGL
    // addon can render nothing at all on some drivers. Feature-detected and
    // context-loss-safe, so the worst case is falling back to DOM — but a driver
    // that "works" while painting an empty terminal is not something a probe
    // catches, which is why desktop stays a deliberate choice rather than a
    // default nobody asked for.
    if (isMobile || gpuRendering) {
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
    // Shell integration (OSC 133, the FinalTerm/iTerm2 sequences most shells can
    // emit): A marks where a prompt starts, D reports the exit code of the
    // command that just finished. We keep a marker per prompt so the user can
    // jump between them, and decorate the prompt of a command that failed.
    //
    // This is entirely opt-in on the server side — a shell that emits nothing
    // simply produces no marks, and everything behaves exactly as before. There
    // is deliberately no attempt to infer prompts heuristically: guessing wrong
    // would put a "failed" mark on an innocent line, which is worse than no mark.
    const shellMarks: { marker: IMarker; exit?: number; decoration?: IDisposable }[] = [];
    shellMarksRef.current = shellMarks;
    const disposeMarks = () => {
      for (const m of shellMarks) {
        m.decoration?.dispose();
        m.marker.dispose();
      }
      shellMarks.length = 0;
    };
    term.parser.registerOscHandler(133, (data) => {
      // Payloads look like "A", "B", "C", "D", "D;0", "A;aid=..." — only the
      // first field is the command, and unknown ones are ignored rather than
      // guessed at.
      const [kind, ...rest] = data.split(";");
      if (kind === "A") {
        const marker = term.registerMarker(0);
        if (marker) {
          // Bounded: a long-lived session can run thousands of commands, and an
          // unbounded marker list is a slow leak in a pane that never closes.
          if (shellMarks.length >= 500) {
            const oldest = shellMarks.shift();
            oldest?.decoration?.dispose();
            oldest?.marker.dispose();
          }
          shellMarks.push({ marker });
        }
      } else if (kind === "D") {
        const last = shellMarks[shellMarks.length - 1];
        const code = Number.parseInt(rest[0] ?? "", 10);
        if (last && Number.isFinite(code)) {
          last.exit = code;
          if (code !== 0 && !last.decoration) {
            const dec = term.registerDecoration({ marker: last.marker, x: 0, width: 1 });
            dec?.onRender((el) => {
              // A gutter tick, not a colour change on the text: the line itself
              // is the user's prompt and output, and recolouring it would be us
              // editing what the server actually printed.
              // A fixed red rather than a theme token: this element is created
              // by xterm outside React, so it cannot read the palette, and a CSS
              // variable nothing defines is configurability that does not exist.
              el.style.background = "#e0574a";
              el.style.borderRadius = "1px";
              el.title = `exit ${code}`;
            });
            if (dec) last.decoration = dec;
          }
        }
      }
      return true;
    });

    // OSC 52 — the remote side (zellij, tmux `set-clipboard on`, nvim) writing
    // its copy into the system clipboard. Before this handler the sequence was
    // silently dropped, and a multiplexer's own "copied to clipboard" was a lie.
    // Write-only: the "?" read query never gets an answer (see osc52.ts).
    term.parser.registerOscHandler(52, (data) => {
      const text = parseOsc52(data);
      if (text) void writeText(text);
      return true;
    });

    // Cmd+F (macOS) / Ctrl+Shift+F opens find; plain Ctrl+F is left to the shell
    // (readline forward-char). Escape closes it. attachCustomKeyEventHandler runs
    // only while THIS terminal has focus, so other panes/tabs are unaffected.
    term.attachCustomKeyEventHandler((ev) => {
      if (ev.type !== "keydown") return true;
      // Hand the app's own chords back before xterm can look at them. Returning
      // false makes xterm return from _keyDown untouched; anything it *does*
      // recognise it cancels with stopPropagation, and the window listener that
      // implements these shortcuts then never runs. That is why ⌘K opened the
      // palette everywhere except the terminal — the one place it is for.
      if (isAppChord(ev)) return false;
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
      // Jump between prompts. Only bound when the shell actually emits OSC 133 —
      // otherwise these keys keep whatever meaning the shell gives them, rather
      // than being swallowed for a feature that would do nothing.
      if (
        (ev.key === "ArrowUp" || ev.key === "ArrowDown") &&
        (ev.metaKey || ev.ctrlKey) &&
        ev.shiftKey &&
        shellMarks.length > 0
      ) {
        const viewportTop = term.buffer.active.viewportY;
        const lines = shellMarks.map((m) => m.marker.line).filter((l) => l >= 0);
        const target =
          ev.key === "ArrowUp"
            ? [...lines].reverse().find((l) => l < viewportTop)
            : lines.find((l) => l > viewportTop);
        if (target !== undefined) term.scrollToLine(target);
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
      // Keyboard paste. macOS keeps ⌘V (the webview's native paste event feeds
      // xterm) and is left alone — a second handler there would double-paste.
      // On Linux/Windows both Ctrl+V and Ctrl+Shift+V paste: WebView2 never
      // delivers a native paste to the xterm textarea, so Windows had no
      // keyboard paste at all (#29), and returning false stops the platforms
      // that DO have a native path from pasting twice. This spends readline's
      // quoted-insert (^V) — deliberate, the Termius trade.
      if (!isMac() && (ev.key === "v" || ev.key === "V") && ev.ctrlKey && !ev.altKey && !ev.metaKey) {
        if (ev.type === "keydown") void pasteClipboard();
        return false;
      }
      return true;
    });

    term.onData((data) => {
      const id = sessionIdRef.current;
      if (id) void api.sessionWrite(id, Array.from(new TextEncoder().encode(data)));
    });

    // Window title (OSC 0/2), local panes only. Two shells on the same machine
    // are otherwise indistinguishable — "zsh" and "zsh" — while a prompt that
    // sets its title (starship, oh-my-zsh) names them by what they are doing.
    // Not turned on for SSH panes: those are already named by their host, and
    // changing what every existing tab is called is a separate decision from
    // this feature. A tab the user renamed keeps their name — see setPaneTitle.
    if (pane.target.kind === "local") {
      term.onTitleChange((title) => {
        const clean = title.trim().slice(0, 120);
        if (clean) setPaneTitle(pane.id, clean);
      });
    }

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
      disposeMarks();
      shellMarksRef.current = null;
      term.dispose();
      eventsRef.current?.dispose();
      eventsRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // live-apply every appearance change — theme, zoom, and the termPrefs typography —
  // without a reconnect. xterm accepts option writes at runtime, but a font-metric
  // change (family/size/line-height/tracking) invalidates the grid, so the refit must
  // follow and the new cols/rows must be pushed to the PTY (the same sync path the
  // ResizeObserver and the old zoom effect used).
  useEffect(() => {
    const term = xtermRef.current;
    const fit = fitRef.current;
    if (!term || !fit) return;
    const isMobile = useApp.getState().device === "mobile";
    const next = termOptions(termPrefs, termTheme, baseFontSize(isMobile) + termZoom);
    term.options.fontFamily = next.fontFamily;
    term.options.fontSize = next.fontSize;
    term.options.lineHeight = next.lineHeight;
    term.options.letterSpacing = next.letterSpacing;
    term.options.cursorStyle = next.cursorStyle;
    term.options.cursorBlink = next.cursorBlink;
    term.options.minimumContrastRatio = next.minimumContrastRatio;
    term.options.theme = next.theme;
    // Applied live like the rest, but this one is destructive downward: xterm trims the
    // ring buffer immediately, so lowering the limit discards the rows above the new one.
    // That is the setting doing what it says — the alternative (defer to the next pane)
    // would leave the memory the user just asked to reclaim allocated until they reconnect.
    term.options.scrollback = next.scrollback;
    if (!hostLaidOut(hostRef.current)) return;
    try {
      fit.fit();
      const id = sessionIdRef.current;
      if (id && term.cols > 0 && term.rows > 0) void api.sessionResize(id, term.cols, term.rows);
    } catch {
      /* ignore */
    }
  }, [termPrefs, termTheme, termZoom]);

  // open the session (once we have auth). Re-runs on a reconnect (pane.gen bumped),
  // re-opening in the SAME pane so the xterm scrollback is preserved.
  useEffect(() => {
    const target = pane.target;
    if (target.kind === "ssh" && target.profile.auth.type === "promptPassword" && pw == null)
      return;
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
      // The dead session's app may have left bracketed paste, mouse tracking,
      // the alt screen etc. switched on in this reused xterm; the fresh shell
      // starts from defaults, and the mismatch garbles pastes (#30) and eats
      // clicks. Reset the app-owned modes without touching the scrollback.
      void resetStaleAppModes(term);
      term.writeln("");
      const again = target.kind === "local" ? "terminal.restarting" : "terminal.reconnecting";
      term.writeln(`\x1b[2m— ${t(again)} —\x1b[0m`);
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
    const vaultId = useApp.getState().vaultId || "";
    const cols = term.cols || 80;
    const rows = term.rows || 24;
    // Output handling, preview accumulation and the close path are the same for
    // both kinds of session — see views/terminal/paneSession.ts. The previous
    // run's plumbing goes first, so a debounced preview from the session we just
    // replaced cannot land on top of the new one.
    eventsRef.current?.dispose();
    const events = createPaneEvents({
      term,
      cancelled: () => cancelled,
      onPreview: (lines) => updatePane(tabId, pane.id, { preview: lines }),
      closedText: (code) => t("terminal.sessionClosed", { code }),
      onClosed: (_exit, dropped) => {
        const old = sessionIdRef.current;
        sessionIdRef.current = null;
        // Evict the now-dead session from the core's map so reconnects don't leak it.
        if (old) void api.sessionClose(old).catch(() => {});
        updatePane(tabId, pane.id, { status: "closed", sessionId: null });
        if (!dropped) return;
        // A session that stayed online a while earns a fresh attempt budget.
        const lt = useApp.getState().terminals.flatMap((x) => x.panes).find((x) => x.id === pane.id);
        if (lt?.lastOnlineAt && Date.now() - lt.lastOnlineAt > STABLE_ONLINE_MS)
          updatePane(tabId, pane.id, { reconnects: 0 });
        scheduleAutoReconnect();
      },
    });
    eventsRef.current = events;

    const opened =
      target.kind === "local"
        ? // Local sessions record under one global switch: a local pane has no
          // profile to carry `recordSessions`. The recording lands in the
          // personal vault when there is one — a local session pushed into a
          // shared team vault would sync a recording of the user's own machine
          // to their colleagues.
          localRecordingRequest(target.spec, vaultId).then((recording) =>
            api.localSessionOpen(target.spec, cols, rows, events.onEvent, recording),
          )
        : // Personal profiles resolve their credential in-core (binding +
          // anti-redirect) before connecting; everything else uses the stored
          // ProfileAuth.
          api
            .resolveConnectAuth(target.profile, vaultId, pw ?? undefined)
            .then(({ user, auth }) =>
              api.sessionOpen(
                {
                  host: target.profile.host,
                  port: target.profile.port,
                  user,
                  auth,
                  jumps: target.profile.jumps,
                  proxy: target.profile.proxy,
                  term: "xterm-256color",
                  cols,
                  rows,
                },
                events.onEvent,
                // A recording per connection, not per pane: a reconnect is a new
                // session with its own start time, and appending it to the previous
                // document would produce one recording whose timeline lies.
                target.profile.recordSessions && vaultId
                  ? {
                      vaultId,
                      recordingId: `rec-${target.profile.profileId}-${Date.now()}`,
                      label: target.profile.label,
                    }
                  : undefined,
                target.profile.agentForward,
              ),
            );

    void opened
      .then((id) => {
        // The pane was torn down or superseded by another reconnect while this
        // connect was in flight → close the just-opened session instead of leaking
        // it (and don't adopt it into a stale component).
        if (cancelled) {
          void api.sessionClose(id).catch(() => {});
          return;
        }
        sessionIdRef.current = id;
        lastSentSizeRef.current = { cols, rows };
        updatePane(tabId, pane.id, { sessionId: id, status: "online", lastOnlineAt: Date.now() });
        term.focus();
        if (target.kind === "local") return;
        // Refresh the host's "recently connected" timestamp on every (re)connect.
        useApp.getState().markConnected(target.profile.profileId);
        void runStartupSnippets(id, target.profile, vaultId);
      })
      .catch((err) => {
        if (cancelled) return;
        const message = apiErrorMessage(err);
        term.writeln(`\x1b[31m${message}\x1b[0m`);
        sessionIdRef.current = null;
        if (target.kind === "local") {
          // A shell that won't start is a settings problem — a wrong path, no
          // execute permission, a starting directory that isn't there. Retrying
          // cannot fix any of those, so the pane says what happened and points
          // at the setting instead of looping.
          updatePane(tabId, pane.id, { status: "error", error: message });
          return;
        }
        const profile = target.profile;
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
        updatePane(tabId, pane.id, { status: "error", error: message, mismatch });
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
    width: rem(24),
    height: rem(24),
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

  // Touch long-press → the same context menu right-click opens. xterm draws to a
  // canvas and a WebView never synthesizes `contextmenu` from a long press, so
  // without this Copy/Paste is unreachable on a phone — i.e. you cannot paste a
  // command into your own shell. Same shape as views/sftp/FileRow.
  const lpTimer = useRef<number | null>(null);
  const lpFired = useRef(false);
  const lpStart = useRef<{ x: number; y: number } | null>(null);
  // Where the finger was when we last scrolled, and the sub-line remainder it
  // left behind. Without carrying the remainder a slow drag never accumulates a
  // whole line and the terminal simply refuses to move.
  const dragY = useRef<number | null>(null);
  const dragRest = useRef(0);
  const clearLp = () => {
    if (lpTimer.current != null) {
      window.clearTimeout(lpTimer.current);
      lpTimer.current = null;
    }
  };
  // A press held across an unmount would fire into a dead pane.
  useEffect(() => () => clearLp(), []);

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
        // Nothing here is the platform's to scroll. xterm's scrollable element is
        // `.xterm-viewport`, but the text is painted in `.xterm-screen`, which sits
        // over it — so a finger on the output lands on a layer that does not
        // scroll, and neither does any ancestor. On a desktop this never showed:
        // the wheel event bubbles and xterm handles it itself. On a phone the
        // platform went looking for anything it could move instead and found the
        // whole shell, which is why swiping the terminal slid the entire interface.
        // Taking the gesture ourselves (onTouchMove) is what actually scrolls the
        // scrollback; this line stops the platform competing for the same finger.
        touchAction: "none",
        // Inner breathing room so the shell text isn't flush against the chrome
        // edges. Same colour as the terminal, so it reads as padding, not a frame.
        padding: rem(8),
        // Focus ring: only when this pane shares its tab with others, so a single
        // terminal isn't boxed for no reason.
        boxShadow: focused && multi ? `inset 0 0 0 2px ${p.accent}` : "none",
      }}
      onContextMenu={(e) => {
        e.preventDefault();
        setMenu({ x: e.clientX, y: e.clientY, hasSel: !!xtermRef.current?.getSelection() });
      }}
      onTouchStart={(e) => {
        const tt = e.touches[0];
        if (!tt) return;
        lpFired.current = false;
        lpStart.current = { x: tt.clientX, y: tt.clientY };
        dragY.current = tt.clientY;
        dragRest.current = 0;
        const { x, y } = lpStart.current;
        clearLp();
        lpTimer.current = window.setTimeout(() => {
          lpFired.current = true;
          navigator.vibrate?.(10);
          // A long press is also a deliberate "work on this pane" signal.
          if (!focused) setActivePane(tabId, pane.id);
          setMenu({ x, y, hasSel: !!xtermRef.current?.getSelection() });
        }, 450);
      }}
      onTouchMove={(e) => {
        const s = lpStart.current;
        const tt = e.touches[0];
        if (!s || !tt) return;
        // Tolerate jitter; only a real drag/scroll cancels the press.
        if (Math.hypot(tt.clientX - s.x, tt.clientY - s.y) > 10) clearLp();

        // Drag the scrollback. The row height comes from the rendered box and
        // xterm's own row count rather than from its private renderer metrics, so
        // it follows the terminal zoom without reaching into internals.
        const term = xtermRef.current;
        const host = hostRef.current;
        if (!term || !host || dragY.current === null || term.rows < 1) return;
        const cell = host.clientHeight / term.rows;
        if (cell <= 0) return;
        const moved = tt.clientY - dragY.current + dragRest.current;
        const lines = Math.trunc(moved / cell);
        if (lines === 0) return;
        // Finger down reveals older output, which is what every other scrollable
        // surface on the device does.
        term.scrollLines(-lines);
        dragY.current = tt.clientY;
        dragRest.current = moved - lines * cell;
      }}
      onTouchEnd={(e) => {
        clearLp();
        dragY.current = null;
        // Swallow the synthetic click/selection that would follow the press.
        if (lpFired.current) e.preventDefault();
      }}
      onTouchCancel={() => {
        clearLp();
        dragY.current = null;
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
            top: rem(6),
            right: rem(6),
            zIndex: 7,
            width: rem(20),
            height: rem(20),
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
            top: rem(10),
            right: rem(12),
            zIndex: 6,
            display: "flex",
            alignItems: "center",
            gap: rem(4),
            padding: `${rem(4)} ${rem(5)} ${rem(4)} ${rem(8)}`,
            borderRadius: 8,
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
              width: rem(150),
              background: p.bg2,
              border: `1px solid ${p.line2}`,
              borderRadius: 6,
              color: p.txt,
              fontFamily: MONO,
              fontSize: TEXT.small,
              padding: `${rem(4)} ${rem(7)}`,
              outline: "none",
            }}
          />
          <span
            style={{
              minWidth: rem(40),
              textAlign: "center",
              fontSize: TEXT.micro,
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
            // Touch has no way to drag out a selection over the xterm canvas, so
            // without this Copy above could never become enabled on a phone.
            ...(isMobile
              ? [
                  {
                    icon: "list" as IconName,
                    label: t("terminal.menu.selectAll"),
                    onClick: () => xtermRef.current?.selectAll(),
                  },
                ]
              : []),
            { icon: "clipboard", label: t("terminal.menu.paste"), onClick: () => void pasteClipboard() },
            { icon: "grid", label: t("terminal.menu.splitRight"), onClick: () => splitPane(tabId, pane.id, "row") },
            { icon: "list", label: t("terminal.menu.splitDown"), onClick: () => splitPane(tabId, pane.id, "col") },
            // Split into a shell on this machine, rather than another of
            // whatever this pane is. Desktop only, like every other way in.
            ...(isMobile
              ? []
              : [
                  {
                    icon: "laptop" as IconName,
                    label: t("terminal.menu.splitLocal"),
                    onClick: () => void splitLocalTerminal(tabId, pane.id, "row"),
                  },
                ]),
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
        // Device pixels: the wide part is a mouse target and the seam inside it is
        // a rule. Neither is made of type, and a 9px grab strip at 150 % would eat
        // terminal columns to no one's benefit.
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

/** Who the focused pane is talking to, in the status bar.
 *
 * A local pane must never be mistakable for a production host — running the
 * wrong command in the wrong place is exactly the failure "trust is visible" is
 * there to prevent. So a local pane says so in words, with the machine's own
 * name and the OS account, next to a laptop rather than the usual host text. */
function PaneIdentity({ pane }: { pane: TerminalPaneState }) {
  const p = usePalette();
  const { t } = useTranslation();
  const machine = useLocalMachine();
  const local = pane.target.kind === "local";
  const profile = paneProfile(pane);
  if (!local && !profile) return null;

  // Ellipsize so a long user@host token can't push the theme/settings control
  // off the fixed-height bar.
  const text = local
    ? machine
      ? `${machine.user}@${machine.hostname}`
      : ""
    : profile!.user
      ? `${profile!.user}@${profile!.host}`
      : profile!.host;

  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: rem(6),
        color: p.txt2,
        minWidth: 0,
        overflow: "hidden",
        textOverflow: "ellipsis",
        whiteSpace: "nowrap",
      }}
    >
      {local && <Icon name="laptop" size={12} color={p.txt3} />}
      {text}
      {local && (
        // The word, not just the icon: an icon alone is a thing to learn, and
        // the cost of not learning it is running something on the wrong machine.
        <span
          style={{
            flexShrink: 0,
            padding: `${rem(1)} ${rem(6)}`,
            borderRadius: 6,
            border: `1px solid ${p.line2}`,
            color: p.txt3,
            fontSize: rem(10),
            letterSpacing: rem(0.4),
            textTransform: "uppercase",
          }}
        >
          {t("terminal.localBadge")}
        </span>
      )}
    </span>
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
    width: rem(22),
    height: rem(22),
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
          onPickLocal={ctx.openLocal}
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
              gap: rem(10),
              color: p.txt3,
              // App chrome, not terminal colours — there is no PTY yet.
              background: p.bg0,
            }}
          >
            <Icon name="terminal" size={34} color={p.txt3} />
            <div style={{ fontSize: TEXT.body }}>{t("terminal.noSessions")}</div>
            <div
              onClick={() => ctx.go("hosts")}
              style={{ fontSize: TEXT.base, color: p.accentText, cursor: "pointer" }}
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
            height: rem(30),
            flexShrink: 0,
            // App chrome stays neutral mono (bg0); a single hairline separates it
            // from the PTY body, which keeps its own terminal theme. Only the
            // terminal itself is tinted by the active colour scheme.
            background: p.bg0,
            borderTop: `1px solid ${p.line}`,
            display: "flex",
            alignItems: "center",
            gap: rem(10),
            padding: `0 ${rem(14)}`,
            fontFamily: MONO,
            fontSize: TEXT.small,
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
          {focusedPane && <PaneIdentity pane={focusedPane} />}
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
              gap: rem(5),
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
