// MobileApp — the phone SHELL, and only the shell: a safe-area-aware frame, a
// bottom tab bar, a push stack with edge-swipe back, the vault sheet, and the
// terminal's on-screen key row. The screens themselves are the desktop views.
//
// It used to also carry its own hosts list, host card and host detail — ~780 lines
// re-implementing ViewHosts, which is where every desktop/mobile divergence came
// from (a shadowed card against the system's flat one, its own radius scale, its
// own auth labels, no density, no bulk select). Those are gone: the hosts tab
// renders ViewHosts, which adapts itself via useNarrow() like its siblings. What
// remains here is what a phone genuinely needs and a desktop genuinely doesn't.

import React, { useEffect, useRef, useState } from "react";
import { usePalette } from "@/theme/ThemeProvider";
import { Icon, Btn, VaultBadge, type IconName } from "@/components/primitives";
import { FlatAvatar, SyncBadge } from "@/components/mono";
import { serverShortLabel, vaultLoc, vaultServer } from "@/bridge/vaults";
import { BottomSheet } from "@/components/Modal";
import { MONO, RADIUS, SIZE, UI } from "@/theme/tokens";
import { useApp } from "@/store/app";
import { useKeyboardInset, useLandscape } from "@/store/responsive";
import { useTranslation, tDyn } from "@/i18n";
import { useCtx } from "@/store/ctx";
import { guard } from "@/store/action";
import type { VaultInfo } from "@/bridge/types";
import * as api from "@/bridge/api";

import { ViewTerminal } from "@/views/ViewTerminal";
import { ReconnectBanner } from "@/components/ReconnectBanner";
import { ViewHosts } from "@/views/ViewHosts";
import { ViewRun } from "@/views/ViewRun";
import { ViewSftp } from "@/views/sftp/ViewSftp";
import { ViewTunnels } from "@/views/ViewTunnels";
import { ViewKnown } from "@/views/ViewKnown";
import { ViewSecrets } from "@/views/ViewSecrets";
import { ViewSettings } from "@/views/ViewSettings";

// ── stack frames ───────────────────────────────────────────────
// There is deliberately no "host" frame: the hosts tab renders the desktop
// ViewHosts, which owns host detail itself (as a full-width overlay once the
// layout is narrow). A second, mobile-only host screen is exactly the fork that
// let this shell drift away from the desktop in the first place.
type Frame =
  | { type: "sftp" }
  | { type: "tunnels" }
  | { type: "known" }
  | { type: "secrets" }
  | { type: "settings" };

type TabId = "hosts" | "terminal" | "run" | "more";

/** Where a store route lands on this shell. The desktop router is the app's real
 *  navigation model — every reused view calls ctx.go() — so the shell mirrors it
 *  instead of honouring one hand-picked route and silently dropping the rest. */
const ROUTE_TAB: Partial<Record<string, TabId>> = {
  hosts: "hosts",
  terminal: "terminal",
  run: "run",
  fleet: "run",
  broadcast: "run",
};
const ROUTE_FRAME: Partial<Record<string, Frame["type"]>> = {
  sftp: "sftp",
  tunnels: "tunnels",
  known: "known",
  secrets: "secrets",
  keys: "secrets",
  passwords: "secrets",
  identities: "secrets",
  notes: "secrets",
  settings: "settings",
};

// ── top bar (vault + trust state + search + lock) ───────────────
// The phone's counterpart to the desktop TitleBar/VaultSwitcher, and it carries the
// same three things: which vault you're in, whether it's actually synced, and the
// way out (lock + search). It renders globally, above the tabs.
function MTopBar({
  vault,
  onVaultTap,
}: {
  vault: VaultInfo | null;
  onVaultTap: () => void;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const ctx = useCtx();
  const servers = useApp((s) => s.servers);
  const syncStatus = useApp((s) => s.syncStatus);
  // Landscape leaves ~244px of content height between this bar and the tab bar.
  // Drop to a single line there and give the height back to the screen.
  const land = useLandscape();
  const name = vault?.name ?? t("mobile.vault");
  // Same rules as Shell's VaultSwitcher — a phone must not have its own opinion
  // about what "synced" means.
  const badgeLabel = (x: VaultInfo): string => {
    if (x.syncTarget !== "cloud") return t("vault.local");
    const loc = vaultLoc(x, servers);
    if (loc.server) return loc.server;
    const srv = vaultServer(x, servers);
    return srv ? serverShortLabel(srv) : t("vault.badgeUnbound");
  };
  const unbound = vault != null && vault.syncTarget === "cloud" && vaultServer(vault, servers) == null;
  const iconBtn: React.CSSProperties = {
    width: SIZE.tapMin,
    height: SIZE.tapMin,
    flexShrink: 0,
    borderRadius: RADIUS.menu,
    background: p.bg2,
    border: `1px solid ${p.line2}`,
    color: p.txt2,
    cursor: "pointer",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
  };
  return (
    <div
      style={{
        flexShrink: 0,
        padding: land ? "2px 16px 6px" : "4px 16px 12px",
        display: "flex",
        alignItems: "center",
        gap: 8,
      }}
    >
      <button
        onClick={onVaultTap}
        aria-haspopup="menu"
        style={{
          display: "flex",
          alignItems: "center",
          gap: 9,
          // Shrink before the search/lock buttons do, and cap at a share of the
          // bar so the spacer beside it is a real gap and not a 0px fiction.
          minWidth: 0,
          flexShrink: 1,
          maxWidth: "66%",
          height: SIZE.tapMin,
          padding: "0 12px 0 7px",
          borderRadius: RADIUS.menu,
          background: p.bg2,
          border: `1px solid ${p.line2}`,
          cursor: "pointer",
        }}
      >
        <FlatAvatar name={name} size={26} shape="square" />
        <span style={{ display: "flex", flexDirection: "column", alignItems: "flex-start", gap: 2, minWidth: 0 }}>
          <span
            style={{
              fontSize: 14,
              fontWeight: 700,
              color: p.txt,
              lineHeight: 1,
              // No fixed cap: it left width unused while the badges below decided
              // the pill's size. Shrink with the column like everything else.
              maxWidth: "100%",
              minWidth: 0,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {name}
          </span>
          {/* Is this vault local or on a server, and is it up to date? Unanswerable
              on a phone until now — on the device most likely to be on a flaky
              network, and the first thing to check when a vault "won't appear". */}
          {vault && !land && (
            <span style={{ display: "flex", alignItems: "center", gap: 5, minWidth: 0, overflow: "hidden" }}>
              <VaultBadge target={vault.syncTarget} label={badgeLabel(vault)} size={10} />
              {unbound && <Icon name="alert" size={10} color={p.amber} />}
              {vault.syncTarget === "cloud" && !unbound && (
                <SyncBadge
                  state={syncStatus.syncing ? "syncing" : syncStatus.lastError ? "error" : "synced"}
                  label={
                    syncStatus.syncing
                      ? t("shell.syncing")
                      : syncStatus.lastError
                        ? t("shell.syncError")
                        : t("shell.synced")
                  }
                  title={syncStatus.lastError ?? undefined}
                />
              )}
            </span>
          )}
        </span>
        <Icon name="cd" size={15} color={p.txt3} />
      </button>
      <div style={{ flex: 1 }} />
      {/* The command palette is mounted on this shell but had no way to open it —
          its only trigger was the desktop title bar and a hardware ⌘K. This is the
          phone's search: hosts, secrets and actions, the same superset ⌘K gives. */}
      {/* Lock lives in More, not here. A phone locks itself — the OS does it, and
          the app's idle auto-lock does it — so a permanent manual lock on the home
          screen buys little and costs a 44px slot on the one row that has to hold
          the vault, its sync state and search. In More it is two taps from every
          tab instead of one tap from one. */}
      <button onClick={ctx.openPalette} aria-label={t("shell.searchPlaceholder")} style={iconBtn}>
        <Icon name="search" size={18} />
      </button>
    </div>
  );
}

// ── vault switcher sheet ───────────────────────────────────────
function MVaultSheet({ onClose }: { onClose: () => void }) {
  const p = usePalette();
  const { t } = useTranslation();
  const vaults = useApp((s) => s.vaults);
  const vaultId = useApp((s) => s.vaultId);
  const setVault = useApp((s) => s.setVault);
  const hosts = useApp((s) => s.hosts);
  const ctx = useCtx();
  return (
    <BottomSheet position="absolute" zIndex={40} onClose={onClose}>
      <div style={{ fontSize: 13, fontWeight: 700, color: p.txt3, textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 12 }}>
        {t("mobile.vault")}
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {vaults.map((x) => {
          const on = x.vaultId === vaultId;
          return (
            <button
              key={x.vaultId}
              onClick={() => {
                void setVault(x.vaultId);
                onClose();
              }}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 12,
                padding: 13,
                borderRadius: 16,
                background: on ? p.accentSoft : p.bg2,
                border: `1px solid ${on ? p.accentLine : p.line}`,
                cursor: "pointer",
              }}
            >
              <FlatAvatar name={x.name} size={36} shape="square" />
              <div style={{ flex: 1, textAlign: "left" }}>
                <div style={{ fontSize: 16, fontWeight: 700, color: p.txt }}>{x.name}</div>
                <div style={{ fontSize: 13, color: p.txt3 }}>{on ? t("count.hosts", { count: hosts.length }) : t("mobile.vaultLower")}</div>
              </div>
              {on && <Icon name="check" size={20} color={p.accentText} />}
            </button>
          );
        })}
        {vaults.length === 0 && <div style={{ fontSize: 13, color: p.txt3, padding: 8 }}>{t("mobile.noVaults")}</div>}
      </div>
      <Btn
        variant="outline"
        size="lg"
        full
        icon="plus"
        onClick={() => {
          ctx.openModal({ kind: "vault" });
          onClose();
        }}
        style={{ marginTop: 10 }}
      >
        {t("vault.create")}
      </Btn>
    </BottomSheet>
  );
}

// ── terminal tab (reuse desktop ViewTerminal + key accessory) ──
// Honest labels: each emits a literal control/escape sequence. (There is no real
// modifier latch — the on-screen row can't compose with the OS keyboard's next
// key — so we expose the useful control codes directly instead of a fake "ctrl".)
const KEY_SEQ: { label: string; bytes: number[] }[] = [
  { label: "esc", bytes: [0x1b] },
  { label: "tab", bytes: [0x09] },
  { label: "^C", bytes: [0x03] }, // interrupt
  { label: "^D", bytes: [0x04] }, // EOF
  { label: "^Z", bytes: [0x1a] }, // suspend
  { label: "^L", bytes: [0x0c] }, // clear
  { label: "^R", bytes: [0x12] }, // reverse-search
  { label: "^A", bytes: [0x01] }, // line start
  { label: "^E", bytes: [0x05] }, // line end
  { label: "^W", bytes: [0x17] }, // delete word
  { label: "^U", bytes: [0x15] }, // delete line
  { label: "|", bytes: [0x7c] },
  { label: "~", bytes: [0x7e] },
  { label: "/", bytes: [0x2f] },
  { label: "-", bytes: [0x2d] },
  { label: "←", bytes: [0x1b, 0x5b, 0x44] },
  { label: "↓", bytes: [0x1b, 0x5b, 0x42] },
  { label: "↑", bytes: [0x1b, 0x5b, 0x41] },
  { label: "→", bytes: [0x1b, 0x5b, 0x43] },
];

function MTerminal({ onNeedHosts }: { onNeedHosts: () => void }) {
  const p = usePalette();
  const { t } = useTranslation();
  const terminals = useApp((s) => s.terminals);
  const activeTermId = useApp((s) => s.activeTermId);
  const setActiveTerm = useApp((s) => s.setActiveTerm);
  const closeTerminal = useApp((s) => s.closeTerminal);
  const reconnectPane = useApp((s) => s.reconnectPane);
  const active = terminals.find((t) => t.id === activeTermId) || terminals[terminals.length - 1];
  // Mobile is single-pane: act on the active tab's active (first) pane.
  const activePane = active?.panes.find((pp) => pp.id === active.activePaneId) ?? active?.panes[0];

  const sendKey = async (bytes: number[]) => {
    const sid = activePane?.sessionId;
    if (!sid) return;
    await guard(async () => {
      await api.sessionWrite(sid, bytes);
    });
  };

  // A phone session dies on every backgrounding / Wi-Fi handoff, so make recovery
  // one tap: re-open the session in the SAME tab (keeps the scrollback) instead of
  // spawning a fresh tab and discarding it.
  const reconnect = () => {
    if (!active || !activePane?.profile) return;
    reconnectPane(active.id, activePane.id, true); // manual: fresh auto-reconnect budget
  };

  if (terminals.length === 0) {
    return (
      <div
        style={{
          flex: 1,
          minHeight: 0,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          gap: 14,
          color: p.txt3,
          padding: 24,
        }}
      >
        <Icon name="terminal" size={40} color={p.txt3} />
        <div style={{ fontSize: 16 }}>{t("terminal.noSessions")}</div>
        <button
          onClick={onNeedHosts}
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 8,
            height: 46,
            padding: "0 20px",
            borderRadius: 12,
            background: p.accent,
            border: "none",
            color: p.accentInk ?? "#fff",
            fontSize: 16,
            fontWeight: 700,
            cursor: "pointer",
          }}
        >
          <Icon name="server" size={18} />
          {t("terminal.openHost")}
        </button>
      </div>
    );
  }

  // A host-key mismatch pane shows the in-pane security card (rendered by the
  // shared TerminalPane) — no reconnect strip: a mismatch must not offer Reconnect.
  const dead =
    activePane &&
    (activePane.status === "closed" || activePane.status === "error") &&
    !activePane.mismatch;

  return (
    <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
      {/* session switcher — desktop tab strip is hidden on mobile */}
      {terminals.length > 1 && (
        <div style={{ flexShrink: 0, display: "flex", gap: 6, padding: "8px 12px", overflowX: "auto", borderBottom: `1px solid ${p.line}`, background: p.bg1 }}>
          {terminals.map((trm) => {
            const on = trm.id === active?.id;
            const tp = trm.panes.find((pp) => pp.id === trm.activePaneId) ?? trm.panes[0];
            return (
              // Two sibling buttons, not a <span onClick> nested inside a <button>:
              // that isn't focusable, has no accessible name, and put a 16px target
              // on an action that closes every pane's backend session.
              <span
                key={trm.id}
                style={{
                  flexShrink: 0,
                  display: "inline-flex",
                  alignItems: "center",
                  borderBottom: `2px solid ${on ? p.txt2 : "transparent"}`,
                }}
              >
                <button
                  onClick={() => setActiveTerm(trm.id)}
                  aria-current={on ? "page" : undefined}
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 7,
                    padding: "6px 4px 6px 10px",
                    minHeight: SIZE.tapMin,
                    border: "none",
                    borderRadius: 0,
                    background: "transparent",
                    color: on ? p.txt : p.txt3,
                    cursor: "pointer",
                    fontSize: 13,
                    fontFamily: MONO,
                  }}
                >
                  <span style={{ width: 7, height: 7, borderRadius: "50%", background: tp?.status === "online" ? p.green : tp?.status === "error" ? p.red : p.txt3 }} />
                  <span style={{ maxWidth: 120, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{trm.title}</span>
                </button>
                <button
                  onClick={() => closeTerminal(trm.id)} // closes every pane's backend session
                  aria-label={t("terminal.tab.close")}
                  style={{
                    width: SIZE.tapMin,
                    height: SIZE.tapMin,
                    flexShrink: 0,
                    display: "inline-flex",
                    alignItems: "center",
                    justifyContent: "center",
                    border: "none",
                    background: "transparent",
                    color: p.txt3,
                    cursor: "pointer",
                  }}
                >
                  <Icon name="x" size={12} />
                </button>
              </span>
            );
          })}
        </div>
      )}

      <div style={{ flex: 1, minHeight: 0, display: "flex" }}>
        <ViewTerminal />
      </div>

      {/* reconnect banner for a dropped/failed session (shared with desktop) */}
      {dead && activePane && (
        <ReconnectBanner pane={activePane} onReconnect={reconnect} variant="strip" />
      )}

      {/* horizontally-scrollable special-keys accessory row */}
      <div style={{ flexShrink: 0, display: "flex", gap: 6, padding: "10px 12px", overflowX: "auto", overscrollBehavior: "contain", borderTop: `1px solid ${p.line}`, background: p.bg1 }}>
        {KEY_SEQ.map((k) => (
          <button
            key={k.label}
            onClick={() => void sendKey(k.bytes)}
            style={{
              flexShrink: 0,
              minWidth: 44,
              height: 44,
              borderRadius: 8,
              background: p.bg3,
              border: `1px solid ${p.line}`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontFamily: MONO,
              fontSize: 13,
              color: p.txt2,
              padding: "0 10px",
              cursor: "pointer",
            }}
          >
            {k.label}
          </button>
        ))}
      </div>
    </div>
  );
}

// ── more grid ──────────────────────────────────────────────────
const MORE_ITEMS: {
  type: Frame["type"];
  icon: IconName;
  labelKey: string;
  descKey: string;
}[] = [
  // Broadcast is not here: it's a mode of the Run tab, exactly as on the desktop,
  // where the sidebar has neither "Broadcast" nor "Fleet" — only "Run".
  { type: "sftp", icon: "folders", labelKey: "nav.sftp", descKey: "mobile.more.sftpDesc" },
  { type: "tunnels", icon: "branch", labelKey: "nav.tunnels", descKey: "mobile.more.tunnelsDesc" },
  { type: "known", icon: "shieldcheck", labelKey: "nav.known", descKey: "mobile.more.knownDesc" },
  { type: "secrets", icon: "key", labelKey: "mobile.more.secrets", descKey: "mobile.more.secretsDesc" },
  { type: "settings", icon: "sliders", labelKey: "nav.settings", descKey: "mobile.more.settingsDesc" },
];

function MMore({ go, onLock }: { go: (t: Frame["type"]) => void; onLock: () => void }) {
  const p = usePalette();
  const { t } = useTranslation();
  const ctx = useCtx();
  return (
    <>
      <div style={{ flexShrink: 0, padding: "4px 16px 14px" }}>
        <h1 style={{ margin: 0, fontSize: 28, fontWeight: 800, letterSpacing: -0.7, color: p.txt }}>{t("nav.more")}</h1>
      </div>
      <div style={{ flex: 1, overflowY: "auto", padding: "0 16px 16px", display: "flex", flexDirection: "column" }}>
        {MORE_ITEMS.map((it, i) => (
          <button
            key={it.type}
            onClick={() => go(it.type)}
            style={{
              width: "100%",
              textAlign: "left",
              display: "flex",
              alignItems: "center",
              gap: 13,
              padding: "15px 4px",
              background: "transparent",
              border: "none",
              borderTop: i === 0 ? undefined : `1px solid ${p.line}`,
              cursor: "pointer",
            }}
          >
            <span
              style={{
                width: 42,
                height: 42,
                borderRadius: 12,
                background: p.bg3,
                border: `1px solid ${p.line}`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                flexShrink: 0,
              }}
            >
              <Icon name={it.icon} size={20} color={p.txt2} />
            </span>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 16, fontWeight: 700, color: p.txt }}>{tDyn(it.labelKey)}</div>
              <div style={{ fontSize: 13, color: p.txt3 }}>{tDyn(it.descKey)}</div>
            </div>
            <Icon name="cd" size={18} color={p.txt3} />
          </button>
        ))}
        {/* import ~/.ssh/config — opens the native file picker + preview overlay */}
        <button
          onClick={() => ctx.openImport()}
          style={{
            width: "100%",
            textAlign: "left",
            display: "flex",
            alignItems: "center",
            gap: 13,
            padding: "15px 4px",
            background: "transparent",
            border: "none",
            borderTop: `1px solid ${p.line}`,
            cursor: "pointer",
          }}
        >
          <span
            style={{
              width: 42,
              height: 42,
              borderRadius: 12,
              background: p.bg3,
              border: `1px solid ${p.line}`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              flexShrink: 0,
            }}
          >
            <Icon name="download" size={20} color={p.txt2} />
          </span>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 16, fontWeight: 700, color: p.txt }}>{t("hosts.importSshConfig")}</div>
            <div style={{ fontSize: 13, color: p.txt3 }}>{tDyn("command.action.importSub")}</div>
          </div>
          <Icon name="cd" size={18} color={p.txt3} />
        </button>
        {/* Lock. It used to sit permanently in the top bar, which is the one row
            that has to carry the vault, its sync state and search — and a phone
            already locks itself twice over (the OS, and the app's idle auto-lock).
            More is where the actions that aren't destinations live (Import is right
            above), and from here it's two taps from any tab. */}
        <button
          onClick={onLock}
          style={{
            width: "100%",
            textAlign: "left",
            display: "flex",
            alignItems: "center",
            gap: 13,
            padding: "15px 4px",
            background: "transparent",
            border: "none",
            borderTop: `1px solid ${p.line}`,
            cursor: "pointer",
          }}
        >
          <span
            style={{
              width: 42,
              height: 42,
              borderRadius: RADIUS.menu,
              background: p.bg3,
              border: `1px solid ${p.line}`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              flexShrink: 0,
            }}
          >
            <Icon name="lock" size={20} color={p.txt2} />
          </span>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 16, fontWeight: 700, color: p.txt }}>{t("shell.lockShort")}</div>
            <div style={{ fontSize: 13, color: p.txt3 }}>{t("mobile.more.lockDesc")}</div>
          </div>
        </button>
      </div>
    </>
  );
}

// ── secondary screen wrapper (back header + desktop view) ──────
function MWrapView({ label, onBack, children }: { label: string; onBack: () => void; children: React.ReactNode }) {
  const p = usePalette();
  const { t } = useTranslation();
  return (
    <>
      <div style={{ flexShrink: 0, padding: "4px 12px 8px", display: "flex", alignItems: "center", borderBottom: `1px solid ${p.line}` }}>
        <button
          onClick={onBack}
          aria-label={t("common.back")}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 2,
            // 44 tall: this is the primary way out of every pushed frame.
            padding: "8px 8px 8px 4px",
            minHeight: 44,
            background: "none",
            border: "none",
            // Ink, not accent: accent-on-bg0 lands at ~3.1:1 in the light families
            // and this is a text label, not the reserved tick.
            color: p.txt,
            cursor: "pointer",
            fontSize: 16,
          }}
        >
          <Icon name="cl" size={22} />
          {/* "Back", not "More": these frames are reached from More, from a host
              card's SFTP button, from a fingerprint, and from a mismatch review —
              naming one of those four was wrong three times out of four. */}
          {t("common.back")}
        </button>
        <div style={{ flex: 1, textAlign: "center", fontSize: 16, fontWeight: 700, color: p.txt, marginRight: 44 }}>{label}</div>
      </div>
      <div style={{ flex: 1, minHeight: 0, display: "flex" }}>{children}</div>
    </>
  );
}

// ── tab bar ────────────────────────────────────────────────────
/** Tab-bar vertical padding. The active tick is pulled up by exactly this much to
 *  sit flush against the bar's top hairline, so the two must stay in step. */
const TAB_PAD_Y = 8;

/** How near the left edge a touch must start to arm the back gesture.
 *
 *  There used to be an invisible 20px shield here that stopped nested horizontal
 *  scrollers from stealing the touch — but the gesture arms at 28px, so the two
 *  disagreed by 8px, and the shield ate every tap in the left band of every pushed
 *  frame (Settings rows, SFTP filenames, part of the back chevron itself) to buy a
 *  gesture that every one of those frames already offers as a back button. The
 *  shield is gone: a rare swipe losing to a scroller is recoverable, a dead strip
 *  down the side of every screen is not. */
const EDGE_SWIPE_PX = 28;

function MTabBar({ tab, setTab }: { tab: TabId; setTab: (t: TabId) => void }) {
  const p = usePalette();
  const { t } = useTranslation();
  const tabs: { id: TabId; icon: IconName; label: string }[] = [
    { id: "hosts", icon: "server", label: t("mobile.tabHosts") },
    { id: "terminal", icon: "terminal", label: t("nav.terminal") },
    { id: "run", icon: "layers", label: t("nav.run") },
    { id: "more", icon: "grid", label: t("nav.more") },
  ];
  return (
    <nav
      aria-label={t("mobile.tabsLabel")}
      style={{
        flexShrink: 0,
        display: "flex",
        // No safe-area inset here: the shell root reserves it once, for every
        // screen. Adding it again parked the bar a home indicator above the
        // ground with dead space underneath.
        padding: `${TAB_PAD_Y}px 8px`,
        borderTop: `1px solid ${p.line}`,
        background: p.bg1,
      }}
    >
      {tabs.map((tb) => {
        const active = tab === tb.id;
        return (
          <button
            key={tb.id}
            onClick={() => setTab(tb.id)}
            aria-current={active ? "page" : undefined}
            style={{
              position: "relative",
              flex: 1,
              minWidth: 0,
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              gap: 3,
              padding: "4px 2px",
              minHeight: 44,
              background: "none",
              border: "none",
              cursor: "pointer",
              // Accent is reserved for the tick (the sidebar's rule, Shell.tsx).
              // An accent label here fails AA at 11px in the light families — and
              // colour alone was carrying the active state, which weight at 11px
              // cannot back up. Ink + the tick fixes contrast and the carrier.
              color: active ? p.txt : p.txt3,
            }}
          >
            {/* The sidebar's accent tick sits flush at its outer edge; the tab
                bar's outer edge is the top one, so the tick rides there. */}
            {active && (
              <span
                aria-hidden
                style={{
                  position: "absolute",
                  top: -TAB_PAD_Y,
                  left: 6,
                  right: 6,
                  height: 2,
                  background: p.accent,
                  borderRadius: RADIUS.tick,
                }}
              />
            )}
            <Icon name={tb.icon} size={23} stroke={active ? 2 : 1.7} />
            <span
              style={{
                fontSize: 11,
                fontWeight: active ? 700 : 500,
                maxWidth: "100%",
                whiteSpace: "nowrap",
                overflow: "hidden",
                textOverflow: "ellipsis",
              }}
            >
              {tb.label}
            </span>
          </button>
        );
      })}
    </nav>
  );
}

// ── root ───────────────────────────────────────────────────────
export function MobileApp() {
  const p = usePalette();
  const { t } = useTranslation();
  const ctx = useCtx();
  const vaultId = useApp((s) => s.vaultId);
  const vaults = useApp((s) => s.vaults);

  const [tab, setTab] = useState<TabId>("hosts");
  const [stack, setStack] = useState<Frame[]>([]);
  const [vaultSheet, setVaultSheet] = useState(false);
  const [sw, setSw] = useState<{ x: number; dx: number } | null>(null);
  const kbInset = useKeyboardInset();

  const vault = vaults.find((v) => v.vaultId === vaultId) ?? vaults[0] ?? null;
  const top = stack[stack.length - 1];
  const push = (f: Frame) => setStack((s) => [...s, f]);

  const runBack = useApp((s) => s.runBack);
  const pop = () => setStack((s) => s.slice(0, -1));

  const switchTab = (t: TabId) => {
    // Re-tapping the active tab pops it to root (the iOS convention) — and it is
    // the obvious escape a user reaches for. setTab alone is a no-op React
    // discards, which left the detail overlay up and the tab looking inert.
    if (t === tab && !stack.length) {
      runBack();
      return;
    }
    setStack([]);
    setTab(t);
  };

  // touch state must reset when leaving a frame
  useEffect(() => {
    if (!top) setSw(null);
  }, [top]);

  // Mirror the store router into this shell's stack. Every reused desktop view
  // navigates with ctx.go() — the command palette's nav items, the terminal status
  // bar's theme link, a host-key mismatch's "review" — and this shell used to
  // honour exactly one route ("known"), so all the others silently did nothing on a
  // phone. Subscribe to routeSeq, not route: it bumps on every navigation, whereas
  // a repeat go("known") sets the same value, fires no update, and would drop a
  // second mismatch review.
  const routeSeq = useApp((s) => s.routeSeq);
  // Skip the mount run. `route` outlives a lock, and this shell is remounted on
  // every unlock (App gates it on `unlocked`), so mirroring on mount replayed the
  // route you happened to be on BEFORE locking — landing you on a Terminal tab
  // that lockInstance just emptied, or an SFTP frame with no session and no tab
  // bar. A fresh shell starts on Hosts; only a real navigation should move it.
  const mirrored = useRef(false);
  useEffect(() => {
    if (!mirrored.current) {
      mirrored.current = true;
      return;
    }
    const route = useApp.getState().route;
    const asTab = ROUTE_TAB[route];
    if (asTab) {
      setStack([]);
      setTab(asTab);
      return;
    }
    const asFrame = ROUTE_FRAME[route];
    if (asFrame) {
      // Dedupe: re-navigating to the screen you're already on must not stack it.
      setStack((s) => (s[s.length - 1]?.type === asFrame ? s : [...s, { type: asFrame }]));
    }
  }, [routeSeq]);

  // The tab bar belongs to the tabs; a pushed frame owns the whole screen.
  const tabBarVisible = !top;
  // the terminal tab is rendered persistently (below), so it's "shown" only when
  // it's the active tab and no secondary frame is pushed on top of it
  const showTerminal = !top && tab === "terminal";
  // ViewSftp is likewise rendered persistently (below): mounted while the sftp
  // frame is on top, only hidden (not unmounted) otherwise, so its panes / cwd /
  // selection survive leaving and returning — same reasoning as the terminal.
  const showSftp = !!top && top.type === "sftp";
  // ViewRun holds live broadcast PTYs, so it belongs to the same set: unmounting
  // it fires ViewBroadcast's cleanup, which closes every session it holds. It used
  // to be re-created per tab, and ANY navigation destroyed the broadcast — a nav
  // guard can't save it, because addTerminal/reviewMismatch/duplicateTerminal all
  // move the route without consulting one. Keeping it mounted removes the hazard
  // rather than asking the user to confirm it.
  //
  // LAZY, though: mounted on first visit, kept alive after. Mounting it at app
  // launch means paying for a screen most sessions never open — ViewBroadcast's
  // 520ms caret interval blinking on battery from boot — and it also breaks the
  // two things that read state AT mount: ViewRun's entry mode and ViewFleet's
  // carried selection, both of which would sample an empty app.
  const showRun = !top && tab === "run";
  const [runMounted, setRunMounted] = useState(false);
  useEffect(() => {
    if (showRun) setRunMounted(true);
  }, [showRun]);

  let screen: React.ReactNode = null;
  if (top) {
    switch (top.type) {
      case "sftp":
        // Rendered persistently below (display-toggled) so its state survives
        // leaving and returning — like the terminal. Nothing to render in-stack.
        break;
      case "tunnels":
        screen = (
          <MWrapView label={t("nav.tunnels")} onBack={pop}>
            <ViewTunnels />
          </MWrapView>
        );
        break;
      case "known":
        screen = (
          <MWrapView label={t("nav.known")} onBack={pop}>
            <ViewKnown />
          </MWrapView>
        );
        break;
      case "secrets":
        screen = (
          <MWrapView label={t("mobile.more.secrets")} onBack={pop}>
            <ViewSecrets />
          </MWrapView>
        );
        break;
      case "settings":
        screen = (
          <MWrapView label={t("nav.settings")} onBack={pop}>
            <ViewSettings />
          </MWrapView>
        );
        break;
    }
  } else {
    switch (tab) {
      case "hosts":
        // The desktop view itself. It already goes single-column and turns its
        // detail rail into a full-screen overlay once useNarrow() fires, so the
        // phone gets the real thing — density, hostsLayout, bulk select, the
        // relative last-connected — instead of a look-alike that drifts.
        screen = (
          <div style={{ flex: 1, minHeight: 0, display: "flex" }}>
            <ViewHosts />
          </div>
        );
        break;
      // "terminal" is intentionally absent here — it's rendered persistently
      // below (display-toggled) so the live SSH session + scrollback survive a
      // tab switch, exactly like the always-mounted desktop ViewTerminal.
      // "run" is intentionally absent here — like the terminal, it is rendered
      // persistently below so its live broadcast survives navigation.
      case "more":
        screen = <MMore go={(t) => push({ type: t })} onLock={ctx.onLock} />;
        break;
    }
  }

  return (
    <div
      className="mobile-shell"
      style={{
        background: p.bg0,
        color: p.txt,
        fontFamily: UI,
        display: "flex",
        flexDirection: "column",
        paddingTop: "env(safe-area-inset-top)",
        paddingLeft: "env(safe-area-inset-left)",
        paddingRight: "env(safe-area-inset-right)",
        // The bottom inset lives here, not on the tab bar: the bar hides on every
        // pushed frame, so delegating it there ran Settings/Secrets/Known/Tunnels/
        // SFTP right under the home indicator. The keyboard, when up, supersedes it.
        paddingBottom: kbInset || "env(safe-area-inset-bottom)",
        overflow: "hidden",
      }}
    >
      {/* On every tab, not just Hosts: the vault you're in and the way to LOCK are
          not properties of the hosts list. The lock used to exist on 1 tab of 4 — on
          the device most likely to be handed over, set down, or left on a table.
          Pushed frames are excluded: MWrapView already gives them a header, and two
          stacked headers on a phone is a worse answer than a lock one tap away. */}
      {!top && <MTopBar vault={vault} onVaultTap={() => setVaultSheet(true)} />}
      <div
        onTouchStart={(e) => {
          // Frames only. This gesture translates the container BELOW — which also
          // holds the Hosts detail rail — so arming it there dragged the list
          // sideways while the rail simply disappeared, attached to nothing. The
          // rail's back is the tab-tap and its own chevron.
          if (top && e.touches[0].clientX < EDGE_SWIPE_PX)
            setSw({ x: e.touches[0].clientX, dx: 0 });
        }}
        onTouchMove={(e) => {
          if (sw) setSw((s) => (s ? { ...s, dx: Math.max(0, e.touches[0].clientX - s.x) } : s));
        }}
        onTouchEnd={() => {
          if (sw && sw.dx > 70) pop();
          setSw(null);
        }}
        style={{
          flex: 1,
          minHeight: 0,
          display: "flex",
          flexDirection: "column",
          position: "relative",
          transform: sw && sw.dx ? `translateX(${Math.min(sw.dx, 140)}px)` : "none",
          transition: sw ? "none" : "transform .2s",
          opacity: sw && sw.dx ? Math.max(0.5, 1 - sw.dx / 320) : 1,
        }}
      >
        {screen}
        {/* The terminal stays mounted across tab switches (display-toggled): the
            backend session persists in the store, so unmounting MTerminal would
            dispose the xterm — blanking the scrollback and dropping the output
            callback, leaving a frozen, empty terminal on return. Desktop keeps
            ViewTerminal mounted for the same reason. */}
        <div
          style={{
            display: showTerminal ? "flex" : "none",
            flexDirection: "column",
            flex: 1,
            minHeight: 0,
          }}
        >
          <MTerminal onNeedHosts={() => switchTab("hosts")} />
        </div>
        {/* Run: mounted for the same reason as the terminal — it owns live
            broadcast sessions. ViewRun itself dual-mounts Broadcast and Fleet so
            switching MODE never tears them down either (spec A13). */}
        <div
          style={{
            display: showRun ? "flex" : "none",
            flexDirection: "column",
            flex: 1,
            minHeight: 0,
          }}
        >
          {runMounted && <ViewRun />}
        </div>
        {/* ViewSftp also stays mounted (display-toggled) so panes/cwd/selection
            survive leaving the sftp frame, mirroring the terminal and desktop.
            MWrapView gives it the same header + back; the edge-swipe still pops
            because this sits inside the swipe-transformed container. */}
        <div
          style={{
            display: showSftp ? "flex" : "none",
            flexDirection: "column",
            flex: 1,
            minHeight: 0,
          }}
        >
          <MWrapView label={t("nav.sftp")} onBack={pop}>
            <ViewSftp />
          </MWrapView>
        </div>
        {vaultSheet && <MVaultSheet onClose={() => setVaultSheet(false)} />}
      </div>
      {tabBarVisible && <MTabBar tab={tab} setTab={switchTab} />}
    </div>
  );
}
