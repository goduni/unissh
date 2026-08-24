// Window shell — title bar, sidebar (220px) <-> icon rail (<880px), vault
// switcher, nav. Faithful port of app-shell.jsx + app-main.jsx title slots,
// fed by real store data.

import React, { useEffect, useRef, useState } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { usePalette, useTheme } from "@/theme/ThemeProvider";
import { MONO, rem, TEXT } from "@/theme/tokens";
import { BTN_RESET, Icon, IconName, Logo, ResizeHandle, VaultBadge } from "@/components/primitives";
import { FlatAvatar, SyncBadge } from "@/components/mono";
import { useExternalEdits } from "@/sftp/external-edit";
import { useMenu } from "@/components/a11y";
import { useApp, HOST_FILTER_ALL } from "@/store/app";
import { hostDrag } from "@/support/hostDrag";
import { isMac } from "@/bridge/platform";
import { useFullscreen, useMaximized, useWindowControls } from "@/shell/WindowChrome";
import type { ControlButton } from "@/shell/windowControls";
import { useNarrow } from "@/store/responsive";
import type { Route } from "@/store/app";
import { useCtx } from "@/store/ctx";
import { apiErrorMessage, type VaultInfo } from "@/bridge/types";
import { serverShortLabel, vaultLoc, vaultServer } from "@/bridge/vaults";
import { useTranslation, tDyn } from "@/i18n";

// The four vault-item types share one screen (ViewSecrets, with in-screen tabs) and
// now one nav destination. Active-state tests membership of this set, not route===,
// so any of the preserved routes still highlights the merged item (spec A6).
const VAULT_ROUTES: Route[] = ["keys", "passwords", "identities", "notes"];
// Broadcast + Fleet exec are two modes of one "Run a command across hosts" screen.
const RUN_ROUTES: Route[] = ["run", "broadcast", "fleet"];

const groupIcon = (label: string): IconName => {
  const l = label.toLowerCase();
  if (l.includes("data") || l.includes("db")) return "database";
  if (l.includes("edge")) return "shield";
  if (l.includes("home")) return "home";
  return "globe";
};

function TitleIconBtn({
  icon,
  onClick,
  active,
  title,
}: {
  icon: IconName;
  onClick?: () => void;
  active?: boolean;
  title?: string;
}) {
  const p = usePalette();
  return (
    <button
      title={title}
      aria-label={title}
      onClick={onClick}
      style={{
        width: rem(30),
        height: rem(30),
        borderRadius: 8,
        // Neutral mono chrome (matches the IconBtn primitive): active = bg2 fill +
        // hairline + txt; resting = transparent + txt2. Accent is reserved for the
        // primary action and active nav tick, never for chrome icon buttons.
        border: `1px solid ${active ? p.line : "transparent"}`,
        background: active ? p.bg2 : "transparent",
        color: active ? p.txt : p.txt2,
        cursor: "pointer",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        flexShrink: 0,
        transition: "background .12s, color .12s",
      }}
      onMouseEnter={(e) => {
        if (!active) e.currentTarget.style.background = p.bg2;
      }}
      onMouseLeave={(e) => {
        if (!active) e.currentTarget.style.background = "transparent";
      }}
    >
      <Icon name={icon} size={15} stroke={1.8} />
    </button>
  );
}

export function SearchBar({ onClick }: { onClick: () => void }) {
  const p = usePalette();
  const { t } = useTranslation();
  // On a narrow window the full search box would be crushed to an unreadable sliver
  // by its 40vw cap, so collapse it to a clean icon-only button (same action).
  const narrow = useNarrow();
  if (narrow) {
    return (
      <button
        onClick={onClick}
        aria-label={t("shell.searchPlaceholder")}
        aria-keyshortcuts="Meta+K"
        style={{
          ...BTN_RESET,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          width: rem(34),
          height: rem(30),
          borderRadius: 8,
          background: p.bg2,
          border: `1px solid ${p.line}`,
          color: p.txt3,
          cursor: "pointer",
        }}
      >
        <Icon name="search" size={15} color={p.txt3} />
      </button>
    );
  }
  return (
    <button
      onClick={onClick}
      aria-label={t("shell.searchPlaceholder")}
      aria-keyshortcuts="Meta+K"
      style={{
        ...BTN_RESET,
        display: "flex",
        alignItems: "center",
        gap: rem(8),
        width: rem(380),
        maxWidth: "40vw",
        height: rem(30),
        padding: `0 ${rem(12)}`,
        borderRadius: 8,
        background: p.bg2,
        border: `1px solid ${p.line}`,
        color: p.txt3,
        fontSize: TEXT.base,
        cursor: "pointer",
      }}
    >
      <Icon name="search" size={14} color={p.txt3} />
      <span
        style={{ flex: 1, minWidth: 0, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}
      >
        {t("shell.searchPlaceholder")}
      </span>
      <span
        style={{
          fontFamily: MONO,
          fontSize: TEXT.micro,
          padding: `${rem(1)} ${rem(6)}`,
          borderRadius: 6,
          background: p.bg3,
          border: `1px solid ${p.line}`,
        }}
      >
        ⌘K
      </span>
    </button>
  );
}

/** Custom close/min/maximize controls for Windows/Linux. Which corner they sit
 *  in and what order they come in is `windowControlsLayout`'s answer, not this
 *  component's — it only draws what it is told. macOS never renders these: it
 *  keeps its native traffic lights, overlaid on the same spot (titleBarStyle:
 *  Overlay), and so does any platform where the system draws the frame. */
export function WindowControls() {
  const p = usePalette();
  const { t } = useTranslation();
  const maximized = useMaximized();
  const layout = useWindowControls();
  // After the hooks, before any window API: `custom` is the only case with
  // buttons of ours, and it is also what rules out a plain browser preview,
  // where getCurrentWindow() throws and — with no ErrorBoundary — would take
  // the whole tree down.
  if (layout.kind !== "custom") return null;
  const win = getCurrentWindow();
  const Btn = ({
    onClick,
    danger,
    children,
    title,
  }: {
    onClick: () => void;
    danger?: boolean;
    children: React.ReactNode;
    title: string;
  }) => (
    <button
      title={title}
      aria-label={title}
      onClick={onClick}
      style={{
        width: rem(30),
        height: rem(30),
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        border: "none",
        background: "transparent",
        color: p.txt2,
        cursor: "pointer",
        borderRadius: 8,
        transition: "background .12s, color .12s",
      }}
      onMouseEnter={(e) => {
        if (danger) {
          e.currentTarget.style.color = p.red;
          e.currentTarget.style.boxShadow = `inset 0 0 0 1px ${p.red}`;
        } else {
          e.currentTarget.style.background = p.bg3;
          e.currentTarget.style.color = p.txt;
        }
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.background = "transparent";
        e.currentTarget.style.color = p.txt2;
        e.currentTarget.style.boxShadow = "none";
      }}
    >
      {children}
    </button>
  );
  const line = (d: string) => (
    <svg width={11} height={11} viewBox="0 0 11 11" fill="none" stroke="currentColor" strokeWidth={1.2}>
      <path d={d} />
    </svg>
  );
  // Same three buttons, same icons, same hover treatment and the same danger
  // styling on close as before; the layout only permutes them. Rendering from
  // the order (rather than reordering with CSS) keeps the DOM order, and with it
  // the tab order and the accessible names, honest about what the eye sees.
  const btn: Record<ControlButton, React.ReactNode> = {
    close: (
      <Btn key="close" title={t("common.close")} danger onClick={() => void win.close()}>
        {line("M2 2l7 7M9 2l-7 7")}
      </Btn>
    ),
    minimize: (
      <Btn key="minimize" title={t("common.minimize")} onClick={() => void win.minimize()}>
        {line("M1.5 5.5h8")}
      </Btn>
    ),
    maximize: (
      <Btn
        key="maximize"
        title={maximized ? t("common.restore") : t("common.maximize")}
        onClick={() => void win.toggleMaximize()}
      >
        {line(maximized ? "M3.8 3.5V1.8h5.4v5.4H7.5M2 3.5h5.5v5.5H2z" : "M2 2h7v7h-7z")}
      </Btn>
    ),
  };
  return <div style={{ display: "flex", gap: rem(2) }}>{layout.order.map((b) => btn[b])}</div>;
}

export function TitleBar() {
  const { t } = useTranslation();
  const { toggleTwin } = useTheme();
  const route = useApp((s) => s.route);
  // Settings is an overlay on the desktop, so the button's lit state follows the
  // overlay rather than the route it no longer changes.
  const settingsOpen = useApp((s) => s.settingsOpen);
  const server = useApp((s) => s.serverStatus);
  const ctx = useCtx();
  // Native fullscreen hides the overlay traffic lights (they move into the
  // auto-revealed menu bar), so the reserved space collapses with them.
  const macFullscreen = useFullscreen(isMac());
  const layout = useWindowControls();
  // One question, asked once. The spacer, the controls and the logo all move off
  // this single answer, so the bar cannot end up reserving a gap on the left and
  // drawing the buttons on the right.
  const onLeft = layout.kind === "custom" && layout.side === "left";
  return (
    <>
      {/* pointerEvents none lets a mousedown on the spacer/logo fall through to
          the toolbar behind them, which carries data-tauri-drag-region — the
          attribute only triggers on the exact element under the cursor. The
          spacer clears the DEFAULT traffic-light span: the buttons are never
          repositioned (tao's inset surgery broke hit-testing on Tahoe). */}
      {layout.kind === "native" && !macFullscreen && (
        <div style={{ width: rem(60), pointerEvents: "none" }} aria-hidden />
      )}
      {onLeft && <WindowControls />}
      <div style={{ marginLeft: rem(4), display: "flex", pointerEvents: "none" }}>
        <Logo size={18} />
      </div>
      <div
        data-tauri-drag-region
        style={{
          flex: 1,
          display: "flex",
          justifyContent: "center",
          minWidth: 0,
          whiteSpace: "nowrap",
          overflow: "hidden",
        }}
      >
        <SearchBar onClick={ctx.openPalette} />
      </div>
      {/* data-tauri-drag-region: the 8px gaps between the icon buttons belong to
          this container's own box, so they drag the window; the buttons still
          win, since a clickable element in the event path blocks dragging. */}
      <div data-tauri-drag-region style={{ display: "flex", alignItems: "center", gap: rem(8) }}>
        <TitleIconBtn icon="moon" onClick={toggleTwin} title={t("shell.appTheme")} />
        <TitleIconBtn
          icon="sliders"
          // A lit button that ignores a click reads as broken, so it closes the
          // panel it opened — the same toggle the chord and the sheet promise.
          onClick={() => {
            const s = useApp.getState();
            if (s.settingsOpen) s.setSettingsOpen(false);
            else ctx.go("settings");
          }}
          active={route === "settings" || settingsOpen}
          title={`${t("nav.settings")} · ${isMac() ? "⌘," : "Ctrl+,"}`}
        />
        <TitleIconBtn icon="lock" onClick={ctx.onLock} title={t("shell.lock")} />
        {/* Account avatar — only for a linked cloud account with a handle. A
            local-only instance has no account, so no avatar is shown. */}
        {server?.connected && server.handle && (
          <span title={server.handle} style={{ display: "inline-flex" }}>
            <FlatAvatar name={server.handle} size={30} shape="round" />
          </span>
        )}
      </div>
      {/* Last in the bar, past the toolbar, when the controls live on the right:
          the search box's flex:1 already ate the space the buttons vacated on
          the left, so nothing is left behind but a wider drag region. */}
      {layout.kind === "custom" && layout.side === "right" && <WindowControls />}
    </>
  );
}

function NavItem({
  icon,
  label,
  count,
  active,
  sub,
  onClick,
  badge,
  onDropHosts,
}: {
  icon?: IconName;
  label: string;
  count?: number;
  active?: boolean;
  sub?: boolean;
  onClick?: () => void;
  badge?: string;
  /** Makes this item a drop target for hosts dragged off the Hosts screen.
   *  Only the group items pass it: "All hosts" is not a group, and dropping a
   *  host on it would mean un-grouping — a menu action, not this gesture. */
  onDropHosts?: (profileIds: string[]) => void;
}) {
  const p = usePalette();
  // Hover fill is React state, not an imperative e.currentTarget.style mutation:
  // a direct DOM write desyncs from React's style model, so on a theme switch the
  // reconciler sees background unchanged ("transparent" both renders) and leaves a
  // stale old-theme fill until the next mouse event. Declaring it keeps it in sync.
  const [hover, setHover] = useState(false);
  // Lit only while a host drag is actually over THIS item, so the affordance
  // says "the drop lands here" and not merely "a drag is happening".
  const [dropOver, setDropOver] = useState(false);
  // `dragleave` is not fired for a drag that ENDS over the item — press Escape
  // with the pointer here and the ring would stay lit on a drop that never
  // happened. `dragend` bubbles to the window for every ending there is.
  useEffect(() => {
    if (!dropOver) return;
    const off = () => setDropOver(false);
    window.addEventListener("dragend", off);
    return () => window.removeEventListener("dragend", off);
  }, [dropOver]);
  const dragProps = onDropHosts
    ? {
        onDragOver: (e: React.DragEvent) => {
          // No payload = not our drag (a file from the desktop, a link): leave it
          // unhandled so the item stays inert rather than pretending to accept it.
          if (hostDrag.get().length === 0) return;
          e.preventDefault();
          e.dataTransfer.dropEffect = "move";
          setDropOver(true);
        },
        // Crossing into the item's own icon/label fires dragleave on the item
        // (relatedTarget = the child), which without this guard blinks the ring
        // off and on as the pointer travels across it.
        onDragLeave: (e: React.DragEvent) => {
          if (e.currentTarget.contains(e.relatedTarget as Node)) return;
          setDropOver(false);
        },
        onDrop: (e: React.DragEvent) => {
          e.preventDefault();
          setDropOver(false);
          const ids = hostDrag.get();
          hostDrag.clear();
          if (ids.length > 0) onDropHosts(ids);
        },
      }
    : null;
  return (
    <button
      onClick={onClick}
      aria-current={active ? "page" : undefined}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      {...dragProps}
      style={{
        ...BTN_RESET,
        display: "flex",
        alignItems: "center",
        gap: rem(8),
        height: rem(32),
        // Reference nav: full-bleed row, no rounded pill / side margin. The accent
        // tick sits flush at the sidebar's left edge; accent is reserved for it.
        width: "100%",
        padding: sub ? `0 ${rem(18)} 0 ${rem(30)}` : `0 ${rem(18)}`,
        borderRadius: 0,
        cursor: "pointer",
        // Active = neutral fill + a 2.5px accent edge tick (the reference tick alone
        // read as almost invisible); hover = the same faint fill, no tick.
        background: active || hover || dropOver ? p.bg2 : "transparent",
        color: active ? p.txt : p.txt2,
        // Drop target = the same accent in a lighter weight: a hairline ring
        // instead of the solid edge tick, so "the drop lands here" is legible at
        // a glance yet never reads as "you are here" — the two are visible side
        // by side while the drag is over a group that isn't the current filter.
        boxShadow:
          [
            active ? `inset 2.5px 0 0 ${p.accent}` : null,
            dropOver ? `inset 0 0 0 1px ${p.accent}` : null,
          ]
            .filter(Boolean)
            .join(", ") || "none",
        fontSize: TEXT.base,
        fontWeight: active ? 600 : 500,
      }}
    >
      {icon && <Icon name={icon} size={15} color={active ? p.txt : p.txt3} stroke={1.7} />}
      <span style={{ flex: 1, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
        {label}
      </span>
      {badge && <span style={{ width: rem(6), height: rem(6), borderRadius: "50%", background: badge }} />}
      {count != null && (
        <span style={{ fontFamily: MONO, fontSize: TEXT.micro, color: p.txt3, fontWeight: 600 }}>
          {count}
        </span>
      )}
    </button>
  );
}

function NavGroup({
  children,
  label,
  action,
}: {
  children: React.ReactNode;
  label: string;
  action?: React.ReactNode;
}) {
  const p = usePalette();
  return (
    <>
      <div style={{ display: "flex", alignItems: "center", padding: `${rem(12)} ${rem(12)} ${rem(5)} ${rem(18)}` }}>
        <span
          style={{
            flex: 1,
            fontSize: TEXT.micro,
            fontWeight: 700,
            letterSpacing: rem(0.6),
            color: p.txt3,
            textTransform: "uppercase",
          }}
        >
          {label}
        </span>
        {action}
      </div>
      {children}
    </>
  );
}

/** Ghost chevron that folds the sidebar to the icon rail. Borderless and quiet so
 *  it sits beside the vault card without competing; a subtle fill appears on hover. */
function CollapseToggle({ onClick }: { onClick: () => void }) {
  const p = usePalette();
  const { t } = useTranslation();
  const [hover, setHover] = useState(false);
  return (
    <button
      title={t("common.minimize")}
      aria-label={t("common.minimize")}
      onClick={onClick}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        ...BTN_RESET,
        flexShrink: 0,
        width: rem(32),
        height: rem(32),
        borderRadius: 8,
        border: "1px solid transparent",
        background: hover ? p.bg1 : "transparent",
        color: hover ? p.txt2 : p.txt3,
        cursor: "pointer",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        transition: "background .12s ease, color .12s ease",
      }}
    >
      <Icon name="cl" size={15} />
    </button>
  );
}

function VaultSwitcher() {
  const p = usePalette();
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const vaults = useApp((s) => s.vaults);
  const vaultId = useApp((s) => s.vaultId);
  const servers = useApp((s) => s.servers);
  const syncStatus = useApp((s) => s.syncStatus);
  const setVault = useApp((s) => s.setVault);
  const menuRef = useRef<HTMLDivElement>(null);
  // outside click / Escape close + ArrowUp/Down over the vault rows
  useMenu(open, () => setOpen(false), menuRef);
  const v = vaults.find((x) => x.vaultId === vaultId) || vaults[0];
  if (!v) return null;

  // The vault's LOCATION for its badge: the bound server (space name via a live
  // session, else the server host, session-independently), so the switcher shows
  // *which* server a cloud vault syncs to — not a generic "Cloud". Amber "no server"
  // flags a cloud vault bound to nothing.
  const badgeLabel = (x: VaultInfo): string => {
    if (x.syncTarget !== "cloud") return t("vault.local");
    const loc = vaultLoc(x, servers);
    if (loc.server) return loc.server;
    const srv = vaultServer(x, servers);
    return srv ? serverShortLabel(srv) : t("vault.badgeUnbound");
  };
  const unboundCloud = (x: VaultInfo) =>
    x.syncTarget === "cloud" && vaultServer(x, servers) == null;
  return (
    <div ref={menuRef} style={{ position: "relative", flex: 1, minWidth: 0 }}>
      <button
        onClick={() => setOpen(!open)}
        aria-haspopup="menu"
        aria-expanded={open}
        style={{
          ...BTN_RESET,
          width: "100%",
          padding: rem(10),
          borderRadius: 10,
          background: p.bg1,
          border: `1px solid ${open ? p.accentLine : p.line}`,
          display: "flex",
          alignItems: "center",
          gap: rem(9),
          cursor: "pointer",
          // clip the location/sync badges to the card so a long "Синхронизировано"
          // + space name can never spill past the rounded frame
          overflow: "hidden",
        }}
      >
        <FlatAvatar name={v.name} size={26} />
        {/* spans (not divs) — the trigger is a <button>, which only allows phrasing content */}
        <span style={{ flex: 1, minWidth: 0, display: "block" }}>
          <span style={{ display: "flex", alignItems: "center", gap: rem(5), minWidth: 0 }}>
            <span
              style={{
                fontSize: TEXT.base,
                fontWeight: 700,
                whiteSpace: "nowrap",
                overflow: "hidden",
                textOverflow: "ellipsis",
              }}
            >
              {v.name}
            </span>
            <Icon name="unlock" size={11} color={p.green} style={{ flexShrink: 0 }} />
          </span>
          <span
            style={{
              fontSize: TEXT.micro,
              color: p.txt3,
              marginTop: rem(2),
              display: "flex",
              alignItems: "center",
              gap: rem(6),
              // Complete the shrink chain so the location/sync badges truncate here
              // instead of spilling over the chevron + collapse toggle at the
              // default (220px) sidebar width.
              minWidth: 0,
              overflow: "hidden",
            }}
          >
            <VaultBadge target={v.syncTarget} label={badgeLabel(v)} size={11} />
            {unboundCloud(v) && <Icon name="alert" size={11} color={p.amber} />}
            {v.syncTarget === "cloud" && !unboundCloud(v) && (
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
        </span>
        <Icon
          name={open ? "cr" : "cd"}
          size={14}
          color={p.txt3}
          style={{ transform: open ? "rotate(90deg)" : "none" }}
        />
      </button>
      {open && (
        <div
          role="menu"
          aria-label={t("shell.vaults")}
          style={{
            position: "absolute",
            bottom: "100%",
            left: 0,
            right: 0,
            marginBottom: rem(6),
            zIndex: 30,
            background: p.bg0,
            border: `1px solid ${p.line2}`,
            borderRadius: 12,
            padding: rem(6),
            boxShadow: p.shadow,
          }}
        >
          {vaults.map((x) => (
            <button
              key={x.vaultId}
              role="menuitemradio"
              aria-checked={x.vaultId === vaultId}
              tabIndex={-1}
              onClick={() => {
                void setVault(x.vaultId);
                setOpen(false);
              }}
              style={{
                ...BTN_RESET,
                width: "100%",
                display: "flex",
                alignItems: "center",
                gap: rem(9),
                padding: rem(8),
                borderRadius: 8,
                cursor: "pointer",
                background: x.vaultId === vaultId ? p.bg4 : "transparent",
              }}
              onMouseEnter={(e) => {
                if (x.vaultId !== vaultId) e.currentTarget.style.background = p.bg2;
              }}
              onMouseLeave={(e) => {
                if (x.vaultId !== vaultId) e.currentTarget.style.background = "transparent";
              }}
            >
              <FlatAvatar name={x.name} size={22} />
              <span
                style={{
                  flex: 1,
                  fontSize: TEXT.base,
                  fontWeight: 600,
                  whiteSpace: "nowrap",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                }}
              >
                {x.name}
              </span>
              <VaultBadge target={x.syncTarget} label={badgeLabel(x)} size={11} />
              {unboundCloud(x) && <Icon name="alert" size={11} color={p.amber} />}
              {x.vaultId === vaultId && <Icon name="check" size={14} color={p.accentText} />}
            </button>
          ))}
          <div style={{ height: 1, background: p.line, margin: `${rem(6)} ${rem(4)}` }} />
          <button
            role="menuitem"
            tabIndex={-1}
            onClick={() => {
              useApp.getState().openModal({ kind: "vault" });
              setOpen(false);
            }}
            style={{
              ...BTN_RESET,
              width: "100%",
              display: "flex",
              alignItems: "center",
              gap: rem(9),
              padding: rem(8),
              borderRadius: 8,
              cursor: "pointer",
              color: p.txt2,
            }}
          >
            <span
              style={{
                width: rem(22),
                height: rem(22),
                borderRadius: 6,
                border: `1px dashed ${p.line2}`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <Icon name="plus" size={12} />
            </span>
            <span style={{ fontSize: TEXT.base, fontWeight: 600 }}>{t("shell.newVault")}</span>
          </button>
        </div>
      )}
    </div>
  );
}

const RAIL_LABEL_KEY: Partial<Record<Route, string>> = {
  hosts: "nav.allHosts",
  run: "nav.run",
  sftp: "nav.sftp",
  terminal: "nav.terminal",
  keys: "nav.keys",
  tunnels: "nav.tunnels",
  known: "nav.known",
  recordings: "nav.recordings",
  snippets: "nav.snippets",
};

function SidebarRail({ onExpand }: { onExpand?: () => void }) {
  const p = usePalette();
  const { t } = useTranslation();
  const route = useApp((s) => s.route);
  const editsNeedingAttention = useExternalEdits((s) =>
    s.edits.some((e) => e.state === "conflict" || e.state === "error"),
  );
  const vaults = useApp((s) => s.vaults);
  const vaultId = useApp((s) => s.vaultId);
  const setVault = useApp((s) => s.setVault);
  const ctx = useCtx();
  const v = vaults.find((x) => x.vaultId === vaultId) || vaults[0];
  const item = (icon: IconName, r: Route, badge?: string) => (
    <button
      key={icon + r}
      onClick={() => ctx.go(r)}
      title={RAIL_LABEL_KEY[r] ? tDyn(RAIL_LABEL_KEY[r]!) : r}
      aria-label={RAIL_LABEL_KEY[r] ? tDyn(RAIL_LABEL_KEY[r]!) : r}
      aria-current={route === r ? "page" : undefined}
      style={{
        width: rem(40),
        height: rem(40),
        borderRadius: 12,
        cursor: "pointer",
        position: "relative",
        border: "1px solid transparent",
        background: "transparent",
        color: route === r ? p.accentText : p.txt3,
        boxShadow: route === r ? `inset 2px 0 0 ${p.accent}` : "none",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
      }}
    >
      <Icon name={icon} size={18} stroke={1.7} />
      {badge && (
        <span
          style={{
            position: "absolute",
            top: rem(7),
            right: rem(7),
            width: rem(6),
            height: rem(6),
            borderRadius: "50%",
            background: badge,
          }}
        />
      )}
    </button>
  );
  return (
    <div
      style={{
        width: rem(60),
        flexShrink: 0,
        background: p.bg0,
        borderRight: `1px solid ${p.line}`,
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        gap: rem(6),
        padding: `${rem(12)} 0`,
      }}
    >
      <button
        onClick={() => {
          const i = vaults.findIndex((x) => x.vaultId === vaultId);
          if (vaults.length) void setVault(vaults[(i + 1) % vaults.length].vaultId);
        }}
        title={t("shell.vaultTooltip", { name: v?.name ?? "" })}
        aria-label={t("shell.vaultTooltip", { name: v?.name ?? "" })}
        style={{
          width: rem(40),
          height: rem(40),
          borderRadius: 12,
          cursor: "pointer",
          background: p.bg3,
          border: `1px solid ${p.line}`,
          color: p.txt2,
          fontWeight: 700,
          fontSize: TEXT.lead,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        {v?.name[0] ?? "?"}
      </button>
      <div style={{ width: rem(24), height: 1, background: p.line, margin: `${rem(4)} 0` }} />
      {item("server", "hosts")}
      {item("terminal", "terminal", p.green)}
      {/* An edit that stopped pushing is only actionable in the SFTP view, so
          the rail is what says so from anywhere else. */}
      {item("folders", "sftp", editsNeedingAttention ? p.amber : undefined)}
      {item("radio", "run")}
      {item("key", "keys")}
      {item("branch", "tunnels")}
      {item("shieldcheck", "known")}
      {item("record", "recordings")}
      {item("terminal", "snippets")}
      <div style={{ flex: 1 }} />
      {onExpand && (
        <button
          title={t("common.maximize")}
          aria-label={t("common.maximize")}
          onClick={onExpand}
          style={{
            width: rem(38),
            height: rem(38),
            borderRadius: 12,
            border: `1px solid ${p.line}`,
            background: p.bg1,
            color: p.txt2,
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <Icon name="cr" size={16} />
        </button>
      )}
      <button
        title={t("shell.lockShort")}
        aria-label={t("shell.lockShort")}
        onClick={ctx.onLock}
        style={{
          width: rem(38),
          height: rem(38),
          borderRadius: 12,
          border: `1px solid ${p.line}`,
          background: p.bg1,
          color: p.txt2,
          cursor: "pointer",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        <Icon name="lock" size={16} />
      </button>
    </div>
  );
}

/** Window wide enough for the full sidebar rather than the icon rail. Takes the
 *  ANSWER, not the width: the caller holds this in root state, and a pixel value
 *  there re-renders the whole app on every frame of a resize (see App.tsx). */
export function Sidebar({
  wide,
  collapsed,
  width,
  onToggleCollapse,
  onResize,
}: {
  wide: boolean;
  collapsed: boolean;
  width: number;
  onToggleCollapse: () => void;
  onResize: (clientX: number) => void;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const route = useApp((s) => s.route);
  const editsNeedingAttention = useExternalEdits((s) =>
    s.edits.some((e) => e.state === "conflict" || e.state === "error"),
  );
  const hosts = useApp((s) => s.hosts);
  const groups = useApp((s) => s.groups);
  const terminals = useApp((s) => s.terminals);
  const tunnels = useApp((s) => s.tunnels);
  const hostFilter = useApp((s) => s.hostFilter);
  const moveHostsToGroup = useApp((s) => s.moveHostsToGroup);
  const setGroupsNavVisible = useApp((s) => s.setGroupsNavVisible);
  const ctx = useCtx();

  // Report whether the group list is actually on screen. The Hosts screen gates
  // its drag on this: folded to the icon rail there are no group items, so
  // there is nothing to drop on, and a host you can pick up but never put down
  // is the affordance-that-can-only-fail this feature is at pains to avoid.
  // Reported from here rather than computed there so it stays true by
  // construction if the rail ever grows or loses a section.
  const groupsShown = wide && !collapsed;
  useEffect(() => setGroupsNavVisible(groupsShown), [groupsShown, setGroupsNavVisible]);

  // Drop of hosts dragged off the Hosts screen. The move itself is the store's,
  // unchanged — drag adds no membership rules of its own, so it and the menu
  // can never disagree about what filing a host means. A false return is
  // "nothing would change" (dropped on the group they are already in, or on a
  // group another window just deleted): no write, no reload, and no toast for a
  // move that didn't happen.
  const dropHostsOn = (groupId: string, label: string) => (profileIds: string[]) => {
    void moveHostsToGroup(groupId, profileIds)
      .then((moved) => {
        if (moved) ctx.toast(t("hosts.bulk.movedToGroup", { name: label }), "ok");
      })
      .catch((e) => ctx.toast(apiErrorMessage(e), "err"));
  };

  if (!wide || collapsed) return <SidebarRail onExpand={wide ? onToggleCollapse : undefined} />;

  const onHosts = route === "hosts";
  const hostCount = hosts.length;

  return (
    <div
      style={{
        // Design pixels (see App.tsx's resizeSidebar): the sidebar holds labels,
        // so it has to grow with them or "Known hosts" truncates at 150 %.
        width: rem(width),
        flexShrink: 0,
        position: "relative",
        background: p.bg0,
        borderRight: `1px solid ${p.line}`,
        display: "flex",
        flexDirection: "column",
        padding: `${rem(12)} 0`,
      }}
    >
      <ResizeHandle side="right" onDrag={onResize} />
      <div style={{ overflow: "hidden", flex: 1, display: "flex", flexDirection: "column" }}>
        <NavGroup
          label={t("shell.groupsHeader")}
          action={
            <button
              onClick={ctx.openGroups}
              title={t("shell.manageGroups")}
              aria-label={t("shell.manageGroups")}
              style={{
                width: rem(22),
                height: rem(22),
                borderRadius: 6,
                border: `1px solid ${p.line}`,
                background: p.bg1,
                color: p.txt3,
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <Icon name="sliders" size={12} />
            </button>
          }
        >
          <NavItem
            icon="server"
            label={t("nav.allHosts")}
            count={hostCount}
            active={onHosts && (hostFilter === HOST_FILTER_ALL || !hostFilter)}
            onClick={() => ctx.goFiltered(HOST_FILTER_ALL)}
          />
          {groups.map((g) => (
            <NavItem
              key={g.groupId}
              icon={groupIcon(g.label)}
              label={g.label}
              count={g.memberIds.filter((m) => hosts.some((h) => h.profileId === m)).length}
              sub
              active={onHosts && hostFilter === g.groupId}
              onClick={() => ctx.goFiltered(g.groupId)}
              onDropHosts={dropHostsOn(g.groupId, g.label)}
            />
          ))}
        </NavGroup>
        <NavGroup label={t("shell.operationsHeader")}>
          <NavItem
            icon="terminal"
            label={t("nav.terminals")}
            count={terminals.length || undefined}
            active={route === "terminal"}
            onClick={() => ctx.go("terminal")}
            badge={
              terminals.some((tm) => tm.panes.some((pp) => pp.status === "online")) ? p.green : undefined
            }
          />
          {/* No local-terminal item here on purpose. Every other row in this
              nav is a destination you return to; a local shell is an action
              that spawns a new tab each time, which made it the odd one out.
              It is reached from the "+" picker, ⌘⇧S / Ctrl+Shift+S, and a
              pane's Split menu. */}
          <NavItem
            icon="folders"
            label={t("nav.sftp")}
            active={route === "sftp"}
            badge={editsNeedingAttention ? p.amber : undefined}
            onClick={() => ctx.go("sftp")}
          />
          <NavItem icon="radio" label={t("nav.run")} active={RUN_ROUTES.includes(route)} onClick={() => ctx.go("run")} />
        </NavGroup>
        <NavGroup label={t("shell.vaultNetworkHeader")}>
          {/* Sidebar numbers are LIVE state (open terminals, active tunnels) or
              host-filter cardinality — never inventory size. Secrets/Known counts
              were shelf-stock trivia; an active tunnel is something running that
              you may have forgotten about, so it earns both number and dot. */}
          <NavItem
            icon="key"
            label={t("nav.secrets")}
            active={VAULT_ROUTES.includes(route)}
            onClick={() => ctx.go("keys")}
          />
          <NavItem
            icon="branch"
            label={t("nav.tunnels")}
            count={tunnels.length || undefined}
            badge={tunnels.length ? p.green : undefined}
            active={route === "tunnels"}
            onClick={() => ctx.go("tunnels")}
          />
          <NavItem
            icon="shieldcheck"
            label={t("nav.known")}
            active={route === "known"}
            onClick={() => ctx.go("known")}
          />
          <NavItem
            icon="record"
            label={t("nav.recordings")}
            active={route === "recordings"}
            onClick={() => ctx.go("recordings")}
          />
          <NavItem
            icon="terminal"
            label={t("nav.snippets")}
            active={route === "snippets"}
            onClick={() => ctx.go("snippets")}
          />
        </NavGroup>
      </div>
      <div
        style={{
          marginTop: rem(8),
          borderTop: `1px solid ${p.line}`,
          padding: `${rem(10)} ${rem(12)} 0`,
          display: "flex",
          alignItems: "center",
          gap: rem(6),
        }}
      >
        <VaultSwitcher />
        <CollapseToggle onClick={onToggleCollapse} />
      </div>
    </div>
  );
}
