// Window shell — title bar, sidebar (220px) <-> icon rail (<880px), vault
// switcher, nav. Faithful port of app-shell.jsx + app-main.jsx title slots,
// fed by real store data.

import React, { useRef, useState } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { usePalette, useTheme } from "@/theme/ThemeProvider";
import { MONO } from "@/theme/tokens";
import { BTN_RESET, Icon, IconName, Logo, ResizeHandle, VaultBadge } from "@/components/primitives";
import { FlatAvatar, SyncBadge } from "@/components/mono";
import { useMenu } from "@/components/a11y";
import { useApp, HOST_FILTER_ALL } from "@/store/app";
import type { Route } from "@/store/app";
import { useCtx } from "@/store/ctx";
import { ItemType } from "@/bridge/types";
import { useTranslation, tDyn } from "@/i18n";

// The four vault-item types share one screen (ViewSecrets, with in-screen tabs) and
// now one nav destination. Active-state tests membership of this set, not route===,
// so any of the preserved routes still highlights the merged item (spec A6).
const VAULT_ROUTES: Route[] = ["keys", "passwords", "identities", "notes"];

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
        width: 30,
        height: 30,
        borderRadius: 8,
        border: `1px solid ${active ? p.accentLine : p.line}`,
        background: active ? p.accentSoft : p.bg2,
        color: active ? p.accent : p.txt2,
        cursor: "pointer",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        flexShrink: 0,
      }}
    >
      <Icon name={icon} size={15} stroke={1.8} />
    </button>
  );
}

export function SearchBar({ onClick }: { onClick: () => void }) {
  const p = usePalette();
  const { t } = useTranslation();
  return (
    <button
      onClick={onClick}
      aria-label={t("shell.searchPlaceholder")}
      aria-keyshortcuts="Meta+K"
      style={{
        ...BTN_RESET,
        display: "flex",
        alignItems: "center",
        gap: 8,
        width: 380,
        maxWidth: "40vw",
        height: 30,
        padding: "0 12px",
        borderRadius: 9,
        background: p.bg2,
        border: `1px solid ${p.line}`,
        color: p.txt3,
        fontSize: 13,
        cursor: "pointer",
      }}
    >
      <Icon name="search" size={14} color={p.txt3} />
      <span style={{ flex: 1, whiteSpace: "nowrap", overflow: "hidden" }}>
        {t("shell.searchPlaceholder")}
      </span>
      <span
        style={{
          fontFamily: MONO,
          fontSize: 11,
          padding: "1px 6px",
          borderRadius: 5,
          background: p.bg3,
          border: `1px solid ${p.line}`,
        }}
      >
        ⌘K
      </span>
    </button>
  );
}

/** Custom min/maximize/close controls for Windows/Linux (macOS uses native
 *  traffic lights). Rendered at the far right of the title bar. */
export function WindowControls() {
  const p = usePalette();
  const { t } = useTranslation();
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
        width: 30,
        height: 30,
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        border: "none",
        background: "transparent",
        color: p.txt2,
        cursor: "pointer",
        borderRadius: 7,
        transition: "background .12s, color .12s",
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.background = danger ? "#e0556a" : p.bg3;
        e.currentTarget.style.color = danger ? "#fff" : p.txt;
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.background = "transparent";
        e.currentTarget.style.color = p.txt2;
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
  return (
    <div style={{ display: "flex", gap: 2, marginLeft: 6 }}>
      <Btn title={t("common.minimize")} onClick={() => void win.minimize()}>
        {line("M1.5 5.5h8")}
      </Btn>
      <Btn title={t("common.maximize")} onClick={() => void win.toggleMaximize()}>
        {line("M2 2h7v7h-7z")}
      </Btn>
      <Btn title={t("common.close")} danger onClick={() => void win.close()}>
        {line("M2 2l7 7M9 2l-7 7")}
      </Btn>
    </div>
  );
}

export function TitleBar() {
  const { t } = useTranslation();
  const { toggleTwin } = useTheme();
  const route = useApp((s) => s.route);
  const server = useApp((s) => s.serverStatus);
  const ctx = useCtx();
  return (
    <>
      <div style={{ marginLeft: 4 }}>
        <Logo size={18} />
      </div>
      <div
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
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <TitleIconBtn icon="moon" onClick={toggleTwin} title={t("shell.appTheme")} />
        <TitleIconBtn
          icon="sliders"
          onClick={() => ctx.go("settings")}
          active={route === "settings"}
          title={t("nav.settings")}
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
}: {
  icon?: IconName;
  label: string;
  count?: number;
  active?: boolean;
  sub?: boolean;
  onClick?: () => void;
  badge?: string;
}) {
  const p = usePalette();
  return (
    <button
      onClick={onClick}
      aria-current={active ? "page" : undefined}
      style={{
        ...BTN_RESET,
        display: "flex",
        alignItems: "center",
        gap: 9,
        height: 32,
        // buttons shrink-to-fit, so the div's margins become width math
        width: sub ? "calc(100% - 30px)" : "calc(100% - 16px)",
        padding: "0 10px",
        margin: sub ? "0 8px 0 22px" : "0 8px",
        borderRadius: 8,
        cursor: "pointer",
        background: "transparent",
        color: active ? p.txt : p.txt2,
        boxShadow: active ? `inset 2px 0 0 ${p.accent}` : "none",
        fontSize: 13,
        fontWeight: active ? 600 : 500,
      }}
      onMouseEnter={(e) => {
        if (!active) e.currentTarget.style.background = p.bg2;
      }}
      onMouseLeave={(e) => {
        if (!active) e.currentTarget.style.background = "transparent";
      }}
    >
      {icon && <Icon name={icon} size={15} color={active ? p.accent : p.txt3} stroke={1.7} />}
      <span style={{ flex: 1, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
        {label}
      </span>
      {badge && <span style={{ width: 6, height: 6, borderRadius: "50%", background: badge }} />}
      {count != null && (
        <span style={{ fontFamily: MONO, fontSize: 11, color: p.txt3, fontWeight: 600 }}>
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
      <div style={{ display: "flex", alignItems: "center", padding: "12px 12px 5px 18px" }}>
        <span
          style={{
            flex: 1,
            fontSize: 10.5,
            fontWeight: 700,
            letterSpacing: 0.6,
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

function VaultSwitcher() {
  const p = usePalette();
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const vaults = useApp((s) => s.vaults);
  const vaultId = useApp((s) => s.vaultId);
  const syncStatus = useApp((s) => s.syncStatus);
  const setVault = useApp((s) => s.setVault);
  const menuRef = useRef<HTMLDivElement>(null);
  // outside click / Escape close + ArrowUp/Down over the vault rows
  useMenu(open, () => setOpen(false), menuRef);
  const v = vaults.find((x) => x.vaultId === vaultId) || vaults[0];
  if (!v) return null;
  return (
    <div ref={menuRef} style={{ position: "relative", margin: "0 12px 8px" }}>
      <button
        onClick={() => setOpen(!open)}
        aria-haspopup="menu"
        aria-expanded={open}
        style={{
          ...BTN_RESET,
          width: "100%",
          padding: 10,
          borderRadius: 10,
          background: p.bg1,
          border: `1px solid ${open ? p.accentLine : p.line}`,
          display: "flex",
          alignItems: "center",
          gap: 9,
          cursor: "pointer",
        }}
      >
        <FlatAvatar name={v.name} size={26} />
        {/* spans (not divs) — the trigger is a <button>, which only allows phrasing content */}
        <span style={{ flex: 1, minWidth: 0, display: "block" }}>
          <span style={{ display: "flex", alignItems: "center", gap: 5, minWidth: 0 }}>
            <span
              style={{
                fontSize: 13,
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
              fontSize: 11,
              color: p.txt3,
              marginTop: 2,
              display: "flex",
              alignItems: "center",
              gap: 6,
            }}
          >
            <VaultBadge
              target={v.syncTarget}
              label={v.syncTarget === "cloud" ? t("vault.cloud") : t("vault.local")}
              size={11}
            />
            {v.syncTarget === "cloud" && (
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
            top: "100%",
            left: 0,
            right: 0,
            marginTop: 6,
            zIndex: 30,
            background: p.bg3,
            border: `1px solid ${p.line2}`,
            borderRadius: 12,
            padding: 6,
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
                gap: 9,
                padding: 8,
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
                  fontSize: 13,
                  fontWeight: 600,
                  whiteSpace: "nowrap",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                }}
              >
                {x.name}
              </span>
              <VaultBadge
                target={x.syncTarget}
                label={x.syncTarget === "cloud" ? t("vault.cloud") : t("vault.local")}
                size={11}
              />
              {x.vaultId === vaultId && <Icon name="check" size={14} color={p.accent} />}
            </button>
          ))}
          <div style={{ height: 1, background: p.line, margin: "6px 4px" }} />
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
              gap: 9,
              padding: 8,
              borderRadius: 8,
              cursor: "pointer",
              color: p.txt2,
            }}
          >
            <span
              style={{
                width: 22,
                height: 22,
                borderRadius: 6,
                border: `1px dashed ${p.line2}`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <Icon name="plus" size={12} />
            </span>
            <span style={{ fontSize: 13, fontWeight: 600 }}>{t("shell.newVault")}</span>
          </button>
        </div>
      )}
    </div>
  );
}

const RAIL_LABEL_KEY: Partial<Record<Route, string>> = {
  hosts: "nav.allHosts",
  fleet: "nav.fleet",
  broadcast: "nav.broadcast",
  sftp: "nav.sftp",
  terminal: "nav.terminal",
  keys: "nav.keys",
  tunnels: "nav.tunnels",
  known: "nav.known",
};

function SidebarRail({ onExpand }: { onExpand?: () => void }) {
  const p = usePalette();
  const { t } = useTranslation();
  const route = useApp((s) => s.route);
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
        width: 40,
        height: 40,
        borderRadius: 11,
        cursor: "pointer",
        position: "relative",
        border: `1px solid ${route === r ? p.accentLine : "transparent"}`,
        background: route === r ? p.accentSoft : "transparent",
        color: route === r ? p.accent : p.txt3,
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
            top: 7,
            right: 7,
            width: 6,
            height: 6,
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
        width: 60,
        flexShrink: 0,
        background: p.bg2,
        borderRight: `1px solid ${p.line}`,
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        gap: 6,
        padding: "12px 0",
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
          width: 40,
          height: 40,
          borderRadius: 12,
          cursor: "pointer",
          background: p.bg3,
          border: `1px solid ${p.line}`,
          color: p.txt2,
          fontWeight: 700,
          fontSize: 15,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        {v?.name[0] ?? "?"}
      </button>
      <div style={{ width: 24, height: 1, background: p.line, margin: "4px 0" }} />
      {item("server", "hosts")}
      {item("terminal", "terminal", p.green)}
      {item("folders", "sftp")}
      {item("radio", "broadcast")}
      {item("layers", "fleet")}
      {item("key", "keys")}
      {item("branch", "tunnels")}
      {item("shieldcheck", "known")}
      <div style={{ flex: 1 }} />
      {onExpand && (
        <button
          title={t("common.maximize")}
          aria-label={t("common.maximize")}
          onClick={onExpand}
          style={{
            width: 38,
            height: 38,
            borderRadius: 11,
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
          width: 38,
          height: 38,
          borderRadius: 11,
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

export function Sidebar({
  winW,
  collapsed,
  width,
  onToggleCollapse,
  onResize,
}: {
  winW: number;
  collapsed: boolean;
  width: number;
  onToggleCollapse: () => void;
  onResize: (clientX: number) => void;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const route = useApp((s) => s.route);
  const hosts = useApp((s) => s.hosts);
  const groups = useApp((s) => s.groups);
  const items = useApp((s) => s.items);
  const knownHosts = useApp((s) => s.knownHosts);
  const terminals = useApp((s) => s.terminals);
  const hostFilter = useApp((s) => s.hostFilter);
  const ctx = useCtx();

  if (winW < 880 || collapsed)
    return <SidebarRail onExpand={winW >= 880 ? onToggleCollapse : undefined} />;

  const onHosts = route === "hosts";
  const keysN = items.filter((i) => i.itemType === ItemType.SshKey).length;
  const passN = items.filter((i) => i.itemType === ItemType.Password).length;
  const notesN = items.filter((i) => i.itemType === ItemType.Note).length;
  const identN = items.filter((i) => i.itemType === ItemType.Identity).length;
  const hostCount = hosts.length;

  return (
    <div
      style={{
        width,
        flexShrink: 0,
        position: "relative",
        background: p.bg2,
        borderRight: `1px solid ${p.line}`,
        display: "flex",
        flexDirection: "column",
        padding: "12px 0",
      }}
    >
      <ResizeHandle side="right" onDrag={onResize} />
      <VaultSwitcher />
      <div style={{ overflow: "hidden", flex: 1, display: "flex", flexDirection: "column" }}>
        <NavGroup
          label={t("shell.groupsHeader")}
          action={
            <button
              onClick={ctx.openGroups}
              title={t("shell.manageGroups")}
              aria-label={t("shell.manageGroups")}
              style={{
                width: 22,
                height: 22,
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
          <NavItem icon="folders" label={t("nav.sftp")} active={route === "sftp"} onClick={() => ctx.go("sftp")} />
          <NavItem icon="radio" label={t("nav.broadcast")} active={route === "broadcast"} onClick={() => ctx.go("broadcast")} />
          <NavItem icon="layers" label={t("nav.fleetExec")} active={route === "fleet"} onClick={() => ctx.go("fleet")} />
        </NavGroup>
        <NavGroup label={t("shell.vaultNetworkHeader")}>
          <NavItem
            icon="key"
            label={t("nav.secrets")}
            count={keysN + passN + identN + notesN}
            active={VAULT_ROUTES.includes(route)}
            onClick={() => ctx.go("keys")}
          />
          <NavItem icon="branch" label={t("nav.tunnels")} active={route === "tunnels"} onClick={() => ctx.go("tunnels")} />
          <NavItem
            icon="shieldcheck"
            label={t("nav.known")}
            count={knownHosts.length}
            active={route === "known"}
            onClick={() => ctx.go("known")}
          />
        </NavGroup>
      </div>
      <div
        style={{
          margin: "8px 12px 0",
          paddingTop: 10,
          borderTop: `1px solid ${p.line}`,
          display: "flex",
          alignItems: "center",
          justifyContent: "flex-end",
        }}
      >
        <button
          title={t("common.minimize")}
          aria-label={t("common.minimize")}
          onClick={onToggleCollapse}
          style={{
            width: 28,
            height: 28,
            borderRadius: 8,
            border: `1px solid ${p.line}`,
            background: p.bg1,
            color: p.txt2,
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <Icon name="cl" size={14} />
        </button>
      </div>
    </div>
  );
}
