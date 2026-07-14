// command-palette.tsx — ⌘K live search across hosts, commands, navigation.
// Pixel-perfect port of command-palette.jsx, wired to the real store + ctx.

import React, { useEffect, useMemo, useRef, useState } from "react";
import { usePalette } from "@/theme/ThemeProvider";
import { MONO, UI } from "@/theme/tokens";
import { Icon, NO_AUTOCORRECT, type IconName } from "@/components/primitives";
import { useApp, type Route } from "@/store/app";
import { useCtx } from "@/store/ctx";
import type { ConnectionProfile } from "@/bridge/types";
import { useTranslation, tDyn } from "@/i18n";

interface NavCmd {
  id: string;
  icon: IconName;
  labelKey: string;
  subKey: string;
  route: Route;
}
interface ActionCmd {
  id: string;
  icon: IconName;
  labelKey: string;
  subKey: string;
  action: "newhost" | "newkey" | "newtunnel" | "import" | "groups" | "sync" | "lock";
}

const CMD_NAV: NavCmd[] = [
  { id: "n-hosts", icon: "server", labelKey: "nav.allHosts", subKey: "command.nav.hosts", route: "hosts" },
  { id: "n-terminal", icon: "terminal", labelKey: "nav.terminals", subKey: "command.nav.terminal", route: "terminal" },
  { id: "n-sftp", icon: "folders", labelKey: "nav.sftp", subKey: "command.nav.sftp", route: "sftp" },
  { id: "n-broadcast", icon: "radio", labelKey: "nav.broadcast", subKey: "command.nav.broadcast", route: "broadcast" },
  { id: "n-fleet", icon: "layers", labelKey: "nav.fleetExec", subKey: "command.nav.fleet", route: "fleet" },
  { id: "n-tunnels", icon: "branch", labelKey: "nav.tunnels", subKey: "command.nav.tunnels", route: "tunnels" },
  { id: "n-known", icon: "shieldcheck", labelKey: "nav.known", subKey: "command.nav.known", route: "known" },
  { id: "n-keys", icon: "key", labelKey: "nav.keys", subKey: "command.nav.keys", route: "keys" },
  { id: "n-passwords", icon: "lock", labelKey: "nav.passwords", subKey: "command.nav.passwords", route: "passwords" },
  { id: "n-identities", icon: "fingerprint", labelKey: "nav.identities", subKey: "command.nav.identities", route: "identities" },
  { id: "n-notes", icon: "note", labelKey: "nav.notes", subKey: "command.nav.notes", route: "notes" },
  { id: "n-settings", icon: "sliders", labelKey: "nav.settings", subKey: "command.nav.settings", route: "settings" },
];
const CMD_ACTIONS: ActionCmd[] = [
  { id: "a-newhost", icon: "plus", labelKey: "command.action.newHost", subKey: "command.action.newHostSub", action: "newhost" },
  { id: "a-newkey", icon: "key", labelKey: "command.action.newKey", subKey: "command.action.newKeySub", action: "newkey" },
  { id: "a-newtunnel", icon: "branch", labelKey: "command.action.newTunnel", subKey: "command.action.newTunnelSub", action: "newtunnel" },
  { id: "a-import", icon: "download", labelKey: "command.action.import", subKey: "command.action.importSub", action: "import" },
  { id: "a-groups", icon: "layers", labelKey: "command.action.groups", subKey: "command.action.groupsSub", action: "groups" },
  { id: "a-sync", icon: "refresh", labelKey: "command.action.sync", subKey: "command.action.syncSub", action: "sync" },
  { id: "a-lock", icon: "lock", labelKey: "command.action.lock", subKey: "command.action.lockSub", action: "lock" },
];

type FlatItem =
  | { id: string; icon: IconName; label: string; sub: string; kind: "host"; host: ConnectionProfile }
  | { id: string; icon: IconName; label: string; sub: string; kind: "nav"; route: Route }
  | { id: string; icon: IconName; label: string; sub: string; kind: "action"; action: ActionCmd["action"] };

interface Group {
  title: string;
  items: FlatItem[];
}

export function CommandPalette() {
  const { t } = useTranslation();
  const p = usePalette();
  const ctx = useCtx();
  const open = useApp((s) => s.palette);
  const setPalette = useApp((s) => s.setPalette);
  const hosts = useApp((s) => s.hosts);

  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (open) inputRef.current?.focus();
  }, [open]);

  const ql = q.trim().toLowerCase();

  const groups = useMemo<Group[]>(() => {
    const match = (s: string) => !ql || s.toLowerCase().includes(ql);

    const hostItems: FlatItem[] = hosts
      .filter((h) => match(h.label) || match(h.host) || match(h.user) || h.tags.some(match))
      .slice(0, 6)
      .map((h) => ({
        id: "h-" + h.profileId,
        icon: "server",
        label: h.label,
        sub: `${h.user}@${h.host}`,
        kind: "host",
        host: h,
      }));
    const navItems: FlatItem[] = CMD_NAV.map((c) => ({
      id: c.id,
      icon: c.icon,
      label: tDyn(c.labelKey),
      sub: tDyn(c.subKey),
      kind: "nav" as const,
      route: c.route,
    })).filter((c) => match(c.label) || match(c.sub));
    const actItems: FlatItem[] = CMD_ACTIONS.map((c) => ({
      id: c.id,
      icon: c.icon,
      label: tDyn(c.labelKey),
      sub: tDyn(c.subKey),
      kind: "action" as const,
      action: c.action,
    })).filter((c) => match(c.label) || match(c.sub));

    return [
      { title: t("command.group.hosts"), items: hostItems },
      { title: t("command.group.actions"), items: actItems },
      { title: t("command.group.go"), items: navItems },
    ].filter((g) => g.items.length);
  }, [ql, hosts, t]);

  const flat = useMemo(() => groups.flatMap((g) => g.items), [groups]);

  useEffect(() => {
    setSel(0);
  }, [q]);

  if (!open) return null;

  const close = () => setPalette(false);

  const run = (it: FlatItem) => {
    if (it.kind === "host") {
      setPalette(false);
      ctx.connect(it.host);
    } else if (it.kind === "nav") {
      setPalette(false);
      ctx.go(it.route);
    } else {
      setPalette(false);
      if (it.action === "newhost") ctx.openModal({ kind: "host" });
      else if (it.action === "newkey") ctx.openModal({ kind: "key" });
      else if (it.action === "newtunnel") ctx.openModal({ kind: "tunnel" });
      else if (it.action === "import") ctx.openImport();
      else if (it.action === "groups") ctx.openGroups();
      else if (it.action === "sync") void ctx.reloadVault();
      else if (it.action === "lock") ctx.onLock();
    }
  };

  const onKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSel((s) => Math.min(s + 1, flat.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSel((s) => Math.max(s - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (flat[sel]) run(flat[sel]);
    } else if (e.key === "Escape") {
      e.preventDefault();
      close();
    }
  };

  let idx = -1;
  return (
    <div
      onClick={close}
      style={{
        position: "absolute",
        inset: 0,
        zIndex: 300,
        display: "flex",
        alignItems: "flex-start",
        justifyContent: "center",
        paddingTop: "12vh",
        background: p.name === "dark" ? "rgba(6,7,11,0.55)" : "rgba(40,44,60,0.35)",
        backdropFilter: "blur(3px)",
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: 600,
          maxWidth: "90%",
          maxHeight: "70vh",
          display: "flex",
          flexDirection: "column",
          background: p.bg1,
          border: `1px solid ${p.line2}`,
          borderRadius: 16,
          boxShadow: p.shadow,
          overflow: "hidden",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 11,
            padding: "14px 16px",
            borderBottom: `1px solid ${p.line}`,
          }}
        >
          <Icon name="search" size={18} color={p.txt3} />
          <input
            ref={inputRef}
            {...NO_AUTOCORRECT}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={onKey}
            placeholder={t("command.searchPlaceholder")}
            style={{
              flex: 1,
              background: "none",
              border: "none",
              outline: "none",
              color: p.txt,
              fontSize: 16,
              fontFamily: UI,
            }}
          />
          <span
            style={{
              fontFamily: MONO,
              fontSize: 11,
              padding: "2px 7px",
              borderRadius: 6,
              background: p.bg3,
              border: `1px solid ${p.line}`,
              color: p.txt3,
            }}
          >
            esc
          </span>
        </div>
        <div style={{ flex: 1, overflowY: "auto", padding: 8 }}>
          {flat.length === 0 ? (
            <div style={{ padding: "34px 0", textAlign: "center", color: p.txt3, fontSize: 14 }}>
              {t("command.empty", { q })}
            </div>
          ) : (
            groups.map((g) => (
              <div key={g.title} style={{ marginBottom: 6 }}>
                <div
                  style={{
                    padding: "6px 10px 4px",
                    fontSize: 10.5,
                    fontWeight: 700,
                    letterSpacing: 0.6,
                    color: p.txt3,
                    textTransform: "uppercase",
                  }}
                >
                  {g.title}
                </div>
                {g.items.map((it, i) => {
                  idx++;
                  const active = idx === sel;
                  const myIdx = idx;
                  return (
                    <div
                      key={it.id}
                      onMouseEnter={() => setSel(myIdx)}
                      onClick={() => run(it)}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 11,
                        padding: "9px 10px",
                        cursor: "pointer",
                        borderTop: i === 0 ? undefined : `1px solid ${p.line}`,
                        boxShadow: active ? `inset 2px 0 0 ${p.accent}` : undefined,
                      }}
                    >
                      <span
                        style={{
                          width: 30,
                          height: 30,
                          borderRadius: 8,
                          background: p.bg2,
                          border: `1px solid ${p.line}`,
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          flexShrink: 0,
                        }}
                      >
                        <Icon name={it.icon} size={15} color={p.txt2} />
                      </span>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div
                          style={{
                            fontSize: 14,
                            fontWeight: 600,
                            color: p.txt,
                            whiteSpace: "nowrap",
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                          }}
                        >
                          {it.label}
                        </div>
                        <div
                          style={{
                            fontFamily: it.kind === "host" ? MONO : UI,
                            fontSize: 11.5,
                            color: p.txt3,
                            whiteSpace: "nowrap",
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                          }}
                        >
                          {it.sub}
                        </div>
                      </div>
                      {it.kind === "host" && (
                        <span style={{ fontSize: 11, color: p.txt3 }}>↵ {t("command.terminalHint")}</span>
                      )}
                    </div>
                  );
                })}
              </div>
            ))
          )}
        </div>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 14,
            padding: "9px 14px",
            borderTop: `1px solid ${p.line}`,
            fontSize: 11.5,
            color: p.txt3,
          }}
        >
          <span>
            <b style={{ color: p.txt2 }}>↑↓</b> {t("command.navHint")}
          </span>
          <span>
            <b style={{ color: p.txt2 }}>↵</b> {t("command.selectHint")}
          </span>
          <span>
            <b style={{ color: p.txt2 }}>esc</b> {t("command.closeHint")}
          </span>
        </div>
      </div>
    </div>
  );
}
