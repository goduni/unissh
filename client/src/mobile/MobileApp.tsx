// MobileApp — native mobile shell for UniSSH. Full-viewport (no desktop phone
// bezel), safe-area aware, bottom tab bar + a local push stack with edge-swipe
// back. Pixel-faithful to the prototype mobile-*.jsx, wired to the real store,
// bridge api, and the desktop ViewX named exports.

import React, { useEffect, useMemo, useRef, useState } from "react";
import { usePalette } from "@/theme/ThemeProvider";
import { Icon, NO_AUTOCORRECT, Spinner, StatusDot, Btn, type IconName } from "@/components/primitives";
import { FlatAvatar, MetaChip } from "@/components/mono";
import { BottomSheet } from "@/components/Modal";
import { MONO, UI, AUTH_LABEL_KEY } from "@/theme/tokens";
import { useApp, HOST_FILTER_ALL } from "@/store/app";
import { useKeyboardInset, useLandscape } from "@/store/responsive";
import { useTranslation, tDyn } from "@/i18n";
import { useCtx } from "@/store/ctx";
import { guard } from "@/store/action";
import { profileAuthKind } from "@/bridge/types";
import type { ConnectionProfile, ServerGroup, VaultInfo } from "@/bridge/types";
import * as api from "@/bridge/api";

import { ViewTerminal } from "@/views/ViewTerminal";
import { ReconnectBanner } from "@/components/ReconnectBanner";
import { ViewFleet } from "@/views/ViewFleet";
import { ViewBroadcast } from "@/views/ViewBroadcast";
import { ViewSftp } from "@/views/sftp/ViewSftp";
import { ViewTunnels } from "@/views/ViewTunnels";
import { ViewKnown } from "@/views/ViewKnown";
import { ViewSecrets } from "@/views/ViewSecrets";
import { ViewSettings } from "@/views/ViewSettings";

// ── helpers ────────────────────────────────────────────────────
/** Set of profileIds that have a live (online) terminal — the only honest
 *  notion of a host being "active". */
function useActiveIds(): Set<string> {
  const terminals = useApp((s) => s.terminals);
  return useMemo(
    () =>
      new Set(
        terminals
          .flatMap((t) => t.panes)
          .filter((pp) => pp.status === "online" && pp.profile)
          .map((pp) => pp.profile!.profileId),
      ),
    [terminals],
  );
}

// ── stack frames ───────────────────────────────────────────────
type Frame =
  | { type: "host"; id: string }
  | { type: "broadcast" }
  | { type: "sftp" }
  | { type: "tunnels" }
  | { type: "known" }
  | { type: "secrets" }
  | { type: "settings" };

type TabId = "hosts" | "terminal" | "fleet" | "more";

// ── top bar (vault pill + lock) ────────────────────────────────
function MTopBar({
  vault,
  onLock,
  onVaultTap,
}: {
  vault: VaultInfo | null;
  onLock: () => void;
  onVaultTap: () => void;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const name = vault?.name ?? t("mobile.vault");
  return (
    <div style={{ flexShrink: 0, padding: "4px 16px 12px", display: "flex", alignItems: "center", gap: 10 }}>
      <button
        onClick={onVaultTap}
        style={{
          display: "flex",
          alignItems: "center",
          gap: 9,
          height: 40,
          padding: "0 12px 0 7px",
          borderRadius: 13,
          background: p.bg2,
          border: `1px solid ${p.line2}`,
          cursor: "pointer",
        }}
      >
        <FlatAvatar name={name} size={26} shape="square" />
        <span style={{ fontSize: 15, fontWeight: 700, color: p.txt, lineHeight: 1 }}>{name}</span>
        <Icon name="cd" size={15} color={p.txt3} />
      </button>
      <div style={{ flex: 1 }} />
      <button
        onClick={onLock}
        aria-label={t("shell.lockShort")}
        style={{
          width: 40,
          height: 40,
          borderRadius: 13,
          background: p.bg2,
          border: `1px solid ${p.line2}`,
          color: p.txt2,
          cursor: "pointer",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        <Icon name="lock" size={18} />
      </button>
    </div>
  );
}

// ── host card ──────────────────────────────────────────────────
function MHostCard({
  h,
  active,
  onOpen,
}: {
  h: ConnectionProfile;
  active: boolean;
  onOpen: () => void;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const authKind = profileAuthKind(h.auth);
  const authWarn = authKind === "password" || authKind === "ask";
  const authLabel = tDyn(AUTH_LABEL_KEY[authKind]);
  const jump = h.jumps.length > 0;
  return (
    <button
      onClick={onOpen}
      style={{
        width: "100%",
        textAlign: "left",
        display: "flex",
        alignItems: "center",
        gap: 13,
        padding: 22,
        borderRadius: 18,
        background: p.bg0,
        border: "1px solid transparent",
        boxShadow: p.shadow,
        cursor: "pointer",
      }}
    >
      <div style={{ flex: 1, minWidth: 0 }}>
        {/* L1 — 7px status dot + name (dot keys off a live session; the paired
            word on L3 carries the meaning so colour is never the sole carrier) */}
        <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
          <span
            style={{
              width: 7,
              height: 7,
              borderRadius: "50%",
              flexShrink: 0,
              background: active ? p.green : p.line2,
            }}
          />
          <span
            style={{
              fontSize: 16,
              fontWeight: 700,
              letterSpacing: "-0.2px",
              color: p.txt,
              whiteSpace: "nowrap",
              overflow: "hidden",
              textOverflow: "ellipsis",
              minWidth: 0,
            }}
          >
            {h.label}
          </span>
          {jump && <Icon name="branch" size={13} color={p.txt3} stroke={1.8} />}
        </div>
        {/* L2 — address (mono, txt2) */}
        <div
          style={{
            fontFamily: MONO,
            fontSize: 11.5,
            color: p.txt2,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            marginTop: 6,
          }}
        >
          {h.user}@{h.host}
        </div>
        {/* L3 — status · auth (one mono line; colour only on meaning) */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 7,
            fontFamily: MONO,
            fontSize: 11.5,
            color: p.txt3,
            marginTop: 14,
          }}
        >
          {active && (
            <>
              <span style={{ color: p.green }}>{t("hosts.session")}</span>
              <span style={{ opacity: 0.4 }}>·</span>
            </>
          )}
          <span style={{ color: authWarn ? p.amber : p.txt3 }}>{authLabel}</span>
        </div>
      </div>
      <Icon name="cd" size={17} color={p.txt3} />
    </button>
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
                borderRadius: 14,
                background: on ? p.accentSoft : p.bg2,
                border: `1px solid ${on ? p.accentLine : p.line}`,
                cursor: "pointer",
              }}
            >
              <FlatAvatar name={x.name} size={36} shape="square" />
              <div style={{ flex: 1, textAlign: "left" }}>
                <div style={{ fontSize: 16, fontWeight: 700, color: p.txt }}>{x.name}</div>
                <div style={{ fontSize: 12.5, color: p.txt3 }}>{on ? t("count.hosts", { count: hosts.length }) : t("mobile.vaultLower")}</div>
              </div>
              {on && <Icon name="check" size={20} color={p.accent} />}
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

// ── hosts tab ──────────────────────────────────────────────────
type SortKey = "name" | "connected" | "added";
const SORT_LABEL_KEY: Record<SortKey, string> = {
  name: "mobile.sort.name",
  connected: "mobile.sort.connected",
  added: "mobile.sort.added",
};

// Same key + value set as the desktop list, so the chosen sort carries across the
// desktop⇄mobile preview toggle. Kept in sync with ViewHosts' loadHostSort.
const HOST_SORT_LS = "unissh.hostSort";
const loadHostSort = (): SortKey => {
  try {
    const v = localStorage.getItem(HOST_SORT_LS);
    return v === "name" || v === "connected" || v === "added" ? v : "name";
  } catch {
    return "name";
  }
};

function MHosts({
  vault,
  onOpenHost,
  onVaultTap,
  onNewHost,
}: {
  vault: VaultInfo | null;
  onOpenHost: (id: string) => void;
  onVaultTap: () => void;
  onNewHost: () => void;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const ctx = useCtx();
  const hosts = useApp((s) => s.hosts);
  const groups = useApp((s) => s.groups);
  const hostFilter = useApp((s) => s.hostFilter);
  const setHostFilter = useApp((s) => s.setHostFilter);
  const onLock = useApp((s) => s.lockInstance);
  const loading = useApp((s) => s.loading);
  const reloadVault = useApp((s) => s.reloadVault);
  const activeIds = useActiveIds();
  const landscape = useLandscape();
  const [sort, setSort] = useState<SortKey>(loadHostSort);
  const lastConnected = useApp((s) => s.lastConnected);
  const changeSort = (k: SortKey) => {
    setSort(k);
    try {
      localStorage.setItem(HOST_SORT_LS, k);
    } catch {
      /* ignore */
    }
  };
  const [sortSheet, setSortSheet] = useState(false);
  const [query, setQuery] = useState("");

  // pull-to-refresh on the hosts list
  const scrollRef = useRef<HTMLDivElement>(null);
  const pullStart = useRef<number | null>(null);
  const [pull, setPull] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const onPullStart = (e: React.TouchEvent) => {
    pullStart.current = (scrollRef.current?.scrollTop ?? 0) <= 0 && !refreshing ? e.touches[0].clientY : null;
  };
  const onPullMove = (e: React.TouchEvent) => {
    if (pullStart.current == null) return;
    const dy = e.touches[0].clientY - pullStart.current;
    setPull(dy > 0 ? Math.min(dy * 0.5, 80) : 0);
  };
  const onPullEnd = async () => {
    if (pullStart.current == null) return;
    pullStart.current = null;
    if (pull > 56 && !refreshing) {
      setRefreshing(true);
      setPull(44);
      try {
        await reloadVault();
      } catch {
        /* errors surface via toast in the store */
      }
      setRefreshing(false);
    }
    setPull(0);
  };

  const tags = useMemo(() => Array.from(new Set(hosts.flatMap((h) => h.tags))).slice(0, 6), [hosts]);

  const filtered = useMemo(() => {
    if (hostFilter === HOST_FILTER_ALL) return hosts;
    if (hostFilter === "__untagged") return hosts.filter((x) => x.tags.length === 0);
    const group = groups.find((g) => g.groupId === hostFilter);
    return hosts.filter(
      (x) => x.tags.includes(hostFilter) || (group?.memberIds.includes(x.profileId) ?? false),
    );
  }, [hosts, groups, hostFilter]);

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    let arr = [...filtered];
    if (q)
      arr = arr.filter(
        (h) =>
          h.label.toLowerCase().includes(q) ||
          h.host.toLowerCase().includes(q) ||
          h.user.toLowerCase().includes(q) ||
          h.tags.some((tag) => tag.toLowerCase().includes(q)),
      );
    if (sort === "name") arr.sort((a, b) => a.label.localeCompare(b.label));
    else if (sort === "connected")
      // "Last connected": most-recent first, never-connected last, name tiebreak.
      arr.sort((a, b) => {
        const ta = lastConnected[a.profileId] ?? 0;
        const tb = lastConnected[b.profileId] ?? 0;
        return tb - ta || a.label.localeCompare(b.label);
      });
    else arr.reverse(); // "added": store order, newest last → newest first
    return arr;
  }, [filtered, sort, query, lastConnected]);

  const sessions = useMemo(() => hosts.filter((h) => activeIds.has(h.profileId)).length, [hosts, activeIds]);

  return (
    <>
      <MTopBar vault={vault} onLock={onLock} onVaultTap={onVaultTap} />
      <div style={{ flexShrink: 0, padding: "0 16px 8px", display: "flex", alignItems: "baseline", gap: 9 }}>
        <h1 style={{ margin: 0, fontSize: landscape ? 21 : 24, fontWeight: 800, letterSpacing: -0.6, color: p.txt }}>{t("mobile.tabHosts")}</h1>
        <span style={{ fontFamily: MONO, fontSize: 13, color: p.txt3, whiteSpace: "nowrap" }}>
          {t("count.hosts", { count: hosts.length })}
          {sessions ? ` · ${t("count.sessions", { count: sessions })}` : ""}
        </span>
      </div>

      <div style={{ flexShrink: 0, padding: "0 16px 10px", display: "flex", alignItems: "center", gap: 9 }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            flex: 1,
            minWidth: 0,
            height: 44,
            padding: "0 12px 0 14px",
            borderRadius: 13,
            background: p.bg2,
            border: `1px solid ${p.line}`,
          }}
        >
          <Icon name="search" size={17} color={p.txt3} />
          <input
            {...NO_AUTOCORRECT}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={t("mobile.searchHosts")}
            style={{
              flex: 1,
              minWidth: 0,
              height: "100%",
              border: "none",
              outline: "none",
              background: "transparent",
              color: p.txt,
              fontFamily: UI,
              fontSize: 16,
            }}
          />
          {query && (
            <button
              onClick={() => setQuery("")}
              aria-label={t("common.clear")}
              style={{
                width: 28,
                height: 28,
                flexShrink: 0,
                borderRadius: 8,
                border: "none",
                background: "transparent",
                color: p.txt3,
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <Icon name="x" size={15} />
            </button>
          )}
        </div>
        <button
          onClick={() => setSortSheet(true)}
          aria-label={t("mobile.sortTitle")}
          title={t("mobile.sortTitle")}
          style={{
            flexShrink: 0,
            width: 44,
            height: 44,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            borderRadius: 13,
            border: `1px solid ${p.line}`,
            background: p.bg2,
            color: p.txt2,
            cursor: "pointer",
          }}
        >
          <Icon name="arrows" size={18} color={p.txt3} />
        </button>
      </div>

      {/* filters: groups + tags in one scrollable strip */}
      <div style={{ flexShrink: 0, display: "flex", alignItems: "center", gap: 7, padding: "0 16px 10px", overflowX: "auto" }}>
        <button
          onClick={() => ctx.openGroups()}
          title={t("mobile.groups")}
          aria-label={t("mobile.groups")}
          style={{
            flexShrink: 0,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            width: 44,
            height: 44,
            borderRadius: 12,
            cursor: "pointer",
            border: `1px solid ${p.line}`,
            background: p.bg2,
            color: p.txt3,
          }}
        >
          <Icon name="folders" size={16} />
        </button>
        {groups.map((g: ServerGroup) => {
          const on = hostFilter === g.groupId;
          return (
            <button
              key={g.groupId}
              onClick={() => setHostFilter(g.groupId)}
              style={{
                flexShrink: 0,
                display: "inline-flex",
                alignItems: "center",
                gap: 6,
                minHeight: 44,
                fontFamily: UI,
                fontSize: 13,
                fontWeight: on ? 700 : 600,
                cursor: "pointer",
                padding: "0 4px",
                border: "none",
                borderBottom: `2px solid ${on ? p.accent : "transparent"}`,
                borderRadius: 0,
                background: "transparent",
                color: on ? p.txt : p.txt3,
              }}
            >
              <Icon name="folder" size={13} color={on ? p.txt2 : p.txt3} />
              {g.label}
            </button>
          );
        })}
        {groups.length > 0 && (
          <span style={{ flexShrink: 0, alignSelf: "stretch", width: 1, margin: "5px 3px", background: p.line }} />
        )}
        {[HOST_FILTER_ALL, ...tags].map((tag) => {
          const isAll = tag === HOST_FILTER_ALL;
          const on = hostFilter === tag;
          return (
            <button
              key={tag}
              onClick={() => setHostFilter(tag)}
              style={{
                flexShrink: 0,
                display: "inline-flex",
                alignItems: "center",
                minHeight: 44,
                fontFamily: isAll ? UI : MONO,
                fontSize: 13,
                fontWeight: on ? 700 : 600,
                cursor: "pointer",
                padding: "0 4px",
                border: "none",
                borderBottom: `2px solid ${on ? p.accent : "transparent"}`,
                borderRadius: 0,
                background: "transparent",
                color: on ? p.txt : p.txt3,
              }}
            >
              {isAll ? t("common.all") : "#" + tag}
            </button>
          );
        })}
        {hosts.some((x) => x.tags.length === 0) && (
          <button
            onClick={() => setHostFilter("__untagged")}
            style={{
              flexShrink: 0,
              display: "inline-flex",
              alignItems: "center",
              minHeight: 44,
              fontFamily: UI,
              fontSize: 13,
              fontWeight: hostFilter === "__untagged" ? 700 : 600,
              cursor: "pointer",
              padding: "0 4px",
              border: "none",
              borderBottom: `2px solid ${hostFilter === "__untagged" ? p.accent : "transparent"}`,
              borderRadius: 0,
              background: "transparent",
              color: hostFilter === "__untagged" ? p.txt : p.txt3,
            }}
          >
            {t("mobile.untagged")}
          </button>
        )}
      </div>

      <div style={{ flex: 1, position: "relative", minHeight: 0, display: "flex", flexDirection: "column" }}>
        {/* pull-to-refresh spinner, revealed as the list is dragged down from the top */}
        <div
          style={{
            position: "absolute",
            top: 4,
            left: 0,
            right: 0,
            display: "flex",
            justifyContent: "center",
            pointerEvents: "none",
            zIndex: 1,
            opacity: pull > 8 || refreshing ? 1 : 0,
            transform: `translateY(${Math.max(0, pull - 26)}px)`,
            transition: pullStart.current == null ? "opacity .2s" : "none",
          }}
        >
          <Spinner size={20} />
        </div>
        <div
          ref={scrollRef}
          onTouchStart={onPullStart}
          onTouchMove={onPullMove}
          onTouchEnd={onPullEnd}
          style={{
            flex: 1,
            overflowY: "auto",
            overscrollBehavior: "contain",
            WebkitOverflowScrolling: "touch",
            padding: "0 16px 16px",
            display: "flex",
            flexDirection: "column",
            gap: 10,
            transform: pull ? `translateY(${pull}px)` : "none",
            transition: pullStart.current == null ? "transform .2s" : "none",
          }}
        >
          {shown.map((h) => (
            <MHostCard key={h.profileId} h={h} active={activeIds.has(h.profileId)} onOpen={() => onOpenHost(h.profileId)} />
          ))}
          {shown.length === 0 &&
            (loading && hosts.length === 0 ? (
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 12, padding: "48px 0", color: p.txt3 }}>
                <Spinner size={22} />
              </div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 10, padding: "48px 0", color: p.txt3 }}>
                <Icon name="server" size={34} color={p.txt3} />
                <div style={{ fontSize: 14 }}>
                  {hosts.length === 0 ? t("mobile.noHostsYet") : t("mobile.nothingFound")}
                </div>
              </div>
            ))}
          {/* clearance so the floating "+" never covers the last card */}
          <div style={{ height: 76 }} />
        </div>
      </div>

      <button
        onClick={onNewHost}
        aria-label={t("hosts.newHost")}
        style={{
          position: "absolute",
          right: 18,
          bottom: 20,
          width: 56,
          height: 56,
          borderRadius: 12,
          background: p.accent,
          border: "none",
          color: p.accentInk ?? "#fff",
          cursor: "pointer",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          boxShadow: "0 8px 22px -12px rgba(0,0,0,0.6)",
          zIndex: 5,
        }}
      >
        <Icon name="plus" size={26} stroke={2.2} />
      </button>

      {sortSheet && (
        <BottomSheet position="absolute" zIndex={40} onClose={() => setSortSheet(false)}>
          <div style={{ fontSize: 13, fontWeight: 700, color: p.txt3, textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 12 }}>
            {t("mobile.sortTitle")}
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {(Object.keys(SORT_LABEL_KEY) as SortKey[]).map((k) => {
              const on = sort === k;
              return (
                <button
                  key={k}
                  onClick={() => {
                    changeSort(k);
                    setSortSheet(false);
                  }}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 12,
                    padding: 14,
                    borderRadius: 14,
                    background: on ? p.accentSoft : p.bg2,
                    border: `1px solid ${on ? p.accentLine : p.line}`,
                    cursor: "pointer",
                  }}
                >
                  <Icon name={k === "name" ? "list" : k === "connected" ? "clock" : "plus"} size={18} color={on ? p.accent : p.txt3} />
                  <span style={{ flex: 1, textAlign: "left", fontSize: 15, fontWeight: 600, color: on ? p.accent : p.txt }}>
                    {tDyn(SORT_LABEL_KEY[k])}
                  </span>
                  {on && <Icon name="check" size={20} color={p.accent} />}
                </button>
              );
            })}
          </div>
        </BottomSheet>
      )}
    </>
  );
}

// ── host detail (push) ─────────────────────────────────────────
function MHostDetail({
  profile,
  active,
  onBack,
  onConnect,
  onSftp,
}: {
  profile: ConnectionProfile;
  active: boolean;
  onBack: () => void;
  onConnect: () => void;
  onSftp: () => void;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const ctx = useCtx();
  const authKind = profileAuthKind(profile.auth);
  const jump = profile.jumps[0];
  // Real known-host state for this host — quiet "Key verified" + short fingerprint
  // when a key is pinned, honest "not yet connected (TOFU)" otherwise. No fabrication.
  const knownHosts = useApp((s) => s.knownHosts);
  const known = knownHosts.find((k) => k.host === profile.host && k.port === profile.port);
  const knownFp = useMemo(() => {
    if (!known) return "";
    const parts = known.key.trim().split(/\s+/);
    const algo = parts[0] ?? "";
    const blob = parts.slice(1).join("");
    return blob ? `${algo} …${blob.slice(-16)}` : algo;
  }, [known]);

  const Row = ({ label, mono, children }: { label: string; mono?: boolean; children: React.ReactNode }) => (
    <div style={{ display: "flex", alignItems: "baseline", gap: 10, padding: "13px 0", borderBottom: `1px solid ${p.line}` }}>
      <span style={{ width: 96, fontSize: 13.5, color: p.txt3, flexShrink: 0 }}>{label}</span>
      <span
        style={{
          flex: 1,
          fontSize: 14,
          color: p.txt,
          fontFamily: mono ? MONO : UI,
          textAlign: "right",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
      >
        {children}
      </span>
    </div>
  );

  const authLabel = authKind === "key" ? t("mobile.authKey") : authKind === "password" ? t("mobile.authPassword") : t("mobile.authPrompt");

  return (
    <>
      <div style={{ flexShrink: 0, padding: "4px 12px 8px", display: "flex", alignItems: "center", gap: 4 }}>
        <button
          onClick={onBack}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 2,
            padding: "8px 8px 8px 4px",
            background: "none",
            border: "none",
            color: p.accent,
            cursor: "pointer",
            fontSize: 16,
            fontWeight: 500,
          }}
        >
          <Icon name="cl" size={22} />
          {t("mobile.tabHosts")}
        </button>
        <div style={{ flex: 1 }} />
        <button
          onClick={() => ctx.openModal({ kind: "host", edit: profile })}
          aria-label={t("common.edit")}
          style={{
            width: 40,
            height: 40,
            borderRadius: 12,
            background: p.bg2,
            border: `1px solid ${p.line2}`,
            color: p.txt2,
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <Icon name="pencil" size={18} />
        </button>
      </div>
      <div
        style={{
          flex: 1,
          overflowY: "auto",
          overscrollBehavior: "contain",
          WebkitOverflowScrolling: "touch",
          padding: "0 16px 16px",
        }}
      >
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", textAlign: "center", padding: "8px 0 20px" }}>
          <span
            style={{
              width: 72,
              height: 72,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              position: "relative",
              marginBottom: 12,
            }}
          >
            <Icon name="server" size={32} color={p.txt2} stroke={1.6} />
            {active && (
              <span
                style={{
                  position: "absolute",
                  bottom: 0,
                  right: 0,
                  background: p.bg0,
                  borderRadius: "50%",
                  padding: 3,
                  display: "flex",
                }}
              >
                <StatusDot status="online" size={12} srLabel={t("mobile.sessionNow")} />
              </span>
            )}
          </span>
          <div style={{ fontSize: 24, fontWeight: 800, letterSpacing: -0.5, color: p.txt, textAlign: "center", wordBreak: "break-word" }}>{profile.label}</div>
          <div style={{ fontFamily: MONO, fontSize: 13, color: active ? p.green : p.txt3, marginTop: 2, textAlign: "center", wordBreak: "break-all" }}>
            {active ? t("mobile.sessionActive") : `${profile.user}@${profile.host}`}
          </div>
        </div>

        <div style={{ display: "flex", gap: 10, marginBottom: 20 }}>
          <button
            onClick={onConnect}
            style={{
              flex: 1,
              height: 50,
              borderRadius: 12,
              background: p.accent,
              border: "none",
              color: p.accentInk ?? "#fff",
              cursor: "pointer",
              fontSize: 16,
              fontWeight: 700,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              gap: 8,
            }}
          >
            <Icon name="terminal" size={19} />
            {active ? t("mobile.openSession") : t("nav.terminal")}
          </button>
          <button
            onClick={onSftp}
            aria-label={t("nav.sftp")}
            style={{
              width: 50,
              height: 50,
              borderRadius: 12,
              background: p.bg2,
              border: `1px solid ${p.line2}`,
              color: p.txt2,
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <Icon name="folders" size={20} />
          </button>
        </div>

        <div>
          <Row label={t("mobile.detail.host")} mono>
            {profile.host}
          </Row>
          <Row label={t("mobile.detail.port")} mono>
            {profile.port}
          </Row>
          <Row label={t("mobile.detail.user")} mono>
            {profile.user}
          </Row>
          <Row label={t("mobile.detail.auth")}>
            <span style={{ color: authKind === "password" || authKind === "ask" ? p.amber : p.txt }}>{authLabel}</span>
          </Row>
          {jump && (
            <Row label={t("mobile.detail.proxyJump")} mono>
              {jump.user}@{jump.host}
            </Row>
          )}
          {profile.tags.length > 0 && (
            <Row label={t("mobile.detail.tags")} mono>
              {profile.tags.map((t) => `#${t}`).join(" ")}
            </Row>
          )}
        </div>

        <div style={{ padding: "13px 0" }}>
          {known ? (
            <div style={{ display: "flex", alignItems: "center", gap: 9, minWidth: 0 }}>
              <MetaChip icon="shieldcheck" tone="good">
                {t("mobile.keyVerified")}
              </MetaChip>
              <span
                style={{
                  flex: 1,
                  minWidth: 0,
                  fontFamily: MONO,
                  fontSize: 12,
                  color: p.txt3,
                  textAlign: "right",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
              >
                {knownFp}
              </span>
            </div>
          ) : (
            <MetaChip icon="shield" tone="neutral">
              {t("mobile.notConnectedTofu")}
            </MetaChip>
          )}
        </div>
      </div>
    </>
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
        <div style={{ fontSize: 15 }}>{t("terminal.noSessions")}</div>
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
            fontSize: 15,
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
              <button
                key={trm.id}
                onClick={() => setActiveTerm(trm.id)}
                style={{
                  flexShrink: 0,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 7,
                  padding: "6px 10px",
                  minHeight: 36,
                  border: "none",
                  borderBottom: `2px solid ${on ? p.txt2 : "transparent"}`,
                  borderRadius: 0,
                  background: "transparent",
                  color: on ? p.txt : p.txt3,
                  cursor: "pointer",
                  fontSize: 12.5,
                  fontFamily: MONO,
                }}
              >
                <span style={{ width: 7, height: 7, borderRadius: "50%", background: tp?.status === "online" ? p.green : tp?.status === "error" ? p.red : p.txt3 }} />
                <span style={{ maxWidth: 120, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{trm.title}</span>
                <span
                  onClick={(e) => {
                    e.stopPropagation();
                    closeTerminal(trm.id); // closes every pane's backend session
                  }}
                  style={{ display: "inline-flex", opacity: 0.6, padding: 2 }}
                >
                  <Icon name="x" size={12} />
                </span>
              </button>
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
              borderRadius: 9,
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
  type: Exclude<Frame["type"], "host">;
  icon: IconName;
  labelKey: string;
  descKey: string;
}[] = [
  { type: "broadcast", icon: "radio", labelKey: "nav.broadcast", descKey: "mobile.more.broadcastDesc" },
  { type: "sftp", icon: "folders", labelKey: "nav.sftp", descKey: "mobile.more.sftpDesc" },
  { type: "tunnels", icon: "branch", labelKey: "nav.tunnels", descKey: "mobile.more.tunnelsDesc" },
  { type: "known", icon: "shieldcheck", labelKey: "nav.known", descKey: "mobile.more.knownDesc" },
  { type: "secrets", icon: "key", labelKey: "mobile.more.secrets", descKey: "mobile.more.secretsDesc" },
  { type: "settings", icon: "sliders", labelKey: "nav.settings", descKey: "mobile.more.settingsDesc" },
];

function MMore({ go }: { go: (t: Exclude<Frame["type"], "host">) => void }) {
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
          style={{
            display: "flex",
            alignItems: "center",
            gap: 2,
            padding: "8px 8px 8px 4px",
            background: "none",
            border: "none",
            color: p.accent,
            cursor: "pointer",
            fontSize: 16,
          }}
        >
          <Icon name="cl" size={22} />
          {t("nav.more")}
        </button>
        <div style={{ flex: 1, textAlign: "center", fontSize: 15, fontWeight: 700, color: p.txt, marginRight: 44 }}>{label}</div>
      </div>
      <div style={{ flex: 1, minHeight: 0, display: "flex" }}>{children}</div>
    </>
  );
}

// ── tab bar ────────────────────────────────────────────────────
function MTabBar({ tab, setTab }: { tab: TabId; setTab: (t: TabId) => void }) {
  const p = usePalette();
  const { t } = useTranslation();
  const tabs: { id: TabId; icon: IconName; label: string }[] = [
    { id: "hosts", icon: "server", label: t("mobile.tabHosts") },
    { id: "terminal", icon: "terminal", label: t("nav.terminal") },
    { id: "fleet", icon: "layers", label: t("nav.fleet") },
    { id: "more", icon: "grid", label: t("nav.more") },
  ];
  return (
    <div
      style={{
        flexShrink: 0,
        display: "flex",
        padding: "8px 8px calc(8px + env(safe-area-inset-bottom))",
        borderTop: `1px solid ${p.line}`,
        background: p.bg1,
      }}
    >
      {tabs.map((t) => {
        const active = tab === t.id;
        return (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            style={{
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
              color: active ? p.accent : p.txt3,
            }}
          >
            <Icon name={t.icon} size={23} stroke={active ? 2 : 1.7} />
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
              {t.label}
            </span>
          </button>
        );
      })}
    </div>
  );
}

// ── root ───────────────────────────────────────────────────────
export function MobileApp() {
  const p = usePalette();
  const { t } = useTranslation();
  const ctx = useCtx();
  const hosts = useApp((s) => s.hosts);
  const vaultId = useApp((s) => s.vaultId);
  const vaults = useApp((s) => s.vaults);
  const activeIds = useActiveIds();

  const [tab, setTab] = useState<TabId>("hosts");
  const [stack, setStack] = useState<Frame[]>([]);
  const [vaultSheet, setVaultSheet] = useState(false);
  const [sw, setSw] = useState<{ x: number; dx: number } | null>(null);
  const kbInset = useKeyboardInset();

  const vault = vaults.find((v) => v.vaultId === vaultId) ?? vaults[0] ?? null;
  const top = stack[stack.length - 1];
  const push = (f: Frame) => setStack((s) => [...s, f]);
  const pop = () => setStack((s) => s.slice(0, -1));

  const switchTab = (t: TabId) => {
    setStack([]);
    setTab(t);
  };

  // touch state must reset when leaving a frame
  useEffect(() => {
    if (!top) setSw(null);
  }, [top]);

  // pop a host-detail frame whose profile no longer exists (deleted via the edit
  // modal), so the user isn't stranded on a blank screen.
  useEffect(() => {
    if (top?.type === "host" && !hosts.some((h) => h.profileId === top.id)) {
      setStack((s) => s.slice(0, -1));
    }
  }, [top, hosts]);

  // Desktop views navigate via store.route; this shell keeps its own stack.
  // Honour the one cross-shell security navigation — the host-key mismatch
  // "review" affordances call reviewMismatch()/go("known") — by pushing the same
  // screen here, so the Verify & accept ceremony is reachable from mobile too.
  // Subscribe to routeSeq (bumped on every navigation, even a repeat go("known"))
  // rather than route, whose same-value set fires no update and would drop a
  // second review request. The dedupe-if-already-on-top guard still stands.
  const routeSeq = useApp((s) => s.routeSeq);
  useEffect(() => {
    if (useApp.getState().route === "known")
      setStack((s) => (s[s.length - 1]?.type === "known" ? s : [...s, { type: "known" }]));
  }, [routeSeq]);

  const connectHost = (profile: ConnectionProfile) => {
    ctx.connect(profile); // opens a terminal tab + switches store.route to terminal
    setStack([]);
    setTab("terminal");
  };

  // tabs hide the tab bar only when in a secondary (non-host) frame
  const tabBarVisible = !top || top.type === "host";
  // the terminal tab is rendered persistently (below), so it's "shown" only when
  // it's the active tab and no secondary frame is pushed on top of it
  const showTerminal = !top && tab === "terminal";
  // ViewSftp is likewise rendered persistently (below): mounted while the sftp
  // frame is on top, only hidden (not unmounted) otherwise, so its panes / cwd /
  // selection survive leaving and returning — same reasoning as the terminal.
  const showSftp = !!top && top.type === "sftp";

  let screen: React.ReactNode = null;
  if (top) {
    switch (top.type) {
      case "host": {
        const profile = hosts.find((h) => h.profileId === top.id);
        screen = profile ? (
          <MHostDetail
            profile={profile}
            active={activeIds.has(profile.profileId)}
            onBack={pop}
            onConnect={() => connectHost(profile)}
            onSftp={() => push({ type: "sftp" })}
          />
        ) : null;
        break;
      }
      case "broadcast":
        screen = (
          <MWrapView label={t("nav.broadcast")} onBack={pop}>
            <ViewBroadcast />
          </MWrapView>
        );
        break;
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
        screen = (
          <MHosts
            vault={vault}
            onOpenHost={(id) => push({ type: "host", id })}
            onVaultTap={() => setVaultSheet(true)}
            onNewHost={() => ctx.onNewHost()}
          />
        );
        break;
      // "terminal" is intentionally absent here — it's rendered persistently
      // below (display-toggled) so the live SSH session + scrollback survive a
      // tab switch, exactly like the always-mounted desktop ViewTerminal.
      case "fleet":
        screen = (
          <div style={{ flex: 1, minHeight: 0, display: "flex" }}>
            <ViewFleet />
          </div>
        );
        break;
      case "more":
        screen = <MMore go={(t) => push({ type: t })} />;
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
        paddingBottom: kbInset, // lift content above the software keyboard
        overflow: "hidden",
      }}
    >
      <div
        onTouchStart={(e) => {
          if (top && e.touches[0].clientX < 28) setSw({ x: e.touches[0].clientX, dx: 0 });
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
        {top && <div style={{ position: "absolute", left: 0, top: 0, bottom: 0, width: 20, zIndex: 50 }} />}
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
