// ViewHosts — the centerpiece: toolbar, tag-filter chips, cards/list grid,
// multi-select Fleet bar, and the right rail toggling Host detail ⇄ live Sessions.
// Ported pixel-for-pixel from the prototype (view-hosts*.jsx) but wired to the
// real store: hosts = ConnectionProfile[], liveness only from open terminal tabs,
// no fake ping/cipher/agent-fwd.

import React, { useEffect, useMemo, useRef, useState } from "react";
import { usePalette, useTheme } from "@/theme/ThemeProvider";
import { MONO, UI, AUTH_LABEL_KEY } from "@/theme/tokens";
import { BTN_RESET, Icon, IconBtn, Btn, Checkbox, Tag, AuthBadge, ResizeHandle, StatusDot } from "@/components/primitives";
import { Card, MetaChip, UnderlineTabs, fmtRelative } from "@/components/mono";
import { pressActivate, useMenu } from "@/components/a11y";
import { useApp, HOST_FILTER_ALL } from "@/store/app";
import { useCtx } from "@/store/ctx";
import * as api from "@/bridge/api";
import { profileAuthKind, apiErrorMessage } from "@/bridge/types";
import type { ConnectionProfile } from "@/bridge/types";
import { useTranslation, tDyn } from "@/i18n";

type SortKey = "name" | "added" | "connected";
type RailTab = "detail" | "sessions";

// Sort-key → i18n sub-key under hosts.sort.* (label rendered via t at call sites).
const SORT_KEYS: Record<SortKey, string> = {
  name: "name",
  connected: "connected",
  added: "recent",
};

// The chosen sort is remembered across sessions (localStorage), restored on load.
const HOST_SORT_LS = "unissh.hostSort";
const loadHostSort = (): SortKey => {
  try {
    const v = localStorage.getItem(HOST_SORT_LS);
    return v === "name" || v === "added" || v === "connected" ? v : "name";
  } catch {
    return "name";
  }
};

// ── HostCard (density: cards) ──────────────────────────────────
function HostCard({
  h,
  selected,
  active,
  session,
  onToggle,
  onOpen,
  onConnect,
  onSftp,
}: {
  h: ConnectionProfile;
  selected: boolean;
  active: boolean;
  session: boolean;
  onToggle: () => void;
  onOpen: () => void;
  onConnect: () => void;
  onSftp: () => void;
}) {
  const p = usePalette();
  const { t, i18n } = useTranslation();
  const [hover, setHover] = useState(false);
  // Hover-only affordances (checkbox, Connect) also appear while the card or
  // anything inside it holds keyboard focus, so they stay reachable by Tab.
  const [focusIn, setFocusIn] = useState(false);
  const show = hover || focusIn;
  const lc = useApp((s) => s.lastConnected[h.profileId]);
  const authKind = profileAuthKind(h.auth);
  const authWarn = authKind === "password" || authKind === "ask";
  const authLabel = tDyn(AUTH_LABEL_KEY[authKind]);
  return (
    <Card
      active={active || selected}
      onClick={onOpen}
      onDoubleClick={onConnect}
      // not a <button>: the card nests interactive controls (checkbox, Connect)
      role="button"
      tabIndex={0}
      onKeyDown={pressActivate(onOpen)}
      onFocus={() => setFocusIn(true)}
      onBlur={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget as Node)) setFocusIn(false);
      }}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{ position: "relative", cursor: "pointer" }}
    >
      <Checkbox
        checked={selected}
        onChange={onToggle}
        size={20}
        title={t("hosts.selectHostLabel", { label: h.label })}
        aria-label={t("hosts.selectHostLabel", { label: h.label })}
        style={{
          position: "absolute",
          top: 12,
          right: 12,
          display: show || selected ? "inline-flex" : "none",
          zIndex: 2,
        }}
      />

      {/* L1 — 7px status dot + name (reference: dot keys off a live session) */}
      <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
        <span
          style={{
            width: 7,
            height: 7,
            borderRadius: "50%",
            flexShrink: 0,
            background: session ? p.green : p.line2,
          }}
        />
        <span
          style={{
            fontSize: 16,
            fontWeight: 700,
            letterSpacing: "-0.2px",
            whiteSpace: "nowrap",
            overflow: "hidden",
            textOverflow: "ellipsis",
            minWidth: 0,
          }}
        >
          {h.label}
        </span>
        {h.jumps.length > 0 && <Icon name="branch" size={12} color={p.txt3} stroke={1.8} />}
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
        {h.user ? `${h.user}@${h.host}` : h.host}
      </div>

      {/* L3 — status · auth (one mono line; colour only on meaning). Fades on hover
          so the hover Connect button never sits over the text. */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 7,
          fontFamily: MONO,
          fontSize: 11.5,
          color: p.txt3,
          marginTop: 16,
          opacity: show ? 0 : 1,
          transition: "opacity .12s ease",
        }}
      >
        {session ? (
          <>
            <span style={{ color: p.green }}>{t("hosts.session")}</span>
            <span style={{ opacity: 0.4 }}>·</span>
          </>
        ) : lc ? (
          <>
            <span>{fmtRelative(lc, i18n.language)}</span>
            <span style={{ opacity: 0.4 }}>·</span>
          </>
        ) : null}
        <span style={{ color: authWarn ? p.amber : p.txt3 }}>{authLabel}</span>
      </div>

      {show && (
        <div
          style={{ position: "absolute", right: 12, bottom: 11, zIndex: 3, display: "flex", gap: 6 }}
        >
          <Btn
            size="sm"
            variant="ghost"
            icon="folders"
            title={t("hosts.openSftp")}
            onClick={(e) => {
              e.stopPropagation();
              onSftp();
            }}
          />
          <Btn
            size="sm"
            variant="outline"
            icon="terminal"
            style={{ border: `1px solid ${p.accent}`, color: p.accent, fontWeight: 700 }}
            onClick={(e) => {
              e.stopPropagation();
              onConnect();
            }}
          >
            {t("hosts.connect")}
          </Btn>
        </div>
      )}
    </Card>
  );
}

// ── HostRow (density: list) ────────────────────────────────────
function HostRow({
  h,
  selected,
  active,
  session,
  first,
  onToggle,
  onOpen,
  onConnect,
}: {
  h: ConnectionProfile;
  selected: boolean;
  active: boolean;
  session: boolean;
  first?: boolean;
  onToggle: () => void;
  onOpen: () => void;
  onConnect: () => void;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const compact = useTheme().density === "compact";
  const [hover, setHover] = useState(false);
  // Same focus-follows-hover trick as HostCard so the row's affordances are Tabbable.
  const [focusIn, setFocusIn] = useState(false);
  const show = hover || focusIn;
  return (
    <div
      role="button"
      tabIndex={0}
      onKeyDown={pressActivate(onOpen)}
      onFocus={() => setFocusIn(true)}
      onBlur={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget as Node)) setFocusIn(false);
      }}
      onClick={onOpen}
      onDoubleClick={onConnect}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        display: "flex",
        alignItems: "center",
        gap: 12,
        padding: "0 4px",
        // Density is the spacing axis: compact packs the rows tighter.
        height: compact ? 38 : 46,
        cursor: "pointer",
        // Hairline row: no per-row box/radius/side-stripe. Selection = faint neutral
        // fill; rows share one 1px line between them (all but the first).
        borderTop: first ? "none" : `1px solid ${p.line}`,
        background: active || selected ? p.bg2 : hover ? p.bg2 : "transparent",
      }}
    >
      <Checkbox
        checked={selected}
        onChange={onToggle}
        size={18}
        title={t("hosts.selectHostLabel", { label: h.label })}
        aria-label={t("hosts.selectHostLabel", { label: h.label })}
        style={{ opacity: show || selected ? 1 : 0.25 }}
      />
      <StatusDot
        status={session ? "online" : "unknown"}
        size={8}
        srLabel={session ? t("hosts.session") : undefined}
      />
      <span
        style={{
          width: 150,
          fontWeight: 600,
          fontSize: 13.5,
          whiteSpace: "nowrap",
          overflow: "hidden",
          textOverflow: "ellipsis",
          flexShrink: 0,
        }}
      >
        {h.label}
      </span>
      <span
        style={{
          fontFamily: MONO,
          fontSize: 11.5,
          color: p.txt3,
          flex: 1,
          minWidth: 0,
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
      >
        {h.user}@{h.host}
      </span>
      <div style={{ display: "flex", gap: 5, width: 130, flexShrink: 0, overflow: "hidden", alignItems: "center" }}>
        {h.tags.slice(0, 2).map((tg) => (
          <Tag key={tg}>{tg}</Tag>
        ))}
        {h.tags.length > 2 && <MetaChip>{`+${h.tags.length - 2}`}</MetaChip>}
      </div>
      <span
        style={{
          fontFamily: MONO,
          fontSize: 11.5,
          color: p.txt3,
          width: 74,
          textAlign: "right",
          flexShrink: 0,
        }}
      >
        {session ? <span style={{ color: p.green }}>{t("hosts.session")}</span> : "—"}
      </span>
      <span style={{ flexShrink: 0, display: "inline-flex" }}>
        <AuthBadge auth={profileAuthKind(h.auth)} jump={h.jumps.length > 0} />
      </span>
      <div style={{ width: 84, flexShrink: 0, display: "flex", justifyContent: "flex-end" }}>
        {show ? (
          <Btn
            size="sm"
            variant="outline"
            icon="terminal"
            style={{ border: `1px solid ${p.accent}`, color: p.accent, fontWeight: 700 }}
            onClick={(e) => {
              e.stopPropagation();
              onConnect();
            }}
          >
            {t("hosts.connect")}
          </Btn>
        ) : null}
      </div>
    </div>
  );
}

// ── Rail: detail row ───────────────────────────────────────────
function DetailRow({
  label,
  children,
  mono,
}: {
  label: string;
  children: React.ReactNode;
  mono?: boolean;
}) {
  const p = usePalette();
  return (
    <div
      style={{
        display: "flex",
        alignItems: "baseline",
        gap: 10,
        padding: "7px 0",
        borderBottom: `1px solid ${p.line}`,
      }}
    >
      <span
        style={{
          minWidth: 72,
          fontSize: 12,
          color: p.txt3,
          flexShrink: 0,
          whiteSpace: "nowrap",
        }}
      >
        {label}
      </span>
      <span
        style={{
          flex: 1,
          minWidth: 0,
          fontSize: 13,
          color: p.txt,
          fontFamily: mono ? MONO : UI,
          whiteSpace: "nowrap",
          overflow: "hidden",
          textOverflow: "ellipsis",
        }}
      >
        {children}
      </span>
    </div>
  );
}

// ── Rail: host detail ──────────────────────────────────────────
function HostDetail({ h, session }: { h: ConnectionProfile; session: boolean }) {
  const p = usePalette();
  const { t, i18n } = useTranslation();
  const ctx = useCtx();
  const vault = useApp((s) => s.vaultId);
  const knownHosts = useApp((s) => s.knownHosts);
  const lastConnected = useApp((s) => s.lastConnected);
  const groups = useApp((s) => s.groups);
  const authKind = profileAuthKind(h.auth);
  const known = knownHosts.find((k) => k.host === h.host && k.port === h.port);
  const firstJump = h.jumps[0];
  const lc = lastConnected[h.profileId];
  const memberOf = groups.filter((g) => g.memberIds.includes(h.profileId));

  const onDelete = () => {
    if (!vault) return;
    ctx.confirm({
      title: t("hosts.deleteTitle"),
      body: t("hosts.deleteBody", { label: h.label }),
      danger: true,
      confirmLabel: t("common.delete"),
      icon: "trash",
      onConfirm: async () => {
        try {
          await api.deleteConnection(vault, h.profileId);
          await useApp.getState().reloadVault();
          ctx.toast(t("modals.host.deleted"), "ok");
        } catch (e) {
          ctx.toast(apiErrorMessage(e), "err");
        }
      },
    });
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 9, marginBottom: 3 }}>
        <span
          style={{
            width: 10,
            height: 10,
            borderRadius: "50%",
            flexShrink: 0,
            background: session ? p.green : p.line2,
          }}
        />
        <h3
          style={{
            margin: 0,
            fontSize: 19,
            fontWeight: 700,
            whiteSpace: "nowrap",
            flexShrink: 0,
            maxWidth: 170,
            overflow: "hidden",
            textOverflow: "ellipsis",
          }}
        >
          {h.label}
        </h3>
        {h.jumps.length > 0 && (
          <span
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 3,
              fontSize: 11,
              color: p.txt3,
              flexShrink: 0,
            }}
          >
            <Icon name="branch" size={12} color={p.txt3} />
            {t("hosts.jump")}
          </span>
        )}
        <div style={{ flex: 1, minWidth: 8 }} />
        {h.auth.type === "personal" && vault && (
          <IconBtn
            icon="fingerprint"
            size={28}
            title={t("hosts.linkIdentity")}
            onClick={() => ctx.openModal({ kind: "bindHost", host: h, vaultId: vault })}
          />
        )}
        <IconBtn
          icon="pencil"
          size={28}
          title={t("common.edit")}
          onClick={() => ctx.openModal({ kind: "host", edit: h })}
        />
        <IconBtn
          icon="trash"
          size={28}
          color={p.red}
          title={t("common.delete")}
          onClick={onDelete}
        />
      </div>
      <div
        style={{
          fontFamily: MONO,
          fontSize: 11.5,
          color: session ? p.green : p.txt3,
          marginBottom: 14,
        }}
      >
        {session ? t("hosts.sessionActive") : t("hosts.noActiveSession")}
      </div>

      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        <Btn
          variant="outline"
          icon="terminal"
          style={{ flex: 1, border: `1px solid ${p.accent}`, color: p.accent, fontWeight: 700 }}
          onClick={() => ctx.connect(h)}
        >
          {t("hosts.connect")}
        </Btn>
        <Btn
          variant="ghost"
          icon="bolt"
          title={t("nav.fleetExec")}
          style={{ padding: "8px 11px" }}
          onClick={() => ctx.go("fleet")}
        />
        {/* Quick SFTP: connect + jump straight to the SFTP view for this host. */}
        <Btn
          variant="ghost"
          icon="folders"
          title={t("hosts.openSftp")}
          style={{ padding: "8px 11px" }}
          onClick={() => void ctx.connectSftp(h)}
        />
      </div>

      <DetailRow label={t("hosts.detail.address")} mono>
        {h.host}:{h.port}
      </DetailRow>
      <DetailRow label={t("hosts.detail.user")} mono>
        {h.auth.type === "personal" ? t("hosts.detail.userPersonal") : h.user}
      </DetailRow>
      <DetailRow label={t("hosts.detail.auth")}>
        <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
          <AuthBadge auth={authKind} />
          {tDyn(AUTH_LABEL_KEY[authKind])}
        </span>
      </DetailRow>
      {firstJump && (
        <DetailRow label="ProxyJump" mono>
          {firstJump.user}@{firstJump.host}:{firstJump.port}
        </DetailRow>
      )}
      {lc != null && lc > 0 && (
        <DetailRow label={t("hosts.detail.lastConnected")}>{fmtRelative(lc, i18n.language)}</DetailRow>
      )}

      {memberOf.length > 0 && (
        <>
          <div
            style={{
              fontSize: 10.5,
              fontWeight: 700,
              letterSpacing: 0.6,
              color: p.txt3,
              textTransform: "uppercase",
              margin: "14px 0 7px",
            }}
          >
            {t("hosts.detail.groups")}
          </div>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
            {memberOf.map((g) => (
              <Tag key={g.groupId}>{g.label}</Tag>
            ))}
          </div>
        </>
      )}
      <div
        style={{
          fontSize: 10.5,
          fontWeight: 700,
          letterSpacing: 0.6,
          color: p.txt3,
          textTransform: "uppercase",
          margin: "14px 0 7px",
        }}
      >
        {t("hosts.tags")}
      </div>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
        {h.tags.length === 0 && (
          <span style={{ fontSize: 12, color: p.txt3 }}>{t("hosts.noTags")}</span>
        )}
        {h.tags.map((tg) => (
          <Tag key={tg} mono>
            #{tg}
          </Tag>
        ))}
      </div>

      <div style={{ flex: 1 }} />
      <div
        role="button"
        tabIndex={0}
        onKeyDown={pressActivate(() => ctx.go("known"))}
        onClick={() => ctx.go("known")}
        style={{
          padding: "12px 0 2px",
          borderTop: `1px solid ${p.line}`,
          background: "transparent",
          cursor: "pointer",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 6,
            fontSize: 11,
            color: p.txt3,
            marginBottom: 5,
          }}
        >
          <Icon name="shieldcheck" size={13} color={known ? p.green : p.txt3} />
          {known ? t("hosts.hostKeyPinned") : t("hosts.hostKeyUnpinned")}
        </div>
        <div style={{ fontFamily: MONO, fontSize: 11, color: p.txt2, wordBreak: "break-all" }}>
          {known ? known.key : t("hosts.unpinned")}
        </div>
      </div>
    </div>
  );
}

// ── Rail: live sessions + tunnels summary ──────────────────────
function SessionsRail() {
  const p = usePalette();
  // aliased to `tr` because the terminals/tunnels .map() callbacks bind `t`.
  const { t: tr } = useTranslation();
  const ctx = useCtx();
  const terminals = useApp((s) => s.terminals);
  const tunnels = useApp((s) => s.tunnels);
  // One card per tab; derive its status/preview/host from the tab's active pane.
  const live = terminals
    .map((tab) => {
      const pane = tab.panes.find((pp) => pp.id === tab.activePaneId) ?? tab.panes[0];
      const online = tab.panes.some((pp) => pp.status === "online");
      const connecting = tab.panes.some((pp) => pp.status === "connecting");
      return {
        id: tab.id,
        title: tab.title,
        status: online ? "online" : connecting ? "connecting" : "closed",
        profile: pane?.profile,
        preview: pane?.preview,
      };
    })
    .filter((t) => t.status === "online" || t.status === "connecting");

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", gap: 12 }}>
      {live.length === 0 && (
        <div style={{ fontSize: 12, color: p.txt3, padding: "4px 2px" }}>
          {tr("hosts.noActiveSessions")}
        </div>
      )}
      {live.map((t) => {
        const online = t.status === "online";
        const color = online ? p.green : p.amber;
        const statusLabel = tr(online ? "terminal.status.online" : "terminal.status.connecting");
        return (
          <div
            key={t.id}
            role="button"
            tabIndex={0}
            title={`${t.title} — ${statusLabel}`}
            aria-label={`${t.title} — ${statusLabel}`}
            onKeyDown={pressActivate(() => {
              useApp.getState().setActiveTerm(t.id);
              ctx.go("terminal");
            })}
            onClick={() => {
              useApp.getState().setActiveTerm(t.id);
              ctx.go("terminal");
            }}
            style={{
              padding: 12,
              borderRadius: 12,
              background: p.bg0,
              border: `1px solid ${p.line}`,
              position: "relative",
              overflow: "hidden",
              cursor: "pointer",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              {/* shape carries the state too: solid = online, hollow = connecting */}
              <span
                style={{
                  width: 8,
                  height: 8,
                  borderRadius: "50%",
                  background: online ? color : "transparent",
                  border: online ? "none" : `1.5px solid ${color}`,
                  boxSizing: "border-box",
                }}
              />
              <span style={{ fontSize: 13, fontWeight: 700 }}>{t.title}</span>
              <span style={{ fontFamily: MONO, fontSize: 10.5, color: p.txt3 }}>
                {t.profile
                  ? t.profile.user
                    ? `${t.profile.user}@${t.profile.host}`
                    : t.profile.host
                  : "pty"}
              </span>
              <div style={{ flex: 1 }} />
              <span style={{ fontFamily: MONO, fontSize: 10.5, color: p.txt3 }}>
                {t.status === "online" ? tr("hosts.online") : "…"}
              </span>
            </div>
            {t.preview && t.preview.length > 0 && (
              <div
                style={{
                  marginTop: 9,
                  borderRadius: 8,
                  background: p.bg0,
                  border: `1px solid ${p.line}`,
                  padding: "8px 10px",
                  fontFamily: MONO,
                  fontSize: 10.5,
                  lineHeight: 1.6,
                }}
              >
                {t.preview.map((l, i) => (
                  <div
                    key={i}
                    style={{
                      color: p.txt3,
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                    }}
                  >
                    {l}
                  </div>
                ))}
              </div>
            )}
          </div>
        );
      })}

      <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 2 }}>
        <span
          style={{
            fontSize: 10.5,
            fontWeight: 700,
            letterSpacing: 0.6,
            color: p.txt3,
            textTransform: "uppercase",
          }}
        >
          {tr("hosts.tunnelsHeading")} · {tunnels.length}
        </span>
        <div style={{ flex: 1, height: 1, background: p.line }} />
        <button
          onClick={() => ctx.go("tunnels")}
          style={{ ...BTN_RESET, fontSize: 11, color: p.accent, cursor: "pointer" }}
        >
          {tr("common.all")} →
        </button>
      </div>
      {tunnels.length === 0 && (
        <div style={{ fontSize: 11.5, color: p.txt3 }}>{tr("hosts.noOpenTunnels")}</div>
      )}
      {tunnels.map((t, i) => (
        <div
          key={t.id}
          role="button"
          tabIndex={0}
          title={`${t.label} — ${tr(t.on ? "tunnels.active" : "tunnels.off")}`}
          aria-label={`${t.label} — ${tr(t.on ? "tunnels.active" : "tunnels.off")}`}
          onKeyDown={pressActivate(() => ctx.go("tunnels"))}
          onClick={() => ctx.go("tunnels")}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 9,
            padding: "9px 2px",
            borderTop: i === 0 ? "none" : `1px solid ${p.line}`,
            background: "transparent",
            cursor: "pointer",
          }}
        >
          <Icon name="branch" size={15} color={p.txt3} />
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontFamily: MONO, fontSize: 12, fontWeight: 600 }}>{t.label}</div>
            <div style={{ fontSize: 10.5, color: p.txt3 }}>{t.route}</div>
          </div>
          {/* solid = forwarding, hollow = off — state isn't colour-only */}
          <span
            style={{
              width: 7,
              height: 7,
              borderRadius: "50%",
              background: t.on ? p.green : "transparent",
              border: t.on ? "none" : `1.5px solid ${p.txt3}`,
              boxSizing: "border-box",
            }}
          />
        </div>
      ))}
      <div style={{ flex: 1 }} />
    </div>
  );
}

// ── Bulk group/tag membership menu (host multi-select bar) ─────
// "Add to…" assigns the selected hosts to a group or tag (creating one inline);
// "Remove from…" lists only the groups/tags the selection actually belongs to,
// so filtering to a tag/group → "select whole group" → remove is a clean
// mass-unassign. Mutations go through the store helpers (which reload the vault).
function BulkActionsMenu({
  mode,
  ids,
  onApplied,
  tight,
}: {
  mode: "add" | "remove";
  ids: string[];
  onApplied: () => void;
  tight: boolean;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const ctx = useCtx();
  const hosts = useApp((s) => s.hosts);
  const groups = useApp((s) => s.groups);
  const addHostsToGroup = useApp((s) => s.addHostsToGroup);
  const removeHostsFromGroup = useApp((s) => s.removeHostsFromGroup);
  const createGroupWithHosts = useApp((s) => s.createGroupWithHosts);
  const addTagToHosts = useApp((s) => s.addTagToHosts);
  const removeTagFromHosts = useApp((s) => s.removeTagFromHosts);

  const [open, setOpen] = useState(false);
  const [newGroup, setNewGroup] = useState("");
  const [newTag, setNewTag] = useState("");
  const ref = useRef<HTMLDivElement | null>(null);
  // shared dropdown contract: outside click AND Escape close, arrows walk the rows
  useMenu(open, () => setOpen(false), ref);

  const selSet = useMemo(() => new Set(ids), [ids]);
  const allTags = useMemo(() => Array.from(new Set(hosts.flatMap((h) => h.tags))).sort(), [hosts]);
  const memberGroups = useMemo(
    () => groups.filter((g) => g.memberIds.some((m) => selSet.has(m))),
    [groups, selSet],
  );
  const memberTags = useMemo(
    () =>
      Array.from(
        new Set(hosts.filter((h) => selSet.has(h.profileId)).flatMap((h) => h.tags)),
      ).sort(),
    [hosts, selSet],
  );

  const close = () => {
    setOpen(false);
    setNewGroup("");
    setNewTag("");
  };
  const done = (msg: string) => {
    ctx.toast(msg, "ok");
    close();
    onApplied();
  };
  const run = async (fn: Promise<void>, msg: string) => {
    try {
      await fn;
      done(msg);
    } catch (e) {
      ctx.toast(apiErrorMessage(e), "err");
    }
  };

  const rowStyle: React.CSSProperties = {
    ...BTN_RESET,
    width: "100%",
    display: "flex",
    alignItems: "center",
    gap: 9,
    padding: "8px 10px",
    borderRadius: 8,
    cursor: "pointer",
    fontSize: 13,
    fontWeight: 500,
    color: p.txt2,
  };
  const hoverOn = (e: React.MouseEvent<HTMLButtonElement>) =>
    (e.currentTarget.style.background = p.bg2);
  const hoverOff = (e: React.MouseEvent<HTMLButtonElement>) =>
    (e.currentTarget.style.background = "transparent");
  const sectionLabel = (label: string) => (
    <div
      style={{
        fontSize: 10.5,
        fontWeight: 700,
        letterSpacing: 0.6,
        textTransform: "uppercase",
        color: p.txt3,
        padding: "6px 10px 4px",
      }}
    >
      {label}
    </div>
  );
  const inputStyle: React.CSSProperties = {
    width: "100%",
    height: 32,
    padding: "0 10px",
    borderRadius: 8,
    fontSize: 13,
    background: p.bg2,
    color: p.txt,
    border: `1px solid ${p.line2}`,
    outline: "none",
  };

  const empty = mode === "remove" && memberGroups.length === 0 && memberTags.length === 0;

  return (
    <div ref={ref} style={{ position: "relative" }}>
      <Btn
        variant="ghost"
        size="sm"
        icon={mode === "add" ? "folder" : "minus"}
        aria-haspopup="menu"
        aria-expanded={open}
        title={tight ? t(mode === "add" ? "hosts.bulk.addTo" : "hosts.bulk.removeFrom") : undefined}
        aria-label={tight ? t(mode === "add" ? "hosts.bulk.addTo" : "hosts.bulk.removeFrom") : undefined}
        onClick={() => setOpen((v) => !v)}
      >
        {!tight && t(mode === "add" ? "hosts.bulk.addTo" : "hosts.bulk.removeFrom")}
      </Btn>
      {open && (
        <div
          role="menu"
          aria-label={t(mode === "add" ? "hosts.bulk.addTo" : "hosts.bulk.removeFrom")}
          style={{
            position: "absolute",
            bottom: "100%",
            left: 0,
            marginBottom: 8,
            width: 248,
            zIndex: 30,
            background: p.bg3,
            border: `1px solid ${p.line2}`,
            borderRadius: 11,
            padding: 6,
            boxShadow: p.shadow,
            maxHeight: 340,
            overflow: "auto",
          }}
        >
          {empty && (
            <div style={{ padding: "10px 10px", fontSize: 12.5, color: p.txt3 }}>
              {t("hosts.bulk.nothingToRemove")}
            </div>
          )}

          {/* groups */}
          {(mode === "add" ? groups : memberGroups).length > 0 && sectionLabel(t("hosts.bulk.groups"))}
          {(mode === "add" ? groups : memberGroups).map((g) => (
            <button
              key={g.groupId}
              role="menuitem"
              tabIndex={-1}
              style={rowStyle}
              onMouseEnter={hoverOn}
              onMouseLeave={hoverOff}
              onClick={() =>
                mode === "add"
                  ? run(addHostsToGroup(g.groupId, ids), t("hosts.bulk.addedToGroup", { name: g.label }))
                  : run(
                      removeHostsFromGroup(g.groupId, ids),
                      t("hosts.bulk.removedFromGroup", { name: g.label }),
                    )
              }
            >
              <Icon name="folder" size={14} color={p.txt3} />
              {g.label}
            </button>
          ))}
          {mode === "add" && (
            <div style={{ padding: "4px 6px 8px" }}>
              <input
                value={newGroup}
                placeholder={t("hosts.bulk.newGroupPlaceholder")}
                onChange={(e) => setNewGroup(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && newGroup.trim()) {
                    e.preventDefault();
                    run(createGroupWithHosts(newGroup, ids), t("hosts.bulk.addedToGroup", { name: newGroup.trim() }));
                  }
                }}
                style={inputStyle}
              />
            </div>
          )}

          {/* tags */}
          {(mode === "add" ? allTags : memberTags).length > 0 && sectionLabel(t("hosts.bulk.tags"))}
          {(mode === "add" ? allTags : memberTags).map((tag) => (
            <button
              key={tag}
              role="menuitem"
              tabIndex={-1}
              style={{ ...rowStyle, fontFamily: MONO }}
              onMouseEnter={hoverOn}
              onMouseLeave={hoverOff}
              onClick={() =>
                mode === "add"
                  ? run(addTagToHosts(tag, ids), t("hosts.bulk.addedTag", { name: tag }))
                  : run(removeTagFromHosts(tag, ids), t("hosts.bulk.removedTag", { name: tag }))
              }
            >
              <Icon name="tag" size={13} color={p.txt3} />#{tag}
            </button>
          ))}
          {mode === "add" && (
            <div style={{ padding: "4px 6px 6px" }}>
              <input
                value={newTag}
                placeholder={t("hosts.bulk.newTagPlaceholder")}
                onChange={(e) => setNewTag(e.target.value)}
                onKeyDown={(e) => {
                  const tg = newTag.trim().replace(/^#/, "");
                  if (e.key === "Enter" && tg) {
                    e.preventDefault();
                    run(addTagToHosts(tg, ids), t("hosts.bulk.addedTag", { name: tg }));
                  }
                }}
                style={inputStyle}
              />
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Main view ──────────────────────────────────────────────────
export function ViewHosts() {
  const p = usePalette();
  const { t } = useTranslation();
  const { hostsLayout, setHostsLayout } = useTheme();
  const ctx = useCtx();
  const hosts = useApp((s) => s.hosts);
  const groups = useApp((s) => s.groups);
  const terminals = useApp((s) => s.terminals);
  const hostFilter = useApp((s) => s.hostFilter);
  const setHostFilter = useApp((s) => s.setHostFilter);
  // When the sidebar selects a GROUP, hostFilter holds a groupId (not a tag), so
  // none of the tag chips highlight — surface the active group as its own visible,
  // dismissable scope token so the filter is never invisible.
  const activeGroup = groups.find((g) => g.groupId === hostFilter);

  const [sort, setSort] = useState<SortKey>(loadHostSort);
  const lastConnected = useApp((s) => s.lastConnected);
  // Persist the choice so it sticks until the user changes it again.
  const changeSort = (k: SortKey) => {
    setSort(k);
    try {
      localStorage.setItem(HOST_SORT_LS, k);
    } catch {
      /* ignore */
    }
  };
  const [sortOpen, setSortOpen] = useState(false);
  const sortRef = useRef<HTMLDivElement | null>(null);
  // same dropdown contract as BulkActionsMenu: outside click / Escape / arrows
  useMenu(sortOpen, () => setSortOpen(false), sortRef);
  const [sel, setSel] = useState<string[]>([]);
  const [open, setOpen] = useState<string | null>(hosts[0]?.profileId ?? null);
  const [rail, setRail] = useState<RailTab>("detail");
  // Collapse toolbar button labels to icons when the main area is too narrow
  // (e.g. rail open + sidebar expanded) so buttons never slide under the rail.
  const mainRef = useRef<HTMLDivElement | null>(null);
  const [tight, setTight] = useState(false);
  useEffect(() => {
    const el = mainRef.current;
    if (!el) return;
    const apply = () => setTight(el.clientWidth < 820);
    const ro = new ResizeObserver(apply);
    ro.observe(el);
    apply();
    return () => ro.disconnect();
  }, []);
  const [railOpen, setRailOpen] = useState(() => {
    try {
      return localStorage.getItem("unissh.hostRailOpen") !== "0";
    } catch {
      return true;
    }
  });
  const [railW, setRailW] = useState(() => {
    try {
      const v = parseInt(localStorage.getItem("unissh.hostRailW") || "264", 10);
      return Number.isFinite(v) ? Math.min(460, Math.max(220, v)) : 264;
    } catch {
      return 264;
    }
  });
  const toggleRail = (open: boolean) => {
    setRailOpen(open);
    try {
      localStorage.setItem("unissh.hostRailOpen", open ? "1" : "0");
    } catch {
      /* ignore */
    }
  };
  const resizeRail = (clientX: number) => {
    const w = Math.min(460, Math.max(220, Math.round(window.innerWidth - clientX)));
    setRailW(w);
    try {
      localStorage.setItem("unissh.hostRailW", String(w));
    } catch {
      /* ignore */
    }
  };

  // set of profileIds with a live (online) terminal
  const activeIds = useMemo(
    () =>
      new Set(
        terminals
          .flatMap((t) => t.panes)
          .filter((pp) => pp.status === "online" && pp.profile)
          .map((pp) => pp.profile!.profileId),
      ),
    [terminals],
  );

  const tagSet = useMemo(
    () => Array.from(new Set(hosts.flatMap((h) => h.tags))).slice(0, 5),
    [hosts],
  );

  const filtered = useMemo(() => {
    if (hostFilter === HOST_FILTER_ALL) return hosts;
    if (hostFilter === "__untagged") return hosts.filter((x) => x.tags.length === 0);
    const group = groups.find((g) => g.groupId === hostFilter);
    return hosts.filter(
      (x) => x.tags.includes(hostFilter) || (group?.memberIds.includes(x.profileId) ?? false),
    );
  }, [hosts, groups, hostFilter]);

  const shown = useMemo(() => {
    const arr = [...filtered];
    if (sort === "name") arr.sort((a, b) => a.label.localeCompare(b.label));
    else if (sort === "connected")
      // most-recently-connected first; never-connected hosts sink to the bottom,
      // tie-broken by name so the order is stable.
      arr.sort((a, b) => {
        const ta = lastConnected[a.profileId] ?? 0;
        const tb = lastConnected[b.profileId] ?? 0;
        return tb - ta || a.label.localeCompare(b.label);
      });
    // "added" keeps store order (most recently saved last); show newest first
    else arr.reverse();
    return arr;
  }, [filtered, sort, lastConnected]);

  const sessions = useMemo(
    () => hosts.filter((h) => activeIds.has(h.profileId)).length,
    [hosts, activeIds],
  );
  // Count live TABS (one card per tab in the rail), not panes, so the badge matches
  // the list below it even when a tab holds several split panes.
  const liveSessions = terminals.filter((t) =>
    t.panes.some((pp) => pp.status === "online" || pp.status === "connecting"),
  ).length;

  const toggle = (id: string) =>
    setSel((s) => (s.includes(id) ? s.filter((x) => x !== id) : [...s, id]));
  const openHost = (id: string) => {
    setOpen(id);
    setRail("detail");
    // Always reveal the rail — otherwise clicking a host does nothing visible
    // once the rail has been collapsed (the collapsed state is persisted).
    if (!railOpen) toggleRail(true);
  };
  const detail = hosts.find((x) => x.profileId === open) || hosts[0];

  const segBtn = (icon: "grid" | "list", val: "cards" | "list") => (
    <button
      onClick={() => setHostsLayout(val)}
      title={t(val === "cards" ? "hosts.viewCards" : "hosts.viewList")}
      aria-label={t(val === "cards" ? "hosts.viewCards" : "hosts.viewList")}
      aria-pressed={hostsLayout === val}
      style={{
        width: 30,
        height: 26,
        borderRadius: 6,
        border: "none",
        background: hostsLayout === val ? p.bg4 : "transparent",
        color: hostsLayout === val ? p.txt : p.txt3,
        cursor: "pointer",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
      }}
    >
      <Icon name={icon} size={14} />
    </button>
  );

  return (
    <div style={{ flex: 1, display: "flex", minWidth: 0 }}>
      {/* main */}
      <div
        ref={mainRef}
        style={{
          flex: 1,
          minWidth: 0,
          position: "relative",
          overflow: "hidden",
          background: p.bg0,
          display: "flex",
          flexDirection: "column",
        }}
      >
        <div
          style={{
            position: "relative",
            display: "flex",
            alignItems: "center",
            gap: 12,
            padding: "24px 22px 14px",
          }}
        >
          {/* Title + count share one baseline (reference .head); the outer row stays
              center-aligned so the toolbar buttons don't ride the text baseline. */}
          <div style={{ display: "flex", alignItems: "baseline", gap: 12, minWidth: 0 }}>
            <h1 style={{ margin: 0, fontSize: 28, fontWeight: 800, letterSpacing: -0.7 }}>
              {t("hosts.title")}
            </h1>
            <span
              style={{
                fontFamily: MONO,
                fontSize: 12,
                color: p.txt3,
                whiteSpace: "nowrap",
              }}
            >
              {t("count.hosts", { count: hosts.length })}
              {sessions ? ` · ${t("count.sessions", { count: sessions })}` : ""}
            </span>
          </div>
          <div style={{ flex: 1 }} />
          {/* Header actions are quiet text, per the reference (.act / .new) — a
              filled primary here becomes a glaring near-white block in dark mode. */}
          <button
            title={t("hosts.importSshConfig")}
            onClick={() => ctx.openImport()}
            style={{
              ...BTN_RESET,
              display: "flex",
              alignItems: "center",
              gap: 5,
              height: 30,
              fontSize: 13,
              fontWeight: 600,
              color: p.txt3,
              cursor: "pointer",
            }}
          >
            <Icon name="download" size={14} />
            {!tight && t("hosts.importSshConfig")}
          </button>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              height: 30,
              background: "transparent",
              border: `1px solid ${p.line}`,
              borderRadius: 8,
              padding: 1,
              gap: 2,
            }}
          >
            {segBtn("grid", "cards")}
            {segBtn("list", "list")}
          </div>
          <div ref={sortRef} style={{ position: "relative" }}>
            <button
              onClick={() => setSortOpen((v) => !v)}
              title={t("hosts.sortTitle")}
              aria-label={t("hosts.sortTitle")}
              aria-haspopup="menu"
              aria-expanded={sortOpen}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 6,
                height: 30,
                padding: "0 10px",
                borderRadius: 8,
                // No grey fill — just the frame. Open state reads via a stronger
                // hairline + darker label instead of a bg tint.
                border: `1px solid ${sortOpen ? p.line2 : p.line}`,
                background: "transparent",
                color: sortOpen ? p.txt : p.txt2,
                cursor: "pointer",
                fontSize: 12.5,
                fontWeight: 600,
              }}
            >
              <Icon
                name={sort === "name" ? "list" : sort === "connected" ? "clock" : "plus"}
                size={14}
              />
              {!tight && tDyn(`hosts.sort.${SORT_KEYS[sort]}`)}
              <Icon name="cd" size={12} color={p.txt3} />
            </button>
            {sortOpen && (
              <div
                role="menu"
                aria-label={t("hosts.sortTitle")}
                style={{
                  position: "absolute",
                  top: "100%",
                  right: 0,
                  marginTop: 6,
                  zIndex: 30,
                  background: p.bg3,
                  border: `1px solid ${p.line2}`,
                  borderRadius: 11,
                  padding: 5,
                  boxShadow: p.shadow,
                  width: 220,
                }}
              >
                {(Object.keys(SORT_KEYS) as SortKey[]).map((k) => (
                  <button
                    key={k}
                    role="menuitemradio"
                    aria-checked={sort === k}
                    tabIndex={-1}
                    onClick={() => {
                      changeSort(k);
                      setSortOpen(false);
                    }}
                    style={{
                      ...BTN_RESET,
                      width: "100%",
                      display: "flex",
                      alignItems: "center",
                      gap: 9,
                      padding: "8px 10px",
                      borderRadius: 8,
                      cursor: "pointer",
                      fontSize: 13,
                      fontWeight: sort === k ? 700 : 500,
                      color: sort === k ? p.txt : p.txt2,
                      background: "transparent",
                    }}
                    onMouseEnter={(e) => {
                      if (sort !== k) e.currentTarget.style.background = p.bg2;
                    }}
                    onMouseLeave={(e) => {
                      if (sort !== k) e.currentTarget.style.background = "transparent";
                    }}
                  >
                    <Icon
                      name={k === "name" ? "list" : k === "connected" ? "clock" : "plus"}
                      size={15}
                      color={sort === k ? p.txt : p.txt3}
                    />
                    <span style={{ flex: 1 }}>{tDyn(`hosts.sort.${SORT_KEYS[k]}`)}</span>
                    {sort === k && <Icon name="check" size={14} color={p.txt} />}
                  </button>
                ))}
              </div>
            )}
          </div>
          <button
            title={t("hosts.newHost")}
            onClick={() => ctx.onNewHost()}
            style={{
              ...BTN_RESET,
              display: "flex",
              alignItems: "center",
              gap: 5,
              height: 30,
              fontSize: 13,
              fontWeight: 700,
              color: p.accent,
              cursor: "pointer",
            }}
          >
            <Icon name="plus" size={15} />
            {!tight && t("hosts.newHost")}
          </button>
          {!railOpen && (
            <button
              title={t("common.show")}
              aria-label={t("common.show")}
              onClick={() => toggleRail(true)}
              style={{
                width: 30,
                height: 30,
                borderRadius: 8,
                border: `1px solid ${p.line}`,
                background: "transparent",
                color: p.txt2,
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <Icon name="cl" size={15} />
            </button>
          )}
        </div>

        <div
          style={{
            position: "relative",
            display: "flex",
            gap: 14,
            padding: "0 22px 10px",
            alignItems: "center",
            flexWrap: "wrap",
          }}
        >
          {activeGroup && (
            <span
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 5,
                fontSize: 13,
                fontWeight: 700,
                color: p.txt,
              }}
            >
              {activeGroup.label}
              <button
                onClick={() => setHostFilter(HOST_FILTER_ALL)}
                title={t("hosts.resetFilter")}
                aria-label={t("hosts.resetFilter")}
                style={{
                  ...BTN_RESET,
                  display: "inline-flex",
                  alignItems: "center",
                  padding: 2,
                  cursor: "pointer",
                  color: p.txt3,
                }}
              >
                <Icon name="x" size={12} />
              </button>
            </span>
          )}
          {[HOST_FILTER_ALL, ...tagSet].map((tag) => {
            const isAll = tag === HOST_FILTER_ALL;
            const on = hostFilter === tag;
            return (
              <button
                key={tag}
                onClick={() => setHostFilter(tag)}
                aria-pressed={on}
                style={{
                  fontFamily: isAll ? UI : MONO,
                  fontSize: 13,
                  fontWeight: 600,
                  cursor: "pointer",
                  padding: "2px 1px 5px",
                  border: "none",
                  borderRadius: 0,
                  borderBottom: `2px solid ${on ? p.accent : "transparent"}`,
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
              aria-pressed={hostFilter === "__untagged"}
              style={{
                fontFamily: UI,
                fontSize: 13,
                fontWeight: 600,
                cursor: "pointer",
                padding: "2px 1px 5px",
                border: "none",
                borderRadius: 0,
                borderBottom: `2px solid ${hostFilter === "__untagged" ? p.accent : "transparent"}`,
                background: "transparent",
                color: hostFilter === "__untagged" ? p.txt : p.txt3,
              }}
            >
              {t("hosts.untagged")}
            </button>
          )}
          {hostFilter !== HOST_FILTER_ALL && (
            <button
              onClick={() => setSel(shown.map((x) => x.profileId))}
              style={{
                marginLeft: 2,
                fontSize: 12.5,
                fontWeight: 600,
                cursor: "pointer",
                padding: 0,
                border: "none",
                background: "transparent",
                color: p.txt2,
                textDecoration: "underline",
                textUnderlineOffset: 3,
              }}
            >
              {t("hosts.selectWholeGroup")}
            </button>
          )}
        </div>

        <div style={{ position: "relative", flex: 1, overflow: "auto", padding: "6px 22px 76px" }}>
          {hosts.length === 0 ? (
            <div
              style={{
                height: "80%",
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                justifyContent: "center",
                gap: 14,
                color: p.txt3,
              }}
            >
              <span
                style={{
                  width: 56,
                  height: 56,
                  borderRadius: 16,
                  background: p.bg2,
                  border: `1px solid ${p.line}`,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                }}
              >
                <Icon name="server" size={26} color={p.txt3} />
              </span>
              <div style={{ textAlign: "center" }}>
                <div style={{ fontSize: 16, fontWeight: 700, color: p.txt }}>
                  {t("hosts.emptyVaultTitle")}
                </div>
                <div style={{ fontSize: 13, color: p.txt3, marginTop: 3 }}>
                  {t("hosts.emptyVaultHint")}
                </div>
              </div>
              <div style={{ display: "flex", gap: 10 }}>
                <Btn variant="ghost" size="sm" icon="download" onClick={() => ctx.openImport()}>
                  {t("hosts.importSshConfig")}
                </Btn>
                <Btn size="sm" icon="plus" onClick={() => ctx.onNewHost()}>
                  {t("hosts.newHost")}
                </Btn>
              </div>
            </div>
          ) : shown.length === 0 ? (
            <div
              style={{
                height: "80%",
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                justifyContent: "center",
                gap: 12,
                color: p.txt3,
              }}
            >
              <Icon name="search" size={30} color={p.txt3} />
              <span style={{ fontSize: 14 }}>
                {hostFilter === "__untagged"
                  ? t("hosts.allHostsTagged")
                  : t("hosts.noHostsForTag", { tag: hostFilter })}
              </span>
              <Btn size="sm" variant="ghost" onClick={() => setHostFilter(HOST_FILTER_ALL)}>
                {t("hosts.resetFilter")}
              </Btn>
            </div>
          ) : hostsLayout === "cards" ? (
            <div
              className="uh-stagger"
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fill, minmax(248px, 1fr))",
                gap: 12,
              }}
            >
              {shown.map((h) => (
                <HostCard
                  key={h.profileId}
                  h={h}
                  selected={sel.includes(h.profileId)}
                  active={open === h.profileId}
                  session={activeIds.has(h.profileId)}
                  onToggle={() => toggle(h.profileId)}
                  onOpen={() => openHost(h.profileId)}
                  onConnect={() => ctx.connect(h)}
                  onSftp={() => void ctx.connectSftp(h)}
                />
              ))}
            </div>
          ) : (
            <div className="uh-stagger" style={{ display: "flex", flexDirection: "column" }}>
              {shown.map((h, i) => (
                <HostRow
                  key={h.profileId}
                  h={h}
                  selected={sel.includes(h.profileId)}
                  active={open === h.profileId}
                  session={activeIds.has(h.profileId)}
                  first={i === 0}
                  onToggle={() => toggle(h.profileId)}
                  onOpen={() => openHost(h.profileId)}
                  onConnect={() => ctx.connect(h)}
                />
              ))}
            </div>
          )}
        </div>

        {sel.length > 0 && (
          <div
            style={{
              position: "absolute",
              left: 22,
              right: 22,
              bottom: 16,
              height: 52,
              borderRadius: 13,
              background: p.bg0,
              border: `1px solid ${p.line2}`,
              boxShadow: p.shadow,
              display: "flex",
              alignItems: "center",
              gap: 12,
              padding: "0 14px",
              zIndex: 5,
            }}
          >
            <span
              style={{
                width: 26,
                height: 26,
                borderRadius: 8,
                background: p.accent,
                color: p.accentInk,
                fontFamily: MONO,
                fontWeight: 700,
                fontSize: 13,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              {sel.length}
            </span>
            <span style={{ fontSize: 13, fontWeight: 600 }}>
              {t("count.hostsSelected", { count: sel.length })}
            </span>
            <span style={{ fontSize: 12, color: p.txt3 }}>{t("hosts.runInParallel")}</span>
            <div style={{ flex: 1 }} />
            <BulkActionsMenu mode="add" ids={sel} onApplied={() => setSel([])} tight={tight} />
            <BulkActionsMenu mode="remove" ids={sel} onApplied={() => setSel([])} tight={tight} />
            {/* Carry the selection as the explicit target scope — without it these
                would silently widen to the filter (Fleet) / whole vault (Broadcast). */}
            <Btn
              variant="ghost"
              size="sm"
              icon="radio"
              onClick={() => {
                useApp.getState().setFleetSelection(sel);
                ctx.go("broadcast");
              }}
            >
              {t("nav.broadcast")}
            </Btn>
            <Btn
              size="sm"
              icon="bolt"
              onClick={() => {
                useApp.getState().setFleetSelection(sel);
                ctx.go("fleet");
              }}
            >
              {t("nav.fleetExec")}
            </Btn>
            <Btn
              variant="danger"
              size="sm"
              icon="trash"
              onClick={() =>
                ctx.confirm({
                  title: t("hosts.bulkDeleteTitle"),
                  body: t("count.hostsDeleteConfirm", { count: sel.length }),
                  danger: true,
                  confirmLabel: t("common.delete"),
                  icon: "trash",
                  onConfirm: async () => {
                    try {
                      const n = sel.length;
                      await useApp.getState().deleteHosts(sel);
                      setSel([]);
                      ctx.toast(t("count.hostsDeleted", { count: n }), "ok");
                    } catch (e) {
                      ctx.toast(apiErrorMessage(e), "err");
                    }
                  },
                })
              }
            >
              {!tight && t("common.delete")}
            </Btn>
            <button
              onClick={() => setSel([])}
              title={t("hosts.clearSelection")}
              aria-label={t("hosts.clearSelection")}
              style={{
                width: 28,
                height: 28,
                borderRadius: 8,
                border: `1px solid ${p.line2}`,
                background: "transparent",
                color: p.txt3,
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <Icon name="x" size={14} />
            </button>
          </div>
        )}
      </div>

      {/* right rail */}
      {railOpen && (
        <div
          style={{
            width: railW,
            flexShrink: 0,
            position: "relative",
            background: p.bg0,
            borderLeft: `1px solid ${p.line}`,
            display: "flex",
            flexDirection: "column",
            padding: 14,
          }}
        >
          <ResizeHandle side="left" onDrag={resizeRail} />
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 8,
              borderBottom: `1px solid ${p.line}`,
              marginBottom: 14,
            }}
          >
            <UnderlineTabs<RailTab>
              ariaLabel={t("hosts.railHost")}
              value={rail}
              onChange={setRail}
              tabs={[
                { value: "detail", label: t("hosts.railHost") },
                { value: "sessions", label: t("hosts.railSessions"), count: liveSessions || undefined },
              ]}
            />
            <button
              title={t("common.hide")}
              aria-label={t("common.hide")}
              onClick={() => toggleRail(false)}
              style={{
                width: 30,
                height: 30,
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
              <Icon name="cr" size={15} />
            </button>
          </div>
          <div style={{ flex: 1, minHeight: 0, overflow: "auto" }}>
            {rail === "detail" ? (
              detail ? (
                <HostDetail h={detail} session={activeIds.has(detail.profileId)} />
              ) : (
                <div style={{ fontSize: 13, color: p.txt3 }}>{t("hosts.selectHost")}</div>
              )
            ) : (
              <SessionsRail />
            )}
          </div>
        </div>
      )}
    </div>
  );
}
