// ViewHosts — the centerpiece: toolbar, tag-filter chips, cards/list grid,
// multi-select Fleet bar, and the right rail toggling Host detail ⇄ live Sessions.
// Ported pixel-for-pixel from the prototype (view-hosts*.jsx) but wired to the
// real store: hosts = ConnectionProfile[], liveness only from open terminal tabs,
// no fake ping/cipher/agent-fwd.

import React, { useEffect, useId, useMemo, useRef, useState } from "react";
import { usePalette, useTheme } from "@/theme/ThemeProvider";
import { AUTH_LABEL_KEY, designPx, MONO, RADIUS, rem, SIZE, SPACE, TEXT, UI } from "@/theme/tokens";
import { BTN_RESET, Icon, IconBtn, Btn, Checkbox, Tag, AuthBadge, ResizeHandle, StatusDot, Spinner, NO_AUTOCORRECT } from "@/components/primitives";
import { Card, MetaChip, UnderlineTabs, fmtRelative } from "@/components/mono";
import { ContextMenu, type MenuItem } from "@/components/ContextMenu";
import { pressActivate, useMenu } from "@/components/a11y";
import { useApp, paneProfile, HOST_FILTER_ALL } from "@/store/app";
import { useIsMobile, useNarrow } from "@/store/responsive";
import { useCtx } from "@/store/ctx";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import * as api from "@/bridge/api";
import { profileAuthKind, apiErrorMessage } from "@/bridge/types";
import type { ConnectionProfile } from "@/bridge/types";
import { useTranslation, tDyn } from "@/i18n";
import { nextRow } from "@/support/listNav";
import { filterHosts, searchKeyAction } from "@/support/hostsSearch";
import { HOST_DRAG_MIME, draggedHostIds, hostDrag } from "@/support/hostDrag";

/** The address as the list shows it — and, since dragging a card no longer lets
 *  you select the text on it (a `draggable` element cannot be text-selected),
 *  as "Copy address" puts it on the clipboard. One definition so the three can
 *  never disagree; it also stops a host with no user rendering as `@10.0.0.1`. */
const hostAddress = (h: ConnectionProfile): string =>
  h.user ? `${h.user}@${h.host}` : h.host;

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
  cursor,
  onToggle,
  onOpen,
  onConnect,
  onSftp,
  onMenu,
  draggable,
  onDragStart,
}: {
  h: ConnectionProfile;
  selected: boolean;
  active: boolean;
  session: boolean;
  /** The search's keyboard highlight — what Enter in the filter box would open.
   *  Deliberately NOT folded into `active`/`selected`: those already mean "the
   *  rail is showing this" and "this is in the bulk selection", and three states
   *  drawn identically tell the user nothing about which key does what. */
  cursor?: boolean;
  onToggle: () => void;
  onOpen: () => void;
  onConnect: () => void;
  onSftp: () => void;
  onMenu: (e: React.MouseEvent) => void;
  /** Off on touch and when the vault has no groups — see ViewHosts. */
  draggable?: boolean;
  onDragStart?: (e: React.DragEvent) => void;
}) {
  const p = usePalette();
  const { t, i18n } = useTranslation();
  // Hover is a property of the POINTER, not of the width: a 700px desktop window
  // still has a mouse, and keying this off useNarrow() made it lose its hover
  // affordances for no reason. Only a real touch shell needs them laid out.
  const touch = useIsMobile();
  const compact = useTheme().density === "compact";
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
      // The search's arrow keys scroll the highlight into view by looking the card
      // up here — a ref map would have to survive every re-order the sort control
      // and the filters do to this list.
      data-host-id={h.profileId}
      active={active || selected}
      draggable={draggable}
      onDragStart={onDragStart}
      onClick={onOpen}
      onDoubleClick={onConnect}
      onContextMenu={onMenu}
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
      aria-current={cursor ? "true" : undefined}
      style={{
        position: "relative",
        cursor: "pointer",
        // A left accent bar, the same language the command palette uses for its
        // highlight. NOT an outline: `[role="button"]:focus-visible` is already
        // `2px solid var(--uh-focus)` at offset 2, and --uh-focus IS p.accent
        // (theme.css / ThemeProvider) — so an outline here was pixel-identical to
        // "this card has keyboard focus", and being inline it also suppressed the
        // real focus ring. The active/selected ring is recomposed here because
        // this style object overrides the one Card sets.
        ...(cursor || active || selected
          ? {
              boxShadow: [
                cursor ? `inset 3px 0 0 ${p.accent}` : null,
                active || selected ? `inset 0 0 0 1px ${p.accentLine}` : null,
              ]
                .filter(Boolean)
                .join(", "),
            }
          : {}),
      }}
    >
      <Checkbox
        checked={selected}
        onChange={onToggle}
        size={20}
        title={t("hosts.selectHostLabel", { label: h.label })}
        aria-label={t("hosts.selectHostLabel", { label: h.label })}
        style={{
          position: "absolute",
          // Touch has no hover, so gating on it meant no host could EVER be
          // selected on a phone — and with it, no bulk delete/tag/group. It is
          // always shown there.
          // The offsets go negative because Checkbox floors its button at the tap
          // minimum on touch: the drawn 20px box centres inside 44, so laying the
          // BUTTON out at 12/12 would put the visible box at 24/24 with a hit area
          // over the name and address. Pull the button back by half the slack so
          // the box lands where it did.
          top: touch ? 12 - (SIZE.tapMin - 20) / 2 : rem(12),
          right: touch ? 12 - (SIZE.tapMin - 20) / 2 : rem(12),
          justifyContent: "center",
          display: touch || show || selected ? "inline-flex" : "none",
          zIndex: 2,
        }}
      />

      {/* L1 — 7px status dot + name (reference: dot keys off a live session) */}
      <div style={{ display: "flex", alignItems: "center", gap: rem(8), minWidth: 0 }}>
        <span
          style={{
            width: rem(7),
            height: rem(7),
            borderRadius: "50%",
            flexShrink: 0,
            background: session ? p.green : p.line2,
          }}
        />
        <span
          style={{
            fontSize: TEXT.lead,
            fontWeight: 700,
            letterSpacing: rem(-0.2),
            whiteSpace: "nowrap",
            overflow: "hidden",
            textOverflow: "ellipsis",
            minWidth: 0,
          }}
        >
          {h.label}
        </span>
        {h.jumps.length > 0 && <Icon name="branch" size={12} color={p.txt3} stroke={1.8} />}
        {h.proxy && <Icon name="globe" size={12} color={p.txt3} stroke={1.8} />}
      </div>

      {/* L2 — address (mono, txt2) */}
      <div
        style={{
          fontFamily: MONO,
          fontSize: TEXT.small,
          color: p.txt2,
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          marginTop: rem(6),
        }}
      >
        {hostAddress(h)}
      </div>

      {/* L3 — status · auth (one mono line; colour only on meaning).
          Desktop: fades on hover so the hover Connect never sits over the text.
          Touch: hover never fires, so the actions ride this row instead and the
          meta shares the width with them rather than fading for nothing. */}
      <div style={{ display: "flex", alignItems: "center", gap: rem(10), marginTop: touch ? rem(12) : rem(16), minWidth: 0 }}>
        <div
          style={{
            flex: 1,
            display: "flex",
            alignItems: "center",
            gap: rem(7),
            fontFamily: MONO,
            fontSize: TEXT.small,
            color: p.txt3,
            opacity: !touch && show ? 0 : 1,
            transition: "opacity .12s ease",
            // keep it one line: long RU auth ("Спросить при подключении") must ellipsize,
            // not wrap to a 2nd line and change the card height.
            minWidth: 0,
            overflow: "hidden",
          }}
        >
          {/* The leading datum gets the same nowrap/ellipsis/minWidth triad as the
              auth label. Only the auth span had it, so once the actions moved onto
              this row the relative time couldn't shrink, froze at its min-content,
              and wrapped the row to two lines — the exact failure the comment above
              says it is preventing. It also yields FIRST: if the row gets truly
              tight, "2h ago" disappearing is survivable, "Password" disappearing is
              not. */}
          {session ? (
            <>
              <span style={{ color: p.green, flexShrink: 0 }}>{t("hosts.session")}</span>
              <span style={{ opacity: 0.4, flexShrink: 0 }}>·</span>
            </>
          ) : lc ? (
            <>
              <span
                style={{
                  minWidth: 0,
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
              >
                {fmtRelative(lc, i18n.language)}
              </span>
              <span style={{ opacity: 0.4, flexShrink: 0 }}>·</span>
            </>
          ) : null}
          <span
            style={{
              color: authWarn ? p.amber : p.txt3,
              minWidth: 0,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {authLabel}
          </span>
        </div>

        {/* Touch: Connect straight off the card, as on the desktop. Without this a
            phone had to open the detail screen to reach it — the desktop's own
            double-click and hover-Connect are both unreachable by a finger. */}
        {touch && (
          <div style={{ display: "flex", gap: rem(6), flexShrink: 0 }}>
            <Btn
              size="md"
              variant="ghost"
              icon="folders"
              aria-label={t("hosts.openSftp")}
              style={{ minHeight: SIZE.tapMin, minWidth: SIZE.tapMin, justifyContent: "center" }}
              onClick={(e) => {
                e.stopPropagation();
                onSftp();
              }}
            />
            <Btn
              size="md"
              variant="outline"
              icon="terminal"
              style={{
                minHeight: SIZE.tapMin,
                border: `1px solid ${p.accent}`,
                color: p.accentText,
                fontWeight: 700,
              }}
              onClick={(e) => {
                e.stopPropagation();
                onConnect();
              }}
            >
              {t("hosts.connect")}
            </Btn>
          </div>
        )}
      </div>

      {!touch && show && (
        <div
          style={{
            position: "absolute",
            right: rem(12),
            // Center the ~27px buttons on the L3 meta row for BOTH densities:
            // the row sits on the bottom padding (18 comfortable / 13 compact),
            // so one fixed offset tuned for comfortable rode 5px high in
            // compact and the Connect button broke out of its row.
            bottom: compact ? rem(7) : rem(11),
            zIndex: 3,
            display: "flex",
            gap: rem(6),
          }}
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
            style={{ border: `1px solid ${p.accent}`, color: p.accentText, fontWeight: 700 }}
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
  cursor,
  onToggle,
  onOpen,
  onConnect,
  onMenu,
  draggable,
  onDragStart,
}: {
  h: ConnectionProfile;
  selected: boolean;
  active: boolean;
  session: boolean;
  first?: boolean;
  /** The search's keyboard highlight — see HostCard. */
  cursor?: boolean;
  onToggle: () => void;
  onOpen: () => void;
  onConnect: () => void;
  onMenu: (e: React.MouseEvent) => void;
  /** Off on touch and when the vault has no groups — see ViewHosts. */
  draggable?: boolean;
  onDragStart?: (e: React.DragEvent) => void;
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
      data-host-id={h.profileId}
      aria-current={cursor ? "true" : undefined}
      draggable={draggable}
      onDragStart={onDragStart}
      onKeyDown={pressActivate(onOpen)}
      onFocus={() => setFocusIn(true)}
      onBlur={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget as Node)) setFocusIn(false);
      }}
      onClick={onOpen}
      onDoubleClick={onConnect}
      onContextMenu={onMenu}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        display: "flex",
        alignItems: "center",
        gap: rem(12),
        padding: `0 ${rem(4)}`,
        // Density is the spacing axis: compact packs the rows tighter.
        height: compact ? rem(38) : rem(46),
        cursor: "pointer",
        // Hairline row: no per-row box/radius/side-stripe. Selection = an inset
        // accentLine frame, NOT a fill — the bg2 tint recoloured the row itself
        // (matches Card); the fill stays hover-only. Inset ring: no layout shift,
        // and it reads over the shared hairlines.
        borderTop: first ? "none" : `1px solid ${p.line}`,
        background: hover ? p.bg2 : "transparent",
        // Left accent bar for the search highlight (see HostCard: an outline would
        // be indistinguishable from the focus ring), composed with the selection ring.
        boxShadow:
          [
            cursor ? `inset 3px 0 0 ${p.accent}` : null,
            active || selected ? `inset 0 0 0 2px ${p.accentLine}` : null,
          ]
            .filter(Boolean)
            .join(", ") || "none",
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
          width: rem(150),
          fontWeight: 600,
          fontSize: TEXT.base,
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
          fontSize: TEXT.small,
          color: p.txt3,
          flex: 1,
          minWidth: 0,
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
      >
        {hostAddress(h)}
      </span>
      {/* Tags and the session column YIELD; the auth badge and Connect do not.
          The row's fixed columns add up to more than a narrow list pane can hold
          (true before the interface scale existed — try a 1000px window), and
          everything being unshrinkable meant the overflow came off the END of the
          row: the connect button, clipped. Large type reaches that width sooner,
          so the two low-priority columns now give first and the actions survive. */}
      <div style={{ display: "flex", gap: rem(5), width: rem(130), minWidth: 0, overflow: "hidden", alignItems: "center" }}>
        {h.tags.slice(0, 2).map((tg) => (
          <Tag key={tg}>{tg}</Tag>
        ))}
        {h.tags.length > 2 && <MetaChip>{`+${h.tags.length - 2}`}</MetaChip>}
      </div>
      <span
        style={{
          fontFamily: MONO,
          fontSize: TEXT.small,
          color: p.txt3,
          width: rem(74),
          minWidth: 0,
          overflow: "hidden",
          textAlign: "right",
        }}
      >
        {session ? <span style={{ color: p.green }}>{t("hosts.session")}</span> : "—"}
      </span>
      <span style={{ flexShrink: 0, display: "inline-flex" }}>
        <AuthBadge auth={profileAuthKind(h.auth)} jump={h.jumps.length > 0} />
      </span>
      {/* 112 (not 84): fits the RU "Подключить" icon+label so it never spills over AuthBadge */}
      <div style={{ width: rem(112), flexShrink: 0, display: "flex", justifyContent: "flex-end" }}>
        {show ? (
          <Btn
            size="sm"
            variant="outline"
            icon="terminal"
            style={{ border: `1px solid ${p.accent}`, color: p.accentText, fontWeight: 700 }}
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
        gap: rem(10),
        padding: `${rem(7)} 0`,
        borderBottom: `1px solid ${p.line}`,
      }}
    >
      <span
        style={{
          minWidth: rem(72),
          // cap + ellipsis so a long RU label ("Последнее подключение") can't shove
          // the value off the row; the fixed flexShrink:0 stays.
          maxWidth: rem(140),
          fontSize: TEXT.small,
          color: p.txt3,
          flexShrink: 0,
          whiteSpace: "nowrap",
          overflow: "hidden",
          textOverflow: "ellipsis",
        }}
      >
        {label}
      </span>
      <span
        style={{
          flex: 1,
          minWidth: 0,
          fontSize: TEXT.base,
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
      {/* Wraps: on touch the three IconBtns below claim a 44px hit box each, which
          pushes this row past a phone's width. Better the actions drop to a second
          line than the delete button sit off-screen. */}
      <div style={{ display: "flex", alignItems: "center", gap: rem(9), marginBottom: rem(3), flexWrap: "wrap" }}>
        <span
          style={{
            width: rem(10),
            height: rem(10),
            borderRadius: "50%",
            flexShrink: 0,
            background: session ? p.green : p.line2,
          }}
        />
        <h3
          style={{
            margin: 0,
            fontSize: TEXT.h3,
            fontWeight: 700,
            whiteSpace: "nowrap",
            flexShrink: 0,
            maxWidth: rem(170),
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
              gap: rem(3),
              fontSize: TEXT.micro,
              color: p.txt3,
              flexShrink: 0,
            }}
          >
            <Icon name="branch" size={12} color={p.txt3} />
            {t("hosts.jump")}
          </span>
        )}
        {h.proxy && (
          <span
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: rem(3),
              fontSize: TEXT.micro,
              color: p.txt3,
              flexShrink: 0,
            }}
          >
            <Icon name="globe" size={12} color={p.txt3} />
            {t("hosts.proxyBadge")}
          </span>
        )}
        <div style={{ flex: 1, minWidth: rem(8) }} />
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
          fontSize: TEXT.small,
          color: session ? p.green : p.txt3,
          marginBottom: rem(14),
        }}
      >
        {session ? t("hosts.sessionActive") : t("hosts.noActiveSession")}
      </div>

      <div style={{ display: "flex", gap: rem(8), marginBottom: rem(16) }}>
        <Btn
          variant="outline"
          icon="terminal"
          style={{ flex: 1, border: `1px solid ${p.accent}`, color: p.accentText, fontWeight: 700 }}
          onClick={() => ctx.connect(h)}
        >
          {t("hosts.connect")}
        </Btn>
        <Btn
          variant="ghost"
          icon="bolt"
          title={t("nav.fleetExec")}
          style={{ padding: `${rem(8)} ${rem(11)}` }}
          onClick={() => ctx.go("fleet")}
        />
        {/* Quick SFTP: connect + jump straight to the SFTP view for this host. */}
        <Btn
          variant="ghost"
          icon="folders"
          title={t("hosts.openSftp")}
          style={{ padding: `${rem(8)} ${rem(11)}` }}
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
        {/* badge + its OWN ellipsizing text child (minWidth:0+triad) so long RU auth
            labels ("Спросить при подключении") truncate with dots, not mid-word. */}
        <span style={{ display: "flex", alignItems: "center", gap: rem(6), minWidth: 0 }}>
          <AuthBadge auth={authKind} />
          <span
            style={{
              minWidth: 0,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {tDyn(AUTH_LABEL_KEY[authKind])}
          </span>
        </span>
      </DetailRow>
      {firstJump && (
        <DetailRow label="ProxyJump" mono>
          {firstJump.user}@{firstJump.host}:{firstJump.port}
        </DetailRow>
      )}
      {h.proxy && (
        <DetailRow label="Proxy" mono>
          {h.proxy.kind}://{h.proxy.username ? `${h.proxy.username}@` : ""}
          {h.proxy.host}:{h.proxy.port}
        </DetailRow>
      )}
      {lc != null && lc > 0 && (
        <DetailRow label={t("hosts.detail.lastConnected")}>{fmtRelative(lc, i18n.language)}</DetailRow>
      )}

      {memberOf.length > 0 && (
        <>
          <div
            style={{
              fontSize: TEXT.micro,
              fontWeight: 700,
              letterSpacing: rem(0.6),
              color: p.txt3,
              textTransform: "uppercase",
              margin: `${rem(14)} 0 ${rem(7)}`,
            }}
          >
            {t("hosts.detail.groups")}
          </div>
          <div style={{ display: "flex", gap: rem(6), flexWrap: "wrap", alignItems: "center" }}>
            {memberOf.map((g) => (
              <Tag key={g.groupId}>{g.label}</Tag>
            ))}
          </div>
        </>
      )}
      <div
        style={{
          fontSize: TEXT.micro,
          fontWeight: 700,
          letterSpacing: rem(0.6),
          color: p.txt3,
          textTransform: "uppercase",
          margin: `${rem(14)} 0 ${rem(7)}`,
        }}
      >
        {t("hosts.tags")}
      </div>
      <div style={{ display: "flex", gap: rem(6), flexWrap: "wrap", alignItems: "center" }}>
        {h.tags.length === 0 && (
          <span style={{ fontSize: TEXT.small, color: p.txt3 }}>{t("hosts.noTags")}</span>
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
          padding: `${rem(12)} 0 ${rem(2)}`,
          borderTop: `1px solid ${p.line}`,
          background: "transparent",
          cursor: "pointer",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: rem(6),
            fontSize: TEXT.micro,
            color: p.txt3,
            marginBottom: rem(5),
          }}
        >
          <Icon name="shieldcheck" size={13} color={known ? p.green : p.txt3} />
          {known ? t("hosts.hostKeyPinned") : t("hosts.hostKeyUnpinned")}
        </div>
        <div style={{ fontFamily: MONO, fontSize: TEXT.micro, color: p.txt2, wordBreak: "break-all" }}>
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
        profile: pane ? paneProfile(pane) : null,
        local: pane?.target.kind === "local",
        preview: pane?.preview,
      };
    })
    .filter((t) => t.status === "online" || t.status === "connecting");

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", gap: rem(12) }}>
      {live.length === 0 && (
        <div style={{ fontSize: TEXT.small, color: p.txt3, padding: `${rem(4)} ${rem(2)}` }}>
          {tr("hosts.noActiveSessions")}
        </div>
      )}
      {live.map((t) => {
        const online = t.status === "online";
        const color = online ? p.green : p.amber;
        const statusLabel = tr(online ? "terminal.status.online" : "terminal.status.connecting");
        // The laptop icon is aria-hidden, so the label carries the local marker
        // too — which session runs on which machine must not need eyesight.
        const cardLabel = t.local
          ? `${t.title} · ${tr("terminal.localBadge")} — ${statusLabel}`
          : `${t.title} — ${statusLabel}`;
        return (
          <div
            key={t.id}
            role="button"
            tabIndex={0}
            title={cardLabel}
            aria-label={cardLabel}
            onKeyDown={pressActivate(() => {
              useApp.getState().setActiveTerm(t.id);
              ctx.go("terminal");
            })}
            onClick={() => {
              useApp.getState().setActiveTerm(t.id);
              ctx.go("terminal");
            }}
            style={{
              padding: rem(12),
              borderRadius: 12,
              background: p.bg0,
              border: `1px solid ${p.line}`,
              position: "relative",
              overflow: "hidden",
              cursor: "pointer",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: rem(8) }}>
              {/* shape carries the state too: solid = online, hollow = connecting */}
              <span
                style={{
                  width: rem(8),
                  height: rem(8),
                  borderRadius: "50%",
                  background: online ? color : "transparent",
                  border: online ? "none" : `1.5px solid ${color}`,
                  boxSizing: "border-box",
                }}
              />
              {/* A local session is marked here too: this rail is the list you
                  scan to find "the one I was working in", and picking the wrong
                  one is picking the wrong machine. */}
              {t.local && <Icon name="laptop" size={13} color={p.txt3} />}
              <span style={{ fontSize: TEXT.base, fontWeight: 700 }}>{t.title}</span>
              <span style={{ fontFamily: MONO, fontSize: TEXT.micro, color: p.txt3 }}>
                {t.local
                  ? tr("terminal.localShell")
                  : t.profile
                    ? t.profile.user
                      ? `${t.profile.user}@${t.profile.host}`
                      : t.profile.host
                    : "pty"}
              </span>
              <div style={{ flex: 1 }} />
              <span style={{ fontFamily: MONO, fontSize: TEXT.micro, color: p.txt3 }}>
                {t.status === "online" ? tr("hosts.online") : "…"}
              </span>
            </div>
            {t.preview && t.preview.length > 0 && (
              <div
                style={{
                  marginTop: rem(9),
                  borderRadius: 8,
                  background: p.bg0,
                  border: `1px solid ${p.line}`,
                  padding: `${rem(8)} ${rem(10)}`,
                  fontFamily: MONO,
                  fontSize: TEXT.micro,
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

      <div style={{ display: "flex", alignItems: "center", gap: rem(8), marginTop: rem(2) }}>
        <span
          style={{
            fontSize: TEXT.micro,
            fontWeight: 700,
            letterSpacing: rem(0.6),
            color: p.txt3,
            textTransform: "uppercase",
          }}
        >
          {tr("hosts.tunnelsHeading")} · {tunnels.length}
        </span>
        <div style={{ flex: 1, height: 1, background: p.line }} />
        <button
          onClick={() => ctx.go("tunnels")}
          style={{ ...BTN_RESET, fontSize: TEXT.micro, color: p.accentText, cursor: "pointer" }}
        >
          {tr("common.all")} →
        </button>
      </div>
      {tunnels.length === 0 && (
        <div style={{ fontSize: TEXT.small, color: p.txt3 }}>{tr("hosts.noOpenTunnels")}</div>
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
            gap: rem(9),
            padding: `${rem(9)} ${rem(2)}`,
            borderTop: i === 0 ? "none" : `1px solid ${p.line}`,
            background: "transparent",
            cursor: "pointer",
          }}
        >
          <Icon name="branch" size={15} color={p.txt3} />
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontFamily: MONO, fontSize: TEXT.small, fontWeight: 600 }}>{t.label}</div>
            <div style={{ fontSize: TEXT.micro, color: p.txt3 }}>{t.route}</div>
          </div>
          {/* solid = forwarding, hollow = off — state isn't colour-only */}
          <span
            style={{
              width: rem(7),
              height: rem(7),
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
    gap: rem(9),
    padding: `${rem(8)} ${rem(10)}`,
    borderRadius: 8,
    cursor: "pointer",
    fontSize: TEXT.base,
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
        fontSize: TEXT.micro,
        fontWeight: 700,
        letterSpacing: rem(0.6),
        textTransform: "uppercase",
        color: p.txt3,
        padding: `${rem(6)} ${rem(10)} ${rem(4)}`,
      }}
    >
      {label}
    </div>
  );
  const inputStyle: React.CSSProperties = {
    width: "100%",
    height: rem(32),
    padding: `0 ${rem(10)}`,
    borderRadius: 8,
    fontSize: TEXT.base,
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
            marginBottom: rem(8),
            width: rem(248),
            zIndex: 30,
            background: p.bg3,
            border: `1px solid ${p.line2}`,
            borderRadius: 12,
            padding: rem(6),
            boxShadow: p.shadow,
            maxHeight: rem(340),
            overflow: "auto",
          }}
        >
          {empty && (
            <div style={{ padding: `${rem(10)} ${rem(10)}`, fontSize: TEXT.base, color: p.txt3 }}>
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
            <div style={{ padding: `${rem(4)} ${rem(6)} ${rem(8)}` }}>
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
            <div style={{ padding: `${rem(4)} ${rem(6)} ${rem(6)}` }}>
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
  const addHostsToGroup = useApp((s) => s.addHostsToGroup);
  const removeHostsFromGroup = useApp((s) => s.removeHostsFromGroup);
  const setGroupsModal = useApp((s) => s.setGroupsModal);
  // Right-click menu on a host card/row. `sub` = the group picker page: the shared
  // ContextMenu is a flat list, so "Add to group" swaps the items in place (its
  // row handler closes-then-clicks, and the batched setMenu wins over onClose).
  const [menu, setMenu] = useState<{ x: number; y: number; id: string; sub: boolean } | null>(null);
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
  // In-list text filter, on every shell. ⌘K is a launcher — it CONNECTS on Enter
  // — so "find the host called prod-db and look at it before touching it" had no
  // non-destructive answer, and on the desktop no answer at all: this box used to
  // render only on touch, so a report of "Enter does nothing in the Hosts search"
  // was about a box that wasn't there.
  const [query, setQuery] = useState("");
  // Which host Enter acts on. Clamped at render (below) rather than only when a
  // key moves it, because the list shrinks under the highlight on every keystroke.
  const [cursor, setCursor] = useState(0);
  const [searchFocus, setSearchFocus] = useState(false);
  const searchRef = useRef<HTMLInputElement | null>(null);
  // The highlight is painted, so it has to be spoken too: a live region tells a
  // screen reader how many hosts survived the query and which one Enter takes.
  const searchStatusId = useId();
  const loading = useApp((s) => s.loading);
  const reloadVault = useApp((s) => s.reloadVault);
  const [sortOpen, setSortOpen] = useState(false);

  // Pull-to-refresh. One gesture on the device most likely to be on a flaky link;
  // the alternative is three taps through the command palette.
  const listRef = useRef<HTMLDivElement | null>(null);
  const pullStart = useRef<number | null>(null);
  const [pull, setPull] = useState(0);
  // Mirrors pullStart.current for RENDER. Reading a ref during render makes the
  // output depend on untracked mutable state — it happened to work only because
  // every mutation sat next to a setPull.
  const [pulling, setPulling] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const onPullStart = (e: React.TouchEvent) => {
    pullStart.current =
      (listRef.current?.scrollTop ?? 0) <= 0 && !refreshing ? e.touches[0].clientY : null;
    setPulling(pullStart.current != null);
  };
  const onPullMove = (e: React.TouchEvent) => {
    if (pullStart.current == null) return;
    const dy = e.touches[0].clientY - pullStart.current;
    setPull(dy > 0 ? Math.min(dy * 0.5, 80) : 0);
  };
  const onPullEnd = async () => {
    if (pullStart.current == null) return;
    pullStart.current = null;
    setPulling(false);
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
  const sortRef = useRef<HTMLDivElement | null>(null);
  // same dropdown contract as BulkActionsMenu: outside click / Escape / arrows
  useMenu(sortOpen, () => setSortOpen(false), sortRef);
  const [sel, setSel] = useState<string[]>([]);
  const [open, setOpen] = useState<string | null>(hosts[0]?.profileId ?? null);
  // Dragging a host onto a group files it there. The drop targets are the
  // sidebar's group items (Shell) — on the desktop that IS the group UI; the
  // chips in the strip below are the touch shell's stand-in for it, and touch
  // has no drag to give them.
  const beginHostDrag = (profileId: string, e: React.DragEvent) => {
    hostDrag.set(draggedHostIds(profileId, sel));
    try {
      // The payload lives in hostDrag; this only arms the native gesture, which
      // WebKit refuses to start with an empty data store. `move`, not `copy`: a
      // host belongs to exactly one group, so the drop empties where it was.
      e.dataTransfer.setData(HOST_DRAG_MIME, profileId);
      e.dataTransfer.effectAllowed = "move";
    } catch {
      /* non-fatal */
    }
    // Covers every ending the drop handler doesn't: Escape, a drop on the
    // toolbar, a drop on a tag chip. The browser fires dragend for all of them,
    // and an empty payload is a no-op everywhere it is read.
    window.addEventListener("dragend", () => hostDrag.clear(), { once: true });
  };
  const [rail, setRail] = useState<RailTab>("detail");
  // The fixed-width detail rail would squish the list to a sliver when there isn't
  // room for both side by side, so render it as a full-width overlay instead. Trigger
  // on the CONTENT width (window minus sidebar), not the raw window: a wide sidebar can
  // starve the row while the window is still wide, so useNarrow alone would miss it.
  // Two different questions, and conflating them is what broke the desktop:
  //   narrow — how much WIDTH is there? (gutters, type scale, rail positioning)
  //   touch  — is there a finger instead of a pointer? (no hover, thumb reach,
  //            detail as a pushed screen, no dense table)
  // A 719px desktop window is narrow but NOT touch.
  const narrow = useNarrow();
  const touch = useIsMobile();
  // A vertical drag on a phone is a scroll, so the phone shell never gets the
  // attribute at all. The other two conditions are the same rule twice: an
  // affordance that can only fail is worse than none. With no groups there is
  // nowhere to drop; with the sidebar folded to its icon rail the groups exist
  // but none of them is on screen, so the drop targets do not either.
  const groupsNavVisible = useApp((s) => s.groupsNavVisible);
  const canDragHosts = !touch && groups.length > 0 && groupsNavVisible;
  const rowRef = useRef<HTMLDivElement | null>(null);
  const [rowW, setRowW] = useState(0);
  useEffect(() => {
    const el = rowRef.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver((ents) => {
      for (const e of ents) setRowW(e.contentRect.width);
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  const railOverlay = narrow || (rowW > 0 && rowW < 640);
  // 22px of inset either side is a fifth of a phone screen; narrow buys it back.
  const gutter = narrow ? SPACE.gutterNarrow : SPACE.gutter;
  // The list layout is a TABLE — fixed status/auth/action columns beside the
  // name and address. That's a density affordance for a wide screen; squeezed
  // into a phone it just clips. Narrow always gets cards, and the layout toggle
  // hides rather than offering a choice that renders broken.
  const layout = touch ? "cards" : hostsLayout;
  // Collapse toolbar button labels to icons when the main area is too narrow
  // (e.g. rail open + sidebar expanded) so buttons never slide under the rail.
  const mainRef = useRef<HTMLDivElement | null>(null);
  const [tight, setTight] = useState(false);
  useEffect(() => {
    const el = mainRef.current;
    if (!el) return;
    // Design pixels — the toolbar's labels grow with the scale, so the width at
    // which they stop fitting grows with them.
    const apply = () => setTight(designPx(el.clientWidth) < 820);
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
  // When the rail overlays (a phone, or a window too narrow for two columns) it
  // stops being a side column and becomes a pushed detail screen: it opens when a
  // host is chosen and closes on back. The desktop's persisted open flag must not
  // drive it — defaulting to "open" would cover the whole list at launch, so a
  // phone would boot into a host detail with no visible way back to the list.
  const [railPushed, setRailPushed] = useState(false);
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
  // Design pixels, like the sidebar's: the pointer measurement is converted once
  // here so a rail dragged wide at 150 % does not come back as a sliver at 100 %.
  const resizeRail = (clientX: number) => {
    const w = Math.min(460, Math.max(220, Math.round(designPx(window.innerWidth - clientX))));
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
          .filter((pp) => pp.status === "online")
          .map((pp) => paneProfile(pp)?.profileId)
          .filter((id): id is string => !!id),
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
    const arr = [...filterHosts(filtered, query)];
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
  }, [filtered, sort, query, lastConnected]);

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
    if (touch) setRailPushed(true);
    else if (!railOpen) toggleRail(true);
  };
  // Back to the top match whenever the list itself changes meaning. Without this,
  // arrowing to the fourth result and then typing one more letter would leave the
  // highlight on whatever host happened to land in that slot.
  useEffect(() => setCursor(0), [query, hostFilter, sort]);
  // ⌘M swaps the whole shell, unmounting the box without a blur event — leaving
  // `searchFocus` stuck true and a card ringed for keys that can no longer arrive.
  useEffect(() => setSearchFocus(false), [touch]);
  // Clamped at RENDER: the list shrinks under the highlight on every keystroke,
  // and a highlight left past the end paints nothing while Enter quietly does
  // nothing either — the exact "as if focus is lost" this screen was reported for.
  const cursorIdx = shown.length === 0 ? -1 : Math.min(cursor, shown.length - 1);
  // Paint the highlight only while the keys that move it will actually arrive:
  // the box focused AND something typed. A ring left behind after the user clicks
  // away advertises an Enter that goes nowhere — which is the "как будто теряется
  // фокус с верхнего совпадения" this screen was reported for to begin with.
  const searching = searchFocus && query.trim() !== "";
  const moveCursor = (delta: number) => {
    const next = nextRow(cursorIdx, delta, shown.length);
    setCursor(next);
    // Scrolling belongs to the arrow keys alone: as an effect it would also fire
    // on mount and yank a list the user had scrolled by hand.
    const id = shown[next]?.profileId;
    if (id)
      listRef.current
        ?.querySelector(`[data-host-id="${CSS.escape(id)}"]`)
        ?.scrollIntoView({ block: "nearest" });
  };
  const onSearchKey = (e: React.KeyboardEvent) => {
    const hit = shown[cursorIdx];
    // The decision itself is a pure function (support/hostsSearch.ts): this repo
    // has no DOM test harness, so keeping it out of the component is the only way
    // the behaviour that was reported broken is pinned by a test at all.
    const action = searchKeyAction(
      {
        key: e.key,
        metaKey: e.metaKey,
        ctrlKey: e.ctrlKey,
        isComposing: e.nativeEvent.isComposing,
      },
      { hasQuery: query.trim() !== "", hasHit: !!hit },
    );
    if (!action) return;
    e.preventDefault();
    if (action.kind === "move") moveCursor(action.delta);
    else if (action.kind === "clear") setQuery("");
    else if (action.kind === "connect" && hit) ctx.connect(hit);
    else if (action.kind === "open" && hit) openHost(hit.profileId);
  };

  /** Is the rail on screen? Side-column mode uses the persisted flag; overlay mode
   *  uses the transient push, so the list is what you land on. */
  // Only a touch shell turns the rail into a pushed screen. On the desktop it
  // stays the persisted side column — which merely becomes a full-width overlay
  // when the row is too tight for two columns. Keying `railShown` off
  // railOverlay made an OPEN rail vanish on any desktop window whose content row
  // fell under 640px, with the show-rail button hidden at the same moment.
  const railShown = touch ? railPushed : railOpen;
  const closeRail = () => (touch ? setRailPushed(false) : toggleRail(false));
  const detail = hosts.find((x) => x.profileId === open) || hosts[0];

  // If the host you're looking at is deleted, leave the detail screen. In overlay
  // mode the rail IS the screen and `detail` falls back to hosts[0] — so without
  // this you'd delete one host and be left staring at a different host's detail,
  // with a Connect button on it, and no sign anything changed.
  useEffect(() => {
    if (!touch || !railPushed) return;
    if (open && !hosts.some((x) => x.profileId === open)) setRailPushed(false);
  }, [hosts, open, touch, railPushed]);

  // The detail rail is a full-screen layer the shell's frame stack knows nothing
  // about, so the shell's back gesture can't see it: the edge-swipe only arms for a
  // real frame, and re-tapping the already-active Hosts tab is a no-op. Claim the
  // shell's back while it's up, so both work — otherwise the only exit is a 44px
  // chevron in the one corner a thumb can't reach.
  const setBackHandler = useApp((s) => s.setBackHandler);
  useEffect(() => {
    if (!touch || !railPushed) return;
    const handler = () => {
      setRailPushed(false);
      return true;
    };
    setBackHandler(handler);
    return () => {
      // Only relinquish if it's still ours — a later view may have taken over.
      if (useApp.getState().backHandler === handler) setBackHandler(null);
    };
  }, [touch, railPushed, setBackHandler]);

  const segBtn = (icon: "grid" | "list", val: "cards" | "list") => (
    <button
      onClick={() => setHostsLayout(val)}
      title={t(val === "cards" ? "hosts.viewCards" : "hosts.viewList")}
      aria-label={t(val === "cards" ? "hosts.viewCards" : "hosts.viewList")}
      aria-pressed={hostsLayout === val}
      style={{
        width: rem(30),
        height: rem(26),
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

  // One search box for both shells — the desktop toolbar and the touch row — so
  // the two cannot drift into filtering differently. Only one branch ever mounts,
  // so the ref and the input id stay unambiguous.
  const searchBox = (
    <div
      style={{
        position: "relative",
        flex: touch ? 1 : undefined,
        width: touch ? undefined : tight ? rem(148) : rem(224),
        // The stated width is a floor, not a suggestion: the toolbar wraps, and
        // without this the box shrinks under its label before the row does.
        flexShrink: touch ? 1 : 0,
        minWidth: 0,
        display: "flex",
        alignItems: "center",
        gap: touch ? rem(8) : rem(6),
        height: touch ? SIZE.tapMin : rem(30),
        padding: touch ? `0 ${rem(6)} 0 ${rem(12)}` : `0 ${rem(4)} 0 ${rem(9)}`,
        borderRadius: RADIUS.ctl,
        background: p.bg2,
        // Focus reads on the frame, matching the sort control's open state.
        border: `1px solid ${searchFocus ? p.line2 : p.line}`,
      }}
    >
      <Icon name="search" size={touch ? 17 : 14} color={p.txt3} />
      <input
        {...NO_AUTOCORRECT}
        ref={searchRef}
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        onKeyDown={onSearchKey}
        onFocus={() => setSearchFocus(true)}
        onBlur={() => setSearchFocus(false)}
        placeholder={t("hosts.searchPlaceholder")}
        aria-label={t("hosts.searchPlaceholder")}
        style={{
          flex: 1,
          minWidth: 0,
          height: "100%",
          border: "none",
          outline: "none",
          background: "transparent",
          color: p.txt,
          fontFamily: UI,
          // 16px or iOS zooms the whole page on focus. The desktop has no such
          // problem and 16px there would tower over every other control.
          fontSize: touch ? TEXT.lead : TEXT.base,
        }}
      />
      {query && (
        <button
          onClick={() => {
            setQuery("");
            // Refocusing re-raises the soft keyboard, which is not what tapping ✕
            // on a phone asks for; on the desktop it keeps typing where it was.
            if (!touch) searchRef.current?.focus();
          }}
          aria-label={t("common.clear")}
          style={{
            width: touch ? SIZE.tapMin : rem(22),
            height: touch ? SIZE.tapMin : rem(22),
            flexShrink: 0,
            border: "none",
            background: "transparent",
            color: p.txt3,
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <Icon name="x" size={touch ? 16 : 13} />
        </button>
      )}
      {/* Off-screen rather than display:none — a hidden node is not announced.
          Only speaks while a query is live, so it stays quiet on arrival. */}
      <span
        id={searchStatusId}
        role="status"
        aria-live="polite"
        style={{
          position: "absolute",
          width: 1,
          height: 1,
          overflow: "hidden",
          clip: "rect(0 0 0 0)",
          clipPath: "inset(50%)",
          whiteSpace: "nowrap",
        }}
      >
        {query.trim()
          ? `${t("count.hosts", { count: shown.length })}${
              shown[cursorIdx]
                ? `. ${t("hosts.searchHighlighted", { label: shown[cursorIdx].label })}`
                : ""
            }`
          : ""}
      </span>
    </div>
  );

  // The sort dropdown is the one header control a phone keeps. It renders in the
  // toolbar on desktop and in the search row on touch, where the toolbar itself is
  // gone — only one branch ever mounts, so the ref stays unambiguous.
  const sortControl = (
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
            gap: rem(6),
            height: touch ? SIZE.tapMin : rem(30),
            padding: touch ? `0 ${rem(12)}` : `0 ${rem(10)}`,
            borderRadius: RADIUS.chip,
            // No grey fill — just the frame. Open state reads via a stronger
            // hairline + darker label instead of a bg tint.
            border: `1px solid ${sortOpen ? p.line2 : p.line}`,
            background: "transparent",
            color: sortOpen ? p.txt : p.txt2,
            cursor: "pointer",
            fontSize: TEXT.base,
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
              marginTop: rem(6),
              zIndex: 30,
              background: p.bg3,
              border: `1px solid ${p.line2}`,
              borderRadius: 12,
              padding: rem(5),
              boxShadow: p.shadow,
              width: rem(220),
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
                  gap: rem(9),
                  padding: `${rem(8)} ${rem(10)}`,
                  borderRadius: 8,
                  cursor: "pointer",
                  fontSize: TEXT.base,
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
  );

  return (
    <div ref={rowRef} style={{ flex: 1, display: "flex", minWidth: 0 }}>
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
        {!touch && (
        <div
          style={{
            position: "relative",
            display: "flex",
            alignItems: "center",
            flexWrap: "wrap",
            gap: rem(12),
            rowGap: rem(10),
            padding: `${rem(24)} ${rem(gutter)} ${rem(14)}`,
          }}
        >
          {/* Title + count share one baseline (reference .head); the outer row stays
              center-aligned so the toolbar buttons don't ride the text baseline. */}
          <div style={{ display: "flex", alignItems: "baseline", gap: rem(12), minWidth: 0 }}>
            <h1 style={{ margin: 0, fontSize: narrow ? TEXT.h2 : TEXT.h1, fontWeight: 800, letterSpacing: rem(-0.7) }}>
              {t("hosts.title")}
            </h1>
            <span
              style={{
                fontFamily: MONO,
                fontSize: TEXT.small,
                color: p.txt3,
                whiteSpace: "nowrap",
              }}
            >
              {/* Whatever narrowed the list — a query or a tag/group chip — count
                  what is on screen: "6 hosts" over three visible cards reads as a
                  rendering bug either way. */}
              {t("count.hosts", {
                count:
                  query.trim() || hostFilter !== HOST_FILTER_ALL ? shown.length : hosts.length,
              })}
              {sessions ? ` · ${t("count.sessions", { count: sessions })}` : ""}
            </span>
          </div>
          <div style={{ flex: 1 }} />
          {/* The desktop's filter box. ⌘K stays the launcher; this narrows the
              list in place, which is what people reach for on the screen that
              shows the list. */}
          {searchBox}
          {/* Header actions are quiet text, per the reference (.act / .new) — a
              filled primary here becomes a glaring near-white block in dark mode. */}
          <button
            title={t("hosts.importSshConfig")}
            aria-label={t("hosts.importSshConfig")}
            onClick={() => ctx.openImport()}
            style={{
              ...BTN_RESET,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              gap: rem(5),
              // `tight` collapses this to an icon on any phone, so 30px would
              // leave a 14px target.
              height: touch ? SIZE.tapMin : rem(30),
              minWidth: touch ? SIZE.tapMin : undefined,
              fontSize: TEXT.base,
              fontWeight: 600,
              color: p.txt3,
              cursor: "pointer",
            }}
          >
            <Icon name="download" size={14} />
            {!tight && t("hosts.importSshConfig")}
          </button>
          {/* The list half of this toggle can't render on touch (see `layout`), but
              the whole toolbar is desktop-only anyway. */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              height: rem(30),
              background: "transparent",
              border: `1px solid ${p.line}`,
              borderRadius: RADIUS.chip,
              padding: rem(1),
              gap: rem(2),
            }}
          >
            {segBtn("grid", "cards")}
            {segBtn("list", "list")}
          </div>
          {sortControl}
          {/* Touch gets the FAB below instead: the primary action belongs in the
              thumb zone, not in the one corner of a phone a thumb can't reach. */}
          {(
            <button
              title={t("hosts.newHost")}
              onClick={() => ctx.onNewHost()}
              style={{
                ...BTN_RESET,
                display: "flex",
                alignItems: "center",
                gap: rem(5),
                height: rem(30),
                fontSize: TEXT.base,
                fontWeight: 700,
                color: p.accentText,
                cursor: "pointer",
              }}
            >
              <Icon name="plus" size={15} />
              {!tight && t("hosts.newHost")}
            </button>
          )}
          {/* Overlay mode has no "show the rail" affordance: the rail is a detail
              screen there, and you get to it by choosing a host. */}
          {!touch && !railOpen && (
            <button
              title={t("common.show")}
              aria-label={t("common.show")}
              onClick={() => toggleRail(true)}
              style={{
                width: rem(30),
                height: rem(30),
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
        )}

        {/* Touch: the filter box gets its own full-width row — the desktop toolbar
            is gone here, and the sort control rides along with it. */}
        {touch && (
          <div style={{ padding: `0 ${rem(gutter)} ${rem(10)}`, display: "flex", alignItems: "center", gap: rem(10) }}>
            {searchBox}
            {sortControl}
          </div>
        )}

        <div
          style={{
            position: "relative",
            display: "flex",
            gap: rem(14),
            padding: `0 ${rem(gutter)} ${rem(10)}`,
            alignItems: "center",
            // Touch adds group chips to the tag chips, which would wrap this strip
            // into three rows of a screen that has none to spare — scroll instead,
            // as the phone list always did.
            ...(touch
              ? {
                  flexWrap: "nowrap" as const,
                  overflowX: "auto" as const,
                  overscrollBehaviorX: "contain" as const,
                  WebkitOverflowScrolling: "touch" as const,
                  scrollbarWidth: "none" as const,
                }
              : { flexWrap: "wrap" as const }),
          }}
        >
          {activeGroup && (
            <span
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: rem(5),
                fontSize: TEXT.base,
                fontWeight: 700,
                color: p.txt,
                // The strip scrolls rather than wraps on touch; without this the
                // scope token squashes to one word per line instead.
                flexShrink: 0,
                whiteSpace: "nowrap",
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
                  padding: rem(2),
                  cursor: "pointer",
                  color: p.txt3,
                }}
              >
                <Icon name="x" size={12} />
              </button>
            </span>
          )}
          {/* Touch: group chips. On the desktop the Sidebar owns group scoping
              (Shell's NavGroup → goFiltered(groupId)) — and the mobile shell has no
              sidebar, so without these a 5-group vault simply cannot be scoped by
              group on a phone, and the activeGroup token above is unreachable. */}
          {touch &&
            groups.map((g) => {
              const on = hostFilter === g.groupId;
              return (
                <button
                  key={g.groupId}
                  onClick={() => setHostFilter(g.groupId)}
                  aria-pressed={on}
                  style={{
                    flexShrink: 0,
                    display: "inline-flex",
                    alignItems: "center",
                    gap: rem(6),
                    minHeight: SIZE.tapMin,
                    fontFamily: UI,
                    fontSize: TEXT.base,
                    fontWeight: 600,
                    cursor: "pointer",
                    padding: `${rem(2)} ${rem(1)} ${rem(5)}`,
                    border: "none",
                    borderRadius: 0,
                    borderBottom: `2px solid ${on ? p.accent : "transparent"}`,
                    background: "transparent",
                    color: on ? p.txt : p.txt3,
                  }}
                >
                  <Icon name="folder" size={13} color={on ? p.txt2 : p.txt3} />
                  {g.label}
                </button>
              );
            })}
          {touch && groups.length > 0 && (
            <span
              aria-hidden
              style={{ flexShrink: 0, alignSelf: "stretch", width: 1, margin: `${rem(5)} 0`, background: p.line }}
            />
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
                  fontSize: TEXT.base,
                  fontWeight: 600,
                  cursor: "pointer",
                  padding: `${rem(2)} ${rem(1)} ${rem(5)}`,
                  minHeight: touch ? SIZE.tapMin : undefined,
                  flexShrink: 0,
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
                fontSize: TEXT.base,
                fontWeight: 600,
                cursor: "pointer",
                padding: `${rem(2)} ${rem(1)} ${rem(5)}`,
                minHeight: touch ? SIZE.tapMin : undefined,
                flexShrink: 0,
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
                marginLeft: rem(2),
                fontSize: TEXT.base,
                fontWeight: 600,
                cursor: "pointer",
                // Same as the chips beside it: this strip scrolls rather than wraps
                // on touch, so an item that can shrink wraps to three lines instead.
                flexShrink: 0,
                whiteSpace: "nowrap",
                minHeight: touch ? SIZE.tapMin : undefined,
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

        <div
          ref={listRef}
          onTouchStart={touch ? onPullStart : undefined}
          onTouchMove={touch ? onPullMove : undefined}
          onTouchEnd={touch ? onPullEnd : undefined}
          style={{
            position: "relative",
            flex: 1,
            overflow: "auto",
            // Without this the WebView rubber-bands this scroller at scrollTop 0 at
            // the same time as the pull transform, and the content travels twice
            // as far as the finger. (html/body's overscroll-behavior does not
            // cascade into an inner scroller.)
            overscrollBehaviorY: "contain",
            padding: `${rem(6)} ${rem(gutter)} ${rem(76)}`,
            transform: pull ? `translateY(${pull}px)` : undefined,
            transition: pulling ? "none" : "transform .2s",
          }}
        >
          {/* Pull-to-refresh spinner, revealed by the drag above the list. */}
          {touch && pull > 0 && (
            <div
              style={{
                position: "absolute",
                top: rem(-34),
                left: 0,
                right: 0,
                display: "flex",
                justifyContent: "center",
                opacity: Math.min(1, pull / 56),
              }}
            >
              <Spinner size={18} />
            </div>
          )}
          {loading && hosts.length === 0 ? (
            // The vault is still loading — NOT empty. Branching on hosts.length
            // alone flashed "This vault is empty / Create a host" on every unlock
            // while reloadVault was still in flight.
            <div
              style={{
                height: "60%",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <Spinner size={22} />
            </div>
          ) : hosts.length === 0 ? (
            <div
              style={{
                height: "80%",
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                justifyContent: "center",
                gap: rem(14),
                color: p.txt3,
              }}
            >
              <span
                style={{
                  width: rem(56),
                  height: rem(56),
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
                <div style={{ fontSize: TEXT.lead, fontWeight: 700, color: p.txt }}>
                  {t("hosts.emptyVaultTitle")}
                </div>
                <div style={{ fontSize: TEXT.base, color: p.txt3, marginTop: rem(3) }}>
                  {t("hosts.emptyVaultHint")}
                </div>
              </div>
              <div style={{ display: "flex", gap: rem(10) }}>
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
                gap: rem(12),
                color: p.txt3,
              }}
            >
              <Icon name="search" size={30} color={p.txt3} />
              {/* A query that matches nothing is not the same dead end as a tag
                  that holds nothing — saying "no hosts tagged prod" to someone who
                  just typed "prd" sends them to reset a filter that was never the
                  problem. Whichever narrowed the list is what gets offered back. */}
              <span style={{ fontSize: TEXT.body }}>
                {query.trim()
                  ? t("hosts.noHostsForQuery", { query: query.trim() })
                  : hostFilter === "__untagged"
                    ? t("hosts.allHostsTagged")
                    : t("hosts.noHostsForTag", { tag: hostFilter })}
              </span>
              {query.trim() ? (
                <Btn
                  size="sm"
                  variant="ghost"
                  onClick={() => {
                    setQuery("");
                    if (!touch) searchRef.current?.focus();
                  }}
                >
                  {t("common.clear")}
                </Btn>
              ) : (
                <Btn size="sm" variant="ghost" onClick={() => setHostFilter(HOST_FILTER_ALL)}>
                  {t("hosts.resetFilter")}
                </Btn>
              )}
            </div>
          ) : layout === "cards" ? (
            <div
              className="uh-stagger"
              style={{
                display: "grid",
                // One column on touch, at any width. auto-fill inverts on a phone:
                // more width means more columns, so a 248px track appears in
                // landscape and squeezes the card's meta line — the auth label, the
                // security-relevant datum — down to nothing. The card also carries
                // permanent Connect/SFTP buttons there, which a 248px track cannot
                // hold alongside anything readable.
                gridTemplateColumns: touch
                  ? "1fr"
                  : `repeat(auto-fill, minmax(${rem(248)}, 1fr))`,
                gap: rem(12),
              }}
            >
              {shown.map((h, i) => (
                <HostCard
                  key={h.profileId}
                  h={h}
                  selected={sel.includes(h.profileId)}
                  active={open === h.profileId}
                  cursor={searching && i === cursorIdx}
                  session={activeIds.has(h.profileId)}
                  onToggle={() => toggle(h.profileId)}
                  onOpen={() => openHost(h.profileId)}
                  onConnect={() => ctx.connect(h)}
                  onSftp={() => void ctx.connectSftp(h)}
                  onMenu={(e) => {
                    e.preventDefault();
                    setMenu({ x: e.clientX, y: e.clientY, id: h.profileId, sub: false });
                  }}
                  draggable={canDragHosts}
                  onDragStart={(e) => beginHostDrag(h.profileId, e)}
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
                  cursor={searching && i === cursorIdx}
                  session={activeIds.has(h.profileId)}
                  first={i === 0}
                  onToggle={() => toggle(h.profileId)}
                  onOpen={() => openHost(h.profileId)}
                  onConnect={() => ctx.connect(h)}
                  onMenu={(e) => {
                    e.preventDefault();
                    setMenu({ x: e.clientX, y: e.clientY, id: h.profileId, sub: false });
                  }}
                  draggable={canDragHosts}
                  onDragStart={(e) => beginHostDrag(h.profileId, e)}
                />
              ))}
            </div>
          )}
        </div>

        {sel.length > 0 && (
          <div
            style={{
              position: "absolute",
              left: gutter,
              right: gutter,
              bottom: rem(16),
              // minHeight (not height) + wrap: in RU the destructive Delete + clear-✕
              // can't fit one row inside overflow:hidden main — let them wrap, don't clip.
              minHeight: rem(52),
              borderRadius: 12,
              background: p.bg0,
              border: `1px solid ${p.line2}`,
              boxShadow: p.shadow,
              display: "flex",
              alignItems: "center",
              flexWrap: "wrap",
              gap: rem(12),
              rowGap: rem(8),
              padding: `0 ${rem(14)}`,
              zIndex: 5,
            }}
          >
            <span
              style={{
                width: rem(26),
                height: rem(26),
                borderRadius: 8,
                background: p.accent,
                color: p.accentInk,
                fontFamily: MONO,
                fontWeight: 700,
                fontSize: TEXT.base,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              {sel.length}
            </span>
            <span style={{ fontSize: TEXT.base, fontWeight: 600 }}>
              {t("count.hostsSelected", { count: sel.length })}
            </span>
            <span style={{ fontSize: TEXT.small, color: p.txt3 }}>{t("hosts.runInParallel")}</span>
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
                width: rem(28),
                height: rem(28),
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

        {/* Touch: the primary action as a thumb-zone FAB. Hidden while the detail
            rail is up — it belongs to the list, and it would sit over the rail's
            own Connect. The list reserves 76px of bottom padding for it.

            NOT a filled accent block. In the mono family the accent IS ink —
            near-black in the light twin, near-WHITE in the dark one — so filling a
            56px disc with it puts a glaring white blob over a near-black list and
            drags every eye to it. The header's New host makes the same call for the
            same reason ("a filled primary here becomes a glaring near-white block
            in dark mode"); this is that rule at 56px. A FAB is primary by size and
            position — alone, in the thumb zone — not by shouting. */}
        {touch && !railShown && !sel.length && (
          <button
            onClick={() => ctx.onNewHost()}
            aria-label={t("hosts.newHost")}
            style={{
              position: "absolute",
              right: rem(18),
              bottom: rem(20),
              width: rem(56),
              height: rem(56),
              borderRadius: RADIUS.menu,
              background: p.bg2,
              border: `1px solid ${p.line2}`,
              color: p.txt,
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              boxShadow: p.shadow,
              zIndex: 5,
            }}
          >
            <Icon name="plus" size={26} stroke={2.2} />
          </button>
        )}
      </div>

      {/* right rail — a fixed-width side column normally; a full-width overlay over
          the list when the window is too narrow to show both side by side */}
      {railShown && (
        <div
          style={{
            flexShrink: 0,
            background: p.bg0,
            display: "flex",
            flexDirection: "column",
            padding: rem(14),
            ...(railOverlay
              ? { position: "absolute", inset: 0, width: "100%", zIndex: 6 }
              : { width: rem(railW), position: "relative", borderLeft: `1px solid ${p.line}` }),
          }}
        >
          {!railOverlay && <ResizeHandle side="left" onDrag={resizeRail} />}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: rem(8),
              borderBottom: `1px solid ${p.line}`,
              marginBottom: rem(14),
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
              title={touch ? t("common.back") : t("common.hide")}
              aria-label={touch ? t("common.back") : t("common.hide")}
              onClick={closeRail}
              style={{
                // In overlay mode this is the only way back to the list, so it has
                // to clear the touch minimum rather than the desktop's 30px.
                width: touch ? SIZE.tapMin : rem(30),
                height: touch ? SIZE.tapMin : rem(30),
                flexShrink: 0,
                borderRadius: RADIUS.chip,
                border: "none",
                background: "transparent",
                color: p.txt3,
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <Icon name={touch ? "cl" : "cr"} size={touch ? 20 : 15} />
            </button>
          </div>
          <div style={{ flex: 1, minHeight: 0, overflow: "auto" }}>
            {rail === "detail" ? (
              detail ? (
                <HostDetail h={detail} session={activeIds.has(detail.profileId)} />
              ) : (
                <div style={{ fontSize: TEXT.base, color: p.txt3 }}>{t("hosts.selectHost")}</div>
              )
            ) : (
              <SessionsRail />
            )}
          </div>
        </div>
      )}

      {(() => {
        if (!menu) return null;
        const mh = hosts.find((h) => h.profileId === menu.id);
        if (!mh) return null;
        const toggleGroup = (g: (typeof groups)[number], member: boolean) => {
          const op = member
            ? removeHostsFromGroup(g.groupId, [mh.profileId]).then(() =>
                ctx.toast(t("hosts.bulk.removedFromGroup", { name: g.label }), "ok"),
              )
            : addHostsToGroup(g.groupId, [mh.profileId]).then(() =>
                ctx.toast(t("hosts.bulk.addedToGroup", { name: g.label }), "ok"),
              );
          void op.catch((e) => ctx.toast(apiErrorMessage(e), "err"));
        };
        const items: MenuItem[] = menu.sub
          ? [
              { icon: "cl", label: t("common.back"), onClick: () => setMenu({ ...menu, sub: false }) },
              // ✓ = already a member; clicking toggles (bulk-bar semantics: a host
              // may sit in several groups, so this adds/removes, never moves).
              ...groups.map((g): MenuItem => {
                const member = g.memberIds.includes(mh.profileId);
                return {
                  icon: member ? "check" : "folder",
                  label: g.label,
                  onClick: () => toggleGroup(g, member),
                };
              }),
              {
                icon: "sliders",
                label: t("hosts.menu.manageGroups"),
                onClick: () => setGroupsModal(true),
              },
            ]
          : [
              { icon: "terminal", label: t("hosts.connect"), onClick: () => ctx.connect(mh) },
              { icon: "folders", label: t("nav.sftp"), onClick: () => void ctx.connectSftp(mh) },
              {
                icon: "copy",
                label: t("hosts.menu.copyAddress"),
                // Dragging a card is what took the old way of getting this out
                // of the screen — you cannot select text on a `draggable`
                // element. This is better than what it replaces: it works in the
                // row layout too, where the address is ellipsised, and it does
                // not depend on hitting 12px of mono type with the pointer.
                onClick: () =>
                  void writeText(hostAddress(mh))
                    .then(() => ctx.toast(t("hosts.addressCopied"), "ok"))
                    .catch((e) => ctx.toast(apiErrorMessage(e), "err")),
              },
              {
                icon: "folder",
                label: t("hosts.menu.addToGroup"),
                onClick: () => setMenu({ ...menu, sub: true }),
              },
            ];
        return (
          <ContextMenu
            x={menu.x}
            y={menu.y}
            title={mh.label}
            items={items}
            onClose={() => setMenu(null)}
          />
        );
      })()}
    </div>
  );
}
