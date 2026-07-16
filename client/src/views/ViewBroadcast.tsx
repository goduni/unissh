// Broadcast — cluster-ssh: one synchronized input mirrored to every live host.
// Pixel-faithful port of view-broadcast.jsx. The prototype's scripted typing/
// mock tiles are replaced with a real broadcast session: on "Connect" we
// build MultiExecTargets from the current vault's hosts (skipping promptPassword
// profiles, which can't be opened headlessly) and call api.broadcastOpen. Each
// tile mirrors its host's live PTY output; the bottom bar fans the typed command
// out to all open hosts via api.broadcastWriteAll. Status comes ONLY from the
// live terminals (statuses[i].connected) — no fake online/ping/cipher.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "@/i18n";
import { usePalette } from "@/theme/ThemeProvider";
import { MONO } from "@/theme/tokens";
import { Btn, Icon, NO_AUTOCORRECT, StatusDot } from "@/components/primitives";
import { useApp, type PendingMismatch } from "@/store/app";
import { useIsMobile, useNarrow } from "@/store/responsive";
import { toast } from "@/store/toast";
import { guard } from "@/store/action";
import * as api from "@/bridge/api";
import {
  apiErrorMessage,
  mismatchFromError,
  type BroadcastEvent,
  type BroadcastHostStatus,
  type ConnectionProfile,
  type MultiExecTarget,
} from "@/bridge/types";

const TERM = "xterm-256color";
const COLS = 80;
const ROWS = 24;
const TAIL_LINES = 6;

// Obviously-destructive verbs — typing one into a fan-out-to-many-live-hosts bar
// always re-confirms, even after the session's first send has been confirmed.
const BROADCAST_DANGER =
  /(\brm\s+-\w*[rf]|\breboot\b|\bshutdown\b|\bhalt\b|\bpoweroff\b|\bmkfs|\bdd\s+if=|:\(\)\s*\{|>\s*\/dev\/)/i;

/** Keep only the last N non-trailing-empty lines of a mirrored buffer. */
function tail(buf: string, n: number): string[] {
  const lines = buf.split(/\r?\n/);
  while (lines.length > 1 && lines[lines.length - 1] === "") lines.pop();
  return lines.slice(-n);
}

interface OpenedHost {
  index: number;
  profile: ConnectionProfile;
  status: BroadcastHostStatus;
}

function HostTile({
  host,
  output,
  onReviewMismatch,
}: {
  host: OpenedHost;
  output: string;
  /** The host failed to open because its pinned key changed — offer the Known
   *  hosts ceremony with the PARSED failing-hop host/port/fingerprint (a jump
   *  host isn't the profile), so the caller pins the right key. */
  onReviewMismatch: (host: OpenedHost, m: PendingMismatch) => void;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const off = !host.status.connected;
  const lines = off ? [] : tail(output, TAIL_LINES);
  const mismatch = off ? mismatchFromError(host.status.error) : null;
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        borderRadius: 12,
        overflow: "hidden",
        border: `1px solid ${p.line}`,
        background: p.bg0,
        opacity: off ? 0.85 : 1,
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          padding: "8px 12px",
          borderBottom: `1px solid ${p.line}`,
        }}
      >
        <StatusDot status={off ? (mismatch ? "error" : "offline") : "online"} size={7} />
        <span
          style={{
            fontFamily: MONO,
            fontSize: 13,
            fontWeight: 600,
            whiteSpace: "nowrap",
            overflow: "hidden",
            textOverflow: "ellipsis",
            minWidth: 0,
          }}
        >
          {host.profile.label}
        </span>
        <div style={{ flex: 1 }} />
        <span style={{ fontFamily: MONO, fontSize: 11, color: off ? p.txt3 : p.green }}>
          {off ? t("broadcast.offline") : t("broadcast.mirrored")}
        </span>
      </div>
      <div
        style={{
          flex: 1,
          padding: "11px 13px",
          fontFamily: MONO,
          fontSize: 12,
          lineHeight: 1.7,
          minHeight: 118,
          whiteSpace: "pre-wrap",
          wordBreak: "break-all",
        }}
      >
        {off ? (
          <div style={{ color: p.red }}>
            ssh: {host.status.error || t("broadcast.connectionRefused")}
            {mismatch && (
              <div style={{ marginTop: 8 }}>
                <Btn
                  variant="danger"
                  size="sm"
                  icon="fingerprint"
                  // Security label must stay fully readable in the clipped grid tile — wrap, don't ellipsize.
                  wrap
                  onClick={() => onReviewMismatch(host, mismatch)}
                >
                  {t("known.changedReview")}
                </Btn>
              </div>
            )}
          </div>
        ) : lines.length === 0 ? (
          <div style={{ color: p.txt3, fontStyle: "italic" }}>{t("broadcast.awaitingOutput")}</div>
        ) : (
          lines.map((ln, i) => (
            <div key={i} style={{ color: p.txt }}>
              {ln || " "}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

export function ViewBroadcast() {
  const p = usePalette();
  const { t } = useTranslation();
  const isMobile = useIsMobile();
  const narrow = useNarrow();
  const hosts = useApp((s) => s.hosts);
  const vaultId = useApp((s) => s.vaultId);
  const fleetSelection = useApp((s) => s.fleetSelection);
  const setFleetSelection = useApp((s) => s.setFleetSelection);

  // Explicit selection carried from the hosts view — without one (empty), broadcast
  // targets every vault host (the historical behaviour).
  const scoped = useMemo(() => {
    if (!fleetSelection.length) return hosts;
    const sel = new Set(fleetSelection);
    return hosts.filter((h) => sel.has(h.profileId));
  }, [hosts, fleetSelection]);

  // The explicit selection scope is one-shot: leaving the view clears it, so a
  // later visit can never silently connect a stale selection (or, worse, imply
  // a narrow scope while actually connecting the whole vault). BUT the host-key
  // "review" detour navigates to the Known-hosts view (route "known") and expects
  // the selection back on return — so clear only when leaving for anything else.
  useEffect(
    () => () => {
      if (useApp.getState().route !== "known") useApp.getState().setFleetSelection([]);
    },
    [],
  );

  const [bcId, setBcId] = useState<string | null>(null);
  const [opened, setOpened] = useState<OpenedHost[]>([]);
  const [outputs, setOutputs] = useState<Record<number, string>>({});
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [caret, setCaret] = useState(true);

  const bcIdRef = useRef<string | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);

  // blinking caret (prototype cadence)
  useEffect(() => {
    const t = setInterval(() => setCaret((c) => !c), 520);
    return () => clearInterval(t);
  }, []);

  // close the broadcast on unmount
  useEffect(() => {
    return () => {
      const id = bcIdRef.current;
      if (id) {
        void api.broadcastClose(id);
        useApp.getState().removeBroadcast(id);
      }
    };
  }, []);

  // Guard nav away from this view while any host is live: leaving unmounts the view
  // and tears the whole broadcast down, so route it through a confirm first. Cleared
  // on unmount (and re-registered whenever the live set changes) so it never goes stale.
  //
  // Desktop only, because the teardown is a property of the DESKTOP router: it swaps
  // the whole view tree by route. The phone shell keeps this view mounted for the
  // session (like the terminal), so nothing here is ever torn down by navigation —
  // and a guard that fires anyway is worse than none: every ctx.go() would raise a
  // danger-styled "this will close your sessions" confirm for a navigation that
  // closes nothing, and confirming it clears the guard for good.
  useEffect(() => {
    if (isMobile) return;
    const app = useApp.getState();
    app.setNavGuard(() =>
      opened.some((h) => h.status.connected)
        ? {
            title: t("broadcast.leaveTitle"),
            body: t("broadcast.leaveBody"),
            confirmLabel: t("broadcast.leaveConfirm"),
          }
        : null,
    );
    return () => app.setNavGuard(null);
  }, [opened, t, isMobile]);

  // A vault switch tears down this broadcast's backend session (store.setVault
  // closes every registered broadcast), so reset local state on a vault change so
  // the view doesn't keep showing the previous vault's hosts. Skips initial mount.
  const firstVault = useRef(true);
  useEffect(() => {
    if (firstVault.current) {
      firstVault.current = false;
      return;
    }
    const id = bcIdRef.current;
    if (id) useApp.getState().removeBroadcast(id); // already closed by setVault
    bcIdRef.current = null;
    setBcId(null);
    setOpened([]);
    setOutputs({});
    setTyped("");
  }, [vaultId]);

  const liveCount = opened.filter((h) => h.status.connected).length;
  // Hosts the Connect action will actually open — the button carries this count.
  const readyCount = scoped.filter((h) => h.auth.type !== "promptPassword").length;

  // Reviewing a mismatch navigates to the Known-hosts view, which unmounts this
  // view and closes the whole broadcast session. If any host is still live, ask
  // first; otherwise there's nothing to lose, so navigate straight through.
  const onReviewMismatch = useCallback(
    (h: OpenedHost, m: PendingMismatch) => {
      const app = useApp.getState();
      const pin: PendingMismatch = {
        host: m.host || h.profile.host,
        port: m.port || h.profile.port,
        fingerprint: m.fingerprint,
      };
      if (liveCount > 0) {
        app.setConfirm({
          title: t("broadcast.reviewDisconnectTitle"),
          body: t("broadcast.reviewDisconnectBody"),
          danger: true,
          confirmLabel: t("broadcast.reviewDisconnectConfirm"),
          icon: "alert",
          onConfirm: () => app.reviewMismatch(pin),
        });
      } else {
        app.reviewMismatch(pin);
      }
    },
    [liveCount, t],
  );

  const connect = async () => {
    if (busy || bcId) return;
    if (!vaultId) {
      toast(t("broadcast.noActiveVault"), "err");
      return;
    }
    const usable = scoped.filter((h) => h.auth.type !== "promptPassword");
    if (usable.length === 0) {
      toast(t("broadcast.noHosts"), "warn");
      return;
    }
    setBusy(true);
    // Resolve each host's connect auth (Personal → in-core binding + anti-redirect),
    // keeping resolved hosts index-aligned with the targets we open. Unbound/
    // redirected personal hosts are shown as disconnected, not opened.
    const resolvedHosts: { profile: ConnectionProfile; target: MultiExecTarget }[] = [];
    const failedHosts: { profile: ConnectionProfile; error: string }[] = [];
    for (const h of usable) {
      try {
        const { user, auth } = await api.resolveConnectAuth(h, vaultId);
        resolvedHosts.push({
          profile: h,
          target: { host: h.host, port: h.port, user, auth, jumps: h.jumps },
        });
      } catch (e) {
        failedHosts.push({ profile: h, error: apiErrorMessage(e) });
      }
    }
    if (resolvedHosts.length === 0) {
      setBusy(false);
      toast(t("broadcast.noHosts"), "warn");
      return;
    }
    const targets: MultiExecTarget[] = resolvedHosts.map((r) => r.target);
    try {
      await guard(async () => {
        const onEvent = (e: BroadcastEvent) => {
          if (e.type === "data") {
            const text = new TextDecoder().decode(new Uint8Array(e.bytes));
            setOutputs((prev) => ({ ...prev, [e.index]: (prev[e.index] ?? "") + text }));
          } else {
            setOpened((prev) =>
              prev.map((h) =>
                h.index === e.index
                  ? { ...h, status: { ...h.status, connected: false, error: t("broadcast.closedCode", { code: e.exit }) } }
                  : h,
              ),
            );
          }
        };
        const res = await api.broadcastOpen(targets, TERM, COLS, ROWS, onEvent);
        // If the vault switched while we were opening, this broadcast belongs to the
        // previous vault's hosts — close it instead of registering it under the new
        // one (the vault-change effect already reset our local state).
        if (useApp.getState().vaultId !== vaultId) {
          void api.broadcastClose(res.id);
          return;
        }
        const map = new Map(res.statuses.map((s) => [s.index, s]));
        const list: OpenedHost[] = resolvedHosts.map((r, i) => ({
          index: i,
          profile: r.profile,
          status: map.get(i) ?? {
            host: r.profile.host,
            index: i,
            connected: false,
            error: t("broadcast.noStatus"),
          },
        }));
        // Unbound/redirected personal hosts: shown as disconnected (never opened).
        failedHosts.forEach((f, j) => {
          const idx = resolvedHosts.length + j;
          list.push({
            index: idx,
            profile: f.profile,
            status: { host: f.profile.host, index: idx, connected: false, error: f.error },
          });
        });
        bcIdRef.current = res.id;
        useApp.getState().addBroadcast(res.id);
        setBcId(res.id);
        setOpened(list);
        const okN = list.filter((h) => h.status.connected).length;
        toast(
          t("broadcast.opened", { ok: okN, hosts: t("count.hosts", { count: list.length }) }),
          okN > 0 ? "ok" : "warn",
        );
      });
    } finally {
      setBusy(false);
    }
  };

  const sentOnce = useRef(false);
  const doSend = async () => {
    const id = bcIdRef.current;
    if (!id || liveCount === 0 || typed.length === 0) return;
    const data = Array.from(new TextEncoder().encode(typed + "\n"));
    await guard(async () => {
      await api.broadcastWriteAll(id, data);
      setTyped("");
    });
    inputRef.current?.focus();
  };
  // Fanning input out to many LIVE hosts is irreversible: confirm the FIRST send of a
  // session (sober), and re-confirm (loud/danger) whenever the command looks
  // destructive — no silent blast to the whole fleet.
  const send = () => {
    if (liveCount === 0 || typed.length === 0) return;
    const dangerous = BROADCAST_DANGER.test(typed);
    if (sentOnce.current && !dangerous) {
      void doSend();
      return;
    }
    useApp.getState().setConfirm({
      title: dangerous ? t("broadcast.dangerTitle") : t("broadcast.sendConfirmTitle"),
      body: dangerous
        ? t("broadcast.dangerBody", { count: liveCount })
        : t("broadcast.sendConfirmBody", { count: liveCount }),
      danger: dangerous,
      icon: dangerous ? "alert" : "radio",
      confirmLabel: t("broadcast.sendConfirm"),
      onConfirm: () => {
        sentOnce.current = true;
        void doSend();
      },
    });
  };

  const failed = opened.filter((h) => !h.status.connected);

  return (
    <div
      className="uh-view"
      style={{
        flex: 1,
        display: "flex",
        flexDirection: "column",
        minWidth: 0,
        background: p.bg0,
        overflow: "hidden",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 10,
          padding: isMobile ? "16px 14px 12px" : "16px 22px 12px",
          // Always wrap so Connect drops to a second row instead of clipping below ~640px.
          flexWrap: "wrap",
        }}
      >
        <Icon name="radio" size={20} color={p.accentText} />
        <h1
          style={{
            margin: 0,
            fontSize: 28,
            fontWeight: 800,
            letterSpacing: -0.7,
            whiteSpace: "nowrap",
            flexShrink: 0,
          }}
        >
          {t("nav.broadcast")}
        </h1>
        <span
          style={{
            fontFamily: MONO,
            fontSize: 12,
            color: p.txt2,
            whiteSpace: "nowrap",
            // Shrink+ellipsize the status so the selection chip and Connect stay reachable.
            overflow: "hidden",
            textOverflow: "ellipsis",
            minWidth: 0,
          }}
        >
          {bcId
            ? t("broadcast.mirroring", { hosts: t("count.hosts", { count: liveCount }) })
            : t("count.hostsReady", { count: readyCount })}
        </span>
        {!bcId && fleetSelection.length > 0 && (
          // Explicit selection scope — dismissible chip; ✕ falls back to all vault hosts.
          <span
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 7,
              fontFamily: MONO,
              fontSize: 12,
              color: p.txt,
              background: "transparent",
              border: `1px solid ${p.line}`,
              borderRadius: 20,
              padding: "2px 6px 2px 9px",
              whiteSpace: "nowrap",
            }}
          >
            {t("count.hostsSelected", { count: scoped.length })}
            <button
              title={t("broadcast.scopeClear")}
              aria-label={t("broadcast.scopeClear")}
              onClick={() => setFleetSelection([])}
              style={{
                width: 16,
                height: 16,
                display: "inline-flex",
                alignItems: "center",
                justifyContent: "center",
                borderRadius: "50%",
                border: "none",
                background: "transparent",
                color: p.txt2,
                cursor: "pointer",
                padding: 0,
              }}
            >
              <Icon name="x" size={11} />
            </button>
          </span>
        )}
        <div style={{ flex: 1 }} />
        {/* No "sync input" switch here: input routing is always all-panes (the core
            only exposes broadcastWriteAll), and a decorative always-on toggle would
            promise a control that doesn't exist. The "mirroring N hosts" chip above
            already states the mode. */}
        {!bcId && scoped.length > 0 && readyCount === 0 && (
          // The Connect button is disabled at zero ready hosts; say WHY here so
          // broadcast.noHosts (otherwise unreachable behind the disabled button)
          // is actually surfaced.
          <span
            style={{
              fontSize: 12,
              color: p.txt3,
              whiteSpace: "nowrap",
              overflow: "hidden",
              textOverflow: "ellipsis",
              minWidth: 0,
            }}
          >
            {t("broadcast.noHosts")}
          </span>
        )}
        {!bcId && (
          <Btn icon="radio" size="sm" onClick={connect} disabled={busy || readyCount === 0}>
            {busy ? t("broadcast.connecting") : t("broadcast.connectN", { count: readyCount })}
          </Btn>
        )}
      </div>

      <div style={{ flex: 1, overflow: "auto", padding: isMobile ? "0 14px 14px" : "0 22px 14px" }}>
        {bcId && opened.length > 0 ? (
          <div
            style={{
              display: "grid",
              gridTemplateColumns: isMobile
                ? "repeat(auto-fill, minmax(150px, 1fr))"
                : "repeat(auto-fill, minmax(240px, 1fr))",
              gap: 12,
            }}
          >
            {opened.map((h) => (
              <HostTile
                key={h.index}
                host={h}
                output={outputs[h.index] ?? ""}
                onReviewMismatch={onReviewMismatch}
              />
            ))}
          </div>
        ) : (
          <div
            style={{
              minHeight: 280,
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              justifyContent: "center",
              gap: 12,
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
              <Icon name="radio" size={26} color={p.txt3} />
            </span>
            <div style={{ textAlign: "center" }}>
              <div style={{ fontSize: 16, fontWeight: 700, color: p.txt }}>{t("broadcast.notStarted")}</div>
              <div style={{ fontSize: 13, color: p.txt3, marginTop: 3 }}>
                {t("broadcast.notStartedHint")}
              </div>
            </div>
            <Btn size="sm" icon="radio" onClick={connect} disabled={busy || readyCount === 0}>
              {busy ? t("broadcast.connecting") : t("broadcast.connectN", { count: readyCount })}
            </Btn>
          </div>
        )}
      </div>

      {/* synchronized input */}
      <div style={{ padding: isMobile ? "12px 14px 18px" : "12px 22px 18px", borderTop: `1px solid ${p.line}`, background: p.bg1 }}>
        <div
          style={{
            display: "flex",
            flexDirection: narrow ? "column" : "row",
            alignItems: narrow ? "stretch" : "center",
            gap: 12,
            height: narrow ? undefined : 50,
            padding: isMobile ? "12px 14px" : "0 16px",
            borderRadius: 12,
            background: p.bg0,
            border: `1px solid ${p.line2}`,
            boxShadow: "none",
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 12,
              alignSelf: narrow ? "stretch" : undefined,
              flex: narrow ? undefined : 1,
            }}
          >
          <Icon name="radio" size={17} color={p.accentText} />
          <div style={{ flex: 1, position: "relative", display: "flex", alignItems: "center" }}>
            <input
              ref={inputRef}
              {...NO_AUTOCORRECT}
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  void send();
                }
              }}
              disabled={!bcId || liveCount === 0}
              placeholder={bcId ? "" : t("broadcast.inputPlaceholder")}
              style={{
                flex: 1,
                background: "transparent",
                border: "none",
                outline: "none",
                fontFamily: MONO,
                fontSize: 16,
                color: p.txt,
                caretColor: "transparent",
              }}
            />
            {bcId && liveCount > 0 && (
              <span
                style={{
                  position: "absolute",
                  pointerEvents: "none",
                  fontFamily: MONO,
                  fontSize: 16,
                  color: p.accentText,
                  opacity: caret ? 1 : 0,
                  left: `calc(${typed.length}ch)`,
                }}
              >
                ▋
              </span>
            )}
          </div>
          </div>
          {!narrow && (
            <span style={{ fontFamily: MONO, fontSize: 12, color: p.txt3 }}>
              Enter → {t("broadcast.toAllHosts")}
            </span>
          )}
          <Btn
            icon="send"
            size="sm"
            full={narrow}
            onClick={() => void send()}
            disabled={!bcId || liveCount === 0}
            style={isMobile ? { minHeight: 44 } : undefined}
          >
            {t("broadcast.send")}
          </Btn>
        </div>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            marginTop: 9,
            fontSize: 12,
            color: p.txt3,
          }}
        >
          <Icon name="alert" size={13} color={p.amber} style={{ flexShrink: 0 }} />
          {t("broadcast.warning")}
          {failed.length > 0 &&
            ` ${t("count.hostsUnavailable", {
              count: failed.length,
              labels: failed.map((h) => h.profile.label).join(", "),
            })}.`}
        </div>
      </div>
    </div>
  );
}
