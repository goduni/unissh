// ViewFleet — parallel exec ("Fleet exec"). Three concepts are kept separate:
//   • Universe = the ambient host filter (all / #tag / group) — which hosts show.
//   • Selection = store.fleetSelection (profile ids) — which hosts actually RUN.
//     Default empty: this is a security tool, so an explicit pick is required.
//   • Search = a local query that narrows the *rendered* grid without unchecking.
// The grid is an in-place multi-select target picker (per-tile checkbox, select
// all/none/invert over the visible set, shift-click range). Run acts on the
// selection only. Wired to the real core: each target runs via a single-host
// api.sshExecMulti call from a bounded JS-side pool, so Stop can genuinely skip
// hosts that haven't launched yet. Hosts whose auth requires an interactive
// password ("ask") are excluded from the runnable set and surfaced as skipped.

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { usePalette } from "@/theme/ThemeProvider";
import { MONO, rgba } from "@/theme/tokens";
import { Icon, Btn, Checkbox, NO_AUTOCORRECT, Spinner } from "@/components/primitives";
import { pressActivate } from "@/components/a11y";
import { useApp, HOST_FILTER_ALL } from "@/store/app";
import { useCtx } from "@/store/ctx";
import { useTranslation } from "@/i18n";
import { useFmt } from "@/i18n/format";
import * as api from "@/bridge/api";
import { apiErrorMessage, mismatchFromError } from "@/bridge/types";
import type { PendingMismatch } from "@/store/app";
import type { ConnectionProfile, MultiExecResult, MultiExecTarget } from "@/bridge/types";

type Phase = "idle" | "running" | "done";

// Per-host run status derived from phase + launch/result/cancel maps.
type HostStatus = "queued" | "running" | "ok" | "fail" | "cancelled";

// How many hosts run at once. Bounded (instead of the core's "all in parallel")
// so Stop / stop-on-error have a real queue of not-yet-started hosts to cut.
const FLEET_CONCURRENCY = 8;
// Per-host command deadline (matches the previous batched behaviour).
const EXEC_TIMEOUT_SECS = 30;

function statusColor(
  p: ReturnType<typeof usePalette>,
  st: HostStatus,
  timedOut: boolean,
): string {
  if (st === "ok") return p.green;
  if (st === "fail") return timedOut ? p.amber : p.red;
  if (st === "running") return p.accent;
  return p.txt3;
}

// ── per-host result tile ───────────────────────────────────────
// Memoised: with the grid re-rendering on every per-host result set, a plain
// component re-renders all N tiles on each of N results (O(N²)). memo + the
// stable onReviewMismatch/useMemo below keep each tile to its own updates.
const HostTile = React.memo(function HostTile({
  h,
  st,
  result,
  selectable,
  checked,
  index,
  onToggle,
  onReviewMismatch,
}: {
  h: ConnectionProfile;
  st: HostStatus;
  result?: MultiExecResult;
  /** Idle-phase picker: the tile shows a checkbox and is click-to-toggle. False
   *  during running/done (the selection is frozen into the run snapshot). */
  selectable: boolean;
  checked: boolean;
  /** Position in the currently-visible list, for shift-click range selection. */
  index: number;
  /** Stable toggle handler — takes (profileId, visible index, shiftKey) so the
   *  memoised tile keeps a stable prop identity. */
  onToggle: (profileId: string, index: number, shiftKey: boolean) => void;
  /** A per-host connect error carrying a host-key mismatch — the tile offers a
   *  "review" affordance that opens the Known hosts ceremony. Passes the profile
   *  plus the PARSED failing-hop host/port/fingerprint (the hop may be a jump
   *  host, not the profile), so the caller pins the right key. */
  onReviewMismatch: (h: ConnectionProfile, m: PendingMismatch) => void;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const { fmtDuration } = useFmt();
  const timedOut = result?.timedOut ?? false;
  const bar = statusColor(p, st, timedOut);
  const mismatch = useMemo(() => mismatchFromError(result?.error), [result]);
  const toggle = (shift: boolean) => onToggle(h.profileId, index, shift);

  // body text colour: stderr/error → red, ok stdout → green-tinted neutral.
  const bodyLines = useMemo(() => {
    if (!result) return [];
    if (result.error) return [{ t: result.error, c: "r" as const }];
    const out: { t: string; c: "g" | "r" | "d" }[] = [];
    const stdout = result.stdout.replace(/\n+$/, "");
    const stderr = result.stderr.replace(/\n+$/, "");
    if (stdout)
      for (const ln of stdout.split("\n"))
        out.push({ t: ln, c: result.exitStatus === 0 ? "g" : "d" });
    if (stderr) for (const ln of stderr.split("\n")) out.push({ t: ln, c: "r" });
    if (out.length === 0) out.push({ t: t("fleet.noOutput"), c: "d" });
    return out;
  }, [result, t]);

  return (
    <div
      role={selectable ? "button" : undefined}
      aria-pressed={selectable ? checked : undefined}
      aria-label={selectable ? t("fleet.selectHostLabel", { host: h.label }) : undefined}
      tabIndex={selectable ? 0 : undefined}
      onClick={selectable ? (e) => toggle(e.shiftKey) : undefined}
      onKeyDown={selectable ? pressActivate(() => toggle(false)) : undefined}
      style={{
        borderRadius: 13,
        background: selectable && checked ? p.bg2 : p.bg1,
        border: `1px solid ${p.line}`,
        boxShadow: selectable && checked ? `inset 0 0 0 1px ${p.line2}` : "none",
        overflow: "hidden",
        cursor: selectable ? "pointer" : "default",
        transition: "border-color .12s, box-shadow .12s",
        userSelect: selectable ? "none" : "auto",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 9,
          padding: "10px 13px",
          borderBottom: `1px solid ${p.line}`,
        }}
      >
        {selectable ? (
          <Checkbox
            checked={checked}
            onChange={() => toggle(false)}
            aria-label={t("fleet.selectHostLabel", { host: h.label })}
          />
        ) : (
          <span
            style={{
              width: 8,
              height: 8,
              borderRadius: "50%",
              background: bar,
              animation: st === "running" ? "uhPulse 1s ease-in-out infinite" : "none",
              flexShrink: 0,
            }}
          />
        )}
        <span
          style={{
            fontWeight: 700,
            fontSize: 14,
            whiteSpace: "nowrap",
            overflow: "hidden",
            textOverflow: "ellipsis",
            minWidth: 0,
            flexShrink: 1,
          }}
        >
          {h.label}
        </span>
        <span
          style={{
            fontFamily: MONO,
            fontSize: 11,
            color: p.txt3,
            whiteSpace: "nowrap",
            overflow: "hidden",
            textOverflow: "ellipsis",
            minWidth: 0,
          }}
        >
          {h.user}@{h.host}
        </span>
        <div style={{ flex: 1 }} />
        {st === "queued" && (
          <span style={{ fontFamily: MONO, fontSize: 11, color: p.txt3 }}>{t("fleet.queued")}</span>
        )}
        {st === "cancelled" && (
          <span style={{ fontFamily: MONO, fontSize: 11, color: p.txt3 }}>
            {t("fleet.cancelled")}
          </span>
        )}
        {st === "running" && (
          <span style={{ fontFamily: MONO, fontSize: 11, color: p.accent }}>
            {t("fleet.running")}
          </span>
        )}
        {result && (
          <span
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 5,
              fontFamily: MONO,
              fontSize: 11,
              color: timedOut ? p.amber : result.exitStatus === 0 ? p.green : p.red,
            }}
          >
            <Icon name={!timedOut && result.exitStatus === 0 ? "check" : "x"} size={12} />
            {timedOut ? t("fleet.timedOut") : t("fleet.exit", { code: result.exitStatus })} ·{" "}
            {fmtDuration(result.durationMs)}
          </span>
        )}
      </div>
      <div
        style={{
          padding: "11px 13px",
          fontFamily: MONO,
          fontSize: 12,
          lineHeight: 1.7,
          minHeight: 64,
          background: p.bg0,
        }}
      >
        {(st === "queued" || st === "cancelled") && <span style={{ color: p.txt3 }}>—</span>}
        {st === "running" && <span style={{ color: p.accent }}>▋</span>}
        {result && (
          <React.Fragment>
            {bodyLines.map((l, i) => (
              <div
                key={i}
                style={{
                  color: l.c === "g" ? p.green : l.c === "r" ? p.red : p.txt2,
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-all",
                }}
              >
                {l.t}
              </div>
            ))}
            {mismatch && (
              <div style={{ marginTop: 8 }}>
                <Btn
                  variant="danger"
                  size="sm"
                  icon="fingerprint"
                  onClick={() => onReviewMismatch(h, mismatch)}
                >
                  {t("known.changedReview")}
                </Btn>
              </div>
            )}
          </React.Fragment>
        )}
      </div>
    </div>
  );
});

// ── Main view ──────────────────────────────────────────────────
export function ViewFleet() {
  const p = usePalette();
  const { t } = useTranslation();
  const ctx = useCtx();
  const hosts = useApp((s) => s.hosts);
  const groups = useApp((s) => s.groups);
  const hostFilter = useApp((s) => s.hostFilter);
  const vaultId = useApp((s) => s.vaultId);
  const fleetSelection = useApp((s) => s.fleetSelection);
  const setFleetSelection = useApp((s) => s.setFleetSelection);
  const reviewMismatch = useApp((s) => s.reviewMismatch);

  const [phase, setPhase] = useState<Phase>("idle");
  // Search narrows the *rendered* grid only; it never unchecks. Selection lives
  // in the store (fleetSelection) so the host-key review detour preserves it.
  const [query, setQuery] = useState("");
  // No pre-filled example command — a command that runs on N hosts must always
  // be typed (or pasted) deliberately; the placeholder carries the hint instead.
  const [command, setCommand] = useState("");
  const [stopOnError, setStopOnError] = useState(true);
  // All per-host maps are keyed by profileId — hostnames can repeat across
  // profiles (same box, different port/user), and h.host keys would collide.
  const [results, setResults] = useState<Record<string, MultiExecResult>>({});
  const [started, setStarted] = useState<Record<string, boolean>>({});
  const [cancelledIds, setCancelledIds] = useState<Record<string, boolean>>({});
  // The target set frozen at Run: the grid renders from this while running/done
  // so a background host sync (the live `hosts` store dep) can't remap the grid
  // mid-run. null until the first Run — the idle grid shows the live `runnable`.
  const [runHosts, setRunHosts] = useState<ConnectionProfile[] | null>(null);
  // Mirrors for the run loop / Stop (state lags a render behind).
  const startedRef = useRef<Record<string, boolean>>({});
  const stopRef = useRef(false);
  // Live mirror of stopOnError so mid-run toggles are honoured both directions
  // (the run closure captured the value at Run-click otherwise).
  const stopOnErrorRef = useRef(stopOnError);
  stopOnErrorRef.current = stopOnError;
  const execBtnRef = useRef<HTMLButtonElement | null>(null);
  // Shift-click range: the last-toggled visible index, and a live mirror of the
  // visible list so the stable toggle handler can resolve a range without
  // capturing a stale closure.
  const lastIdxRef = useRef<number | null>(null);
  const visibleRef = useRef<ConnectionProfile[]>([]);

  // The selection is one-shot, BUT the host-key "review" detour navigates to the
  // Known-hosts view (route "known") and expects to come back to the same picks —
  // so clear only when leaving for anything else. The route is already updated
  // when this unmount cleanup runs.
  useEffect(
    () => () => {
      if (useApp.getState().route !== "known") useApp.getState().setFleetSelection([]);
    },
    [],
  );

  // Carried selection from the hosts view: if any pre-checked host falls outside
  // the current universe, widen the filter to ALL so the user can see what's
  // checked. Once, on mount only — later filter changes are the user's call.
  useEffect(() => {
    const carried = useApp.getState().fleetSelection;
    if (!carried.length) return;
    const shown = new Set(filtered.map((h) => h.profileId));
    if (carried.some((id) => !shown.has(id))) useApp.getState().setHostFilter(HOST_FILTER_ALL);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Toggle one host (or a shift-range) in the store selection. Stable identity so
  // the memoised tiles don't re-render on unrelated selection changes — reads the
  // live selection/visible list from refs + the store instead of closing over them.
  const onToggle = useCallback(
    (profileId: string, index: number, shift: boolean) => {
      const cur = new Set(useApp.getState().fleetSelection);
      const willCheck = !cur.has(profileId);
      if (shift && lastIdxRef.current != null) {
        const vis = visibleRef.current;
        const lo = Math.min(lastIdxRef.current, index);
        const hi = Math.max(lastIdxRef.current, index);
        for (let i = lo; i <= hi; i++) {
          const id = vis[i]?.profileId;
          if (!id) continue;
          if (willCheck) cur.add(id);
          else cur.delete(id);
        }
      } else if (willCheck) cur.add(profileId);
      else cur.delete(profileId);
      lastIdxRef.current = index;
      setFleetSelection([...cur]);
    },
    [setFleetSelection],
  );

  const onReviewMismatch = useCallback(
    (h: ConnectionProfile, m: PendingMismatch) => {
      // Trust the PARSED failing-hop host/port (a jump host isn't the profile);
      // fall back to the profile only if the parse somehow lacked them.
      reviewMismatch({
        host: m.host || h.host,
        port: m.port || h.port,
        fingerprint: m.fingerprint,
      });
    },
    [reviewMismatch],
  );

  // Universe = the ambient host filter (tag/group/all). This is purely "which
  // hosts are shown" — the fine "which run" is the selection, applied below.
  const filtered = useMemo(() => {
    if (hostFilter === HOST_FILTER_ALL) return hosts;
    if (hostFilter === "__untagged") return hosts.filter((x) => x.tags.length === 0);
    const group = groups.find((g) => g.groupId === hostFilter);
    return hosts.filter(
      (x) => x.tags.includes(hostFilter) || (group?.memberIds.includes(x.profileId) ?? false),
    );
  }, [hosts, groups, hostFilter]);

  // Batchable hosts vs skipped ones. PromptPassword needs interactive input, so
  // it's excluded and surfaced as "skipped". Personal IS batchable when bound: its
  // credential is resolved per-host at run time (binding + anti-redirect); an
  // unbound/redirected one is reported as a per-host error, never run silently.
  const runnable = useMemo(
    () => filtered.filter((h) => h.auth.type !== "promptPassword"),
    [filtered],
  );
  const skipped = filtered.length - runnable.length;

  // Selection = which hosts actually run. selectedRunnable intersects the store
  // selection with the runnable universe (a pick can survive a filter change and
  // fall out of view — it only runs if it's currently runnable).
  const sel = useMemo(() => new Set(fleetSelection), [fleetSelection]);
  const selectedRunnable = useMemo(
    () => runnable.filter((h) => sel.has(h.profileId)),
    [runnable, sel],
  );

  // The rendered (idle) grid: runnable narrowed by the search query. Selection
  // persists across search; select-all/none/invert act on this visible set.
  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return runnable;
    return runnable.filter(
      (h) =>
        h.label.toLowerCase().includes(q) ||
        h.host.toLowerCase().includes(q) ||
        h.user.toLowerCase().includes(q) ||
        h.tags.some((tg) => tg.toLowerCase().includes(q)),
    );
  }, [runnable, query]);
  visibleRef.current = visible;

  // Bulk selection ops operate on the currently-visible runnable set (Gmail-style).
  const selectAllVisible = () => {
    const cur = new Set(fleetSelection);
    for (const h of visible) cur.add(h.profileId);
    setFleetSelection([...cur]);
  };
  const selectNoneVisible = () => {
    const cur = new Set(fleetSelection);
    for (const h of visible) cur.delete(h.profileId);
    setFleetSelection([...cur]);
  };
  const invertVisible = () => {
    const cur = new Set(fleetSelection);
    for (const h of visible) {
      if (cur.has(h.profileId)) cur.delete(h.profileId);
      else cur.add(h.profileId);
    }
    setFleetSelection([...cur]);
  };

  const filterLabel =
    hostFilter === HOST_FILTER_ALL
      ? t("common.all")
      : hostFilter === "__untagged"
        ? t("fleet.untagged")
        : `#${hostFilter}`;

  const okCount = Object.values(results).filter((r) => !r.timedOut && r.exitStatus === 0).length;
  const failCount = Object.values(results).filter((r) => r.timedOut || r.exitStatus !== 0).length;

  const statusOf = (h: ConnectionProfile): HostStatus => {
    if (phase === "idle") return "queued";
    const r = results[h.profileId];
    if (r) return !r.timedOut && r.exitStatus === 0 ? "ok" : "fail";
    if (cancelledIds[h.profileId]) return "cancelled";
    if (started[h.profileId]) return "running";
    return "queued";
  };

  const run = async () => {
    const cmd = command.trim();
    if (!cmd || selectedRunnable.length === 0 || !vaultId || phase === "running") return;
    // Freeze the scope at launch — the grid, Stop and cancellation all run off
    // this snapshot, so a background host sync can't add/drop/reorder tiles mid-run.
    const snapshot = selectedRunnable;
    setRunHosts(snapshot);
    setPhase("running");
    setResults({});
    setStarted({});
    setCancelledIds({});
    startedRef.current = {};
    stopRef.current = false;
    // Bounded worker pool over an explicit queue. Stop (and stop-on-error) cuts
    // the queue: hosts never launched are marked "cancelled"; commands already
    // in flight finish on their own and report normally.
    const queue = [...snapshot];
    let failed = false;
    const worker = async () => {
      for (;;) {
        if (stopRef.current || (stopOnErrorRef.current && failed)) return;
        const h = queue.shift();
        if (!h) return;
        startedRef.current[h.profileId] = true;
        setStarted((s) => ({ ...s, [h.profileId]: true }));
        let r: MultiExecResult;
        try {
          // Resolve connect auth per host (Personal → in-core binding + anti-
          // redirect). An unbound/redirected personal host is reported as a
          // per-host error, never run silently.
          const { user, auth } = await api.resolveConnectAuth(h, vaultId);
          const target: MultiExecTarget = {
            host: h.host,
            port: h.port,
            user,
            auth,
            jumps: h.jumps,
          };
          const out = await api.sshExecMulti([target], cmd, 0, EXEC_TIMEOUT_SECS);
          r = out[0] ?? {
            host: h.host,
            stdout: "",
            stderr: "",
            exitStatus: -1,
            error: t("error.generic"),
            durationMs: 0,
            timedOut: false,
          };
        } catch (e) {
          r = {
            host: h.host,
            stdout: "",
            stderr: "",
            exitStatus: -1,
            error: apiErrorMessage(e),
            durationMs: 0,
            timedOut: false,
          };
        }
        if (r.timedOut || r.exitStatus !== 0) failed = true;
        setResults((prev) => ({ ...prev, [h.profileId]: r }));
      }
    };
    await Promise.all(
      Array.from({ length: Math.min(FLEET_CONCURRENCY, queue.length) }, () => worker()),
    );
    // Whatever is still queued was never launched — mark it honestly.
    if (queue.length) {
      setCancelledIds((prev) => {
        const next = { ...prev };
        for (const h of queue) next[h.profileId] = true;
        return next;
      });
    }
    setPhase("done");
  };

  // Stop = ignore-remaining: no not-yet-started host launches (there is no core
  // API to abort an exec mid-flight; in-flight commands finish and report).
  const stop = () => {
    stopRef.current = true;
    setCancelledIds((prev) => {
      const next = { ...prev };
      // Iterate the frozen snapshot, not the live selection.
      for (const h of runHosts ?? selectedRunnable)
        if (!startedRef.current[h.profileId]) next[h.profileId] = true;
      return next;
    });
  };

  // Failed profile ids from the last run (keyed by profileId in `results`).
  const failedIds = useMemo(
    () =>
      Object.entries(results)
        .filter(([, r]) => r.timedOut || r.exitStatus !== 0)
        .map(([id]) => id),
    [results],
  );

  // Re-run failed: reset to idle with the selection narrowed to the failures, so
  // the user reviews the reduced radius and hits Run again. Command is kept.
  const rerunFailed = () => {
    setFleetSelection(failedIds);
    setResults({});
    setStarted({});
    setCancelledIds({});
    setRunHosts(null);
    lastIdxRef.current = null;
    setPhase("idle");
  };

  return (
    // Entry motion comes from the uh-stagger grid rise below — no root fade on top.
    <div
      style={{
        flex: 1,
        display: "flex",
        flexDirection: "column",
        minWidth: 0,
        background: p.bg0,
        overflow: "hidden",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "16px 22px 12px" }}>
        <Icon name="layers" size={20} color={p.accent} />
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
          {t("nav.fleetExec")}
        </h1>
        {/* Coarse universe label — a muted hint so the user knows which hosts the
            picker below is drawn from (the fine "which run" is the selection). */}
        <span
          style={{
            fontFamily: MONO,
            fontSize: 12,
            color: p.txt3,
            whiteSpace: "nowrap",
            overflow: "hidden",
            textOverflow: "ellipsis",
            minWidth: 0,
          }}
        >
          {filterLabel}
        </span>
        {skipped > 0 && (
          <span
            style={{
              fontFamily: MONO,
              fontSize: 11,
              color: p.amber,
              whiteSpace: "nowrap",
            }}
            title={t("fleet.skippedTitle")}
          >
            ⚠ {t("fleet.skipped", { count: skipped })}
          </span>
        )}
        <div style={{ flex: 1 }} />
        {phase === "done" && (
          <span style={{ display: "inline-flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontFamily: MONO, fontSize: 12.5 }}>
              <span style={{ color: p.green }}>{t("fleet.okCount", { count: okCount })}</span> ·{" "}
              <span style={{ color: p.red }}>{t("fleet.failCount", { count: failCount })}</span>
            </span>
            {failCount > 0 && (
              <Btn variant="ghost" size="sm" icon="refresh" onClick={rerunFailed}>
                {t("fleet.rerunFailed", { count: failCount })}
              </Btn>
            )}
          </span>
        )}
      </div>

      {/* selection toolbar — the in-place target picker's controls (idle only;
          during a run/after it the grid is the frozen result snapshot, not a picker) */}
      {phase === "idle" && filtered.length > 0 && runnable.length > 0 && (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            flexWrap: "wrap",
            padding: "0 22px 12px",
          }}
        >
          <span style={{ fontSize: 12.5, color: p.txt2, whiteSpace: "nowrap" }}>
            {t("fleet.selectedOfTotal", {
              n: selectedRunnable.length,
              m: runnable.length,
            })}
          </span>
          <Btn variant="ghost" size="sm" onClick={selectAllVisible}>
            {t("fleet.selAll")}
          </Btn>
          <Btn variant="ghost" size="sm" onClick={selectNoneVisible}>
            {t("fleet.selNone")}
          </Btn>
          <Btn variant="ghost" size="sm" onClick={invertVisible}>
            {t("fleet.invert")}
          </Btn>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              flex: 1,
              minWidth: 180,
              height: 34,
              padding: "0 12px",
              borderRadius: 9,
              background: p.bg1,
              border: `1px solid ${p.line2}`,
            }}
          >
            <Icon name="search" size={14} color={p.txt3} />
            <input
              {...NO_AUTOCORRECT}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={t("fleet.searchPlaceholder")}
              style={{
                fontSize: 13,
                color: p.txt,
                flex: 1,
                background: "transparent",
                border: "none",
                outline: "none",
                minWidth: 0,
              }}
            />
            {query && (
              <button
                aria-label={t("common.clear")}
                onClick={() => setQuery("")}
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  justifyContent: "center",
                  border: "none",
                  background: "transparent",
                  color: p.txt3,
                  cursor: "pointer",
                  padding: 0,
                }}
              >
                <Icon name="x" size={12} />
              </button>
            )}
          </div>
        </div>
      )}

      {/* command bar */}
      <div style={{ padding: "0 22px 14px" }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 12,
            height: 50,
            padding: "0 16px",
            borderRadius: 12,
            background: p.bg1,
            border: `1px solid ${p.line2}`,
            boxShadow: "none",
          }}
        >
          <span style={{ fontFamily: MONO, fontSize: 18, color: p.accent, fontWeight: 700 }}>
            ❯
          </span>
          <input
            {...NO_AUTOCORRECT}
            value={command}
            onChange={(e) => setCommand(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && phase !== "running") {
                // Blast-radius guard: with more than one selected target, Enter arms
                // the count-labelled Run button instead of firing — the second Enter
                // executes with the radius in plain sight. A single target runs.
                // Nothing selected → Enter does nothing (Run is disabled).
                if (selectedRunnable.length === 0) return;
                if (selectedRunnable.length > 1) execBtnRef.current?.focus();
                else void run();
              }
            }}
            disabled={phase === "running"}
            placeholder={t("fleet.commandPlaceholder")}
            style={{
              fontFamily: MONO,
              fontSize: 15,
              color: p.txt,
              flex: 1,
              background: "transparent",
              border: "none",
              outline: "none",
              minWidth: 0,
            }}
          />
          <Checkbox
            checked={stopOnError}
            onChange={setStopOnError}
            label={t("fleet.stopOnError")}
            title={t("fleet.stopOnErrorTitle")}
            style={{ gap: 6, whiteSpace: "nowrap" }}
            labelStyle={{ fontSize: 12, color: p.txt3 }}
          />
          {phase === "running" ? (
            <Btn
              variant="ghost"
              icon="stop"
              size="sm"
              onClick={stop}
              title={t("fleet.stopTitle")}
              style={{ color: p.red, borderColor: rgba(p.red, 0.45) }}
            >
              {t("fleet.stop")}
              <Spinner size={13} />
            </Btn>
          ) : (
            <Btn
              btnRef={execBtnRef}
              icon="play"
              size="sm"
              onClick={run}
              disabled={!command.trim() || selectedRunnable.length === 0}
            >
              {t("fleet.runOnHosts", { count: selectedRunnable.length })}
            </Btn>
          )}
        </div>
        {phase === "idle" && selectedRunnable.length === 0 && runnable.length > 0 && (
          <div style={{ fontSize: 12, color: p.txt3, padding: "7px 4px 0" }}>
            {t("fleet.selectHostsHint")}
          </div>
        )}
      </div>

      {/* per-host grid */}
      <div style={{ flex: 1, overflow: "auto", padding: "0 22px 18px" }}>
        {filtered.length === 0 ? (
          <div
            style={{
              height: "70%",
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
              <Icon name="layers" size={26} color={p.txt3} />
            </span>
            <div style={{ textAlign: "center" }}>
              <div style={{ fontSize: 16, fontWeight: 700, color: p.txt }}>
                {t("fleet.emptyTitle")}
              </div>
              <div style={{ fontSize: 13, color: p.txt3, marginTop: 3 }}>
                {t("fleet.emptyDesc")}
              </div>
            </div>
            <Btn size="sm" icon="plus" onClick={() => ctx.onNewHost()}>
              {t("fleet.newHost")}
            </Btn>
          </div>
        ) : runnable.length === 0 ? (
          <div
            style={{
              height: "70%",
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              justifyContent: "center",
              gap: 12,
              color: p.txt3,
            }}
          >
            <Icon name="lock" size={30} color={p.amber} />
            <span style={{ fontSize: 14, textAlign: "center", maxWidth: 360 }}>
              {t("fleet.allRequirePassword")}
            </span>
          </div>
        ) : phase === "idle" && visible.length === 0 ? (
          <div
            style={{
              height: "70%",
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              justifyContent: "center",
              gap: 10,
              color: p.txt3,
            }}
          >
            <Icon name="search" size={26} color={p.txt3} />
            <span style={{ fontSize: 14, textAlign: "center" }}>{t("fleet.noMatches")}</span>
          </div>
        ) : (
          <div
            className="uh-stagger"
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))",
              gap: 14,
            }}
          >
            {(phase === "idle" ? visible : (runHosts ?? selectedRunnable)).map((h, i) => (
              <HostTile
                key={h.profileId}
                h={h}
                st={statusOf(h)}
                result={results[h.profileId]}
                selectable={phase === "idle"}
                checked={sel.has(h.profileId)}
                index={i}
                onToggle={onToggle}
                onReviewMismatch={onReviewMismatch}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
