import { type CSSProperties, type RefObject, useEffect, useId, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { ApiError } from "../api/errors";
import { fmtEpoch, fmtNum, fmtRelative } from "../util/format";
import type { AuditEntry, AuditSink } from "../api/types";
import { truncId } from "../util/bytes";
import { DataTable, type Column } from "../ui/DataTable";
import { Icon } from "../ui/icons";
import {
  Btn,
  Card,
  CardHeader,
  EmptyState,
  ErrorCard,
  Field,
  IconBtn,
  InlineError,
  Missing,
  PubkeyChip,
  Skeleton,
  SummaryCount,
  SummaryLine,
  SummaryPart,
  Tag,
  TextInput,
  ToneBadge,
  ZkBanner,
  tint,
  type Tone,
} from "../ui/primitives";
import { useAsync } from "../util/useAsync";
import { Screen } from "./Screen";
import { MONO } from "../theme/tokens";
import "./data.css";

interface DecodedEvent {
  /** Event name (server-observed) or a placeholder for opaque/client blobs. */
  type: string;
  /** Short human-readable summary of the relevant fields, or null. */
  detail: string | null;
}

type EventBlob = {
  event?: string;
  account_id?: string;
  device_id?: string;
  vault_id?: string;
  new_epoch?: number;
  revoke_epoch?: number | null;
  display_name?: string | null;
  by?: string;
};

/** Human summary for a single server-observed event. */
function eventDetail(ev: EventBlob): string | null {
  switch (ev.event) {
    case "bootstrap_admin":
    case "login":
    case "logout":
    case "device_add":
    case "device_label":
    case "device_remove":
    case "keyset_publish":
      return `acct ${truncId(ev.account_id)} · dev ${truncId(ev.device_id)}`;
    case "admin_grant":
    case "admin_revoke":
    case "account_disable":
    case "account_enable":
      return `acct ${truncId(ev.account_id)}`;
    case "tenant_suspend":
    case "tenant_activate":
      return ev.by ? `by ${ev.by}` : null;
    case "tenant_rename":
      return `${ev.display_name ? `«${ev.display_name}»` : "(reset)"}${
        ev.by ? ` · by ${ev.by}` : ""
      }`;
    case "access_grant":
      return `vault ${truncId(ev.vault_id)} · epoch ${ev.new_epoch}${
        ev.revoke_epoch != null ? ` (revoke ≤ ${ev.revoke_epoch})` : ""
      }`;
    default: {
      // Unknown server-observed event — surface remaining keys generically.
      const keys = Object.keys(ev).filter((k) => k !== "event" && k !== "ts");
      return keys.length ? keys.join(", ") : null;
    }
  }
}

/**
 * Decode an audit entry per server docs/audit-entry-blob-format.md:
 * only `server-observed` blobs are UTF-8 JSON (discriminated by `event`);
 * `client-signed` blobs are opaque binary and must NOT be JSON.parse'd.
 */
function decodeEvent(entry: AuditEntry): DecodedEvent {
  if (entry.source !== "server-observed") {
    return { type: "(client-signed)", detail: null };
  }
  try {
    const ev = JSON.parse(atob(entry.entry_blob)) as EventBlob;
    return { type: ev.event || "(opaque)", detail: eventDetail(ev) };
  } catch {
    return { type: "(opaque)", detail: null };
  }
}

type VerifyResult = { kind: "ok" | "tamper" | "broken" | "error"; msg: string };

export function Audit() {
  const { t } = useTranslation();
  // The tamper finding is the panel's headline security result — it must NOT be a
  // 4.5s toast that vanishes. Hold it as a persistent, dismissible card.
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [exportOpen, setExportOpen] = useState(false);
  const exportToggle = useRef<HTMLButtonElement>(null);
  const closeExport = () => {
    setExportOpen(false);
    exportToggle.current?.focus();
  };

  const verify = async () => {
    setVerifying(true);
    try {
      const r = await api.admin.auditVerify();
      // Server-side verify CANNOT detect tail-truncation/full-wipe: a truncated
      // chain still re-verifies (each remaining record's prev_hash matches), so the
      // server reports ok=true. Anchor the (count, head) client-side — an
      // anti-rollback cursor like the sync server_seq — and flag a DROP in count, or
      // a changed head at the same count, as tamper the server hid.
      // Instance-wide audit log → a single anchor. (The panel connects to one
      // instance per origin; a different instance URL gets its own localStorage.)
      const ANCHOR_KEY = "unissh.auditAnchor";
      let tamper: string | null = null;
      if (r.ok) {
        try {
          const raw = localStorage.getItem(ANCHOR_KEY);
          const prev = raw ? (JSON.parse(raw) as { count: number; head: string | null }) : null;
          if (prev) {
            if (r.count < prev.count) {
              tamper = t("screen.audit.tamperShrank", { prev: prev.count, now: r.count });
            } else if (r.count === prev.count && prev.head && r.head_hash !== prev.head) {
              tamper = t("screen.audit.tamperRewritten");
            }
          }
          // Advance the anchor ONLY on a clean reading. Advancing on a detected tamper
          // (e.g. head-changed-at-same-count, where count >= prev.count is still true)
          // would overwrite the trusted head with the tampered one — self-healing the
          // attack so the next verify no longer flags it.
          if (!tamper && (!prev || r.count >= prev.count)) {
            localStorage.setItem(ANCHOR_KEY, JSON.stringify({ count: r.count, head: r.head_hash }));
          }
        } catch {
          /* localStorage unavailable → skip anchoring (server verify still shown) */
        }
      }
      if (tamper) setResult({ kind: "tamper", msg: tamper });
      else if (r.ok) setResult({ kind: "ok", msg: t("screen.audit.chainIntact", { count: r.count }) });
      else setResult({ kind: "broken", msg: t("screen.audit.chainBroken", { seq: r.broken_at }) });
    } catch (e) {
      setResult({ kind: "error", msg: e instanceof Error ? e.message : String(e) });
    } finally {
      setVerifying(false);
    }
  };

  return (
    <Screen
      title={t("screen.audit.title")}
      sub={t("screen.audit.sub")}
      zk
      actions={
        <>
          <Btn
            ref={exportToggle}
            icon="download"
            onClick={() => setExportOpen((o) => !o)}
            ariaExpanded={exportOpen}
            ariaControls="audit-export"
          >
            {t("screen.audit.export")}
          </Btn>
          <Btn icon="shieldcheck" loading={verifying} onClick={() => void verify()}>
            {t("screen.audit.verifyChain")}
          </Btn>
        </>
      }
    >
      {exportOpen ? <ExportCard onClose={closeExport} toggle={exportToggle} /> : null}
      {result ? (
        <VerifyResultCard
          result={result}
          retrying={verifying}
          onRetry={() => void verify()}
          onDismiss={() => setResult(null)}
        />
      ) : null}
      <SinksCard />
      <AuditBody />
    </Screen>
  );
}

/** Optional inclusive seq bound: "" → none; otherwise a positive integer. */
function parseSeq(v: string): number | undefined | null {
  const s = v.trim();
  if (!s) return undefined;
  return /^[1-9][0-9]*$/.test(s) ? Number(s) : null;
}

/** File name when the server's Content-Disposition isn't readable (cross-origin
 *  without the header exposed): the range actually exported, read off the body's
 *  last line, so the pinned upper bound is not lost. */
async function fallbackName(blob: Blob, from: number): Promise<string> {
  const lines = (await blob.text()).trimEnd().split("\n");
  try {
    const last = JSON.parse(lines[lines.length - 1]) as { seq?: number };
    if (typeof last.seq === "number") return `unissh-audit-${from}-${last.seq}.jsonl`;
  } catch {
    /* empty export or unparsable tail → generic name */
  }
  return `unissh-audit-${from}.jsonl`;
}

/** Download the log (or a seq range) as JSON Lines, with the chain fields.
 *  Escape closes it while focus is in the card, on its toggle, or nowhere
 *  (focus elsewhere, e.g. in a dialog, keeps its own Escape). */
function ExportCard({ onClose, toggle }: { onClose: () => void; toggle: RefObject<HTMLButtonElement | null> }) {
  const { t } = useTranslation();
  const form = useRef<HTMLFormElement>(null);
  const ids = useId();
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape" || e.defaultPrevented) return;
      const at = document.activeElement;
      const ours =
        !at || at === document.body || at === toggle.current || (form.current?.contains(at) ?? false);
      if (!ours) return;
      e.preventDefault();
      onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose, toggle]);
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fromSeq = parseSeq(from);
  const toSeq = parseSeq(to);
  const invalid =
    fromSeq === null ||
    toSeq === null ||
    (fromSeq !== undefined && toSeq !== undefined && toSeq < fromSeq);
  // Which bound the message is about: the red edge goes on that field.
  const fromBad = fromSeq === null;
  const toBad = toSeq === null || (fromSeq != null && toSeq !== undefined && toSeq < fromSeq);
  const invalidId = `${ids}-invalid`;

  const download = async () => {
    if (invalid) return;
    setBusy(true);
    setError(null);
    try {
      const { blob, filename } = await api.admin.auditExport({ from_seq: fromSeq, to_seq: toSeq });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename ?? (await fallbackName(blob, fromSeq ?? 1));
      a.click();
      URL.revokeObjectURL(url);
      onClose();
    } catch (e) {
      // The export never answers 404 itself: a 404 is a server older than it.
      if (e instanceof ApiError && e.status === 404) setError(t("screen.audit.exportUnsupported"));
      else setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card pad={false}>
      <form
        id="audit-export"
        ref={form}
        onSubmit={(e) => {
          e.preventDefault();
          void download();
        }}
      >
        <CardHeader title={t("screen.audit.exportTitle")} />
        <div style={{ padding: 16 }}>
          <p
            style={{
              margin: "0 0 16px",
              fontSize: 14,
              lineHeight: "20px",
              maxWidth: "72ch",
              color: "var(--muted-foreground)",
            }}
          >
            {t("screen.audit.exportHint")}
          </p>
          <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
            <div style={{ flex: "1 1 160px", maxWidth: 280 }}>
              <Field label={t("screen.audit.exportFrom")} tag="from_seq" tagMono htmlFor={`${ids}-from`}>
                <TextInput
                  id={`${ids}-from`}
                  value={from}
                  onChange={setFrom}
                  placeholder="1"
                  mono
                  autoFocus
                  inputMode="numeric"
                  ariaLabel={t("screen.audit.exportFrom")}
                  invalid={fromBad}
                  describedBy={fromBad ? invalidId : undefined}
                />
              </Field>
            </div>
            <div style={{ flex: "1 1 160px", maxWidth: 280 }}>
              <Field label={t("screen.audit.exportTo")} tag="to_seq" tagMono htmlFor={`${ids}-to`}>
                <TextInput
                  id={`${ids}-to`}
                  value={to}
                  onChange={setTo}
                  placeholder={t("screen.audit.exportToHead")}
                  mono
                  inputMode="numeric"
                  ariaLabel={t("screen.audit.exportTo")}
                  invalid={toBad}
                  describedBy={toBad ? invalidId : undefined}
                />
              </Field>
            </div>
          </div>
          {invalid ? (
            <p
              id={invalidId}
              role="alert"
              style={{
                margin: "0 0 12px",
                fontSize: 14,
                lineHeight: "20px",
                maxWidth: "72ch",
                color: "var(--destructive)",
              }}
            >
              {t("screen.audit.exportInvalid")}
            </p>
          ) : null}
          {error ? <InlineError>{error}</InlineError> : null}
        </div>
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            gap: 8,
            justifyContent: "flex-end",
            padding: "12px 16px",
            borderTop: "1px solid var(--rule)",
          }}
        >
          <Btn size="sm" variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Btn>
          <Btn size="sm" variant="primary" type="submit" icon="download" loading={busy} disabled={invalid}>
            {t("screen.audit.exportDownload")}
          </Btn>
        </div>
      </form>
    </Card>
  );
}

/** How long a sink may trail the log without a success before it reads as
 *  lagging. A healthy sink trails by up to one idle poll (2 s) plus one batch. */
const SINK_LAG_GRACE_S = 30;

/**
 * - failing: the latest failure is newer than the latest success (the server
 *   counts an idle poll that found nothing to send as a success);
 * - lagging: entries are waiting (lag > 0) and no success for SINK_LAG_GRACE_S;
 * - healthy: otherwise, including a sink that is behind but delivering.
 */
type SinkState = "healthy" | "lagging" | "failing";

function sinkState(s: AuditSink, nowS = Date.now() / 1000): SinkState {
  if (s.last_error_at != null && s.last_error_at > (s.last_success_at ?? -Infinity)) {
    return "failing";
  }
  const stale = s.last_success_at == null || nowS - s.last_success_at > SINK_LAG_GRACE_S;
  return s.lag > 0 && stale ? "lagging" : "healthy";
}

const SINK_TONE: Record<SinkState, Tone> = {
  healthy: "success",
  lagging: "warning",
  failing: "destructive",
};

const MUTED = { color: "var(--muted-foreground)" } as const;
const ELLIPSIS: CSSProperties = { overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" };

/** Delivery state of each sink configured in the server's `[audit.*]` config. */
function SinksCard() {
  const { t } = useTranslation();
  const sinks = useAsync(() => api.admin.auditSinks(), []);
  const list = sinks.data?.sinks ?? [];
  // The endpoint never answers 404 itself: a 404 is a server older than sinks.
  const unsupported = sinks.errorStatus === 404;

  const columns: Column<AuditSink>[] = [
    {
      key: "sink",
      label: t("screen.audit.sinkColumn"),
      width: "minmax(0, 1fr)",
      render: (s) => (
        <span title={s.sink} style={{ ...ELLIPSIS, display: "block", fontFamily: MONO, fontSize: 12, fontWeight: 600 }}>
          {s.sink}
        </span>
      ),
    },
    {
      key: "state",
      label: t("common.state"),
      width: "136px",
      render: (s) => {
        const state = sinkState(s);
        return <ToneBadge tone={SINK_TONE[state]}>{t(`screen.audit.sinkState.${state}`)}</ToneBadge>;
      },
    },
    {
      key: "last_seq",
      label: t("screen.audit.sinkLastSeq"),
      width: "136px",
      numeric: true,
      render: (s) => s.last_seq,
    },
    {
      key: "lag",
      label: t("screen.audit.sinkLag"),
      width: "96px",
      numeric: true,
      render: (s) => s.lag,
    },
    {
      key: "last_success_at",
      label: t("screen.audit.sinkLastSuccess"),
      // Wide enough for the head in full («Последний успех», "Last success").
      width: "144px",
      render: (s) =>
        s.last_success_at != null ? (
          <span title={fmtEpoch(s.last_success_at)} style={MUTED}>
            {fmtRelative(s.last_success_at)}
          </span>
        ) : null,
    },
    {
      key: "last_error",
      label: t("screen.audit.sinkLastError"),
      width: "minmax(0, 1.4fr)",
      // The error of a failing sink is said in red; an older one, already recovered from, is muted.
      render: (s) =>
        s.last_error ? (
          <span
            title={`${s.last_error} · ${fmtEpoch(s.last_error_at)}`}
            style={{ ...ELLIPSIS, display: "block", ...MUTED }}
          >
            <span
              style={{
                fontFamily: MONO,
                fontSize: 12,
                color: sinkState(s) === "failing" ? "var(--destructive)" : undefined,
              }}
            >
              {s.last_error}
            </span>{" "}
            · {fmtRelative(s.last_error_at)}
          </span>
        ) : null,
    },
  ];

  return (
    <Card pad={false}>
      <CardHeader
        title={t("screen.audit.sinksTitle")}
        actions={
          <Btn icon="refresh" size="sm" variant="ghost" onClick={sinks.reload} loading={sinks.loading}>
            {t("common.checkNow")}
          </Btn>
        }
      />
      <DataTable
        bare
        columns={columns}
        rows={list}
        rowKey={(s) => s.sink}
        loading={sinks.loading}
        error={unsupported ? null : sinks.error}
        onRetry={sinks.reload}
        empty={{
          title: t(unsupported ? "screen.audit.sinksUnsupported" : "screen.audit.sinksNone"),
          icon: "server",
        }}
        summary
        minWidth={800}
        ariaLabel={t("screen.audit.sinksTitle")}
      />
    </Card>
  );
}

/** The verdict of a chain check, said in a word beside the colour. */
const VERDICT_TONE: Record<VerifyResult["kind"], Tone> = {
  ok: "success",
  tamper: "destructive",
  broken: "destructive",
  error: "absent",
};

function VerifyResultCard({
  result,
  onDismiss,
  onRetry,
  retrying,
}: {
  result: VerifyResult;
  onDismiss: () => void;
  /** A check that could not run (kind "error") offers to run again. */
  onRetry: () => void;
  retrying: boolean;
}) {
  const { t } = useTranslation();
  const ok = result.kind === "ok";
  const color = ok ? "var(--success)" : "var(--destructive)";
  return (
    <div
      role={ok ? "status" : "alert"}
      style={{
        display: "flex",
        flexWrap: "wrap",
        alignItems: "center",
        gap: "8px 12px",
        padding: "10px 12px 10px 16px",
        background: tint(color, 10),
        border: `1px solid ${tint(color, 40)}`,
        borderRadius: "var(--radius-lg)",
      }}
    >
      <Icon name={ok ? "shieldcheck" : "alert"} size={16} color={color} />
      <ToneBadge tone={VERDICT_TONE[result.kind]}>{t(`screen.audit.verdict.${result.kind}`)}</ToneBadge>
      <p
        style={{
          flex: "1 1 16rem",
          minWidth: 0,
          margin: 0,
          fontSize: 14,
          lineHeight: "20px",
          maxWidth: "72ch",
          overflowWrap: "anywhere",
          color: ok ? "var(--foreground)" : "var(--destructive)",
        }}
      >
        {result.msg}
      </p>
      <div style={{ display: "flex", alignItems: "center", gap: 4, marginLeft: "auto" }}>
        {result.kind === "error" ? (
          <Btn size="sm" variant="outline" icon="refresh" loading={retrying} onClick={onRetry}>
            {t("common.retry")}
          </Btn>
        ) : null}
        <IconBtn icon="x" title={t("common.close")} onClick={onDismiss} />
      </div>
    </div>
  );
}

// ── The log, grouped by day ─────────────────────────────────────

/** The reader's local date of an epoch-seconds moment ("2026-10-24"): the key of its day. */
function localDay(sec: number): string {
  const d = new Date(sec * 1000);
  return [d.getFullYear(), d.getMonth() + 1, d.getDate()].map((p) => String(p).padStart(2, "0")).join("-");
}

/** The log cut into the reader's local days, in the order it came: a new group wherever the day changes. */
function byLocalDay(entries: AuditEntry[]): { day: string; at: number; items: AuditEntry[] }[] {
  const days: { day: string; at: number; items: AuditEntry[] }[] = [];
  for (const entry of entries) {
    const day = localDay(entry.recorded_at);
    const last = days[days.length - 1];
    if (last && last.day === day) last.items.push(entry);
    else days.push({ day, at: entry.recorded_at, items: [entry] });
  }
  return days;
}

/** Whole calendar days between a moment and now: 0 today, 1 yesterday. */
function daysAgo(sec: number, nowMs = Date.now()): number {
  const a = new Date(sec * 1000);
  const b = new Date(nowMs);
  return Math.round(
    (Date.UTC(b.getFullYear(), b.getMonth(), b.getDate()) - Date.UTC(a.getFullYear(), a.getMonth(), a.getDate())) /
      86_400_000,
  );
}

/** A day as the head of its rows says it: "Today · Sat, 24 October 2026", further off the date alone. */
function DayWords({ day, at }: { day: string; at: number }) {
  const { t, i18n } = useTranslation();
  const ago = daysAgo(at);
  const word = ago === 0 ? t("common.today") : ago === 1 ? t("common.yesterday") : null;
  return (
    <>
      {word ? <span style={{ color: "var(--foreground)" }}>{word} · </span> : null}
      <time dateTime={day}>
        {new Date(at * 1000).toLocaleDateString(i18n.language, {
          weekday: "short",
          day: "numeric",
          month: "long",
          year: "numeric",
        })}
      </time>
    </>
  );
}

/** The clock of a row (its day is the group's head); how long ago is its title. */
function RowClock({ at }: { at: number }) {
  const { i18n } = useTranslation();
  const d = new Date(at * 1000);
  return (
    <time dateTime={d.toISOString()} title={fmtRelative(at)} style={MUTED}>
      {d.toLocaleTimeString(i18n.language, { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
    </time>
  );
}

/**
 * What happened, in one line: the event's name in mono in the text colour
 * (muted for an entry the server cannot read), then its fields muted, cut at
 * the cell's end; the whole line is the title. An event is a fact, not a
 * state: a removal is not a failure, so no event name is ever red.
 */
function EventCell({ row }: { row: AuditEntry }) {
  const ev = decodeEvent(row);
  const unnamed = ev.type.startsWith("(");
  return (
    <span
      title={ev.detail ? `${ev.type} · ${ev.detail}` : ev.type}
      style={{
        display: "flex",
        alignItems: "baseline",
        gap: 8,
        minWidth: 0,
        fontFamily: MONO,
        fontSize: 12,
        lineHeight: "16px",
        whiteSpace: "nowrap",
      }}
    >
      <span
        style={{
          flexShrink: 0,
          fontWeight: 500,
          color: unnamed ? "var(--muted-foreground)" : "var(--foreground)",
        }}
      >
        {ev.type}
      </span>
      {ev.detail ? <span style={{ ...ELLIPSIS, minWidth: 0, ...MUTED }}>{ev.detail}</span> : null}
    </span>
  );
}

/** The head row in the label style, as DataTable draws it. */
const HEAD: CSSProperties = {
  height: 28,
  background: "var(--rail)",
  borderBottom: "1px solid var(--rule)",
  fontSize: 11,
  fontWeight: 600,
  letterSpacing: "0.05em",
  textTransform: "uppercase",
  color: "var(--muted-foreground)",
};

function AuditBody() {
  const { t } = useTranslation();
  const [rows, setRows] = useState<AuditEntry[]>([]);
  const [sinceSeq, setSinceSeq] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = (reset: boolean) => {
    setLoading(true);
    setError(null);
    api.identity
      .audit(reset ? 0 : sinceSeq, 50)
      .then((r) => {
        setRows((p) => (reset ? r.entries : [...p, ...r.entries]));
        setSinceSeq(r.next_since);
        setHasMore(r.has_more);
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    setRows([]);
    load(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const columns: Column<AuditEntry>[] = [
    {
      key: "seq",
      // The field the export bounds and the chain's verdicts name: an identifier, so mono and lowercase.
      label: <span className="data-head-mono">seq</span>,
      width: "72px",
      numeric: true,
      render: (row) => row.seq,
    },
    {
      key: "recorded_at",
      label: t("screen.audit.colWhen"),
      width: "80px",
      render: (row) => <RowClock at={row.recorded_at} />,
    },
    {
      key: "event",
      label: t("screen.audit.colEvent"),
      width: "minmax(0, 1.6fr)",
      render: (row) => <EventCell row={row} />,
    },
    {
      key: "source",
      label: t("screen.audit.colSource"),
      width: "136px",
      // Who wrote it down is a fact, not a state: one neutral chip for both sources.
      render: (row) => <Tag mono>{row.source}</Tag>,
    },
    {
      key: "author_pubkey",
      label: t("screen.audit.colAuthor"),
      width: "minmax(0, 1fr)",
      render: (row) => <PubkeyChip value={row.author_pubkey} />,
    },
  ];

  return (
    <>
      <ZkBanner tone="amber">{t("zk.audit")}</ZkBanner>
      <DayLog
        columns={columns}
        rows={rows}
        loading={loading}
        error={error}
        hasMore={hasMore}
        onRetry={() => load(true)}
        onMore={() => load(false)}
      />
    </>
  );
}

/**
 * The log as DataTable draws a table (summary line, the head 28 px on --rail,
 * rows of 32 px divided by --rule), its rows grouped under the day they were
 * recorded on: a 28 px head on --elevated at 40 % with the day and, after a
 * middle dot, how many entries it holds (left out for the last day while more
 * is to be read, since its rows are not all here).
 */
function DayLog({
  columns,
  rows,
  loading,
  error,
  hasMore,
  onRetry,
  onMore,
}: {
  columns: Column<AuditEntry>[];
  rows: AuditEntry[];
  loading: boolean;
  error: string | null;
  hasMore: boolean;
  onRetry: () => void;
  onMore: () => void;
}) {
  const { t } = useTranslation();
  const firstLoad = loading && rows.length === 0;

  if (error && rows.length === 0) {
    return <ErrorCard message={error} onRetry={onRetry} retrying={loading} />;
  }
  if (!loading && rows.length === 0) {
    return <EmptyState icon="eye" title={t("screen.audit.empty")} />;
  }

  const grid: CSSProperties = {
    display: "grid",
    gridTemplateColumns: columns.map((c) => c.width).join(" "),
    columnGap: 12,
    alignItems: "center",
    padding: "0 16px",
  };
  const rowStyle: CSSProperties = {
    ...grid,
    minHeight: 32,
    paddingTop: 4,
    paddingBottom: 4,
    borderBottom: "1px solid var(--rule)",
  };
  const cellStyle = (c: Column<AuditEntry>): CSSProperties => ({
    minWidth: 0,
    overflow: "hidden",
    padding: 3,
    margin: -3,
    textAlign: c.numeric ? "right" : "left",
    fontFamily: c.numeric ? MONO : undefined,
    fontSize: c.numeric ? 12 : undefined,
  });

  const days = byLocalDay(rows);
  const n = fmtNum(rows.length);
  const signed = rows.filter((r) => r.source === "client-signed").length;

  return (
    <div
      style={{
        background: "var(--card)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius-lg)",
        boxShadow: "var(--elev-card)",
        overflow: "hidden",
      }}
    >
      <SummaryLine loading={firstLoad}>
        {firstLoad ? null : (
          <>
            <SummaryCount>{hasMore ? t("common.shownMore", { n }) : t("common.inAll", { n })}</SummaryCount>
            <SummaryPart label={<span style={{ fontFamily: MONO }}>client-signed</span>} value={fmtNum(signed)} />
            <SummaryPart
              label={<span style={{ fontFamily: MONO }}>server-observed</span>}
              value={fmtNum(rows.length - signed)}
            />
          </>
        )}
      </SummaryLine>

      {error ? (
        <div style={{ borderBottom: "1px solid var(--rule)" }}>
          <ErrorCard message={error} onRetry={onRetry} retrying={loading} band />
        </div>
      ) : null}

      <div style={{ overflowX: "auto" }}>
        <div role="table" aria-label={t("screen.audit.title")} aria-busy={loading || undefined} style={{ minWidth: 760 }}>
          <div role="row" style={{ ...grid, ...HEAD }}>
            {columns.map((c) => (
              <span key={c.key} role="columnheader" style={{ ...ELLIPSIS, minWidth: 0, textAlign: c.numeric ? "right" : "left" }}>
                {c.label}
              </span>
            ))}
          </div>

          {firstLoad ? (
            <div role="rowgroup">
              {Array.from({ length: 5 }, (_, i) => (
                <div key={i} role="row" className="dt-row dt-skeleton-row" style={rowStyle}>
                  {columns.map((c) => (
                    <span key={c.key} role="cell" style={cellStyle(c)}>
                      <Skeleton width="75%" height={14} style={c.numeric ? { marginLeft: "auto" } : undefined} />
                    </span>
                  ))}
                </div>
              ))}
            </div>
          ) : (
            days.map((group, index) => {
              const whole = !(hasMore && index === days.length - 1);
              return (
                <div key={group.day} role="rowgroup">
                  <div
                    role="row"
                    style={{
                      display: "flex",
                      alignItems: "center",
                      height: 28,
                      padding: "0 16px",
                      background: tint("var(--elevated)", 40),
                      borderTop: index > 0 ? "1px solid var(--rule)" : undefined,
                      borderBottom: "1px solid var(--rule)",
                      fontSize: 12,
                      fontWeight: 500,
                      lineHeight: "16px",
                      color: "var(--muted-foreground)",
                    }}
                  >
                    <span role="rowheader" aria-colspan={columns.length} style={ELLIPSIS}>
                      <DayWords day={group.day} at={group.at} />
                      {whole ? <span style={{ fontWeight: 400 }}> · {fmtNum(group.items.length)}</span> : null}
                    </span>
                  </div>
                  {group.items.map((row) => (
                    <div key={String(row.seq)} role="row" className="dt-row" style={rowStyle}>
                      {columns.map((c) => {
                        const v = c.render(row);
                        return (
                          <span key={c.key} role="cell" style={cellStyle(c)}>
                            {v === null || v === undefined || v === "" ? <Missing /> : v}
                          </span>
                        );
                      })}
                    </div>
                  ))}
                </div>
              );
            })
          )}
        </div>
      </div>

      {hasMore ? (
        <div
          style={{
            display: "flex",
            justifyContent: "center",
            padding: "8px 16px",
            borderTop: "1px solid var(--rule)",
          }}
        >
          <Btn size="sm" variant="outline" loading={loading} onClick={onMore}>
            {t("common.more")}
          </Btn>
        </div>
      ) : null}
    </div>
  );
}
