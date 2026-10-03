import { type RefObject, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { fmtRelative } from "../util/format";
import type { AuditEntry, AuditSink } from "../api/types";
import { truncId } from "../util/bytes";
import { DataTable, type Column } from "../ui/DataTable";
import { Icon } from "../ui/icons";
import {
  Btn,
  Card,
  ErrorCard,
  Field,
  PubkeyChip,
  Spinner,
  StatusDot,
  Tag,
  TextInput,
  ZkBanner,
  type DotStatus,
  type TagTone,
} from "../ui/primitives";
import { useAsync } from "../util/useAsync";
import { Screen } from "./Screen";
import { MONO } from "../theme/tokens";

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
  const [exportOpen, setExportOpen] = useState(false);
  const exportToggle = useRef<HTMLButtonElement>(null);
  const closeExport = () => {
    setExportOpen(false);
    exportToggle.current?.focus();
  };

  const verify = async () => {
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
            size="sm"
            onClick={() => setExportOpen((o) => !o)}
            ariaExpanded={exportOpen}
            ariaControls="audit-export"
          >
            {t("screen.audit.export")}
          </Btn>
          <Btn icon="shieldcheck" size="sm" onClick={() => void verify()}>
            {t("screen.audit.verifyChain")}
          </Btn>
        </>
      }
    >
      {exportOpen ? <ExportCard onClose={closeExport} toggle={exportToggle} /> : null}
      {result ? <VerifyResultCard result={result} onDismiss={() => setResult(null)} /> : null}
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
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card style={{ marginBottom: 14 }}>
      <form
        id="audit-export"
        ref={form}
        onSubmit={(e) => {
          e.preventDefault();
          void download();
        }}
      >
        <div style={{ fontSize: 13.5, fontWeight: 700, marginBottom: 4 }}>
          {t("screen.audit.exportTitle")}
        </div>
        <div style={{ fontSize: 12, color: "var(--txt3)", lineHeight: 1.5, marginBottom: 14 }}>
          {t("screen.audit.exportHint")}
        </div>
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
          <div style={{ flex: "1 1 160px" }}>
            <Field label={t("screen.audit.exportFrom")} tag="from_seq">
              <TextInput
                value={from}
                onChange={setFrom}
                placeholder="1"
                mono
                autoFocus
                inputMode="numeric"
                ariaLabel={t("screen.audit.exportFrom")}
              />
            </Field>
          </div>
          <div style={{ flex: "1 1 160px" }}>
            <Field label={t("screen.audit.exportTo")} tag="to_seq">
              <TextInput
                value={to}
                onChange={setTo}
                placeholder={t("screen.audit.exportToHead")}
                mono
                inputMode="numeric"
                ariaLabel={t("screen.audit.exportTo")}
              />
            </Field>
          </div>
        </div>
        {invalid ? (
          <div role="alert" style={{ fontSize: 12, color: "var(--red)", marginBottom: 10 }}>
            {t("screen.audit.exportInvalid")}
          </div>
        ) : null}
        {error ? (
          <div role="alert" style={{ fontSize: 12, color: "var(--red)", marginBottom: 10 }}>
            {error}
          </div>
        ) : null}
        <div style={{ display: "flex", gap: 9, justifyContent: "flex-end" }}>
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

const SINK_TONE: Record<SinkState, { tag: TagTone; dot: DotStatus }> = {
  healthy: { tag: "green", dot: "online" },
  lagging: { tag: "amber", dot: "warn" },
  failing: { tag: "red", dot: "offline" },
};

/** Delivery state of each sink configured in the server's `[audit.*]` config. */
function SinksCard() {
  const { t } = useTranslation();
  const sinks = useAsync(() => api.admin.auditSinks(), []);
  const list = sinks.data?.sinks ?? [];

  return (
    <Card style={{ marginBottom: 14 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
        <div style={{ flex: 1, fontSize: 13.5, fontWeight: 700 }}>{t("screen.audit.sinksTitle")}</div>
        <Btn icon="refresh" size="sm" variant="ghost" onClick={sinks.reload} loading={sinks.loading}>
          {t("common.checkNow")}
        </Btn>
      </div>
      {sinks.error ? (
        <ErrorCard message={sinks.error} onRetry={sinks.reload} />
      ) : sinks.data === null ? (
        <Spinner size={16} />
      ) : list.length === 0 ? (
        <div style={{ fontSize: 12, color: "var(--txt3)", lineHeight: 1.5 }}>
          {t("screen.audit.sinksNone")}
        </div>
      ) : (
        <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: 10 }}>
          {list.map((s) => (
            <SinkRow key={s.sink} sink={s} />
          ))}
        </ul>
      )}
    </Card>
  );
}

function SinkRow({ sink }: { sink: AuditSink }) {
  const { t } = useTranslation();
  const state = sinkState(sink);
  const tone = SINK_TONE[state];
  const fact = { fontSize: 12, color: "var(--txt2)" } as const;
  return (
    <li style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
      <span style={{ marginTop: 5 }}>
        <StatusDot status={tone.dot} />
      </span>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <span style={{ fontFamily: MONO, fontSize: 12.5, fontWeight: 700 }}>{sink.sink}</span>
          <Tag tone={tone.tag}>{t(`screen.audit.sinkState.${state}`)}</Tag>
        </div>
        <div style={{ display: "flex", gap: "4px 16px", flexWrap: "wrap", marginTop: 4 }}>
          <span style={fact}>
            {t("screen.audit.sinkLastSeq")}{" "}
            <span style={{ fontFamily: MONO }}>{sink.last_seq}</span>
          </span>
          <span style={fact}>
            {t("screen.audit.sinkLag")} <span style={{ fontFamily: MONO }}>{sink.lag}</span>
          </span>
          <span style={fact}>
            {t("screen.audit.sinkLastSuccess")} {fmtRelative(sink.last_success_at)}
          </span>
        </div>
        {sink.last_error ? (
          <div style={{ ...fact, marginTop: 3 }}>
            {t("screen.audit.sinkLastError")}{" "}
            <span style={{ fontFamily: MONO, color: state === "failing" ? "var(--red)" : undefined }}>
              {sink.last_error}
            </span>{" "}
            · {fmtRelative(sink.last_error_at)}
          </div>
        ) : null}
      </div>
    </li>
  );
}

function VerifyResultCard({
  result,
  onDismiss,
}: {
  result: VerifyResult;
  onDismiss: () => void;
}) {
  const { t } = useTranslation();
  const ok = result.kind === "ok";
  const color = ok ? "var(--green)" : "var(--red)";
  return (
    <div
      role={ok ? "status" : "alert"}
      style={{
        display: "flex",
        gap: 10,
        alignItems: "flex-start",
        background: `color-mix(in srgb, ${color} 9%, transparent)`,
        border: `1px solid color-mix(in srgb, ${color} 34%, transparent)`,
        borderRadius: 11,
        padding: "12px 14px",
        marginBottom: 14,
      }}
    >
      <Icon name={ok ? "shieldcheck" : "alert"} size={16} color={color} style={{ marginTop: 1 }} />
      <span style={{ flex: 1, fontSize: 12.5, color: "var(--txt)", lineHeight: 1.5 }}>
        {result.msg}
      </span>
      <button
        aria-label={t("common.close")}
        onClick={onDismiss}
        style={{
          border: "none",
          background: "transparent",
          color: "var(--txt3)",
          cursor: "pointer",
          display: "flex",
        }}
      >
        <Icon name="plus" size={14} style={{ transform: "rotate(45deg)" }} />
      </button>
    </div>
  );
}

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
      label: "seq",
      width: "86px",
      render: (row) => (
        <span style={{ fontFamily: MONO, fontSize: 12 }}>{row.seq}</span>
      ),
    },
    {
      key: "event",
      label: "event",
      width: "1.6fr",
      render: (row) => {
        const ev = decodeEvent(row);
        return (
          <div style={{ minWidth: 0 }}>
            <div
              style={{
                fontFamily: MONO,
                fontSize: 12,
                fontWeight: 600,
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
            >
              {ev.type}
            </div>
            {ev.detail ? (
              <div
                style={{
                  fontSize: 11,
                  color: "var(--txt3)",
                  fontFamily: MONO,
                  marginTop: 1,
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
              >
                {ev.detail}
              </div>
            ) : null}
          </div>
        );
      },
    },
    {
      key: "source",
      label: "source",
      width: "150px",
      render: (row) => (
        <Tag tone={row.source === "client-signed" ? "accent" : "neutral"}>{row.source}</Tag>
      ),
    },
    {
      key: "author_pubkey",
      label: "author_pubkey",
      width: "1fr",
      render: (row) => <PubkeyChip value={row.author_pubkey} />,
    },
    {
      key: "recorded_at",
      label: t("screen.audit.colWhen"),
      width: "96px",
      render: (row) => (
        <span style={{ fontSize: 12, color: "var(--txt2)" }}>{fmtRelative(row.recorded_at)}</span>
      ),
    },
  ];

  return (
    <>
      <ZkBanner tone="amber">{t("zk.audit")}</ZkBanner>

      <DataTable<AuditEntry>
        columns={columns}
        rows={rows}
        rowKey={(row) => String(row.seq)}
        loading={loading}
        error={error}
        onRetry={() => load(true)}
        empty={{ title: t("screen.audit.empty"), icon: "eye" }}
        more={{ hasMore, loading, onMore: () => load(false) }}
      />
    </>
  );
}
