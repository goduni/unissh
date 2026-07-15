import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { fmtRelative } from "../util/format";
import type { AuditEntry } from "../api/types";
import { truncId } from "../util/bytes";
import { DataTable, type Column } from "../ui/DataTable";
import { Icon } from "../ui/icons";
import { Btn, PubkeyChip, Tag, ZkBanner } from "../ui/primitives";
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
        <Btn icon="shieldcheck" size="sm" onClick={() => void verify()}>
          {t("screen.audit.verifyChain")}
        </Btn>
      }
    >
      {result ? <VerifyResultCard result={result} onDismiss={() => setResult(null)} /> : null}
      <AuditBody />
    </Screen>
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
