import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { truncId } from "../util/bytes";
import { fmtBytes, fmtRelative } from "../util/format";
import { OBJECT_TAG_LABEL } from "../api/types";
import type { ObjectMeta } from "../api/types";
import { DataTable, type Column } from "../ui/DataTable";
import { PubkeyChip, Tag, ZkBanner, type TagTone } from "../ui/primitives";
import { KeysetGate } from "../ui/overlays";
import { Screen } from "./Screen";
import { MONO } from "../theme/tokens";

const TAG_FILTERS: { label: string; tag: number | undefined }[] = [
  { label: "common.all", tag: undefined },
  { label: "screen.objects.tagVault", tag: 1 },
  { label: "screen.objects.tagItem", tag: 2 },
  { label: "screen.objects.tagManifest", tag: 3 },
  { label: "screen.objects.tagGrant", tag: 4 },
  { label: "screen.objects.tagAudit", tag: 5 },
  { label: "screen.objects.tagKeyset", tag: 6 },
];

function tagTone(tag: number): TagTone {
  switch (tag) {
    case 1:
      return "accent";
    case 2:
      return "green";
    case 3:
      return "purple";
    case 4:
      return "amber";
    case 5:
      return "neutral";
    case 6:
      return "red";
    default:
      return "neutral";
  }
}

export function Objects() {
  const { t } = useTranslation();
  return (
    <Screen title={t("screen.objects.title")} sub={t("screen.objects.sub")} zk>
      <KeysetGate>
        <ObjectsBody />
      </KeysetGate>
    </Screen>
  );
}

function ObjectsBody() {
  const { t } = useTranslation();
  const [tag, setTag] = useState<number | undefined>(undefined);
  const [rows, setRows] = useState<ObjectMeta[]>([]);
  const [cursor, setCursor] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = (reset: boolean) => {
    setLoading(true);
    setError(null);
    api.admin
      .objects({ tag, cursor: reset ? 0 : cursor, limit: 50 })
      .then((r) => {
        setRows((p) => (reset ? r.items : [...p, ...r.items]));
        setCursor(r.next_cursor);
        setHasMore(r.has_more);
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    setRows([]);
    load(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tag]);

  const columns: Column<ObjectMeta>[] = [
    {
      key: "server_seq",
      label: "seq",
      width: "84px",
      render: (row) => (
        <span style={{ fontFamily: MONO, fontSize: 12 }}>
          {row.server_seq}
        </span>
      ),
    },
    {
      key: "object_tag",
      label: "tag",
      width: "94px",
      render: (row) => (
        <Tag tone={tagTone(row.object_tag)}>
          {OBJECT_TAG_LABEL[row.object_tag] ?? row.object_tag}
        </Tag>
      ),
    },
    {
      key: "vault_id",
      label: "vault_id",
      width: "1.1fr",
      render: (row) => (
        <span style={{ display: "inline-flex", alignItems: "center", gap: 7, minWidth: 0 }}>
          <span
            style={{
              fontFamily: MONO,
              fontSize: 12,
              color: "var(--txt2)",
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {truncId(row.vault_id)}
          </span>
          {row.tombstone ? <Tag tone="red">TOMB</Tag> : null}
        </span>
      ),
    },
    {
      key: "obj_version",
      label: "ver",
      width: "64px",
      render: (row) => (
        <span style={{ fontFamily: MONO, fontSize: 12, color: "var(--txt3)" }}>
          {row.obj_version ?? "—"}
        </span>
      ),
    },
    {
      key: "key_epoch",
      label: "epoch",
      width: "64px",
      render: (row) => (
        <span style={{ fontFamily: MONO, fontSize: 12, color: "var(--txt3)" }}>
          {row.key_epoch ?? "—"}
        </span>
      ),
    },
    {
      key: "author_pubkey",
      label: "author",
      width: "1fr",
      render: (row) => <PubkeyChip value={row.author_pubkey} />,
    },
    {
      key: "received_at",
      label: t("screen.objects.colReceived"),
      width: "84px",
      render: (row) => (
        <span style={{ fontSize: 12, color: "var(--txt2)" }}>{fmtRelative(row.received_at)}</span>
      ),
    },
    {
      key: "blob_len",
      label: t("screen.objects.colSize"),
      width: "78px",
      render: (row) => (
        <span style={{ fontFamily: MONO, fontSize: 12 }}>
          {fmtBytes(row.blob_len)}
        </span>
      ),
    },
  ];

  return (
    <>
      <ZkBanner>{t("zk.objects")}</ZkBanner>

      <div style={{ display: "flex", flexWrap: "wrap", gap: 7, marginBottom: 14 }}>
        {TAG_FILTERS.map((f) => {
          const on = f.tag === tag;
          return (
            <button
              key={f.label}
              onClick={() => setTag(f.tag)}
              style={{
                padding: "6px 13px",
                borderRadius: 8,
                cursor: "pointer",
                fontFamily: "inherit",
                fontSize: 12.5,
                fontWeight: on ? 700 : 600,
                background: on ? "var(--accentSoft)" : "var(--bg1)",
                color: on ? "var(--accent)" : "var(--txt2)",
                border: on ? "1px solid var(--accentLine)" : "1px solid var(--line)",
              }}
            >
              {t(f.label)}
            </button>
          );
        })}
      </div>

      <DataTable<ObjectMeta>
        columns={columns}
        rows={rows}
        rowKey={(row) => String(row.server_seq)}
        loading={loading}
        error={error}
        onRetry={() => load(true)}
        empty={{ title: t("screen.objects.empty"), icon: "layers" }}
        more={{ hasMore, loading, onMore: () => load(false) }}
      />
    </>
  );
}
