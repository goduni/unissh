import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { truncId } from "../util/bytes";
import { fmtBytes, fmtEpoch, fmtNum, fmtRelative } from "../util/format";
import type { ObjectMeta } from "../api/types";
import { DataTable, type Column } from "../ui/DataTable";
import { PubkeyChip, Segmented, SummaryCount, Tag, ToneBadge, ZkBanner } from "../ui/primitives";
import { Screen } from "./Screen";
import { MONO } from "../theme/tokens";
import "./data.css";

const TAG_FILTERS: { label: string; tag: number | undefined }[] = [
  { label: "common.all", tag: undefined },
  { label: "screen.objects.tagVault", tag: 1 },
  { label: "screen.objects.tagItem", tag: 2 },
  { label: "screen.objects.tagManifest", tag: 3 },
  { label: "screen.objects.tagGrant", tag: 4 },
  { label: "screen.objects.tagAudit", tag: 5 },
  { label: "screen.objects.tagKeyset", tag: 6 },
];

/** The kind of an object in the reader's words, as the filter names it. */
const TAG_WORD = new Map(TAG_FILTERS.flatMap((f) => (f.tag === undefined ? [] : [[f.tag, f.label] as const])));

/** The toggle group speaks strings: "all" stands for no tag. */
const ALL = "all";
const filterValue = (tag: number | undefined) => (tag === undefined ? ALL : String(tag));

export function Objects() {
  const { t } = useTranslation();
  return (
    <Screen title={t("screen.objects.title")} sub={t("screen.objects.sub")} zk>
      <ObjectsBody />
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

  const muted = { color: "var(--muted-foreground)" } as const;

  const columns: Column<ObjectMeta>[] = [
    {
      key: "server_seq",
      // The server's sequence number, as the audit log names it: an identifier, so mono and lowercase.
      label: <span className="data-head-mono">seq</span>,
      width: "80px",
      numeric: true,
      render: (row) => row.server_seq,
    },
    {
      key: "object_tag",
      label: t("screen.objects.colType"),
      width: "112px",
      // The kind of an object is a fact, not a state: one neutral chip for every kind,
      // in the filter's words; a tag the panel does not know stays its number, in mono.
      render: (row) => {
        const word = TAG_WORD.get(row.object_tag);
        return word ? <Tag>{t(word)}</Tag> : <Tag mono>{row.object_tag}</Tag>;
      },
    },
    {
      key: "vault_id",
      label: t("screen.objects.colVault"),
      width: "1.1fr",
      render: (row) =>
        row.vault_id || row.tombstone ? (
          <span style={{ display: "inline-flex", alignItems: "center", gap: 8, minWidth: 0, maxWidth: "100%" }}>
            <span
              title={row.vault_id ?? undefined}
              style={{
                ...muted,
                fontFamily: MONO,
                fontSize: 12,
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
            >
              {truncId(row.vault_id)}
            </span>
            {row.tombstone ? <ToneBadge tone="absent">{t("common.tombstone")}</ToneBadge> : null}
          </span>
        ) : null,
    },
    {
      key: "obj_version",
      label: t("screen.objects.colVersion"),
      width: "64px",
      numeric: true,
      render: (row) => row.obj_version,
    },
    {
      key: "key_epoch",
      label: t("screen.objects.colEpoch"),
      width: "64px",
      numeric: true,
      render: (row) => row.key_epoch,
    },
    {
      key: "author_pubkey",
      label: t("screen.objects.colAuthor"),
      width: "1fr",
      render: (row) => <PubkeyChip value={row.author_pubkey} />,
    },
    {
      key: "received_at",
      label: t("screen.objects.colReceived"),
      width: "96px",
      render: (row) => (
        <span title={fmtEpoch(row.received_at)} style={muted}>
          {fmtRelative(row.received_at)}
        </span>
      ),
    },
    {
      key: "blob_len",
      label: t("screen.objects.colSize"),
      width: "84px",
      numeric: true,
      render: (row) => fmtBytes(row.blob_len),
    },
  ];

  // How many: the whole list, or what a narrowed one found; a page with more behind it says so.
  // While the first page is read, the summary line holds a skeleton in the count's place.
  const n = fmtNum(rows.length);
  const count = hasMore
    ? t("common.shownMore", { n })
    : tag !== undefined
      ? t("common.found", { n })
      : t("common.inAll", { n });

  return (
    <>
      <ZkBanner>{t("zk.objects")}</ZkBanner>

      {/* Long labels in some languages: the group scrolls sideways on a phone instead of breaking. */}
      <div style={{ maxWidth: "100%", overflowX: "auto" }}>
        <Segmented
          ariaLabel={t("screen.objects.filterTag")}
          options={TAG_FILTERS.map((f) => ({ value: filterValue(f.tag), label: t(f.label) }))}
          value={filterValue(tag)}
          onChange={(v) => setTag(v === ALL ? undefined : Number(v))}
        />
      </div>

      <DataTable<ObjectMeta>
        columns={columns}
        rows={rows}
        rowKey={(row) => String(row.server_seq)}
        loading={loading}
        error={error}
        onRetry={() => load(true)}
        empty={
          tag !== undefined
            ? {
                title: t("screen.objects.empty"),
                icon: "layers",
                actionLabel: t("common.resetFilters"),
                onAction: () => setTag(undefined),
              }
            : { title: t("screen.objects.empty"), icon: "layers" }
        }
        more={{ hasMore, loading, onMore: () => load(false) }}
        summary={loading && rows.length === 0 ? true : <SummaryCount>{count}</SummaryCount>}
        minWidth={760}
        ariaLabel={t("screen.objects.title")}
      />
    </>
  );
}
