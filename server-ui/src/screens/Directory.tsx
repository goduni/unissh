import { useMemo, useState, type CSSProperties } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import type { DirEntry } from "../api/types";
import { useUi } from "../store/ui";
import { useAsync } from "../util/useAsync";
import { truncId } from "../util/bytes";
import { DataTable, type Column } from "../ui/DataTable";
import { Icon } from "../ui/icons";
import {
  Avatar,
  PubkeyChip,
  StateBadge,
  SummaryCount,
  SummaryPart,
  TextInput,
  ZkBanner,
  initialsOf,
} from "../ui/primitives";
import { Screen } from "./Screen";
import { MONO } from "../theme/tokens";
import "./identity.css";

export function Directory() {
  const { t } = useTranslation();
  return (
    <Screen title={t("screen.directory.title")} sub={t("screen.directory.sub")} zk>
      <DirectoryBody />
    </Screen>
  );
}

function DirectoryBody() {
  const { t, i18n } = useTranslation();
  const reloadTick = useUi((s) => s.reloadTick);
  const data = useAsync(() => api.identity.directory(), [reloadTick]);
  const [q, setQ] = useState("");

  const accounts = useMemo(() => data.data?.accounts ?? [], [data.data]);
  const filtered = useMemo(() => {
    const s = q.trim().toLowerCase();
    if (!s) return accounts;
    return accounts.filter(
      (a) =>
        (a.display_name ?? "").toLowerCase().includes(s) ||
        (a.handle ?? "").toLowerCase().includes(s) ||
        a.member_pubkey.toLowerCase().includes(s),
    );
  }, [accounts, q]);

  const nameOf = (a: DirEntry) => a.display_name || a.handle || "—";

  // The summary line: how many, or what the filter found and the filter itself.
  const query = q.trim();
  const reading = data.loading && accounts.length === 0;
  const summary = query ? (
    <>
      <SummaryCount>{t("common.found", { n: filtered.length.toLocaleString(i18n.language) })}</SummaryCount>
      <SummaryPart
        label={t("common.filter")}
        value={
          <span style={{ ...TRUNC, display: "inline-block", maxWidth: "24ch", verticalAlign: "bottom" }}>{query}</span>
        }
        active
      />
    </>
  ) : (
    <SummaryCount n={accounts.length} />
  );

  const columns: Column<DirEntry>[] = [
    {
      key: "who",
      label: t("screen.directory.colPerson"),
      width: "1.8fr",
      render: (a) => (
        <span style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
          <Avatar label={initialsOf(nameOf(a))} size={18} />
          {a.display_name ? (
            <span style={{ ...TRUNC, fontWeight: 500 }}>{a.display_name}</span>
          ) : (
            <span style={{ ...TRUNC, fontFamily: MONO, fontSize: 12, color: a.handle ? undefined : "var(--muted-foreground)" }}>
              {a.handle || truncId(a.account_id)}
            </span>
          )}
          {a.display_name && a.handle ? (
            <span
              style={{
                ...TRUNC,
                flexShrink: 4,
                fontFamily: MONO,
                fontSize: 12,
                lineHeight: "16px",
                color: "var(--muted-foreground)",
              }}
            >
              {a.handle}
            </span>
          ) : null}
        </span>
      ),
    },
    {
      key: "member",
      label: t("screen.directory.colMemberKey"),
      width: "1.5fr",
      render: (a) => <PubkeyChip value={a.member_pubkey} />,
    },
    {
      key: "x25519",
      label: t("screen.directory.colX25519"),
      width: "1.5fr",
      render: (a) => <PubkeyChip value={a.x25519_pub} />,
    },
    {
      key: "status",
      label: t("common.status"),
      width: "112px",
      // The badge says the state in the reader's words, as on every other screen.
      render: (a) => <StateBadge state={a.status === "active" ? "active" : "disabled"} />,
    },
  ];

  return (
    <>
      <ZkBanner>{t("zk.directory")}</ZkBanner>

      <div style={{ display: "flex" }}>
        <div className="id-filter">
          <Icon name="searchIcon" size={16} color="var(--muted-foreground)" />
          <TextInput
            value={q}
            onChange={setQ}
            placeholder={t("screen.directory.filterPlaceholder")}
            ariaLabel={t("screen.directory.filterPlaceholder")}
            style={{ paddingLeft: 32 }}
          />
        </div>
      </div>

      <DataTable
        columns={columns}
        rows={filtered}
        rowKey={(a) => a.account_id}
        loading={data.loading}
        error={data.error}
        onRetry={data.reload}
        summary={reading ? true : summary}
        minWidth={720}
        ariaLabel={t("screen.directory.title")}
        empty={
          query
            ? {
                title: t("common.nothingFound"),
                icon: "searchIcon",
                actionLabel: t("common.resetFilters"),
                onAction: () => setQ(""),
              }
            : { title: t("screen.directory.empty"), icon: "user" }
        }
      />
    </>
  );
}

const TRUNC: CSSProperties = {
  minWidth: 0,
  whiteSpace: "nowrap",
  overflow: "hidden",
  textOverflow: "ellipsis",
};
