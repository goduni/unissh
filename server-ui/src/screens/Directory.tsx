import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import type { DirEntry } from "../api/types";
import { useUi } from "../store/ui";
import { useAsync } from "../util/useAsync";
import { DataTable, type Column } from "../ui/DataTable";
import { Icon } from "../ui/icons";
import { Avatar, PubkeyChip, StatusDot, ZkBanner, initialsOf } from "../ui/primitives";
import { Screen } from "./Screen";
import { MONO } from "../theme/tokens";

export function Directory() {
  const { t } = useTranslation();
  return (
    <Screen title={t("screen.directory.title")} sub={t("screen.directory.sub")} zk>
      <DirectoryBody />
    </Screen>
  );
}

function DirectoryBody() {
  const { t } = useTranslation();
  const reloadTick = useUi((s) => s.reloadTick);
  const data = useAsync(() => api.identity.directory(), [reloadTick]);
  const [q, setQ] = useState("");

  const accounts = data.data?.accounts ?? [];
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

  const columns: Column<DirEntry>[] = [
    {
      key: "who",
      label: t("screen.directory.colPerson"),
      width: "1.8fr",
      render: (a) => (
        <span style={{ display: "flex", alignItems: "center", gap: 10, minWidth: 0 }}>
          <Avatar label={initialsOf(nameOf(a))} seed={a.account_id.length} size={30} />
          <span style={{ minWidth: 0 }}>
            <span
              style={{
                display: "block",
                fontSize: 13,
                fontWeight: 600,
                whiteSpace: "nowrap",
                overflow: "hidden",
                textOverflow: "ellipsis",
              }}
            >
              {nameOf(a)}
            </span>
            <span style={{ fontSize: 11, color: "var(--txt3)", fontFamily: MONO }}>
              {a.handle ?? "—"}
            </span>
          </span>
        </span>
      ),
    },
    { key: "member", label: "member_pubkey", width: "1.5fr", render: (a) => <PubkeyChip value={a.member_pubkey} /> },
    { key: "x25519", label: "x25519_pub", width: "1.5fr", render: (a) => <PubkeyChip value={a.x25519_pub} /> },
    {
      key: "status",
      label: t("common.status"),
      width: "110px",
      render: (a) => (
        <span
          style={{
            display: "flex",
            alignItems: "center",
            gap: 6,
            fontSize: 12,
            fontWeight: 600,
            color: a.status === "active" ? "var(--green)" : "var(--red)",
          }}
        >
          <StatusDot status={a.status === "active" ? "online" : "offline"} size={7} />
          {a.status === "active" ? t("common.active") : t("common.disabled")}
        </span>
      ),
    },
  ];

  return (
    <>
      <ZkBanner>{t("zk.directory")}</ZkBanner>

      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          height: 34,
          padding: "0 12px",
          marginBottom: 14,
          borderRadius: 9,
          background: "var(--bg1)",
          border: "1px solid var(--line)",
          maxWidth: 460,
        }}
      >
        <Icon name="searchIcon" size={14} color="var(--txt3)" />
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder={t("screen.directory.filterPlaceholder")}
          style={{
            flex: 1,
            border: "none",
            background: "transparent",
            color: "var(--txt)",
            fontSize: 13,
            outline: "none",
            fontFamily: "inherit",
          }}
        />
      </div>

      <DataTable
        columns={columns}
        rows={filtered}
        rowKey={(a) => a.account_id}
        loading={data.loading}
        error={data.error}
        onRetry={data.reload}
        empty={{ title: t("screen.directory.empty"), icon: "user" }}
      />
    </>
  );
}
