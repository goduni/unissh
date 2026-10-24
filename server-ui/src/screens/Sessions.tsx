import { useState, type CSSProperties } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { useUi } from "../store/ui";
import { useAsync } from "../util/useAsync";
import { truncId } from "../util/bytes";
import { fmtRelative, isExpired } from "../util/format";
import { DataTable, type Column } from "../ui/DataTable";
import { PubkeyChip, StateBadge, SummaryCount, SummaryPart, TextInput, ZkBanner } from "../ui/primitives";
import { RowMenu } from "./RowMenu";
import { Screen } from "./Screen";
import "./identity.css";

interface SessionRow {
  session_id: string;
  account_id: string;
  device_id: string;
  access_expires: number;
  refresh_expires: number;
  created_at: number;
}

export function Sessions() {
  const { t } = useTranslation();
  return (
    <Screen title={t("screen.sessions.title")} sub={t("screen.sessions.sub")}>
      <SessionsBody />
    </Screen>
  );
}

function SessionsBody() {
  const { t } = useTranslation();
  const [acc, setAcc] = useState("");
  const askConfirm = useUi((s) => s.askConfirm);
  const toast = useUi((s) => s.toast);

  const x = useAsync(() => api.admin.sessions(acc || undefined), [acc]);
  const rows: SessionRow[] = x.data?.sessions ?? [];

  // The summary line: how many, and the account the list is narrowed to.
  const summary = (
    <>
      <SummaryCount n={rows.length} />
      {acc ? <SummaryPart label="account_id" value={truncId(acc)} active /> : null}
    </>
  );

  // A moment in words ("in 12 min", "5 min ago") is the panel's own text: Geologica, muted.
  const when = (sec: number) => (sec ? <span style={MUTED}>{fmtRelative(sec)}</span> : null);

  const columns: Column<SessionRow>[] = [
    {
      key: "account_id",
      label: t("screen.sessions.colAccount"),
      width: "minmax(140px, 1fr)",
      render: (row) => <PubkeyChip value={row.account_id} />,
    },
    {
      key: "device_id",
      label: t("screen.sessions.colDevice"),
      width: "minmax(140px, 1fr)",
      render: (row) => <PubkeyChip value={row.device_id} />,
    },
    {
      key: "created_at",
      label: t("screen.sessions.colCreated"),
      width: "minmax(104px, 1fr)",
      render: (row) => when(row.created_at),
    },
    {
      key: "access",
      label: "access",
      width: "104px",
      render: (row) => when(row.access_expires),
    },
    {
      key: "refresh",
      label: "refresh",
      width: "104px",
      render: (row) => when(row.refresh_expires),
    },
    {
      key: "status",
      label: t("screen.sessions.colStatus"),
      width: "104px",
      render: (row) => <StateBadge state={isExpired(row.access_expires) ? "stale" : "active"} />,
    },
    {
      key: "actions",
      label: "",
      width: "28px",
      align: "right",
      render: (row) => (
        <RowMenu
          label={t("common.actionsFor", { name: truncId(row.session_id) })}
          items={[
            {
              key: "revoke",
              label: t("common.revoke"),
              destructive: true,
              onSelect: () =>
                askConfirm({
                  title: t("screen.sessions.revokeTitle"),
                  desc: t("screen.sessions.revokeDesc", { id: truncId(row.session_id) }),
                  danger: true,
                  confirmLabel: t("common.revoke"),
                  onConfirm: async () => {
                    await api.admin.sessionRevoke(row.session_id);
                    toast("success", t("common.revoke"));
                    x.reload();
                  },
                }),
            },
          ]}
        />
      ),
    },
  ];

  return (
    <>
      <ZkBanner>{t("zk.sessions")}</ZkBanner>
      <div style={{ display: "flex" }}>
        <div className="id-filter">
          <TextInput
            mono
            value={acc}
            onChange={setAcc}
            placeholder={t("screen.sessions.accountFilterPlaceholder")}
            ariaLabel={t("screen.sessions.accountFilterPlaceholder")}
          />
        </div>
      </div>
      <DataTable<SessionRow>
        columns={columns}
        rows={rows}
        rowKey={(row) => row.session_id}
        loading={x.loading}
        error={x.error}
        onRetry={x.reload}
        summary={x.loading && rows.length === 0 ? true : summary}
        // The columns at their least, side by side: on a phone the table scrolls sideways.
        minWidth={840}
        ariaLabel={t("screen.sessions.title")}
        empty={{ title: t("screen.sessions.empty"), icon: "clock" }}
      />
    </>
  );
}

const MUTED: CSSProperties = {
  display: "block",
  minWidth: 0,
  overflow: "hidden",
  textOverflow: "ellipsis",
  whiteSpace: "nowrap",
  color: "var(--muted-foreground)",
};
