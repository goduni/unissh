import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { useUi } from "../store/ui";
import { useAsync } from "../util/useAsync";
import { truncId } from "../util/bytes";
import { fmtRelative, isExpired } from "../util/format";
import { DataTable, type Column } from "../ui/DataTable";
import { Btn, PubkeyChip, StateBadge, TextInput, ZkBanner } from "../ui/primitives";
import { Screen } from "./Screen";
import { MONO } from "../theme/tokens";

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

  const columns: Column<SessionRow>[] = [
    {
      key: "account_id",
      label: t("screen.sessions.colAccount"),
      width: "1fr",
      render: (row) => <PubkeyChip value={row.account_id} />,
    },
    {
      key: "device_id",
      label: t("screen.sessions.colDevice"),
      width: "1fr",
      render: (row) => (
        <span
          style={{
            fontFamily: MONO,
            fontSize: 12,
            color: "var(--txt2)",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            display: "block",
          }}
        >
          {truncId(row.device_id)}
        </span>
      ),
    },
    {
      key: "created_at",
      label: t("screen.sessions.colCreated"),
      width: "1fr",
      render: (row) => (
        <span style={{ fontSize: 12, color: "var(--txt2)" }}>{fmtRelative(row.created_at)}</span>
      ),
    },
    {
      key: "access",
      label: "access",
      width: "110px",
      render: (row) => (
        <span style={{ fontFamily: MONO, fontSize: 12, color: "var(--txt2)" }}>
          {fmtRelative(row.access_expires)}
        </span>
      ),
    },
    {
      key: "refresh",
      label: "refresh",
      width: "100px",
      render: (row) => (
        <span style={{ fontFamily: MONO, fontSize: 12, color: "var(--txt2)" }}>
          {fmtRelative(row.refresh_expires)}
        </span>
      ),
    },
    {
      key: "status",
      label: t("screen.sessions.colStatus"),
      width: "96px",
      render: (row) => <StateBadge state={isExpired(row.access_expires) ? "stale" : "active"} />,
    },
    {
      key: "actions",
      label: "",
      width: "100px",
      align: "right",
      render: (row) => (
        <Btn
          size="sm"
          variant="danger"
          onClick={() =>
            askConfirm({
              title: t("common.revoke"),
              desc: `${truncId(row.session_id)}`,
              danger: true,
              confirmLabel: t("common.revoke"),
              onConfirm: async () => {
                await api.admin.sessionRevoke(row.session_id);
                toast("success", t("common.revoke"));
                x.reload();
              },
            })
          }
        >
          {t("common.revoke")}
        </Btn>
      ),
    },
  ];

  return (
    <>
      <ZkBanner>
        <b style={{ color: "var(--txt)" }}>{t("zk.sessions")}</b>
      </ZkBanner>
      <div style={{ marginBottom: 14, maxWidth: 460 }}>
        <TextInput
          mono
          value={acc}
          onChange={setAcc}
          placeholder={t("screen.sessions.accountFilterPlaceholder")}
        />
      </div>
      <DataTable<SessionRow>
        columns={columns}
        rows={x.data?.sessions ?? []}
        rowKey={(row) => row.session_id}
        loading={x.loading}
        error={x.error}
        onRetry={x.reload}
        empty={{ title: t("screen.sessions.empty"), icon: "clock" }}
      />
    </>
  );
}
