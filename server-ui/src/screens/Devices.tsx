import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { useUi } from "../store/ui";
import { useAsync } from "../util/useAsync";
import { truncId } from "../util/bytes";
import { fmtDate } from "../util/format";
import { DataTable, type Column } from "../ui/DataTable";
import { Btn, StateBadge, Tag, TextInput } from "../ui/primitives";
import { Icon } from "../ui/icons";
import { Screen } from "./Screen";
import { MONO } from "../theme/tokens";

interface DeviceRow {
  device_id: string;
  kind: "app" | "web";
  label: string | null;
  status: "active" | "revoked";
  registered_at: number;
  active_sessions: number;
}

export function Devices() {
  const { t } = useTranslation();
  return (
    <Screen title={t("screen.devices.title")} sub={t("screen.devices.sub")}>
      <DevicesBody />
    </Screen>
  );
}

function DevicesBody() {
  const { t } = useTranslation();
  const [acc, setAcc] = useState("");
  const askConfirm = useUi((s) => s.askConfirm);
  const toast = useUi((s) => s.toast);

  const x = useAsync(() => api.admin.devices(acc || undefined), [acc]);

  const columns: Column<DeviceRow>[] = [
    {
      key: "device_id",
      label: t("screen.devices.colDevice"),
      width: "1.6fr",
      render: (row) => (
        <span style={{ display: "inline-flex", alignItems: "center", gap: 8, minWidth: 0 }}>
          <Icon name="fingerprint" size={15} color="var(--txt3)" />
          <span style={{ display: "flex", flexDirection: "column", minWidth: 0 }}>
            <span
              style={{
                fontFamily: row.label ? "inherit" : MONO,
                fontSize: row.label ? 13 : 12,
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
            >
              {row.label || truncId(row.device_id)}
            </span>
            {row.label && (
              <span
                style={{
                  fontFamily: MONO,
                  fontSize: 11,
                  color: "var(--txt3)",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
              >
                {truncId(row.device_id)}
              </span>
            )}
          </span>
        </span>
      ),
    },
    {
      key: "kind",
      label: t("screen.devices.colKind"),
      width: "90px",
      render: (row) => (
        <Tag tone={row.kind === "web" ? "accent" : "neutral"}>{row.kind}</Tag>
      ),
    },
    {
      key: "status",
      label: t("screen.devices.colStatus"),
      width: "110px",
      render: (row) => <StateBadge state={row.status} />,
    },
    {
      key: "registered_at",
      label: t("screen.devices.colRegistered"),
      width: "130px",
      render: (row) => (
        <span style={{ fontFamily: MONO, fontSize: 12, color: "var(--txt2)" }}>
          {fmtDate(row.registered_at)}
        </span>
      ),
    },
    {
      key: "active_sessions",
      label: t("screen.devices.colSessions"),
      width: "90px",
      render: (row) => (
        <span style={{ fontFamily: MONO, fontSize: 12 }}>
          {row.active_sessions}
        </span>
      ),
    },
    {
      key: "actions",
      label: "",
      width: "120px",
      align: "right",
      render: (row) => (
        <Btn
          size="sm"
          variant="danger"
          disabled={row.status !== "active"}
          onClick={() =>
            askConfirm({
              title: t("common.revoke"),
              desc: `${truncId(row.device_id)}`,
              danger: true,
              confirmLabel: t("common.revoke"),
              onConfirm: async () => {
                await api.identity.deviceRevoke(row.device_id);
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
      <div style={{ marginBottom: 14, maxWidth: 460 }}>
        <TextInput
          mono
          value={acc}
          onChange={setAcc}
          placeholder={t("screen.devices.accountFilterPlaceholder")}
        />
      </div>
      <DataTable<DeviceRow>
        columns={columns}
        rows={x.data?.devices ?? []}
        rowKey={(row) => row.device_id}
        loading={x.loading}
        error={x.error}
        onRetry={x.reload}
        empty={{ title: t("screen.devices.empty"), icon: "fingerprint" }}
      />
    </>
  );
}
