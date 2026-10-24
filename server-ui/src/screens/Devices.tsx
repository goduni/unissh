import { useState, type CSSProperties } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { useUi } from "../store/ui";
import { useAsync } from "../util/useAsync";
import { truncId } from "../util/bytes";
import { fmtDate } from "../util/format";
import { DataTable, type Column } from "../ui/DataTable";
import { PubkeyChip, StateBadge, SummaryCount, SummaryPart, Tag, TextInput } from "../ui/primitives";
import { Icon } from "../ui/icons";
import { RowMenu } from "./RowMenu";
import { Screen } from "./Screen";
import "./identity.css";

interface DeviceRow {
  device_id: string;
  kind: "app" | "web";
  label: string | null;
  /** "expired": past its expiry (a 30-day panel device), drawn as an absent state (dashed, muted). */
  status: "active" | "revoked" | "expired";
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
  const rows: DeviceRow[] = x.data?.devices ?? [];

  // The summary line: how many, and the account the list is narrowed to.
  const summary = (
    <>
      <SummaryCount n={rows.length} />
      {acc ? <SummaryPart label="account_id" value={truncId(acc)} active /> : null}
    </>
  );

  const columns: Column<DeviceRow>[] = [
    {
      key: "device_id",
      label: t("screen.devices.colDevice"),
      // Room for a name and its key side by side; on a phone the table scrolls sideways rather than cut them.
      width: "minmax(280px, 1.8fr)",
      render: (row) => (
        <span style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
          <Icon name="fingerprint" size={16} color="var(--muted-foreground)" />
          {row.label ? <span style={{ ...TRUNC, fontWeight: 500 }}>{row.label}</span> : null}
          {/* When the line is short the key gives way first: the name is what the reader looks for. */}
          <span style={{ display: "flex", minWidth: 0, flexShrink: row.label ? 100 : 1 }}>
            <PubkeyChip value={row.device_id} />
          </span>
        </span>
      ),
    },
    {
      key: "kind",
      label: t("screen.devices.colKind"),
      width: "72px",
      render: (row) => (
        <Tag mono variant="outline">
          {row.kind}
        </Tag>
      ),
    },
    {
      key: "status",
      label: t("screen.devices.colStatus"),
      width: "104px",
      render: (row) => <StateBadge state={row.status} />,
    },
    {
      key: "registered_at",
      label: t("screen.devices.colRegistered"),
      width: "104px",
      render: (row) =>
        row.registered_at ? (
          <span style={{ ...TRUNC, display: "block", color: "var(--muted-foreground)" }}>{fmtDate(row.registered_at)}</span>
        ) : null,
    },
    {
      key: "active_sessions",
      label: t("screen.devices.colSessions"),
      width: "80px",
      numeric: true,
      render: (row) => row.active_sessions,
    },
    {
      key: "actions",
      label: "",
      width: "28px",
      align: "right",
      render: (row) => {
        const name = row.label ? `${row.label} (${truncId(row.device_id)})` : truncId(row.device_id);
        return (
          <RowMenu
            label={t("common.actionsFor", { name: row.label || truncId(row.device_id) })}
            items={[
              {
                key: "revoke",
                label: t("common.revoke"),
                destructive: true,
                // A revoked or expired device has nothing left to revoke: the item stays, unavailable.
                disabled: row.status !== "active",
                onSelect: () =>
                  askConfirm({
                    title: t("screen.devices.revokeTitle"),
                    desc: t("screen.devices.revokeDesc", { name }),
                    danger: true,
                    confirmLabel: t("common.revoke"),
                    onConfirm: async () => {
                      await api.identity.deviceRevoke(row.device_id);
                      toast("success", t("common.revoke"));
                      x.reload();
                    },
                  }),
              },
            ]}
          />
        );
      },
    },
  ];

  return (
    <>
      <div style={{ display: "flex" }}>
        <div className="id-filter">
          <TextInput
            mono
            value={acc}
            onChange={setAcc}
            placeholder={t("screen.devices.accountFilterPlaceholder")}
            ariaLabel={t("screen.devices.accountFilterPlaceholder")}
          />
        </div>
      </div>
      <DataTable<DeviceRow>
        columns={columns}
        rows={rows}
        rowKey={(row) => row.device_id}
        loading={x.loading}
        error={x.error}
        onRetry={x.reload}
        summary={x.loading && rows.length === 0 ? true : summary}
        minWidth={760}
        ariaLabel={t("screen.devices.title")}
        empty={{ title: t("screen.devices.empty"), icon: "fingerprint" }}
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
