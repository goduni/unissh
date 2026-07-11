import { useTranslation } from "react-i18next";
import { api } from "../api";
import type { EnrollGrant } from "../api/types";
import { useUi } from "../store/ui";
import { useAsync } from "../util/useAsync";
import { truncId } from "../util/bytes";
import { fmtDate, fmtRelative } from "../util/format";
import { DataTable, type Column } from "../ui/DataTable";
import { Btn, StateBadge, TierBadge } from "../ui/primitives";
import { Screen } from "./Screen";
import { MONO } from "../theme/tokens";

export function Enroll() {
  const { t } = useTranslation();
  const openEnroll = useUi((s) => s.openEnroll);
  return (
    <Screen
      title={t("screen.enroll.title")}
      sub={t("screen.enroll.sub")}
      actions={
        <Btn variant="primary" icon="key" onClick={openEnroll}>
          {t("screen.enroll.issue")}
        </Btn>
      }
    >
      <EnrollBody />
    </Screen>
  );
}

function EnrollBody() {
  const { t } = useTranslation();
  const askConfirm = useUi((s) => s.askConfirm);
  const toast = useUi((s) => s.toast);
  const openEnroll = useUi((s) => s.openEnroll);
  const reloadTick = useUi((s) => s.reloadTick);

  // Instance-level (ops-scoped) — not tied to the active tenant.
  const data = useAsync(() => api.ops.enrollGrants(), [reloadTick]);

  const revoke = (g: EnrollGrant) => (e: React.MouseEvent) => {
    e.stopPropagation();
    askConfirm({
      title: t("screen.enroll.revokeTitle"),
      desc: t("screen.enroll.revokeDesc"),
      danger: true,
      confirmLabel: t("common.revoke"),
      onConfirm: async () => {
        await api.ops.enrollRevoke(g.grant_id);
        toast("success", t("screen.enroll.revoked"));
        data.reload();
      },
    });
  };

  const columns: Column<EnrollGrant>[] = [
    {
      key: "label",
      label: t("screen.enroll.colLabel"),
      width: "1.4fr",
      render: (v) => <span style={{ fontSize: 13, color: "var(--txt)" }}>{v.label}</span>,
    },
    {
      key: "tier",
      label: t("screen.enroll.colTier"),
      width: "96px",
      render: (v) =>
        v.tier ? <TierBadge tier={v.tier} /> : <span style={{ color: "var(--txt3)" }}>—</span>,
    },
    { key: "state", label: t("common.state"), width: "104px", render: (v) => <StateBadge state={v.state} /> },
    {
      key: "exp",
      label: t("screen.enroll.colExpires"),
      width: "1fr",
      render: (v) => (
        <div style={{ minWidth: 0 }}>
          <div style={{ fontSize: 12.5, color: "var(--txt2)" }}>
            {v.expires_at ? fmtRelative(v.expires_at) : t("screen.enroll.noExpiry")}
          </div>
          <div style={{ fontSize: 11, color: "var(--txt3)" }}>{fmtDate(v.created_at)}</div>
        </div>
      ),
    },
    {
      key: "tenant",
      label: t("screen.enroll.colTenant"),
      width: "1.1fr",
      render: (v) =>
        v.redeemed_tenant ? (
          <span style={mono}>{truncId(v.redeemed_tenant, 10, 4)}</span>
        ) : (
          <span style={{ color: "var(--txt3)" }}>—</span>
        ),
    },
    {
      key: "act",
      label: "",
      width: "100px",
      align: "right",
      render: (v) =>
        v.state === "pending" ? (
          <Btn size="sm" variant="danger" icon="trash" onClick={revoke(v)}>
            {t("common.revoke")}
          </Btn>
        ) : null,
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={data.data?.grants ?? []}
      rowKey={(v) => v.grant_id}
      loading={data.loading}
      error={data.error}
      onRetry={data.reload}
      empty={{
        title: t("screen.enroll.emptyTitle"),
        hint: t("screen.enroll.emptyHint"),
        icon: "key",
        actionLabel: t("screen.enroll.emptyAction"),
        onAction: openEnroll,
      }}
    />
  );
}

const mono: React.CSSProperties = { fontFamily: MONO, fontSize: 12.5, color: "var(--txt2)" };
