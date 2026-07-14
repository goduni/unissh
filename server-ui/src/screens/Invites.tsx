import { useTranslation } from "react-i18next";
import { api } from "../api";
import type { InviteRow } from "../api/types";
import { useUi } from "../store/ui";
import { useAsync } from "../util/useAsync";
import { truncId } from "../util/bytes";
import { fmtDate, fmtRelative } from "../util/format";
import { DataTable, type Column } from "../ui/DataTable";
import { Btn, StateBadge } from "../ui/primitives";
import { Screen } from "./Screen";
import { MONO } from "../theme/tokens";

export function Invites() {
  const { t } = useTranslation();
  const openInvite = useUi((s) => s.openInvite);
  return (
    <Screen
      title={t("screen.invites.title")}
      sub={t("screen.invites.sub")}
      actions={
        <Btn variant="primary" icon="tag" onClick={openInvite}>
          {t("screen.invites.issue")}
        </Btn>
      }
    >
      <InvitesBody />
    </Screen>
  );
}

function InvitesBody() {
  const { t } = useTranslation();
  const openInvite = useUi((s) => s.openInvite);
  const reloadTick = useUi((s) => s.reloadTick);

  const data = useAsync(() => api.admin.invites(), [reloadTick]);

  // NOTE: v2 invite create/revoke land server-side in Task 8. The admin listing is
  // read-only lifecycle metadata; there is no revoke route yet, so no revoke action.
  const columns: Column<InviteRow>[] = [
    { key: "id", label: "invite_id", width: "1.6fr", render: (v) => <span style={mono}>{truncId(v.invite_id, 10, 4)}</span> },
    { key: "state", label: t("common.state"), width: "120px", render: (v) => <StateBadge state={v.state} /> },
    {
      key: "exp",
      label: t("screen.invites.colExpires"),
      width: "1fr",
      render: (v) => (
        <div style={{ minWidth: 0 }}>
          <div style={{ fontSize: 12.5, color: "var(--txt2)" }}>{fmtRelative(v.expires_at)}</div>
          <div style={{ fontSize: 11, color: "var(--txt3)" }}>{fmtDate(v.created_at)}</div>
        </div>
      ),
    },
    { key: "redeemed", label: t("screen.invites.colRedeemed"), width: "120px", render: (v) => <span style={{ fontSize: 12, color: "var(--txt3)" }}>{v.redeemed_at ? fmtRelative(v.redeemed_at) : "—"}</span> },
  ];

  return (
    <DataTable
      columns={columns}
      rows={data.data?.invites ?? []}
      rowKey={(v) => v.invite_id}
      loading={data.loading}
      error={data.error}
      onRetry={data.reload}
      empty={{ title: t("screen.invites.emptyTitle"), hint: t("screen.invites.emptyHint"), icon: "tag", actionLabel: t("screen.invites.emptyAction"), onAction: openInvite }}
    />
  );
}

const mono: React.CSSProperties = { fontFamily: MONO, fontSize: 12.5, color: "var(--txt2)" };
