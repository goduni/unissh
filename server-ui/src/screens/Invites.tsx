import type { CSSProperties } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import type { InviteRow } from "../api/types";
import { useUi } from "../store/ui";
import { useAsync } from "../util/useAsync";
import { fmtDate, fmtRelative } from "../util/format";
import { DataTable, type Column } from "../ui/DataTable";
import { Btn, Missing, PubkeyChip, StateBadge } from "../ui/primitives";
import { Screen } from "./Screen";

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
    {
      key: "id",
      label: t("screen.invites.colInvite"),
      width: "1.6fr",
      render: (v) => <PubkeyChip value={v.invite_id} head={10} tail={4} />,
    },
    // The badge says the state in the reader's words («Использовано», "Redeemed").
    { key: "state", label: t("common.state"), width: "120px", render: (v) => <StateBadge state={v.state} /> },
    {
      key: "exp",
      label: t("screen.invites.colExpires"),
      width: "1fr",
      render: (v) => (
        <div style={{ minWidth: 0 }}>
          <div style={LINE}>{v.expires_at ? fmtRelative(v.expires_at) : <Missing />}</div>
          {v.created_at ? (
            <div style={{ ...LINE, fontSize: 12, lineHeight: "16px", color: "var(--muted-foreground)" }}>
              {fmtDate(v.created_at)}
            </div>
          ) : null}
        </div>
      ),
    },
    {
      key: "redeemed",
      label: t("screen.invites.colRedeemed"),
      width: "120px",
      render: (v) =>
        v.redeemed_at ? <span style={{ ...LINE, color: "var(--muted-foreground)" }}>{fmtRelative(v.redeemed_at)}</span> : null,
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={data.data?.invites ?? []}
      rowKey={(v) => v.invite_id}
      loading={data.loading}
      error={data.error}
      onRetry={data.reload}
      summary
      minWidth={560}
      ariaLabel={t("screen.invites.title")}
      empty={{
        title: t("screen.invites.emptyTitle"),
        hint: t("screen.invites.emptyHint"),
        icon: "tag",
        actionLabel: t("screen.invites.emptyAction"),
        onAction: openInvite,
      }}
    />
  );
}

const LINE: CSSProperties = {
  display: "block",
  minWidth: 0,
  overflow: "hidden",
  textOverflow: "ellipsis",
  whiteSpace: "nowrap",
};
