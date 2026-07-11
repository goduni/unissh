import { useTranslation } from "react-i18next";
import { api } from "../api";
import type { InviteRow } from "../api/types";
import { useSession } from "../store/session";
import { useTenant } from "../store/tenant";
import { useUi } from "../store/ui";
import { useAsync } from "../util/useAsync";
import { truncId } from "../util/bytes";
import { fmtDate, fmtRelative } from "../util/format";
import { DataTable, type Column } from "../ui/DataTable";
import { KeysetGate } from "../ui/overlays";
import { Btn, RoleBadge, StateBadge } from "../ui/primitives";
import { Screen } from "./Screen";
import { MONO } from "../theme/tokens";

export function Invites() {
  const { t } = useTranslation();
  const openInvite = useUi((s) => s.openInvite);
  const openKeyset = useUi((s) => s.openKeyset);
  const keysetUnlocked = useSession((s) => s.keysetUnlocked);
  return (
    <Screen
      title={t("screen.invites.title")}
      sub={t("screen.invites.sub")}
      actions={
        // Keep enabled and gate on click: a disabled button's `title` is neither
        // reliably shown nor announced. Locked → clicking opens the unlock modal.
        <Btn
          variant="primary"
          icon="tag"
          onClick={keysetUnlocked ? openInvite : openKeyset}
        >
          {t("screen.invites.issue")}
        </Btn>
      }
    >
      <KeysetGate>
        <InvitesBody />
      </KeysetGate>
    </Screen>
  );
}

function InvitesBody() {
  const { t } = useTranslation();
  const askConfirm = useUi((s) => s.askConfirm);
  const toast = useUi((s) => s.toast);
  const openInvite = useUi((s) => s.openInvite);
  const reloadTick = useUi((s) => s.reloadTick);
  const activeTenantId = useTenant((s) => s.activeTenantId);

  const data = useAsync(() => api.admin.invites(), [activeTenantId, reloadTick]);

  const revoke = (inv: InviteRow) => (e: React.MouseEvent) => {
    e.stopPropagation();
    askConfirm({
      title: t("screen.invites.revokeTitle"),
      desc: t("screen.invites.revokeDesc"),
      danger: true,
      confirmLabel: t("common.revoke"),
      onConfirm: async () => {
        await api.admin.inviteRevoke(inv.invite_id);
        toast("success", t("screen.invites.revoked"));
        data.reload();
      },
    });
  };

  const columns: Column<InviteRow>[] = [
    { key: "id", label: "invite_id", width: "1.3fr", render: (v) => <span style={mono}>{truncId(v.invite_id, 10, 4)}</span> },
    { key: "role", label: t("common.role"), width: "92px", render: (v) => <RoleBadge role={v.role} /> },
    { key: "state", label: t("common.state"), width: "104px", render: (v) => <StateBadge state={v.state} /> },
    { key: "scope", label: "Scope", width: "90px", render: (v) => <span style={{ ...mono, color: "var(--txt3)" }}>{v.scope ?? "—"}</span> },
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
    { key: "redeemed", label: t("screen.invites.colRedeemed"), width: "100px", render: (v) => <span style={{ fontSize: 12, color: "var(--txt3)" }}>{v.redeemed_at ? fmtRelative(v.redeemed_at) : "—"}</span> },
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
