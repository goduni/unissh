import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { switchTenant } from "../api/tenant-switch";
import type { OpsTenant } from "../api/types";
import { useTenant } from "../store/tenant";
import { useUi } from "../store/ui";
import { useAsync } from "../util/useAsync";
import { truncId } from "../util/bytes";
import { fmtDate, fmtNum } from "../util/format";
import { DataTable, type Column } from "../ui/DataTable";
import { Btn, Field, TextInput, StateBadge, TierBadge, gradientFor } from "../ui/primitives";
import { Modal } from "../ui/overlays";
import { Screen } from "./Screen";
import { MONO } from "../theme/tokens";

export function Tenants() {
  const { t } = useTranslation();
  const askConfirm = useUi((s) => s.askConfirm);
  const toast = useUi((s) => s.toast);
  const openBootstrap = useUi((s) => s.openBootstrap);
  const reloadTick = useUi((s) => s.reloadTick);
  const setTenants = useTenant((s) => s.setTenants);
  const activeId = useTenant((s) => s.activeTenantId);

  const [renaming, setRenaming] = useState<string | null>(null);
  const [renameValue, setRenameValue] = useState("");
  const [renameBusy, setRenameBusy] = useState(false);
  // Scales to many small personal spaces: filter the (unbounded) list client-side.
  const [q, setQ] = useState("");

  const list = useAsync(() => api.ops.tenants(), [reloadTick]);
  const rows = (() => {
    const all = list.data?.tenants ?? [];
    const s = q.trim().toLowerCase();
    if (!s) return all;
    return all.filter(
      (tn) =>
        (tn.display_name ?? "").toLowerCase().includes(s) ||
        tn.tenant_id.toLowerCase().includes(s) ||
        tn.tier.toLowerCase().includes(s),
    );
  })();

  useEffect(() => {
    if (list.data) setTenants(list.data.tenants);
  }, [list.data, setTenants]);

  const toggleStatus = (tn: OpsTenant) => (e: React.MouseEvent) => {
    e.stopPropagation();
    const suspend = tn.status !== "suspended";
    askConfirm({
      title: suspend ? t("screen.tenants.suspendTitle") : t("screen.tenants.activateTitle"),
      desc: suspend
        ? t(tn.tier === "personal" ? "screen.tenants.suspendDescPersonal" : "screen.tenants.suspendDesc")
        : t("screen.tenants.activateDesc"),
      danger: suspend,
      confirmLabel: suspend ? t("screen.tenants.suspend") : t("screen.tenants.activate"),
      requireText: suspend ? tn.tenant_id : undefined,
      onConfirm: async () => {
        await api.ops.tenantStatus(tn.tenant_id, suspend);
        toast("success", suspend ? t("screen.tenants.toastSuspended") : t("screen.tenants.toastActivated"));
        list.reload();
      },
    });
  };

  const openRename = (tn: OpsTenant) => (e: React.MouseEvent) => {
    e.stopPropagation();
    setRenaming(tn.tenant_id);
    setRenameValue(tn.display_name ?? "");
  };

  const saveRename = async () => {
    if (!renaming) return;
    setRenameBusy(true);
    try {
      await api.ops.tenantProfile(renaming, renameValue.trim());
      toast("success", t("screen.tenants.toastRenamed"));
      setRenaming(null);
      list.reload();
    } finally {
      setRenameBusy(false);
    }
  };

  const columns: Column<OpsTenant>[] = [
    {
      key: "tenant",
      label: t("screen.tenants.colTenant"),
      width: "2fr",
      render: (tn) => (
        <span style={{ display: "flex", alignItems: "center", gap: 10, minWidth: 0 }}>
          <span style={tile(tn.tenant_id)}>
            {((tn.display_name || truncId(tn.tenant_id, 1, 0))[0] || "·").toUpperCase()}
          </span>
          <span style={{ display: "flex", flexDirection: "column", minWidth: 0 }}>
            <span
              style={{
                fontSize: 13,
                fontWeight: 600,
                color: "var(--txt)",
                whiteSpace: "nowrap",
                overflow: "hidden",
                textOverflow: "ellipsis",
              }}
            >
              {tn.display_name || truncId(tn.tenant_id, 10, 6)}
            </span>
            <span
              style={{
                fontFamily: MONO,
                fontSize: 11,
                color: "var(--txt3)",
                whiteSpace: "nowrap",
                overflow: "hidden",
                textOverflow: "ellipsis",
              }}
            >
              {truncId(tn.tenant_id, 10, 6)}
            </span>
          </span>
        </span>
      ),
    },
    { key: "tier", label: t("screen.tenants.colTier"), width: "80px", render: (tn) => <TierBadge tier={tn.tier} /> },
    {
      key: "owner",
      label: t("screen.tenants.colOwner"),
      width: "110px",
      render: (tn) => (
        <span style={{ ...mono, color: "var(--txt3)" }}>
          {tn.genesis_owner ? truncId(tn.genesis_owner, 6, 4) : "—"}
        </span>
      ),
    },
    { key: "status", label: t("common.status"), width: "110px", render: (tn) => <StateBadge state={tn.status} /> },
    {
      key: "next_seq",
      label: "next_seq",
      width: "110px",
      render: (tn) => <span style={mono}>{fmtNum(tn.next_seq)}</span>,
    },
    {
      key: "accounts",
      label: t("screen.tenants.colAccounts"),
      width: "70px",
      render: (tn) => <span style={mono}>{tn.accounts}</span>,
    },
    {
      key: "created",
      label: t("screen.tenants.colCreated"),
      width: "100px",
      render: (tn) => <span style={{ ...mono, color: "var(--txt3)" }}>{fmtDate(tn.created_at)}</span>,
    },
    {
      key: "actions",
      label: "",
      width: "270px",
      align: "right",
      render: (tn) => (
        <span style={{ display: "flex", gap: 7, justifyContent: "flex-end" }}>
          {tn.tenant_id === activeId ? (
            <span style={{ fontSize: 11.5, color: "var(--accent)", fontWeight: 600, alignSelf: "center" }}>
              {t("common.active")}
            </span>
          ) : (
            <Btn
              size="sm"
              onClick={(e) => {
                e.stopPropagation();
                switchTenant(tn.tenant_id);
              }}
            >
              {t("screen.tenants.select")}
            </Btn>
          )}
          <Btn size="sm" icon="sliders" title={t("screen.tenants.rename")} onClick={openRename(tn)} />
          <Btn
            size="sm"
            variant={tn.status === "suspended" ? "soft" : "danger"}
            onClick={toggleStatus(tn)}
          >
            {t(tn.status === "suspended" ? "screen.tenants.activate" : "screen.tenants.suspend")}
          </Btn>
        </span>
      ),
    },
  ];

  return (
    <Screen
      title={t("screen.tenants.title")}
      sub={t("screen.tenants.sub")}
      actions={
        <Btn variant="primary" icon="plus" onClick={openBootstrap}>
          {t("screen.tenants.createSpace")}
        </Btn>
      }
    >
      {(list.data?.tenants.length ?? 0) > 8 ? (
        <div style={{ marginBottom: 12, maxWidth: 320 }}>
          <TextInput value={q} onChange={setQ} placeholder={t("screen.tenants.searchPlaceholder")} />
        </div>
      ) : null}
      <DataTable
        columns={columns}
        rows={rows}
        rowKey={(tn) => tn.tenant_id}
        loading={list.loading}
        error={list.error}
        onRetry={list.reload}
        empty={{ title: t("screen.tenants.emptyTitle"), icon: "database", actionLabel: t("screen.tenants.emptyAction"), onAction: openBootstrap }}
      />

      {renaming ? (
        <Modal onClose={() => setRenaming(null)} width={420}>
          <div style={{ padding: 22 }}>
            <div style={{ fontSize: 16, fontWeight: 800, marginBottom: 4 }}>{t("screen.tenants.renameModalTitle")}</div>
            <div
              style={{
                fontFamily: MONO,
                fontSize: 11.5,
                color: "var(--txt3)",
                marginBottom: 16,
              }}
            >
              {truncId(renaming, 14, 8)}
            </div>
            <Field label={t("screen.tenants.displayNameLabel")} hint={t("screen.tenants.displayNameHint")}>
              <TextInput
                value={renameValue}
                onChange={setRenameValue}
                placeholder="Acme Corp"
              />
            </Field>
            <div style={{ display: "flex", gap: 9 }}>
              <Btn full onClick={() => setRenaming(null)}>
                {t("common.cancel")}
              </Btn>
              <Btn full variant="primary" loading={renameBusy} onClick={saveRename}>
                {t("common.save")}
              </Btn>
            </div>
          </div>
        </Modal>
      ) : null}
    </Screen>
  );
}

const mono: React.CSSProperties = { fontFamily: MONO, fontSize: 12.5, color: "var(--txt2)" };

function tile(seed: string): React.CSSProperties {
  let h = 0;
  for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) | 0;
  return {
    width: 26,
    height: 26,
    borderRadius: 7,
    background: gradientFor(Math.abs(h)),
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    color: "#fff",
    fontWeight: 700,
    fontSize: 12,
    flexShrink: 0,
  };
}
