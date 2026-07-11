import { useTranslation } from "react-i18next";
import { api } from "../api";
import { SYNC_TARGET_LABEL, CACHE_POLICY_LABEL, type VaultRow } from "../api/types";
import { useTenant } from "../store/tenant";
import { useAsync } from "../util/useAsync";
import { truncId } from "../util/bytes";
import { DataTable, type Column } from "../ui/DataTable";
import { KeysetGate } from "../ui/overlays";
import { PubkeyChip, Tag, ZkBanner } from "../ui/primitives";
import { Screen } from "./Screen";
import { MONO } from "../theme/tokens";

export function Vaults() {
  const { t } = useTranslation();
  return (
    <Screen title={t("screen.vaults.title")} sub={t("screen.vaults.sub")} zk>
      <KeysetGate>
        <VaultsBody />
      </KeysetGate>
    </Screen>
  );
}

function VaultsBody() {
  const { t } = useTranslation();
  const activeTenantId = useTenant((s) => s.activeTenantId);
  const vaults = useAsync(() => api.admin.vaults(), [activeTenantId]);

  const columns: Column<VaultRow>[] = [
    {
      key: "vault_id",
      label: "vault_id",
      width: "1.3fr",
      render: (r) => (
        <span style={{ display: "inline-flex", alignItems: "center", gap: 7 }}>
          <span style={{ fontFamily: MONO }}>{truncId(r.vault_id)}</span>
          {r.tombstone ? <Tag tone="red">TOMB</Tag> : null}
        </span>
      ),
    },
    {
      key: "owner_pubkey",
      label: "owner_pubkey",
      width: "1.2fr",
      render: (r) => <PubkeyChip value={r.owner_pubkey} />,
    },
    {
      key: "latest_epoch",
      label: "epoch",
      width: "70px",
      render: (r) => (
        <span style={{ fontFamily: MONO }}>{r.latest_epoch}</span>
      ),
    },
    {
      key: "latest_version",
      label: "version",
      width: "78px",
      render: (r) => (
        <span style={{ fontFamily: MONO }}>{r.latest_version}</span>
      ),
    },
    {
      key: "sync",
      label: "sync",
      width: "92px",
      render: (r) => <Tag tone="accent">{SYNC_TARGET_LABEL[r.sync_target]}</Tag>,
    },
    {
      key: "cache_policy",
      label: "cache_policy",
      width: "132px",
      render: (r) => (
        <span style={{ fontFamily: MONO, color: "var(--txt3)" }}>
          {CACHE_POLICY_LABEL[r.cache_policy]}
        </span>
      ),
    },
  ];

  return (
    <>
      <ZkBanner>{t("zk.vaults")}</ZkBanner>
      <DataTable
        columns={columns}
        rows={vaults.data?.vaults ?? []}
        rowKey={(r) => r.vault_id}
        loading={vaults.loading}
        error={vaults.error}
        onRetry={vaults.reload}
        empty={{ title: t("screen.vaults.empty"), icon: "lock" }}
      />
    </>
  );
}
