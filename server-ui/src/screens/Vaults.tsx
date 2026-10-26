import { useTranslation } from "react-i18next";
import { api } from "../api";
import type { VaultRow } from "../api/types";
import { useAsync } from "../util/useAsync";
import { truncId } from "../util/bytes";
import { DataTable, type Column } from "../ui/DataTable";
import { PubkeyChip, Tag, ToneBadge, ZkBanner } from "../ui/primitives";
import { Screen } from "./Screen";
import { MONO } from "../theme/tokens";

export function Vaults() {
  const { t } = useTranslation();
  return (
    <Screen title={t("screen.vaults.title")} sub={t("screen.vaults.sub")} zk>
      <VaultsBody />
    </Screen>
  );
}

function VaultsBody() {
  const { t } = useTranslation();
  const vaults = useAsync(() => api.admin.vaults(), []);
  // The two open policies, in words; a code the panel has not met is shown as it came.
  const syncLabel = (v: number) =>
    v === 0 ? t("screen.vaults.sync.local") : v === 1 ? t("screen.vaults.sync.cloud") : String(v);
  const cacheLabel = (v: number) =>
    v === 0 ? t("screen.vaults.cache.offline") : v === 1 ? t("screen.vaults.cache.online") : String(v);

  const columns: Column<VaultRow>[] = [
    {
      key: "vault_id",
      label: t("screen.vaults.colVault"),
      width: "1.3fr",
      // A tombstoned vault stays on the sheet: struck, muted, and said in a word.
      render: (r) => (
        <span style={{ display: "inline-flex", alignItems: "center", gap: 8, minWidth: 0, maxWidth: "100%" }}>
          <span
            title={r.vault_id}
            style={{
              fontFamily: MONO,
              fontSize: 12,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
              color: r.tombstone ? "var(--muted-foreground)" : undefined,
              textDecoration: r.tombstone ? "line-through" : undefined,
            }}
          >
            {truncId(r.vault_id)}
          </span>
          {r.tombstone ? <ToneBadge tone="absent">{t("common.tombstone")}</ToneBadge> : null}
        </span>
      ),
    },
    {
      key: "owner_pubkey",
      label: t("screen.vaults.colOwner"),
      width: "1.2fr",
      render: (r) => <PubkeyChip value={r.owner_pubkey} />,
    },
    {
      key: "latest_epoch",
      label: t("screen.vaults.colEpoch"),
      width: "112px",
      numeric: true,
      render: (r) => r.latest_epoch,
    },
    {
      key: "latest_version",
      label: t("screen.vaults.colVersion"),
      width: "80px",
      numeric: true,
      render: (r) => r.latest_version,
    },
    {
      key: "sync",
      label: t("screen.vaults.colSync"),
      // Wide enough for «Синхронизация» in the head.
      width: "120px",
      render: (r) => <Tag>{syncLabel(r.sync_target)}</Tag>,
    },
    {
      key: "cache_policy",
      label: t("screen.vaults.colCache"),
      width: "132px",
      render: (r) => (
        <span style={{ fontSize: 12, color: "var(--muted-foreground)" }}>{cacheLabel(r.cache_policy)}</span>
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
        summary
        ariaLabel={t("screen.vaults.title")}
      />
    </>
  );
}
