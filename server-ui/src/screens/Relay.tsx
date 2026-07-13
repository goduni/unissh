import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import type { KeysetGen, RelayChannel } from "../api/types";
import { useAsync } from "../util/useAsync";
import { truncId } from "../util/bytes";
import { fmtRelative } from "../util/format";
import { DataTable, type Column } from "../ui/DataTable";
import { KeysetGate } from "../ui/overlays";
import { Card, StateBadge, TextInput, ZkBanner } from "../ui/primitives";
import { Screen } from "./Screen";
import { MONO } from "../theme/tokens";

export function Relay() {
  const { t } = useTranslation();
  return (
    <Screen title={t("screen.relay.title")} sub={t("screen.relay.sub")} zk>
      <KeysetGate>
        <RelayBody />
      </KeysetGate>
    </Screen>
  );
}

function RelayBody() {
  const { t } = useTranslation();
  const [acc, setAcc] = useState("");

  const relay = useAsync(() => api.admin.relay(), []);
  const keysets = useAsync(() => api.admin.keysets(acc || undefined), [acc]);

  const channelColumns: Column<RelayChannel>[] = [
    {
      key: "channel_id",
      label: "channel_id",
      width: "1fr",
      render: (r) => (
        <span style={{ fontFamily: MONO }}>{truncId(r.channel_id)}</span>
      ),
    },
    {
      key: "state",
      label: "state",
      width: "90px",
      render: (r) => <StateBadge state={r.state} />,
    },
    {
      key: "expires_at",
      label: "expires_at",
      width: "1fr",
      render: (r) => fmtRelative(r.expires_at),
    },
  ];

  const keysetColumns: Column<KeysetGen>[] = [
    {
      key: "generation",
      label: "generation",
      width: "1fr",
      render: (r) => (
        <span style={{ fontFamily: MONO }}>{r.generation}</span>
      ),
    },
    {
      key: "uploaded_at",
      label: "uploaded_at",
      width: "1fr",
      render: (r) => fmtRelative(r.uploaded_at),
    },
  ];

  const headerStyle = {
    padding: "14px 18px",
    borderBottom: "1px solid var(--line)",
    fontWeight: 700,
    fontSize: 13.5,
  } as const;

  return (
    <>
      <ZkBanner>{t("zk.relay")}</ZkBanner>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
        <Card pad={false}>
          <div style={headerStyle}>{t("screen.relay.pakeChannels")}</div>
          <div style={{ padding: 14 }}>
            <DataTable
              columns={channelColumns}
              rows={relay.data?.channels ?? []}
              rowKey={(r) => r.channel_id}
              loading={relay.loading}
              error={relay.error}
              onRetry={relay.reload}
              empty={{ title: t("common.empty") }}
            />
          </div>
        </Card>

        <Card pad={false}>
          <div style={headerStyle}>{t("screen.relay.keysetGenerations")}</div>
          <div style={{ padding: 14 }}>
            <div style={{ marginBottom: 14 }}>
              <TextInput value={acc} onChange={setAcc} placeholder="account_id" mono />
            </div>
            <DataTable
              columns={keysetColumns}
              rows={keysets.data?.keysets ?? []}
              rowKey={(r) => String(r.generation)}
              loading={keysets.loading}
              error={keysets.error}
              onRetry={keysets.reload}
              empty={{ title: t("common.empty") }}
            />
          </div>
        </Card>
      </div>
    </>
  );
}
