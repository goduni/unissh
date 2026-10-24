import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import type { KeysetGen, RelayChannel } from "../api/types";
import { useAsync } from "../util/useAsync";
import { truncId } from "../util/bytes";
import { fmtEpoch, fmtRelative } from "../util/format";
import { DataTable, type Column } from "../ui/DataTable";
import { Card, CardHeader, StateBadge, TextInput, ZkBanner, type Tone } from "../ui/primitives";
import { Screen } from "./Screen";
import { MONO } from "../theme/tokens";

/**
 * A PAKE channel's state as a status badge: amber while the handshake runs
 * (open, then msg1..msg3), green once done, muted and dashed once expired.
 * A state the panel does not know stays a plain neutral word.
 */
const CHANNEL_TONE: Record<string, Tone> = {
  open: "warning",
  msg1: "warning",
  msg2: "warning",
  msg3: "warning",
  done: "success",
  expired: "absent",
};

export function Relay() {
  const { t } = useTranslation();
  return (
    <Screen title={t("screen.relay.title")} sub={t("screen.relay.sub")} zk>
      <RelayBody />
    </Screen>
  );
}

function RelayBody() {
  const { t } = useTranslation();
  const [acc, setAcc] = useState("");

  const relay = useAsync(() => api.admin.relay(), []);
  const keysets = useAsync(() => api.admin.keysets(acc || undefined), [acc]);

  const muted = { color: "var(--muted-foreground)" } as const;

  const channelColumns: Column<RelayChannel>[] = [
    {
      key: "channel_id",
      label: t("screen.relay.colChannel"),
      width: "minmax(0, 1fr)",
      render: (r) => (
        <span title={r.channel_id} style={{ fontFamily: MONO, fontSize: 12 }}>
          {truncId(r.channel_id)}
        </span>
      ),
    },
    {
      key: "state",
      label: t("common.state"),
      // The badge says the state in the reader's words («Шаг 2/3», "Step 2/3").
      width: "112px",
      render: (r) => <StateBadge state={r.state} tone={CHANNEL_TONE[r.state] ?? "neutral"} />,
    },
    {
      key: "expires_at",
      label: t("screen.relay.colExpires"),
      width: "minmax(0, 1fr)",
      render: (r) => (
        <span title={fmtEpoch(r.expires_at)} style={muted}>
          {fmtRelative(r.expires_at)}
        </span>
      ),
    },
  ];

  const keysetColumns: Column<KeysetGen>[] = [
    {
      key: "generation",
      label: t("screen.relay.colGeneration"),
      width: "96px",
      numeric: true,
      render: (r) => r.generation,
    },
    {
      key: "uploaded_at",
      label: t("screen.relay.colUploaded"),
      width: "minmax(0, 1fr)",
      render: (r) => (
        <span title={fmtEpoch(r.uploaded_at)} style={muted}>
          {fmtRelative(r.uploaded_at)}
        </span>
      ),
    },
  ];

  return (
    <>
      <ZkBanner>{t("zk.relay")}</ZkBanner>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 380px), 1fr))",
          alignItems: "start",
          gap: 16,
        }}
      >
        <Card pad={false}>
          <CardHeader title={t("screen.relay.pakeChannels")} />
          <DataTable
            bare
            columns={channelColumns}
            rows={relay.data?.channels ?? []}
            rowKey={(r) => r.channel_id}
            loading={relay.loading}
            error={relay.error}
            onRetry={relay.reload}
            empty={{ title: t("common.empty") }}
            summary
            minWidth={360}
            ariaLabel={t("screen.relay.pakeChannels")}
          />
        </Card>

        <Card pad={false}>
          <CardHeader
            title={t("screen.relay.keysetGenerations")}
            actions={
              <TextInput
                value={acc}
                onChange={setAcc}
                placeholder="account_id"
                ariaLabel={t("screen.relay.accountFilter")}
                mono
                style={{ width: 220, height: 28 }}
              />
            }
          />
          <DataTable
            bare
            columns={keysetColumns}
            rows={keysets.data?.keysets ?? []}
            rowKey={(r) => String(r.generation)}
            loading={keysets.loading}
            error={keysets.error}
            onRetry={keysets.reload}
            empty={{ title: t("common.empty") }}
            summary
            minWidth={280}
            ariaLabel={t("screen.relay.keysetGenerations")}
          />
        </Card>
      </div>
    </>
  );
}
