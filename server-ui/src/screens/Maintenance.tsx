import { useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { useUi } from "../store/ui";
import { useAsync } from "../util/useAsync";
import { fmtNum } from "../util/format";
import {
  Btn,
  Card,
  CardHeader,
  EmptyState,
  ErrorCard,
  Field,
  Missing,
  Segmented,
  Skeleton,
  StateBadge,
  SummaryLine,
  TextInput,
  Well,
  ZkBanner,
} from "../ui/primitives";
import { Screen } from "./Screen";
import { MONO } from "../theme/tokens";

export function Maintenance() {
  const { t } = useTranslation();
  return (
    <Screen title={t("screen.maint.title")} sub={t("screen.maint.sub")}>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 360px), 1fr))",
          gap: 16,
          alignItems: "start",
        }}
      >
        <MigrationsCard />
        <SeqBumpCard />
      </div>
      <ZkBanner>{t("zk.maint")}</ZkBanner>
    </Screen>
  );
}

function MigrationsCard() {
  const { t } = useTranslation();
  const migrations = useAsync(() => api.admin.migrations(), []);
  const list = migrations.data?.migrations ?? [];

  return (
    <Card pad={false}>
      <CardHeader title={t("screen.maint.migrations")} />
      {migrations.error && !migrations.data ? (
        <ErrorCard band message={migrations.error} onRetry={migrations.reload} retrying={migrations.loading} />
      ) : (
        <>
          <SummaryLine count={list.length} loading={migrations.loading} />
          {migrations.loading ? (
            <div aria-hidden="true">
              {Array.from({ length: 4 }, (_, i) => (
                <div
                  key={i}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 12,
                    minHeight: 32,
                    padding: "4px 16px",
                    borderTop: i > 0 ? "1px solid var(--rule)" : undefined,
                  }}
                >
                  <Skeleton width={40} height={12} />
                  <Skeleton width="50%" height={12} />
                </div>
              ))}
            </div>
          ) : list.length === 0 ? (
            <EmptyState compact flat icon="database" title={t("common.empty")} />
          ) : (
            <ol style={{ listStyle: "none", margin: 0, padding: 0 }}>
              {list.map((m, i) => (
                <li
                  key={m.version}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 12,
                    minHeight: 32,
                    padding: "4px 16px",
                    borderTop: i > 0 ? "1px solid var(--rule)" : undefined,
                  }}
                >
                  <span style={{ fontFamily: MONO, fontSize: 12, lineHeight: "16px", color: "var(--muted-foreground)" }}>
                    {`000${m.version}`}
                  </span>
                  <span style={{ flex: 1, minWidth: 0, overflowWrap: "anywhere" }}>{m.description}</span>
                  <StateBadge state="done" label={t("screen.maint.migrationApplied")} />
                </li>
              ))}
            </ol>
          )}
        </>
      )}
    </Card>
  );
}

function SeqBumpCard() {
  const { t } = useTranslation();
  const valueId = useId();
  // Owner-gated, instance-wide anti-rollback floor. The current next_seq comes from
  // the owner overview; reload it after a bump so the shown value isn't stale.
  const overview = useAsync(() => api.admin.overview(), []);
  const next = overview.data?.next_seq;
  const [mode, setMode] = useState<"by" | "to">("by");
  const [amount, setAmount] = useState("");
  const askConfirm = useUi((s) => s.askConfirm);
  const toast = useUi((s) => s.toast);

  const doBump = () => {
    // Validate before the confirm: empty → 0 and "abc" → NaN must not reach the
    // server on this irreversible action.
    const n = Number(amount);
    if (!amount.trim() || !Number.isInteger(n) || n <= 0) {
      toast("error", t("screen.maint.seqBumpInvalid"));
      return;
    }
    askConfirm({
      title: t("screen.maint.seqBumpConfirmTitle"),
      desc: t("screen.maint.seqBumpConfirmDesc"),
      danger: true,
      confirmLabel: t("screen.maint.seqBumpConfirmLabel"),
      requireText: "BUMP",
      onConfirm: async () => {
        const r = await api.admin.seqBump(mode === "by" ? { by: n } : { to: n });
        toast("success", t("screen.maint.seqBumpDone", { seq: r.new }));
        overview.reload();
      },
    });
  };

  return (
    <Card pad={false}>
      <CardHeader title={t("screen.maint.seqBumpTitle")} />
      <div style={{ padding: 16 }}>
        {/* The consequence, before the click. */}
        <p
          style={{
            margin: "0 0 12px",
            maxWidth: "72ch",
            fontSize: 14,
            lineHeight: "20px",
            color: "var(--muted-foreground)",
          }}
        >
          {t("screen.maint.seqBumpHint")}
        </p>
        <Well
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: 12,
            marginBottom: 16,
          }}
        >
          <span style={{ fontSize: 12, lineHeight: "16px", color: "var(--muted-foreground)" }}>
            {t("screen.maint.currentNextSeq")}
          </span>
          {next !== undefined ? (
            <span style={{ fontFamily: MONO, fontSize: 13, fontWeight: 600, lineHeight: "20px" }}>{fmtNum(next)}</span>
          ) : overview.loading ? (
            <Skeleton width={64} height={14} />
          ) : (
            <Missing />
          )}
        </Well>
        <Field label={t("screen.maint.modeLabel")}>
          <Segmented
            ariaLabel={t("screen.maint.modeLabel")}
            options={[
              { value: "by", label: t("screen.maint.modeByLabel") },
              { value: "to", label: t("screen.maint.modeToLabel") },
            ]}
            value={mode}
            onChange={setMode}
          />
        </Field>
        <Field label={t("screen.maint.valueLabel")} htmlFor={valueId}>
          <TextInput id={valueId} value={amount} onChange={setAmount} placeholder="0" mono inputMode="numeric" />
        </Field>
        <Btn variant="danger" onClick={doBump}>
          {t("screen.maint.runSeqBump")}
        </Btn>
      </div>
    </Card>
  );
}
