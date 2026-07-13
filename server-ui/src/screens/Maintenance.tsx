import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { useSession } from "../store/session";
import { useUi } from "../store/ui";
import { useAsync } from "../util/useAsync";
import { fmtNum } from "../util/format";
import { Icon } from "../ui/icons";
import { Btn, Card, Field, Segmented, Spinner, TextInput, ZkBanner } from "../ui/primitives";
import { Screen } from "./Screen";
import { MONO } from "../theme/tokens";

export function Maintenance() {
  const { t } = useTranslation();
  return (
    <Screen title={t("screen.maint.title")} sub={t("screen.maint.sub")}>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: 14,
          marginBottom: 14,
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
  const unlocked = useSession((s) => s.keysetUnlocked);
  const migrations = useAsync(
    () => (unlocked ? api.admin.migrations() : Promise.resolve(null)),
    [unlocked],
  );

  return (
    <Card pad={false}>
      <div
        style={{
          padding: "14px 18px",
          borderBottom: "1px solid var(--line)",
          fontWeight: 700,
          fontSize: 13.5,
        }}
      >
        {t("screen.maint.migrations")}
      </div>
      <div style={{ padding: 14 }}>
        {!unlocked ? (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              fontSize: 12.5,
              color: "var(--txt3)",
            }}
          >
            <Icon name="lock" size={14} color="var(--txt3)" />
            {t("screen.maint.keysetRequired")}
          </div>
        ) : migrations.loading ? (
          <div style={{ display: "flex", justifyContent: "center", padding: 24 }}>
            <Spinner />
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column" }}>
            {(migrations.data?.migrations ?? []).map((m) => (
              <div
                key={m.version}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 12,
                  padding: "11px 4px",
                  borderBottom: "1px solid var(--line)",
                }}
              >
                <span style={{ fontFamily: MONO, fontSize: 12.5, color: "var(--txt2)" }}>
                  {`000${m.version}`}
                </span>
                <span style={{ flex: 1, minWidth: 0, fontSize: 12.5, color: "var(--txt)" }}>
                  {m.description}
                </span>
                <span style={{ fontSize: 11.5, fontWeight: 700, color: "var(--green)" }}>{t("screen.maint.migrationApplied")}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </Card>
  );
}

function SeqBumpCard() {
  const { t } = useTranslation();
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
      title: "seq-bump",
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
      <div
        style={{
          padding: "14px 18px",
          borderBottom: "1px solid var(--line)",
          fontWeight: 700,
          fontSize: 13.5,
        }}
      >
        Anti-rollback · seq-bump
      </div>
      <div style={{ padding: "16px 18px" }}>
        <div style={{ fontSize: 12.5, color: "var(--txt3)", lineHeight: 1.55, marginBottom: 14 }}>
          {t("screen.maint.seqBumpHint")}
        </div>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            padding: "10px 13px",
            background: "var(--bg2)",
            border: "1px solid var(--line)",
            borderRadius: 10,
            marginBottom: 14,
          }}
        >
          <span style={{ fontSize: 12, color: "var(--txt3)", fontWeight: 600 }}>{t("screen.maint.currentNextSeq")}</span>
          <span style={{ fontFamily: MONO, fontSize: 14, fontWeight: 700 }}>
            {next === undefined ? "—" : fmtNum(next)}
          </span>
        </div>
        <Field label={t("screen.maint.modeLabel")}>
          <Segmented
            options={[
              { value: "by", label: t("screen.maint.modeByLabel") },
              { value: "to", label: t("screen.maint.modeToLabel") },
            ]}
            value={mode}
            onChange={setMode}
          />
        </Field>
        <Field label={t("screen.maint.valueLabel")}>
          <TextInput value={amount} onChange={setAmount} placeholder="0" mono />
        </Field>
        <Btn variant="danger" full onClick={doBump}>
          {t("screen.maint.runSeqBump")}
        </Btn>
      </div>
    </Card>
  );
}
