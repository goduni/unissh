import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { useUi } from "../store/ui";
import { fmtDate } from "../util/format";
import { Icon } from "../ui/icons";
import { Btn, Field, TextInput } from "../ui/primitives";
import { Modal } from "../ui/overlays";
import { MONO } from "../theme/tokens";

const TIERS: { value: string; label: string }[] = [
  { value: "", label: "screen.enroll.tierDefault" },
  { value: "personal", label: "screen.enroll.tierPersonal" },
  { value: "org", label: "screen.enroll.tierOrg" },
];
const TTLS: { seconds: number; label: string }[] = [
  { seconds: 0, label: "screen.enroll.ttlNone" },
  { seconds: 86400, label: "screen.enroll.ttl24h" },
  { seconds: 604800, label: "screen.enroll.ttl7d" },
  { seconds: 2592000, label: "screen.enroll.ttl30d" },
];

export function MintGrantModal() {
  const { t } = useTranslation();
  const open = useUi((s) => s.enrollOpen);
  const close = useUi((s) => s.closeEnroll);
  const bumpReload = useUi((s) => s.bumpReload);

  const [label, setLabel] = useState("");
  const [tier, setTier] = useState("");
  const [ttl, setTtl] = useState(0);
  const [token, setToken] = useState<string | null>(null);
  const [expiresAt, setExpiresAt] = useState<number | null>(null);
  const [copied, setCopied] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setLabel("");
      setTier("");
      setTtl(0);
      setToken(null);
      setExpiresAt(null);
      setError(null);
      setCopied(false);
    }
  }, [open]);

  if (!open) return null;

  const mint = async () => {
    if (!label.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const r = await api.ops.enrollCreate(label.trim(), tier || undefined, ttl || undefined);
      setToken(r.token);
      setExpiresAt(r.expires_at);
      bumpReload();
    } catch (e) {
      setError(e instanceof Error ? e.message : t("screen.enroll.mintError"));
    } finally {
      setBusy(false);
    }
  };

  const copyToken = () => {
    if (!token) return;
    void navigator.clipboard?.writeText(token);
    setCopied(true);
    setTimeout(() => setCopied(false), 1200);
  };

  return (
    <Modal onClose={close} width={440}>
      <div style={{ padding: "20px 22px 0" }}>
        <div style={{ fontSize: 16, fontWeight: 800 }}>{t("screen.enroll.issueTitle")}</div>
        <div style={{ fontSize: 12, color: "var(--txt3)", marginTop: 2 }}>
          {t("screen.enroll.issueSubtitle")}
        </div>
      </div>

      <div style={{ padding: "18px 22px" }}>
        {token ? (
          <>
            <div
              style={{
                display: "flex",
                gap: 10,
                alignItems: "flex-start",
                background: "color-mix(in srgb, var(--amber) 10%, transparent)",
                border: "1px solid color-mix(in srgb, var(--amber) 32%, transparent)",
                borderRadius: 10,
                padding: "11px 13px",
                marginBottom: 14,
              }}
            >
              <Icon name="alert" size={15} color="var(--amber)" style={{ marginTop: 1 }} />
              <div style={{ fontSize: 12, color: "var(--txt2)", lineHeight: 1.5 }}>
                {t("screen.enroll.shownOnce")}
                <div style={{ marginTop: 4, color: "var(--txt)" }}>{t("screen.enroll.deliverHint")}</div>
              </div>
            </div>
            <div style={{ fontSize: 11, fontWeight: 600, color: "var(--txt3)", marginBottom: 5 }}>
              {t("screen.enroll.tokenLabel")}
            </div>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 10,
                padding: "11px 13px",
                borderRadius: 11,
                background: "var(--bg2)",
                border: "1px solid var(--accentLine)",
              }}
            >
              <span
                style={{
                  flex: 1,
                  fontFamily: MONO,
                  fontSize: 12.5,
                  color: "var(--accent)",
                  wordBreak: "break-all",
                }}
              >
                {token}
              </span>
              <Btn size="sm" variant="soft" icon={copied ? "check" : "copy"} onClick={copyToken}>
                {copied ? t("common.copied") : t("common.copy")}
              </Btn>
            </div>
            {expiresAt ? (
              <div style={{ fontSize: 11.5, color: "var(--txt3)", marginTop: 8 }}>
                {t("screen.enroll.expiresIn", { when: fmtDate(expiresAt) })}
              </div>
            ) : null}
            <Btn full onClick={close} style={{ marginTop: 14 }}>
              {t("common.done")}
            </Btn>
          </>
        ) : (
          <>
            <Field label={t("screen.enroll.labelLabel")}>
              <TextInput value={label} onChange={setLabel} placeholder={t("screen.enroll.labelPlaceholder")} />
            </Field>
            <Field label={t("screen.enroll.tierLabel")}>
              <div style={{ display: "flex", gap: 8 }}>
                {TIERS.map((x) => (
                  <Chip key={x.value || "default"} active={tier === x.value} onClick={() => setTier(x.value)}>
                    {t(x.label)}
                  </Chip>
                ))}
              </div>
            </Field>
            <Field label={t("screen.enroll.ttlLabel")}>
              <div style={{ display: "flex", gap: 8 }}>
                {TTLS.map((x) => (
                  <Chip key={x.seconds} active={ttl === x.seconds} onClick={() => setTtl(x.seconds)}>
                    {t(x.label)}
                  </Chip>
                ))}
              </div>
            </Field>
            <div style={{ fontSize: 11.5, color: "var(--txt3)", lineHeight: 1.5, marginTop: -4, marginBottom: 12 }}>
              {t("screen.enroll.advisoryNote")}
            </div>

            {error ? (
              <div style={{ fontSize: 12.5, color: "var(--red)", marginBottom: 12, display: "flex", gap: 6, alignItems: "center" }}>
                <Icon name="alert" size={14} color="var(--red)" />
                {error}
              </div>
            ) : null}

            <div style={{ display: "flex", gap: 9 }}>
              <Btn full onClick={close}>
                {t("common.cancel")}
              </Btn>
              <Btn full variant="primary" loading={busy} disabled={!label.trim()} onClick={mint}>
                {t("screen.enroll.mintButton")}
              </Btn>
            </div>
          </>
        )}
      </div>
    </Modal>
  );
}

function Chip({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      style={{
        flex: 1,
        padding: "8px 0",
        borderRadius: 8,
        border: active ? "1px solid var(--accentLine)" : "1px solid var(--line)",
        background: active ? "var(--accentSoft)" : "var(--bg2)",
        color: active ? "var(--accent)" : "var(--txt2)",
        fontFamily: "inherit",
        fontSize: 13,
        fontWeight: 600,
        cursor: "pointer",
      }}
    >
      {children}
    </button>
  );
}
