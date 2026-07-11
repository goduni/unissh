import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { useUi } from "../store/ui";
import { useTenant } from "../store/tenant";
import { fmtDate } from "../util/format";
import { Icon } from "../ui/icons";
import { Btn, Field, TextInput } from "../ui/primitives";
import { Modal } from "../ui/overlays";
import { MONO } from "../theme/tokens";

const ROLES = ["viewer", "editor", "admin"] as const;
const TTLS: { label: string; seconds: number }[] = [
  { label: "common.ttl1h", seconds: 3600 },
  { label: "common.ttl24h", seconds: 86400 },
  { label: "common.ttl7d", seconds: 604800 },
];

export function InviteModal() {
  const { t } = useTranslation();
  const open = useUi((s) => s.inviteOpen);
  const close = useUi((s) => s.closeInvite);
  const bumpReload = useUi((s) => s.bumpReload);
  // The invite is minted for the ACTIVE space — the invitee needs its id too, not
  // just the token (both /v1/register and /v1/invite/redeem resolve the space from
  // the tenant header). Surfacing only the token was a dead-end handoff.
  const spaceId = useTenant((s) => s.activeTenantId) ?? "";

  const [role, setRole] = useState<(typeof ROLES)[number]>("editor");
  const [ttl, setTtl] = useState(86400);
  const [scope, setScope] = useState("");
  const [token, setToken] = useState<string | null>(null);
  const [expiresAt, setExpiresAt] = useState<number | null>(null);
  const [copied, setCopied] = useState<"space" | "token" | "both" | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setRole("editor");
      setTtl(86400);
      setScope("");
      setToken(null);
      setExpiresAt(null);
      setError(null);
      setCopied(null);
    }
  }, [open]);

  if (!open) return null;

  const issue = async () => {
    setBusy(true);
    setError(null);
    try {
      const r = await api.identity.issueInvite(role, scope || undefined, ttl);
      setToken(r.token);
      setExpiresAt(r.expires_at);
      bumpReload();
    } catch (e) {
      setError(e instanceof Error ? e.message : t("screen.invites.issueError"));
    } finally {
      setBusy(false);
    }
  };

  const copyVal = (text: string, mark: "space" | "token" | "both") => {
    void navigator.clipboard?.writeText(text);
    setCopied(mark);
    setTimeout(() => setCopied(null), 1200);
  };

  return (
    <Modal onClose={close} width={440}>
      <div style={{ padding: "20px 22px 0" }}>
        <div style={{ fontSize: 16, fontWeight: 800 }}>{t("screen.invites.issueTitle")}</div>
        <div style={{ fontSize: 12, color: "var(--txt3)", marginTop: 2 }}>
          {t("screen.invites.issueSubtitle")}
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
                {t("screen.invites.shownOnce")}
                <div style={{ marginTop: 4, color: "var(--txt)" }}>{t("screen.invites.deliverHint")}</div>
              </div>
            </div>
            <CredField
              label={t("screen.invites.spaceIdLabel")}
              value={spaceId}
              copied={copied === "space"}
              onCopy={() => copyVal(spaceId, "space")}

            />
            <div style={{ height: 10 }} />
            <CredField
              label={t("screen.invites.tokenLabel")}
              value={token}
              copied={copied === "token"}
              onCopy={() => copyVal(token, "token")}
            />
            {expiresAt ? (
              <div style={{ fontSize: 11.5, color: "var(--txt3)", marginTop: 8 }}>
                {t("screen.invites.expiresIn", { when: fmtDate(expiresAt) })}
              </div>
            ) : null}
            <Btn
              full
              variant="primary"
              icon={copied === "both" ? "check" : "copy"}
              onClick={() =>
                copyVal(`${t("screen.invites.spaceIdLabel")}: ${spaceId}\n${t("screen.invites.tokenLabel")}: ${token}`, "both")
              }
              style={{ marginTop: 14 }}
            >
              {copied === "both" ? t("common.copied") : t("screen.invites.copyBoth")}
            </Btn>
            <Btn full onClick={close} style={{ marginTop: 9 }}>
              {t("common.done")}
            </Btn>
          </>
        ) : (
          <>
            <Field label={t("screen.invites.roleLabel")}>
              <div style={{ display: "flex", gap: 8 }}>
                {ROLES.map((r) => (
                  <Chip key={r} active={role === r} onClick={() => setRole(r)}>
                    {r}
                  </Chip>
                ))}
              </div>
            </Field>
            <Field label={t("screen.invites.ttlLabel")}>
              <div style={{ display: "flex", gap: 8 }}>
                {TTLS.map((x) => (
                  <Chip key={x.seconds} active={ttl === x.seconds} onClick={() => setTtl(x.seconds)}>
                    {t(x.label)}
                  </Chip>
                ))}
              </div>
            </Field>
            <Field label={t("screen.invites.scopeLabel")}>
              <TextInput value={scope} onChange={setScope} placeholder={t("screen.invites.scopePlaceholder")} />
            </Field>
            <div style={{ fontSize: 11.5, color: "var(--txt3)", lineHeight: 1.5, marginTop: -4, marginBottom: 12 }}>
              {t("screen.invites.advisoryNote")}
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
              <Btn full variant="primary" loading={busy} onClick={issue}>
                {t("screen.invites.issueButton")}
              </Btn>
            </div>
          </>
        )}
      </div>
    </Modal>
  );
}

function CredField({
  label,
  value,
  copied,
  onCopy,
}: {
  label: string;
  value: string;
  copied: boolean;
  onCopy: () => void;
}) {
  const { t } = useTranslation();
  return (
    <div>
      <div style={{ fontSize: 11, fontWeight: 600, color: "var(--txt3)", marginBottom: 5 }}>{label}</div>
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
          {value || "—"}
        </span>
        <Btn size="sm" variant="soft" icon={copied ? "check" : "copy"} onClick={onCopy}>
          {copied ? t("common.copied") : t("common.copy")}
        </Btn>
      </div>
    </div>
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
