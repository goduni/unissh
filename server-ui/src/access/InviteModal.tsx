import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { useUi } from "../store/ui";
import { useAsync } from "../util/useAsync";
import { fmtDate } from "../util/format";
import { Icon } from "../ui/icons";
import { Btn, Field, SecretRow } from "../ui/primitives";
import { Modal } from "../ui/overlays";
import { useCopy } from "../ui/useCopy";

const ROLES = ["member", "admin"] as const;
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

  // The invite is scoped to a SPACE the caller admins (v2). The invitee joins that
  // space with the token; the server resolves the space from the token's intents.
  // Filter to spaces the caller ADMINS — the server rejects an invite into a space
  // the caller only belongs to (403), so member-only spaces must not be offered
  // (mirrors the Spaces "Add member" gate).
  const spaces = useAsync(() => api.spaces.list(), [open]);
  const spaceList = (spaces.data?.spaces ?? []).filter((s) => s.role === "admin");

  const [spaceId, setSpaceId] = useState("");
  const [role, setRole] = useState<(typeof ROLES)[number]>("member");
  const [ttl, setTtl] = useState(86400);
  const [token, setToken] = useState<string | null>(null);
  const [expiresAt, setExpiresAt] = useState<number | null>(null);
  const [url, setUrl] = useState<string | null>(null);
  const both = useCopy(1200);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setRole("member");
      setTtl(86400);
      setToken(null);
      setExpiresAt(null);
      setUrl(null);
      setError(null);
    }
  }, [open]);

  // Default the space to the first one the caller admins, once the list loads.
  useEffect(() => {
    if (open && !spaceId && spaceList.length) setSpaceId(spaceList[0].space_id);
  }, [open, spaceId, spaceList]);

  if (!open) return null;

  const issue = async () => {
    if (!spaceId) {
      setError(t("screen.invites.noSpaces"));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const r = await api.identity.issueInvite({
        space_intents: [{ space_id: spaceId, role }],
        ttl_seconds: ttl,
      });
      setToken(r.token);
      setExpiresAt(r.expires_at);
      setUrl(r.url);
      bumpReload();
    } catch (e) {
      setError(e instanceof Error ? e.message : t("screen.invites.issueError"));
    } finally {
      setBusy(false);
    }
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
            <SecretRow label={t("screen.invites.spaceIdLabel")} value={spaceId} />
            <div style={{ height: 10 }} />
            <SecretRow label={t("screen.invites.tokenLabel")} value={token} />
            {url ? (
              <>
                <div style={{ height: 10 }} />
                <SecretRow label={t("screen.invites.urlLabel")} value={url} />
              </>
            ) : null}
            {expiresAt ? (
              <div style={{ fontSize: 11.5, color: "var(--txt3)", marginTop: 8 }}>
                {t("screen.invites.expiresIn", { when: fmtDate(expiresAt) })}
              </div>
            ) : null}
            <Btn
              full
              variant="primary"
              icon={both.copied ? "check" : "copy"}
              onClick={() =>
                both.copy(`${t("screen.invites.spaceIdLabel")}: ${spaceId}\n${t("screen.invites.tokenLabel")}: ${token}`)
              }
              style={{ marginTop: 14 }}
            >
              {both.copied ? t("common.copied") : t("screen.invites.copyBoth")}
            </Btn>
            <Btn full onClick={close} style={{ marginTop: 9 }}>
              {t("common.done")}
            </Btn>
          </>
        ) : (
          <>
            <Field label={t("screen.invites.spaceLabel")}>
              {spaceList.length === 0 ? (
                <div style={{ fontSize: 12.5, color: "var(--txt3)" }}>
                  {spaces.loading ? t("common.loading") : t("screen.invites.noSpaces")}
                </div>
              ) : (
                <select
                  value={spaceId}
                  onChange={(e) => setSpaceId(e.target.value)}
                  style={{
                    width: "100%",
                    height: 34,
                    borderRadius: 8,
                    background: "var(--bg2)",
                    border: "1px solid var(--line)",
                    color: "var(--txt)",
                    fontFamily: "inherit",
                    fontSize: 13,
                    padding: "0 10px",
                  }}
                >
                  {spaceList.map((s) => (
                    <option key={s.space_id} value={s.space_id}>
                      {s.name}
                    </option>
                  ))}
                </select>
              )}
            </Field>
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
              <Btn full variant="primary" loading={busy} disabled={spaceList.length === 0} onClick={issue}>
                {t("screen.invites.issueButton")}
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
