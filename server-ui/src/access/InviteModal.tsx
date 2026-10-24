import "./access.css";
import { useEffect, useId, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { useUi } from "../store/ui";
import { useAsync } from "../util/useAsync";
import { fmtDate } from "../util/format";
import { Icon } from "../ui/icons";
import { Btn, Field, InlineError, SecretRow, Segmented } from "../ui/primitives";
import { Modal } from "../ui/overlays";
import { useCopy } from "../ui/useCopy";
import { Caution, DialogFoot, DialogTitle } from "./kit";

const ROLES = ["member", "admin"] as const;
const TTLS: { label: string; seconds: number }[] = [
  { label: "common.ttl1h", seconds: 3600 },
  { label: "common.ttl24h", seconds: 86400 },
  { label: "common.ttl7d", seconds: 604800 },
];

// Field's own bottom margin is dropped: the body's 16 px gap spaces the fields.
const FIELD = { marginBottom: 0 };

export function InviteModal() {
  const { t } = useTranslation();
  const open = useUi((s) => s.inviteOpen);
  const close = useUi((s) => s.closeInvite);
  const bumpReload = useUi((s) => s.bumpReload);
  const titleId = useId();
  const descId = useId();
  const spaceSelectId = useId();

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
  const both = useCopy(1500);
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

  // When the token appears the form is gone; the focus moves to the warning that says
  // it is shown once, so it is read first and Tab stays inside the dialog.
  const shownOnce = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (token) shownOnce.current?.focus();
  }, [token]);

  if (!open) return null;

  const issue = async (e?: FormEvent) => {
    e?.preventDefault();
    if (busy) return;
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

  const head = (
    <DialogTitle
      titleId={titleId}
      title={t("screen.invites.issueTitle")}
      descId={descId}
      description={t("screen.invites.issueSubtitle")}
    />
  );

  return (
    <Modal onClose={close} width={460} labelledBy={titleId} describedBy={descId}>
      {token ? (
        <>
          <div className="acc-dlg-body">
            {head}
            <Caution ref={shownOnce} focusable>
              {t("screen.invites.shownOnce")}
              <div style={{ marginTop: 4, fontWeight: 600 }}>{t("screen.invites.deliverHint")}</div>
            </Caution>
            <SecretRow label={t("screen.invites.spaceIdLabel")} value={spaceId} />
            <SecretRow label={t("screen.invites.tokenLabel")} value={token} />
            {url ? <SecretRow label={t("screen.invites.urlLabel")} value={url} /> : null}
            {expiresAt ? (
              <p className="acc-note">{t("screen.invites.expiresIn", { when: fmtDate(expiresAt) })}</p>
            ) : null}
            {both.failed ? (
              <p role="alert" className="acc-error">
                {t("common.copyFailed")}
              </p>
            ) : null}
          </div>
          <DialogFoot>
            <Btn variant="outline" onClick={close}>
              {t("common.done")}
            </Btn>
            <Btn
              variant="primary"
              icon={both.copied ? "check" : both.failed ? "x" : "copy"}
              onClick={() =>
                both.copy(`${t("screen.invites.spaceIdLabel")}: ${spaceId}\n${t("screen.invites.tokenLabel")}: ${token}`)
              }
            >
              {both.copied ? t("common.copied") : t("screen.invites.copyBoth")}
            </Btn>
          </DialogFoot>
        </>
      ) : (
        <form className="acc-dlg-form" onSubmit={issue} noValidate>
          <div className="acc-dlg-body">
            {head}
            <Field
              label={t("screen.invites.spaceLabel")}
              htmlFor={spaceList.length === 0 ? undefined : spaceSelectId}
              style={FIELD}
            >
              {spaceList.length === 0 ? (
                // Absent, or still on its way: a dashed placeholder holding the field's place.
                <div className="acc-absent" role={spaces.loading ? "status" : undefined}>
                  {spaces.loading ? t("common.loading") : t("screen.invites.noSpaces")}
                </div>
              ) : (
                <div style={{ position: "relative" }}>
                  <select
                    id={spaceSelectId}
                    value={spaceId}
                    onChange={(e) => setSpaceId(e.target.value)}
                    className="u-input acc-select"
                    autoFocus
                  >
                    {spaceList.map((s) => (
                      <option key={s.space_id} value={s.space_id}>
                        {s.name}
                      </option>
                    ))}
                  </select>
                  <Icon
                    name="chevronDown"
                    size={16}
                    color="var(--muted-foreground)"
                    style={{ position: "absolute", top: 8, right: 10, pointerEvents: "none" }}
                  />
                </div>
              )}
            </Field>
            <Field label={t("screen.invites.roleLabel")} style={FIELD}>
              <Segmented
                ariaLabel={t("screen.invites.roleLabel")}
                options={ROLES.map((r) => ({ value: r, label: r }))}
                value={role}
                onChange={setRole}
              />
            </Field>
            <Field label={t("screen.invites.ttlLabel")} style={FIELD}>
              <Segmented
                ariaLabel={t("screen.invites.ttlLabel")}
                options={TTLS.map((x) => ({ value: String(x.seconds), label: t(x.label) }))}
                value={String(ttl)}
                onChange={(v) => setTtl(Number(v))}
              />
            </Field>
            {/* The bound of what the role means, said before the click. */}
            <p className="acc-copy">{t("screen.invites.advisoryNote")}</p>

            {error ? <InlineError>{error}</InlineError> : null}
          </div>
          <DialogFoot>
            <Btn variant="outline" onClick={close}>
              {t("common.cancel")}
            </Btn>
            <Btn variant="primary" type="submit" loading={busy} disabled={spaceList.length === 0}>
              {t("screen.invites.issueButton")}
            </Btn>
          </DialogFoot>
        </form>
      )}
    </Modal>
  );
}
