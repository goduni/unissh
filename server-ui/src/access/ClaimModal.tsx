import "./access.css";
import { useEffect, useId, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { claimInstance, type ClaimOutcome } from "../api/auth-service";
import { ApiError } from "../api/errors";
import { CryptoUnavailableError } from "../crypto/provider";
import { useCryptoReady } from "../crypto/wasm-provider";
import { useUi } from "../store/ui";
import { Icon } from "../ui/icons";
import { Btn, Field, InlineError, TextInput, ZkBanner } from "../ui/primitives";
import { Modal } from "../ui/overlays";
import { CautionLine, CopyWell, DialogFoot, DialogTitle } from "./kit";

// Field's own bottom margin is dropped: the body's 16 px gap spaces the fields.
const FIELD = { marginBottom: 0 };

/**
 * First-run instance claim: setup code → genesis owner keyset. The keyset is
 * generated in the browser and never sent to the server; escrow sign-in is armed
 * on success so the owner can log in later by handle+password+Secret Key.
 */
export function ClaimModal({
  instanceUrl,
  onClose,
}: {
  instanceUrl: string;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const toast = useUi((s) => s.toast);
  const titleId = useId();
  const descId = useId();
  const kitId = useId();
  const codeId = useId();
  const nameId = useId();
  const handleId = useId();
  const spaceId = useId();
  const passwordId = useId();

  const [setupCode, setSetupCode] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [handle, setHandle] = useState("");
  const [spaceName, setSpaceName] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // The refusal names the setup-code field (said under it), not the server's answer.
  const [codeMissing, setCodeMissing] = useState(false);
  const [result, setResult] = useState<ClaimOutcome | null>(null);
  // Gate "Continue" on the whole Emergency Kit: the recovery file is downloaded AND
  // the operator has explicitly acknowledged saving the Secret Key. The Secret Key is
  // the one irreplaceable part (zero-knowledge — the server never holds it), so the
  // acknowledgement, not just the file, is the real gate.
  const [downloaded, setDownloaded] = useState(false);
  const [secretAck, setSecretAck] = useState(false);
  // Session-mint runs behind the save-gate and is retryable: a transient failure
  // must keep the (already-revealed) Secret Key on screen, never a null result.
  const [finishing, setFinishing] = useState(false);
  const [finishError, setFinishError] = useState<string | null>(null);

  const cryptoReady = useCryptoReady();

  // When the Secret Key appears the form is gone; the focus moves to the warning that
  // says it is shown once, so it is read first and Tab stays inside the dialog.
  const shownOnce = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (result) shownOnce.current?.focus();
  }, [result]);

  const create = async (e?: FormEvent) => {
    e?.preventDefault();
    if (busy) return;
    if (!setupCode.trim()) {
      setCodeMissing(true);
      return setError(t("access.onb.claim_err_no_code"));
    }
    setCodeMissing(false);
    setError(null);
    setBusy(true);
    try {
      const outcome = await claimInstance({
        instanceUrl,
        setupCode,
        password: password || null,
        displayName,
        handle,
        spaceName,
      });
      setResult(outcome);
      toast("success", t("access.onb.claim_created_toast"));
    } catch (e) {
      const msg = e instanceof Error ? e.message : "";
      setError(
        e instanceof CryptoUnavailableError
          ? t("access.onb.bs_err_crypto")
          : e instanceof ApiError && /setup|code/i.test(msg)
            ? t("access.onb.claim_err_code")
            : e instanceof ApiError && /claimed/i.test(msg)
              ? t("access.onb.claim_err_claimed")
              : msg || t("access.onb.bs_err_generic"),
      );
    } finally {
      setBusy(false);
    }
  };

  const downloadKeyset = () => {
    if (!result) return;
    const blob = new Blob([result.enc as unknown as BlobPart], {
      type: "application/octet-stream",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "identity.kit";
    a.click();
    URL.revokeObjectURL(url);
    setDownloaded(true);
  };

  // Resolves whether the copy landed: the well shows the green check, or says the
  // browser refused and how to copy by hand. Never a "copied" the clipboard did not take.
  const copySecret = async (): Promise<boolean> => {
    if (!result) return false;
    try {
      await navigator.clipboard.writeText(result.secretKeyHex);
      toast("success", t("access.onb.bs_copied_toast"));
      return true;
    } catch {
      /* clipboard may be unavailable in this context */
      return false;
    }
  };

  const finish = async () => {
    if (!result) return;
    setFinishError(null);
    setFinishing(true);
    try {
      // Mint + commit the session (flips the app into the Shell). Retryable — the
      // owner is already minted and the Secret Key is saved, so on failure we just
      // surface an error and let the operator retry with the key still on screen.
      await result.commit();
      // Session live → arm escrow with the now-live Bearer. armEscrow never throws;
      // a failure is advisory only.
      const armWarn = t("access.onb.claim_arm_warn");
      void result.armEscrow().then((armed) => {
        if (!armed) useUi.getState().toast("info", armWarn);
      });
    } catch (e) {
      setFinishError(e instanceof Error ? e.message : t("access.onb.bs_err_generic"));
      setFinishing(false);
    }
  };

  // Once the Secret Key exists but the Emergency Kit isn't secured yet, Escape /
  // backdrop must NOT dismiss. Both halves are required: the recovery file is
  // downloaded AND the Secret Key is acknowledged as stored.
  const kitSecured = downloaded && secretAck;
  const locked = result !== null && !kitSecured;

  const head = (
    <DialogTitle
      titleId={titleId}
      title={t("access.onb.claim_title")}
      descId={descId}
      description={result ? t("access.onb.bs_done_step") : t("access.onb.claim_step1")}
    />
  );

  return (
    <Modal
      onClose={onClose}
      width={480}
      dismissable={!locked}
      labelledBy={titleId}
      describedBy={descId}
    >
      {result ? (
        <>
          <div className="acc-dlg-body">
            {head}
            {/* The zero-knowledge warning, said first and loud. The wrapper takes the
                focus on reveal; its negative margin cancels the banner's own. */}
            <div ref={shownOnce} tabIndex={-1} className="acc-focus-target" style={{ marginBottom: -16 }}>
              <ZkBanner tone="amber">{t("access.onb.bs_done_intro")}</ZkBanner>
            </div>

            {/* Emergency Kit — the Secret Key and its offline recovery file, grouped
                as one labelled object; "Enter the panel" gates on both being secured. */}
            <section aria-labelledby={kitId} className="acc-kit">
              <div
                id={kitId}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  fontSize: 13,
                  fontWeight: 600,
                  lineHeight: "18px",
                }}
              >
                <Icon name="shieldcheck" size={16} />
                {t("access.onb.bs_kit_label")}
              </div>

              <CopyWell
                label={t("access.onb.bs_secretkey_label")}
                tag={t("access.onb.bs_secretkey_tag")}
                hint={t("access.onb.bs_secretkey_hint")}
                value={result.secretKeyHex}
                onCopy={copySecret}
                copyLabel={t("access.onb.bs_copy_btn")}
              />

              <div className="acc-stack" style={{ gap: 6 }}>
                <Btn
                  full
                  variant="outline"
                  icon={downloaded ? "check" : "download"}
                  iconColor={downloaded ? "var(--success)" : undefined}
                  onClick={downloadKeyset}
                >
                  {t("access.onb.bs_download_btn")}
                </Btn>
                {/* Said in a word, not only by the icon: the file half of the gate is done. */}
                <p
                  role="status"
                  style={{ margin: 0, fontSize: 12, lineHeight: "16px", color: "var(--success)" }}
                >
                  {downloaded ? t("access.onb.bs_downloaded") : ""}
                </p>
              </div>

              <CheckRow
                checked={secretAck}
                onChange={setSecretAck}
                label={t("access.onb.bs_secretack_label")}
              />
            </section>

            {finishError ? <InlineError>{finishError}</InlineError> : null}
          </div>
          <DialogFoot note={!kitSecured ? t("access.onb.bs_done_gate") : undefined}>
            <Btn variant="primary" disabled={!kitSecured || finishing} loading={finishing} onClick={finish}>
              {t("access.onb.claim_enter_btn")}
            </Btn>
          </DialogFoot>
        </>
      ) : (
        <form className="acc-dlg-form" onSubmit={create} noValidate>
          <div className="acc-dlg-body">
            {head}
            <p className="acc-copy">{t("access.onb.claim_intro")}</p>

            <Field
              label={t("access.onb.setup_label")}
              tag={t("access.onb.setup_tag")}
              hint={t("access.onb.setup_hint")}
              error={codeMissing ? error : null}
              htmlFor={codeId}
              style={FIELD}
            >
              <TextInput
                id={codeId}
                value={setupCode}
                onChange={(v) => {
                  setSetupCode(v);
                  if (codeMissing) {
                    setCodeMissing(false);
                    setError(null);
                  }
                }}
                placeholder={t("access.onb.setup_ph")}
                mono
                invalid={codeMissing}
                autoFocus
              />
            </Field>

            <Field
              label={t("access.onb.bs_name_label")}
              tag={t("access.onb.bs_name_tag")}
              hint={t("access.onb.bs_name_hint")}
              htmlFor={nameId}
              style={FIELD}
            >
              <TextInput
                id={nameId}
                value={displayName}
                onChange={setDisplayName}
                placeholder={t("access.onb.bs_name_ph")}
              />
            </Field>

            <Field
              label={t("access.onb.bs_handle_label")}
              tag={t("access.onb.bs_handle_tag")}
              hint={t("access.onb.bs_handle_hint")}
              htmlFor={handleId}
              style={FIELD}
            >
              <TextInput
                id={handleId}
                value={handle}
                onChange={setHandle}
                placeholder={t("access.onb.bs_handle_ph")}
                mono
                autoComplete="username"
              />
            </Field>

            <Field
              label={t("access.onb.space_label")}
              tag={t("access.onb.space_tag")}
              hint={t("access.onb.space_hint")}
              htmlFor={spaceId}
              style={FIELD}
            >
              <TextInput
                id={spaceId}
                value={spaceName}
                onChange={setSpaceName}
                placeholder={t("access.onb.space_ph")}
              />
            </Field>

            <Field
              label={t("access.onb.bs_pwd_label")}
              tag={t("access.onb.bs_pwd_tag")}
              hint={t("access.onb.bs_pwd_hint")}
              htmlFor={passwordId}
              style={FIELD}
            >
              <TextInput
                id={passwordId}
                type="password"
                value={password}
                onChange={setPassword}
                placeholder="••••••••"
                mono
                autoComplete="new-password"
              />
            </Field>

            {!cryptoReady ? <CautionLine>{t("access.onb.ks_crypto_warn")}</CautionLine> : null}
            {error && !codeMissing ? <InlineError>{error}</InlineError> : null}
          </div>
          <DialogFoot>
            <Btn variant="outline" onClick={onClose}>
              {t("common.cancel")}
            </Btn>
            <Btn variant="primary" type="submit" loading={busy}>
              {t("access.onb.claim_create_btn")}
            </Btn>
          </DialogFoot>
        </form>
      )}
    </Modal>
  );
}

/** Inline acknowledgement checkbox (accessible button + check glyph). Local to the
 *  claim reveal — the Secret-Key "I've stored it" gate. */
function CheckRow({
  checked,
  onChange,
  label,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
}) {
  return (
    <button
      type="button"
      role="checkbox"
      aria-checked={checked}
      onClick={() => onChange(!checked)}
      className="acc-check"
    >
      <span className="acc-check-box">
        {checked ? <Icon name="check" size={12} stroke={2.4} /> : null}
      </span>
      <span className="acc-check-label">{label}</span>
    </button>
  );
}
