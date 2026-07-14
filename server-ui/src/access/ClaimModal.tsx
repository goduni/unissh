import { useState } from "react";
import { useTranslation } from "react-i18next";
import { claimInstance, type ClaimOutcome } from "../api/auth-service";
import { ApiError } from "../api/errors";
import { CryptoUnavailableError, getCrypto } from "../crypto/provider";
import { useUi } from "../store/ui";
import { Icon } from "../ui/icons";
import { Btn, Field, InlineError, TextInput } from "../ui/primitives";
import { Modal } from "../ui/overlays";

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

  const [setupCode, setSetupCode] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [handle, setHandle] = useState("");
  const [spaceName, setSpaceName] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ClaimOutcome | null>(null);
  // Gate "Done" until the genesis keyset is downloaded — losing it (with the
  // password) makes the owner unrecoverable, so it can't be the easy skip.
  const [downloaded, setDownloaded] = useState(false);
  // Session-mint runs behind the save-gate and is retryable: a transient failure
  // must keep the (already-revealed) Secret Key on screen, never a null result.
  const [finishing, setFinishing] = useState(false);
  const [finishError, setFinishError] = useState<string | null>(null);

  const cryptoReady = getCrypto().available;

  const create = async () => {
    if (!setupCode.trim()) return setError(t("access.onb.claim_err_no_code"));
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
    a.download = "genesis.keyset";
    a.click();
    URL.revokeObjectURL(url);
    setDownloaded(true);
  };

  const copySecret = async () => {
    if (!result) return;
    try {
      await navigator.clipboard.writeText(result.secretKeyHex);
      toast("success", t("access.onb.bs_copied_toast"));
    } catch {
      /* clipboard may be unavailable in this context */
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

  // Once the genesis Secret Key exists but isn't saved yet, Escape / backdrop must
  // NOT dismiss — losing it makes the owner permanently unrecoverable.
  const locked = result !== null && !downloaded;

  return (
    <Modal onClose={onClose} width={460} dismissable={!locked}>
      <div style={{ padding: "20px 22px 0" }}>
        <div style={{ fontSize: 16, fontWeight: 800 }}>{t("access.onb.claim_title")}</div>
        <div style={{ fontSize: 12, color: "var(--txt3)", marginTop: 2 }}>
          {result ? t("access.onb.bs_done_step") : t("access.onb.claim_step1")}
        </div>
      </div>

      <div style={{ padding: "18px 22px" }}>
        {result ? (
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
                marginBottom: 16,
              }}
            >
              <Icon name="alert" size={15} color="var(--amber)" style={{ marginTop: 1 }} />
              <div style={{ fontSize: 12, color: "var(--txt2)", lineHeight: 1.5 }}>
                {t("access.onb.bs_done_intro")}
              </div>
            </div>
            <Field
              label={t("access.onb.bs_secretkey_label")}
              tag={t("access.onb.bs_secretkey_tag")}
              hint={t("access.onb.bs_secretkey_hint")}
            >
              <div style={{ display: "flex", gap: 8 }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <TextInput value={result.secretKeyHex} mono />
                </div>
                <Btn icon="copy" onClick={copySecret}>
                  {t("access.onb.bs_copy_btn")}
                </Btn>
              </div>
            </Field>
            <Btn
              full
              icon={downloaded ? "check" : "download"}
              variant="primary"
              onClick={downloadKeyset}
              style={{ marginBottom: 9 }}
            >
              {t("access.onb.bs_download_btn")}
            </Btn>
            <Btn
              full
              variant="soft"
              disabled={!downloaded || finishing}
              loading={finishing}
              onClick={finish}
            >
              {t("access.onb.claim_enter_btn")}
            </Btn>
            {finishError ? (
              <div style={{ marginTop: 9 }}>
                <InlineError>{finishError}</InlineError>
              </div>
            ) : null}
            {!downloaded ? (
              <div style={{ fontSize: 11.5, color: "var(--txt3)", marginTop: 8, textAlign: "center" }}>
                {t("access.onb.bs_done_gate")}
              </div>
            ) : null}
          </>
        ) : (
          <>
            <div
              style={{
                fontSize: 12.5,
                color: "var(--txt2)",
                lineHeight: 1.55,
                marginBottom: 16,
              }}
            >
              {t("access.onb.claim_intro")}
            </div>

            <Field
              label={t("access.onb.setup_label")}
              tag={t("access.onb.setup_tag")}
              hint={t("access.onb.setup_hint")}
            >
              <TextInput
                value={setupCode}
                onChange={setSetupCode}
                placeholder={t("access.onb.setup_ph")}
                mono
              />
            </Field>

            <Field
              label={t("access.onb.bs_name_label")}
              tag={t("access.onb.bs_name_tag")}
              hint={t("access.onb.bs_name_hint")}
            >
              <TextInput
                value={displayName}
                onChange={setDisplayName}
                placeholder={t("access.onb.bs_name_ph")}
              />
            </Field>

            <Field
              label={t("access.onb.bs_handle_label")}
              tag={t("access.onb.bs_handle_tag")}
              hint={t("access.onb.bs_handle_hint")}
            >
              <TextInput
                value={handle}
                onChange={setHandle}
                placeholder={t("access.onb.bs_handle_ph")}
                mono
              />
            </Field>

            <Field
              label={t("access.onb.space_label")}
              tag={t("access.onb.space_tag")}
              hint={t("access.onb.space_hint")}
            >
              <TextInput
                value={spaceName}
                onChange={setSpaceName}
                placeholder={t("access.onb.space_ph")}
              />
            </Field>

            <Field
              label={t("access.onb.bs_pwd_label")}
              tag={t("access.onb.bs_pwd_tag")}
              hint={t("access.onb.bs_pwd_hint")}
            >
              <TextInput
                type="password"
                value={password}
                onChange={setPassword}
                placeholder="••••••••"
                mono
              />
            </Field>

            {!cryptoReady ? (
              <div
                style={{
                  fontSize: 11.5,
                  color: "var(--amber)",
                  marginBottom: 12,
                  display: "flex",
                  gap: 6,
                  alignItems: "center",
                }}
              >
                <Icon name="alert" size={13} color="var(--amber)" />
                {t("access.onb.ks_crypto_warn")}
              </div>
            ) : null}

            {error ? <InlineError>{error}</InlineError> : null}

            <div style={{ display: "flex", gap: 9 }}>
              <Btn full onClick={onClose}>
                {t("common.cancel")}
              </Btn>
              <Btn full variant="primary" loading={busy} onClick={create}>
                {t("access.onb.claim_create_btn")}
              </Btn>
            </div>
          </>
        )}
      </div>
    </Modal>
  );
}
