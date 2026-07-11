import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { CryptoUnavailableError, getCrypto } from "../crypto/provider";
import { useTenant } from "../store/tenant";
import { useUi } from "../store/ui";
import { bytesToB64, bytesToHex } from "../util/bytes";
import { Icon } from "../ui/icons";
import { Btn, Field, InlineError, TextInput } from "../ui/primitives";
import { Modal } from "../ui/overlays";

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

export function BootstrapModal() {
  const { t } = useTranslation();
  const open = useUi((s) => s.bootstrapOpen);
  const close = useUi((s) => s.closeBootstrap);
  const toast = useUi((s) => s.toast);
  const setTenants = useTenant((s) => s.setTenants);

  const [tenantId, setTenantId] = useState(() => bytesToB64(randomBytes(16)));
  const [tier, setTier] = useState<"personal" | "org">("personal");
  const [displayName, setDisplayName] = useState("");
  const [handle, setHandle] = useState("");
  const [password, setPassword] = useState("");
  const [bootstrapToken, setBootstrapToken] = useState("");
  const [advanced, setAdvanced] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{ secretKeyHex: string; enc: Uint8Array } | null>(null);
  // Gate "Done" until the genesis keyset is downloaded — losing it means the
  // owner is unrecoverable (bs_done_intro), so it can't be the easy skip.
  const [downloaded, setDownloaded] = useState(false);

  // The modal is mounted once in Shell and only hidden via `open`, so state
  // would otherwise persist across reopens — including the one-time Secret Key.
  // Reset to a fresh Step 1 (new tenant_id) every time it opens.
  useEffect(() => {
    if (open) {
      setResult(null);
      setDownloaded(false);
      setError(null);
      setBusy(false);
      setTenantId(bytesToB64(randomBytes(16)));
      setDisplayName("");
      setHandle("");
      setPassword("");
      setBootstrapToken("");
      setAdvanced(false);
    }
  }, [open]);

  if (!open) return null;

  const create = async () => {
    setError(null);
    setBusy(true);
    try {
      const cr = getCrypto();
      const accountId = randomBytes(16);
      const acc = await cr.createAccount(password || null);
      const reg = await cr.buildRegistration(accountId);
      await api.identity.bootstrap(tenantId, {
        registration_payload: bytesToB64(reg.payload),
        registration_signature: bytesToB64(reg.signature),
        tier,
        display_name: displayName || undefined,
        handle: handle || undefined,
        tenant_bootstrap_token: bootstrapToken || undefined,
      });
      setResult({ secretKeyHex: bytesToHex(acc.secretKey), enc: acc.enc });
      try {
        const tn = await api.ops.tenants();
        setTenants(tn.tenants);
      } catch {
        /* ignore tenant reload error */
      }
      toast("success", t("access.onb.bs_created_toast"));
    } catch (e) {
      const msg = e instanceof Error ? e.message : "";
      setError(
        e instanceof CryptoUnavailableError
          ? t("access.onb.bs_err_crypto")
          : /bootstrap disabled/i.test(msg)
            ? t("access.onb.bs_err_disabled")
            : /bootstrap token/i.test(msg)
              ? t("access.onb.bs_err_token")
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

  // P0: once the genesis Secret Key + keyset exist but aren't downloaded yet,
  // Escape / backdrop must NOT close the modal — losing them makes the space's
  // owner permanently unrecoverable. The only exit is downloading, then "Done".
  const locked = result !== null && !downloaded;

  return (
    <Modal onClose={close} width={440} dismissable={!locked}>
      <div style={{ padding: "20px 22px 0" }}>
        <div style={{ fontSize: 16, fontWeight: 800 }}>{t("access.onb.bs_title")}</div>
        <div style={{ fontSize: 12, color: "var(--txt3)", marginTop: 2 }}>
          {result ? t("access.onb.bs_done_step") : t("access.onb.bs_step1")}
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
            <Btn full variant="soft" disabled={!downloaded} onClick={close}>
              {t("access.onb.bs_done_btn")}
            </Btn>
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
              {t("access.onb.bs_intro")}
            </div>

            <Field
              label={t("access.onb.bs_token_label")}
              tag={t("access.onb.bs_token_tag")}
              hint={t("access.onb.bs_token_hint")}
            >
              <TextInput
                type="password"
                value={bootstrapToken}
                onChange={setBootstrapToken}
                placeholder={t("access.onb.bs_token_ph")}
                mono
              />
            </Field>

            <Field
              label={t("access.onb.bs_tier_label")}
              tag={t("access.onb.bs_tier_tag")}
              hint={t("access.onb.bs_tier_hint")}
            >
              <div style={{ display: "flex", gap: 8 }}>
                {(["personal", "org"] as const).map((x) => (
                  <button
                    key={x}
                    onClick={() => setTier(x)}
                    style={{
                      flex: 1,
                      padding: "8px 0",
                      borderRadius: 8,
                      border: tier === x ? "1px solid var(--accentLine)" : "1px solid var(--line)",
                      background: tier === x ? "var(--accentSoft)" : "var(--bg2)",
                      color: tier === x ? "var(--accent)" : "var(--txt2)",
                      fontFamily: "inherit",
                      fontSize: 13,
                      fontWeight: 600,
                      cursor: "pointer",
                    }}
                  >
                    {t(x === "personal" ? "access.onb.bs_tier_personal" : "access.onb.bs_tier_org")}
                  </button>
                ))}
              </div>
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

            <button
              onClick={() => setAdvanced((v) => !v)}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 5,
                background: "none",
                border: "none",
                color: "var(--txt3)",
                fontFamily: "inherit",
                fontSize: 12,
                fontWeight: 600,
                cursor: "pointer",
                padding: "2px 0",
                marginBottom: advanced ? 12 : 14,
              }}
            >
              <Icon name={advanced ? "chevronDown" : "chevronRight"} size={13} />
              {t("access.onb.bs_advanced")}
            </button>
            {advanced ? (
              <Field
                label={t("access.onb.bs_tenantid_label")}
                tag={t("access.onb.bs_tenantid_tag")}
                hint={t("access.onb.bs_tenantid_hint")}
              >
                <div style={{ display: "flex", gap: 8 }}>
                  <TextInput value={tenantId} onChange={setTenantId} mono />
                  <Btn icon="refresh" onClick={() => setTenantId(bytesToB64(randomBytes(16)))} />
                </div>
              </Field>
            ) : null}

            {error ? <InlineError>{error}</InlineError> : null}

            <div style={{ display: "flex", gap: 9 }}>
              <Btn full onClick={close}>
                {t("common.cancel")}
              </Btn>
              <Btn full variant="primary" loading={busy} onClick={create}>
                {t("access.onb.bs_create_btn")}
              </Btn>
            </div>
          </>
        )}
      </div>
    </Modal>
  );
}
