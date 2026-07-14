import { useEffect, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { loginWithEscrow, NotAKeysetFileError, oidcLogin, restoreFromKit } from "../api/auth-service";
import { ApiError } from "../api/errors";
import type { InstanceInfo } from "../api/types";
import { CryptoUnavailableError, getCrypto } from "../crypto/provider";
import { usePrefs } from "../store/prefs";
import { MONO } from "../theme/tokens";
import { Icon, type IconName } from "../ui/icons";
import { Btn, Field, InlineError, Segmented, TextInput } from "../ui/primitives";
import { ClaimModal } from "./ClaimModal";

function Brand() {
  const { t } = useTranslation();
  return (
    <div style={{ padding: "24px 24px 0", display: "flex", gap: 13, alignItems: "center" }}>
      <span style={{ position: "relative", width: 34, height: 34 }}>
        <span
          style={{
            position: "absolute",
            inset: 0,
            borderRadius: 9,
            background: "linear-gradient(140deg, var(--accent), var(--purple))",
            boxShadow: "0 6px 18px -6px var(--accent)",
          }}
        />
        <span
          style={{
            position: "absolute",
            inset: 0,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            color: "#fff",
            fontFamily: MONO,
            fontWeight: 700,
            fontSize: 15,
          }}
        >
          ›_
        </span>
      </span>
      <div>
        <div style={{ fontSize: 17, fontWeight: 800 }}>
          Uni<span style={{ color: "var(--accent)" }}>SSH</span> Admin
        </div>
        <div style={{ fontSize: 12, color: "var(--txt3)" }}>{t("access.onb.server_subtitle")}</div>
      </div>
    </div>
  );
}

function Card({ children }: { children: ReactNode }) {
  return (
    <div
      style={{
        height: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "var(--desk)",
        padding: 24,
      }}
    >
      <div
        style={{
          width: 440,
          maxWidth: "100%",
          background: "var(--bg1)",
          border: "1px solid var(--line)",
          borderRadius: 16,
          boxShadow: "var(--shadow)",
          overflow: "hidden",
        }}
      >
        {children}
      </div>
    </div>
  );
}

export function Login() {
  const { t } = useTranslation();
  const instanceUrl = usePrefs((s) => s.instanceUrl);
  const setInstanceUrl = usePrefs((s) => s.setInstanceUrl);

  const [url, setUrl] = useState(instanceUrl);
  const [info, setInfo] = useState<InstanceInfo | null>(null);
  const [probing, setProbing] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Probe against a given base URL (empty → same origin as the panel).
  const probe = async (raw: string) => {
    setProbing(true);
    setError(null);
    const clean = raw.trim();
    setInstanceUrl(clean);
    try {
      const r = await api.instance();
      setInfo(r);
    } catch (e) {
      setInfo(null);
      setError(e instanceof ApiError ? e.message : t("access.onb.server_err_network"));
    } finally {
      setProbing(false);
    }
  };

  // Auto-probe on first mount so a same-origin / remembered instance skips the URL
  // step and goes straight to sign-in (or claim).
  useEffect(() => {
    void probe(instanceUrl);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ── Instance discovered ──────────────────────────────────────
  if (info) {
    const back = () => {
      setInfo(null);
      setError(null);
    };
    if (!info.claimed) {
      return (
        <>
          <Card>
            <Brand />
            <div style={{ padding: "18px 24px 24px" }}>
              <InstanceSummary info={info} onChange={back} />
              <div style={{ fontSize: 12.5, color: "var(--txt2)", lineHeight: 1.55, margin: "14px 0 16px" }}>
                {t("access.onb.disc_unclaimed")}
              </div>
            </div>
          </Card>
          <ClaimModal instanceUrl={url.trim()} onClose={back} />
        </>
      );
    }
    return (
      <Card>
        <Brand />
        <div style={{ padding: "18px 24px 24px" }}>
          <InstanceSummary info={info} onChange={back} />
          <div style={{ height: 14 }} />
          <LoginForm instanceUrl={url.trim()} info={info} />
        </div>
      </Card>
    );
  }

  // ── Step 0: server address ───────────────────────────────────
  return (
    <Card>
      <Brand />
      <div style={{ padding: "20px 24px 24px" }}>
        <div style={{ fontSize: 12.5, color: "var(--txt2)", lineHeight: 1.55, marginBottom: 16 }}>
          {t("access.onb.disc_intro")}
        </div>
        <Field
          label={t("access.onb.server_url_label")}
          tag={t("access.onb.server_url_tag")}
          hint={t("access.onb.server_url_hint")}
        >
          <TextInput value={url} onChange={setUrl} placeholder="https://unissh.example:8443" mono />
        </Field>
        {error ? <InlineError>{error}</InlineError> : null}
        <Btn variant="primary" full icon="enter" loading={probing} onClick={() => void probe(url)}>
          {t("access.onb.disc_continue")}
        </Btn>
      </div>
    </Card>
  );
}

function InstanceSummary({ info, onChange }: { info: InstanceInfo; onChange: () => void }) {
  const { t } = useTranslation();
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 11,
        padding: "11px 13px",
        borderRadius: 12,
        border: "1px solid var(--line)",
        background: "var(--bg2)",
      }}
    >
      <Icon name={info.claimed ? "check" : "database"} size={16} color="var(--txt3)" />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 13, fontWeight: 700, overflow: "hidden", textOverflow: "ellipsis" }}>
          {info.name || t("access.onb.disc_untitled")}
        </div>
        <div style={{ fontSize: 11, color: "var(--txt3)", fontFamily: MONO }}>v{info.version}</div>
      </div>
      <button
        type="button"
        onClick={onChange}
        style={{
          background: "none",
          border: "none",
          color: "var(--accent)",
          fontFamily: "inherit",
          fontSize: 12,
          fontWeight: 600,
          cursor: "pointer",
          padding: "4px 6px",
        }}
      >
        {t("access.onb.disc_change")}
      </button>
    </div>
  );
}

// The claimed-instance sign-in menu. A small segmented control chooses the way in:
// "Identity" (escrow) and "Emergency Kit" (offline file restore) are always offered;
// "SSO" appears only when the instance advertises an OIDC provider (`info.oidc`) —
// never a dead entry. There is no "Reconnect" concept in the panel.
type SignInMode = "identity" | "kit" | "sso";

function LoginForm({ instanceUrl, info }: { instanceUrl: string; info: InstanceInfo }) {
  const { t } = useTranslation();
  const ssoEnabled = !!info.oidc;
  const [mode, setMode] = useState<SignInMode>("identity");

  const tabs: { value: SignInMode; label: string; icon: IconName }[] = [
    { value: "identity", label: t("access.onb.signin_tab_identity"), icon: "fingerprint" },
    { value: "kit", label: t("access.onb.signin_tab_kit"), icon: "file" },
  ];
  if (ssoEnabled) {
    tabs.push({ value: "sso", label: t("access.onb.signin_tab_sso"), icon: "enter" });
  }

  return (
    <>
      <Segmented options={tabs} value={mode} onChange={setMode} />
      <div style={{ height: 16 }} />
      {mode === "identity" ? <IdentitySignIn instanceUrl={instanceUrl} /> : null}
      {mode === "kit" ? <RestoreSignIn instanceUrl={instanceUrl} /> : null}
      {mode === "sso" ? <SsoSignIn instanceUrl={instanceUrl} /> : null}
    </>
  );
}

// ── Crypto-unavailable notice (shared by the keyset paths) ─────
function CryptoWarn() {
  const { t } = useTranslation();
  return (
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
  );
}

// ── Sign in with your identity (escrow: handle + password + Secret Key) ─────
function IdentitySignIn({ instanceUrl }: { instanceUrl: string }) {
  const { t } = useTranslation();
  const [handle, setHandle] = useState("");
  const [password, setPassword] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const cryptoReady = getCrypto().available;

  const submit = async () => {
    if (!handle.trim()) return setError(t("access.onb.login_err_no_handle"));
    if (!secretKey.trim()) return setError(t("access.onb.login_err_no_secret"));
    setError(null);
    setBusy(true);
    try {
      await loginWithEscrow({
        instanceUrl,
        handle,
        password: password || null,
        secretKeyHex: secretKey,
      });
      // Success flips the app into the Shell (session committed in the store).
    } catch (e) {
      if (e instanceof CryptoUnavailableError) {
        setError(t("access.onb.bs_err_crypto"));
      } else if (e instanceof ApiError) {
        setError(e.status === 403 ? t("access.onb.login_err_bad") : e.message);
      } else {
        setError(e instanceof Error ? e.message : t("access.onb.login_err_generic"));
      }
      setBusy(false);
    }
  };

  return (
    <>
      <div style={{ fontSize: 12.5, color: "var(--txt2)", lineHeight: 1.55, marginBottom: 14 }}>
        {t("access.onb.login_intro")}
      </div>
      <Field
        label={t("access.onb.login_handle_label")}
        tag={t("access.onb.login_handle_tag")}
        hint={t("access.onb.login_handle_hint")}
      >
        <TextInput
          value={handle}
          onChange={setHandle}
          placeholder={t("access.onb.login_handle_ph")}
          mono
        />
      </Field>
      <Field
        label={t("access.onb.ks_pwd_label")}
        tag={t("access.onb.ks_pwd_tag")}
        hint={t("access.onb.ks_pwd_hint")}
      >
        <TextInput type="password" value={password} onChange={setPassword} placeholder="••••••••" mono />
      </Field>
      <Field
        label={t("access.onb.ks_secretkey_label")}
        tag={t("access.onb.ks_secretkey_tag")}
        hint={t("access.onb.ks_secretkey_hint")}
      >
        <TextInput value={secretKey} onChange={setSecretKey} placeholder="hex" mono />
      </Field>

      {!cryptoReady ? <CryptoWarn /> : null}
      {error ? <InlineError>{error}</InlineError> : null}

      <Btn variant="primary" full icon="enter" loading={busy} onClick={submit}>
        {t("access.onb.login_btn")}
      </Btn>
    </>
  );
}

// ── Restore from Emergency Kit (offline: identity.kit file + password + Secret Key) ──
function RestoreSignIn({ instanceUrl }: { instanceUrl: string }) {
  const { t } = useTranslation();
  const [file, setFile] = useState<File | null>(null);
  const [password, setPassword] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const cryptoReady = getCrypto().available;

  const submit = async () => {
    if (!file) return setError(t("access.onb.restore_err_no_file"));
    if (!secretKey.trim()) return setError(t("access.onb.login_err_no_secret"));
    setError(null);
    setBusy(true);
    try {
      // Read the recovery file as raw bytes and unlock it locally — the same tail as
      // escrow sign-in, only the keyset blob comes from the FILE, not escrowFetch.
      const fileBytes = new Uint8Array(await file.arrayBuffer());
      await restoreFromKit({
        instanceUrl,
        fileBytes,
        password: password || null,
        secretKeyHex: secretKey,
      });
      // Success flips the app into the Shell (session committed in the store).
    } catch (e) {
      if (e instanceof CryptoUnavailableError) {
        setError(t("access.onb.bs_err_crypto"));
      } else if (e instanceof NotAKeysetFileError) {
        setError(t("access.onb.restore_err_notkit"));
      } else if (e instanceof ApiError) {
        // A failure only after the file unlocked (self-enroll / challenge) — surface it.
        setError(e.message);
      } else {
        // A local unlock failure: wrong password / Secret Key, or a corrupt file.
        setError(t("access.onb.restore_err_bad"));
      }
      setBusy(false);
    }
  };

  return (
    <>
      <div style={{ fontSize: 12.5, color: "var(--txt2)", lineHeight: 1.55, marginBottom: 14 }}>
        {t("access.onb.restore_intro")}
      </div>
      <Field
        label={t("access.onb.restore_file_label")}
        tag={t("access.onb.restore_file_tag")}
        hint={file ? file.name : t("access.onb.restore_file_hint")}
      >
        <TextInput type="file" accept=".kit,.keyset" onFile={setFile} />
      </Field>
      <Field
        label={t("access.onb.ks_pwd_label")}
        tag={t("access.onb.ks_pwd_tag")}
        hint={t("access.onb.ks_pwd_hint")}
      >
        <TextInput type="password" value={password} onChange={setPassword} placeholder="••••••••" mono />
      </Field>
      <Field
        label={t("access.onb.ks_secretkey_label")}
        tag={t("access.onb.ks_secretkey_tag")}
        hint={t("access.onb.ks_secretkey_hint")}
      >
        <TextInput value={secretKey} onChange={setSecretKey} placeholder="hex" mono />
      </Field>

      {!cryptoReady ? <CryptoWarn /> : null}
      {error ? <InlineError>{error}</InlineError> : null}

      <Btn variant="primary" full icon="enter" loading={busy} onClick={submit}>
        {t("access.onb.restore_btn")}
      </Btn>
    </>
  );
}

// ── Sign in with SSO (OIDC redirect) — shown only when info.oidc is set ─────
function SsoSignIn({ instanceUrl }: { instanceUrl: string }) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const cryptoReady = getCrypto().available;

  // SSO: redirect the browser to the IdP. On the callback load, App resumes the flow.
  const startSso = async () => {
    if (!cryptoReady) return setError(t("access.onb.bs_err_crypto"));
    setError(null);
    setBusy(true);
    try {
      await oidcLogin(instanceUrl); // navigates away on success
    } catch (e) {
      setError(e instanceof Error ? e.message : t("access.onb.sso_err"));
      setBusy(false);
    }
  };

  return (
    <>
      <div style={{ fontSize: 12.5, color: "var(--txt2)", lineHeight: 1.55, marginBottom: 14 }}>
        {t("access.onb.sso_hint")}
      </div>
      {!cryptoReady ? <CryptoWarn /> : null}
      {error ? <InlineError>{error}</InlineError> : null}
      <Btn variant="primary" full icon="enter" loading={busy} onClick={startSso}>
        {t("access.onb.sso_cta")}
      </Btn>
    </>
  );
}
