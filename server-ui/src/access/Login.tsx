import "./access.css";
import { useEffect, useId, useState, type FormEvent, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { loginWithEscrow, NotAKeysetFileError, oidcLogin, restoreFromKit } from "../api/auth-service";
import { ApiError } from "../api/errors";
import type { InstanceInfo } from "../api/types";
import { CryptoUnavailableError } from "../crypto/provider";
import { useCryptoReady } from "../crypto/wasm-provider";
import { Wordmark } from "../shell/Mark";
import { usePrefs } from "../store/prefs";
import { Icon } from "../ui/icons";
import { Btn, Field, InlineError, TextInput } from "../ui/primitives";
import { ClaimModal } from "./ClaimModal";
import { CautionLine, LineTabs, panelId, SecretInput, tabId, ThemeToggle } from "./kit";
import { PromptLines } from "./PromptLines";

// Field's own bottom margin is dropped: the form's 16 px gap spaces the fields.
const FIELD = { marginBottom: 0 };

// The way in: the one split screen. A rail-coloured panel with the drawn device and the
// wordmark (5 parts) beside the form (4 parts, at most 360 px); on phones the panel is a
// band of at least 160 px above the form.
function Frame({ children }: { children: ReactNode }) {
  const { t } = useTranslation();
  return (
    <div className="acc-login">
      <header className="acc-panel">
        <PromptLines />
        <span style={{ position: "relative" }}>
          <Wordmark />
        </span>
        <p className="acc-panel-note">{t("access.onb.server_subtitle")}</p>
      </header>
      <div className="acc-side">
        <div className="acc-topbar">
          <ThemeToggle />
        </div>
        <main className="acc-main">
          <div className="acc-column">{children}</div>
        </main>
      </div>
    </div>
  );
}

/** The headline of the login page: 24 / 600, its only use. */
function Headline({ children }: { children: ReactNode }) {
  return (
    <h1
      style={{
        margin: 0,
        fontSize: 24,
        fontWeight: 600,
        lineHeight: 1.333,
        letterSpacing: "-0.025em",
        textWrap: "balance",
        color: "var(--foreground)",
      }}
    >
      {children}
    </h1>
  );
}

function Copy({ children }: { children: ReactNode }) {
  return <p className="acc-copy">{children}</p>;
}

export function Login() {
  const { t } = useTranslation();
  const instanceUrl = usePrefs((s) => s.instanceUrl);
  const setInstanceUrl = usePrefs((s) => s.setInstanceUrl);
  const urlId = useId();

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
          <Frame>
            <Headline>{t("access.onb.claim_title")}</Headline>
            <InstanceSummary info={info} onChange={back} />
            <Copy>{t("access.onb.disc_unclaimed")}</Copy>
          </Frame>
          <ClaimModal instanceUrl={url.trim()} onClose={back} />
        </>
      );
    }
    return (
      <Frame>
        <Headline>{t("access.onb.headline_signin")}</Headline>
        <InstanceSummary info={info} onChange={back} />
        <LoginForm instanceUrl={url.trim()} info={info} />
      </Frame>
    );
  }

  // ── Step 0: server address ───────────────────────────────────
  const submitUrl = (e: FormEvent) => {
    e.preventDefault();
    if (probing) return;
    void probe(url);
  };
  return (
    <Frame>
      <div className="acc-stack">
        <Headline>{t("access.onb.headline_connect")}</Headline>
        <Copy>{t("access.onb.disc_intro")}</Copy>
      </div>
      <form className="acc-form" onSubmit={submitUrl} noValidate>
        <Field
          label={t("access.onb.server_url_label")}
          tag={t("access.onb.server_url_tag")}
          hint={t("access.onb.server_url_hint")}
          htmlFor={urlId}
          style={FIELD}
        >
          <TextInput
            id={urlId}
            value={url}
            onChange={setUrl}
            placeholder="https://unissh.example:8443"
            mono
            autoFocus
          />
        </Field>
        {error ? <InlineError>{error}</InlineError> : null}
        <Btn variant="primary" type="submit" full loading={probing}>
          {t("access.onb.disc_continue")}
        </Btn>
      </form>
    </Frame>
  );
}

function InstanceSummary({ info, onChange }: { info: InstanceInfo; onChange: () => void }) {
  const { t } = useTranslation();
  const nameId = useId();
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 12,
        minHeight: 48,
        padding: "8px 12px",
        borderRadius: "var(--radius-md)",
        // Solid: a claimed instance is there to sign in to; dashed: not set up yet.
        border: `1px ${info.claimed ? "solid" : "dashed"} var(--border)`,
        background: info.claimed ? "var(--card)" : "transparent",
      }}
    >
      <Icon name={info.claimed ? "check" : "database"} size={16} color="var(--muted-foreground)" />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div
          id={nameId}
          style={{
            fontSize: 13,
            fontWeight: 600,
            lineHeight: "18px",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {info.name || t("access.onb.disc_untitled")}
        </div>
        <div
          style={{
            fontFamily: "var(--font-mono)",
            fontSize: 12,
            lineHeight: "16px",
            color: "var(--muted-foreground)",
          }}
        >
          v{info.version}
        </div>
      </div>
      <button type="button" className="u-link" aria-describedby={nameId} onClick={onChange}>
        {t("access.onb.disc_change")}
      </button>
    </div>
  );
}

// The claimed-instance sign-in menu. Line tabs choose the way in (each shows its own
// panel): "Identity" (escrow) and "Emergency Kit" (offline file restore) are always
// offered; "SSO" appears only when the instance advertises an OIDC provider
// (`info.oidc`) — never a dead entry. There is no "Reconnect" concept in the panel.
type SignInMode = "identity" | "kit" | "sso";

function LoginForm({ instanceUrl, info }: { instanceUrl: string; info: InstanceInfo }) {
  const { t } = useTranslation();
  const ssoEnabled = !!info.oidc;
  const [mode, setMode] = useState<SignInMode>("identity");
  // The first field takes the focus on arrival only; after a switch it stays on the tab.
  const [switched, setSwitched] = useState(false);
  const base = useId();

  const tabs: { value: SignInMode; label: string }[] = [
    { value: "identity", label: t("access.onb.signin_tab_identity") },
    { value: "kit", label: t("access.onb.signin_tab_kit") },
  ];
  if (ssoEnabled) {
    tabs.push({ value: "sso", label: t("access.onb.signin_tab_sso") });
  }

  const choose = (m: SignInMode) => {
    setSwitched(true);
    setMode(m);
  };

  return (
    <>
      <LineTabs
        tabs={tabs}
        value={mode}
        onChange={choose}
        idBase={base}
        ariaLabel={t("access.onb.signin_method")}
      />
      <div role="tabpanel" id={panelId(base, mode)} aria-labelledby={tabId(base, mode)}>
        {mode === "identity" ? <IdentitySignIn instanceUrl={instanceUrl} autoFocus={!switched} /> : null}
        {mode === "kit" ? <RestoreSignIn instanceUrl={instanceUrl} /> : null}
        {mode === "sso" ? <SsoSignIn instanceUrl={instanceUrl} /> : null}
      </div>
    </>
  );
}

// ── Sign in with your identity (escrow: handle + password + Secret Key) ─────
function IdentitySignIn({ instanceUrl, autoFocus }: { instanceUrl: string; autoFocus: boolean }) {
  const { t } = useTranslation();
  const handleId = useId();
  const passwordId = useId();
  const secretId = useId();
  const [handle, setHandle] = useState("");
  const [password, setPassword] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Which field a refusal is about (said under it); null: the server's answer.
  const [invalid, setInvalid] = useState<"handle" | "secret" | null>(null);
  const cryptoReady = useCryptoReady();

  const submit = async (e?: FormEvent) => {
    e?.preventDefault();
    if (busy) return;
    if (!handle.trim()) {
      setInvalid("handle");
      return setError(t("access.onb.login_err_no_handle"));
    }
    if (!secretKey.trim()) {
      setInvalid("secret");
      return setError(t("access.onb.login_err_no_secret"));
    }
    setInvalid(null);
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
        // Refused credentials: an empty password field is a likely cause, so say so.
        setError(
          e.status !== 403
            ? e.message
            : t(password ? "access.onb.login_err_bad" : "access.onb.login_err_bad_nopwd"),
        );
      } else {
        setError(e instanceof Error ? e.message : t("access.onb.login_err_generic"));
      }
      setBusy(false);
    }
  };

  // Editing the field a refusal named clears that refusal.
  const clearIf = (field: "handle" | "secret") => {
    if (invalid === field) {
      setInvalid(null);
      setError(null);
    }
  };

  return (
    <form className="acc-form" onSubmit={submit} noValidate>
      <Copy>{t("access.onb.login_intro")}</Copy>
      <Field
        label={t("access.onb.login_handle_label")}
        tag={t("access.onb.login_handle_tag")}
        hint={t("access.onb.login_handle_hint")}
        error={invalid === "handle" ? error : null}
        htmlFor={handleId}
        style={FIELD}
      >
        <TextInput
          id={handleId}
          value={handle}
          onChange={(v) => {
            setHandle(v);
            clearIf("handle");
          }}
          placeholder={t("access.onb.login_handle_ph")}
          mono
          invalid={invalid === "handle"}
          autoComplete="username"
          autoFocus={autoFocus}
        />
      </Field>
      <Field
        label={t("access.onb.ks_pwd_label")}
        tag={t("access.onb.ks_pwd_tag")}
        hint={t("access.onb.ks_pwd_hint")}
        htmlFor={passwordId}
        style={FIELD}
      >
        <TextInput
          id={passwordId}
          type="password"
          value={password}
          onChange={setPassword}
          placeholder={t("access.onb.ks_pwd_ph")}
          mono
          autoComplete="current-password"
        />
      </Field>
      <Field
        label={t("access.onb.ks_secretkey_label")}
        tag={t("access.onb.ks_secretkey_tag")}
        hint={t("access.onb.ks_secretkey_hint")}
        error={invalid === "secret" ? error : null}
        htmlFor={secretId}
        style={FIELD}
      >
        <SecretInput
          id={secretId}
          value={secretKey}
          onChange={(v) => {
            setSecretKey(v);
            clearIf("secret");
          }}
          placeholder="hex"
          invalid={invalid === "secret"}
        />
      </Field>

      {!cryptoReady ? <CautionLine>{t("access.onb.ks_crypto_warn")}</CautionLine> : null}
      {error && !invalid ? <InlineError>{error}</InlineError> : null}

      <Btn variant="primary" type="submit" full loading={busy}>
        {t("access.onb.login_btn")}
      </Btn>
    </form>
  );
}

// ── Restore from Emergency Kit (offline: identity.kit file + password + Secret Key) ──
function RestoreSignIn({ instanceUrl }: { instanceUrl: string }) {
  const { t } = useTranslation();
  const fileId = useId();
  const passwordId = useId();
  const secretId = useId();
  const [file, setFile] = useState<File | null>(null);
  const [password, setPassword] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Which field a refusal is about (said under it); null: the unlock's answer.
  const [invalid, setInvalid] = useState<"file" | "secret" | null>(null);
  const cryptoReady = useCryptoReady();

  const submit = async (e?: FormEvent) => {
    e?.preventDefault();
    if (busy) return;
    if (!file) {
      setInvalid("file");
      return setError(t("access.onb.restore_err_no_file"));
    }
    if (!secretKey.trim()) {
      setInvalid("secret");
      return setError(t("access.onb.login_err_no_secret"));
    }
    setInvalid(null);
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

  const clearIf = (field: "file" | "secret") => {
    if (invalid === field) {
      setInvalid(null);
      setError(null);
    }
  };

  return (
    <form className="acc-form" onSubmit={submit} noValidate>
      <Copy>{t("access.onb.restore_intro")}</Copy>
      <Field
        label={t("access.onb.restore_file_label")}
        tag={t("access.onb.restore_file_tag")}
        tagMono
        hint={
          file ? (
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--foreground)" }}>
              {file.name}
            </span>
          ) : (
            t("access.onb.restore_file_hint")
          )
        }
        error={invalid === "file" ? error : null}
        htmlFor={fileId}
        style={FIELD}
      >
        <TextInput
          id={fileId}
          type="file"
          accept=".kit,.keyset"
          invalid={invalid === "file"}
          onFile={(picked) => {
            setFile(picked);
            clearIf("file");
          }}
        />
      </Field>
      <Field
        label={t("access.onb.ks_pwd_label")}
        tag={t("access.onb.ks_pwd_tag")}
        hint={t("access.onb.ks_pwd_hint")}
        htmlFor={passwordId}
        style={FIELD}
      >
        <TextInput
          id={passwordId}
          type="password"
          value={password}
          onChange={setPassword}
          placeholder={t("access.onb.ks_pwd_ph")}
          mono
          autoComplete="current-password"
        />
      </Field>
      <Field
        label={t("access.onb.ks_secretkey_label")}
        tag={t("access.onb.ks_secretkey_tag")}
        hint={t("access.onb.ks_secretkey_hint")}
        error={invalid === "secret" ? error : null}
        htmlFor={secretId}
        style={FIELD}
      >
        <SecretInput
          id={secretId}
          value={secretKey}
          onChange={(v) => {
            setSecretKey(v);
            clearIf("secret");
          }}
          placeholder="hex"
          invalid={invalid === "secret"}
        />
      </Field>

      {!cryptoReady ? <CautionLine>{t("access.onb.ks_crypto_warn")}</CautionLine> : null}
      {error && !invalid ? <InlineError>{error}</InlineError> : null}

      <Btn variant="primary" type="submit" full loading={busy}>
        {t("access.onb.restore_btn")}
      </Btn>
    </form>
  );
}

// ── Sign in with SSO (OIDC redirect) — shown only when info.oidc is set ─────
function SsoSignIn({ instanceUrl }: { instanceUrl: string }) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const cryptoReady = useCryptoReady();

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
    <div className="acc-form">
      <Copy>{t("access.onb.sso_hint")}</Copy>
      {!cryptoReady ? <CautionLine>{t("access.onb.ks_crypto_warn")}</CautionLine> : null}
      {error ? <InlineError>{error}</InlineError> : null}
      <Btn variant="primary" full loading={busy} onClick={startSso}>
        {t("access.onb.sso_cta")}
      </Btn>
    </div>
  );
}
