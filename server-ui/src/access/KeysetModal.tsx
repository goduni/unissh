import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { unlockWithKeyset } from "../api/auth-service";
import { ApiError } from "../api/errors";
import type { AccountMatch } from "../api/types";
import { CryptoUnavailableError, getCrypto } from "../crypto/provider";
import { useTenant } from "../store/tenant";
import { useUi } from "../store/ui";
import { hexToBytes, truncId } from "../util/bytes";
import { fmtEpoch } from "../util/format";
import { Icon } from "../ui/icons";
import { Btn, Field, InlineError, StateBadge, Tag, TextInput } from "../ui/primitives";
import { Modal } from "../ui/overlays";
import { MONO } from "../theme/tokens";

export function KeysetModal() {
  const { t } = useTranslation();
  const open = useUi((s) => s.keysetModalOpen);
  const close = useUi((s) => s.closeKeyset);
  const toast = useUi((s) => s.toast);
  const setActive = useTenant((s) => s.setActive);

  const [accountId, setAccountId] = useState("");
  const [deviceId, setDeviceId] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [fileName, setFileName] = useState("");
  const [password, setPassword] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [handle, setHandle] = useState("");
  const [searching, setSearching] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);
  const [matches, setMatches] = useState<AccountMatch[] | null>(null);

  if (!open) return null;
  const cryptoReady = getCrypto().available;

  const search = async () => {
    setSearchError(null);
    setMatches(null);
    const h = handle.trim();
    if (!h) return setSearchError(t("access.onb.ks_search_empty"));
    setSearching(true);
    try {
      const r = await api.ops.account(h);
      setMatches(r.matches);
    } catch (e) {
      if (e instanceof ApiError) {
        setSearchError(e.message);
      } else {
        setSearchError(e instanceof Error ? e.message : t("access.onb.ks_search_err"));
      }
    } finally {
      setSearching(false);
    }
  };

  const pick = (m: AccountMatch, dev: string) => {
    setAccountId(m.account_id);
    setDeviceId(dev);
    // The matched account may live in another space; the challenge/verify carries
    // the active-tenant header, so switch context to it or the unlock 401s.
    setActive(m.tenant_id);
  };

  const submit = async () => {
    setError(null);
    if (!file) return setError(t("access.onb.ks_err_no_file"));
    if (!accountId.trim() || !deviceId.trim()) return setError(t("access.onb.ks_err_no_ids"));
    setBusy(true);
    try {
      const enc = new Uint8Array(await file.arrayBuffer());
      await unlockWithKeyset({
        encKeyset: enc,
        password: password || null,
        secretKey: secretKey ? hexToBytes(secretKey) : new Uint8Array(0),
        accountId: accountId.trim(),
        deviceId: deviceId.trim(),
      });
      toast("success", t("access.onb.ks_unlocked_toast"));
      close();
    } catch (e) {
      if (e instanceof CryptoUnavailableError) {
        setError(t("access.onb.bs_err_crypto"));
      } else if (e instanceof ApiError) {
        setError(e.message);
      } else {
        setError(e instanceof Error ? e.message : t("access.onb.ks_err_generic"));
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal onClose={close} width={440}>
      <div style={{ padding: "20px 22px 0", display: "flex", gap: 13, alignItems: "center" }}>
        <span
          style={{
            width: 42,
            height: 42,
            borderRadius: 12,
            background: "color-mix(in srgb, var(--amber) 16%, transparent)",
            border: "1px solid color-mix(in srgb, var(--amber) 38%, transparent)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            color: "var(--amber)",
          }}
        >
          <Icon name="lock" size={20} />
        </span>
        <div>
          <div style={{ fontSize: 16, fontWeight: 800 }}>{t("access.onb.ks_title")}</div>
          <div style={{ fontSize: 12, color: "var(--txt3)" }}>{t("access.onb.ks_sub")}</div>
        </div>
      </div>

      <div style={{ padding: "18px 22px" }}>
        <div style={{ fontSize: 12.5, color: "var(--txt2)", lineHeight: 1.55, marginBottom: 16 }}>
          {t("access.onb.ks_note")}
        </div>

        <Field
          label={t("access.onb.ks_search_label")}
          tag={t("access.onb.ks_search_tag")}
          hint={t("access.onb.ks_search_hint")}
        >
          <div style={{ display: "flex", gap: 8 }}>
            <div style={{ flex: 1 }}>
              <TextInput
                value={handle}
                onChange={setHandle}
                placeholder={t("access.onb.ks_search_ph")}
                mono
              />
            </div>
            <Btn icon="searchIcon" loading={searching} onClick={search}>
              {t("access.onb.ks_search_btn")}
            </Btn>
          </div>
        </Field>

        {searchError ? <InlineError>{searchError}</InlineError> : null}

        {matches ? (
          matches.length === 0 ? (
            <div
              style={{
                fontSize: 12.5,
                color: "var(--txt3)",
                padding: "10px 12px",
                marginBottom: 14,
                background: "var(--bg2)",
                border: "1px solid var(--line)",
                borderRadius: 10,
              }}
            >
              {t("access.onb.ks_search_none")}
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 10, marginBottom: 16 }}>
              {matches.map((m) => (
                <div
                  key={`${m.tenant_id}/${m.account_id}`}
                  style={{
                    background: "var(--bg2)",
                    border: "1px solid var(--line)",
                    borderRadius: 11,
                    padding: "11px 13px",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                    <span style={{ fontSize: 13, fontWeight: 700 }}>
                      {m.display_name || m.handle || "—"}
                    </span>
                    {m.is_admin ? <Tag tone="amber">admin</Tag> : null}
                    <StateBadge state={m.status} />
                    <span
                      style={{
                        marginLeft: "auto",
                        fontSize: 11,
                        color: "var(--txt3)",
                        fontFamily: MONO,
                      }}
                    >
                      tenant {truncId(m.tenant_id)}
                    </span>
                  </div>
                  <div
                    style={{
                      fontSize: 11,
                      color: "var(--txt3)",
                      fontFamily: MONO,
                      marginTop: 4,
                    }}
                  >
                    {m.handle ?? "—"} · acct {truncId(m.account_id)}
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", gap: 6, marginTop: 9 }}>
                    {m.devices.length === 0 ? (
                      <div style={{ fontSize: 11.5, color: "var(--txt3)" }}>
                        {t("access.onb.ks_no_devices")}
                      </div>
                    ) : (
                      m.devices.map((d) => {
                        const on = accountId === m.account_id && deviceId === d.device_id;
                        return (
                          <button
                            key={d.device_id}
                            type="button"
                            onClick={() => pick(m, d.device_id)}
                            style={{
                              display: "flex",
                              alignItems: "center",
                              gap: 9,
                              padding: "7px 10px",
                              borderRadius: 9,
                              border: on ? "1px solid var(--accentLine)" : "1px solid var(--line)",
                              background: on ? "var(--accentSoft)" : "var(--bg3)",
                              cursor: "pointer",
                              textAlign: "left",
                              fontFamily: "inherit",
                              width: "100%",
                            }}
                          >
                            <Icon
                              name="key"
                              size={14}
                              color={on ? "var(--accent)" : "var(--txt3)"}
                            />
                            <span
                              style={{
                                flex: 1,
                                fontSize: 11.5,
                                fontFamily: MONO,
                                color: on ? "var(--accent)" : "var(--txt2)",
                                overflow: "hidden",
                                textOverflow: "ellipsis",
                                whiteSpace: "nowrap",
                              }}
                            >
                              {truncId(d.device_id, 8, 6)}
                            </span>
                            <StateBadge state={d.status} />
                            <span style={{ fontSize: 10.5, color: "var(--txt3)" }}>
                              {fmtEpoch(d.registered_at)}
                            </span>
                          </button>
                        );
                      })
                    )}
                  </div>
                </div>
              ))}
            </div>
          )
        ) : null}

        <Field label={t("access.onb.ks_accountid_label")} tag={t("access.onb.ks_accountid_tag")}>
          <TextInput value={accountId} onChange={setAccountId} placeholder="base64" mono />
        </Field>
        <Field label={t("access.onb.ks_deviceid_label")} tag={t("access.onb.ks_deviceid_tag")}>
          <TextInput value={deviceId} onChange={setDeviceId} placeholder="base64" mono />
        </Field>

        <Field label={t("access.onb.ks_file_label")} tag={t("access.onb.ks_file_tag")}>
          <label
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              padding: "10px 13px",
              borderRadius: 10,
              background: "var(--bg2)",
              border: "1px dashed var(--line2)",
              color: "var(--txt2)",
              cursor: "pointer",
            }}
          >
            <Icon name="file" size={16} />
            <span style={{ flex: 1, fontSize: 12.5, fontFamily: MONO }}>
              {fileName || t("access.onb.ks_file_ph")}
            </span>
            {file ? <span style={{ fontSize: 11, color: "var(--green)" }}>✓</span> : null}
            <input
              type="file"
              accept=".keyset,.age,application/octet-stream"
              style={{ display: "none" }}
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) {
                  setFile(f);
                  setFileName(f.name);
                }
              }}
            />
          </label>
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
          <Btn full onClick={close}>
            {t("common.cancel")}
          </Btn>
          <Btn full variant="primary" icon="unlock" loading={busy} onClick={submit}>
            {t("access.onb.ks_unlock_btn")}
          </Btn>
        </div>
      </div>
    </Modal>
  );
}
