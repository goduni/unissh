import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { ApiError } from "../api/errors";
import { usePrefs } from "../store/prefs";
import { useSession } from "../store/session";
import { useTenant } from "../store/tenant";
import { useUi } from "../store/ui";
import { Icon } from "../ui/icons";
import { Btn, Field, TextInput } from "../ui/primitives";
import { MONO } from "../theme/tokens";

export function OpsLogin() {
  const { t } = useTranslation();
  const setOpsToken = useSession((s) => s.setOpsToken);
  const clearOps = useSession((s) => s.clearOps);
  const opsNotice = useSession((s) => s.opsNotice);
  const setTenants = useTenant((s) => s.setTenants);
  const instanceUrl = usePrefs((s) => s.instanceUrl);
  const setInstanceUrl = usePrefs((s) => s.setInstanceUrl);
  const openBootstrap = useUi((s) => s.openBootstrap);
  const go = useUi((s) => s.go);

  const [token, setToken] = useState("");
  const [url, setUrl] = useState(instanceUrl);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const connect = async () => {
    if (!token.trim()) return;
    setBusy(true);
    setError(null);
    setInstanceUrl(url.trim());
    setOpsToken(token.trim());
    try {
      const r = await api.ops.tenants();
      setTenants(r.tenants);
      // Fresh server with no tenants → drop the operator straight into
      // first-time setup so they don't have to hunt for the create button.
      if (r.tenants.length === 0) {
        go("tenants");
        openBootstrap();
      }
    } catch (e) {
      clearOps();
      setError(
        e instanceof ApiError
          ? e.code === "forbidden"
            ? t("access.onb.ops_err_forbidden")
            : e.message
          : t("access.onb.ops_err_network"),
      );
    } finally {
      setBusy(false);
    }
  };

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
          width: 420,
          maxWidth: "100%",
          background: "var(--bg1)",
          border: "1px solid var(--line)",
          borderRadius: 16,
          boxShadow: "var(--shadow)",
          overflow: "hidden",
        }}
      >
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
            <div style={{ fontSize: 12, color: "var(--txt3)" }}>
              {t("access.onb.ops_subtitle")}
            </div>
          </div>
        </div>

        <div style={{ padding: "20px 24px 24px" }}>
          <div style={{ fontSize: 12.5, color: "var(--txt2)", lineHeight: 1.55, marginBottom: 16 }}>
            {t("access.onb.ops_intro")}
          </div>

          <Field
            label={t("access.onb.ops_url_label")}
            tag={t("access.onb.ops_url_tag")}
            hint={t("access.onb.ops_url_hint")}
          >
            <TextInput value={url} onChange={setUrl} placeholder="https://unissh.example:8443" mono />
          </Field>
          <Field
            label={t("access.onb.ops_token_label")}
            tag={t("access.onb.ops_token_tag")}
            hint={t("access.onb.ops_token_hint")}
          >
            <TextInput
              type="password"
              value={token}
              onChange={setToken}
              placeholder={t("access.onb.ops_token_ph")}
              mono
            />
          </Field>

          {error || opsNotice ? (
            <div
              style={{
                display: "flex",
                gap: 9,
                alignItems: "center",
                background: "color-mix(in srgb, var(--red) 9%, transparent)",
                border: "1px solid color-mix(in srgb, var(--red) 30%, transparent)",
                borderRadius: 10,
                padding: "10px 12px",
                marginBottom: 14,
                fontSize: 12.5,
                color: "var(--txt2)",
              }}
            >
              <Icon name="alert" size={15} color="var(--red)" />
              {error || opsNotice}
            </div>
          ) : null}

          <Btn variant="primary" full icon="enter" loading={busy} onClick={connect}>
            {t("access.onb.ops_connect_btn")}
          </Btn>
        </div>
      </div>
    </div>
  );
}
