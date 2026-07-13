import { useTranslation } from "react-i18next";
import { useSession } from "../store/session";
import { useUi } from "../store/ui";
import { useTheme } from "../theme/ThemeProvider";
import { usePrefs } from "../store/prefs";
import { Icon } from "../ui/icons";
import { MONO } from "../theme/tokens";

export function Titlebar() {
  const { t } = useTranslation();
  const { effMode } = useTheme();
  const toggleMode = usePrefs((s) => s.toggleMode);

  const serverTrusted = useSession((s) => s.bearer != null);
  const keysetUnlocked = useSession((s) => s.keysetUnlocked);
  const adminLabel = useSession((s) => s.adminLabel);

  const openKeyset = useUi((s) => s.openKeyset);
  const togglePanel = useUi((s) => s.togglePanel);

  return (
    <div
      style={{
        height: 46,
        flexShrink: 0,
        display: "flex",
        alignItems: "center",
        padding: "0 14px",
        gap: 14,
        borderBottom: "1px solid var(--line)",
        background: "var(--bg1)",
      }}
    >
      <div style={{ display: "inline-flex", alignItems: "center", gap: 9 }}>
        <span style={{ position: "relative", width: 22, height: 22, flexShrink: 0 }}>
          <span
            style={{
              position: "absolute",
              inset: 0,
              borderRadius: 6,
              background: "linear-gradient(140deg, var(--accent), var(--purple))",
              boxShadow: "0 4px 14px -4px var(--accent)",
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
              fontSize: 11,
            }}
          >
            ›_
          </span>
        </span>
        <span style={{ fontWeight: 700, fontSize: 16, letterSpacing: -0.3 }}>
          Uni<span style={{ color: "var(--accent)" }}>SSH</span>
        </span>
        <span
          style={{
            fontSize: 11,
            fontWeight: 700,
            letterSpacing: 0.5,
            textTransform: "uppercase",
            color: "var(--txt3)",
            background: "var(--bg3)",
            border: "1px solid var(--line)",
            borderRadius: 5,
            padding: "2px 6px",
          }}
        >
          Admin
        </span>
      </div>

      <div style={{ flex: 1 }} />

      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        {/* Ops badge */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 7,
            height: 30,
            padding: "0 11px",
            borderRadius: 8,
            background: "var(--bg2)",
            border: "1px solid var(--line)",
          }}
        >
          <span
            style={{
              width: 7,
              height: 7,
              borderRadius: "50%",
              background: serverTrusted ? "var(--green)" : "var(--txt3)",
              boxShadow: serverTrusted
                ? "0 0 0 3px color-mix(in srgb, var(--green) 20%, transparent), 0 0 7px var(--green)"
                : undefined,
            }}
          />
          <span style={{ fontSize: 12, fontWeight: 600, color: "var(--txt2)" }}>{t("access.ops")}</span>
        </div>

        {/* Keyset badge */}
        <div
          onClick={keysetUnlocked ? undefined : openKeyset}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 7,
            height: 30,
            padding: "0 11px",
            borderRadius: 8,
            background: keysetUnlocked
              ? "color-mix(in srgb, var(--green) 12%, transparent)"
              : "color-mix(in srgb, var(--amber) 12%, transparent)",
            border: keysetUnlocked
              ? "1px solid color-mix(in srgb, var(--green) 34%, transparent)"
              : "1px solid color-mix(in srgb, var(--amber) 34%, transparent)",
            color: keysetUnlocked ? "var(--green)" : "var(--amber)",
            cursor: keysetUnlocked ? "default" : "pointer",
          }}
        >
          <Icon name={keysetUnlocked ? "unlock" : "lock"} size={13} />
          <span style={{ fontSize: 12, fontWeight: 600 }}>
            {keysetUnlocked ? `${t("access.keyset")} · ${adminLabel ?? ""}` : t("access.keysetLocked")}
          </span>
        </div>

        <button
          onClick={toggleMode}
          title={t("settings.theme")}
          style={iconBtnStyle}
        >
          <Icon name={effMode === "dark" ? "sun" : "moon"} size={15} />
        </button>
        <button onClick={togglePanel} title={t("settings.title")} style={iconBtnStyle}>
          <Icon name="sliders" size={15} />
        </button>
        <span
          style={{
            width: 30,
            height: 30,
            borderRadius: 8,
            background: "linear-gradient(140deg, var(--accent), var(--purple))",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            color: "#fff",
            fontWeight: 700,
            fontSize: 12,
          }}
        >
          OP
        </span>
      </div>
    </div>
  );
}

const iconBtnStyle: React.CSSProperties = {
  width: 30,
  height: 30,
  borderRadius: 8,
  border: "1px solid var(--line)",
  background: "var(--bg2)",
  color: "var(--txt2)",
  cursor: "pointer",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
};
