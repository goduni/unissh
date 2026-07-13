import { useTranslation } from "react-i18next";
import { lockKeyset } from "../api/auth-service";
import { api } from "../api";
import { useMeta } from "../store/meta";
import { useSession } from "../store/session";
import { useUi } from "../store/ui";
import { useAsync } from "../util/useAsync";
import { truncId } from "../util/bytes";
import { Icon } from "../ui/icons";
import { NAV } from "./nav";
import { MONO } from "../theme/tokens";

export function Sidebar() {
  const { t } = useTranslation();
  const route = useUi((s) => s.route);
  const go = useUi((s) => s.go);

  const keysetUnlocked = useSession((s) => s.keysetUnlocked);
  const adminLabel = useSession((s) => s.adminLabel);
  const counts = useMeta((s) => s.counts);

  // Instance identity replaces the old tenant switcher: this panel administers ONE
  // instance (no per-tenant context to switch between anymore).
  const inst = useAsync(() => api.instance(), []);
  const instName = inst.data?.name || t("access.selfHosted");
  const instSub = adminLabel
    ? adminLabel
    : inst.data
      ? truncId(inst.data.instance_id, 8, 4)
      : t("common.loading");

  return (
    <div
      style={{
        width: 222,
        flexShrink: 0,
        background: "var(--bg2)",
        borderRight: "1px solid var(--line)",
        display: "flex",
        flexDirection: "column",
        padding: "12px 0",
      }}
    >
      {/* Instance identity */}
      <div style={{ margin: "0 12px 4px" }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 9,
            padding: 9,
            borderRadius: 10,
            background: "var(--bg3)",
            border: "1px solid var(--line)",
          }}
        >
          <span
            style={{
              width: 22,
              height: 22,
              borderRadius: 6,
              background: "linear-gradient(140deg, var(--accent), var(--purple))",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              color: "#fff",
              fontWeight: 700,
              fontSize: 11,
              flexShrink: 0,
            }}
          >
            {(instName[0] || "·").toUpperCase()}
          </span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div
              style={{
                fontSize: 13,
                fontWeight: 700,
                whiteSpace: "nowrap",
                overflow: "hidden",
                textOverflow: "ellipsis",
              }}
            >
              {instName}
            </div>
            <div
              style={{
                fontSize: 11,
                color: "var(--txt3)",
                whiteSpace: "nowrap",
                overflow: "hidden",
                textOverflow: "ellipsis",
              }}
            >
              {instSub}
            </div>
          </div>
        </div>
      </div>

      {/* Nav */}
      <div style={{ overflowY: "auto", flex: 1, paddingTop: 4 }}>
        {NAV.map((group) => (
          <div key={group.key}>
            <div style={{ display: "flex", alignItems: "center", padding: "12px 12px 5px 18px" }}>
              <span
                style={{
                  flex: 1,
                  fontSize: 10.5,
                  fontWeight: 700,
                  letterSpacing: 0.6,
                  color: "var(--txt3)",
                  textTransform: "uppercase",
                }}
              >
                {t(`nav.${group.key}`)}
              </span>
              {group.keysetTag ? (
                <span
                  style={{
                    fontSize: 9,
                    fontWeight: 700,
                    letterSpacing: 0.4,
                    color: "var(--amber)",
                    display: "flex",
                    alignItems: "center",
                    gap: 3,
                  }}
                >
                  <Icon name="key" size={10} color="var(--amber)" />
                  KEYSET
                </span>
              ) : null}
            </div>
            {group.items.map((it) => {
              const isActive = route === it.route;
              const locked = !!it.keyset && !keysetUnlocked;
              const count = it.count ? counts[it.count] : undefined;
              return (
                <div
                  key={it.route}
                  className="navitem"
                  onClick={() => go(it.route)}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 9,
                    height: 32,
                    padding: "0 10px",
                    margin: "0 8px",
                    borderRadius: 8,
                    cursor: "pointer",
                    fontSize: 13,
                    color: isActive ? "var(--txt)" : "var(--txt2)",
                    fontWeight: isActive ? 600 : 500,
                    background: isActive ? "var(--bg4)" : "transparent",
                    boxShadow: isActive ? "inset 2px 0 0 var(--accent)" : undefined,
                  }}
                >
                  <Icon name={it.icon} size={15} color={isActive ? "var(--accent)" : "var(--txt3)"} />
                  <span
                    style={{
                      flex: 1,
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                    }}
                  >
                    {t(`nav.${it.key}`)}
                  </span>
                  {locked ? <Icon name="lock" size={12} color="var(--txt3)" /> : null}
                  {count != null ? (
                    <span
                      style={{
                        fontFamily: MONO,
                        fontSize: 11,
                        color: "var(--txt3)",
                        fontWeight: 600,
                      }}
                    >
                      {count}
                    </span>
                  ) : null}
                </div>
              );
            })}
          </div>
        ))}
      </div>

      {/* Footer */}
      <div
        style={{
          margin: "8px 12px 0",
          paddingTop: 10,
          borderTop: "1px solid var(--line)",
          display: "flex",
          alignItems: "center",
          gap: 8,
        }}
      >
        <span
          style={{
            width: 28,
            height: 28,
            borderRadius: 8,
            background: "var(--bg3)",
            border: "1px solid var(--line)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            color: keysetUnlocked ? "var(--green)" : "var(--amber)",
            flexShrink: 0,
          }}
        >
          <Icon name={keysetUnlocked ? "unlock" : "lock"} size={14} />
        </span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 12, fontWeight: 600 }}>{t("access.selfHosted")}</div>
          <div style={{ fontSize: 10.5, color: "var(--txt3)" }}>
            {keysetUnlocked ? t("access.footerUnlocked") : t("access.footerLocked")}
          </div>
        </div>
        {keysetUnlocked ? (
          <button
            onClick={lockKeyset}
            title={t("access.lock")}
            style={{
              width: 28,
              height: 28,
              borderRadius: 8,
              border: "1px solid var(--line)",
              background: "var(--bg1)",
              color: "var(--txt2)",
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <Icon name="lock" size={14} />
          </button>
        ) : null}
      </div>
    </div>
  );
}
