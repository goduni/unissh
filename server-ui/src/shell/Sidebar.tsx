import { useState } from "react";
import { useTranslation } from "react-i18next";
import { lockKeyset } from "../api/auth-service";
import { switchTenant } from "../api/tenant-switch";
import { useMeta } from "../store/meta";
import { useSession } from "../store/session";
import { useTenant } from "../store/tenant";
import { useUi } from "../store/ui";
import { truncId } from "../util/bytes";
import { Icon } from "../ui/icons";
import { gradientFor } from "../ui/primitives";
import { NAV } from "./nav";
import { MONO } from "../theme/tokens";

export function Sidebar() {
  const { t } = useTranslation();
  const route = useUi((s) => s.route);
  const go = useUi((s) => s.go);
  const switcherOpen = useUi((s) => s.tenantSwitcherOpen);
  const toggleSwitcher = useUi((s) => s.toggleTenantSwitcher);
  const openBootstrap = useUi((s) => s.openBootstrap);

  const tenants = useTenant((s) => s.tenants);
  const activeId = useTenant((s) => s.activeTenantId);

  const keysetUnlocked = useSession((s) => s.keysetUnlocked);
  const counts = useMeta((s) => s.counts);

  const active = tenants.find((x) => x.tenant_id === activeId);
  const activeIdx = tenants.findIndex((x) => x.tenant_id === activeId);

  // Switcher search — scales when there are many (personal) spaces.
  const [q, setQ] = useState("");
  const qq = q.trim().toLowerCase();
  const shown = qq
    ? tenants.filter(
        (tn) =>
          (tn.display_name ?? "").toLowerCase().includes(qq) ||
          tn.tenant_id.toLowerCase().includes(qq),
      )
    : tenants;

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
      {/* Tenant switcher */}
      <div style={{ position: "relative", margin: "0 12px 4px" }}>
        <div
          onClick={toggleSwitcher}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 9,
            padding: 9,
            borderRadius: 10,
            background: "var(--bg3)",
            border: "1px solid var(--line)",
            cursor: "pointer",
          }}
        >
          <span style={tileStyle(Math.max(0, activeIdx))}>
            {((active?.display_name || truncId(active?.tenant_id, 1, 0))[0] || "·").toUpperCase()}
          </span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div
              style={{
                fontSize: 13,
                fontWeight: 700,
                whiteSpace: "nowrap",
                overflow: "hidden",
                textOverflow: "ellipsis",
                fontFamily: active?.display_name ? "inherit" : MONO,
              }}
            >
              {active ? active.display_name || truncId(active.tenant_id, 8, 4) : "—"}
            </div>
            <div style={{ fontSize: 11, color: "var(--txt3)" }}>
              {active
                ? `${active.tier} · ${active.accounts} ${t("screen.tenants.colAccounts")}`
                : t("common.na")}
            </div>
          </div>
          <Icon
            name="chevronDown"
            size={13}
            color="var(--txt3)"
            style={{ transform: switcherOpen ? "rotate(180deg)" : "none" }}
          />
        </div>

        {switcherOpen ? (
          <div
            style={{
              position: "absolute",
              top: "100%",
              left: 0,
              right: 0,
              marginTop: 6,
              zIndex: 40,
              background: "var(--bg3)",
              border: "1px solid var(--line2)",
              borderRadius: 12,
              padding: 6,
              boxShadow: "var(--shadow)",
            }}
          >
            {tenants.length > 8 ? (
              <input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder={t("screen.tenants.searchPlaceholder")}
                autoFocus
                style={{
                  width: "100%",
                  boxSizing: "border-box",
                  marginBottom: 6,
                  padding: "7px 10px",
                  borderRadius: 8,
                  border: "1px solid var(--line2)",
                  background: "var(--bg2)",
                  color: "var(--txt)",
                  fontSize: 12.5,
                  fontFamily: "inherit",
                  outline: "none",
                }}
              />
            ) : null}
            {shown.map((tn, i) => (
              <div
                key={tn.tenant_id}
                onClick={() => {
                  switchTenant(tn.tenant_id);
                  toggleSwitcher();
                }}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 9,
                  padding: 8,
                  borderRadius: 8,
                  cursor: "pointer",
                  background: tn.tenant_id === activeId ? "var(--bg4)" : "transparent",
                }}
              >
                <span style={tileStyle(i)}>
                  {((tn.display_name || truncId(tn.tenant_id, 1, 0))[0] || "·").toUpperCase()}
                </span>
                <span
                  style={{
                    flex: 1,
                    fontSize: 12.5,
                    fontWeight: 600,
                    fontFamily: tn.display_name ? "inherit" : MONO,
                    whiteSpace: "nowrap",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                  }}
                >
                  {tn.display_name || truncId(tn.tenant_id, 8, 4)}
                </span>
                <span style={{ fontFamily: MONO, fontSize: 11, color: "var(--txt3)" }}>
                  {tn.accounts}
                </span>
                {tn.tenant_id === activeId ? <Icon name="check" size={13} color="var(--accent)" /> : null}
              </div>
            ))}
            <div style={{ height: 1, background: "var(--line)", margin: "6px 4px" }} />
            <div
              onClick={() => {
                toggleSwitcher();
                openBootstrap();
              }}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 9,
                padding: 8,
                borderRadius: 8,
                cursor: "pointer",
                color: "var(--txt2)",
              }}
            >
              <span
                style={{
                  width: 22,
                  height: 22,
                  borderRadius: 6,
                  border: "1px dashed var(--line2)",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                }}
              >
                <Icon name="plus" size={12} />
              </span>
              <span style={{ fontSize: 13, fontWeight: 600 }}>{t("screen.tenants.createSpace")}</span>
            </div>
          </div>
        ) : null}
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

function tileStyle(i: number): React.CSSProperties {
  return {
    width: 22,
    height: 22,
    borderRadius: 6,
    background: gradientFor(i),
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    color: "#fff",
    fontWeight: 700,
    fontSize: 11,
    flexShrink: 0,
  };
}
