import { useEffect } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { useMeta } from "../store/meta";
import { useSession } from "../store/session";
import { useTenant } from "../store/tenant";
import { useUi, type Route } from "../store/ui";
import { useAsync } from "../util/useAsync";
import { fmtNum } from "../util/format";
import { MONO } from "../theme/tokens";
import { Icon, type IconName } from "../ui/icons";
import { KpiCard, Spinner, ZkBanner } from "../ui/primitives";
import { Screen } from "./Screen";

export function Overview() {
  const { t } = useTranslation();
  const go = useUi((s) => s.go);
  const keysetUnlocked = useSession((s) => s.keysetUnlocked);
  const activeTenantId = useTenant((s) => s.activeTenantId);
  const tenants = useTenant((s) => s.tenants);
  const setCounts = useMeta((s) => s.setCounts);

  const version = useAsync(() => api.version(), []);
  const ready = useAsync(() => api.readyz(), []);
  const opsOv = useAsync(() => api.ops.overview(), []);
  const adminOv = useAsync(
    () => (keysetUnlocked ? api.admin.overview() : Promise.resolve(null)),
    [keysetUnlocked, activeTenantId],
  );

  useEffect(() => {
    if (adminOv.data) {
      setCounts({
        accounts: adminOv.data.accounts,
        pending_invites: adminOv.data.pending_invites,
        devices: adminOv.data.devices,
      });
    }
  }, [adminOv.data, setCounts]);

  const suspended = tenants.filter((x) => x.status === "suspended").length;

  const statusItems = [
    { label: t("screen.overview.statusVersion"), value: version.data ? `${version.data.server}` : "…", icon: "shield" as const, mono: true },
    {
      label: "readyz",
      value: ready.loading ? "…" : ready.data ? "OK" : "FAIL",
      icon: "activity" as const,
      mono: false,
    },
    {
      label: "Σ next_seq",
      value: opsOv.data ? fmtNum(opsOv.data.instance_generation) : "…",
      icon: "layers" as const,
      mono: true,
    },
    {
      label: t("nav.tenants"),
      value: opsOv.data
        ? opsOv.data.tenants_personal !== undefined
          ? t("screen.overview.spacesValue", {
              total: opsOv.data.tenants,
              personal: opsOv.data.tenants_personal,
            })
          : String(opsOv.data.tenants)
        : "…",
      icon: "database" as const,
      mono: true,
    },
  ];

  const kpis: { label: string; value: string; icon: IconName; route: Route; delta?: string }[] = keysetUnlocked && adminOv.data
    ? [
        { label: t("nav.accounts"), value: String(adminOv.data.accounts), icon: "server" as const, route: "accounts" as Route, delta: t("screen.overview.deltaAdmins", { count: adminOv.data.admins }) },
        { label: t("nav.devices"), value: String(adminOv.data.devices), icon: "fingerprint" as const, route: "devices" as Route, delta: t("screen.overview.deltaSessions", { count: adminOv.data.active_sessions }) },
        { label: t("nav.vaults"), value: String(adminOv.data.vaults), icon: "lock" as const, route: "vaults" as Route },
        { label: t("nav.objects"), value: fmtNum(adminOv.data.objects), icon: "layers" as const, route: "objects" as Route },
        { label: t("nav.invites"), value: String(adminOv.data.pending_invites), icon: "tag" as const, route: "invites" as Route, delta: t("screen.overview.deltaPending") },
        { label: "next_seq", value: fmtNum(adminOv.data.next_seq), icon: "refresh" as const, route: "maint" as Route },
      ]
    : opsOv.data
      ? [
          { label: t("nav.tenants"), value: String(opsOv.data.tenants), icon: "database" as const, route: "tenants" as Route },
          { label: t("nav.accounts"), value: String(opsOv.data.accounts), icon: "server" as const, route: "accounts" as Route },
          { label: t("nav.objects"), value: fmtNum(opsOv.data.objects), icon: "layers" as const, route: "objects" as Route },
          { label: "Σ next_seq", value: fmtNum(opsOv.data.instance_generation), icon: "refresh" as const, route: "maint" as Route },
        ]
      : [];

  return (
    <Screen title={t("screen.overview.title")} sub={t("screen.overview.sub")}>
      {/* status row */}
      <div
        style={{
          display: "flex",
          flexWrap: "wrap",
          gap: 10,
          alignItems: "center",
          padding: "13px 16px",
          background: "var(--bg1)",
          border: "1px solid var(--line)",
          borderRadius: 12,
          marginBottom: 16,
        }}
      >
        {statusItems.map((s, i) => (
          <div
            key={s.label}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              paddingRight: 18,
              borderRight: i < statusItems.length - 1 ? "1px solid var(--line)" : undefined,
            }}
          >
            <Icon name={s.icon} size={15} color="var(--txt3)" />
            <div>
              <div
                style={{
                  fontSize: 10.5,
                  color: "var(--txt3)",
                  textTransform: "uppercase",
                  letterSpacing: 0.4,
                  fontWeight: 600,
                }}
              >
                {s.label}
              </div>
              <div style={{ fontSize: 13, fontWeight: 700, fontFamily: s.mono ? MONO : "inherit" }}>
                {s.value}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* KPI grid */}
      {opsOv.loading && !opsOv.data ? (
        <div style={{ display: "flex", justifyContent: "center", padding: 40 }}>
          <Spinner />
        </div>
      ) : (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(168px, 1fr))",
            gap: 12,
            marginBottom: 18,
          }}
        >
          {kpis.map((k) => (
            <div key={k.label} className="hoverable">
              <KpiCard
                label={k.label}
                value={k.value}
                delta={k.delta}
                deltaColor="var(--txt3)"
                icon={k.icon}
                onClick={() => go(k.route)}
              />
            </div>
          ))}
        </div>
      )}

      {/* warnings */}
      <div
        style={{
          background: "var(--bg1)",
          border: "1px solid var(--line)",
          borderRadius: 14,
          padding: "17px 19px",
          marginBottom: 14,
        }}
      >
        <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 12 }}>{t("screen.overview.attentionTitle")}</div>
        <div style={{ display: "flex", flexDirection: "column", gap: 9 }}>
          {suspended > 0 ? (
            <WarnRow
              color="var(--red)"
              icon="alert"
              title={t("screen.overview.suspendedTitle")}
              desc={t("screen.overview.suspendedDesc", { count: suspended })}
            />
          ) : null}
          {!keysetUnlocked ? (
            <WarnRow
              color="var(--amber)"
              icon="lock"
              title={t("access.keysetLocked")}
              desc={t("screen.overview.keysetLockedDesc")}
            />
          ) : null}
          <WarnRow
            color={ready.data ? "var(--green)" : "var(--red)"}
            icon={ready.data ? "check" : "alert"}
            title={ready.data ? "readyz · OK" : t("screen.overview.readyzDownTitle")}
            desc={ready.data ? t("screen.overview.readyzOkDesc") : t("screen.overview.readyzDownDesc")}
          />
        </div>
      </div>

      <ZkBanner>
        <b style={{ color: "var(--txt)" }}>{t("zk.overview")}</b>
      </ZkBanner>
    </Screen>
  );
}

function WarnRow({
  color,
  icon,
  title,
  desc,
}: {
  color: string;
  icon: "alert" | "lock" | "check";
  title: string;
  desc: string;
}) {
  return (
    <div
      style={{
        display: "flex",
        gap: 10,
        alignItems: "flex-start",
        padding: "10px 11px",
        borderRadius: 10,
        background: `color-mix(in srgb, ${color} 9%, transparent)`,
        border: `1px solid color-mix(in srgb, ${color} 28%, transparent)`,
      }}
    >
      <Icon name={icon} size={15} color={color} style={{ marginTop: 1 }} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 12.5, fontWeight: 600, color: "var(--txt)" }}>{title}</div>
        <div style={{ fontSize: 11.5, color: "var(--txt3)", marginTop: 1 }}>{desc}</div>
      </div>
    </div>
  );
}
