import { useEffect } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { useMeta } from "../store/meta";
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
  const reloadTick = useUi((s) => s.reloadTick);
  const setCounts = useMeta((s) => s.setCounts);

  const version = useAsync(() => api.version(), []);
  const ready = useAsync(() => api.readyz(), []);
  // Owner-gated instance overview (Bearer; no tenant). The panel is always
  // authenticated here (Shell requires an unlocked keyset session).
  const adminOv = useAsync(() => api.admin.overview(), [reloadTick]);

  useEffect(() => {
    if (adminOv.data) {
      setCounts({
        accounts: adminOv.data.accounts,
        pending_invites: adminOv.data.pending_invites,
        devices: adminOv.data.devices,
      });
    }
  }, [adminOv.data, setCounts]);

  const statusItems = [
    { label: t("screen.overview.statusVersion"), value: version.data ? `${version.data.server}` : "…", icon: "shield" as const, mono: true },
    {
      label: "readyz",
      value: ready.loading ? "…" : ready.data ? "OK" : "FAIL",
      icon: "activity" as const,
      mono: false,
    },
    {
      label: "instance_generation",
      value: adminOv.data ? fmtNum(adminOv.data.instance_generation) : "…",
      icon: "layers" as const,
      mono: true,
    },
  ];

  const kpis: { label: string; value: string; icon: IconName; route: Route; delta?: string }[] = adminOv.data
    ? [
        { label: t("nav.accounts"), value: String(adminOv.data.accounts), icon: "server" as const, route: "accounts" as Route, delta: t("screen.overview.deltaOwners", { count: adminOv.data.owners }) },
        { label: t("nav.devices"), value: String(adminOv.data.devices), icon: "fingerprint" as const, route: "devices" as Route, delta: t("screen.overview.deltaSessions", { count: adminOv.data.active_sessions }) },
        { label: t("nav.vaults"), value: String(adminOv.data.vaults), icon: "lock" as const, route: "vaults" as Route },
        { label: t("nav.objects"), value: fmtNum(adminOv.data.objects), icon: "layers" as const, route: "objects" as Route },
        { label: t("nav.invites"), value: String(adminOv.data.pending_invites), icon: "tag" as const, route: "invites" as Route, delta: t("screen.overview.deltaPending") },
        { label: "next_seq", value: fmtNum(adminOv.data.next_seq), icon: "refresh" as const, route: "maint" as Route },
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
      {adminOv.loading && !adminOv.data ? (
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
