import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { useAsync } from "../util/useAsync";
import { fmtNum, fmtRelative } from "../util/format";
import { Btn, Card, Spinner, Tag } from "../ui/primitives";
import { Icon } from "../ui/icons";
import { KeysetGate } from "../ui/overlays";
import { Screen } from "./Screen";
import { MONO } from "../theme/tokens";

/** "Nd HH:MM"-style uptime label from a duration in seconds. */
function fmtUptime(sec: number, daysLabel: string): string {
  const total = Math.max(0, Math.floor(sec));
  const d = Math.floor(total / 86400);
  const h = Math.floor((total % 86400) / 3600);
  const m = Math.floor((total % 3600) / 60);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d}${daysLabel} ${pad(h)}:${pad(m)}`;
}

export function Health() {
  const { t } = useTranslation();

  const ready = useAsync(() => api.readyz(), []);
  const version = useAsync(() => api.version(), []);

  const checkNow = () => {
    ready.reload();
    version.reload();
  };

  return (
    <Screen
      title={t("screen.health.title")}
      sub={t("screen.health.sub")}
      actions={
        <Btn icon="refresh" size="sm" onClick={checkNow}>
          {t("common.checkNow")}
        </Btn>
      }
    >
      {/* liveness — ungated */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: 14,
          marginBottom: 16,
        }}
      >
        <LivenessCard
          ok={!!ready.data}
          loading={ready.loading}
          label="readyz"
          okDesc={t("screen.health.readyzOkDesc")}
          failDesc={t("screen.health.readyzFailDesc")}
        />
        <Card>
          <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
            <span
              style={{
                width: 48,
                height: 48,
                borderRadius: 13,
                background: "var(--accentSoft)",
                border: "1px solid var(--accentLine)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "var(--accent)",
                flexShrink: 0,
              }}
            >
              <Icon name="shield" size={22} />
            </span>
            <div style={{ minWidth: 0 }}>
              <div
                style={{
                  fontFamily: MONO,
                  fontSize: 12.5,
                  color: "var(--txt3)",
                  fontWeight: 700,
                }}
              >
                version
              </div>
              {version.loading ? (
                <div style={{ marginTop: 8 }}>
                  <Spinner size={16} />
                </div>
              ) : (
                <>
                  <div
                    style={{
                      fontFamily: MONO,
                      fontSize: 18,
                      fontWeight: 700,
                      marginTop: 3,
                      letterSpacing: -0.4,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {version.data ? version.data.server : "—"}
                  </div>
                  <div
                    style={{
                      fontFamily: MONO,
                      fontSize: 11.5,
                      color: "var(--txt3)",
                      marginTop: 2,
                    }}
                  >
                    api {version.data ? version.data.api : "—"}
                  </div>
                </>
              )}
            </div>
          </div>
        </Card>
      </div>

      {/* diagnostics — keyset-gated */}
      <KeysetGate>
        <HealthBody />
      </KeysetGate>
    </Screen>
  );
}

function LivenessCard({
  ok,
  loading,
  label,
  okDesc,
  failDesc,
}: {
  ok: boolean;
  loading: boolean;
  label: string;
  okDesc: string;
  failDesc: string;
}) {
  const color = ok ? "var(--green)" : "var(--red)";
  return (
    <Card>
      <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
        <span
          style={{
            width: 48,
            height: 48,
            borderRadius: 13,
            background: `color-mix(in srgb, ${color} 12%, transparent)`,
            border: `1px solid color-mix(in srgb, ${color} 32%, transparent)`,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            flexShrink: 0,
          }}
        >
          <span
            style={{
              width: 13,
              height: 13,
              borderRadius: "50%",
              background: color,
              boxShadow: `0 0 0 4px color-mix(in srgb, ${color} 20%, transparent), 0 0 9px ${color}`,
              animation: ok ? "pulseDot 2s ease-in-out infinite" : undefined,
            }}
          />
        </span>
        <div style={{ minWidth: 0 }}>
          <div
            style={{
              fontFamily: MONO,
              fontSize: 12.5,
              color: "var(--txt3)",
              fontWeight: 700,
            }}
          >
            {label}
          </div>
          <div
            style={{
              fontSize: 18,
              fontWeight: 700,
              marginTop: 3,
              color,
              letterSpacing: -0.4,
            }}
          >
            {loading ? "…" : ok ? "OK" : "FAIL"}
          </div>
          <div style={{ fontSize: 11.5, color: "var(--txt3)", marginTop: 2 }}>
            {ok ? okDesc : failDesc}
          </div>
        </div>
      </div>
    </Card>
  );
}

function HealthBody() {
  const { t } = useTranslation();

  const health = useAsync(() => api.admin.health(), []);

  if (health.loading && !health.data) {
    return (
      <Card>
        <div style={{ display: "flex", justifyContent: "center", padding: 24 }}>
          <Spinner />
        </div>
      </Card>
    );
  }

  const h = health.data;
  const pool = h?.db.pool;

  return (
    <Card>
      <HealthRow
        label="status"
        value={
          h ? (
            <Tag tone={h.status === "ok" ? "green" : "amber"}>{h.status}</Tag>
          ) : (
            "—"
          )
        }
      />
      <HealthRow label="version" value={h ? h.version : "—"} mono />
      <HealthRow label="uptime" value={h ? fmtUptime(h.uptime_seconds, t("screen.health.uptimeDaysShort")) : "—"} mono />
      <HealthRow label="DB backend" value={h ? h.db.backend : "—"} mono />
      <HealthRow
        label="DB reachable"
        value={
          h ? (
            <Tag tone={h.db.reachable ? "green" : "red"}>
              {h.db.reachable ? "yes" : "no"}
            </Tag>
          ) : (
            "—"
          )
        }
      />
      <HealthRow
        label="pool used / idle / size / max"
        value={
          pool
            ? `${fmtNum(pool.in_use)} / ${fmtNum(pool.idle)} / ${fmtNum(pool.size)} / ${fmtNum(pool.max)}`
            : "—"
        }
        mono
      />
      <HealthRow
        label="janitor interval"
        value={h ? t("common.unitSeconds", { n: fmtNum(h.janitor.interval_seconds) }) : "—"}
        mono
      />
      <HealthRow
        label="janitor last run"
        value={h ? fmtRelative(h.janitor.last_run) : "—"}
      />
      <HealthRow label="TLS" value={h ? h.tls : "—"} mono />
      <HealthRow
        label="trust_proxy"
        value={
          h ? (
            <Tag tone={h.trust_proxy ? "amber" : "neutral"}>
              {h.trust_proxy ? "on" : "off"}
            </Tag>
          ) : (
            "—"
          )
        }
        last
      />
    </Card>
  );
}

function HealthRow({
  label,
  value,
  mono,
  last,
}: {
  label: string;
  value: ReactNode;
  mono?: boolean;
  last?: boolean;
}) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "13px 0",
        borderBottom: last ? undefined : "1px solid var(--line)",
      }}
    >
      <span style={{ fontSize: 12.5, color: "var(--txt3)" }}>{label}</span>
      <span
        style={{
          fontSize: 13,
          color: "var(--txt)",
          fontWeight: 600,
          fontFamily: mono ? MONO : "inherit",
        }}
      >
        {value}
      </span>
    </div>
  );
}
