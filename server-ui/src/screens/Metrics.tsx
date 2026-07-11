import { useTranslation } from "react-i18next";
import { api } from "../api";
import { useTenant } from "../store/tenant";
import { useAsync } from "../util/useAsync";
import { fmtNum } from "../util/format";
import { type IconName } from "../ui/icons";
import { KeysetGate } from "../ui/overlays";
import { Btn, Card, ErrorCard, KpiCard, Spinner } from "../ui/primitives";
import type { MetricsPoint } from "../api/types";
import { Screen } from "./Screen";
import { MONO } from "../theme/tokens";

export function Metrics() {
  const { t } = useTranslation();
  return (
    <Screen title={t("screen.metrics.title")} sub={t("screen.metrics.sub")}>
      <KeysetGate>
        <MetricsBody />
      </KeysetGate>
    </Screen>
  );
}

const KPI_DEFS: { name: string; icon: IconName }[] = [
  { name: "unissh_push_objects_total", icon: "layers" },
  { name: "unissh_delta_requests_total", icon: "refresh" },
  { name: "unissh_rate_limited_total", icon: "alert" },
  { name: "unissh_auth_verify_total", icon: "key" },
  { name: "unissh_admin_requests_total", icon: "shield" },
];

/** Last cumulative value of a counter series (0 if empty). */
function lastValue(points: MetricsPoint[] | undefined): number {
  if (!points || points.length === 0) return 0;
  return points[points.length - 1].v;
}

/** Per-interval deltas (v[i]-v[i-1], clamped ≥0). */
function deltas(points: MetricsPoint[]): number[] {
  const out: number[] = [];
  for (let i = 1; i < points.length; i++) {
    out.push(Math.max(0, points[i].v - points[i - 1].v));
  }
  return out;
}

function MetricsBody() {
  const { t } = useTranslation();
  const activeTenantId = useTenant((s) => s.activeTenantId);
  const m = useAsync(() => api.admin.metricsSummary(), [activeTenantId]);

  if (m.loading) {
    return (
      <div style={{ display: "flex", justifyContent: "center", padding: 40 }}>
        <Spinner />
      </div>
    );
  }

  if (m.error) {
    return (
      <>
        <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 14 }}>
          <Btn icon="refresh" size="sm" onClick={m.reload}>
            {t("common.refresh")}
          </Btn>
        </div>
        <ErrorCard message={m.error} onRetry={m.reload} />
      </>
    );
  }

  if (m.data && !m.data.enabled) {
    return (
      <>
        <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 14 }}>
          <Btn icon="refresh" size="sm" onClick={m.reload}>
            {t("common.refresh")}
          </Btn>
        </div>
        <div style={{ fontSize: 13, color: "var(--txt3)" }}>{t("screen.metrics.disabled")}</div>
      </>
    );
  }

  const series = m.data?.series ?? {};
  const names = Object.keys(series).sort((a, b) => a.localeCompare(b));

  // Pick the 1-2 highest-volume series (by latest cumulative value) for charting.
  const charted = names
    .map((name) => ({ name, points: series[name] ?? [], last: lastValue(series[name]) }))
    .filter((s) => s.points.length >= 2 && s.last > 0)
    .sort((a, b) => b.last - a.last)
    .slice(0, 2);

  return (
    <>
      <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 14 }}>
        <Btn icon="refresh" size="sm" onClick={m.reload}>
          {t("common.refresh")}
        </Btn>
      </div>

      {/* KPI cards */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
          gap: 12,
          marginBottom: 16,
        }}
      >
        {KPI_DEFS.filter((d) => series[d.name] !== undefined).map((d) => (
          <KpiCard
            key={d.name}
            label={d.name}
            value={fmtNum(lastValue(series[d.name]))}
            icon={d.icon}
          />
        ))}
      </div>

      {/* sparkline / bar charts of per-interval deltas */}
      {charted.length > 0 ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 12, marginBottom: 16 }}>
          {charted.map((s) => (
            <DeltaChart
              key={s.name}
              name={s.name}
              points={s.points}
              sampleInterval={m.data?.sample_interval_seconds ?? 0}
              retained={m.data?.retained_samples ?? 0}
            />
          ))}
        </div>
      ) : null}

      {/* raw table */}
      <Card pad={false}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            padding: "14px 18px",
            borderBottom: "1px solid var(--line)",
          }}
        >
          <span style={{ fontWeight: 700, fontSize: 13.5 }}>{t("screen.metrics.rows")}</span>
          <span style={{ fontFamily: MONO, fontSize: 11.5, color: "var(--txt3)" }}>
            /v1/admin/metrics/summary
          </span>
        </div>
        <div>
          {names.map((name) => (
            <div
              key={name}
              style={{
                display: "flex",
                justifyContent: "space-between",
                padding: "11px 18px",
                borderBottom: "1px solid var(--line)",
              }}
            >
              <span style={{ fontFamily: MONO, fontSize: 12, color: "var(--txt2)" }}>
                {name}
              </span>
              <span
                style={{
                  fontFamily: MONO,
                  fontSize: 12,
                  color: "var(--txt)",
                  fontWeight: 600,
                }}
              >
                {fmtNum(lastValue(series[name]))}
              </span>
            </div>
          ))}
        </div>
      </Card>
    </>
  );
}

function DeltaChart({
  name,
  points,
  sampleInterval,
  retained,
}: {
  name: string;
  points: MetricsPoint[];
  sampleInterval: number;
  retained: number;
}) {
  const { t } = useTranslation();
  const d = deltas(points);
  const W = 1000;
  const H = 120;
  const PAD = 4;
  const max = Math.max(1, ...d);
  const n = d.length;
  const slot = n > 0 ? (W - PAD * 2) / n : 0;
  const barW = Math.max(1, slot * 0.7);

  return (
    <Card>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          marginBottom: 10,
        }}
      >
        <span style={{ fontFamily: MONO, fontSize: 12.5, fontWeight: 700, color: "var(--txt)" }}>
          {name}
        </span>
        <span style={{ fontFamily: MONO, fontSize: 11, color: "var(--txt3)" }}>
          Δ/{sampleInterval}s · {t("screen.metrics.window", { n: retained })}
        </span>
      </div>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        preserveAspectRatio="none"
        width="100%"
        height={H}
        style={{ display: "block" }}
      >
        {d.map((v, i) => {
          const h = (v / max) * (H - PAD * 2);
          const x = PAD + i * slot + (slot - barW) / 2;
          const y = H - PAD - h;
          return <rect key={i} x={x} y={y} width={barW} height={h} rx={1} fill="var(--accent)" />;
        })}
      </svg>
    </Card>
  );
}
