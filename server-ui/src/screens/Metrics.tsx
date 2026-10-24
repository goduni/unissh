import { useState, type CSSProperties, type KeyboardEvent as ReactKeyboardEvent } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { useAsync, type AsyncState } from "../util/useAsync";
import { fmtNum } from "../util/format";
import {
  Btn,
  Card,
  CardHeader,
  EmptyState,
  ErrorCard,
  Skeleton,
  StatTile,
  StatTiles,
} from "../ui/primitives";
import { DataTable, type Column } from "../ui/DataTable";
import type { MetricsPoint, MetricsSummary } from "../api/types";
import { Screen } from "./Screen";
import { MONO } from "../theme/tokens";

export function Metrics() {
  const { t } = useTranslation();
  const m = useAsync(() => api.admin.metricsSummary(), []);
  return (
    <Screen
      title={t("screen.metrics.title")}
      sub={t("screen.metrics.sub")}
      actions={
        <Btn icon="refresh" loading={m.loading} onClick={m.reload}>
          {t("common.refresh")}
        </Btn>
      }
    >
      <MetricsBody m={m} />
    </Screen>
  );
}

const KPI_NAMES: string[] = [
  "unissh_push_objects_total",
  "unissh_delta_requests_total",
  "unissh_rate_limited_total",
  "unissh_auth_verify_total",
  "unissh_admin_requests_total",
];

/** The series' name without the product's prefix and the counter's suffix: the key of its tile's label. */
function shortName(name: string): string {
  return name.replace(/^unissh_/, "").replace(/_total$/, "");
}

/** The series' full name under its figure: what to grep for in Prometheus. */
const SERIES_NOTE: CSSProperties = {
  minWidth: 0,
  fontFamily: MONO,
  overflow: "hidden",
  textOverflow: "ellipsis",
  whiteSpace: "nowrap",
};

/** As many columns as tiles, three at least (the card keeps its rhythm). */
function tileCols(n: number): 3 | 4 | 5 | 6 {
  return n <= 3 ? 3 : n >= 6 ? 6 : (n as 4 | 5);
}

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

const MUTED: CSSProperties = { color: "var(--muted-foreground)" };

function MetricsBody({ m }: { m: AsyncState<MetricsSummary> }) {
  const { t } = useTranslation();
  // A tile names its counter in the reader's words; the series' own name stands under the figure.
  const kpiLabel = (name: string) =>
    t(`screen.metrics.kpi.${shortName(name)}`, { defaultValue: shortName(name) });

  if (m.error) {
    return <ErrorCard message={m.error} onRetry={m.reload} retrying={m.loading} />;
  }

  if (m.loading && !m.data) {
    return (
      <>
        <StatTiles cols={5}>
          {KPI_NAMES.map((name) => (
            <StatTile key={name} label={kpiLabel(name)} value="" loading />
          ))}
        </StatTiles>
        <Card pad={false}>
          <div style={{ padding: 16 }}>
            <Skeleton height={200} />
          </div>
        </Card>
      </>
    );
  }

  if (m.data && !m.data.enabled) {
    return <EmptyState icon="activity" title={t("screen.metrics.disabled")} />;
  }

  const series = m.data?.series ?? {};
  const names = Object.keys(series).sort((a, b) => a.localeCompare(b));
  const kpis = KPI_NAMES.filter((name) => series[name] !== undefined);

  // Pick the 1-2 highest-volume series (by latest cumulative value) for charting.
  const charted = names
    .map((name) => ({ name, points: series[name] ?? [], last: lastValue(series[name]) }))
    .filter((s) => s.points.length >= 2 && s.last > 0)
    .sort((a, b) => b.last - a.last)
    .slice(0, 2);

  const columns: Column<string>[] = [
    {
      key: "name",
      label: t("screen.metrics.colSeries"),
      width: "minmax(0, 1fr)",
      render: (name) => (
        <span style={{ fontFamily: MONO, fontSize: 12, lineHeight: "16px", overflowWrap: "anywhere" }}>{name}</span>
      ),
    },
    {
      key: "value",
      label: t("screen.metrics.colValue"),
      width: "minmax(96px, 180px)",
      numeric: true,
      render: (name) => fmtNum(lastValue(series[name])),
    },
  ];

  return (
    <>
      {/* The counters' latest values: one card of figures. */}
      {kpis.length > 0 ? (
        <StatTiles cols={tileCols(kpis.length)}>
          {kpis.map((name) => (
            <StatTile key={name} label={kpiLabel(name)} value={fmtNum(lastValue(series[name]))}>
              <span title={name} style={SERIES_NOTE}>
                {name}
              </span>
            </StatTile>
          ))}
        </StatTiles>
      ) : null}

      {/* Per-interval deltas of the busiest series: the first in the blue, the second muted. */}
      {charted.map((s, i) => (
        <DeltaChart
          key={s.name}
          name={s.name}
          points={s.points}
          second={i > 0}
          sampleInterval={m.data?.sample_interval_seconds ?? 0}
          retained={m.data?.retained_samples ?? 0}
        />
      ))}

      {/* raw table */}
      <Card pad={false}>
        <CardHeader
          title={t("screen.metrics.rows")}
          actions={
            <span style={{ ...MUTED, fontFamily: MONO, fontSize: 12, lineHeight: "16px" }}>
              /v1/admin/metrics/summary
            </span>
          }
        />
        <DataTable
          bare
          summary
          columns={columns}
          rows={names}
          rowKey={(name) => name}
          minWidth={360}
          ariaLabel={t("screen.metrics.rows")}
          empty={{ title: t("common.empty"), icon: "activity" }}
        />
      </Card>
    </>
  );
}

/** The plot's height in pixels. */
const PLOT = 160;
/** Pixels at the left for the values of the gridlines. */
const GUTTER = 44;

/** The top of the scale rounded to 1, 2 or 5 of a power of ten; gridlines at the half (when whole) and the top. */
function scaleOf(largest: number): { max: number; ticks: number[] } {
  if (largest <= 1) return { max: 1, ticks: [1] };
  const power = 10 ** Math.floor(Math.log10(largest));
  const max = [1, 2, 5, 10].map((k) => k * power).find((top) => top >= largest) ?? 10 * power;
  return { max, ticks: max % 2 === 0 ? [max / 2, max] : [max] };
}

/**
 * The deltas of one counter between its samples, as bars on a zero line: plain
 * elements in a flex row (not an SVG, whose viewBox would scale the hairlines),
 * hairline gridlines at the half and the top with their values at the left. The
 * plot is one focus stop; the arrow keys walk its steps and the line above says
 * the step's moment and number (the window's total when none is chosen). The
 * same series stands beside it as a table for assistive technology.
 */
function DeltaChart({
  name,
  points,
  second,
  sampleInterval,
  retained,
}: {
  name: string;
  points: MetricsPoint[];
  /** The second series: muted, not the blue. */
  second?: boolean;
  sampleInterval: number;
  retained: number;
}) {
  const { t, i18n } = useTranslation();
  const [at, setAt] = useState<number | null>(null);
  // Said aloud only while the keys walk the steps, not when a pointer passes over the bars.
  const [walked, setWalked] = useState(false);
  // The focus came by the keyboard: the line says the keys.
  const [keys, setKeys] = useState(false);

  const d = deltas(points);
  const n = d.length;
  const scale = scaleOf(Math.max(0, ...d));
  const height = (v: number) => (v / scale.max) * PLOT;
  const sum = d.reduce((a, b) => a + b, 0);
  // A step ends at the later of its two samples.
  const momentOf = (i: number) => points[i + 1].t * 1000;
  const stamp = new Intl.DateTimeFormat(i18n.language, {
    day: "numeric",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
  const fill = second ? "color-mix(in oklch, var(--muted-foreground) 50%, transparent)" : "var(--primary)";
  // Many steps leave no room for the 2 px between them.
  const gap = n > 160 ? 0 : n > 80 ? 1 : 2;
  const shown = at === null ? null : { moment: momentOf(at), v: d[at] };
  const total = `Σ ${fmtNum(sum)}`;

  const move = (to: number) => setAt(Math.min(n - 1, Math.max(0, to)));
  const onKey = (e: ReactKeyboardEvent<HTMLDivElement>) => {
    if (e.key === "ArrowRight") move((at ?? -1) + 1);
    else if (e.key === "ArrowLeft") move((at ?? n) - 1);
    else if (e.key === "Home") move(0);
    else if (e.key === "End") move(n - 1);
    else if (e.key === "Escape" && at !== null) setAt(null);
    else return;
    setWalked(true);
    e.preventDefault();
  };

  return (
    <Card pad={false}>
      <CardHeader
        title={<span style={{ fontFamily: MONO, fontSize: 13, letterSpacing: 0, overflowWrap: "anywhere" }}>{name}</span>}
        actions={
          <span style={{ ...MUTED, fontSize: 12, lineHeight: "16px", whiteSpace: "nowrap" }}>
            <span style={{ fontFamily: MONO }}>Δ/{sampleInterval}s</span> · {t("screen.metrics.window", { n: retained })}
          </span>
        }
      />
      <div
        style={{ padding: "8px 16px 12px" }}
        onPointerLeave={(e) => {
          if (e.pointerType === "mouse") setAt(null);
        }}
      >
        <p
          aria-live={walked ? "polite" : "off"}
          style={{
            ...MUTED,
            margin: 0,
            minHeight: 20,
            display: "flex",
            flexWrap: "wrap",
            alignItems: "center",
            gap: "0 8px",
            fontSize: 12,
            lineHeight: "16px",
          }}
        >
          {shown ? (
            <>
              <span style={{ fontWeight: 500, color: "var(--foreground)" }}>{stamp.format(shown.moment)}</span>
              <span style={{ fontFamily: MONO, color: "var(--foreground)" }}>Δ {fmtNum(shown.v)}</span>
            </>
          ) : keys ? (
            t("screen.metrics.chartKeys")
          ) : (
            <span style={{ fontFamily: MONO }}>{total}</span>
          )}
        </p>

        <div
          role="group"
          tabIndex={0}
          aria-label={`${name}. ${total}. ${t("screen.metrics.chartKeys")}`}
          onKeyDown={onKey}
          onFocus={(e) => setKeys(e.currentTarget.matches(":focus-visible"))}
          onBlur={() => {
            setWalked(false);
            setKeys(false);
          }}
          style={{
            position: "relative",
            height: PLOT,
            marginTop: 8,
            paddingLeft: GUTTER,
            borderRadius: "var(--radius-sm)",
          }}
        >
          {scale.ticks.map((v) => (
            <span key={v} aria-hidden="true">
              <span
                style={{
                  position: "absolute",
                  left: GUTTER,
                  right: 0,
                  top: PLOT - height(v),
                  borderTop: "1px solid var(--rule)",
                }}
              />
              <span
                style={{
                  ...MUTED,
                  position: "absolute",
                  left: 0,
                  width: GUTTER - 8,
                  top: PLOT - height(v),
                  transform: "translateY(-50%)",
                  textAlign: "right",
                  fontSize: 11,
                  fontWeight: 600,
                  lineHeight: "16px",
                  whiteSpace: "nowrap",
                }}
              >
                {fmtNum(v)}
              </span>
            </span>
          ))}
          <span
            aria-hidden="true"
            style={{ position: "absolute", left: GUTTER, right: 0, bottom: 0, borderTop: "1px solid var(--border)" }}
          />
          <div aria-hidden="true" style={{ position: "relative", display: "flex", height: "100%", gap }}>
            {d.map((v, i) => (
              <div
                key={i}
                onPointerEnter={(e) => {
                  if (e.pointerType === "mouse") {
                    setWalked(false);
                    setAt(i);
                  }
                }}
                onClick={() => setAt(i)}
                style={{
                  position: "relative",
                  flex: "1 1 0",
                  minWidth: 0,
                  background: at === i ? "var(--elevated)" : undefined,
                }}
              >
                <span
                  style={{
                    position: "absolute",
                    left: 0,
                    right: 0,
                    bottom: 0,
                    height: v > 0 ? Math.max(2, height(v)) : 0,
                    background: fill,
                    borderRadius: "2px 2px 0 0",
                  }}
                />
              </div>
            ))}
          </div>
        </div>

        {n > 0 ? (
          <div
            aria-hidden="true"
            style={{
              ...MUTED,
              display: "flex",
              justifyContent: "space-between",
              gap: 8,
              paddingLeft: GUTTER,
              paddingTop: 4,
              fontSize: 11,
              lineHeight: "16px",
            }}
          >
            <span>{stamp.format(momentOf(0))}</span>
            <span>{stamp.format(momentOf(n - 1))}</span>
          </div>
        ) : null}

        <table className="u-sr-only">
          <caption>{name}</caption>
          <thead>
            <tr>
              <th scope="col">{t("screen.metrics.colTime")}</th>
              <th scope="col">{t("screen.metrics.colDelta")}</th>
            </tr>
          </thead>
          <tbody>
            {d.map((v, i) => (
              <tr key={i}>
                <th scope="row">{stamp.format(momentOf(i))}</th>
                <td>{fmtNum(v)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
