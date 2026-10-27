import type { CSSProperties, ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { useAsync } from "../util/useAsync";
import { fmtNum, fmtRelative } from "../util/format";
import { Btn, Card, ErrorCard, Missing, Skeleton, StateBadge, Term, ToneBadge, type Tone } from "../ui/primitives";
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

/** A machine's value: mono 12 px in full text. */
const MONO_VALUE: CSSProperties = { fontFamily: MONO, fontSize: 12, lineHeight: "16px", color: "var(--foreground)" };
/** What is said second, beside a value. */
const MUTED: CSSProperties = { color: "var(--muted-foreground)" };

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
        <Btn icon="refresh" loading={ready.loading || version.loading} onClick={checkNow}>
          {t("common.checkNow")}
        </Btn>
      }
    >
      {/* liveness — ungated */}
      <Card pad={false}>
        <dl style={{ margin: 0 }}>
          <KvRow label={t("screen.health.ready")} code="readyz">
            {ready.loading ? (
              <BadgeSkeleton />
            ) : (
              <>
                <StateBadge state={ready.data ? "ok" : "failing"} />
                <span style={MUTED}>
                  {ready.data ? t("screen.health.readyzOkDesc") : t("screen.health.readyzFailDesc")}
                </span>
              </>
            )}
          </KvRow>
          <KvRow label={t("screen.health.version")} code="version" last>
            {version.loading ? (
              <Skeleton width={120} height={12} />
            ) : (
              <>
                <span style={MONO_VALUE}>{version.data ? version.data.server : <Missing />}</span>
                <span style={{ ...MONO_VALUE, ...MUTED }}>
                  {version.data ? t("screen.health.api", { v: version.data.api }) : <Missing />}
                </span>
              </>
            )}
          </KvRow>
        </dl>
      </Card>

      {/* diagnostics */}
      <HealthBody />
    </Screen>
  );
}

/** The tone of the instance's own word for its state; a word it has not said before is unknown (muted, dashed). */
function statusTone(status: string): Tone {
  if (status === "ok") return "success";
  if (status === "degraded") return "warning";
  return "absent";
}

function HealthBody() {
  const { t } = useTranslation();

  const health = useAsync(() => api.admin.health(), []);

  if (health.error && !health.data) {
    return <ErrorCard message={health.error} onRetry={health.reload} retrying={health.loading} />;
  }

  const h = health.data;
  const pool = h?.db.pool;
  // While the diagnostics are read, each row keeps its place with a skeleton.
  const mono = (v: ReactNode, width = 96) =>
    h ? <span style={MONO_VALUE}>{v}</span> : <Skeleton width={width} height={12} />;

  return (
    <Card pad={false}>
      <dl style={{ margin: 0 }} aria-busy={health.loading || undefined}>
        <KvRow label={t("screen.health.status")} code="status">
          {h ? <StateBadge state={h.status} tone={statusTone(h.status)} /> : <BadgeSkeleton />}
        </KvRow>
        <KvRow label={t("screen.health.version")} code="version">{mono(h?.version)}</KvRow>
        <KvRow label={t("screen.health.uptime")} code="uptime">{mono(h ? fmtUptime(h.uptime_seconds, t("screen.health.uptimeDaysShort")) : null, 72)}</KvRow>
        <KvRow label={t("screen.health.dbBackend")} code="db.backend">{mono(h?.db.backend, 64)}</KvRow>
        <KvRow label={t("screen.health.dbReachable")} code="db.reachable">
          {h ? (
            <ToneBadge tone={h.db.reachable ? "success" : "destructive"}>
              {h.db.reachable ? t("screen.health.reachable") : t("screen.health.unreachable")}
            </ToneBadge>
          ) : (
            <BadgeSkeleton />
          )}
        </KvRow>
        <KvRow label={t("screen.health.dbPool")} code="db.pool" hint={t("screen.health.dbPoolHint")}>
          {mono(
            pool
              ? `${fmtNum(pool.in_use)} / ${fmtNum(pool.idle)} / ${fmtNum(pool.size)} / ${fmtNum(pool.max)}`
              : null,
          )}
        </KvRow>
        <KvRow label={t("screen.health.janitorInterval")} code="janitor.interval">
          {mono(h ? t("common.unitSeconds", { n: fmtNum(h.janitor.interval_seconds) }) : null, 48)}
        </KvRow>
        <KvRow label={t("screen.health.janitorLastRun")} code="janitor.last_run">
          {!h ? (
            <Skeleton width={72} height={12} />
          ) : h.janitor.last_run ? (
            <span>{fmtRelative(h.janitor.last_run)}</span>
          ) : (
            <Missing />
          )}
        </KvRow>
        <KvRow label={t("screen.health.tls")} code="tls">{mono(h?.tls, 64)}</KvRow>
        <KvRow label={t("screen.health.trustProxy")} code="trust_proxy" last>
          {h ? (
            <ToneBadge tone={h.trust_proxy ? "warning" : "neutral"}>
              {h.trust_proxy ? t("screen.health.on") : t("screen.health.off")}
            </ToneBadge>
          ) : (
            <BadgeSkeleton />
          )}
        </KvRow>
      </dl>
    </Card>
  );
}

/** The place of a status badge while its state is read. */
function BadgeSkeleton() {
  return <Skeleton width={64} height={20} radius="var(--radius-sm)" />;
}

/**
 * One line of a ruled key–value list: the key in plain words over its machine name (with an optional
 * legend for a compound value), the value beside it; at least 32 px, divided by --rule.
 */
function KvRow({
  label,
  code,
  hint,
  children,
  last,
}: {
  label: string;
  code: string;
  hint?: string;
  children: ReactNode;
  last?: boolean;
}) {
  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "minmax(112px, 240px) minmax(0, 1fr)",
        columnGap: 16,
        alignItems: "center",
        minHeight: 32,
        padding: "6px 16px",
        borderBottom: last ? undefined : "1px solid var(--rule)",
      }}
    >
      <dt
        style={{
          minWidth: 0,
          fontSize: 13,
          lineHeight: "18px",
          overflowWrap: "anywhere",
        }}
      >
        <Term label={label} code={code} />
        {hint ? <span style={{ display: "block", fontSize: 11, color: "var(--muted-foreground)" }}>{hint}</span> : null}
      </dt>
      <dd
        style={{
          margin: 0,
          minWidth: 0,
          display: "flex",
          flexWrap: "wrap",
          alignItems: "center",
          gap: "4px 12px",
          overflowWrap: "anywhere",
        }}
      >
        {children}
      </dd>
    </div>
  );
}
