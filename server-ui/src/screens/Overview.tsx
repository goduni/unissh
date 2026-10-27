import { useEffect, type CSSProperties, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { useMeta } from "../store/meta";
import { useUi, type Route } from "../store/ui";
import { useAsync } from "../util/useAsync";
import { fmtNum } from "../util/format";
import { MONO } from "../theme/tokens";
import {
  Card,
  CardHeader,
  EmptyState,
  ErrorCard,
  Missing,
  Skeleton,
  StatTile,
  StatTiles,
  ToneBadge,
  ZkBanner,
  type Tone,
} from "../ui/primitives";
import { Screen } from "./Screen";

/** A fact's name, in the panel's words; 12 px muted. */
const FACT_KEY: CSSProperties = { fontSize: 12, lineHeight: "16px", color: "var(--muted-foreground)" };
/** A machine's value: mono 12 px in full text. */
const MONO_VALUE: CSSProperties = { fontFamily: MONO, fontSize: 12, lineHeight: "20px", color: "var(--foreground)" };
/** A line of the attention card: the state as a word, then what it means. */
const ATTENTION_ROW: CSSProperties = {
  display: "flex",
  flexWrap: "wrap",
  alignItems: "center",
  gap: "4px 12px",
  minHeight: 36,
  padding: "6px 16px",
};

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

  const ov = adminOv.data;

  // The server in two facts: what runs, and whether it answers.
  const facts: { key: string; label: ReactNode; value: ReactNode }[] = [
    {
      key: "version",
      label: <span style={FACT_KEY}>{t("screen.overview.statusVersion")}</span>,
      value: version.data ? (
        <span style={MONO_VALUE}>{version.data.server}</span>
      ) : version.loading ? (
        <Skeleton width={72} height={14} />
      ) : (
        <Missing />
      ),
    },
    {
      key: "readyz",
      label: (
        <span style={FACT_KEY} title="readyz">
          {t("screen.overview.ready")}
        </span>
      ),
      value: ready.loading ? (
        <Skeleton width={64} height={20} radius="var(--radius-sm)" />
      ) : ready.data ? (
        <ToneBadge tone="success">{t("screen.health.state.ok")}</ToneBadge>
      ) : (
        <ToneBadge tone="destructive">{t("screen.health.state.failing")}</ToneBadge>
      ),
    },
  ];

  const tiles: { label: string; value: string; route: Route; note?: string }[] = [
    {
      label: t("nav.accounts"),
      value: ov ? String(ov.accounts) : "",
      route: "accounts",
      note: ov ? t("screen.overview.deltaOwners", { count: ov.owners }) : undefined,
    },
    {
      label: t("nav.devices"),
      value: ov ? String(ov.devices) : "",
      route: "devices",
      note: ov ? t("screen.overview.deltaSessions", { count: ov.active_sessions }) : undefined,
    },
    { label: t("nav.vaults"), value: ov ? String(ov.vaults) : "", route: "vaults" },
    { label: t("screen.overview.objects"), value: ov ? fmtNum(ov.objects) : "", route: "objects" },
    {
      label: t("nav.invites"),
      value: ov ? String(ov.pending_invites) : "",
      route: "invites",
      note: ov ? t("screen.overview.deltaPending") : undefined,
    },
    { label: t("screen.overview.nextSeq"), value: ov ? fmtNum(ov.next_seq) : "", route: "maint" },
  ];

  // Only what is wrong or about to be: a warning or a failure, a line each. A healthy readyz is already said in the
  // strip above; when nothing is wrong the card says so in one dashed row.
  const attention: { key: string; tone: Extract<Tone, "warning" | "destructive">; title: string; desc: string }[] =
    ready.loading || ready.data
      ? []
      : [
          {
            key: "readyz",
            tone: "destructive",
            title: t("screen.overview.readyzDownTitle"),
            desc: t("screen.overview.readyzDownDesc"),
          },
        ];

  return (
    <Screen title={t("screen.overview.title")} sub={t("screen.overview.sub")}>
      {/* The instance: a ruled strip of facts. */}
      <Card pad={false}>
        <dl style={{ display: "flex", flexWrap: "wrap", margin: 0 }}>
          {facts.map((f, i) => (
            <div
              key={f.key}
              style={{
                display: "grid",
                gap: 4,
                alignContent: "start",
                minWidth: 0,
                padding: "8px 16px",
                borderLeft: i > 0 ? "1px solid var(--rule)" : undefined,
              }}
            >
              <dt>{f.label}</dt>
              <dd style={{ margin: 0, display: "flex", alignItems: "center", minHeight: 20 }}>{f.value}</dd>
            </div>
          ))}
        </dl>
      </Card>

      {/* What needs attention: a line each, the state as a word, then what it means. */}
      <Card pad={false}>
        <CardHeader title={t("screen.overview.attentionTitle")} />
        {ready.loading ? (
          <div role="status" aria-busy="true" style={ATTENTION_ROW}>
            <span className="u-sr-only">{t("common.loading")}</span>
            <Skeleton width={96} height={20} radius="var(--radius-sm)" />
            <Skeleton width={160} height={12} />
          </div>
        ) : attention.length === 0 ? (
          // Absent, not broken: the compact dashed row, inset from the card's edges.
          <div style={{ padding: 8 }}>
            <EmptyState compact icon="check" title={t("screen.overview.attentionNone")} />
          </div>
        ) : (
          <ul style={{ listStyle: "none", margin: 0, padding: 0 }}>
            {attention.map((a, i) => (
              <li key={a.key} style={{ ...ATTENTION_ROW, borderTop: i > 0 ? "1px solid var(--rule)" : undefined }}>
                <ToneBadge tone={a.tone}>{a.title}</ToneBadge>
                <span style={{ minWidth: 0, color: "var(--muted-foreground)" }}>{a.desc}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>

      {/* The figures of the instance: one card, each leading to its section. */}
      {adminOv.error && !ov ? (
        <ErrorCard message={adminOv.error} onRetry={adminOv.reload} retrying={adminOv.loading} />
      ) : (
        <StatTiles cols={3}>
          {tiles.map((k) => (
            <StatTile key={k.route} label={k.label} value={k.value} loading={!ov} onClick={() => go(k.route)}>
              {k.note ? <span>{k.note}</span> : null}
            </StatTile>
          ))}
        </StatTiles>
      )}

      <ZkBanner>{t("zk.overview")}</ZkBanner>
    </Screen>
  );
}
