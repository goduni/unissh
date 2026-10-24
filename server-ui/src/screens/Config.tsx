import { useState, type CSSProperties } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { useUi } from "../store/ui";
import { useAsync } from "../util/useAsync";
import { Btn, Card, EmptyState, ErrorCard, Missing, Skeleton, Tag, TextInput, Toggle, ToneBadge } from "../ui/primitives";
import { Screen } from "./Screen";
import type { ConfigResp } from "../api/types";
import { MONO } from "../theme/tokens";

const SECTION_ORDER: (keyof ConfigResp)[] = [
  "server",
  "db",
  "limits",
  "sync",
  "session",
  "obs",
  "setup",
  "oidc",
  "ops",
];

const HOT_LIMIT_KEYS = ["max_object_bytes", "max_objects_per_push"] as const;
type HotLimitKey = (typeof HOT_LIMIT_KEYS)[number];

/** A line of the ruled list: the key in muted mono, the value beside it; at least 32 px. */
const ROW: CSSProperties = {
  display: "grid",
  gridTemplateColumns: "minmax(140px, 280px) minmax(0, 1fr)",
  columnGap: 16,
  alignItems: "center",
  minHeight: 32,
  padding: "4px 16px",
  borderTop: "1px solid var(--rule)",
};
const KEY: CSSProperties = {
  minWidth: 0,
  fontFamily: MONO,
  fontSize: 12,
  lineHeight: "16px",
  color: "var(--muted-foreground)",
  overflowWrap: "anywhere",
};
const VALUE: CSSProperties = {
  margin: 0,
  minWidth: 0,
  display: "flex",
  flexWrap: "wrap",
  alignItems: "center",
  gap: "4px 12px",
  fontFamily: MONO,
  fontSize: 12,
  lineHeight: "16px",
  color: "var(--foreground)",
  overflowWrap: "anywhere",
};
/** The head of a section: a 28 px row on --elevated at 40 %, the TOML table's name in mono. */
const GROUP_HEAD: CSSProperties = {
  display: "flex",
  alignItems: "center",
  minHeight: 28,
  margin: 0,
  padding: "0 16px",
  background: "color-mix(in oklch, var(--elevated) 40%, transparent)",
  fontFamily: MONO,
  fontSize: 12,
  fontWeight: 500,
  lineHeight: "16px",
  color: "var(--muted-foreground)",
};

export function Config() {
  const { t } = useTranslation();
  return (
    <Screen title={t("screen.config.title")} sub={t("screen.config.sub")}>
      <ConfigBody />
    </Screen>
  );
}

function ConfigBody() {
  const { t } = useTranslation();
  const toast = useUi((s) => s.toast);
  const askConfirm = useUi((s) => s.askConfirm);

  const cfg = useAsync(() => api.admin.config(), []);

  if (cfg.loading && !cfg.data) {
    return (
      <Card pad={false}>
        <div style={{ ...GROUP_HEAD, borderTop: 0 }}>
          <Skeleton width={64} height={12} />
        </div>
        {Array.from({ length: 6 }, (_, i) => (
          <div key={i} style={ROW}>
            <Skeleton width="60%" height={12} />
            <Skeleton width="40%" height={12} />
          </div>
        ))}
      </Card>
    );
  }

  if (!cfg.data) {
    return cfg.error ? <ErrorCard message={cfg.error} onRetry={cfg.reload} retrying={cfg.loading} /> : null;
  }
  const data = cfg.data;

  const onToggleValidate = (next: boolean) => {
    // Turning signature validation OFF is a security downgrade — confirm it, and
    // route through ConfirmDialog so a failed PUT surfaces instead of silently
    // leaving the toggle out of sync with the server.
    askConfirm({
      title: t("screen.config.validateTitle"),
      desc: next ? t("screen.config.validateOnDesc") : t("screen.config.validateOffDesc"),
      danger: !next,
      confirmLabel: next ? t("screen.config.validateOnBtn") : t("screen.config.validateOffBtn"),
      onConfirm: async () => {
        await api.admin.configPut({ validate_signatures: next });
        toast("success", t("screen.config.applied"));
        cfg.reload();
      },
    });
  };

  const stringify = (v: unknown): string => {
    if (typeof v === "boolean") return String(v);
    if (typeof v === "number") return String(v);
    if (v === null || v === undefined) return "—";
    if (typeof v === "string") return v;
    return JSON.stringify(v);
  };

  const validating = Boolean(data.sync.validate_signatures);

  return (
    <>
      {/* What a change does, said before the click. */}
      <p style={{ margin: 0, maxWidth: "72ch", fontSize: 14, lineHeight: "20px", color: "var(--muted-foreground)" }}>
        {t("screen.config.hotReloadNote")}
      </p>

      <Card pad={false}>
        {SECTION_ORDER.map((name, si) => {
          const section = data[name];
          const entries = Object.entries(section);
          const headId = `config-section-${name}`;
          return (
            <section key={name} aria-labelledby={headId}>
              <h2 id={headId} style={{ ...GROUP_HEAD, borderTop: si > 0 ? "1px solid var(--rule)" : undefined }}>
                [{name}]
              </h2>
              {entries.length === 0 ? (
                <div style={{ borderTop: "1px solid var(--rule)" }}>
                  <EmptyState compact flat title={t("common.empty")} />
                </div>
              ) : (
                <dl style={{ margin: 0 }}>
                  {entries.map(([key, value]) => {
                    const isValidate = name === "sync" && key === "validate_signatures";
                    const isHotLimit =
                      name === "limits" && (HOT_LIMIT_KEYS as readonly string[]).includes(key);
                    return (
                      <div key={key} style={ROW}>
                        <dt style={KEY}>{key}</dt>
                        <dd style={VALUE}>
                          {isValidate ? (
                            <>
                              <Toggle checked={validating} onChange={onToggleValidate} label="validate_signatures" />
                              <span>{String(validating)}</span>
                              {/* Trust is visible: a write the server no longer verifies is said in a word. */}
                              {!validating ? (
                                <ToneBadge tone="warning">{t("screen.config.validateOffBadge")}</ToneBadge>
                              ) : null}
                            </>
                          ) : isHotLimit ? (
                            <HotLimitEditor
                              field={key as HotLimitKey}
                              initial={value}
                              onApplied={() => {
                                toast("success", t("screen.config.applied"));
                                cfg.reload();
                              }}
                              onError={(msg) => toast("error", msg)}
                            />
                          ) : value === "***" ? (
                            <Tag tone="neutral" mono>
                              ***
                            </Tag>
                          ) : value === null || value === undefined || (typeof value === "string" && value.trim() === "") ? (
                            // Not set: an absent value (null, or an empty string such as an unset tls_cert) is the
                            // muted em dash, never a blank.
                            <Missing />
                          ) : (
                            stringify(value)
                          )}
                        </dd>
                      </div>
                    );
                  })}
                </dl>
              )}
            </section>
          );
        })}
      </Card>
    </>
  );
}

function HotLimitEditor({
  field,
  initial,
  onApplied,
  onError,
}: {
  field: HotLimitKey;
  initial: unknown;
  onApplied: () => void;
  onError: (msg: string) => void;
}) {
  const { t } = useTranslation();
  const [raw, setRaw] = useState(typeof initial === "number" ? String(initial) : "");
  const [busy, setBusy] = useState(false);

  const apply = () => {
    const n = Number(raw);
    if (!raw.trim() || !Number.isInteger(n) || n <= 0) {
      onError(t("screen.config.errIntPositive"));
      return;
    }
    setBusy(true);
    void api.admin
      .configPut(
        field === "max_object_bytes"
          ? { max_object_bytes: n }
          : { max_objects_per_push: n },
      )
      .then(() => {
        onApplied();
      })
      .catch((e) => {
        onError(e instanceof Error ? e.message : t("common.error"));
      })
      .finally(() => {
        setBusy(false);
      });
  };

  return (
    <span style={{ display: "flex", alignItems: "center", gap: 8, width: 240, maxWidth: "100%" }}>
      <TextInput value={raw} onChange={setRaw} mono inputMode="numeric" ariaLabel={field} style={{ height: 28 }} />
      <Btn size="sm" variant="outline" loading={busy} onClick={apply}>
        {t("common.apply")}
      </Btn>
    </span>
  );
}
