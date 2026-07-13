import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { useUi } from "../store/ui";
import { useAsync } from "../util/useAsync";
import { Btn, Spinner, Tag, TextInput, Toggle } from "../ui/primitives";
import { KeysetGate } from "../ui/overlays";
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

export function Config() {
  const { t } = useTranslation();
  return (
    <Screen title={t("screen.config.title")} sub={t("screen.config.sub")}>
      <KeysetGate>
        <ConfigBody />
      </KeysetGate>
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
      <div style={{ display: "flex", justifyContent: "center", padding: 40 }}>
        <Spinner />
      </div>
    );
  }

  if (!cfg.data) return null;
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

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      {SECTION_ORDER.map((name) => {
        const section = data[name];
        const entries = Object.entries(section);
        return (
          <div
            key={name}
            style={{
              background: "var(--bg1)",
              border: "1px solid var(--line)",
              borderRadius: 14,
              overflow: "hidden",
            }}
          >
            <div
              style={{
                padding: "12px 18px",
                borderBottom: "1px solid var(--line)",
                fontFamily: MONO,
                fontSize: 13,
                fontWeight: 700,
                color: "var(--accent)",
              }}
            >
              [{name}]
            </div>
            {entries.map(([key, value]) => {
              const isValidate = name === "sync" && key === "validate_signatures";
              const isHotLimit =
                name === "limits" && (HOT_LIMIT_KEYS as readonly string[]).includes(key);
              return (
                <div
                  key={key}
                  style={{
                    display: "grid",
                    gridTemplateColumns: "2fr 1fr",
                    alignItems: "center",
                    padding: "11px 18px",
                    borderBottom: "1px solid var(--line)",
                  }}
                >
                  <span
                    style={{
                      fontFamily: MONO,
                      fontSize: 12.5,
                      color: "var(--txt2)",
                    }}
                  >
                    {key}
                  </span>
                  <span
                    style={{
                      display: "flex",
                      justifyContent: "flex-end",
                      fontFamily: MONO,
                      fontSize: 12.5,
                      color: "var(--txt)",
                      fontWeight: 600,
                    }}
                  >
                    {isValidate ? (
                      <Toggle
                        checked={Boolean(data.sync.validate_signatures)}
                        onChange={onToggleValidate}
                        label="validate_signatures"
                      />
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
                      <Tag tone="neutral">***</Tag>
                    ) : (
                      stringify(value)
                    )}
                  </span>
                </div>
              );
            })}
          </div>
        );
      })}

      <div style={{ fontSize: 12, color: "var(--txt3)" }}>
        {t("screen.config.hotReloadNote")}
      </div>
    </div>
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
    <span style={{ display: "flex", alignItems: "center", gap: 8, width: 200 }}>
      <TextInput value={raw} onChange={setRaw} mono />
      <Btn size="sm" variant="soft" loading={busy} onClick={apply}>
        {t("common.apply")}
      </Btn>
    </span>
  );
}
