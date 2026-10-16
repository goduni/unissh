import { useEffect, useId, useState } from "react";
import { Btn } from "@/components/primitives";
import { useTranslation } from "@/i18n";
import { apiErrorMessage } from "@/bridge/types";
import { toast } from "@/store/toast";
import * as api from "@/bridge/mcp";

const MIB = 1024 * 1024;

/** Ranges mirror `GrantLimits::is_valid` / `BrokerLimits::is_valid` in the core. */
const within = (value: number, min: number, max: number) =>
  Number.isInteger(value) && value >= min && value <= max;
/** History must hold the work that can be in flight at once. */
const historyHoldsWork = (l: api.McpGrantLimits) =>
  l.retained_commands >= l.max_active_commands && l.retained_sessions >= l.max_connections;
export const validGrantLimits = (l: api.McpGrantLimits) =>
  within(l.max_connections, 1, 64) && within(l.max_active_commands, 1, 256) &&
  within(l.retained_commands, 1, 10000) && within(l.retained_sessions, 1, 1000) &&
  within(l.output_per_run_bytes / MIB, 1, 64) && historyHoldsWork(l);
const validAppLimits = (l: api.McpAppLimits) =>
  within(l.max_connections, 1, 256) && within(l.retained_commands, 16, 100000) &&
  within(l.output_total_bytes / MIB, 1, 1024);

function LimitField({ label, hint, value, min, max, scale = 1, onChange }: {
  label: string; hint: string; value: number; min: number; max: number; scale?: number; onChange: (value: number) => void;
}) {
  const { t } = useTranslation();
  const id = useId();
  const shown = value / scale;
  const invalid = !within(shown, min, max);
  return <label className="mcp-limit">
    <span className="mcp-field-label">{label}</span>
    <input type="number" min={min} max={max} step={1} required value={Number.isNaN(shown) ? "" : shown}
      aria-invalid={invalid} aria-describedby={invalid ? `${id}-error ${hint}` : hint}
      onChange={e => onChange(e.target.value === "" ? NaN : Number(e.target.value) * scale)} />
    {invalid && <span className="mcp-duration-error" id={`${id}-error`}>{t("mcp.limits.range", { min, max })}</span>}
  </label>;
}

/** Resource ceilings of one integration's grant, inside the access editor. */
export function McpGrantLimitsEditor({ value, onChange }: {
  value: api.McpGrantLimits; onChange: (value: api.McpGrantLimits) => void;
}) {
  const { t } = useTranslation();
  const id = useId();
  const hint = `${id}-hint`;
  const valid = validGrantLimits(value);
  // An invalid value disables saving; keep the reason in view.
  const [open, setOpen] = useState(!valid);
  const set = (key: keyof api.McpGrantLimits) => (v: number) => onChange({ ...value, [key]: v });
  return <details className="mcp-limits-details" open={open || !valid} onToggle={e => setOpen(e.currentTarget.open)}>
    <summary>{t("mcp.limits.grantTitle")}</summary>
    <fieldset className="mcp-limits" aria-label={t("mcp.limits.grantTitle")}>
      <LimitField label={t("mcp.limits.connections")} hint={hint} value={value.max_connections} min={1} max={64} onChange={set("max_connections")} />
      <LimitField label={t("mcp.limits.activeCommands")} hint={hint} value={value.max_active_commands} min={1} max={256} onChange={set("max_active_commands")} />
      <LimitField label={t("mcp.limits.retainedCommands")} hint={hint} value={value.retained_commands} min={1} max={10000} onChange={set("retained_commands")} />
      <LimitField label={t("mcp.limits.retainedSessions")} hint={hint} value={value.retained_sessions} min={1} max={1000} onChange={set("retained_sessions")} />
      <LimitField label={t("mcp.limits.outputPerCommand")} hint={hint} value={value.output_per_run_bytes} min={1} max={64} scale={MIB} onChange={set("output_per_run_bytes")} />
    </fieldset>
    {!historyHoldsWork(value) && <p className="mcp-duration-error" role="alert">{t("mcp.limits.historyTooSmall")}</p>}
    <p className="mcp-duration-hint" id={hint}>{t("mcp.limits.grantHint")}</p>
  </details>;
}

/** Application-wide ceilings shared by all integrations, in the server options. */
export function McpAppLimitsSettings() {
  const { t } = useTranslation();
  const id = useId();
  const hint = `${id}-hint`;
  const [value, setValue] = useState<api.McpAppLimits | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let alive = true;
    void api.mcpLimits().then(v => { if (alive) setValue(v); })
      .catch(e => { if (alive) toast(apiErrorMessage(e), "err"); });
    return () => { alive = false; };
  }, []);
  if (!value) return null;
  const valid = validAppLimits(value);
  const set = (key: keyof api.McpAppLimits) => (v: number) => setValue({ ...value, [key]: v });
  return <form className="mcp-app-limits" onSubmit={e => {
    e.preventDefault();
    if (!valid || busy) return;
    setBusy(true);
    void api.mcpSetLimits(value).then(() => toast(t("mcp.limits.saved"), "ok"))
      .catch(e => toast(apiErrorMessage(e), "err")).finally(() => setBusy(false));
  }}>
    <fieldset className="mcp-limits" disabled={busy}>
      <legend className="mcp-field-label">{t("mcp.limits.appTitle")}</legend>
      <LimitField label={t("mcp.limits.connections")} hint={hint} value={value.max_connections} min={1} max={256} onChange={set("max_connections")} />
      <LimitField label={t("mcp.limits.retainedCommands")} hint={hint} value={value.retained_commands} min={16} max={100000} onChange={set("retained_commands")} />
      <LimitField label={t("mcp.limits.outputTotal")} hint={hint} value={value.output_total_bytes} min={1} max={1024} scale={MIB} onChange={set("output_total_bytes")} />
    </fieldset>
    <p id={hint}>{t("mcp.limits.appHint")}</p>
    <div><Btn type="submit" disabled={busy || !valid}>{t("common.save")}</Btn></div>
  </form>;
}
