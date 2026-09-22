import { useId, useState } from "react";
import { useTranslation } from "@/i18n";

/** Native grant ceiling, independent of the access expiry. */
export function McpCommandLimit({ value, onChange }: {
  value: number; onChange: (milliseconds: number) => void;
}) {
  const { t } = useTranslation();
  const id = useId();
  const presets = [10, 60, 240];
  const [custom, setCustom] = useState(!presets.includes(value / 60000));
  return <fieldset className="mcp-duration" aria-describedby={`${id}-hint`}>
    <legend className="mcp-field-label">{t("mcp.commandLimit")}</legend>
    <div className="mcp-choice-group">
      {presets.map(minutes => <label className="mcp-choice" key={minutes}>
        <input type="radio" name={id} checked={!custom && value === minutes * 60000}
          onChange={() => { setCustom(false); onChange(minutes * 60000); }} />
        <span>{t("mcp.commandMinutes", { count: minutes })}</span>
      </label>)}
      <label className="mcp-choice"><input type="radio" name={id} checked={custom}
        onChange={() => setCustom(true)} /><span>{t("mcp.customDuration")}</span></label>
    </div>
    {custom && <label className="mcp-duration-amount">
      <span className="mcp-field-label">{t("mcp.durationUnits.minutes")}</span>
      <input type="number" min={1} max={1440} step={1} value={value ? value / 60000 : ""}
        aria-invalid={value < 60000 || value > 86400000}
        onChange={e => onChange(Number(e.target.value) * 60000)} />
    </label>}
    <p className="mcp-duration-hint" id={`${id}-hint`}>{t("mcp.commandLimitHint")}</p>
  </fieldset>;
}
