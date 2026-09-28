import { useEffect, useId, useState } from "react";
import * as api from "@/bridge/api";
import { apiErrorMessage } from "@/bridge/types";
import { Btn } from "@/components/primitives";
import { useTranslation } from "@/i18n";
import { toast } from "@/store/toast";

export function McpRecordingSettings({ onSaved }: { onSaved: () => void }) {
  const { t } = useTranslation();
  const id = useId();
  const [value, setValue] = useState<api.McpRecordingPreferences | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let alive = true;
    void api.mcpRecordingPreferences().then(v => { if (alive) setValue(v); })
      .catch(e => { if (alive) toast(apiErrorMessage(e), "err"); });
    return () => { alive = false; };
  }, []);
  if (!value) return null;
  const valid = Number.isInteger(value.maxBytes) && value.maxBytes >= 16384 && value.maxBytes <= 524288 &&
    (value.retentionDays === null || Number.isInteger(value.retentionDays) && value.retentionDays >= 1 && value.retentionDays <= 3650);
  return <details className="recording-settings">
    <summary>{t("recordings.mcpSettings")}</summary>
    <form className="mcp-access-editor" onSubmit={e => {
      e.preventDefault();
      if (!valid || busy) return;
      setBusy(true);
      void api.setMcpRecordingPreferences(value).then(() => { toast(t("recordings.settingsSaved"), "ok"); onSaved(); })
        .catch(e => toast(apiErrorMessage(e), "err")).finally(() => setBusy(false));
    }}>
      <fieldset disabled={busy}>
        <label className="mcp-duration-amount"><span className="mcp-field-label">{t("recordings.captureLimit")}</span>
          <input type="number" min={16} max={512} step={1} required value={value.maxBytes ? value.maxBytes / 1024 : ""}
            onChange={e => setValue({ ...value, maxBytes: Number(e.target.value) * 1024 })} />
        </label>
        <fieldset className="mcp-duration"><legend className="mcp-field-label">{t("recordings.retention")}</legend>
          <div className="mcp-choice-group">
            <label className="mcp-choice"><input type="radio" name={id} checked={value.retentionDays === null}
              onChange={() => setValue({ ...value, retentionDays: null })} /><span>{t("recordings.keepForever")}</span></label>
            <label className="mcp-choice"><input type="radio" name={id} checked={value.retentionDays !== null}
              onChange={() => setValue({ ...value, retentionDays: 30 })} /><span>{t("recordings.keepDays")}</span></label>
          </div>
          {value.retentionDays !== null && <label className="mcp-duration-amount"><span className="mcp-field-label">{t("recordings.days")}</span>
            <input type="number" min={1} max={3650} step={1} required value={value.retentionDays || ""}
              onChange={e => setValue({ ...value, retentionDays: Number(e.target.value) })} /></label>}
        </fieldset>
        <p className="mcp-duration-hint">{t("recordings.settingsHint")}</p>
        {value.retentionDays !== null && <p className="mcp-duration-hint">{t("recordings.retentionHint")}</p>}
        <div><Btn type="submit" disabled={busy || !valid}>{t("common.save")}</Btn></div>
      </fieldset>
    </form>
  </details>;
}
