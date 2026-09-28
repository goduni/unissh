import { useId } from "react";
import { useTranslation } from "@/i18n";
import {
  DURATION_PRESETS,
  DURATION_UNITS,
  MAX_GRANT_SECONDS,
  durationSeconds,
  type AccessDuration,
  type DurationUnit,
} from "./duration";

export function McpDurationPicker({
  value,
  onChange,
}: {
  value: AccessDuration;
  onChange: (value: AccessDuration) => void;
}) {
  const { t } = useTranslation();
  const id = useId();
  const invalid = durationSeconds(value) === undefined;
  const max = Math.floor(MAX_GRANT_SECONDS / DURATION_UNITS[value.unit]);
  const labels = [
    t("mcp.thirtyMinutes"),
    t("mcp.oneHour"),
    t("mcp.eightHours"),
    t("mcp.oneDay"),
  ];
  const choices = [
    ...DURATION_PRESETS.map((seconds, i) => ({
      value: seconds,
      label: labels[i],
    })),
    { value: "custom" as const, label: t("mcp.customDuration") },
    { value: "forever" as const, label: t("mcp.noExpiry") },
  ];
  return (
    <fieldset className="mcp-duration" aria-describedby={`${id}-hint`}>
      <legend className="mcp-field-label">{t("mcp.duration")}</legend>
      <div className="mcp-choice-group">
        {choices.map((choice) => (
          <label className="mcp-choice" key={choice.value}>
            <input
              type="radio"
              name={id}
              value={choice.value}
              checked={value.choice === choice.value}
              onChange={() => onChange({ ...value, choice: choice.value })}
            />
            <span>{choice.label}</span>
          </label>
        ))}
      </div>
      {value.choice === "custom" && (
        <div className="mcp-custom-duration">
          <label className="mcp-duration-amount">
            <span className="mcp-field-label">{t("mcp.durationAmount")}</span>
            <input
              type="number"
              inputMode="numeric"
              min={1}
              max={max}
              step={1}
              value={value.amount}
              aria-invalid={invalid}
              aria-describedby={invalid ? `${id}-error` : `${id}-hint`}
              onChange={(e) => onChange({ ...value, amount: e.target.value })}
            />
          </label>
          <fieldset className="mcp-duration-unit">
            <legend className="mcp-field-label">{t("mcp.durationUnit")}</legend>
            <div className="mcp-choice-group">
              {(Object.keys(DURATION_UNITS) as DurationUnit[]).map((unit) => (
                <label className="mcp-choice" key={unit}>
                  <input
                    type="radio"
                    name={`${id}-unit`}
                    checked={value.unit === unit}
                    onChange={() => onChange({ ...value, unit })}
                  />
                  <span>{t(`mcp.durationUnits.${unit}`)}</span>
                </label>
              ))}
            </div>
          </fieldset>
          {invalid && (
            <p className="mcp-duration-error" id={`${id}-error`} role="alert">
              {t("mcp.durationInvalid", { max })}
            </p>
          )}
        </div>
      )}
      <p className="mcp-duration-hint" id={`${id}-hint`}>
        {t(
          value.choice === "forever"
            ? "mcp.durationUnlimitedHint"
            : "mcp.durationStartsOnSave",
        )}
      </p>
    </fieldset>
  );
}
