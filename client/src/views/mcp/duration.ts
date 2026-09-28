// Native mcp_grant accepts a positive u32 number of seconds, or null.
export const MAX_GRANT_SECONDS = 0xffff_ffff;
export const DURATION_PRESETS = [1800, 3600, 28800, 86400] as const;
export const DURATION_UNITS = {
  minutes: 60,
  hours: 3600,
  days: 86400,
} as const;
export type DurationUnit = keyof typeof DURATION_UNITS;
export interface AccessDuration {
  choice: "forever" | "custom" | number;
  amount: string;
  unit: DurationUnit;
}

export function initialDuration(seconds: number | null): AccessDuration {
  if (seconds === null)
    return { choice: "forever", amount: "1", unit: "hours" };
  // The editor grants a new duration from save time. Round the remaining lease
  // to a whole minute instead of resetting every finite grant to 30 minutes.
  const minutes = Math.max(
    1,
    Math.min(Math.ceil(seconds / 60), Math.floor(MAX_GRANT_SECONDS / 60)),
  );
  const unit =
    minutes % 1440 === 0 ? "days" : minutes % 60 === 0 ? "hours" : "minutes";
  return {
    choice:
      DURATION_PRESETS.find((preset) => preset === minutes * 60) ?? "custom",
    amount: String((minutes * 60) / DURATION_UNITS[unit]),
    unit,
  };
}

/** undefined is invalid; null explicitly requests no expiry. */
export function durationSeconds(
  duration: AccessDuration,
): number | null | undefined {
  if (duration.choice === "forever") return null;
  const seconds =
    duration.choice === "custom"
      ? /^\d+$/.test(duration.amount)
        ? Number(duration.amount) * DURATION_UNITS[duration.unit]
        : NaN
      : duration.choice;
  return Number.isSafeInteger(seconds) &&
    seconds > 0 &&
    seconds <= MAX_GRANT_SECONDS
    ? seconds
    : undefined;
}

export function formatDuration(seconds: number, locale: string): string {
  const minutes = Math.max(0, Math.ceil(seconds / 60));
  const parts = [
    [Math.floor(minutes / 1440), "day"],
    [Math.floor((minutes % 1440) / 60), "hour"],
    [minutes % 60, "minute"],
  ] as const;
  return parts
    .filter(
      ([value, unit]) => value > 0 || (minutes === 0 && unit === "minute"),
    )
    .map(([value, unit]) =>
      new Intl.NumberFormat(locale, {
        style: "unit",
        unit,
        unitDisplay: "short",
      }).format(value),
    )
    .join(" ");
}
