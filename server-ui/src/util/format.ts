// Formatting helpers for epoch-seconds timestamps and numbers.
import i18n from "../i18n";

export function fmtNum(n: number): string {
  return n.toLocaleString(i18n.language || "ru-RU");
}

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

/** Absolute local date-time from epoch seconds. */
export function fmtEpoch(sec: number | null | undefined): string {
  if (!sec) return "—";
  const d = new Date(sec * 1000);
  return d.toLocaleString(undefined, {
    year: "2-digit",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/** Date only (no time). */
export function fmtDate(sec: number | null | undefined): string {
  if (!sec) return "—";
  return new Date(sec * 1000).toLocaleDateString(undefined, {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  });
}

/** Relative "5 min ago" / "in 12 min" from epoch seconds. */
export function fmtRelative(sec: number | null | undefined, nowMs = Date.now()): string {
  if (!sec) return "—";
  const diff = sec * 1000 - nowMs; // >0 future
  const abs = Math.abs(diff);
  const m = Math.round(abs / 60000);
  const h = Math.round(abs / 3600000);
  const d = Math.round(abs / 86400000);
  let body: string;
  if (abs < 60000) body = i18n.t("format.relative.lessThanMinute");
  else if (m < 60) body = i18n.t("format.relative.minutes", { m });
  else if (h < 24) body = i18n.t("format.relative.hours", { h });
  else body = i18n.t("format.relative.days", { d });
  return diff >= 0 ? i18n.t("format.relative.future", { body }) : i18n.t("format.relative.past", { body });
}

/** Whether an epoch-seconds expiry is in the past. */
export function isExpired(sec: number | null | undefined, nowMs = Date.now()): boolean {
  return !!sec && sec * 1000 <= nowMs;
}
