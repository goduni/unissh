// i18n bootstrap. Initializes the default i18next instance (react-i18next picks
// it up globally, so no <I18nextProvider> is required) and exposes language
// helpers. Language preference persists in localStorage["unissh.lang"], mirroring
// the ThemeProvider's unissh.* pattern.

import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import { locale } from "@tauri-apps/plugin-os";
import { ru } from "./locales/ru";
import { en } from "./locales/en";
import { logError } from "@/bridge/log";

export const LANGS = ["ru", "en"] as const;
export type Lang = (typeof LANGS)[number];

/** Native endonym shown in the language picker. Typed as Record<Lang,…> so adding
 *  a code to LANGS forces a label here and the selector auto-populates. */
export const LANG_LABELS: Record<Lang, string> = { ru: "Русский", en: "English" };

const LS_KEY = "unissh.lang";

function lsGet(): Lang | null {
  try {
    const v = localStorage.getItem(LS_KEY);
    return v === "ru" || v === "en" ? v : null;
  } catch {
    return null;
  }
}

/** Synchronous best-effort initial language (no async, safe for first paint). */
function detectInitial(): Lang {
  const stored = lsGet();
  if (stored) return stored;
  try {
    return navigator.language?.toLowerCase().startsWith("ru") ? "ru" : "en";
  } catch {
    return "ru";
  }
}

i18n.use(initReactI18next).init({
  resources: { ru: { translation: ru }, en: { translation: en } },
  lng: detectInitial(),
  fallbackLng: "ru",
  interpolation: { escapeValue: false }, // React already escapes
  returnNull: false,
});

try {
  document.documentElement.lang = i18n.language;
} catch {
  /* ignore */
}

export function currentLang(): Lang {
  return i18n.language?.toLowerCase().startsWith("ru") ? "ru" : "en";
}

/** Explicit user choice — persists and wins over system detection. */
export function setLang(l: Lang) {
  i18n.changeLanguage(l);
  try {
    localStorage.setItem(LS_KEY, l);
  } catch {
    /* ignore */
  }
  try {
    document.documentElement.lang = l;
  } catch {
    /* ignore */
  }
}

/**
 * First-run refinement from the OS locale (more authoritative than
 * navigator.language). Only applies when the user has not chosen explicitly;
 * does NOT persist, so it keeps tracking the system until the user picks.
 */
export async function refineLangFromSystem(): Promise<void> {
  if (lsGet()) return; // explicit preference wins
  try {
    const loc = await locale();
    const want: Lang = loc?.toLowerCase().startsWith("ru") ? "ru" : "en";
    if (want !== currentLang()) {
      await i18n.changeLanguage(want);
      try {
        document.documentElement.lang = want;
      } catch {
        /* ignore */
      }
    }
  } catch {
    /* ignore — keep the sync guess */
  }
}

// ── dev-only RU/EN key parity (plural suffixes stripped) ───────────────────
if ((import.meta as { env?: { DEV?: boolean } }).env?.DEV) {
  const PLURAL = /_(zero|one|two|few|many|other)$/;
  const flat = (o: Record<string, unknown>, p = "", acc = new Set<string>()) => {
    for (const [k, v] of Object.entries(o)) {
      const key = p ? `${p}.${k}` : k;
      if (v && typeof v === "object") flat(v as Record<string, unknown>, key, acc);
      else acc.add(key.replace(PLURAL, ""));
    }
    return acc;
  };
  const r = flat(ru);
  const e = flat(en);
  const missing = [...r].filter((k) => !e.has(k));
  const extra = [...e].filter((k) => !r.has(k));
  if (missing.length) logError(`[i18n] EN missing keys: ${missing.join(", ")}`);
  if (extra.length) logError(`[i18n] EN has extra keys: ${extra.join(", ")}`);
}

/** Translate a key known only at runtime (resolved from a typed data table:
 *  sort labels, nav items, tab labels, T_META, etc.). Bypasses literal-key
 *  checking — the constant table is the source of truth. Components that call
 *  this also subscribe via useTranslation, so they re-render on language change. */
export function tDyn(key: string, opts?: Record<string, unknown>): string {
  return (i18n.t as unknown as (k: string, o?: Record<string, unknown>) => string)(key, opts);
}

export { i18n };
export { useTranslation, Trans } from "react-i18next";
