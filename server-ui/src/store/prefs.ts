import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { Density, Mode } from "../theme/tokens";

export type PubkeyFormat = "truncate" | "full";
export type Lang = "ru" | "en";

interface PrefsState {
  mode: Mode;
  density: Density;
  lang: Lang;
  pubkeyFormat: PubkeyFormat;
  /** Base URL of the server instance. Empty → same origin as the panel. */
  instanceUrl: string;
  setMode: (m: Mode) => void;
  setDensity: (d: Density) => void;
  setLang: (l: Lang) => void;
  setPubkeyFormat: (f: PubkeyFormat) => void;
  setInstanceUrl: (u: string) => void;
}

export const usePrefs = create<PrefsState>()(
  persist(
    (set) => ({
      mode: "dark",
      density: "cards",
      lang: "ru",
      pubkeyFormat: "truncate",
      instanceUrl: "",
      setMode: (mode) => set({ mode }),
      setDensity: (density) => set({ density }),
      setLang: (lang) => set({ lang }),
      setPubkeyFormat: (pubkeyFormat) => set({ pubkeyFormat }),
      setInstanceUrl: (instanceUrl) => set({ instanceUrl }),
    }),
    {
      name: "unissh-admin-prefs",
      // Only the preferences are stored; an `accent` left by an older panel is
      // dropped on the next write.
      partialize: (s) => ({
        mode: s.mode,
        density: s.density,
        lang: s.lang,
        pubkeyFormat: s.pubkeyFormat,
        instanceUrl: s.instanceUrl,
      }),
    },
  ),
);
