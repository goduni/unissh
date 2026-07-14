import React, {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import {
  AccentKey,
  AppThemeFamily,
  Density,
  HostsLayout,
  EffMode,
  Mode,
  Palette,
  resolveAppPalette,
  TERM_LINK,
  TERM_THEMES,
  TermTheme,
  TermThemePalette,
  validateTermThemeImport,
} from "./tokens";

interface ThemeCtx {
  p: Palette;
  mode: Mode;
  setMode: (m: Mode) => void;
  cycleMode: () => void;
  toggleTwin: () => void;
  family: AppThemeFamily;
  setFamily: (f: AppThemeFamily) => void;
  effMode: EffMode;
  sysDark: boolean;
  accent: AccentKey;
  setAccent: (a: AccentKey) => void;
  density: Density;
  setDensity: (d: Density) => void;
  hostsLayout: HostsLayout;
  setHostsLayout: (h: HostsLayout) => void;
  termThemeId: string;
  setTermThemeId: (id: string) => void;
  resetTermTheme: () => void;
  termTheme: TermTheme;
  /** Builtin + user-custom themes, in display order. */
  termThemes: TermTheme[];
  /** Just the user-created themes (those the editor can edit/delete). */
  customThemes: TermTheme[];
  addTermTheme: (palette: TermThemePalette) => TermTheme;
  updateTermTheme: (id: string, palette: TermThemePalette) => void;
  deleteTermTheme: (id: string) => void;
}

const Ctx = createContext<ThemeCtx | null>(null);

const CUSTOM_THEMES_KEY = "unissh.termThemes";

function newThemeId(): string {
  const rnd =
    typeof crypto !== "undefined" && crypto.randomUUID
      ? crypto.randomUUID()
      : Math.random().toString(36).slice(2);
  return `custom-${rnd}`;
}

/** Load + validate user themes from localStorage. Drops any malformed entry so a
 *  hand-edited store can never crash the app or poison theme resolution. */
function loadCustomThemes(): TermTheme[] {
  try {
    const raw = localStorage.getItem(CUSTOM_THEMES_KEY);
    if (!raw) return [];
    const arr = JSON.parse(raw);
    if (!Array.isArray(arr)) return [];
    const out: TermTheme[] = [];
    for (const item of arr) {
      const pal = validateTermThemeImport(item);
      if (!pal) continue;
      const id =
        item && typeof item === "object" && typeof (item as { id?: unknown }).id === "string"
          ? (item as { id: string }).id
          : newThemeId();
      out.push({ ...pal, id, custom: true });
    }
    return out;
  } catch {
    return [];
  }
}

function saveCustomThemes(list: TermTheme[]) {
  try {
    localStorage.setItem(CUSTOM_THEMES_KEY, JSON.stringify(list));
  } catch {
    /* ignore (private mode / quota) */
  }
}

function lsGet(key: string, fallback: string): string {
  try {
    return localStorage.getItem(key) ?? fallback;
  } catch {
    return fallback;
  }
}
function lsSet(key: string, val: string) {
  try {
    localStorage.setItem(key, val);
  } catch {
    /* ignore */
  }
}

// One-time store migration to the family + mode + per-mode-terminal-override model.
// Guarded by unissh.themeV, runs at import (before the provider mounts) so the state
// initializers read migrated values. The legacy default unissh.term="nebula" means
// "never chose one" → treat as unset (follow the theme link); any other value becomes
// a manual override on the side matching that theme's light/dark flag.
function migrateThemeStore() {
  try {
    const v = Number(lsGet("unissh.themeV", "1"));
    if (v >= 3) return;
    // v1 → v2: adopt the family + per-mode-terminal-override model. The legacy
    // default unissh.term="nebula" means "never chose one" → follow the theme link;
    // any other value becomes a manual override on the matching light/dark side.
    if (v < 2) {
      const legacyTerm = lsGet("unissh.term", "nebula");
      if (legacyTerm && legacyTerm !== "nebula") {
        const known = [...TERM_THEMES, ...loadCustomThemes()];
        const isLight = known.find((t) => t.id === legacyTerm)?.light ?? false;
        lsSet(isLight ? "unissh.termOverrideLight" : "unissh.termOverrideDark", legacyTerm);
      }
    }
    // v2 → v3: the minimalist "mono" family becomes the default. Flip the old
    // default (nebula) and any unset value to mono; preserve an explicit "candy"
    // (only ever a deliberate opt-in). The theme manager still lets a user switch
    // back at any time, so this is a reversible default change, not a lock-in.
    const fam = lsGet("unissh.appTheme", "");
    if (fam === "" || fam === "nebula") lsSet("unissh.appTheme", "mono");
    // Density split: the old unissh.density ("cards"|"list") was really a Hosts
    // LAYOUT choice → move it to unissh.hostsLayout, and reset the new spacing axis
    // (unissh.density = comfortable|compact) to its default.
    const oldDensity = lsGet("unissh.density", "");
    if (oldDensity === "cards" || oldDensity === "list") {
      lsSet("unissh.hostsLayout", oldDensity);
      lsSet("unissh.density", "comfortable");
    }
    lsSet("unissh.themeV", "3");
  } catch {
    /* best-effort: never block boot on a migration hiccup */
  }
}
migrateThemeStore();

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [mode, setModeState] = useState<Mode>(() => lsGet("unissh.mode", "auto") as Mode);
  const [family, setFamilyState] = useState<AppThemeFamily>(() => {
    // Default (and fallback for a hand-edited / forward-incompatible value) is now
    // "mono", the minimalist default family. An explicit "nebula"/"candy" is still
    // honored so the theme manager round-trips; an unknown value can never reach
    // resolveAppPalette / TERM_LINK (that would throw).
    const stored = lsGet("unissh.appTheme", "mono");
    return stored === "candy" || stored === "nebula" || stored === "mono" ? stored : "mono";
  });
  const [accent, setAccentState] = useState<AccentKey>(
    () => lsGet("unissh.accent", "blue") as AccentKey,
  );
  const [density, setDensityState] = useState<Density>(() =>
    // Spacing axis. A stale pre-v3 value ("cards"/"list") sanitizes to comfortable.
    lsGet("unissh.density", "comfortable") === "compact" ? "compact" : "comfortable",
  );
  const [hostsLayout, setHostsLayoutState] = useState<HostsLayout>(() =>
    lsGet("unissh.hostsLayout", "cards") === "list" ? "list" : "cards",
  );
  // Manual terminal-theme overrides, one per effective mode. null → follow the
  // theme's linked default (TERM_LINK). Empty string in storage means "no override".
  const [termOverrideDark, setTermOverrideDarkState] = useState<string | null>(
    () => lsGet("unissh.termOverrideDark", "") || null,
  );
  const [termOverrideLight, setTermOverrideLightState] = useState<string | null>(
    () => lsGet("unissh.termOverrideLight", "") || null,
  );
  const [customThemes, setCustomThemes] = useState<TermTheme[]>(() => loadCustomThemes());
  const [sysDark, setSysDark] = useState<boolean>(() => {
    try {
      return window.matchMedia("(prefers-color-scheme: dark)").matches;
    } catch {
      return true;
    }
  });

  useEffect(() => {
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const on = (e: MediaQueryListEvent) => setSysDark(e.matches);
    mq.addEventListener?.("change", on);
    return () => mq.removeEventListener?.("change", on);
  }, []);

  const setMode = (m: Mode) => {
    setModeState(m);
    lsSet("unissh.mode", m);
  };
  const setFamily = (f: AppThemeFamily) => {
    setFamilyState(f);
    lsSet("unissh.appTheme", f);
  };
  const setAccent = (a: AccentKey) => {
    setAccentState(a);
    lsSet("unissh.accent", a);
  };
  const setDensity = (d: Density) => {
    setDensityState(d);
    lsSet("unissh.density", d);
  };
  const setHostsLayout = (h: HostsLayout) => {
    setHostsLayoutState(h);
    lsSet("unissh.hostsLayout", h);
  };
  const cycleMode = () => {
    const order: Mode[] = ["light", "dark", "auto"];
    setMode(order[(order.indexOf(mode) + 1) % order.length]);
  };

  const addTermTheme = (palette: TermThemePalette): TermTheme => {
    // Guarantee a unique id against both builtins and existing custom themes, so
    // an (astronomically unlikely) generator collision can't silently overwrite one.
    const taken = new Set([...TERM_THEMES, ...customThemes].map((th) => th.id));
    let id = newThemeId();
    while (taken.has(id)) id = newThemeId();
    const theme: TermTheme = { ...palette, id, custom: true };
    setCustomThemes((cur) => {
      const next = [...cur, theme];
      saveCustomThemes(next);
      return next;
    });
    return theme;
  };
  const updateTermTheme = (id: string, palette: TermThemePalette) => {
    setCustomThemes((cur) => {
      const next = cur.map((t) => (t.id === id ? { ...palette, id, custom: true } : t));
      saveCustomThemes(next);
      return next;
    });
  };
  const deleteTermTheme = (id: string) => {
    setCustomThemes((cur) => {
      const next = cur.filter((t) => t.id !== id);
      saveCustomThemes(next);
      return next;
    });
    // If the deleted theme was an active override, clear it so the terminal falls
    // back to the theme's linked default for that mode (never a stale/dark builtin).
    if (termOverrideDark === id) {
      setTermOverrideDarkState(null);
      lsSet("unissh.termOverrideDark", "");
    }
    if (termOverrideLight === id) {
      setTermOverrideLightState(null);
      lsSet("unissh.termOverrideLight", "");
    }
  };

  const effMode: EffMode = mode === "auto" ? (sysDark ? "dark" : "light") : mode;
  // Flip the current effective mode's twin (also exits "auto"), preserving family.
  const toggleTwin = () => setMode(effMode === "dark" ? "light" : "dark");
  const p = useMemo(() => resolveAppPalette(family, effMode, accent), [family, effMode, accent]);
  const termThemes = useMemo(() => [...TERM_THEMES, ...customThemes], [customThemes]);

  // Effective terminal theme = the per-mode manual override, else the family's
  // linked default for the current effective mode. Fallbacks stay mode-aware so a
  // light UI never drops back to a dark builtin.
  const termOverride = effMode === "dark" ? termOverrideDark : termOverrideLight;
  const termThemeId = termOverride ?? (TERM_LINK[family] ?? TERM_LINK.nebula)[effMode];
  const termTheme = useMemo(
    () =>
      termThemes.find((t) => t.id === termThemeId) ??
      termThemes.find((t) => (effMode === "light" ? t.light : !t.light)) ??
      TERM_THEMES[0],
    [termThemes, termThemeId, effMode],
  );
  // A grid pick writes only the current mode's override; a mode flip re-derives the
  // other side from the link and never clobbers it.
  const setTermThemeId = (id: string) => {
    if (effMode === "dark") {
      setTermOverrideDarkState(id);
      lsSet("unissh.termOverrideDark", id);
    } else {
      setTermOverrideLightState(id);
      lsSet("unissh.termOverrideLight", id);
    }
  };
  const resetTermTheme = () => {
    if (effMode === "dark") {
      setTermOverrideDarkState(null);
      lsSet("unissh.termOverrideDark", "");
    } else {
      setTermOverrideLightState(null);
      lsSet("unissh.termOverrideLight", "");
    }
  };

  // reflect into CSS vars (focus ring follows accent, desk follows palette)
  useEffect(() => {
    const root = document.documentElement;
    root.style.setProperty("--uh-focus", p.accent);
    root.style.setProperty("--uh-desk", p.desk);
    document.body.style.background = p.desk;
    document.body.style.color = p.txt;
  }, [p]);

  const value: ThemeCtx = {
    p,
    mode,
    setMode,
    cycleMode,
    toggleTwin,
    family,
    setFamily,
    effMode,
    sysDark,
    accent,
    setAccent,
    density,
    setDensity,
    hostsLayout,
    setHostsLayout,
    termThemeId,
    setTermThemeId,
    resetTermTheme,
    termTheme,
    termThemes,
    customThemes,
    addTermTheme,
    updateTermTheme,
    deleteTermTheme,
  };

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useTheme(): ThemeCtx {
  const v = useContext(Ctx);
  if (!v) throw new Error("useTheme must be used within ThemeProvider");
  return v;
}

/** Convenience: just the palette (the most common need in views). */
export function usePalette(): Palette {
  return useTheme().p;
}
