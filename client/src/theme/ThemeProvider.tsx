import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import {
  AccentKey,
  AppThemeFamily,
  Density,
  DEFAULT_TERM_PREFS,
  DEFAULT_UI_SCALE,
  detectUiScale,
  HostsLayout,
  EffMode,
  isHexColor,
  Mode,
  Palette,
  resolveAppPalette,
  rootFontPx,
  sanitizeUiScale,
  TERM_FONTS,
  TERM_LINK,
  TERM_SCROLLBACK_LIMIT,
  TERM_SCROLLBACK_MIN,
  TERM_THEMES,
  TermFontId,
  TermPrefs,
  TermTheme,
  TermThemePalette,
  UiScale,
  validateTermThemeImport,
} from "./tokens";
import { isDesktopOs } from "@/bridge/platform";

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
  /** Interface scale, in percent. Sets the ROOT font size and nothing else —
   *  every migrated size is a `rem` off it, so no consumer reads this to size
   *  itself. Device-local, like density; never synced. */
  uiScale: UiScale;
  setUiScale: (s: UiScale) => void;
  hostsLayout: HostsLayout;
  setHostsLayout: (h: HostsLayout) => void;
  termThemeId: string;
  setTermThemeId: (id: string) => void;
  resetTermTheme: () => void;
  /** Terminal typography + behaviour. Independent of the terminal COLOUR theme. */
  termPrefs: TermPrefs;
  setTermPrefs: (patch: Partial<TermPrefs>) => void;
  resetTermPrefs: () => void;
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

const TERM_PREFS_KEY = "unissh.termPrefs";

/** Load prefs, dropping any field that is missing or malformed rather than the whole
 *  object — a hand-edited or forward-incompatible store degrades to defaults per field
 *  instead of resetting everything the user chose. */
function loadTermPrefs(): TermPrefs {
  try {
    const raw = localStorage.getItem(TERM_PREFS_KEY);
    if (!raw) return DEFAULT_TERM_PREFS;
    const o = JSON.parse(raw) as Partial<TermPrefs>;
    const num = (v: unknown, lo: number, hi: number, dflt: number): number =>
      typeof v === "number" && Number.isFinite(v) ? Math.min(hi, Math.max(lo, v)) : dflt;
    return {
      fontId:
        TERM_FONTS.some((f) => f.id === o.fontId) || o.fontId === "custom"
          ? (o.fontId as TermFontId)
          : DEFAULT_TERM_PREFS.fontId,
      fontCustom: typeof o.fontCustom === "string" ? o.fontCustom.slice(0, 64) : "",
      lineHeight: num(o.lineHeight, 1.0, 1.6, DEFAULT_TERM_PREFS.lineHeight),
      letterSpacing: num(o.letterSpacing, -1, 2, DEFAULT_TERM_PREFS.letterSpacing),
      cursor:
        o.cursor === "bar" || o.cursor === "underline" || o.cursor === "block"
          ? o.cursor
          : DEFAULT_TERM_PREFS.cursor,
      cursorBlink: typeof o.cursorBlink === "boolean" ? o.cursorBlink : true,
      fg: isHexColor(o.fg) ? (o.fg as string) : null,
      minContrast: o.minContrast === true,
      // Rounded and bounded only by what xterm itself accepts — a negative value makes the
      // option setter throw, and a fractional one sizes a ring buffer to a fraction of a
      // row. How much memory the chosen number costs is the user's call, not this clamp's.
      scrollback: Math.round(
        num(o.scrollback, TERM_SCROLLBACK_MIN, TERM_SCROLLBACK_LIMIT, DEFAULT_TERM_PREFS.scrollback),
      ),
    };
  } catch {
    return DEFAULT_TERM_PREFS;
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

const UI_SCALE_KEY = "unissh.uiScale";

/** The user's EXPLICIT interface scale, or `null` for "never said" — the same
 *  tri-state the custom title bar uses, and for the same reason: only the second
 *  state may be overridden by detection at boot. A present-but-garbage value
 *  (hand-edited, or written by a schema this build does not know) still counts as
 *  an answer — it sanitises to 100 % rather than reopening the question. */
function lsUiScale(): UiScale | null {
  try {
    const v = localStorage.getItem(UI_SCALE_KEY);
    return v === null ? null : sanitizeUiScale(v);
  } catch {
    return null;
  }
}

// One-time store migration to the family + mode + per-mode-terminal-override model.
// Guarded by unissh.themeV, runs at import (before the provider mounts) so the state
// initializers read migrated values. The legacy default unissh.term="nebula" means
// "never chose one" → treat as unset (follow the theme link); any other value becomes
// a manual override on the side matching that theme's light/dark flag.
/** Exported for the test: this migration was once dead for its entire audience
 *  (an early-return threshold left behind a version bump), and a rename that
 *  silently resets a user's chosen theme is invisible until someone complains. */
export function migrateThemeStore() {
  try {
    const v = Number(lsGet("unissh.themeV", "1"));
    if (v >= 4) return;
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
    // default (nebula) and any unset value to mono; an explicit named family
    // (only ever a deliberate opt-in) is preserved.
    //
    // Gated on the version, and that gate is load-bearing: without it, a later
    // step raising the ceiling would re-run this on someone who deliberately
    // picked nebula *after* v3 and silently flip them to mono.
    if (v < 3) {
      const fam = lsGet("unissh.appTheme", "");
      if (fam === "" || fam === "nebula") lsSet("unissh.appTheme", "mono");
      // Density split: the old unissh.density ("cards"|"list") was really a Hosts
      // LAYOUT choice → move it to unissh.hostsLayout, and reset the new spacing
      // axis (unissh.density = comfortable|compact) to its default.
      const oldDensity = lsGet("unissh.density", "");
      if (oldDensity === "cards" || oldDensity === "list") {
        lsSet("unissh.hostsLayout", oldDensity);
        lsSet("unissh.density", "comfortable");
      }
    }
    // v3 → v4: the "candy" family is replaced by "barbie". Without this the
    // rename drops anyone using it back to mono and leaves their terminal
    // override pointing at an id that no longer exists — two settings they chose
    // on purpose, reset in silence.
    if (lsGet("unissh.appTheme", "") === "candy") lsSet("unissh.appTheme", "barbie");
    for (const k of ["unissh.termOverrideLight", "unissh.termOverrideDark"]) {
      const t = lsGet(k, "");
      if (t === "candy-light") lsSet(k, "barbie-light");
      else if (t === "candy-dark") lsSet(k, "barbie-dark");
    }
    lsSet("unissh.themeV", "4");
  } catch {
    /* best-effort: never block boot on a migration hiccup */
  }
}
migrateThemeStore();

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [mode, setModeState] = useState<Mode>(() => lsGet("unissh.mode", "auto") as Mode);
  const [family, setFamilyState] = useState<AppThemeFamily>(() => {
    // Default (and fallback for a hand-edited / forward-incompatible value) is now
    // "mono", the minimalist default family. An explicit "nebula"/"barbie" is
    // still honored so the theme manager round-trips; an unknown value can never
    // reach resolveAppPalette / TERM_LINK (that would throw).
    const stored = lsGet("unissh.appTheme", "mono");
    return stored === "barbie" || stored === "nebula" || stored === "mono" ? stored : "mono";
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
  const [uiScale, setUiScaleState] = useState<UiScale>(() => lsUiScale() ?? DEFAULT_UI_SCALE);
  // Manual terminal-theme overrides, one per effective mode. null → follow the
  // theme's linked default (TERM_LINK). Empty string in storage means "no override".
  const [termOverrideDark, setTermOverrideDarkState] = useState<string | null>(
    () => lsGet("unissh.termOverrideDark", "") || null,
  );
  const [termOverrideLight, setTermOverrideLightState] = useState<string | null>(
    () => lsGet("unissh.termOverrideLight", "") || null,
  );
  const [customThemes, setCustomThemes] = useState<TermTheme[]>(() => loadCustomThemes());
  const [termPrefs, setTermPrefsState] = useState<TermPrefs>(loadTermPrefs);

  const setTermPrefs = useCallback((patch: Partial<TermPrefs>) => {
    setTermPrefsState((prev) => {
      const next = { ...prev, ...patch };
      try {
        localStorage.setItem(TERM_PREFS_KEY, JSON.stringify(next));
      } catch {
        /* ignore (private mode / quota) */
      }
      return next;
    });
  }, []);

  const resetTermPrefs = useCallback(() => {
    setTermPrefsState(DEFAULT_TERM_PREFS);
    try {
      localStorage.removeItem(TERM_PREFS_KEY);
    } catch {
      /* ignore */
    }
  }, []);

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
  const setUiScale = (v: UiScale) => {
    setUiScaleState(v);
    // Writing the key is also what ENDS boot-time detection, for good: from here
    // on the display never gets a vote, so plugging in a monitor cannot undo a
    // choice the user made by looking at the result.
    lsSet(UI_SCALE_KEY, String(v));
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

  // The one place the scale is expressed. Everything else is `rem`.
  useEffect(() => {
    document.documentElement.style.fontSize = `${rootFontPx(uiScale)}px`;
  }, [uiScale]);

  // First launch only: start a HiDPI user somewhere readable instead of at 100 %.
  // Desktop only — a phone already scales through the OS, and its device pixel
  // ratio says nothing about how big the type looks in the hand. Deliberately not
  // persisted (see lsUiScale): leaving the key unset keeps the answer live, so
  // moving the same profile between a scaled and an unscaled session keeps doing
  // the right thing instead of freezing whichever ran first.
  useEffect(() => {
    if (!isDesktopOs() || lsUiScale() !== null) return;
    let cancelled = false;
    void (async () => {
      try {
        const { getCurrentWindow } = await import("@tauri-apps/api/window");
        const factor = await getCurrentWindow().scaleFactor();
        if (cancelled) return;
        setUiScaleState(detectUiScale(factor, window.devicePixelRatio));
      } catch {
        /* no window to ask (browser preview), or the platform declined — 100 % */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

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
    uiScale,
    setUiScale,
    hostsLayout,
    setHostsLayout,
    termThemeId,
    setTermThemeId,
    resetTermTheme,
    termPrefs,
    setTermPrefs,
    resetTermPrefs,
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
