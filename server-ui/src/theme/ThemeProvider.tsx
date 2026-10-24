import {
  createContext,
  useContext,
  useEffect,
  useLayoutEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { usePrefs } from "../store/prefs";
import type { Density, EffMode, Mode } from "./tokens";

interface ThemeCtx {
  /** The reader's choice: dark, light, or auto (as the system has it). */
  mode: Mode;
  /** The sheet actually shown. */
  effMode: EffMode;
  density: Density;
}

const Ctx = createContext<ThemeCtx | null>(null);

const DARK_QUERY = "(prefers-color-scheme: dark)";

function systemPrefersDark(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.matchMedia === "function" &&
    window.matchMedia(DARK_QUERY).matches
  );
}

/**
 * Chooses the sheet: sets `data-theme="dark|light"` on <html>, where
 * theme/global.css switches every token. "auto" follows the system, live.
 */
export function ThemeProvider({ children }: { children: ReactNode }) {
  const mode = usePrefs((s) => s.mode);
  const density = usePrefs((s) => s.density);

  const [systemDark, setSystemDark] = useState(systemPrefersDark);

  useEffect(() => {
    if (typeof window === "undefined" || !window.matchMedia) return;
    const mq = window.matchMedia(DARK_QUERY);
    const onChange = () => setSystemDark(mq.matches);
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);

  const effMode: EffMode = mode === "auto" ? (systemDark ? "dark" : "light") : mode;

  // Before paint, so a light sheet never flashes dark on load.
  useLayoutEffect(() => {
    const root = document.documentElement;
    root.dataset.theme = effMode;
    root.dataset.density = density;
    root.style.colorScheme = effMode;
  }, [effMode, density]);

  const value = useMemo<ThemeCtx>(() => ({ mode, effMode, density }), [mode, effMode, density]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useTheme(): ThemeCtx {
  const v = useContext(Ctx);
  if (!v) throw new Error("useTheme must be used within ThemeProvider");
  return v;
}
