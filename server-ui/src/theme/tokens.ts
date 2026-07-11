// Design tokens — exact port of unissh-client's tokens.ts (client/src/theme).
// buildPalette(mode, accent) yields the precise palette the prototype/mockup use.
// The admin panel consumes these as CSS custom properties (see ThemeProvider).

export const UI = "'Hanken Grotesk', system-ui, -apple-system, sans-serif";
export const MONO = "'JetBrains Mono', ui-monospace, SFMono-Regular, monospace";

export type Mode = "dark" | "light" | "auto";
export type EffMode = "dark" | "light";
export type AccentKey = "blue" | "green" | "violet" | "amber" | "rose";
export type Density = "cards" | "list";

export interface Palette {
  name: string;
  desk: string;
  bg0: string;
  bg1: string;
  bg2: string;
  bg3: string;
  bg4: string;
  line: string;
  line2: string;
  txt: string;
  txt2: string;
  txt3: string;
  accent: string;
  accent2: string;
  accentSoft: string;
  accentLine: string;
  green: string;
  amber: string;
  red: string;
  purple: string;
  glow: string;
  shadow: string;
}

export const DARK: Palette = {
  name: "dark",
  desk: "#08090d",
  bg0: "#0c0e14",
  bg1: "#10131c",
  bg2: "#161a26",
  bg3: "#1b2030",
  bg4: "#232a3d",
  line: "rgba(255,255,255,0.07)",
  line2: "rgba(255,255,255,0.13)",
  txt: "#eef0f7",
  txt2: "#9aa1b8",
  txt3: "#8b93ac",
  accent: "#5b8cff",
  accent2: "#7aa2ff",
  accentSoft: "rgba(91,140,255,0.15)",
  accentLine: "rgba(91,140,255,0.40)",
  green: "#3ad29f",
  amber: "#ffb454",
  red: "#ff6b80",
  purple: "#b98cff",
  glow: "rgba(91,140,255,0.22)",
  shadow: "0 24px 70px -12px rgba(0,0,0,0.7), 0 0 0 1px rgba(255,255,255,0.05)",
};

export const LIGHT: Palette = {
  name: "light",
  desk: "#dfe2ea",
  bg0: "#ffffff",
  bg1: "#f7f8fb",
  bg2: "#f0f2f7",
  bg3: "#eaedf4",
  bg4: "#e2e8fb",
  line: "rgba(15,20,40,0.09)",
  line2: "rgba(15,20,40,0.16)",
  txt: "#161a26",
  txt2: "#4a5066",
  txt3: "#5c6075",
  accent: "#3a6df0",
  accent2: "#2f5fe0",
  accentSoft: "rgba(58,109,240,0.12)",
  accentLine: "rgba(58,109,240,0.38)",
  green: "#16a571",
  amber: "#d98a1f",
  red: "#e0556a",
  purple: "#8c5cf0",
  glow: "rgba(58,109,240,0.16)",
  shadow: "0 24px 60px -14px rgba(20,26,45,0.28), 0 0 0 1px rgba(15,20,40,0.07)",
};

export function hexToRgb(h: string): [number, number, number] {
  const n = parseInt(h.slice(1), 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}
export function rgba(h: string, a: number): string {
  const [r, g, b] = hexToRgb(h);
  return `rgba(${r},${g},${b},${a})`;
}

interface AccentPreset {
  accent: string;
  accent2: string;
  purple: string;
}

export const ACCENTS: Record<AccentKey, AccentPreset> = {
  blue: { accent: "#5b8cff", accent2: "#7aa2ff", purple: "#b98cff" },
  green: { accent: "#2fd27a", accent2: "#5be0a0", purple: "#39c0c8" },
  violet: { accent: "#a87bff", accent2: "#c4a0ff", purple: "#ff8ad0" },
  amber: { accent: "#ff9f45", accent2: "#ffba70", purple: "#ff7a7a" },
  rose: { accent: "#fb6f92", accent2: "#ff93ad", purple: "#c08bff" },
};
export const ACCENTS_LIGHT: Record<AccentKey, AccentPreset> = {
  blue: { accent: "#3a6df0", accent2: "#2f5fe0", purple: "#8c5cf0" },
  green: { accent: "#16a571", accent2: "#0f8a5e", purple: "#1f9aa0" },
  violet: { accent: "#7c4dff", accent2: "#6a3aef", purple: "#d04ba0" },
  amber: { accent: "#d9821f", accent2: "#c0700f", purple: "#e05a5a" },
  rose: { accent: "#e05478", accent2: "#cf3f63", purple: "#9a5cf0" },
};

export const ACCENT_KEYS: AccentKey[] = ["blue", "green", "violet", "amber", "rose"];

export function buildPalette(mode: EffMode, accentKey: AccentKey = "blue"): Palette {
  const base = mode === "dark" ? DARK : LIGHT;
  const a = (mode === "dark" ? ACCENTS : ACCENTS_LIGHT)[accentKey] || ACCENTS.blue;
  const softA = mode === "dark" ? 0.15 : 0.12;
  const lineA = mode === "dark" ? 0.4 : 0.38;
  const glowA = mode === "dark" ? 0.22 : 0.16;
  return {
    ...base,
    accent: a.accent,
    accent2: a.accent2,
    purple: a.purple,
    accentSoft: rgba(a.accent, softA),
    accentLine: rgba(a.accent, lineA),
    glow: rgba(a.accent, glowA),
  };
}

/** Map a palette to the CSS custom properties the markup references via var(--…). */
export function paletteToVars(p: Palette): Record<string, string> {
  return {
    "--desk": p.desk,
    "--bg0": p.bg0,
    "--bg1": p.bg1,
    "--bg2": p.bg2,
    "--bg3": p.bg3,
    "--bg4": p.bg4,
    "--line": p.line,
    "--line2": p.line2,
    "--txt": p.txt,
    "--txt2": p.txt2,
    "--txt3": p.txt3,
    "--accent": p.accent,
    "--accent2": p.accent2,
    "--accentSoft": p.accentSoft,
    "--accentLine": p.accentLine,
    "--green": p.green,
    "--amber": p.amber,
    "--red": p.red,
    "--purple": p.purple,
    "--glow": p.glow,
    "--shadow": p.shadow,
  };
}
