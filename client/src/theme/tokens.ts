// Design tokens — exact port of the prototype's tokens.jsx.
// Palettes, accent presets, terminal themes, fonts. No CSS variables: the
// palette is a plain object consumed inline (and via ThemeProvider context),
// exactly like the prototype.

export const UI = "'Hanken Grotesk', system-ui, -apple-system, sans-serif";
export const MONO = "'JetBrains Mono', ui-monospace, SFMono-Regular, monospace";

// ── Geometry ───────────────────────────────────────────────────
// Colour was the only tokenised axis here for a long time, and geometry paid for
// it: the palette propagated to every surface automatically while every radius and
// inset stayed a bare literal, so the mobile shell drifted to a 12–18 radius scale
// against the desktop's 6–11 without anything to notice. These name the values the
// mono system actually uses. Reach for the primitives (Card, Btn, HairlineRow)
// first — they consume these; the tokens are for geometry outside a primitive.

/** Corner radii — a SCALE, not a continuum. The app had seventeen of these across
 *  211 sites (0,2,3,4,5,6,7,8,9,10,11,12,13,14,16,18,20): 8 and 9 both appeared
 *  ~40 times for near-identical roles, and 10/11/12/13 split four ways inside four
 *  pixels. None of that reads as a decision — it reads as noise. Eight steps, each
 *  with a role.
 *
 *  The card twin is density-aware: the compact end of the SPACING axis tightens the
 *  radius with the padding (see mono.Card). */
export const RADIUS = {
  /** Full-bleed rows / anything that must not round. */
  none: 0,
  /** The active-state tick / underline bar. */
  tick: 2,
  /** Tags and the smallest chips. */
  tag: 6,
  /** Icon buttons, menu rows, inputs, segmented controls. */
  chip: 8,
  /** Buttons. */
  ctl: 10,
  /** Popovers, dropdown menus, and the compact card. */
  menu: 12,
  cardCompact: 12,
  /** Cards and sheets. */
  card: 16,
  /** Modals — the only thing large enough to earn a larger corner. */
  modal: 20,
} as const;

/** Type scale. Twenty sizes lived here across ~480 sites, nine of them inside the
 *  10–14.5 band: 12 / 12.5 / 13 / 13.5 all carried the same secondary-label role,
 *  271 times, inside a pixel and a half. Half a pixel is not a decision anyone can
 *  read — but four of them mean two identical labels never quite agree, and that
 *  reads as an app assembled from parts. Integers only, one role each.
 *
 *  Steps land at ~1.08–1.2, which is the product register's range: this UI has far
 *  more type elements than a marketing page, so exaggerated contrast is noise. */
export const TEXT = {
  /** Badges, status words, the densest mono meta. */
  micro: 11,
  /** Secondary labels, table cells, chips. */
  small: 12,
  /** The base. Buttons, rows, most body copy in the app. */
  base: 13,
  /** Emphasised body — a row's primary name. */
  body: 14,
  /** Prominent single-line text: empty-state titles, a frame's header, the command
   *  input. (Inputs are force-floored at 16 on coarse pointers anyway — anything
   *  smaller makes iOS zoom the page on focus. See theme.css.) */
  lead: 16,
  /** Section heading. */
  h3: 19,
  /** View heading, narrow. */
  h2: 24,
  /** View heading. */
  h1: 28,
} as const;

/** Layout insets. */
export const SPACE = {
  /** A view's horizontal content gutter. */
  gutter: 22,
  /** The same gutter on a phone or a narrowed window, where 22 wastes scarce width. */
  gutterNarrow: 16,
} as const;

export const SIZE = {
  /** Minimum touch target. WCAG 2.5.5 asks 44x44 CSS px; Apple HIG and Material
   *  agree. Anything interactive on a touch surface must clear this. */
  tapMin: 44,
} as const;

export type Mode = "dark" | "light" | "auto";
export type EffMode = "dark" | "light";
export type AccentKey = "blue" | "green" | "violet" | "amber" | "rose";
/** Global SPACING axis (row height / padding / hairline-vs-shadow). Independent of
 *  the Hosts card/list layout and of the mobile touch-shell platform flag. */
export type Density = "comfortable" | "compact";
/** Hosts list rendering: a card grid vs a flat row list. A per-view layout choice,
 *  NOT the spacing density. */
export type HostsLayout = "cards" | "list";
export type AppThemeFamily = "mono" | "nebula" | "candy";

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
  /** The accent at text weight: the same hue, darkened (light) or lightened (dark)
   *  until it clears AA on EVERY surface tier (bg0..bg4). `accent` is a FILL
   *  colour — it sizes buttons,
   *  ticks and borders, where contrast rules don't apply — and it is near-ink in the
   *  mono family but saturated in nebula/candy, so using it for a LABEL passes in the
   *  default theme and quietly fails in the opt-in ones. Any accent-coloured text
   *  must use this. Derived, never authored; see accentTextFor. */
  accentText: string;
  accent2: string;
  accentSoft: string;
  accentLine: string;
  green: string;
  amber: string;
  red: string;
  purple: string;
  glow: string;
  shadow: string;
  /** Optional holo gradient for opt-in chrome (e.g. the primary button). The solid
   *  `accent` is still used everywhere a gradient isn't valid (borders, shadows). */
  accentGradient?: string;
  /** Label/ink colour for text sitting ON the accent (or accentGradient) surface —
   *  the primary button chrome. White where it clears WCAG AA (≥4.5:1), otherwise
   *  a dark theme ink. Consumers fall back to "#fff" when absent. */
  accentInk?: string;
  /** Label/ink colour for text sitting ON the danger `red` surface (the danger
   *  button chrome). Same AA rule as accentInk, computed against `red` — the
   *  accent ink routinely fails on red (e.g. candy-light's plum on #d02545 is
   *  3.05:1). Consumers fall back to "#fff" when absent. */
  dangerInk?: string;
  /** Modal / overlay backdrop scrim for this palette (light/dark-aware). Consumers
   *  fall back to a neutral rgba when absent. */
  scrim?: string;
}

/** A palette as authored. `accentText` is DERIVED from the authored colours rather
 *  than hand-picked, so retuning an accent or a surface can't silently drop it out
 *  of AA. buildPalette / resolveAppPalette — the only ways the app obtains a
 *  palette — add it; nothing else should construct a Palette by hand. */
export type AuthoredPalette = Omit<Palette, "accentText">;

// ── App palettes ───────────────────────────────────────────────
export const DARK: AuthoredPalette = {
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
  txt3: "#8b93ac", // AA-contrast secondary text (was #646c85, ~3.4:1 — failed WCAG)
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

export const LIGHT: AuthoredPalette = {
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
  txt3: "#5c6075", // AA-contrast secondary text (was #727892, ~4.36:1 — under 4.5:1)
  accent: "#3a6df0",
  accent2: "#2f5fe0",
  accentSoft: "rgba(58,109,240,0.12)",
  accentLine: "rgba(58,109,240,0.38)",
  green: "#0f7e52", // AA-contrast on bg0–bg2 (was #16a571, ~3.2:1 on white as text)
  amber: "#96600e", // AA-contrast on bg0–bg2 (was #d98a1f, ~2.8:1 on white as text)
  red: "#c9334b", // AA-contrast on bg0–bg2 (was #e0556a, ~3.7:1 on white as text)
  purple: "#8c5cf0",
  glow: "rgba(58,109,240,0.16)",
  shadow: "0 24px 60px -14px rgba(20,26,45,0.28), 0 0 0 1px rgba(15,20,40,0.07)",
};

// ── Candy Holo — pink-dominant light hero + deep-plum dark twin ─
// A "named" theme that owns its full surfaces (not just an accent). Light-terminal
// ANSI and a couple of tokens are deepened for WCAG legibility on the pale pink.
export const CANDY_LIGHT: AuthoredPalette = {
  name: "candy-light",
  desk: "#ffe3f4",
  bg0: "#fff2fb",
  bg1: "#ffffff",
  bg2: "#fff0f9",
  bg3: "#ffe3f2",
  bg4: "#ffd0ea",
  line: "rgba(176,106,255,0.14)",
  line2: "rgba(176,106,255,0.30)",
  txt: "#4a1440",
  txt2: "#8a3a72",
  txt3: "#985982", // AA-contrast on bg0–bg2 (was #a2628c, ~4.1:1 on the pale pink)
  accent: "#ff2f9e",
  accent2: "#ff5fb8",
  accentSoft: "rgba(255,47,158,0.12)",
  accentLine: "rgba(255,47,158,0.40)",
  green: "#0d7a51", // AA-contrast on bg0–bg2 (was #12a06a, ~3.1:1 as text)
  amber: "#96600e", // AA-contrast on bg0–bg2 (was #cc7d1c, ~3.0:1 as text)
  red: "#d02545", // AA-contrast on bg0–bg2 (was #e0294f, ~4.2:1 as text)
  purple: "#9b5fff",
  glow: "rgba(255,47,158,0.28)",
  shadow: "0 18px 50px -12px rgba(176,106,255,0.28), 0 0 0 1px rgba(176,106,255,0.10)",
  accentGradient: "linear-gradient(90deg,#ff5fb8,#b06aff 55%,#5ec7ff)",
  // Deep plum ink: ≥4.65:1 on every gradient stop (#ff5fb8 / #b06aff / #5ec7ff)
  // and on the solid accent — white only reached ~1.9:1 on the cyan end.
  accentInk: "#3d1035",
  dangerInk: "#ffffff", // white clears AA on this red (5.21:1); the plum ink is 2.75:1
};

export const CANDY_DARK: AuthoredPalette = {
  name: "candy-dark",
  desk: "#180a1e",
  bg0: "#1e0f26",
  bg1: "#251330",
  bg2: "#2c1638",
  bg3: "#351a44",
  bg4: "#43215a",
  line: "rgba(255,140,220,0.10)",
  line2: "rgba(255,140,220,0.22)",
  txt: "#fbeaf6",
  txt2: "#d3a8cf",
  txt3: "#aa7ead", // AA-contrast down to bg3 (was #a578a8, ~4.6:1 on bg2 — no headroom)
  accent: "#ff5fb8",
  accent2: "#ff86cc",
  accentSoft: "rgba(255,95,184,0.15)",
  accentLine: "rgba(255,95,184,0.42)",
  green: "#4fe0b0",
  amber: "#ffcf6a",
  red: "#ff6b8f",
  purple: "#b06aff",
  glow: "rgba(176,106,255,0.35)",
  shadow: "0 24px 70px -12px rgba(120,40,160,0.5), 0 0 0 1px rgba(255,140,220,0.08)",
  accentGradient: "linear-gradient(90deg,#ff5fb8,#b06aff 55%,#5ec7ff)",
  accentInk: "#3d1035", // same ink as candy-light — the gradient is shared
  dangerInk: "#3d1035", // white fails AA on this pastel red (2.71:1); plum is 5.86:1
};

// ── Mono — the minimalist DEFAULT family ───────────────────────
// Near-monochrome: colour carries MEANING ONLY (green/amber/red status + one
// neutral accent). No gradients; the 5-level bg ladder collapses to base (bg0/bg1)
// + a barely-elevated panel/hover/selected tier (bg2..bg4 within ~2% L of base) so
// existing bgN consumers render flat. Every txt/semantic pair is AA-verified on
// base AND elevated in both twins (scripts/mono-contrast golden check).
export const MONO_LIGHT: AuthoredPalette = {
  name: "mono-light",
  desk: "#e7e8ec",
  bg0: "#ffffff",
  bg1: "#ffffff",
  bg2: "#f7f8fa",
  bg3: "#f1f2f5",
  bg4: "#eceef2",
  line: "rgba(20,24,40,0.09)",
  line2: "rgba(20,24,40,0.15)",
  txt: "#191b22",
  txt2: "#545863", // AA on white & bg2..bg4
  txt3: "#676a73", // AA (≥4.5:1) on white AND on bg2 (#f7f8fa)
  accent: "#22242c",
  accent2: "#111319",
  accentSoft: "rgba(34,36,44,0.06)",
  accentLine: "rgba(34,36,44,0.22)",
  green: "#0c6e45", // AA (≥4.5:1) as text on bg0..bg4
  amber: "#8f5e10",
  red: "#c22e45", // AA (≥4.5:1) as text on bg0..bg4
  purple: "#676a73", // decorative purple → neutral in mono
  glow: "rgba(34,36,44,0.05)",
  shadow: "0 8px 26px -14px rgba(30,36,55,0.22), 0 0 0 1px rgba(20,24,40,0.05)",
  accentInk: "#ffffff", // on #22242c ≈ 15:1
  dangerInk: "#ffffff", // on #c9334b ≈ 5.17:1
  scrim: "rgba(18,22,38,0.42)",
};

export const MONO_DARK: AuthoredPalette = {
  name: "mono-dark",
  desk: "#08090c",
  bg0: "#0f1116",
  bg1: "#0f1116",
  bg2: "#14161d",
  bg3: "#1b1e28",
  bg4: "#232734",
  line: "rgba(255,255,255,0.07)",
  line2: "rgba(255,255,255,0.13)",
  txt: "#e9ebf1",
  txt2: "#9aa0b2",
  txt3: "#8b93ac", // AA on bg0..bg4 (proven value from the shipped DARK palette)
  accent: "#e9ebf1", // near-white "ink" accent
  accent2: "#ffffff",
  accentSoft: "rgba(233,235,241,0.10)",
  accentLine: "rgba(233,235,241,0.24)",
  green: "#3ad29f",
  amber: "#e0a860",
  red: "#ff6b80",
  purple: "#9aa0b2", // decorative purple → neutral in mono
  glow: "rgba(233,235,241,0.08)",
  shadow: "0 12px 34px -18px rgba(0,0,0,0.7), 0 0 0 1px rgba(255,255,255,0.05)",
  accentInk: "#12141a", // dark ink on the near-white accent
  dangerInk: "#12141a", // dark ink on pastel red #ff6b80 (white fails AA there)
  scrim: "rgba(0,0,0,0.6)",
};

// ── Terminal themes (classic + custom) ─────────────────────────
export interface TermTheme {
  id: string;
  name: string;
  custom?: boolean;
  light?: boolean;
  bg: string;
  fg: string;
  dimc: string;
  green: string;
  blue: string;
  cyan: string;
  red: string;
  yellow: string;
  purple: string;
  /** ANSI white / brightWhite. Decoupled from `fg` so "white" text renders truly
   *  white instead of the soft theme foreground. Optional for back-compat with
   *  themes saved before this field existed — defaults to pure white. */
  white?: string;
  sel: string;
  /** Optional explicit ANSI black and bright variants. When absent, termToXterm
   *  derives them from the base palette (real dark `black`, lifted brights), so
   *  custom/imported themes never have to define them. */
  black?: string;
  brightBlack?: string;
  brightRed?: string;
  brightGreen?: string;
  brightYellow?: string;
  brightBlue?: string;
  brightMagenta?: string;
  brightCyan?: string;
  brightWhite?: string;
}

export const TERM_THEMES: TermTheme[] = [
  { id: "nebula", name: "UniSSH Nebula", custom: true, bg: "#0c0e16", fg: "#d8def2", dimc: "#565d78", green: "#3ad29f", blue: "#5b8cff", cyan: "#57c7ff", red: "#ff6b8b", yellow: "#ffcf6b", purple: "#b98cff", white: "#ffffff", sel: "rgba(91,140,255,0.22)" },
  { id: "dracula", name: "Dracula", bg: "#282a36", fg: "#f8f8f2", dimc: "#6272a4", green: "#50fa7b", blue: "#bd93f9", cyan: "#8be9fd", red: "#ff5555", yellow: "#f1fa8c", purple: "#ff79c6", white: "#ffffff", sel: "rgba(189,147,249,0.25)" },
  { id: "nord", name: "Nord", bg: "#2e3440", fg: "#d8dee9", dimc: "#4c566a", green: "#a3be8c", blue: "#88c0d0", cyan: "#8fbcbb", red: "#bf616a", yellow: "#ebcb8b", purple: "#b48ead", white: "#ffffff", sel: "rgba(136,192,208,0.22)" },
  { id: "gruvbox", name: "Gruvbox Dark", bg: "#282828", fg: "#ebdbb2", dimc: "#928374", green: "#b8bb26", blue: "#83a598", cyan: "#8ec07c", red: "#fb4934", yellow: "#fabd2f", purple: "#d3869b", white: "#ffffff", sel: "rgba(131,165,152,0.22)" },
  { id: "solarized", name: "Solarized Dark", bg: "#002b36", fg: "#93a1a1", dimc: "#586e75", green: "#859900", blue: "#268bd2", cyan: "#2aa198", red: "#dc322f", yellow: "#b58900", purple: "#6c71c4", white: "#ffffff", sel: "rgba(38,139,210,0.22)" },
  { id: "tokyo", name: "Tokyo Night", bg: "#1a1b26", fg: "#c0caf5", dimc: "#565f89", green: "#9ece6a", blue: "#7aa2f7", cyan: "#7dcfff", red: "#f7768e", yellow: "#e0af68", purple: "#bb9af7", white: "#ffffff", sel: "rgba(122,162,247,0.22)" },
  { id: "solight", name: "Solarized Light", light: true, bg: "#fdf6e3", fg: "#586e75", dimc: "#93a1a1", green: "#859900", blue: "#268bd2", cyan: "#2aa198", red: "#dc322f", yellow: "#b58900", purple: "#6c71c4", white: "#eee8d5", sel: "rgba(38,139,210,0.15)" },
  { id: "candy-light", name: "Candy Holo Light", light: true, bg: "#fff2fb", fg: "#4a1440", dimc: "#a2628c", green: "#0e8055", blue: "#8552db", cyan: "#1c7994", red: "#e0294f", yellow: "#cc7d1c", purple: "#cf2680", white: "#4a1440", sel: "rgba(217,40,134,0.20)" },
  { id: "candy-dark", name: "Candy Holo Dark", bg: "#160a1e", fg: "#fbeaf6", dimc: "#a578a8", green: "#4fe0b0", blue: "#b06aff", cyan: "#5ec7ff", red: "#ff6b8f", yellow: "#ffcf6a", purple: "#ff5fb8", white: "#fbeaf6", sel: "rgba(255,95,184,0.28)" },
  { id: "catppuccin-mocha", name: "Catppuccin Mocha", bg: "#1e1e2e", fg: "#cdd6f4", dimc: "#585b70", green: "#a6e3a1", blue: "#89b4fa", cyan: "#94e2d5", red: "#f38ba8", yellow: "#f9e2af", purple: "#cba6f7", white: "#bac2de", sel: "rgba(137,180,250,0.24)" },
  { id: "catppuccin-latte", name: "Catppuccin Latte", light: true, bg: "#eff1f5", fg: "#4c4f69", dimc: "#9ca0b0", green: "#40a02b", blue: "#1e66f5", cyan: "#179299", red: "#d20f39", yellow: "#df8e1d", purple: "#8839ef", white: "#5c5f77", sel: "rgba(30,102,245,0.16)" },
  { id: "rose-pine", name: "Rosé Pine", bg: "#191724", fg: "#e0def4", dimc: "#6e6a86", green: "#31748f", blue: "#9ccfd8", cyan: "#ebbcba", red: "#eb6f92", yellow: "#f6c177", purple: "#c4a7e7", white: "#e0def4", sel: "rgba(196,167,231,0.24)" },
  { id: "rose-pine-dawn", name: "Rosé Pine Dawn", light: true, bg: "#faf4ed", fg: "#575279", dimc: "#9893a5", green: "#286983", blue: "#56949f", cyan: "#d7827e", red: "#b4637a", yellow: "#ea9d34", purple: "#907aa9", white: "#575279", sel: "rgba(144,122,169,0.18)" },
  { id: "everforest-dark", name: "Everforest Dark", bg: "#2d353b", fg: "#d3c6aa", dimc: "#859289", green: "#a7c080", blue: "#7fbbb3", cyan: "#83c092", red: "#e67e80", yellow: "#dbbc7f", purple: "#d699b6", white: "#d3c6aa", sel: "rgba(127,187,179,0.22)" },
  { id: "one-dark", name: "One Dark", bg: "#282c34", fg: "#abb2bf", dimc: "#5c6370", green: "#98c379", blue: "#61afef", cyan: "#56b6c2", red: "#e06c75", yellow: "#e5c07b", purple: "#c678dd", white: "#ffffff", sel: "rgba(97,175,239,0.22)" },
  { id: "kanagawa-wave", name: "Kanagawa Wave", bg: "#1f1f28", fg: "#dcd7ba", dimc: "#727169", green: "#98bb6c", blue: "#7e9cd8", cyan: "#7aa89f", red: "#e82424", yellow: "#e6c384", purple: "#957fb8", white: "#dcd7ba", sel: "rgba(126,156,216,0.24)" },
  { id: "github-light", name: "GitHub Light", light: true, bg: "#ffffff", fg: "#24292f", dimc: "#6e7781", green: "#116329", blue: "#0550ae", cyan: "#1b7c83", red: "#cf222e", yellow: "#8a6a00", purple: "#8250df", white: "#24292f", sel: "rgba(5,80,174,0.14)" },
];

export const AUTH_LABEL_KEY: Record<string, string> = {
  key: "auth.key",
  password: "auth.password",
  ask: "auth.ask",
  personal: "auth.personal",
};

// ── Accent presets + palette factory ───────────────────────────
export function hexToRgb(h: string): [number, number, number] {
  const n = parseInt(h.slice(1), 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}
export function rgba(h: string, a: number): string {
  const [r, g, b] = hexToRgb(h);
  return `rgba(${r},${g},${b},${a})`;
}

/** WCAG 2.1 relative luminance of a hex colour (sRGB). */
function relLuminance(h: string): number {
  const [r, g, b] = hexToRgb(h).map((c) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
/** WCAG 2.1 contrast ratio between two hex colours (1..21). */
export function contrastRatio(a: string, b: string): number {
  const la = relLuminance(a);
  const lb = relLuminance(b);
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}

/** Deterministic palette-driven colour for a vault avatar (no mock VAULTS.color).
 *  Shared by the desktop shell, the secrets view and the mobile app so the same
 *  vault keeps the same hue everywhere — and follows the active theme's palette. */
export function vaultColor(p: Palette, id: string | null): string {
  const swatches = [p.accent, p.green, p.purple, p.amber, p.red];
  if (!id) return p.accent;
  let h = 0;
  for (let i = 0; i < id.length; i++) h = (h * 31 + id.charCodeAt(i)) >>> 0;
  return swatches[h % swatches.length];
}

const clampByte = (n: number): number => Math.max(0, Math.min(255, Math.round(n)));
const toHex2 = (n: number): string => clampByte(n).toString(16).padStart(2, "0");
/** Mix a hex colour toward white by `amt` (0..1). Used to derive bright ANSI
 *  variants on dark themes — same hue, lifted luminance, so output "pops". */
export function lighten(h: string, amt: number): string {
  const [r, g, b] = hexToRgb(h);
  return `#${toHex2(r + (255 - r) * amt)}${toHex2(g + (255 - g) * amt)}${toHex2(b + (255 - b) * amt)}`;
}
/** Mix a hex colour toward black by `amt` (0..1). The bright-variant move on a
 *  light theme, where lifting toward white would only wash colours out. */
export function darken(h: string, amt: number): string {
  const [r, g, b] = hexToRgb(h);
  return `#${toHex2(r * (1 - amt))}${toHex2(g * (1 - amt))}${toHex2(b * (1 - amt))}`;
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

/** Walk the accent toward the ink end of its own hue until it clears AA as body
 *  text on BOTH base surfaces, and return it unchanged when it already does — which
 *  is the mono family, whose accent is ink by design. This is what lets a saturated
 *  brand accent (candy's #ff2f9e is 3.41:1 on white) still label something without
 *  either failing AA or being flattened to plain grey. */
function accentTextFor(accent: string, surfaces: string[], mode: EffMode): string {
  // EVERY surface tier, not just the base ones. bg3/bg4 are the hover/selected
  // tiers — a highlighted row, the current item in a menu — which is exactly where
  // an accent-coloured label or check glyph lands, and in the light twins they are
  // the darkest of the ladder, so they are what actually fails: derived against
  // bg0..bg2 alone, candy's accentText sat at 3.87:1 on bg4.
  const ok = (c: string) => surfaces.every((s) => contrastRatio(c, s) >= 4.5);
  let c = accent;
  // 4% per step. `darken` scales R/G/B uniformly, which leaves HSV hue and
  // saturation untouched — the walk deepens the colour without muddying it (candy
  // #ff2f9e H328 S82 -> #b1216d H328 S81 in 9 steps). `lighten` does desaturate
  // toward white, but no dark-mode accent ever iterates: they all pass at i=0.
  for (let i = 0; i < 30 && !ok(c); i++) c = mode === "dark" ? lighten(c, 0.04) : darken(c, 0.04);
  return c;
}

/** The surface tiers accent-coloured text/glyphs can sit on. */
const surfacesOf = (p: AuthoredPalette): string[] => [p.bg0, p.bg1, p.bg2, p.bg3, p.bg4];

export function buildPalette(mode: EffMode, accentKey: AccentKey = "blue"): Palette {
  const base = mode === "dark" ? DARK : LIGHT;
  const a = (mode === "dark" ? ACCENTS : ACCENTS_LIGHT)[accentKey] || ACCENTS.blue;
  const softA = mode === "dark" ? 0.15 : 0.12;
  const lineA = mode === "dark" ? 0.4 : 0.38;
  const glowA = mode === "dark" ? 0.22 : 0.16;
  return {
    ...base,
    accent: a.accent,
    accentText: accentTextFor(a.accent, surfacesOf(base), mode),
    accent2: a.accent2,
    purple: a.purple,
    accentSoft: rgba(a.accent, softA),
    accentLine: rgba(a.accent, lineA),
    glow: rgba(a.accent, glowA),
    // Primary-button label ink: white where it clears AA on this accent, else a
    // dark theme ink (the pastel dark-mode accents all fail with white, ~3.2:1).
    accentInk: contrastRatio("#ffffff", a.accent) >= 4.5 ? "#ffffff" : mode === "dark" ? base.bg0 : base.txt,
    // Danger-button label ink, same rule against the base red (accents don't
    // change `red`): dark #ff6b80 → bg0 (7.04:1); light #c9334b → white (5.17:1).
    dangerInk: contrastRatio("#ffffff", base.red) >= 4.5 ? "#ffffff" : mode === "dark" ? base.bg0 : base.txt,
  };
}

// ── Named app themes ───────────────────────────────────────────
// Nebula keeps the base+accent machinery above; named themes ("candy") own a full
// palette per effective mode. resolveAppPalette is the single entry point the
// ThemeProvider uses instead of calling buildPalette directly.
export const APP_THEMES: Record<
  Exclude<AppThemeFamily, "nebula">,
  { dark: AuthoredPalette; light: AuthoredPalette }
> = {
  mono: { dark: MONO_DARK, light: MONO_LIGHT },
  candy: { dark: CANDY_DARK, light: CANDY_LIGHT },
};

export function resolveAppPalette(
  family: AppThemeFamily,
  mode: EffMode,
  accentKey: AccentKey = "blue",
): Palette {
  // Fall back to the Nebula (base + accent) path for "nebula" AND for any
  // unrecognized family, so a corrupt/forward-incompatible persisted value can't
  // crash the whole app (same hardening buildPalette applies to a bad accent).
  const themed = family !== "nebula" ? APP_THEMES[family] : undefined;
  if (!themed) return buildPalette(mode, accentKey);
  const base = themed[mode];
  return { ...base, accentText: accentTextFor(base.accent, surfacesOf(base), mode) };
}

// Default terminal theme per (family, effective mode) — the linked default that a
// per-mode manual override can replace (see ThemeProvider).
export const TERM_LINK: Record<AppThemeFamily, { dark: string; light: string }> = {
  mono: { dark: "nebula", light: "solight" },
  nebula: { dark: "nebula", light: "solight" },
  candy: { dark: "candy-dark", light: "candy-light" },
};

/** Map a terminal theme to an xterm.js ITheme.
 *
 *  Bright ANSI colours are now DISTINCT from their normal twins (previously every
 *  bright mapped onto the base colour, which made un-styled output look flat next
 *  to apps like Termius). Each bright is a lifted variant of the base — toward
 *  white on dark themes, toward black on light ones — unless the theme overrides
 *  it explicitly. ANSI `black` is a real dark tone (not the background, which made
 *  black-on-default text invisible). */
export function termToXterm(t: TermTheme) {
  // ANSI white is its own channel, not the soft `fg`, so SGR-37/bold-white text
  // renders truly white. `foreground` keeps `fg` (the designed default tone).
  const white = t.white ?? "#ffffff";
  const bright = (base: string, override?: string): string =>
    override ?? (t.light ? darken(base, 0.18) : lighten(base, 0.18));
  return {
    background: t.bg,
    foreground: t.fg,
    cursor: t.fg,
    cursorAccent: t.bg,
    selectionBackground: t.sel,
    // A visible ANSI black: derived from the bg (lifted on dark, the dark fg on
    // light) so colour-0 text isn't swallowed by the background.
    black: t.black ?? (t.light ? t.fg : lighten(t.bg, 0.22)),
    red: t.red,
    green: t.green,
    yellow: t.yellow,
    blue: t.blue,
    magenta: t.purple,
    cyan: t.cyan,
    white,
    brightBlack: t.brightBlack ?? t.dimc,
    brightRed: bright(t.red, t.brightRed),
    brightGreen: bright(t.green, t.brightGreen),
    brightYellow: bright(t.yellow, t.brightYellow),
    brightBlue: bright(t.blue, t.brightBlue),
    brightMagenta: bright(t.purple, t.brightMagenta),
    brightCyan: bright(t.cyan, t.brightCyan),
    brightWhite: t.brightWhite ?? white,
  };
}

// ── Terminal typography & behaviour ────────────────────────────
// Colour (TermTheme) and typography (TermPrefs) are independent axes: a font size
// applies to every theme, and a theme applies at every font size. Keeping them apart is
// what lets the theme picker stay a picker instead of growing a font section per theme.

export type TermCursorStyle = "block" | "bar" | "underline";

export type TermFontId =
  | "jetbrains"
  | "fira"
  | "cascadia"
  | "sfmono"
  | "menlo"
  | "system"
  | "custom";

/** Only JetBrains Mono is bundled (`@fontsource/jetbrains-mono`). The rest exist only if
 *  the user installed them, which is why the settings picker probes each with
 *  `document.fonts.check` and says so instead of silently falling back. */
export const TERM_FONTS: { id: TermFontId; name: string; stack: string }[] = [
  { id: "jetbrains", name: "JetBrains Mono", stack: MONO },
  { id: "fira", name: "Fira Code", stack: `'Fira Code', ${MONO}` },
  { id: "cascadia", name: "Cascadia Code", stack: `'Cascadia Code', ${MONO}` },
  { id: "sfmono", name: "SF Mono", stack: `'SF Mono', ${MONO}` },
  { id: "menlo", name: "Menlo", stack: `Menlo, ${MONO}` },
  { id: "system", name: "System monospace", stack: "ui-monospace, monospace" },
];

export interface TermPrefs {
  fontId: TermFontId;
  /** CSS family name used when `fontId` is "custom". */
  fontCustom: string;
  lineHeight: number;
  /** Extra tracking in px; xterm takes a number. */
  letterSpacing: number;
  cursor: TermCursorStyle;
  cursorBlink: boolean;
  /** Overrides the active theme's `fg` for text AND cursor. null = follow the theme. */
  fg: string | null;
  /** Raise xterm's contrast floor from the cosmetic 1.1 to WCAG AA. */
  minContrast: boolean;
}

export const DEFAULT_TERM_PREFS: TermPrefs = {
  fontId: "jetbrains",
  fontCustom: "",
  lineHeight: 1.2,
  letterSpacing: 0,
  cursor: "block",
  cursorBlink: true,
  fg: null,
  minContrast: false,
};

/** A family name is user input that ends up inside a CSS declaration, so anything that
 *  could terminate the quote and append a second property is refused outright rather
 *  than escaped — there is no legitimate font whose name contains a quote or semicolon. */
const SAFE_FAMILY = /^[\w .+-]{1,64}$/;

export function termFontStack(prefs: TermPrefs): string {
  if (prefs.fontId === "custom") {
    const name = (prefs.fontCustom ?? "").trim();
    if (!name || !SAFE_FAMILY.test(name)) return MONO;
    return `'${name}', ${MONO}`;
  }
  return TERM_FONTS.find((f) => f.id === prefs.fontId)?.stack ?? MONO;
}

/** Build the xterm options for a pane. The ONLY place this happens — the settings live
 *  preview calls it too, so the preview cannot drift from what a real pane will do. */
export function termOptions(prefs: TermPrefs, theme: TermTheme, fontSize: number) {
  const base = termToXterm(theme);
  return {
    fontFamily: termFontStack(prefs),
    fontSize,
    lineHeight: prefs.lineHeight,
    letterSpacing: prefs.letterSpacing,
    cursorStyle: prefs.cursor,
    cursorBlink: prefs.cursorBlink,
    theme: prefs.fg ? { ...base, foreground: prefs.fg, cursor: prefs.fg } : base,
    // Render bold text in the (distinct) bright palette and nudge any too-low-contrast
    // glyph so nothing comes out unreadable.
    drawBoldTextInBrightColors: true,
    minimumContrastRatio: prefs.minContrast ? 4.5 : 1.1,
    allowProposedApi: true,
    // When a TUI turns on mouse reporting, a plain drag no longer selects text. macOS
    // needs this flag for the Option+drag override (Shift works elsewhere by default).
    macOptionClickForcesSelection: true,
  };
}

// ── Custom terminal-theme editor support ───────────────────────

/** The nine solid-colour fields of a TermTheme (everything except `sel`, which
 *  is a translucent rgba). Used by the editor grid and import validation. */
export const TERM_COLOR_FIELDS = [
  "bg",
  "fg",
  "dimc",
  "red",
  "green",
  "yellow",
  "blue",
  "cyan",
  "purple",
] as const;
export type TermColorField = (typeof TERM_COLOR_FIELDS)[number];

/** Colour fields exposed in the custom-theme editor: the required nine plus the
 *  optional `white` channel. White is kept OUT of TERM_COLOR_FIELDS so import
 *  validation of older theme files (which lack `white`) stays backward-compatible. */
export const TERM_EDITOR_FIELDS = [...TERM_COLOR_FIELDS, "white"] as const;
export type TermEditorField = (typeof TERM_EDITOR_FIELDS)[number];

/** True for a `#RGB` or `#RRGGBB` hex colour. (Plain boolean, not a type
 *  predicate: narrowing an already-`string` value with `s is string` would
 *  collapse it to `never` inside a follow-up check.) */
export function isHexColor(s: unknown): boolean {
  return typeof s === "string" && /^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/.test(s.trim());
}

/** Normalize any theme colour (hex or `rgb(a)(...)`) to a 6-digit lowercase hex,
 *  which is all `<input type="color">` accepts. Unparseable input → black. */
export function toHexInput(s: string): string {
  const v = (s ?? "").trim();
  if (/^#[0-9a-fA-F]{6}$/.test(v)) return v.toLowerCase();
  if (/^#[0-9a-fA-F]{3}$/.test(v)) {
    return (
      "#" +
      v
        .slice(1)
        .split("")
        .map((c) => c + c)
        .join("")
    ).toLowerCase();
  }
  const m = v.match(/^rgba?\(\s*([0-9]+)\s*,\s*([0-9]+)\s*,\s*([0-9]+)/i);
  if (m) {
    const hx = (n: number) => Math.max(0, Math.min(255, n)).toString(16).padStart(2, "0");
    return `#${hx(+m[1])}${hx(+m[2])}${hx(+m[3])}`;
  }
  return "#000000";
}

/** A portable, id-free theme palette — the JSON export/import shape. */
export type TermThemePalette = Omit<TermTheme, "id" | "custom">;

/** Validate the translucent selection colour: a hex, or a well-formed `rgb(a)(...)`
 *  with a closing paren and bounded numeric parts. Length-capped so a malicious
 *  import can't smuggle a multi-MB string past validation into localStorage. */
export function isSelColor(s: unknown): boolean {
  if (typeof s !== "string") return false;
  const v = s.trim();
  if (v.length > 64) return false;
  if (isHexColor(v)) return true;
  return /^rgba?\(\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}\s*(,\s*(0|1|0?\.\d{1,4})\s*)?\)$/i.test(v);
}

/** Extract the alpha of a `sel` colour (the 4th rgba component), defaulting to
 *  0.28 for a hex or alpha-less value. Lets the editor keep an imported theme's
 *  selection opacity when the user only re-picks its hue. */
export function selAlpha(sel: string): number {
  const m = sel.match(/^rgba?\([^)]*,\s*(0|1|0?\.\d{1,4})\s*\)$/i);
  const a = m ? parseFloat(m[1]) : NaN;
  return Number.isFinite(a) ? a : 0.28;
}

/** Strictly validate parsed JSON as an importable theme palette: a non-empty
 *  name, all nine solid fields valid hex, and `sel` a valid hex or rgba string.
 *  Returns a normalized palette, or null if anything is missing/malformed. */
export function validateTermThemeImport(raw: unknown): TermThemePalette | null {
  if (!raw || typeof raw !== "object") return null;
  const o = raw as Record<string, unknown>;
  const name = typeof o.name === "string" ? o.name.trim().slice(0, 40) : "";
  if (!name) return null;
  for (const f of TERM_COLOR_FIELDS) {
    if (!isHexColor(o[f])) return null;
  }
  // `sel` is the translucent selection highlight — hex or a bounded rgb(a)(...).
  if (!isSelColor(o.sel)) return null;
  const lc = (k: TermColorField) => (o[k] as string).toLowerCase();
  return {
    name,
    bg: lc("bg"),
    fg: lc("fg"),
    dimc: lc("dimc"),
    red: lc("red"),
    green: lc("green"),
    yellow: lc("yellow"),
    blue: lc("blue"),
    cyan: lc("cyan"),
    purple: lc("purple"),
    // `white` is optional (older exports lack it); accept a valid hex, else omit
    // so termToXterm's pure-white default applies.
    ...(isHexColor(o.white) ? { white: (o.white as string).toLowerCase() } : {}),
    sel: (o.sel as string).trim().toLowerCase(),
    ...(typeof o.light === "boolean" ? { light: o.light } : {}),
  };
}
