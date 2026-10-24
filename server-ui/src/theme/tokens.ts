// The admin's design tokens live as CSS custom properties in ./global.css (the
// Carbon Sheet: hueless neutrals, one blue, state colours). This module keeps the
// two font stacks for inline styles and the theme-mode types.

/** Geologica: the panel's own words. Same stack as `var(--font-sans)`. */
export const UI = '"Geologica", "Segoe UI", system-ui, sans-serif';
/** JetBrains Mono: anything a machine issued. Same stack as `var(--font-mono)`. */
export const MONO = '"JetBrains Mono", ui-monospace, "SF Mono", Menlo, monospace';

/** The reader's choice: a sheet, or "as the system has it" (followed live). */
export type Mode = "dark" | "light" | "auto";
/** The sheet actually shown. */
export type EffMode = "dark" | "light";
export type Density = "cards" | "list";
