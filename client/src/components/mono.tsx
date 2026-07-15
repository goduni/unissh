// mono.tsx — shared primitives for the minimalist ("monochrome × air") redesign.
// Density-aware, AA-safe, keyboard-first. See the redesign spec §3.
//
// Density comes from useTheme().density: "comfortable" (borderless card on a soft
// shadow / generous rows) vs "compact" (1px hairline / tight rows). Colour is spent
// only on meaning; everything structural is neutral.

import React, { useRef, useState } from "react";
import { usePalette, useTheme } from "@/theme/ThemeProvider";
import { MONO, UI } from "@/theme/tokens";
import { BTN_RESET, Icon, IconName, Spinner } from "@/components/primitives";
import { useMenu } from "@/components/a11y";

// ── Card ───────────────────────────────────────────────────────
// A discrete object tile (a host card, a password card). Comfortable = borderless
// on a soft neutral shadow; Compact = 1px hairline, no shadow. Never both.
export function Card({
  children,
  onClick,
  active,
  style,
  ...rest
}: {
  children: React.ReactNode;
  onClick?: () => void;
  active?: boolean;
  style?: React.CSSProperties;
} & React.HTMLAttributes<HTMLDivElement>) {
  const p = usePalette();
  const compact = useTheme().density === "compact";
  // Flat card: a 1px hairline, NO drop shadow. A soft shadow reads muddy/grey and
  // turns into visual noise across a grid of dozens of cards. Density changes size
  // only (comfortable 16/18, compact 11/13). Selected = faint fill + a slightly
  // stronger border (no shadow ring, no layout shift).
  return (
    <div
      onClick={onClick}
      style={{
        background: active ? p.bg2 : p.bg0,
        border: `1px solid ${active ? p.line2 : p.line}`,
        borderRadius: compact ? 11 : 16,
        padding: compact ? 13 : 18,
        boxShadow: "none",
        cursor: onClick ? "pointer" : undefined,
        ...style,
      }}
      {...rest}
    >
      {children}
    </div>
  );
}

// ── HairlineRow ────────────────────────────────────────────────
// A list row (keys, known hosts, tunnels, detail facts). Rows share one hairline
// between them (all but the first carry a top border); no per-row box or shadow.
// Density only changes the vertical rhythm.
export function HairlineRow({
  children,
  onClick,
  active,
  first,
  style,
  ...rest
}: {
  children: React.ReactNode;
  onClick?: () => void;
  active?: boolean;
  first?: boolean;
  style?: React.CSSProperties;
} & React.HTMLAttributes<HTMLDivElement>) {
  const p = usePalette();
  const compact = useTheme().density === "compact";
  return (
    <div
      onClick={onClick}
      style={{
        display: "flex",
        alignItems: "center",
        gap: 14,
        padding: compact ? "9px 6px" : "14px 6px",
        borderTop: first ? undefined : `1px solid ${p.line}`,
        background: active ? p.bg2 : "transparent",
        cursor: onClick ? "pointer" : undefined,
        ...style,
      }}
      {...rest}
    >
      {children}
    </div>
  );
}

// ── FactRow ────────────────────────────────────────────────────
// A label + value detail row (the host rail, settings). Label neutral-tertiary,
// value in ink; hairline between rows.
export function FactRow({
  label,
  children,
  first,
}: {
  label: React.ReactNode;
  children: React.ReactNode;
  first?: boolean;
}) {
  const p = usePalette();
  return (
    <div
      style={{
        display: "flex",
        alignItems: "baseline",
        justifyContent: "space-between",
        gap: 12,
        padding: "10px 0",
        borderTop: first ? undefined : `1px solid ${p.line}`,
        fontSize: 12.5,
      }}
    >
      <span style={{ color: p.txt3, flexShrink: 0 }}>{label}</span>
      <span style={{ fontFamily: MONO, color: p.txt, textAlign: "right", minWidth: 0, overflow: "hidden", textOverflow: "ellipsis" }}>
        {children}
      </span>
    </div>
  );
}

// ── MetaChip ───────────────────────────────────────────────────
// Flat icon+text secondary datum (key algo, "used by N", cert, "in agent",
// verified). No fill/border — the mono system's replacement for tinted pill badges.
// A semantic `tone` colours icon+text together; the text is always present so
// colour is never the sole carrier.
export type MetaTone = "neutral" | "good" | "warn" | "danger";
export function MetaChip({
  icon,
  children,
  tone = "neutral",
  mono,
}: {
  icon?: IconName;
  children: React.ReactNode;
  tone?: MetaTone;
  mono?: boolean;
}) {
  const p = usePalette();
  const c = tone === "good" ? p.green : tone === "warn" ? p.amber : tone === "danger" ? p.red : p.txt2;
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 5,
        fontSize: 11.5,
        fontWeight: 600,
        color: c,
        fontFamily: mono ? MONO : UI,
        whiteSpace: "nowrap",
        // Let a long (RU) datum ("не используется") truncate when its row is tight
        // instead of forcing the row past the pane edge.
        minWidth: 0,
        overflow: "hidden",
      }}
    >
      {icon && <Icon name={icon} size={12} color={c} stroke={1.8} />}
      <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", minWidth: 0 }}>
        {children}
      </span>
    </span>
  );
}

// ── FlatAvatar ─────────────────────────────────────────────────
// Neutral tonal initials tile — no gradient. Shape distinguishes role: a vault is
// a rounded square (a container), an account is round (a person).
export function FlatAvatar({
  name,
  size = 26,
  shape = "square",
}: {
  name: string;
  size?: number;
  shape?: "square" | "round";
}) {
  const p = usePalette();
  return (
    <span
      style={{
        width: size,
        height: size,
        flexShrink: 0,
        borderRadius: shape === "round" ? "50%" : Math.round(size * 0.28),
        background: p.bg3,
        border: `1px solid ${p.line}`,
        color: p.txt2,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        fontWeight: 700,
        fontSize: Math.round(size * 0.42),
      }}
    >
      {(name || "?").trim()[0]?.toUpperCase() || "?"}
    </span>
  );
}

// ── UnderlineTabs ──────────────────────────────────────────────
// The one in-screen tab control: underline-active ink text, never a filled pill.
// A proper ARIA tablist (aria-selected, roving tabindex, Left/Right + Home/End);
// pass `controls` per tab to associate its tabpanel.
export interface UnderlineTab<T extends string> {
  value: T;
  label: React.ReactNode;
  count?: number;
  controls?: string;
}
export function UnderlineTabs<T extends string>({
  value,
  onChange,
  tabs,
  ariaLabel,
  gap = 20,
}: {
  value: T;
  onChange: (v: T) => void;
  tabs: UnderlineTab<T>[];
  ariaLabel: string;
  gap?: number;
}) {
  const p = usePalette();
  const ref = useRef<HTMLDivElement>(null);
  const focusTab = (n: number) =>
    ref.current?.querySelectorAll<HTMLElement>('[role="tab"]')[n]?.focus();
  const onKey = (e: React.KeyboardEvent) => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(e.key)) return;
    e.preventDefault();
    const i = tabs.findIndex((t) => t.value === value);
    const n =
      e.key === "ArrowRight"
        ? (i + 1) % tabs.length
        : e.key === "ArrowLeft"
          ? (i - 1 + tabs.length) % tabs.length
          : e.key === "Home"
            ? 0
            : tabs.length - 1;
    onChange(tabs[n].value);
    focusTab(n);
  };
  return (
    <div
      ref={ref}
      role="tablist"
      aria-label={ariaLabel}
      // Wrap to a second row rather than spill off the edge / over an adjacent
      // primary action when the (RU) tab labels don't fit; minWidth:0 lets the
      // strip shrink inside a nowrap header instead of forcing it wider.
      style={{ display: "flex", flexWrap: "wrap", gap, rowGap: 4, minWidth: 0 }}
    >
      {tabs.map((tb) => {
        const on = tb.value === value;
        return (
          <button
            key={tb.value}
            role="tab"
            aria-selected={on}
            aria-controls={tb.controls}
            tabIndex={on ? 0 : -1}
            onClick={() => onChange(tb.value)}
            onKeyDown={onKey}
            style={{
              ...BTN_RESET,
              position: "relative",
              padding: "0 0 10px",
              display: "inline-flex",
              alignItems: "center",
              gap: 7,
              fontSize: 13.5,
              fontWeight: on ? 700 : 600,
              color: on ? p.txt : p.txt3,
              cursor: "pointer",
            }}
          >
            {tb.label}
            {tb.count != null && (
              <span style={{ fontFamily: MONO, fontSize: 11, color: on ? p.txt2 : p.txt3 }}>
                {tb.count}
              </span>
            )}
            {on && (
              <span
                aria-hidden
                style={{
                  position: "absolute",
                  left: 0,
                  right: 0,
                  bottom: -1,
                  height: 2,
                  background: p.accent,
                  borderRadius: 2,
                }}
              />
            )}
          </button>
        );
      })}
    </div>
  );
}

// ── RowOverflowMenu ────────────────────────────────────────────
// A keyboard-operable "⋯" menu that collapses several row actions. Opens on
// click / Enter / Space / ArrowDown / Shift-F10 / Menu; useMenu drives ArrowUp/Down
// + Escape + outside-click over the [role="menuitem"] rows; Tab closes.
export interface OverflowItem {
  label: string;
  icon?: IconName;
  onClick: () => void;
  danger?: boolean;
}
export function RowOverflowMenu({ items, ariaLabel }: { items: OverflowItem[]; ariaLabel: string }) {
  const p = usePalette();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useMenu(open, () => setOpen(false), ref);
  const openKey = (e: React.KeyboardEvent) => {
    if (
      e.key === "Enter" ||
      e.key === " " ||
      e.key === "ArrowDown" ||
      e.key === "ArrowUp" ||
      e.key === "ContextMenu" ||
      (e.key === "F10" && e.shiftKey)
    ) {
      e.preventDefault();
      setOpen(true);
    }
  };
  return (
    <div ref={ref} style={{ position: "relative", flexShrink: 0 }}>
      <button
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={ariaLabel}
        onClick={() => setOpen((o) => !o)}
        onKeyDown={openKey}
        style={{
          width: 30,
          height: 30,
          borderRadius: 8,
          border: "none",
          background: open ? p.bg3 : "transparent",
          color: p.txt3,
          cursor: "pointer",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        <Icon name="more" size={16} />
      </button>
      {open && (
        <div
          role="menu"
          aria-label={ariaLabel}
          onKeyDown={(e) => {
            if (e.key === "Tab") setOpen(false);
          }}
          style={{
            position: "absolute",
            top: "100%",
            right: 0,
            marginTop: 6,
            zIndex: 30,
            minWidth: 180,
            background: p.bg2,
            border: `1px solid ${p.line2}`,
            borderRadius: 12,
            padding: 6,
            boxShadow: p.shadow,
          }}
        >
          {items.map((it, i) => (
            <button
              key={i}
              role="menuitem"
              tabIndex={-1}
              onClick={() => {
                it.onClick();
                setOpen(false);
              }}
              style={{
                ...BTN_RESET,
                width: "100%",
                display: "flex",
                alignItems: "center",
                gap: 9,
                padding: "8px 10px",
                borderRadius: 8,
                cursor: "pointer",
                fontSize: 13,
                fontWeight: 500,
                color: it.danger ? p.red : p.txt2,
              }}
              onMouseEnter={(e) => (e.currentTarget.style.background = p.bg3)}
              onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
            >
              {it.icon && <Icon name={it.icon} size={14} color={it.danger ? p.red : p.txt3} />}
              {it.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

// ── SyncBadge ──────────────────────────────────────────────────
// Cloud-vault sync state (the currently-missing "is my vault up to date" signal):
// synced = quiet green check, syncing = spinner, error = amber caution. Colour is
// always paired with an icon + the passed word, never hue alone.
export type SyncState = "synced" | "syncing" | "error";
export function SyncBadge({ state, label, title }: { state: SyncState; label: string; title?: string }) {
  const p = usePalette();
  const color = state === "error" ? p.amber : state === "syncing" ? p.txt3 : p.green;
  return (
    <span
      title={title}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 4,
        fontSize: 11,
        fontWeight: 600,
        color,
        whiteSpace: "nowrap",
      }}
    >
      {state === "syncing" ? (
        <Spinner size={11} color={color} />
      ) : (
        <Icon name={state === "error" ? "alert" : "check"} size={12} color={color} stroke={1.9} />
      )}
      {label}
    </span>
  );
}

// ── fmtRelative ────────────────────────────────────────────────
// Locale-relative "5 minutes ago" from an epoch-ms timestamp. Replaces the
// meaningless CRDT "v{version}" subtitle and surfaces last-connected/updated.
export function fmtRelative(ms: number, locale = "en"): string {
  const rtf = new Intl.RelativeTimeFormat(locale, { numeric: "auto" });
  const s = Math.round((ms - Date.now()) / 1000);
  const abs = Math.abs(s);
  if (abs < 45) return rtf.format(Math.round(s), "second");
  if (abs < 3600) return rtf.format(Math.round(s / 60), "minute");
  if (abs < 86400) return rtf.format(Math.round(s / 3600), "hour");
  if (abs < 2592000) return rtf.format(Math.round(s / 86400), "day");
  if (abs < 31536000) return rtf.format(Math.round(s / 2592000), "month");
  return rtf.format(Math.round(s / 31536000), "year");
}
