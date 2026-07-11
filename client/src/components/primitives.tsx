// Primitive components — faithful port of the prototype's tokens.jsx primitives.
// All pull the active palette from ThemeProvider via usePalette().

import React, { CSSProperties, useEffect, useState } from "react";
import { usePalette } from "@/theme/ThemeProvider";
import { MONO, UI, AUTH_LABEL_KEY, Palette } from "@/theme/tokens";
import { tDyn } from "@/i18n";

// Spread onto any text <input>/<textarea> to stop the WebView from spell-checking,
// auto-capitalizing, auto-correcting or autofilling data the user types into an SSH
// client (hostnames, usernames, commands, key material, secret values, …). Place
// the spread BEFORE any explicit prop so a field can still override (e.g. a real
// autoComplete). Not for the hidden xterm textarea — that's a raw DOM node, set its
// attributes via term.textarea.setAttribute(...) instead.
export const NO_AUTOCORRECT = {
  autoCorrect: "off",
  autoCapitalize: "off",
  autoComplete: "off",
  spellCheck: false,
} as const;

// Unstyled-button reset — lets a former clickable <div>/<span> become a real
// keyboard-operable <button> without changing its box metrics or typography.
// Spread FIRST so the local styles keep winning.
export const BTN_RESET: CSSProperties = {
  appearance: "none",
  background: "none",
  border: "none",
  margin: 0,
  padding: 0,
  font: "inherit",
  color: "inherit",
  textAlign: "left",
  cursor: "pointer",
};

// ── Icons (Lucide-derived line set) ────────────────────────────
export const ICONS = {
  server: '<rect x="2.5" y="3" width="19" height="7.5" rx="2"/><rect x="2.5" y="13.5" width="19" height="7.5" rx="2"/><circle cx="6" cy="6.75" r="0.6" fill="currentColor" stroke="none"/><circle cx="6" cy="17.25" r="0.6" fill="currentColor" stroke="none"/>',
  key: '<circle cx="7.5" cy="16" r="3.6"/><path d="M10.3 13.4 20 3.7"/><path d="M17 6.7l2.3 2.3"/><path d="M14.2 9.5l2 2"/>',
  lock: '<rect x="4.5" y="11" width="15" height="9.5" rx="2.2"/><path d="M8 11V7.3a4 4 0 0 1 8 0V11"/>',
  unlock: '<rect x="4.5" y="11" width="15" height="9.5" rx="2.2"/><path d="M8 11V7.3a4 4 0 0 1 7.4-2"/>',
  folder: '<path d="M4 6.5a2 2 0 0 1 2-2h3.7l2 2H18a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2z"/>',
  terminal: '<polyline points="5 7 10 12 5 17"/><line x1="12" y1="17" x2="19" y2="17"/>',
  search: '<circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.8" y2="16.8"/>',
  plus: '<line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>',
  minus: '<line x1="5" y1="12" x2="19" y2="12"/>',
  cr: '<polyline points="9 6 15 12 9 18"/>',
  cd: '<polyline points="6 9 12 15 18 9"/>',
  tag: '<path d="M11 3.5H5a1.5 1.5 0 0 0-1.5 1.5v6a2 2 0 0 0 .6 1.4l7 7a1.6 1.6 0 0 0 2.3 0l5.7-5.7a1.6 1.6 0 0 0 0-2.3l-7-7A2 2 0 0 0 11 3.5z"/><circle cx="7.5" cy="7.5" r="1.1" fill="currentColor" stroke="none"/>',
  globe: '<circle cx="12" cy="12" r="8.5"/><line x1="3.5" y1="12" x2="20.5" y2="12"/><path d="M12 3.5c2.4 2.3 3.7 5.3 3.7 8.5S14.4 18.2 12 20.5C9.6 18.2 8.3 15.2 8.3 12S9.6 5.8 12 3.5z"/>',
  shield: '<path d="M12 3l7.5 2.8v5.7c0 4.3-3.2 7.5-7.5 8.7-4.3-1.2-7.5-4.4-7.5-8.7V5.8z"/>',
  shieldcheck: '<path d="M12 3l7.5 2.8v5.7c0 4.3-3.2 7.5-7.5 8.7-4.3-1.2-7.5-4.4-7.5-8.7V5.8z"/><polyline points="9 12 11 14 15.5 9.5"/>',
  eye: '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/>',
  copy: '<rect x="9" y="9" width="11.5" height="11.5" rx="2.2"/><path d="M5.5 15H5a1.5 1.5 0 0 1-1.5-1.5V5A1.5 1.5 0 0 1 5 3.5h8.5A1.5 1.5 0 0 1 15 5v.5"/>',
  clipboard: '<rect x="8" y="3.5" width="8" height="3.5" rx="1.2"/><path d="M9 5.5H6.5A1.5 1.5 0 0 0 5 7v12.5A1.5 1.5 0 0 0 6.5 21h11a1.5 1.5 0 0 0 1.5-1.5V7a1.5 1.5 0 0 0-1.5-1.5H15"/>',
  activity: '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
  command: '<path d="M15 6v12a3 3 0 1 1-3-3h6a3 3 0 1 1-3 3"/><path d="M9 18V6a3 3 0 1 0-3 3h12a3 3 0 1 0-3-3"/>',
  ar: '<line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/>',
  check: '<polyline points="20 6 9 17 4 12"/>',
  database: '<ellipse cx="12" cy="5.5" rx="7.5" ry="2.8"/><path d="M4.5 5.5v6c0 1.6 3.4 2.8 7.5 2.8s7.5-1.2 7.5-2.8v-6"/><path d="M4.5 11.5v6c0 1.6 3.4 2.8 7.5 2.8s7.5-1.2 7.5-2.8v-6"/>',
  sliders: '<line x1="21" y1="5" x2="14" y2="5"/><line x1="10" y1="5" x2="3" y2="5"/><line x1="21" y1="12" x2="12" y2="12"/><line x1="8" y1="12" x2="3" y2="12"/><line x1="21" y1="19" x2="16" y2="19"/><line x1="12" y1="19" x2="3" y2="19"/><line x1="14" y1="3" x2="14" y2="7"/><line x1="8" y1="10" x2="8" y2="14"/><line x1="16" y1="17" x2="16" y2="21"/>',
  more: '<circle cx="5" cy="12" r="1.5" fill="currentColor" stroke="none"/><circle cx="12" cy="12" r="1.5" fill="currentColor" stroke="none"/><circle cx="19" cy="12" r="1.5" fill="currentColor" stroke="none"/>',
  layers: '<polygon points="12 2.5 21 7 12 11.5 3 7 12 2.5"/><polyline points="3 12 12 16.5 21 12"/><polyline points="3 17 12 21.5 21 17"/>',
  zap: '<polygon points="13 2.5 4 13.5 11 13.5 10 21.5 20 10.5 13 10.5 13 2.5"/>',
  download: '<path d="M12 3.5v11"/><polyline points="7.5 10.5 12 15 16.5 10.5"/><path d="M5 20.5h14"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2.5M12 19.5V22M2 12h2.5M19.5 12H22M4.9 4.9l1.8 1.8M17.3 17.3l1.8 1.8M19.1 4.9l-1.8 1.8M6.7 17.3l-1.8 1.8"/>',
  moon: '<path d="M20.5 13A8.5 8.5 0 1 1 11 3.5 6.6 6.6 0 0 0 20.5 13z"/>',
  branch: '<line x1="6" y1="4.5" x2="6" y2="14"/><circle cx="6" cy="17.5" r="2.6"/><circle cx="18" cy="6.5" r="2.6"/><path d="M18 9.1c0 5-4 7.4-9 7.4"/>',
  wifi: '<path d="M4.5 11.5a11 11 0 0 1 15 0"/><path d="M8 15a6 6 0 0 1 8 0"/><line x1="12" y1="18.7" x2="12.01" y2="18.7"/>',
  note: '<path d="M14 3.5H7A2 2 0 0 0 5 5.5v13A2 2 0 0 0 7 20.5h10a2 2 0 0 0 2-2V8.5z"/><polyline points="14 3.5 14 8.5 19 8.5"/><line x1="8.5" y1="13" x2="14" y2="13"/><line x1="8.5" y1="16.5" x2="12" y2="16.5"/>',
  x: '<line x1="6" y1="6" x2="18" y2="18"/><line x1="18" y1="6" x2="6" y2="18"/>',
  dot: '<circle cx="12" cy="12" r="4" fill="currentColor" stroke="none"/>',
  hash: '<line x1="4" y1="9" x2="20" y2="9"/><line x1="4" y1="15" x2="20" y2="15"/><line x1="10" y1="3" x2="8" y2="21"/><line x1="16" y1="3" x2="14" y2="21"/>',
  grid: '<rect x="3.5" y="3.5" width="7" height="7" rx="1.5"/><rect x="13.5" y="3.5" width="7" height="7" rx="1.5"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.5"/><rect x="13.5" y="13.5" width="7" height="7" rx="1.5"/>',
  list: '<line x1="8" y1="6" x2="20" y2="6"/><line x1="8" y1="12" x2="20" y2="12"/><line x1="8" y1="18" x2="20" y2="18"/><circle cx="4" cy="6" r="1" fill="currentColor" stroke="none"/><circle cx="4" cy="12" r="1" fill="currentColor" stroke="none"/><circle cx="4" cy="18" r="1" fill="currentColor" stroke="none"/>',
  bolt: '<path d="M12 3.5 5 13h6l-1 7.5L18 11h-6z"/>',
  folders: '<path d="M4 7.5a2 2 0 0 1 2-2h3l2 2h5a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2z"/>',
  refresh: '<path d="M21 12a9 9 0 1 1-2.6-6.3"/><polyline points="21 4 21 9 16 9"/>',
  enter: '<polyline points="9 10 4 14 9 18"/><path d="M4 14h11a5 5 0 0 0 5-5V6"/>',
  trash: '<polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>',
  pencil: '<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/>',
  play: '<polygon points="6 4 20 12 6 20 6 4" fill="currentColor" stroke="none"/>',
  stop: '<rect x="6" y="6" width="12" height="12" rx="2" fill="currentColor" stroke="none"/>',
  send: '<line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>',
  upload: '<path d="M12 20.5v-11"/><polyline points="7.5 13.5 12 9 16.5 13.5"/><path d="M5 3.5h14"/>',
  file: '<path d="M14 3.5H7A2 2 0 0 0 5 5.5v13A2 2 0 0 0 7 20.5h10a2 2 0 0 0 2-2V8.5z"/><polyline points="14 3.5 14 8.5 19 8.5"/>',
  radio: '<circle cx="12" cy="12" r="2.4" fill="currentColor" stroke="none"/><path d="M7.8 7.8a6 6 0 0 0 0 8.4M16.2 16.2a6 6 0 0 0 0-8.4"/><path d="M4.9 4.9a10 10 0 0 0 0 14.2M19.1 19.1a10 10 0 0 0 0-14.2"/>',
  alert: '<path d="M10.3 3.8 1.8 18a1.9 1.9 0 0 0 1.7 2.9h17a1.9 1.9 0 0 0 1.7-2.9L13.7 3.8a1.9 1.9 0 0 0-3.4 0z"/><line x1="12" y1="9" x2="12" y2="13.5"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
  home: '<path d="M3 11.5 12 4l9 7.5"/><path d="M5.5 10v9.5h13V10"/>',
  cl: '<polyline points="15 6 9 12 15 18"/>',
  folderOpen: '<path d="M4 6.5a2 2 0 0 1 2-2h3.7l2 2H18a2 2 0 0 1 2 2v.5H4z"/><path d="M3.4 10.5h17.2l-1.8 8a1.5 1.5 0 0 1-1.5 1.2H6.7a1.5 1.5 0 0 1-1.5-1.2z"/>',
  drive: '<rect x="2.5" y="13" width="19" height="6.5" rx="2"/><path d="M5.5 13 8 4.5h8L18.5 13"/><circle cx="7" cy="16.2" r="0.7" fill="currentColor" stroke="none"/>',
  arrows: '<polyline points="7 4 3 8 7 12"/><line x1="3" y1="8" x2="17" y2="8"/><polyline points="17 12 21 16 17 20"/><line x1="21" y1="16" x2="7" y2="16"/>',
  star: '<polygon points="12 3 14.6 8.6 20.5 9.3 16 13.3 17.3 19.2 12 16 6.7 19.2 8 13.3 3.5 9.3 9.4 8.6 12 3"/>',
  clock: '<circle cx="12" cy="12" r="8.5"/><polyline points="12 7 12 12 15.5 14"/>',
  link: '<path d="M9.5 14.5 14.5 9.5"/><path d="M8 12 6 14a3.5 3.5 0 0 0 5 5l2-2"/><path d="M16 12l2-2a3.5 3.5 0 0 0-5-5l-2 2"/>',
  fingerprint: '<path d="M12 4.5a6.5 6.5 0 0 0-6.5 6.5v2"/><path d="M12 4.5a6.5 6.5 0 0 1 6.5 6.5v4"/><path d="M9 11a3 3 0 0 1 6 0v4a2 2 0 0 1-2 2"/><path d="M12 11v5"/><path d="M5.8 17.5A6.5 6.5 0 0 0 7 19"/>',
  cloud: '<path d="M7 18.5h9.5a4 4 0 0 0 .6-7.96 5.5 5.5 0 0 0-10.6-1.2A4.2 4.2 0 0 0 7 18.5z"/>',
  users: '<path d="M16 19v-1.5a3.5 3.5 0 0 0-3.5-3.5h-5A3.5 3.5 0 0 0 4 17.5V19"/><circle cx="10" cy="8" r="3.2"/><path d="M20 19v-1.5a3.5 3.5 0 0 0-2.6-3.4"/><path d="M15.5 5a3.2 3.2 0 0 1 0 6.2"/>',
} as const;

export type IconName = keyof typeof ICONS;

export function Icon({
  name,
  size = 16,
  stroke = 1.6,
  color = "currentColor",
  style,
}: {
  name: IconName;
  size?: number;
  stroke?: number;
  color?: string;
  style?: CSSProperties;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke={color}
      strokeWidth={stroke}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      style={{ flexShrink: 0, ...style }}
      dangerouslySetInnerHTML={{ __html: ICONS[name] || "" }}
    />
  );
}

// ── Primitives ─────────────────────────────────────────────────
export type Status = "online" | "offline" | "unknown";
export const STATUS_COLOR = (p: Palette, s: Status) =>
  s === "online" ? p.green : s === "offline" ? p.red : p.txt3;

export function StatusDot({
  status,
  size = 8,
  glow = true,
}: {
  status: Status;
  size?: number;
  glow?: boolean;
}) {
  const p = usePalette();
  const c = STATUS_COLOR(p, status);
  return (
    <span
      style={{
        width: size,
        height: size,
        borderRadius: "50%",
        background: c,
        flexShrink: 0,
        boxShadow: glow && status === "online" ? `0 0 0 3px ${c}22, 0 0 7px ${c}99` : "none",
      }}
    />
  );
}

export function Tag({ children, mono }: { children: React.ReactNode; mono?: boolean }) {
  const p = usePalette();
  return (
    <span
      style={{
        fontSize: 11,
        fontWeight: 500,
        color: p.txt2,
        fontFamily: mono ? MONO : UI,
        background: p.bg3,
        border: `1px solid ${p.line}`,
        borderRadius: 6,
        padding: "1px 7px",
        lineHeight: 1.5,
        whiteSpace: "nowrap",
        display: "inline-block",
        maxWidth: "100%",
        overflow: "hidden",
        textOverflow: "ellipsis",
        boxSizing: "border-box",
      }}
    >
      {children}
    </span>
  );
}

/** Local/Cloud vault badge — driven purely by vault.syncTarget. A small glyph +
 *  label, NOT a liveness dot: it states the vault's sync nature, nothing more. */
export function VaultBadge({
  target,
  label,
  size = 12,
}: {
  target: "local" | "cloud";
  label: string;
  size?: number;
}) {
  const p = usePalette();
  const cloud = target === "cloud";
  const c = cloud ? p.accent : p.txt3;
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 4,
        fontSize: 10.5,
        fontWeight: 600,
        color: c,
        background: cloud ? p.accentSoft : p.bg3,
        border: `1px solid ${cloud ? p.accentLine : p.line}`,
        borderRadius: 6,
        padding: "1px 7px",
        lineHeight: 1.5,
        whiteSpace: "nowrap",
      }}
    >
      <Icon name={cloud ? "cloud" : "drive"} size={size} color={c} stroke={1.7} />
      {label}
    </span>
  );
}

export type AuthKind = "key" | "password" | "ask" | "personal";
export function AuthBadge({ auth, jump }: { auth: AuthKind; jump?: boolean }) {
  const p = usePalette();
  const icon: IconName =
    auth === "key" ? "key" : auth === "password" ? "lock" : auth === "personal" ? "fingerprint" : "eye";
  const c =
    auth === "key" ? p.accent : auth === "password" ? p.amber : auth === "personal" ? p.purple : p.txt3;
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 4, color: c }} title={tDyn(AUTH_LABEL_KEY[auth])}>
      <Icon name={icon} size={13} color={c} stroke={1.7} />
      {jump && <Icon name="branch" size={12} color={p.purple} stroke={1.7} />}
    </span>
  );
}

export type BtnVariant = "primary" | "outline" | "ghost" | "soft" | "danger";
export type BtnSize = "sm" | "md" | "lg";
/** Thin draggable divider for resizable panels. Reports the live pointer X to
 *  the parent, which clamps it into a width. Sits absolutely on the panel edge
 *  (parent must be position:relative). */
export function ResizeHandle({
  side = "right",
  onDrag,
}: {
  side?: "left" | "right";
  onDrag: (clientX: number) => void;
}) {
  const p = usePalette();
  const [drag, setDrag] = useState(false);
  useEffect(() => {
    if (!drag) return;
    const move = (e: MouseEvent) => onDrag(e.clientX);
    const up = () => setDrag(false);
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseup", up);
    const pc = document.body.style.cursor;
    const ps = document.body.style.userSelect;
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
    return () => {
      window.removeEventListener("mousemove", move);
      window.removeEventListener("mouseup", up);
      document.body.style.cursor = pc;
      document.body.style.userSelect = ps;
    };
  }, [drag, onDrag]);
  return (
    <div
      onMouseDown={(e) => {
        e.preventDefault();
        setDrag(true);
      }}
      style={{
        position: "absolute",
        top: 0,
        bottom: 0,
        width: 7,
        cursor: "col-resize",
        zIndex: 40,
        background: drag ? p.accentLine : "transparent",
        ...(side === "right" ? { right: -3 } : { left: -3 }),
      }}
    />
  );
}

export function Btn({
  children,
  icon,
  variant = "primary",
  size = "md",
  full,
  onClick,
  style,
  disabled,
  title,
  btnRef,
  "aria-haspopup": ariaHasPopup,
  "aria-expanded": ariaExpanded,
  "aria-label": ariaLabel,
}: {
  children?: React.ReactNode;
  icon?: IconName;
  variant?: BtnVariant;
  size?: BtnSize;
  full?: boolean;
  onClick?: (e: React.MouseEvent) => void;
  style?: CSSProperties;
  disabled?: boolean;
  title?: string;
  /** Ref to the underlying <button> — for programmatic focus (e.g. the fleet
   *  command bar routing Enter to the count-labelled Execute button). */
  btnRef?: React.Ref<HTMLButtonElement>;
  // pass-through ARIA for dropdown triggers / icon-only usages
  "aria-haspopup"?: React.AriaAttributes["aria-haspopup"];
  "aria-expanded"?: boolean;
  "aria-label"?: string;
}) {
  const p = usePalette();
  const pad = size === "sm" ? "5px 10px" : size === "lg" ? "11px 18px" : "8px 14px";
  const fs = size === "sm" ? 12.5 : size === "lg" ? 15 : 13.5;
  const variants: Record<BtnVariant, CSSProperties> = {
    primary: {
      // Named themes (e.g. Candy Holo) can paint the primary button with a holo
      // gradient; everything else falls back to the solid accent. The glow below
      // stays a solid colour (a gradient can't be a box-shadow colour). The label
      // uses the palette's accentInk so it clears AA on the accent/gradient.
      background: p.accentGradient ?? p.accent,
      color: p.accentInk ?? "#fff",
      border: "1px solid transparent",
      boxShadow: `0 1px 0 rgba(255,255,255,0.2) inset, 0 6px 18px -6px ${p.accent}`,
    },
    outline: { background: "transparent", color: p.txt, border: `1px solid ${p.line2}` },
    ghost: { background: p.bg3, color: p.txt, border: `1px solid ${p.line}` },
    soft: { background: p.accentSoft, color: p.accent, border: `1px solid ${p.accentLine}` },
    // Destructive/security actions: deliberately sober (solid red, no glow). The
    // label uses dangerInk — accentInk is tuned for the accent surface and can
    // fail AA on red (e.g. candy-light's plum ink on #d02545 is 3.05:1).
    danger: {
      background: p.red,
      color: p.dangerInk ?? "#fff",
      border: "1px solid transparent",
      boxShadow: "none",
    },
  };
  return (
    <button
      ref={btnRef}
      onClick={onClick}
      disabled={disabled}
      title={title}
      aria-haspopup={ariaHasPopup}
      aria-expanded={ariaExpanded}
      aria-label={ariaLabel}
      style={{
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        gap: 7,
        fontFamily: UI,
        fontSize: fs,
        fontWeight: 600,
        letterSpacing: 0.1,
        padding: pad,
        borderRadius: 9,
        cursor: disabled ? "default" : "pointer",
        width: full ? "100%" : "auto",
        opacity: disabled ? 0.5 : 1,
        transition: "filter .15s, transform .1s",
        whiteSpace: "nowrap",
        ...variants[variant],
        ...style,
      }}
      onMouseEnter={(e) => {
        if (!disabled) e.currentTarget.style.filter = "brightness(1.08)";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.filter = "none";
      }}
    >
      {icon && <Icon name={icon} size={fs} stroke={1.9} />}
      {children}
    </button>
  );
}

export function Logo({ size = 22, color }: { size?: number; color?: string }) {
  const p = usePalette();
  const c = color || p.accent;
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 9 }}>
      <span style={{ position: "relative", width: size, height: size, flexShrink: 0 }}>
        <span
          style={{
            position: "absolute",
            inset: 0,
            borderRadius: size * 0.28,
            background: `linear-gradient(140deg, ${c}, ${p.purple})`,
            boxShadow: `0 4px 14px -4px ${c}`,
          }}
        />
        <span
          style={{
            position: "absolute",
            inset: 0,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            color: "#fff",
            fontFamily: MONO,
            fontWeight: 700,
            fontSize: size * 0.5,
          }}
        >
          ›_
        </span>
      </span>
      <span style={{ fontWeight: 700, fontSize: size * 0.74, letterSpacing: -0.3 }}>
        Uni<span style={{ color: c }}>SSH</span>
      </span>
    </span>
  );
}

// ── Shared atoms used across shell / settings ──────────────────
export function IconBtn({
  icon,
  active,
  onClick,
  title,
  size = 30,
  color,
}: {
  icon: IconName;
  active?: boolean;
  onClick?: () => void;
  title?: string;
  size?: number;
  color?: string;
}) {
  const p = usePalette();
  return (
    <button
      onClick={onClick}
      title={title}
      aria-label={title}
      style={{
        width: size,
        height: size,
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        borderRadius: 8,
        background: active ? p.accentSoft : "transparent",
        border: `1px solid ${active ? p.accentLine : "transparent"}`,
        color: color || (active ? p.accent : p.txt2),
        cursor: "pointer",
        transition: "background .12s, color .12s",
      }}
      onMouseEnter={(e) => {
        if (!active) e.currentTarget.style.background = p.bg3;
      }}
      onMouseLeave={(e) => {
        if (!active) e.currentTarget.style.background = "transparent";
      }}
    >
      <Icon name={icon} size={Math.round(size * 0.53)} stroke={1.7} />
    </button>
  );
}

export interface SegOption<T extends string> {
  value: T;
  label?: string;
  icon?: IconName;
}
export function Segmented<T extends string>({
  options,
  value,
  onChange,
  size = "md",
  disabled = false,
}: {
  options: SegOption<T>[];
  value: T;
  onChange: (v: T) => void;
  size?: "sm" | "md";
  disabled?: boolean;
}) {
  const p = usePalette();
  const pad = size === "sm" ? "5px 9px" : "6px 12px";
  const fs = size === "sm" ? 12 : 13;
  return (
    <div
      style={{
        display: "inline-flex",
        background: p.bg2,
        border: `1px solid ${p.line}`,
        borderRadius: 9,
        padding: 2,
        gap: 2,
        opacity: disabled ? 0.5 : 1,
      }}
    >
      {options.map((o) => {
        const on = o.value === value;
        return (
          <button
            key={o.value}
            onClick={disabled ? undefined : () => onChange(o.value)}
            disabled={disabled}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 6,
              padding: pad,
              fontSize: fs,
              fontWeight: 600,
              fontFamily: UI,
              borderRadius: 7,
              cursor: disabled ? "default" : "pointer",
              border: "1px solid transparent",
              background: on ? p.bg4 : "transparent",
              color: on ? p.txt : p.txt2,
              transition: "background .12s, color .12s",
            }}
          >
            {o.icon && <Icon name={o.icon} size={fs + 1} stroke={1.8} />}
            {o.label}
          </button>
        );
      })}
    </div>
  );
}

/** The one checkbox. A keyboard-operable button with role="checkbox" — themed box
 *  + check glyph, optional inline label. Clicks never bubble (checkboxes routinely
 *  sit inside clickable cards/rows). Position/visibility overrides go via `style`. */
export function Checkbox({
  checked,
  onChange,
  label,
  size = 16,
  title,
  "aria-label": ariaLabel,
  style,
  labelStyle,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label?: React.ReactNode;
  /** Box side in px (the glyph and radius scale with it). */
  size?: number;
  title?: string;
  "aria-label"?: string;
  style?: CSSProperties;
  labelStyle?: CSSProperties;
}) {
  const p = usePalette();
  return (
    <button
      role="checkbox"
      aria-checked={checked}
      title={title}
      aria-label={ariaLabel}
      onClick={(e) => {
        e.stopPropagation();
        onChange(!checked);
      }}
      style={{
        ...BTN_RESET,
        display: "inline-flex",
        alignItems: "center",
        gap: 8,
        flexShrink: 0,
        ...style,
      }}
    >
      <span
        style={{
          width: size,
          height: size,
          borderRadius: Math.round(size * 0.3),
          border: `1px solid ${checked ? p.accent : p.line2}`,
          background: checked ? p.accent : p.bg2,
          display: "inline-flex",
          alignItems: "center",
          justifyContent: "center",
          flexShrink: 0,
          transition: "background .12s, border-color .12s",
        }}
      >
        {checked && (
          <Icon name="check" size={Math.round(size * 0.68)} color={p.accentInk ?? "#fff"} stroke={3} />
        )}
      </span>
      {label != null && (
        <span style={{ fontSize: 12.5, color: p.txt2, ...labelStyle }}>{label}</span>
      )}
    </button>
  );
}

export function Toggle({
  checked,
  onChange,
  disabled,
  touch,
  title,
  "aria-label": ariaLabel,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  /** Keeps the switch visible/focusable but inert (announced via aria-disabled) —
   *  e.g. a closed tunnel that can't be re-enabled in place. */
  disabled?: boolean;
  /** Pad the (transparent) hit-area out to a 44×44 touch target while the visible
   *  track stays 44×26. Off by default so existing desktop rows don't reflow. */
  touch?: boolean;
  title?: string;
  "aria-label"?: string;
}) {
  const p = usePalette();
  // The button is a transparent hit-area; the 44×26 track lives in an inner span
  // so `touch` can grow the tap target (padding) without moving the visual switch.
  return (
    <button
      role="switch"
      aria-checked={checked}
      aria-disabled={disabled || undefined}
      title={title}
      aria-label={ariaLabel}
      onClick={disabled ? undefined : () => onChange(!checked)}
      style={{
        ...BTN_RESET,
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        flexShrink: 0,
        cursor: disabled ? "default" : "pointer",
        padding: touch ? 9 : 0, // 26 + 2×9 = 44 → 44×44 hit-area, track unchanged
      }}
    >
      <span
        style={{
          width: 44,
          height: 26,
          borderRadius: 13,
          background: checked ? p.accent : p.bg4,
          position: "relative",
          transition: "background .18s",
          flexShrink: 0,
        }}
      >
        <span
          style={{
            position: "absolute",
            top: 3,
            left: checked ? 21 : 3,
            width: 20,
            height: 20,
            borderRadius: "50%",
            background: "#fff",
            transition: "left .18s cubic-bezier(.2,.8,.3,1)",
            boxShadow: "0 1px 3px rgba(0,0,0,0.3)",
          }}
        />
      </span>
    </button>
  );
}

// ── Form field + boxed input ───────────────────────────────────
/** Label (+ optional hint) wrapper around a form control. Ported 1:1 from the
 *  prototype's NHField and the entry-overlay Field label. `w` sets the label's
 *  width; `labelGap` is the label→control spacing (6 by default; the entry
 *  overlays use 7). */
export function Field({
  label,
  hint,
  w,
  labelGap = 6,
  children,
}: {
  label?: string;
  hint?: string;
  w?: string;
  labelGap?: number;
  children: React.ReactNode;
}) {
  const p = usePalette();
  return (
    <label style={{ display: "block", width: w || "auto" }}>
      {label != null && (
        <div style={{ fontSize: 12, fontWeight: 600, color: p.txt2, marginBottom: labelGap }}>
          {label}
          {hint && <span style={{ color: p.txt3, fontWeight: 500 }}> · {hint}</span>}
        </div>
      )}
      {children}
    </label>
  );
}

/** The shared boxed text input: a rounded bg2 box with an accent-capable border +
 *  focus-ring, an optional leading icon, and a bare inner <input>. Box metrics are
 *  props (defaults match the modal fields; the entry overlays pass a taller/rounder
 *  box) so every call site renders exactly as it did inline. The bare inner input is
 *  kept as a separate element (not flattened onto the box) to preserve the exact
 *  text metrics the prototype ships. */
export function Input({
  value,
  onChange,
  placeholder,
  type,
  mono,
  accent,
  icon,
  height = 40,
  radius = 9,
  pad = "0 12px",
  gap,
  fontSize = 13.5,
  autoFocus,
  onKeyDown,
}: {
  value: string;
  onChange?: (v: string) => void;
  placeholder?: string;
  type?: string;
  mono?: boolean;
  accent?: boolean;
  icon?: IconName;
  height?: number;
  radius?: number;
  pad?: string;
  gap?: number;
  fontSize?: number;
  autoFocus?: boolean;
  onKeyDown?: (e: React.KeyboardEvent) => void;
}) {
  const p = usePalette();
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        ...(gap != null ? { gap } : null),
        height,
        padding: pad,
        borderRadius: radius,
        background: p.bg2,
        border: `1px solid ${accent ? p.accentLine : p.line2}`,
        boxShadow: accent ? `0 0 0 3px ${p.accentSoft}` : "none",
      }}
    >
      {icon && <Icon name={icon} size={17} color={accent ? p.accent : p.txt3} />}
      <input
        {...NO_AUTOCORRECT}
        value={value}
        placeholder={placeholder}
        type={type || "text"}
        autoFocus={autoFocus}
        onKeyDown={onKeyDown}
        onChange={(e) => onChange?.(e.target.value)}
        style={{
          flex: 1,
          minWidth: 0,
          background: "none",
          border: "none",
          outline: "none",
          fontFamily: mono ? MONO : UI,
          fontSize,
          color: p.txt,
        }}
      />
    </div>
  );
}

export function Spinner({ size = 16, color }: { size?: number; color?: string }) {
  const p = usePalette();
  return (
    <span
      style={{
        width: size,
        height: size,
        borderRadius: "50%",
        border: `2px solid ${color || p.accent}`,
        borderTopColor: "transparent",
        display: "inline-block",
        animation: "uhSpin .7s linear infinite",
      }}
    />
  );
}
