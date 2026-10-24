import {
  createContext,
  useContext,
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type CSSProperties,
  type KeyboardEvent as ReactKeyboardEvent,
  type MouseEvent as ReactMouseEvent,
  type ReactNode,
  type Ref,
  type RefObject,
} from "react";
import { createPortal } from "react-dom";
import { useTranslation } from "react-i18next";
import { usePrefs } from "../store/prefs";
import { Icon, type IconName } from "./icons";
import { MONO } from "../theme/tokens";
import { useCopy } from "./useCopy";

// The kit of the Carbon Sheet. Colours come only from the
// tokens in theme/global.css; :hover and :focus-visible live in its u-* classes.

// ── Shared text roles ──────────────────────────────────────────
/** The label style: 11/600, uppercase, tracked, muted. Names a group below it. */
const LABEL: CSSProperties = {
  fontSize: 11,
  fontWeight: 600,
  lineHeight: "16px",
  letterSpacing: "0.05em",
  textTransform: "uppercase",
  color: "var(--muted-foreground)",
};
/** Prose: hints, descriptions, empty states, failures. 14/20, capped at 72ch. */
const COPY: CSSProperties = { fontSize: 14, lineHeight: "20px", maxWidth: "72ch" };
/** A well: --elevated on a --rule hairline, 7 px corners. */
const WELL: CSSProperties = {
  padding: "8px 12px",
  borderRadius: "var(--radius-md)",
  background: "var(--elevated)",
  borderWidth: 1,
  borderStyle: "solid",
  borderColor: "var(--rule)",
};

/** A state colour on its own tint: `tint("var(--success)")` is 15 % of it over the ground. */
export function tint(color: string, percent = 15): string {
  return `color-mix(in oklch, ${color} ${percent}%, transparent)`;
}

function cx(...names: (string | false | null | undefined)[]): string {
  return names.filter(Boolean).join(" ");
}

// ── Btn ────────────────────────────────────────────────────────
/**
 * `primary`: the one solid blue of a screen. `outline`: the working secondary.
 * `ghost`: no edge at rest. `destructive`: solid red, only for the confirming
 * button of a dialog that says the consequence.
 * Legacy: `soft` draws as `outline`; `danger` as an outline with a red word
 * (a row action that removes or revokes and then asks).
 */
export type BtnVariant = "primary" | "outline" | "ghost" | "destructive" | "soft" | "danger";
/** Heights 24 / 28 / 32 / 36. 32 is the default; 28 inside cards and rows. */
export type BtnSize = "xs" | "sm" | "md" | "lg";

const BTN_H: Record<BtnSize, number> = { xs: 24, sm: 28, md: 32, lg: 36 };
const BTN_PAD: Record<BtnSize, number> = { xs: 8, sm: 10, md: 12, lg: 16 };
const BTN_GAP: Record<BtnSize, number> = { xs: 4, sm: 6, md: 8, lg: 8 };
const BTN_FONT: Record<BtnSize, number> = { xs: 12, sm: 12, md: 13, lg: 13 };
const BTN_ICON: Record<BtnSize, number> = { xs: 12, sm: 16, md: 16, lg: 16 };
const BTN_CLASS: Record<BtnVariant, string> = {
  primary: "u-btn--primary",
  outline: "u-btn--outline",
  ghost: "u-btn--ghost",
  destructive: "u-btn--destructive",
  soft: "u-btn--outline",
  danger: "u-btn--outline-destructive",
};

export function Btn({
  variant = "outline",
  size = "md",
  icon,
  iconRight,
  iconColor,
  onClick,
  disabled,
  loading,
  type = "button",
  full,
  title,
  children,
  style,
  className,
  ariaLabel,
  ariaExpanded,
  ariaControls,
  ref,
}: {
  variant?: BtnVariant;
  size?: BtnSize;
  icon?: IconName;
  iconRight?: IconName;
  /** Colour of the leading icon only (e.g. the green check after a copy). */
  iconColor?: string;
  onClick?: (e: ReactMouseEvent) => void;
  disabled?: boolean;
  /** Working: the button is off and shows a spinner before its word. */
  loading?: boolean;
  type?: "button" | "submit";
  full?: boolean;
  title?: string;
  children?: ReactNode;
  style?: CSSProperties;
  className?: string;
  ariaLabel?: string;
  ariaExpanded?: boolean;
  ariaControls?: string;
  /** For returning focus to the button (e.g. a disclosure toggle on close). */
  ref?: Ref<HTMLButtonElement>;
}) {
  const iconOnly = children == null || children === false || children === "";
  const lead = loading || icon;
  const h = BTN_H[size];
  const pad = iconOnly ? 0 : lead ? BTN_PAD[size] - 2 : BTN_PAD[size];
  return (
    <button
      ref={ref}
      type={type}
      title={title}
      aria-label={ariaLabel}
      aria-expanded={ariaExpanded}
      aria-controls={ariaControls}
      aria-busy={loading || undefined}
      onClick={onClick}
      disabled={disabled || loading}
      className={cx("u-btn", BTN_CLASS[variant], className)}
      style={{
        height: h,
        minWidth: iconOnly ? h : undefined,
        padding: `0 ${pad}px`,
        gap: BTN_GAP[size],
        fontSize: BTN_FONT[size],
        width: full ? "100%" : undefined,
        ...style,
      }}
    >
      {loading ? (
        <Spinner size={BTN_ICON[size]} decorative />
      ) : icon ? (
        <Icon name={icon} size={BTN_ICON[size]} color={iconColor} />
      ) : null}
      {children}
      {iconRight ? <Icon name={iconRight} size={BTN_ICON[size]} /> : null}
    </button>
  );
}

// ── IconBtn ────────────────────────────────────────────────────
/** A 28 px ghost square with a 16 px icon; muted at rest. `title` is also its name. */
export function IconBtn({
  icon,
  onClick,
  active,
  title,
  size = 28,
  ariaLabel,
  disabled,
  tone,
  ref,
}: {
  icon: IconName;
  onClick?: (e: ReactMouseEvent) => void;
  /** A pressed toggle: drawn on --elevated, announced as pressed. */
  active?: boolean;
  title?: string;
  size?: number;
  ariaLabel?: string;
  disabled?: boolean;
  /** `destructive`: the icon of a removal turns red under the pointer or the focus. */
  tone?: "destructive";
  ref?: Ref<HTMLButtonElement>;
}) {
  return (
    <button
      ref={ref}
      type="button"
      title={title}
      aria-label={ariaLabel ?? title}
      aria-pressed={active}
      disabled={disabled}
      onClick={onClick}
      className={cx("u-btn u-btn--ghost u-iconbtn", tone === "destructive" && "u-iconbtn--destructive")}
      style={{ width: size, height: size, padding: 0 }}
    >
      <Icon name={icon} size={size >= 28 ? 16 : 14} />
    </button>
  );
}

// ── LinkBtn ────────────────────────────────────────────────────
/** A text link that does something here: --link at 500, underlined on hover. */
export function LinkBtn({
  children,
  onClick,
  title,
  style,
}: {
  children: ReactNode;
  onClick?: (e: ReactMouseEvent) => void;
  title?: string;
  style?: CSSProperties;
}) {
  return (
    <button type="button" className="u-link" title={title} onClick={onClick} style={style}>
      {children}
    </button>
  );
}

// ── Segmented (the toggle group) ───────────────────────────────
/**
 * One of a few, chosen in place: outline segments in one 28 px frame, the chosen
 * one --elevated at 600. A radio group: arrow keys move the choice. Never blue.
 */
export function Segmented<T extends string>({
  options,
  value,
  onChange,
  ariaLabel,
  size = "sm",
}: {
  options: { value: T; label: string; icon?: IconName }[];
  value: T;
  onChange: (v: T) => void;
  ariaLabel?: string;
  /** `sm` 28 px (default), `md` 32 px beside other 32 px controls. */
  size?: "sm" | "md";
}) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const chosen = options.findIndex((o) => o.value === value);

  const onKey = (e: ReactKeyboardEvent, i: number) => {
    const n = options.length;
    let next = -1;
    if (e.key === "ArrowRight" || e.key === "ArrowDown") next = (i + 1) % n;
    else if (e.key === "ArrowLeft" || e.key === "ArrowUp") next = (i - 1 + n) % n;
    else if (e.key === "Home") next = 0;
    else if (e.key === "End") next = n - 1;
    if (next < 0) return;
    e.preventDefault();
    onChange(options[next].value);
    refs.current[next]?.focus();
  };

  return (
    <div role="radiogroup" aria-label={ariaLabel} className="u-seg" style={{ height: size === "md" ? 32 : 28 }}>
      {options.map((o, i) => {
        const on = o.value === value;
        return (
          <button
            key={o.value}
            ref={(el) => {
              refs.current[i] = el;
            }}
            type="button"
            role="radio"
            aria-checked={on}
            tabIndex={on || (chosen < 0 && i === 0) ? 0 : -1}
            onClick={() => onChange(o.value)}
            onKeyDown={(e) => onKey(e, i)}
            className="u-seg__item"
          >
            {o.icon ? <Icon name={o.icon} size={14} /> : null}
            {o.label}
          </button>
        );
      })}
    </div>
  );
}

// ── Toggle (switch) ────────────────────────────────────────────
/** A round 36 × 20 track: --primary when on, --input when off. */
export function Toggle({
  checked,
  onChange,
  label,
  disabled,
  id,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label?: string;
  disabled?: boolean;
  id?: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      id={id}
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className="u-switch"
    >
      <span className="u-switch__thumb" aria-hidden="true" />
    </button>
  );
}

// ── StatusDot ──────────────────────────────────────────────────
export type DotStatus = "online" | "offline" | "warn" | "unknown";
const DOT_COLOR: Record<DotStatus, string> = {
  online: "var(--success)",
  offline: "var(--destructive)",
  warn: "var(--warning)",
  unknown: "var(--muted-foreground)",
};
/**
 * The 7 px round dot of a state; unknown is a hollow ring. It repeats a word
 * that stands beside it, so it is hidden from assistive technology unless it is
 * given its own `label`.
 */
export function StatusDot({
  status,
  size = 7,
  label,
}: {
  status: DotStatus;
  size?: number;
  label?: string;
}) {
  const c = DOT_COLOR[status];
  const hollow = status === "unknown";
  return (
    <span
      role={label ? "img" : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
      style={{
        width: size,
        height: size,
        borderRadius: "50%",
        background: hollow ? "transparent" : c,
        border: hollow ? `1px solid ${c}` : undefined,
        flexShrink: 0,
        display: "inline-block",
      }}
    />
  );
}

// ── Spinner ────────────────────────────────────────────────────
/** A turning ring in the current colour; standalone it is muted and says "loading". */
export function Spinner({
  size = 16,
  label,
  decorative,
}: {
  size?: number;
  /** What is loading, for assistive technology (default: common.loading). */
  label?: string;
  /** Inside a control that already says it is working (Btn sets aria-busy). */
  decorative?: boolean;
}) {
  const { t } = useTranslation();
  const ring = (
    <span
      aria-hidden="true"
      style={{
        width: size,
        height: size,
        flexShrink: 0,
        borderRadius: "50%",
        border: "2px solid color-mix(in oklch, currentColor 25%, transparent)",
        borderTopColor: "currentColor",
        display: "inline-block",
        animation: "spin .7s linear infinite",
      }}
    />
  );
  if (decorative) return ring;
  return (
    <span role="status" style={{ display: "inline-flex", color: "var(--muted-foreground)" }}>
      {ring}
      <span className="u-sr-only">{label ?? t("common.loading")}</span>
    </span>
  );
}

// ── Skeleton ───────────────────────────────────────────────────
/** A placeholder bar on --elevated that holds a value's place while it is read. */
export function Skeleton({
  width = "100%",
  height = 12,
  radius,
  style,
}: {
  width?: number | string;
  height?: number | string;
  radius?: number | string;
  style?: CSSProperties;
}) {
  return (
    <span
      aria-hidden="true"
      className="u-skeleton"
      style={{ width, height, borderRadius: radius, ...style }}
    />
  );
}

// ── SectionLabel ───────────────────────────────────────────────
/** The label style (11 px uppercase muted) naming the group of things below it. */
export function SectionLabel({
  children,
  id,
  style,
}: {
  children: ReactNode;
  id?: string;
  style?: CSSProperties;
}) {
  return (
    <div id={id} style={{ ...LABEL, ...style }}>
      {children}
    </div>
  );
}

// ── Missing ────────────────────────────────────────────────────
/** A missing value: a muted em dash. */
export function Missing() {
  return <span style={{ color: "var(--muted-foreground)" }}>—</span>;
}

// ── ToneBadge (the status badge) ───────────────────────────────
/**
 * The roles a state can take: `success` (active, ok, done), `warning` (pending,
 * caution, stale, degraded), `destructive` (revoked, disabled, failure),
 * `neutral` (a plain fact, work in progress) and `absent` (unknown, expired,
 * not there: muted, dashed, no fill).
 */
export type Tone = "success" | "warning" | "destructive" | "neutral" | "absent";

const TONE_STYLE: Record<Tone, CSSProperties> = {
  success: { color: "var(--success)", background: tint("var(--success)") },
  warning: { color: "var(--warning)", background: tint("var(--warning)") },
  destructive: { color: "var(--destructive)", background: tint("var(--destructive)") },
  neutral: { color: "var(--foreground)", background: "var(--elevated)" },
  absent: {
    color: "var(--muted-foreground)",
    background: "transparent",
    borderColor: "var(--border)",
    borderStyle: "dashed",
  },
};

const CHIP: CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  flexShrink: 0,
  height: 20,
  padding: "0 8px",
  borderRadius: "var(--radius-sm)",
  borderWidth: 1,
  borderStyle: "solid",
  borderColor: "transparent",
  fontSize: 11,
  fontWeight: 600,
  lineHeight: 1,
  whiteSpace: "nowrap",
};

/** A state as a word with a 7 px dot, in the colour of its role, on its 15 % tint. 20 px tall. */
export function ToneBadge({
  tone,
  children,
  title,
}: {
  tone: Tone;
  children: ReactNode;
  title?: string;
}) {
  return (
    <span title={title} style={{ ...CHIP, gap: 6, ...TONE_STYLE[tone] }}>
      <span
        aria-hidden="true"
        style={{ width: 7, height: 7, borderRadius: "50%", background: "currentColor", flexShrink: 0 }}
      />
      {children}
    </span>
  );
}

// ── Tag ────────────────────────────────────────────────────────
/**
 * Legacy tones. A tag is a plain fact, not a state: `neutral` (and `accent`,
 * since blue is never decoration) is full text on --elevated; green / amber /
 * red repeat a state as text on its tint; `purple` is the violet series.
 */
export type TagTone = "accent" | "green" | "amber" | "red" | "purple" | "neutral";

const TAG_STYLE: Record<TagTone, CSSProperties> = {
  accent: TONE_STYLE.neutral,
  neutral: TONE_STYLE.neutral,
  green: TONE_STYLE.success,
  amber: TONE_STYLE.warning,
  red: TONE_STYLE.destructive,
  purple: { color: "var(--series-4)", background: tint("var(--series-4)") },
};

/** A plain fact in a 20 px chip, no dot. `outline`: full text inside a --border hairline. */
export function Tag({
  tone = "neutral",
  children,
  mono,
  variant = "filled",
  title,
}: {
  tone?: TagTone;
  children: ReactNode;
  /** Machine text (a code, an id): JetBrains Mono. */
  mono?: boolean;
  variant?: "filled" | "outline";
  title?: string;
}) {
  const look: CSSProperties =
    variant === "outline" && (tone === "neutral" || tone === "accent")
      ? { color: "var(--foreground)", background: "transparent", borderColor: "var(--border)" }
      : TAG_STYLE[tone];
  return (
    <span
      title={title}
      style={{
        ...CHIP,
        ...look,
        fontFamily: mono ? MONO : undefined,
        fontWeight: mono ? 500 : 600,
      }}
    >
      {children}
    </span>
  );
}

// ── Badges ─────────────────────────────────────────────────────
/**
 * A role is a fact, not a state: admin filled, the others outlined. The word
 * is the panel's (`role.*`); an unknown role shows as the server named it.
 */
export function RoleBadge({ role }: { role: string }) {
  const { t } = useTranslation();
  return (
    <Tag variant={role === "admin" ? "filled" : "outline"}>{t(`role.${role}`, { defaultValue: role })}</Tag>
  );
}
/** A tier: the org tier in the violet series, the others outlined. */
export function TierBadge({ tier }: { tier: string }) {
  return tier === "org" ? <Tag tone="purple">{tier}</Tag> : <Tag variant="outline">{tier}</Tag>;
}

const STATE_TONE: Record<string, Tone> = {
  active: "success",
  done: "success",
  ok: "success",
  healthy: "success",
  pending: "warning",
  msg1: "warning",
  msg2: "warning",
  msg3: "warning",
  stale: "warning",
  lagging: "warning",
  degraded: "warning",
  revoked: "destructive",
  suspended: "destructive",
  disabled: "destructive",
  failed: "destructive",
  failing: "destructive",
  expired: "absent",
  unknown: "absent",
  redeemed: "neutral",
  open: "neutral",
};
/**
 * The status badge of a known state word, said in the panel's word for it
 * (`state.*`; an unknown state shows as the server named it). `label` replaces
 * that word; `tone` overrides the role the state maps to.
 */
export function StateBadge({
  state,
  label,
  tone,
}: {
  state: string;
  label?: ReactNode;
  tone?: Tone;
}) {
  const { t } = useTranslation();
  return (
    <ToneBadge tone={tone ?? STATE_TONE[state] ?? "neutral"}>
      {label ?? t(`state.${state}`, { defaultValue: state })}
    </ToneBadge>
  );
}

// ── Avatar ─────────────────────────────────────────────────────
/**
 * @deprecated No gradients (the No-Hue Rule). Returns the initials tile's
 * ground, `var(--elevated)`; text on it must be `var(--foreground)`.
 */
export function gradientFor(_seed: number): string {
  return "var(--elevated)";
}
/** Two initials from the words that start with a letter or a digit: "Anna · personal" gives "AP", not "A·". */
export function initialsOf(name: string): string {
  return name
    .split(/\s+/)
    .filter((w) => /^[\p{L}\p{N}]/u.test(w))
    .map((w) => [...w][0])
    .join("")
    .slice(0, 2)
    .toUpperCase();
}
/**
 * An initials tile: mono letters on --elevated with 5 px corners. The signed-in
 * account's own is `round` on `primary`. `seed` is accepted and ignored.
 */
export function Avatar({
  label,
  size = 38,
  round,
  tone = "neutral",
}: {
  label: string;
  /** @deprecated Ignored: tiles no longer vary by colour. */
  seed?: number;
  size?: number;
  round?: boolean;
  tone?: "neutral" | "primary";
}) {
  const primary = tone === "primary";
  return (
    <span
      style={{
        width: size,
        height: size,
        borderRadius: round ? "50%" : "var(--radius-sm)",
        background: primary ? "var(--primary)" : "var(--elevated)",
        color: primary ? "var(--primary-foreground)" : "var(--foreground)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        fontFamily: MONO,
        fontWeight: 700,
        fontSize: Math.max(10, Math.round(size * 0.36)),
        letterSpacing: "0.05em",
        lineHeight: 1,
        flexShrink: 0,
      }}
    >
      {label}
    </span>
  );
}

// ── Copy failure popover ───────────────────────────────────────
/**
 * The browser refused a copy: a popover beside the button, in red copy with the
 * way out (the value itself, selectable). It stays until dismissed.
 */
function CopyFailed({
  anchor,
  value,
  onDismiss,
}: {
  anchor: RefObject<HTMLElement | null>;
  value: string;
  onDismiss: () => void;
}) {
  const { t } = useTranslation();
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);

  useLayoutEffect(() => {
    const place = () => {
      const r = anchor.current?.getBoundingClientRect();
      if (!r) return;
      setPos({ top: r.bottom + 6, left: Math.max(8, Math.min(r.left, window.innerWidth - 300)) });
    };
    place();
    window.addEventListener("scroll", place, true);
    window.addEventListener("resize", place);
    return () => {
      window.removeEventListener("scroll", place, true);
      window.removeEventListener("resize", place);
    };
  }, [anchor]);

  // Escape closes the popover only, not the dialog or drawer under it.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      e.stopPropagation();
      onDismiss();
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [onDismiss]);

  if (!pos) return null;
  return createPortal(
    <div
      onClick={(e) => e.stopPropagation()}
      style={{
        position: "fixed",
        top: pos.top,
        left: pos.left,
        zIndex: 400,
        width: 292,
        padding: 12,
        background: "var(--popover)",
        color: "var(--foreground)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius-md)",
        boxShadow: "var(--elev-popover)",
        fontFamily: "var(--font-sans)",
        animation: "popIn var(--duration-base) var(--ease-out-soft)",
      }}
    >
      <div style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
        <p role="alert" style={{ ...COPY, margin: 0, flex: 1, color: "var(--destructive)" }}>
          {t("common.copyFailed")}
        </p>
        <IconBtn icon="x" size={24} title={t("common.close")} onClick={onDismiss} />
      </div>
      <div
        style={{
          ...WELL,
          marginTop: 8,
          fontFamily: MONO,
          fontSize: 12,
          lineHeight: "16px",
          wordBreak: "break-all",
          userSelect: "all",
        }}
      >
        {value}
      </div>
    </div>,
    document.body,
  );
}

// ── PubkeyChip ─────────────────────────────────────────────────
/** A key or id in muted mono, cut in the middle (per prefs), with its copy button. */
export function PubkeyChip({
  value,
  prefix = "",
  head = 6,
  tail = 4,
}: {
  value: string | null | undefined;
  prefix?: string;
  head?: number;
  tail?: number;
}) {
  const { t } = useTranslation();
  const fmt = usePrefs((s) => s.pubkeyFormat);
  const { copied, failed, copy, dismiss } = useCopy(1500);
  const btn = useRef<HTMLButtonElement>(null);
  const v = value ?? "";
  const shown =
    fmt === "full" || v.length <= head + tail + 1
      ? v
      : `${v.slice(0, head)}…${v.slice(-tail)}`;
  const onCopy = (e: ReactMouseEvent) => {
    e.stopPropagation();
    if (!v) return;
    copy(v);
  };
  if (!v) return <Missing />;
  const name = copied ? t("common.copied") : t("common.copy");
  return (
    <span
      title={v}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 2,
        maxWidth: "100%",
        fontFamily: MONO,
        fontSize: 12,
        lineHeight: "16px",
        color: "var(--muted-foreground)",
      }}
    >
      <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        {prefix}
        {shown}
      </span>
      <button
        ref={btn}
        type="button"
        onClick={onCopy}
        title={name}
        aria-label={name}
        className="u-btn u-btn--ghost u-iconbtn"
        style={{
          width: 24,
          height: 24,
          padding: 0,
          color: copied ? "var(--success)" : failed ? "var(--destructive)" : undefined,
        }}
      >
        <Icon name={copied ? "check" : failed ? "x" : "copy"} size={14} />
      </button>
      {failed ? <CopyFailed anchor={btn} value={v} onDismiss={dismiss} /> : null}
    </span>
  );
}

// ── ZkBanner ───────────────────────────────────────────────────
/**
 * The zero-knowledge boundary, said where it applies: explicit and unmissable.
 * A solid box whose sentence opens with "Zero-knowledge." at 600 (no eyebrow
 * over the text); `amber` (a limit of the guarantee) is the caution box:
 * warning edge at 40 % on a 10 % fill. It is the only place a screen says it:
 * the page title carries no zero-knowledge tag.
 */
export function ZkBanner({
  children,
  tone = "accent",
}: {
  children: ReactNode;
  tone?: "accent" | "amber";
}) {
  const { t } = useTranslation();
  const caution = tone === "amber";
  return (
    <div
      role="note"
      style={{
        display: "flex",
        gap: 12,
        alignItems: "flex-start",
        padding: "12px 16px",
        borderRadius: "var(--radius-lg)",
        border: `1px solid ${caution ? tint("var(--warning)", 40) : "var(--border)"}`,
        background: caution ? tint("var(--warning)", 10) : "var(--card)",
        boxShadow: caution ? undefined : "var(--elev-card)",
      }}
    >
      <span
        aria-hidden="true"
        style={{
          width: 22,
          height: 22,
          borderRadius: "var(--radius-md)",
          background: caution ? "transparent" : "var(--elevated)",
          color: caution ? "var(--warning)" : "var(--foreground)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          flexShrink: 0,
        }}
      >
        <Icon name={caution ? "alert" : "shieldcheck"} size={caution ? 16 : 14} />
      </span>
      <div style={{ ...COPY, minWidth: 0, paddingTop: 1, color: "var(--foreground)" }}>
        <strong style={{ fontWeight: 600 }}>{t("zk.lead", { defaultValue: "Zero-knowledge." })}</strong> {children}
      </div>
    </div>
  );
}

// ── Stat tiles ─────────────────────────────────────────────────
const TilesCtx = createContext(false);

/**
 * The figures of a page in one card, as columns divided by rules: two on a
 * phone, `cols` (default 4) from 1024 px. Holds StatTile / KpiCard children.
 */
export function StatTiles({
  children,
  cols = 4,
  style,
}: {
  children: ReactNode;
  cols?: 3 | 4 | 5 | 6;
  style?: CSSProperties;
}) {
  return (
    <TilesCtx.Provider value={true}>
      <div className="u-tiles" data-cols={cols} style={style}>
        {children}
      </div>
    </TilesCtx.Provider>
  );
}

/**
 * One figure: the label in the label style, the figure at 20/600, muted note
 * lines at 12 px. A card of its own unless it stands in StatTiles. `tone`
 * colours a count that stands for a state (errors above zero).
 */
export function StatTile({
  label,
  value,
  children,
  onClick,
  tone,
  loading,
}: {
  label: string;
  value: ReactNode;
  children?: ReactNode;
  onClick?: () => void;
  tone?: "destructive" | "warning";
  loading?: boolean;
}) {
  const inTiles = useContext(TilesCtx);
  const body = (
    <>
      <div style={{ ...LABEL, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={label}>
        {label}
      </div>
      <div
        style={{
          marginTop: 4,
          fontSize: 20,
          fontWeight: 600,
          lineHeight: "28px",
          letterSpacing: "-0.025em",
          color: tone ? `var(--${tone})` : undefined,
        }}
      >
        {loading ? <Skeleton width={56} height={28} /> : value}
      </div>
      {children ? (
        <div
          style={{
            marginTop: 4,
            display: "grid",
            gap: 4,
            fontSize: 12,
            lineHeight: "16px",
            color: "var(--muted-foreground)",
          }}
        >
          {children}
        </div>
      ) : null}
    </>
  );
  const pad: CSSProperties = { padding: "12px 16px", minWidth: 0 };
  if (onClick) {
    return (
      <button
        type="button"
        onClick={onClick}
        className={cx("u-tile-btn", !inTiles && "u-tile-btn--card")}
        style={pad}
      >
        {body}
      </button>
    );
  }
  return (
    <div
      style={
        inTiles
          ? pad
          : {
              ...pad,
              background: "var(--card)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-lg)",
              boxShadow: "var(--elev-card)",
            }
      }
    >
      {body}
    </div>
  );
}

/** Legacy name of StatTile: `delta` is its note line; `icon` and `deltaColor` are ignored. */
export function KpiCard({
  label,
  value,
  delta,
  onClick,
}: {
  label: string;
  value: string;
  delta?: string;
  /** @deprecated Ignored: growth is said by its sign and number, never by colour. */
  deltaColor?: string;
  /** @deprecated Ignored: stat tiles carry no icon. */
  icon: IconName;
  onClick?: () => void;
}) {
  return (
    <StatTile label={label} value={value} onClick={onClick}>
      {delta ? <span>{delta}</span> : null}
    </StatTile>
  );
}

// ── Field + TextInput ──────────────────────────────────────────
/** What a Field tells the control inside it: the ids of its hint and error, and whether it is in error. */
interface FieldInfo {
  describedBy?: string;
  invalid: boolean;
}
const FieldCtx = createContext<FieldInfo>({ invalid: false });

/**
 * For a custom control inside a Field: the `aria-describedby` ids of the
 * Field's error and hint, and whether the Field shows an error.
 */
export function useField(): FieldInfo {
  return useContext(FieldCtx);
}

function joinIds(...ids: (string | false | null | undefined)[]): string | undefined {
  const s = ids.filter(Boolean).join(" ");
  return s || undefined;
}

/**
 * A label above its control at 8 px (13/500), an optional muted `tag` at the
 * right, the muted hint under it, and the error in red copy (role="alert").
 * The hint and the error carry ids; a TextInput inside picks them up as its
 * aria-describedby (and aria-invalid while there is an error) by itself.
 */
export function Field({
  label,
  children,
  hint,
  tag,
  tagMono,
  error,
  htmlFor,
  style,
}: {
  label: ReactNode;
  children: ReactNode;
  hint?: ReactNode;
  /** A short word at the right of the label ("optional", "keyset"): the panel's own words, so sans. */
  tag?: string;
  /** The tag is machine text (an API field, a file name): set it in mono. */
  tagMono?: boolean;
  error?: ReactNode;
  /** The id of the control, to bind the label to it. */
  htmlFor?: string;
  style?: CSSProperties;
}) {
  const base = useId();
  const hintId = `${base}-hint`;
  const errorId = `${base}-error`;
  const info: FieldInfo = {
    describedBy: joinIds(error ? errorId : null, hint ? hintId : null),
    invalid: !!error,
  };
  const labelStyle: CSSProperties = { fontSize: 13, fontWeight: 500, lineHeight: "16px" };
  return (
    <div style={{ marginBottom: 16, ...style }}>
      <div
        style={{
          display: "flex",
          alignItems: "baseline",
          justifyContent: "space-between",
          gap: 8,
          marginBottom: 8,
        }}
      >
        {htmlFor ? (
          <label htmlFor={htmlFor} style={labelStyle}>
            {label}
          </label>
        ) : (
          <div style={labelStyle}>{label}</div>
        )}
        {tag ? (
          <span
            style={{
              fontFamily: tagMono ? MONO : undefined,
              fontSize: tagMono ? 11 : 12,
              lineHeight: "16px",
              color: "var(--muted-foreground)",
              whiteSpace: "nowrap",
            }}
          >
            {tag}
          </span>
        ) : null}
      </div>
      <FieldCtx.Provider value={info}>{children}</FieldCtx.Provider>
      {error ? (
        <p id={errorId} role="alert" style={{ ...COPY, margin: "8px 0 0", color: "var(--destructive)" }}>
          {error}
        </p>
      ) : null}
      {hint ? (
        <p id={hintId} style={{ ...COPY, margin: "8px 0 0", color: "var(--muted-foreground)" }}>
          {hint}
        </p>
      ) : null}
    </div>
  );
}

/**
 * A 32 px field on the --input hairline. `secret` masks a token without being a
 * password field. Inside a Field it is described by the Field's hint and error.
 */
export function TextInput({
  value,
  onChange,
  placeholder,
  type = "text",
  mono,
  onFile,
  accept,
  ariaLabel,
  inputMode,
  autoFocus,
  id,
  name,
  invalid,
  disabled,
  autoComplete,
  secret,
  describedBy,
  style,
}: {
  value?: string;
  onChange?: (v: string) => void;
  placeholder?: string;
  type?: "text" | "password" | "file";
  mono?: boolean;
  onFile?: (f: File) => void;
  accept?: string;
  ariaLabel?: string;
  inputMode?: "text" | "numeric";
  autoFocus?: boolean;
  id?: string;
  name?: string;
  /** Draws the red edge and sets aria-invalid; say why in Field's `error`. Defaults to the Field's state. */
  invalid?: boolean;
  disabled?: boolean;
  autoComplete?: string;
  secret?: boolean;
  /** Ids of the elements that describe the field (a hint, an error); joined with the Field's own. */
  describedBy?: string;
  style?: CSSProperties;
}) {
  const field = useField();
  const isInvalid = invalid ?? field.invalid;
  return (
    <input
      id={id}
      name={name}
      type={type}
      autoFocus={autoFocus}
      value={type === "file" ? undefined : value}
      accept={accept}
      placeholder={placeholder}
      aria-label={ariaLabel}
      aria-invalid={isInvalid || undefined}
      aria-describedby={joinIds(describedBy, field.describedBy)}
      inputMode={inputMode}
      disabled={disabled}
      autoComplete={autoComplete ?? (secret ? "off" : undefined)}
      spellCheck={mono || secret ? false : undefined}
      onChange={(e) => {
        if (type === "file") {
          const f = e.target.files?.[0];
          if (f && onFile) onFile(f);
        } else onChange?.(e.target.value);
      }}
      className={cx("u-input", secret && "u-input--secret")}
      style={{
        fontFamily: mono ? MONO : undefined,
        fontSize: mono ? 12 : undefined,
        ...style,
      }}
    />
  );
}

// ── EmptyState / ErrorCard ─────────────────────────────────────
/**
 * Nothing here yet: a dashed 10 px box, a 20 px muted icon, one sentence and the
 * action that changes it (an outline button). `compact`: one row inside a card
 * that already has a head. `flat`: no box (the card around it is the box).
 */
export function EmptyState({
  icon = "box",
  title,
  hint,
  actionLabel,
  onAction,
  action,
  compact,
  flat,
}: {
  icon?: IconName;
  title: string;
  hint?: string;
  actionLabel?: string;
  onAction?: () => void;
  /** A custom action in place of actionLabel/onAction. */
  action?: ReactNode;
  compact?: boolean;
  flat?: boolean;
}) {
  const act =
    action ??
    (actionLabel && onAction ? (
      <Btn size="sm" variant="outline" onClick={onAction}>
        {actionLabel}
      </Btn>
    ) : null);
  const muted: CSSProperties = { color: "var(--muted-foreground)", margin: 0 };
  if (compact) {
    return (
      <div
        style={{
          display: "flex",
          flexWrap: "wrap",
          alignItems: "center",
          justifyContent: "center",
          gap: "8px 12px",
          padding: "12px 16px",
          textAlign: "center",
          border: flat ? 0 : "1px dashed var(--border)",
          borderRadius: flat ? 0 : "var(--radius-lg)",
        }}
      >
        <Icon name={icon} size={16} color="var(--muted-foreground)" />
        <p style={{ ...COPY, ...muted, maxWidth: "48ch" }}>
          {title}
          {hint ? ` ${hint}` : null}
        </p>
        {act}
      </div>
    );
  }
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        gap: 12,
        padding: "40px 24px",
        textAlign: "center",
        border: flat ? 0 : "1px dashed var(--border)",
        borderRadius: flat ? 0 : "var(--radius-lg)",
      }}
    >
      <Icon name={icon} size={20} color="var(--muted-foreground)" />
      <div style={{ maxWidth: "48ch" }}>
        <p style={{ ...COPY, ...muted, fontWeight: 500 }}>{title}</p>
        {hint ? <p style={{ ...COPY, ...muted, marginTop: 4 }}>{hint}</p> : null}
      </div>
      {act}
    </div>
  );
}

/** Which failure a box says: no connection, the server, no rights, not there, or none known. */
export type FailKind = "network" | "server" | "forbidden" | "notFound" | "generic";

/** The failure an HTTP status stands for; 0 is no connection (how the API client marks a network error). */
export function failKindOf(status: number | undefined): FailKind {
  if (status === undefined) return "generic";
  if (status === 0) return "network";
  if (status === 401 || status === 403) return "forbidden";
  if (status === 404 || status === 410) return "notFound";
  if (status >= 500) return "server";
  return "generic";
}

const FAIL_KEY: Record<FailKind, string> = {
  network: "common.failNetwork",
  server: "common.failServer",
  forbidden: "common.failForbidden",
  notFound: "common.failNotFound",
  generic: "common.failGeneric",
};
const FAIL_DEFAULT: Record<FailKind, string> = {
  network: "No connection to the server.",
  server: "The server returned an error.",
  forbidden: "You don't have the rights for this.",
  notFound: "Not found.",
  generic: "Couldn't load this.",
};

/**
 * A failure, drawn where the thing that failed would stand: a solid 10 px box,
 * red at 40 % on a 10 % fill, role="alert". It says which failure it is in a
 * sentence of red copy (from `kind`, else `status`, else the generic one), the
 * server's own words under it in muted mono at 12 px, and "try again" as an
 * outline button at its right. `band`: inside a card, no edge.
 */
export function ErrorCard({
  message,
  kind,
  status,
  onRetry,
  band,
  retrying,
  retryLabel,
}: {
  /** The raw detail (the server's message, or the browser's); shown under the lead. */
  message: string;
  /** Which failure it is. Wins over `status`. */
  kind?: FailKind;
  /** The HTTP status of the failure (0 for no connection); picks `kind` when that is not given. */
  status?: number;
  onRetry?: () => void;
  band?: boolean;
  retrying?: boolean;
  retryLabel?: string;
}) {
  const { t } = useTranslation();
  const k = kind ?? failKindOf(status);
  const detail = message.trim();
  return (
    <div
      style={{
        display: "flex",
        flexWrap: "wrap",
        alignItems: "center",
        gap: "8px 12px",
        padding: "12px 16px",
        background: tint("var(--destructive)", 10),
        border: band ? 0 : `1px solid ${tint("var(--destructive)", 40)}`,
        borderRadius: band ? 0 : "var(--radius-lg)",
      }}
    >
      <div role="alert" style={{ flex: "1 1 16rem", minWidth: 0, maxWidth: "72ch" }}>
        <p style={{ ...COPY, margin: 0, color: "var(--destructive)" }}>
          {t(FAIL_KEY[k], { defaultValue: FAIL_DEFAULT[k] })}
        </p>
        {detail ? (
          <p
            style={{
              margin: "2px 0 0",
              fontFamily: MONO,
              fontSize: 12,
              lineHeight: "16px",
              color: "var(--muted-foreground)",
              overflowWrap: "anywhere",
            }}
          >
            {detail}
          </p>
        ) : null}
      </div>
      {onRetry ? (
        <Btn
          size="sm"
          variant="outline"
          icon="refresh"
          loading={retrying}
          onClick={onRetry}
          style={{ marginLeft: "auto", flexShrink: 0 }}
        >
          {retryLabel ?? t("common.retry")}
        </Btn>
      ) : null}
    </div>
  );
}

// ── InlineError ────────────────────────────────────────────────
/** The failure box in compact form, inside a dialog or a form: red copy, role="alert". */
export function InlineError({ children }: { children: ReactNode }) {
  return (
    <div
      role="alert"
      style={{
        display: "flex",
        gap: 8,
        alignItems: "flex-start",
        padding: "8px 12px",
        marginBottom: 12,
        background: tint("var(--destructive)", 10),
        border: `1px solid ${tint("var(--destructive)", 40)}`,
        borderRadius: "var(--radius-lg)",
        fontSize: 14,
        lineHeight: "20px",
        color: "var(--destructive)",
      }}
    >
      <Icon name="alert" size={16} style={{ marginTop: 2 }} />
      <div style={{ minWidth: 0, overflowWrap: "anywhere" }}>{children}</div>
    </div>
  );
}

// ── Well ───────────────────────────────────────────────────────
/**
 * A block inside a card or a dialog that holds a value to copy, a payload or a
 * running job: --elevated on a --rule hairline, 7 px corners. `dashed`: a slot
 * that is still empty (no fill).
 */
export function Well({
  children,
  dashed,
  style,
}: {
  children: ReactNode;
  dashed?: boolean;
  style?: CSSProperties;
}) {
  return (
    <div
      style={{
        ...WELL,
        ...(dashed ? { background: "transparent", borderStyle: "dashed", borderColor: "var(--border)" } : null),
        ...style,
      }}
    >
      {children}
    </div>
  );
}

// ── SecretRow ──────────────────────────────────────────────────
/** A value to copy in a well (mono, selectable) with an outline copy button. */
export function SecretRow({
  label,
  value,
  onCopy,
}: {
  label: string;
  value: string;
  onCopy?: () => void;
}) {
  const { t } = useTranslation();
  const { copied, failed, copy } = useCopy(1500);
  return (
    <div>
      <div style={{ fontSize: 13, fontWeight: 500, lineHeight: "16px", marginBottom: 8 }}>{label}</div>
      <div
        style={{
          ...WELL,
          display: "flex",
          alignItems: "center",
          gap: 8,
          padding: "6px 6px 6px 12px",
        }}
      >
        <span
          style={{
            flex: 1,
            minWidth: 0,
            fontFamily: MONO,
            fontSize: 12,
            lineHeight: "16px",
            color: value ? "var(--foreground)" : "var(--muted-foreground)",
            wordBreak: "break-all",
            userSelect: "all",
          }}
        >
          {value || "—"}
        </span>
        <Btn
          size="sm"
          variant="outline"
          icon={copied ? "check" : failed ? "x" : "copy"}
          iconColor={copied ? "var(--success)" : failed ? "var(--destructive)" : undefined}
          onClick={() => {
            copy(value);
            onCopy?.();
          }}
        >
          {copied ? t("common.copied") : t("common.copy")}
        </Btn>
      </div>
      {failed ? (
        <p role="alert" style={{ ...COPY, margin: "8px 0 0", color: "var(--destructive)" }}>
          {t("common.copyFailed")}
        </p>
      ) : null}
    </div>
  );
}

// ── Card ───────────────────────────────────────────────────────
/**
 * An object on the sheet: --card, a --border hairline, 10 px corners, the
 * whisper of --elev-card. Panels pad 16; `pad={false}` for a flush table or a
 * CardHeader (the content is then clipped to the corners). `dashed`: absent or
 * archived (no fill, no shadow).
 */
export function Card({
  children,
  style,
  pad = true,
  dashed,
}: {
  children: ReactNode;
  style?: CSSProperties;
  pad?: boolean;
  dashed?: boolean;
}) {
  return (
    <div
      style={{
        background: dashed ? "transparent" : "var(--card)",
        border: `1px ${dashed ? "dashed" : "solid"} var(--border)`,
        borderRadius: "var(--radius-lg)",
        boxShadow: dashed ? "none" : "var(--elev-card)",
        padding: pad ? 16 : 0,
        overflow: pad ? undefined : "hidden",
        ...style,
      }}
    >
      {children}
    </div>
  );
}

/** The head of a card: 16 × 12 over a --rule, the title (15/600) left, actions right. */
export function CardHeader({
  title,
  actions,
  children,
  style,
}: {
  title?: ReactNode;
  actions?: ReactNode;
  /** Anything between the title and the actions (a count, a muted note). */
  children?: ReactNode;
  style?: CSSProperties;
}) {
  return (
    <div
      style={{
        display: "flex",
        flexWrap: "wrap",
        alignItems: "center",
        justifyContent: "space-between",
        gap: "8px 12px",
        minHeight: 48,
        padding: "12px 16px",
        borderBottom: "1px solid var(--rule)",
        ...style,
      }}
    >
      {title != null ? (
        <h2 style={{ margin: 0, fontSize: 15, fontWeight: 600, lineHeight: "20px", letterSpacing: "-0.025em" }}>
          {title}
        </h2>
      ) : null}
      {children}
      {actions ? <div style={{ display: "flex", alignItems: "center", gap: 8, marginLeft: "auto" }}>{actions}</div> : null}
    </div>
  );
}

// ── Summary line ───────────────────────────────────────────────
/** The count of a summary line at 500 in full text: "in all: N" (or your own words). */
export function SummaryCount({ n, children }: { n?: number; children?: ReactNode }) {
  const { t, i18n } = useTranslation();
  return (
    <span style={{ fontWeight: 500, color: "var(--foreground)" }}>
      {children ?? t("common.inAll", { n: (n ?? 0).toLocaleString(i18n.language) })}
    </span>
  );
}

/** One part of a summary line, "label: value" (the value mono); with `onClick` it narrows the list. */
export function SummaryPart({
  label,
  value,
  onClick,
  active,
}: {
  label: ReactNode;
  value: ReactNode;
  onClick?: () => void;
  /** The part in effect: 600. */
  active?: boolean;
}) {
  const inner = (
    <>
      {label}: <span style={{ fontFamily: MONO, color: "var(--foreground)" }}>{value}</span>
    </>
  );
  const weight: CSSProperties = { fontWeight: active ? 600 : undefined };
  return onClick ? (
    <button type="button" className="u-summary-link" aria-pressed={active} onClick={onClick} style={weight}>
      {inner}
    </button>
  ) : (
    <span style={weight}>{inner}</span>
  );
}

/**
 * How many, above a table's head: a 32 px line, 16 px in, 12 px muted text, a
 * --rule under it. `count` puts "in all: N" first; while `loading`, a skeleton
 * holds the count's place. Further parts (SummaryPart) follow at 16 px gaps.
 */
export function SummaryLine({
  count,
  loading,
  children,
  style,
}: {
  count?: number;
  loading?: boolean;
  children?: ReactNode;
  style?: CSSProperties;
}) {
  return (
    <div
      style={{
        display: "flex",
        flexWrap: "wrap",
        alignItems: "center",
        columnGap: 16,
        minHeight: 32,
        padding: "0 16px",
        borderBottom: "1px solid var(--rule)",
        fontSize: 12,
        lineHeight: "16px",
        color: "var(--muted-foreground)",
        ...style,
      }}
    >
      {loading ? <Skeleton width={96} height={12} /> : count != null ? <SummaryCount n={count} /> : null}
      {children}
    </div>
  );
}
