import { type CSSProperties, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { usePrefs } from "../store/prefs";
import { Icon, type IconName } from "./icons";
import { MONO } from "../theme/tokens";
import { useCopy } from "./useCopy";

// ── Btn ────────────────────────────────────────────────────────
type BtnVariant = "primary" | "outline" | "ghost" | "soft" | "danger";
type BtnSize = "sm" | "md" | "lg";

const SIZE_PAD: Record<BtnSize, string> = {
  sm: "6px 11px",
  md: "8px 14px",
  lg: "10px 18px",
};
const SIZE_FONT: Record<BtnSize, number> = { sm: 12, md: 13.5, lg: 14 };

export function Btn({
  variant = "outline",
  size = "md",
  icon,
  iconRight,
  onClick,
  disabled,
  loading,
  type = "button",
  full,
  title,
  children,
  style,
}: {
  variant?: BtnVariant;
  size?: BtnSize;
  icon?: IconName;
  iconRight?: IconName;
  onClick?: (e: React.MouseEvent) => void;
  disabled?: boolean;
  loading?: boolean;
  type?: "button" | "submit";
  full?: boolean;
  title?: string;
  children?: ReactNode;
  style?: CSSProperties;
}) {
  const variantStyle: CSSProperties =
    variant === "primary"
      ? { background: "var(--accent)", color: "#fff", border: "1px solid transparent", boxShadow: "0 6px 18px -6px var(--accent)" }
      : variant === "soft"
        ? { background: "var(--accentSoft)", color: "var(--accent)", border: "1px solid var(--accentLine)" }
        : variant === "ghost"
          ? { background: "var(--bg3)", color: "var(--txt)", border: "1px solid var(--line)" }
          : variant === "danger"
            ? { background: "transparent", color: "var(--red)", border: "1px solid color-mix(in srgb, var(--red) 40%, transparent)" }
            : { background: "transparent", color: "var(--txt)", border: "1px solid var(--line2)" };

  return (
    <button
      type={type}
      title={title}
      onClick={onClick}
      disabled={disabled || loading}
      style={{
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        gap: 7,
        padding: SIZE_PAD[size],
        fontSize: SIZE_FONT[size],
        fontWeight: variant === "primary" ? 700 : 600,
        fontFamily: "inherit",
        borderRadius: 9,
        cursor: disabled || loading ? "default" : "pointer",
        opacity: disabled ? 0.5 : 1,
        width: full ? "100%" : undefined,
        whiteSpace: "nowrap",
        ...variantStyle,
        ...style,
      }}
    >
      {loading ? <Spinner size={14} /> : icon ? <Icon name={icon} size={15} stroke={1.8} /> : null}
      {children}
      {iconRight ? <Icon name={iconRight} size={15} stroke={1.8} /> : null}
    </button>
  );
}

// ── IconBtn ────────────────────────────────────────────────────
export function IconBtn({
  icon,
  onClick,
  active,
  title,
  size = 30,
}: {
  icon: IconName;
  onClick?: (e: React.MouseEvent) => void;
  active?: boolean;
  title?: string;
  size?: number;
}) {
  return (
    <button
      type="button"
      title={title}
      onClick={onClick}
      style={{
        width: size,
        height: size,
        borderRadius: 8,
        border: active ? "1px solid var(--accentLine)" : "1px solid var(--line)",
        background: active ? "var(--accentSoft)" : "var(--bg2)",
        color: active ? "var(--accent)" : "var(--txt2)",
        cursor: "pointer",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
      }}
    >
      <Icon name={icon} size={15} />
    </button>
  );
}

// ── Segmented ──────────────────────────────────────────────────
export function Segmented<T extends string>({
  options,
  value,
  onChange,
}: {
  options: { value: T; label: string; icon?: IconName }[];
  value: T;
  onChange: (v: T) => void;
}) {
  return (
    <div
      role="tablist"
      style={{
        display: "flex",
        gap: 3,
        padding: 3,
        background: "var(--bg2)",
        border: "1px solid var(--line)",
        borderRadius: 10,
      }}
    >
      {options.map((o) => {
        const on = o.value === value;
        return (
          <button
            key={o.value}
            role="tab"
            aria-selected={on}
            onClick={() => onChange(o.value)}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
              padding: "6px 13px",
              borderRadius: 7,
              border: "none",
              cursor: "pointer",
              fontFamily: "inherit",
              fontSize: 12.5,
              fontWeight: on ? 700 : 600,
              background: on ? "var(--bg4)" : "transparent",
              color: on ? "var(--txt)" : "var(--txt3)",
            }}
          >
            {o.icon ? <Icon name={o.icon} size={14} /> : null}
            {o.label}
          </button>
        );
      })}
    </div>
  );
}

// ── Toggle ─────────────────────────────────────────────────────
export function Toggle({
  checked,
  onChange,
  label,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label?: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      onClick={() => onChange(!checked)}
      style={{
        width: 44,
        height: 26,
        borderRadius: 13,
        border: "1px solid var(--line2)",
        background: checked ? "var(--accent)" : "var(--bg3)",
        position: "relative",
        cursor: "pointer",
        flexShrink: 0,
        transition: "background .15s",
      }}
    >
      <span
        style={{
          position: "absolute",
          top: 2,
          left: checked ? 20 : 2,
          width: 20,
          height: 20,
          borderRadius: "50%",
          background: "#fff",
          transition: "left .15s",
          boxShadow: "0 1px 3px rgba(0,0,0,.3)",
        }}
      />
    </button>
  );
}

// ── StatusDot ──────────────────────────────────────────────────
export type DotStatus = "online" | "offline" | "warn" | "unknown";
const DOT_COLOR: Record<DotStatus, string> = {
  online: "var(--green)",
  offline: "var(--red)",
  warn: "var(--amber)",
  unknown: "var(--txt3)",
};
export function StatusDot({ status, size = 8 }: { status: DotStatus; size?: number }) {
  const c = DOT_COLOR[status];
  return (
    <span
      style={{
        width: size,
        height: size,
        borderRadius: "50%",
        background: c,
        boxShadow: `0 0 0 3px color-mix(in srgb, ${c} 20%, transparent), 0 0 7px ${c}`,
        flexShrink: 0,
        display: "inline-block",
      }}
    />
  );
}

// ── Spinner ────────────────────────────────────────────────────
export function Spinner({ size = 18 }: { size?: number }) {
  return (
    <span
      style={{
        width: size,
        height: size,
        borderRadius: "50%",
        border: "2px solid var(--line2)",
        borderTopColor: "var(--accent)",
        display: "inline-block",
        animation: "spin .7s linear infinite",
      }}
    />
  );
}

// ── Tag ────────────────────────────────────────────────────────
export type TagTone = "accent" | "green" | "amber" | "red" | "purple" | "neutral";
const TONE_VAR: Record<TagTone, string> = {
  accent: "var(--accent)",
  green: "var(--green)",
  amber: "var(--amber)",
  red: "var(--red)",
  purple: "var(--purple)",
  neutral: "var(--txt2)",
};
export function Tag({
  tone = "neutral",
  children,
  mono,
}: {
  tone?: TagTone;
  children: ReactNode;
  mono?: boolean;
}) {
  const c = TONE_VAR[tone];
  return (
    <span
      style={{
        fontSize: 11,
        fontWeight: 700,
        letterSpacing: 0.3,
        color: c,
        background: `color-mix(in srgb, ${c} 13%, transparent)`,
        border: `1px solid color-mix(in srgb, ${c} 36%, transparent)`,
        borderRadius: 6,
        padding: "2px 7px",
        whiteSpace: "nowrap",
        fontFamily: mono ? `var(--mono, ${MONO})` : "inherit",
      }}
    >
      {children}
    </span>
  );
}

// ── Badges ─────────────────────────────────────────────────────
export function RoleBadge({ role }: { role: string }) {
  const tone: TagTone = role === "admin" ? "amber" : role === "editor" ? "accent" : "neutral";
  return <Tag tone={tone}>{role}</Tag>;
}
export function TierBadge({ tier }: { tier: string }) {
  return <Tag tone={tier === "org" ? "purple" : "neutral"}>{tier}</Tag>;
}
const STATE_TONE: Record<string, TagTone> = {
  active: "green",
  pending: "amber",
  redeemed: "accent",
  expired: "neutral",
  revoked: "red",
  suspended: "red",
  disabled: "red",
  done: "green",
  open: "accent",
  msg1: "amber",
  msg2: "amber",
  msg3: "amber",
  stale: "amber",
};
export function StateBadge({ state }: { state: string }) {
  return <Tag tone={STATE_TONE[state] ?? "neutral"}>{state}</Tag>;
}

// ── Avatar ─────────────────────────────────────────────────────
const GRADS = [
  "linear-gradient(140deg,#5b8cff,#b98cff)",
  "linear-gradient(140deg,#3ad29f,#5b8cff)",
  "linear-gradient(140deg,#ffb454,#ff6b80)",
  "linear-gradient(140deg,#b98cff,#ff8ad0)",
  "linear-gradient(140deg,#57c7ff,#3ad29f)",
  "linear-gradient(140deg,#ff6b80,#ffb454)",
  "linear-gradient(140deg,#7aa2ff,#57c7ff)",
  "linear-gradient(140deg,#3ad29f,#b8bb26)",
];
export function gradientFor(seed: number): string {
  return GRADS[((seed % GRADS.length) + GRADS.length) % GRADS.length];
}
export function initialsOf(name: string): string {
  return name
    .split(/\s+/)
    .filter(Boolean)
    .map((w) => w[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();
}
export function Avatar({
  label,
  seed = 0,
  size = 38,
}: {
  label: string;
  seed?: number;
  size?: number;
}) {
  return (
    <span
      style={{
        width: size,
        height: size,
        borderRadius: size * 0.29,
        background: gradientFor(seed),
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        color: "#fff",
        fontWeight: 700,
        fontSize: size * 0.37,
        flexShrink: 0,
      }}
    >
      {label}
    </span>
  );
}

// ── PubkeyChip ─────────────────────────────────────────────────
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
  const fmt = usePrefs((s) => s.pubkeyFormat);
  const { copied, copy } = useCopy(1100);
  const v = value ?? "";
  const shown =
    fmt === "full" || v.length <= head + tail + 1
      ? v
      : `${v.slice(0, head)}…${v.slice(-tail)}`;
  const onCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (!v) return;
    copy(v);
  };
  return (
    <span
      title={v || undefined}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        maxWidth: "100%",
        fontFamily: MONO,
        fontSize: 11.5,
        color: "var(--txt2)",
      }}
    >
      <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        {prefix}
        {shown || "—"}
      </span>
      {v ? (
        <button
          type="button"
          onClick={onCopy}
          title="Copy"
          style={{
            border: "none",
            background: "transparent",
            color: copied ? "var(--green)" : "var(--txt3)",
            cursor: "pointer",
            display: "flex",
            padding: 2,
            flexShrink: 0,
          }}
        >
          <Icon name={copied ? "check" : "copy"} size={13} />
        </button>
      ) : null}
    </span>
  );
}

// ── ZkBanner ───────────────────────────────────────────────────
export function ZkBanner({
  children,
  tone = "accent",
}: {
  children: ReactNode;
  tone?: "accent" | "amber";
}) {
  const c = tone === "amber" ? "var(--amber)" : "var(--accent)";
  const bg =
    tone === "amber"
      ? "color-mix(in srgb, var(--amber) 9%, transparent)"
      : "var(--accentSoft)";
  const line =
    tone === "amber"
      ? "color-mix(in srgb, var(--amber) 30%, transparent)"
      : "var(--accentLine)";
  return (
    <div
      style={{
        display: "flex",
        gap: 10,
        alignItems: "flex-start",
        background: bg,
        border: `1px solid ${line}`,
        borderRadius: 11,
        padding: "12px 15px",
        marginBottom: 16,
      }}
    >
      <Icon
        name={tone === "amber" ? "alert" : "shieldcheck"}
        size={15}
        color={c}
        style={{ marginTop: 1 }}
      />
      <div style={{ fontSize: 12.5, color: "var(--txt2)", lineHeight: 1.55 }}>{children}</div>
    </div>
  );
}

// ── KpiCard ────────────────────────────────────────────────────
export function KpiCard({
  label,
  value,
  delta,
  deltaColor = "var(--txt3)",
  icon,
  onClick,
}: {
  label: string;
  value: string;
  delta?: string;
  deltaColor?: string;
  icon: IconName;
  onClick?: () => void;
}) {
  return (
    <div
      onClick={onClick}
      style={{
        background: "var(--bg1)",
        border: "1px solid var(--line)",
        borderRadius: 14,
        padding: "15px 17px",
        cursor: onClick ? "pointer" : "default",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <span style={{ fontSize: 12, color: "var(--txt3)", fontWeight: 600 }}>{label}</span>
        <span
          style={{
            width: 30,
            height: 30,
            borderRadius: 9,
            background: "var(--accentSoft)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            color: "var(--accent)",
          }}
        >
          <Icon name={icon} size={16} />
        </span>
      </div>
      <div
        style={{
          fontFamily: MONO,
          fontSize: 28,
          fontWeight: 700,
          marginTop: 10,
          letterSpacing: -1,
        }}
      >
        {value}
      </div>
      {delta ? (
        <div style={{ fontSize: 11.5, color: deltaColor, marginTop: 2, fontWeight: 600 }}>
          {delta}
        </div>
      ) : null}
    </div>
  );
}

// ── Field + TextInput ──────────────────────────────────────────
export function Field({
  label,
  children,
  hint,
  tag,
}: {
  label: ReactNode;
  children: ReactNode;
  hint?: ReactNode;
  /** Tiny technical term shown right of the label (e.g. "keyset", "handle"). */
  tag?: string;
}) {
  return (
    <div style={{ marginBottom: 14 }}>
      <div
        style={{
          display: "flex",
          alignItems: "baseline",
          justifyContent: "space-between",
          gap: 8,
          marginBottom: 7,
        }}
      >
        <div
          style={{
            fontSize: 11,
            fontWeight: 700,
            letterSpacing: 0.4,
            textTransform: "uppercase",
            color: "var(--txt3)",
          }}
        >
          {label}
        </div>
        {tag ? (
          <span
            style={{
              fontSize: 10,
              fontFamily: MONO,
              color: "var(--txt3)",
              opacity: 0.65,
              whiteSpace: "nowrap",
            }}
          >
            {tag}
          </span>
        ) : null}
      </div>
      {children}
      {hint ? (
        <div style={{ fontSize: 11, color: "var(--txt3)", marginTop: 5, lineHeight: 1.5 }}>
          {hint}
        </div>
      ) : null}
    </div>
  );
}

export function TextInput({
  value,
  onChange,
  placeholder,
  type = "text",
  mono,
  onFile,
  accept,
}: {
  value?: string;
  onChange?: (v: string) => void;
  placeholder?: string;
  type?: "text" | "password" | "file";
  mono?: boolean;
  onFile?: (f: File) => void;
  accept?: string;
}) {
  return (
    <input
      type={type}
      value={type === "file" ? undefined : value}
      accept={accept}
      placeholder={placeholder}
      onChange={(e) => {
        if (type === "file") {
          const f = e.target.files?.[0];
          if (f && onFile) onFile(f);
        } else onChange?.(e.target.value);
      }}
      style={{
        width: "100%",
        height: 38,
        padding: "0 13px",
        borderRadius: 10,
        background: "var(--bg2)",
        border: "1px solid var(--line)",
        color: "var(--txt)",
        fontFamily: mono ? MONO : "inherit",
        fontSize: 13,
        outline: "none",
      }}
    />
  );
}

// ── EmptyState / ErrorCard ─────────────────────────────────────
export function EmptyState({
  icon = "box",
  title,
  hint,
  actionLabel,
  onAction,
}: {
  icon?: IconName;
  title: string;
  hint?: string;
  actionLabel?: string;
  onAction?: () => void;
}) {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        padding: "64px 20px",
        textAlign: "center",
      }}
    >
      <span
        style={{
          width: 60,
          height: 60,
          borderRadius: 17,
          background: "var(--bg1)",
          border: "1px solid var(--line)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          color: "var(--accent)",
          marginBottom: 15,
        }}
      >
        <Icon name={icon} size={24} />
      </span>
      <div style={{ fontSize: 16, fontWeight: 700, color: "var(--txt)" }}>{title}</div>
      {hint ? (
        <div style={{ fontSize: 13, color: "var(--txt3)", marginTop: 6, maxWidth: 380 }}>{hint}</div>
      ) : null}
      {actionLabel && onAction ? (
        <div style={{ marginTop: 16 }}>
          <Btn variant="primary" onClick={onAction}>
            {actionLabel}
          </Btn>
        </div>
      ) : null}
    </div>
  );
}

export function ErrorCard({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div
      style={{
        display: "flex",
        gap: 12,
        alignItems: "center",
        background: "color-mix(in srgb, var(--red) 8%, transparent)",
        border: "1px solid color-mix(in srgb, var(--red) 30%, transparent)",
        borderRadius: 12,
        padding: "16px 18px",
      }}
    >
      <Icon name="alert" size={18} color="var(--red)" />
      <div style={{ flex: 1, fontSize: 13, color: "var(--txt2)" }}>{message}</div>
      {onRetry ? (
        <Btn size="sm" icon="refresh" onClick={onRetry}>
          {/* label set by caller via children? keep simple */}
          Retry
        </Btn>
      ) : null}
    </div>
  );
}

// ── InlineError ────────────────────────────────────────────────
/** Compact red inline error box (alert icon + message) used inside modals. */
export function InlineError({ children }: { children: ReactNode }) {
  return (
    <div
      style={{
        display: "flex",
        gap: 9,
        alignItems: "center",
        background: "color-mix(in srgb, var(--red) 9%, transparent)",
        border: "1px solid color-mix(in srgb, var(--red) 30%, transparent)",
        borderRadius: 10,
        padding: "10px 12px",
        marginBottom: 14,
        fontSize: 12.5,
        color: "var(--txt2)",
      }}
    >
      <Icon name="alert" size={15} color="var(--red)" />
      {children}
    </div>
  );
}

// ── SecretRow ──────────────────────────────────────────────────
/** Bordered mono value-box with a soft copy button + copied flash. */
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
  const { copied, copy } = useCopy(1200);
  return (
    <div>
      <div style={{ fontSize: 11, fontWeight: 600, color: "var(--txt3)", marginBottom: 5 }}>
        {label}
      </div>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 10,
          padding: "11px 13px",
          borderRadius: 11,
          background: "var(--bg2)",
          border: "1px solid var(--accentLine)",
        }}
      >
        <span
          style={{
            flex: 1,
            fontFamily: MONO,
            fontSize: 12.5,
            color: "var(--accent)",
            wordBreak: "break-all",
          }}
        >
          {value || "—"}
        </span>
        <Btn
          size="sm"
          variant="soft"
          icon={copied ? "check" : "copy"}
          onClick={() => {
            copy(value);
            onCopy?.();
          }}
        >
          {copied ? t("common.copied") : t("common.copy")}
        </Btn>
      </div>
    </div>
  );
}

// ── Card ───────────────────────────────────────────────────────
export function Card({
  children,
  style,
  pad = true,
}: {
  children: ReactNode;
  style?: CSSProperties;
  pad?: boolean;
}) {
  return (
    <div
      style={{
        background: "var(--bg1)",
        border: "1px solid var(--line)",
        borderRadius: 14,
        padding: pad ? "17px 19px" : 0,
        ...style,
      }}
    >
      {children}
    </div>
  );
}
