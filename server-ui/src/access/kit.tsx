import "./access.css";
import { useEffect, useId, useRef, useState, type KeyboardEvent, type ReactNode, type Ref } from "react";
import { useTranslation } from "react-i18next";
import { usePrefs } from "../store/prefs";
import type { Mode } from "../theme/tokens";
import { Icon } from "../ui/icons";
import { Btn, IconBtn, TextInput, Well } from "../ui/primitives";

// The few pieces of the way in (login, claim, invite) the shared kit does not carry:
// line tabs, the masked Secret Key field with its show toggle, a copy well whose write
// the caller owns, the amber caution, the dialog's head and foot, the theme button.

// ── Caution ──────────────────────────────────────────────────────────────────
/** A caution to read before going on: a solid amber box, the words at full strength. */
export function Caution({
  children,
  ref,
  focusable,
}: {
  children: ReactNode;
  ref?: Ref<HTMLDivElement>;
  /** Takes the focus when a dialog moves on to it (tabIndex −1). */
  focusable?: boolean;
}) {
  return (
    <div
      ref={ref}
      tabIndex={focusable ? -1 : undefined}
      className={focusable ? "acc-caution acc-focus-target" : "acc-caution"}
    >
      <Icon name="alert" size={16} style={{ marginTop: 2 }} />
      <div style={{ minWidth: 0 }}>{children}</div>
    </div>
  );
}

/** One line of caution in amber, with its icon (e.g. crypto-wasm not loaded). */
export function CautionLine({ children }: { children: ReactNode }) {
  return (
    <p className="acc-caution-line">
      <Icon name="alert" size={14} style={{ marginTop: 2 }} />
      <span>{children}</span>
    </p>
  );
}

// ── Line tabs: which panel shows ─────────────────────────────────────────────
export const tabId = (base: string, value: string) => `${base}-tab-${value}`;
export const panelId = (base: string, value: string) => `${base}-panel-${value}`;

/** A 36 px strip between two rules; the active tab at 600 over a 2 px blue line. */
export function LineTabs<T extends string>({
  tabs,
  value,
  onChange,
  idBase,
  ariaLabel,
}: {
  tabs: { value: T; label: string }[];
  value: T;
  onChange: (v: T) => void;
  idBase: string;
  ariaLabel: string;
}) {
  const list = useRef<HTMLDivElement>(null);
  const onKey = (e: KeyboardEvent<HTMLDivElement>) => {
    const i = tabs.findIndex((x) => x.value === value);
    const n = tabs.length;
    let next = -1;
    if (e.key === "ArrowRight") next = (i + 1) % n;
    else if (e.key === "ArrowLeft") next = (i - 1 + n) % n;
    else if (e.key === "Home") next = 0;
    else if (e.key === "End") next = n - 1;
    if (next < 0) return;
    e.preventDefault();
    onChange(tabs[next].value);
    list.current?.querySelectorAll<HTMLButtonElement>('[role="tab"]')[next]?.focus();
  };
  return (
    <div ref={list} role="tablist" aria-label={ariaLabel} className="acc-tabs" onKeyDown={onKey}>
      {tabs.map((tab) => {
        const on = tab.value === value;
        return (
          <button
            key={tab.value}
            type="button"
            role="tab"
            id={tabId(idBase, tab.value)}
            aria-selected={on}
            aria-controls={on ? panelId(idBase, tab.value) : undefined}
            tabIndex={on ? 0 : -1}
            className="acc-tab"
            onClick={() => onChange(tab.value)}
          >
            {tab.label}
          </button>
        );
      })}
    </div>
  );
}

// ── The Secret Key as typed: masked, with a show toggle ──────────────────────
/** A text field drawn as dots (never a password field, so no manager takes it for a
 *  password), mono, with a pressed/unpressed "show" button inside its right edge. */
export function SecretInput({
  id,
  value,
  onChange,
  placeholder,
  invalid,
}: {
  id: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  invalid?: boolean;
}) {
  const { t } = useTranslation();
  const [shown, setShown] = useState(false);
  return (
    <div style={{ position: "relative" }}>
      <TextInput
        id={id}
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        mono
        secret={!shown}
        invalid={invalid}
        autoComplete="off"
        style={{ paddingRight: 36 }}
      />
      <span style={{ position: "absolute", top: 2, right: 2 }}>
        <IconBtn
          icon="eye"
          active={shown}
          ariaLabel={t("access.onb.secret_show")}
          title={t("access.onb.secret_show")}
          onClick={() => setShown((s) => !s)}
        />
      </span>
    </div>
  );
}

// ── Copy well: a value a machine issued, to copy ─────────────────────────────
type CopyState = "idle" | "copied" | "failed";

async function writeClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

/**
 * The value in a well (mono, selectable) with an outline copy button: the green check
 * for a second and a half when the write lands, the red cross and the way out when
 * the browser refuses it. Unlike `SecretRow`, the caller may own the write (`onCopy`
 * resolves whether it landed), so nothing says "copied" that the clipboard did not take.
 */
export function CopyWell({
  label,
  tag,
  hint,
  value,
  onCopy,
  copyLabel,
}: {
  label: string;
  tag?: string;
  hint?: ReactNode;
  value: string;
  onCopy?: () => Promise<boolean>;
  /** The button's word at rest (default "Copy"). */
  copyLabel?: string;
}) {
  const { t } = useTranslation();
  const labelId = useId();
  const [state, setState] = useState<CopyState>("idle");

  useEffect(() => {
    if (state !== "copied") return;
    const h = setTimeout(() => setState("idle"), 1500);
    return () => clearTimeout(h);
  }, [state]);

  const copy = async () => {
    const ok = await (onCopy ? onCopy() : writeClipboard(value));
    setState(ok ? "copied" : "failed");
  };

  return (
    <div role="group" aria-labelledby={labelId} className="acc-stack">
      <div className="acc-field-head">
        <span id={labelId} className="acc-label">
          {label}
        </span>
        {tag ? <span className="acc-tag">{tag}</span> : null}
      </div>
      <Well style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 6px 6px 12px" }}>
        <span className="acc-well-value">{value || "—"}</span>
        <Btn
          size="sm"
          variant="outline"
          icon={state === "copied" ? "check" : state === "failed" ? "x" : "copy"}
          iconColor={
            state === "copied" ? "var(--success)" : state === "failed" ? "var(--destructive)" : undefined
          }
          onClick={() => void copy()}
        >
          {state === "copied" ? t("common.copied") : (copyLabel ?? t("common.copy"))}
        </Btn>
      </Well>
      <span role="status" className="u-sr-only">
        {state === "copied" ? t("common.copied") : ""}
      </span>
      {state === "failed" ? (
        <p role="alert" className="acc-error">
          {t("common.copyFailed")}
        </p>
      ) : null}
      {hint ? <p className="acc-hint">{hint}</p> : null}
    </div>
  );
}

// ── Dialog head and foot (inside the shared Modal) ───────────────────────────
/** The dialog's title at 18 / 600 and its muted description; ids feed Modal's labelledBy. */
export function DialogTitle({
  titleId,
  title,
  descId,
  description,
}: {
  titleId: string;
  title: ReactNode;
  descId: string;
  description: ReactNode;
}) {
  return (
    <div>
      <h2 id={titleId} className="acc-dlg-title">
        {title}
      </h2>
      <p id={descId} className="acc-dlg-desc">
        {description}
      </p>
    </div>
  );
}

/** The foot under a rule: an optional muted note (what the click needs) and the actions. */
export function DialogFoot({ note, children }: { note?: ReactNode; children: ReactNode }) {
  return (
    <div className="acc-dlg-foot">
      {note ? <p className="acc-dlg-foot-note">{note}</p> : null}
      <div className="acc-dlg-foot-actions">{children}</div>
    </div>
  );
}

// ── Theme: one icon button that goes round light, dark and "as the system" ───
const MODES: Mode[] = ["light", "dark", "auto"];

/** Where there is no menu (the login page). It shows and names the choice in effect. */
export function ThemeToggle() {
  const { t } = useTranslation();
  const mode = usePrefs((s) => s.mode);
  const setMode = usePrefs((s) => s.setMode);
  const name =
    mode === "auto" ? t("settings.system") : mode === "light" ? t("settings.light") : t("settings.dark");
  const label = `${t("settings.theme")}: ${name}`;
  const next = MODES[(MODES.indexOf(mode) + 1) % MODES.length];
  return (
    <IconBtn
      icon={mode === "auto" ? "monitor" : mode === "light" ? "sun" : "moon"}
      size={32}
      ariaLabel={label}
      title={label}
      onClick={() => setMode(next)}
    />
  );
}
