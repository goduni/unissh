import {
  useEffect,
  useId,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
  type ReactNode,
  type RefObject,
} from "react";
import { useTranslation } from "react-i18next";
import { ApiError } from "../api/errors";
import { useUi } from "../store/ui";
import { Icon } from "./icons";
import { Btn, IconBtn } from "./primitives";
import { MONO } from "../theme/tokens";

// What floats over the sheet: dialogs and sheets on --background, toasts on
// --popover; a --border hairline, --elev-popover, over the --overlay scrim.

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), summary, [tabindex]';

/** What Tab reaches inside `box`, in document order (no tabIndex=-1, nothing hidden or inert). */
function tabbables(box: HTMLElement): HTMLElement[] {
  return Array.from(box.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
    (el) => el.tabIndex >= 0 && !el.closest("[inert]") && el.getClientRects().length > 0,
  );
}

/**
 * Focus moves into the dialog when it opens (unless something inside already
 * took it, e.g. an autoFocus field) and returns to where it was when it closes.
 */
function useDialogFocus(ref: RefObject<HTMLElement | null>) {
  useEffect(() => {
    const box = ref.current;
    const before = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    if (box && !box.contains(document.activeElement)) {
      (tabbables(box)[0] ?? box).focus({ preventScroll: true });
    }
    return () => {
      if (before && before.isConnected) before.focus({ preventScroll: true });
    };
  }, [ref]);
}

/**
 * Tab and Shift+Tab go round inside the dialog, whatever holds the focus: a
 * control, an element focused by script outside the tab order (tabIndex=-1, a
 * heading, a banner), the dialog itself, or a popover portalled out of it.
 * The browser never moves the focus here; the next stop is chosen by hand.
 */
function trapTab(e: ReactKeyboardEvent<HTMLElement>) {
  if (e.key !== "Tab" || e.defaultPrevented) return;
  const box = e.currentTarget;
  const items = tabbables(box);
  e.preventDefault();
  if (items.length === 0) {
    box.focus();
    return;
  }
  const back = e.shiftKey;
  const active = document.activeElement;
  const at = active instanceof HTMLElement ? items.indexOf(active) : -1;
  let next: HTMLElement | undefined;
  if (at >= 0) {
    next = items[(at + (back ? -1 : 1) + items.length) % items.length];
  } else if (active && active !== box && box.contains(active)) {
    // Outside the tab order: step from its place in the document.
    if (back) {
      const before = items.filter((el) => el.compareDocumentPosition(active) & Node.DOCUMENT_POSITION_FOLLOWING);
      next = before[before.length - 1];
    } else {
      next = items.find((el) => active.compareDocumentPosition(el) & Node.DOCUMENT_POSITION_FOLLOWING);
    }
  }
  (next ?? (back ? items[items.length - 1] : items[0])).focus();
}

// ── Modal (centered) ───────────────────────────────────────────
/**
 * A dialog: the ground with a --border hairline, 10 px corners, --elev-popover,
 * never taller than the screen less 32 px (it scrolls inside), over the scrim.
 */
export function Modal({
  onClose,
  width = 420,
  dismissable = true,
  children,
  ariaLabel,
  labelledBy,
  describedBy,
  role = "dialog",
}: {
  onClose: () => void;
  width?: number;
  /** When false, Escape and backdrop clicks are ignored — the only exit is an
   *  explicit in-dialog action. Used to gate one-time secrets (e.g. the genesis
   *  keyset must be downloaded before the modal can close). */
  dismissable?: boolean;
  children: ReactNode;
  /** The dialog's name, when no title element names it (prefer `labelledBy`). */
  ariaLabel?: string;
  /** The id of the dialog's title. */
  labelledBy?: string;
  describedBy?: string;
  /** `alertdialog` for a confirmation of something that cannot be undone. */
  role?: "dialog" | "alertdialog";
}) {
  const box = useRef<HTMLDivElement>(null);
  // A press that starts inside the dialog and ends on the scrim is not a dismissal.
  const pressedScrim = useRef(false);
  useDialogFocus(box);
  useEffect(() => {
    if (!dismissable) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose, dismissable]);
  return (
    <div
      onMouseDown={(e) => {
        pressedScrim.current = e.target === e.currentTarget;
      }}
      onClick={(e) => {
        if (dismissable && pressedScrim.current && e.target === e.currentTarget) onClose();
      }}
      style={{
        position: "fixed",
        inset: 0,
        background: "var(--overlay)",
        zIndex: 200,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 16,
        animation: "fadeIn var(--duration-base) var(--ease-out-soft)",
      }}
    >
      <div
        ref={box}
        role={role}
        aria-modal="true"
        aria-label={ariaLabel}
        aria-labelledby={labelledBy}
        aria-describedby={describedBy}
        tabIndex={-1}
        onKeyDown={trapTab}
        onClick={(e) => e.stopPropagation()}
        style={{
          width,
          maxWidth: "100%",
          maxHeight: "calc(100dvh - 32px)",
          overflowY: "auto",
          background: "var(--background)",
          color: "var(--foreground)",
          border: "1px solid var(--border)",
          borderRadius: "var(--radius-lg)",
          boxShadow: "var(--elev-popover)",
          outline: "none",
          animation: "popIn var(--duration-base) var(--ease-out-soft)",
        }}
      >
        {children}
      </div>
    </div>
  );
}

// ── Drawer (right) ─────────────────────────────────────────────
/** A sheet from the right: the ground, a --border edge, --elev-popover, over the scrim. */
export function Drawer({
  onClose,
  width = 380,
  children,
  ariaLabel,
  labelledBy,
}: {
  onClose: () => void;
  width?: number;
  children: ReactNode;
  ariaLabel?: string;
  /** The id of the drawer's title. */
  labelledBy?: string;
}) {
  const box = useRef<HTMLDivElement>(null);
  useDialogFocus(box);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <>
      <div
        onClick={onClose}
        style={{
          position: "fixed",
          inset: 0,
          background: "var(--overlay)",
          zIndex: 150,
          animation: "fadeIn var(--duration-base) var(--ease-out-soft)",
        }}
      />
      <div
        ref={box}
        role="dialog"
        aria-modal="true"
        aria-label={ariaLabel}
        aria-labelledby={labelledBy}
        tabIndex={-1}
        onKeyDown={trapTab}
        style={{
          position: "fixed",
          top: 0,
          right: 0,
          bottom: 0,
          width,
          maxWidth: "88vw",
          background: "var(--background)",
          color: "var(--foreground)",
          borderLeft: "1px solid var(--border)",
          zIndex: 151,
          display: "flex",
          flexDirection: "column",
          boxShadow: "var(--elev-popover)",
          outline: "none",
          animation: "drawerIn var(--duration-slow) var(--ease-out-soft)",
        }}
      >
        {children}
      </div>
    </>
  );
}

// ── ConfirmDialog (driven by ui store) ─────────────────────────
/**
 * The head (title 18/600, the consequence in muted copy), then the foot over a
 * --rule: cancel as an outline, the confirming button solid red when the action
 * is dangerous (its label says what happens), else the primary.
 */
export function ConfirmDialog() {
  const { t } = useTranslation();
  const confirm = useUi((s) => s.confirm);
  const clearConfirm = useUi((s) => s.clearConfirm);
  const toast = useUi((s) => s.toast);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const titleId = useId();
  const descId = useId();

  useEffect(() => {
    setText("");
    setBusy(false);
  }, [confirm]);

  if (!confirm) return null;
  const needText = confirm.requireText;
  const canConfirm = !needText || text === needText;

  const run = async () => {
    if (!canConfirm) return;
    setBusy(true);
    try {
      await confirm.onConfirm();
      clearConfirm();
    } catch (e) {
      // Never swallow a failed dangerous action: a 409 (last admin, already-redeemed
      // grant, concurrent change) must be shown, not read as "nothing happened".
      // Keep the dialog open so the operator can retry or cancel.
      const err = e instanceof ApiError ? e : null;
      toast("error", e instanceof Error ? e.message : String(e), err?.retryAfter || undefined);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      onClose={clearConfirm}
      width={440}
      role={confirm.danger ? "alertdialog" : "dialog"}
      labelledBy={titleId}
      describedBy={descId}
    >
      <div style={{ padding: 24 }}>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          {confirm.danger ? <Icon name="alert" size={20} color="var(--destructive)" /> : null}
          <h2
            id={titleId}
            style={{ margin: 0, fontSize: 18, fontWeight: 600, lineHeight: "24px", letterSpacing: "-0.025em" }}
          >
            {confirm.title}
          </h2>
        </div>
        <p
          id={descId}
          style={{
            margin: "8px 0 0",
            fontSize: 14,
            lineHeight: "20px",
            maxWidth: "72ch",
            color: "var(--muted-foreground)",
          }}
        >
          {confirm.desc}
        </p>
        {needText ? (
          <label style={{ display: "grid", gap: 6, marginTop: 16, fontSize: 13, lineHeight: "18px" }}>
            {t("common.typeToConfirm", { text: needText })}
            <input
              autoFocus
              className="u-input"
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder={needText}
              autoComplete="off"
              spellCheck={false}
              style={{ fontFamily: MONO, fontSize: 12 }}
            />
          </label>
        ) : null}
      </div>
      <div
        style={{
          display: "flex",
          flexWrap: "wrap",
          justifyContent: "flex-end",
          gap: 8,
          padding: "16px 24px",
          borderTop: "1px solid var(--rule)",
        }}
      >
        <Btn variant="outline" onClick={clearConfirm}>
          {t("common.cancel")}
        </Btn>
        <Btn
          variant={confirm.danger ? "destructive" : "primary"}
          disabled={!canConfirm}
          loading={busy}
          onClick={run}
        >
          {confirm.confirmLabel}
        </Btn>
      </div>
    </Modal>
  );
}

// ── Toaster ────────────────────────────────────────────────────
const TOAST_LOOK = {
  error: { icon: "alert", color: "var(--destructive)" },
  success: { icon: "check", color: "var(--success)" },
  info: { icon: "info", color: "var(--muted-foreground)" },
} as const;

function ToastItem({
  id,
  kind,
  message,
  retryAfter,
}: {
  id: number;
  kind: string;
  message: string;
  retryAfter?: number;
}) {
  const { t } = useTranslation();
  const dismiss = useUi((s) => s.dismissToast);
  // Errors persist until dismissed so a failed action isn't a 4.5s flash the
  // operator can miss; info/success stay transient.
  useEffect(() => {
    if (kind === "error") return;
    const h = setTimeout(() => dismiss(id), 4500);
    return () => clearTimeout(h);
  }, [id, kind, dismiss]);
  // Live "retry in Ns" countdown — a static number that never ticks reads as stuck.
  const [secsLeft, setSecsLeft] = useState(retryAfter ?? 0);
  useEffect(() => {
    setSecsLeft(retryAfter ?? 0);
    if (!retryAfter) return;
    const iv = setInterval(() => setSecsLeft((n) => (n > 1 ? n - 1 : 0)), 1000);
    return () => clearInterval(iv);
  }, [retryAfter]);
  const look = kind === "error" ? TOAST_LOOK.error : kind === "success" ? TOAST_LOOK.success : TOAST_LOOK.info;
  return (
    <div
      role={kind === "error" ? "alert" : "status"}
      aria-live={kind === "error" ? "assertive" : "polite"}
      style={{
        display: "flex",
        alignItems: "flex-start",
        gap: 8,
        padding: "8px 8px 8px 12px",
        background: "var(--popover)",
        color: "var(--foreground)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius-md)",
        boxShadow: "var(--elev-popover)",
        minWidth: 240,
        maxWidth: "min(360px, calc(100vw - 32px))",
        animation: "popIn var(--duration-base) var(--ease-out-soft)",
      }}
    >
      <Icon name={look.icon} size={16} color={look.color} style={{ marginTop: 4 }} />
      <span style={{ flex: 1, minWidth: 0, fontSize: 13, lineHeight: "20px", padding: "2px 0", overflowWrap: "anywhere" }}>
        {message}
        {secsLeft > 0 ? (
          <span style={{ color: "var(--muted-foreground)" }}> · {t("common.retryIn", { n: secsLeft })}</span>
        ) : null}
      </span>
      <IconBtn icon="x" size={24} title={t("common.close")} onClick={() => dismiss(id)} />
    </div>
  );
}

export function Toaster() {
  const toasts = useUi((s) => s.toasts);
  return (
    <div
      style={{
        position: "fixed",
        bottom: 16,
        right: 16,
        zIndex: 300,
        display: "flex",
        flexDirection: "column",
        gap: 8,
      }}
    >
      {toasts.map((t) => (
        <ToastItem key={t.id} id={t.id} kind={t.kind} message={t.message} retryAfter={t.retryAfter} />
      ))}
    </div>
  );
}
