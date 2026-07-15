import { useEffect, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { ApiError } from "../api/errors";
import { useUi } from "../store/ui";
import { Icon } from "./icons";
import { Btn } from "./primitives";
import { MONO } from "../theme/tokens";

// ── Modal (centered) ───────────────────────────────────────────
export function Modal({
  onClose,
  width = 420,
  dismissable = true,
  children,
}: {
  onClose: () => void;
  width?: number;
  /** When false, Escape and backdrop clicks are ignored — the only exit is an
   *  explicit in-dialog action. Used to gate one-time secrets (e.g. the genesis
   *  keyset must be downloaded before the modal can close). */
  dismissable?: boolean;
  children: ReactNode;
}) {
  useEffect(() => {
    if (!dismissable) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose, dismissable]);
  return (
    <div
      onClick={dismissable ? onClose : undefined}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,.45)",
        zIndex: 200,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 24,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width,
          maxWidth: "100%",
          background: "var(--bg1)",
          border: "1px solid var(--line2)",
          borderRadius: 16,
          boxShadow: "var(--shadow)",
          overflow: "hidden",
          animation: "popIn .22s cubic-bezier(.2,.7,.2,1)",
        }}
      >
        {children}
      </div>
    </div>
  );
}

// ── Drawer (right) ─────────────────────────────────────────────
export function Drawer({
  onClose,
  width = 380,
  children,
}: {
  onClose: () => void;
  width?: number;
  children: ReactNode;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <>
      <div
        onClick={onClose}
        style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,.34)", zIndex: 150 }}
      />
      <div
        style={{
          position: "fixed",
          top: 0,
          right: 0,
          bottom: 0,
          width,
          maxWidth: "88vw",
          background: "var(--bg1)",
          borderLeft: "1px solid var(--line2)",
          zIndex: 151,
          display: "flex",
          flexDirection: "column",
          boxShadow: "var(--shadow)",
          animation: "drawerIn .26s cubic-bezier(.2,.7,.2,1)",
        }}
      >
        {children}
      </div>
    </>
  );
}

// ── ConfirmDialog (driven by ui store) ─────────────────────────
export function ConfirmDialog() {
  const { t } = useTranslation();
  const confirm = useUi((s) => s.confirm);
  const clearConfirm = useUi((s) => s.clearConfirm);
  const toast = useUi((s) => s.toast);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);

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
    <Modal onClose={clearConfirm} width={412}>
      <div style={{ padding: 22 }}>
        <div style={{ display: "flex", gap: 13, alignItems: "center", marginBottom: 14 }}>
          <span
            style={{
              width: 38,
              height: 38,
              borderRadius: 11,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              color: confirm.danger ? "var(--red)" : "var(--accent)",
              background: confirm.danger
                ? "color-mix(in srgb, var(--red) 14%, transparent)"
                : "var(--accentSoft)",
              border: confirm.danger
                ? "1px solid color-mix(in srgb, var(--red) 36%, transparent)"
                : "1px solid var(--accentLine)",
            }}
          >
            <Icon name="alert" size={18} />
          </span>
          <div style={{ fontSize: 16, fontWeight: 800 }}>{confirm.title}</div>
        </div>
        <div style={{ fontSize: 13, color: "var(--txt2)", lineHeight: 1.55, marginBottom: 16 }}>
          {confirm.desc}
        </div>
        {needText ? (
          <input
            autoFocus
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={needText}
            style={{
              width: "100%",
              height: 38,
              padding: "0 13px",
              borderRadius: 10,
              background: "var(--bg2)",
              border: "1px solid var(--line)",
              color: "var(--txt)",
              fontFamily: MONO,
              fontSize: 13,
              outline: "none",
              marginBottom: 16,
            }}
          />
        ) : null}
        <div style={{ display: "flex", gap: 9 }}>
          <Btn full onClick={clearConfirm}>
            {t("common.cancel")}
          </Btn>
          <Btn
            full
            variant={confirm.danger ? "danger" : "primary"}
            disabled={!canConfirm}
            loading={busy}
            onClick={run}
            style={
              confirm.danger
                ? { background: "var(--red)", color: "#fff", border: "1px solid transparent" }
                : undefined
            }
          >
            {confirm.confirmLabel}
          </Btn>
        </div>
      </div>
    </Modal>
  );
}

// ── Toaster ────────────────────────────────────────────────────
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
  const color =
    kind === "error" ? "var(--red)" : kind === "success" ? "var(--green)" : "var(--accent)";
  return (
    <div
      role={kind === "error" ? "alert" : "status"}
      aria-live={kind === "error" ? "assertive" : "polite"}
      style={{
        display: "flex",
        alignItems: "center",
        gap: 10,
        padding: "11px 14px",
        background: "var(--bg2)",
        border: `1px solid color-mix(in srgb, ${color} 40%, var(--line2))`,
        borderRadius: 11,
        boxShadow: "var(--shadow)",
        minWidth: 240,
        maxWidth: 360,
        animation: "popIn .2s ease",
      }}
    >
      <Icon name={kind === "success" ? "check" : "alert"} size={15} color={color} />
      <span style={{ fontSize: 12.5, color: "var(--txt)", flex: 1 }}>
        {message}
        {secsLeft > 0 ? (
          <span style={{ color: "var(--txt3)" }}> · {t("common.retryIn", { n: secsLeft })}</span>
        ) : null}
      </span>
      <button
        aria-label={t("common.close")}
        onClick={() => dismiss(id)}
        style={{ border: "none", background: "transparent", color: "var(--txt3)", cursor: "pointer", display: "flex" }}
      >
        <Icon name="plus" size={14} style={{ transform: "rotate(45deg)" }} />
      </button>
    </div>
  );
}

export function Toaster() {
  const toasts = useUi((s) => s.toasts);
  return (
    <div
      style={{
        position: "fixed",
        bottom: 18,
        right: 18,
        zIndex: 300,
        display: "flex",
        flexDirection: "column",
        gap: 9,
      }}
    >
      {toasts.map((t) => (
        <ToastItem key={t.id} id={t.id} kind={t.kind} message={t.message} retryAfter={t.retryAfter} />
      ))}
    </div>
  );
}
