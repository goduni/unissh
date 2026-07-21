// Toasts, confirm dialog, shortcuts cheat-sheet — port of ui-feedback.jsx.

import { useEffect, useRef, useState } from "react";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { usePalette } from "@/theme/ThemeProvider";
import { MONO, rgba } from "@/theme/tokens";
import { Btn, Icon, IconName } from "@/components/primitives";
import { useDialogFocus, useDialogKeys } from "@/components/a11y";
import { useApp, type ConfirmData } from "@/store/app";
import { useIsMobile } from "@/store/responsive";
import { useTranslation, tDyn } from "@/i18n";
import type { ToastDetail, ToastKind } from "@/store/toast";

interface ToastItem extends ToastDetail {
  id: number;
  count: number; // identical messages coalesced into one toast ("×N")
}

const TOAST_META: Record<ToastKind, { icon: IconName; color: (p: ReturnType<typeof usePalette>) => string }> = {
  ok: { icon: "check", color: (p) => p.green },
  err: { icon: "x", color: (p) => p.red },
  warn: { icon: "alert", color: (p) => p.amber },
  info: { icon: "bolt", color: (p) => p.accentText },
};

let toastSeq = 0;
const TOAST_AUTO_DISMISS_MS = 2600;
// Hard cap on visible toasts — a burst (or lingering err toasts) can't fill the
// screen; the oldest is evicted regardless of kind once this is exceeded.
const MAX_TOASTS = 5;

export function ToastHost() {
  const p = usePalette();
  const { t } = useTranslation();
  const isMobile = useIsMobile();
  const [items, setItems] = useState<ToastItem[]>([]);
  // Source of truth lives in a ref so a burst of synchronous toasts (e.g. an
  // SFTP batch delete failing per file) dedupes correctly before any re-render.
  const listRef = useRef<ToastItem[]>([]);
  const timersRef = useRef<Map<number, number>>(new Map());
  const [copiedId, setCopiedId] = useState<number | null>(null);

  const sync = () => setItems([...listRef.current]);
  const dismiss = (id: number) => {
    const tm = timersRef.current.get(id);
    if (tm != null) {
      clearTimeout(tm);
      timersRef.current.delete(id);
    }
    listRef.current = listRef.current.filter((x) => x.id !== id);
    sync();
  };
  const armTimer = (id: number) => {
    const old = timersRef.current.get(id);
    if (old != null) clearTimeout(old);
    timersRef.current.set(
      id,
      window.setTimeout(() => dismiss(id), TOAST_AUTO_DISMISS_MS),
    );
  };

  useEffect(() => {
    const on = (e: Event) => {
      const detail = (e as CustomEvent<ToastDetail>).detail;
      // Dedupe: an identical visible toast bumps its counter instead of stacking.
      const dup = listRef.current.find((x) => x.text === detail.text && x.kind === detail.kind);
      if (dup) {
        dup.count += 1;
        if (dup.kind !== "err") armTimer(dup.id);
      } else {
        const id = ++toastSeq;
        listRef.current.push({ ...detail, id, count: 1 });
        // Errors are real error surfaces: they stay until explicitly dismissed so
        // they can be read, selected and copied. ok/info/warn auto-dismiss.
        if (detail.kind !== "err") armTimer(id);
        // Cap the stack — evict the oldest (front), clearing its timer too.
        while (listRef.current.length > MAX_TOASTS) {
          const oldest = listRef.current[0];
          const tm = timersRef.current.get(oldest.id);
          if (tm != null) {
            clearTimeout(tm);
            timersRef.current.delete(oldest.id);
          }
          listRef.current.shift();
        }
      }
      sync();
    };
    window.addEventListener("unissh:toast", on);
    const timers = timersRef.current;
    return () => {
      window.removeEventListener("unissh:toast", on);
      for (const tm of timers.values()) clearTimeout(tm);
      timers.clear();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const actBtn = {
    width: 22,
    height: 22,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    borderRadius: 6,
    border: "none",
    background: "transparent",
    color: p.txt3,
    cursor: "pointer",
    flexShrink: 0,
  } as const;

  return (
    <div
      role="status"
      aria-live="polite"
      style={{
        position: "fixed",
        zIndex: 400,
        display: "flex",
        flexDirection: "column",
        gap: 8,
        pointerEvents: "none",
        // Desktop: bottom-right, off the shell prompt (persistent err toasts no
        // longer sit on the terminal line). Mobile: near-full-width bottom-center.
        ...(isMobile
          ? { bottom: 24, left: 12, right: 12, alignItems: "stretch" }
          : { bottom: 24, right: 24, maxWidth: 420, alignItems: "flex-end" }),
      }}
    >
      {items.map((x) => {
        const meta = TOAST_META[x.kind];
        const c = meta.color(p);
        const isErr = x.kind === "err";
        return (
          <div
            key={x.id}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              padding: isErr ? "10px 10px 10px 16px" : "10px 16px",
              borderRadius: 12,
              background: p.bg3,
              border: `1px solid ${isErr ? rgba(p.red, 0.5) : p.line2}`,
              boxShadow: p.shadow,
              color: p.txt,
              fontSize: 13,
              fontWeight: 600,
              maxWidth: "min(520px, calc(100vw - 32px))",
              animation: "uhToast .26s cubic-bezier(.2,.8,.3,1)",
              // Errors are interactive (dismiss/copy) and their text selectable;
              // transient toasts stay click-through like before.
              pointerEvents: isErr ? "auto" : "none",
              userSelect: isErr ? "text" : undefined,
            }}
          >
            <Icon name={meta.icon} size={16} color={c} stroke={2} style={{ flexShrink: 0 }} />
            <span style={{ whiteSpace: "pre-wrap", wordBreak: "break-word", minWidth: 0 }}>
              {x.text}
            </span>
            {x.count > 1 && (
              <span
                style={{
                  fontFamily: MONO,
                  fontSize: 12,
                  color: c,
                  background: rgba(c, 0.14),
                  border: `1px solid ${rgba(c, 0.35)}`,
                  borderRadius: 20,
                  padding: "1px 7px",
                  flexShrink: 0,
                }}
              >
                ×{x.count}
              </span>
            )}
            {isErr && (
              <>
                <button
                  title={t("feedback.toastCopy")}
                  aria-label={t("feedback.toastCopy")}
                  onClick={() => {
                    void writeText(x.text);
                    setCopiedId(x.id);
                    window.setTimeout(
                      () => setCopiedId((cur) => (cur === x.id ? null : cur)),
                      1200,
                    );
                  }}
                  style={actBtn}
                >
                  <Icon
                    name={copiedId === x.id ? "check" : "copy"}
                    size={13}
                    color={copiedId === x.id ? p.green : undefined}
                  />
                </button>
                <button
                  title={t("feedback.toastDismiss")}
                  aria-label={t("feedback.toastDismiss")}
                  onClick={() => dismiss(x.id)}
                  style={actBtn}
                >
                  <Icon name="x" size={13} />
                </button>
              </>
            )}
          </div>
        );
      })}
    </div>
  );
}

export function ConfirmDialog() {
  const data = useApp((s) => s.confirm);
  const setConfirm = useApp((s) => s.setConfirm);
  if (!data) return null;
  // The card is a separate component so its dialog hooks (Escape, focus trap +
  // restore) only run while a confirm is actually open.
  return <ConfirmCard data={data} close={() => setConfirm(null)} />;
}

function ConfirmCard({ data, close }: { data: ConfirmData; close: () => void }) {
  const p = usePalette();
  const { t } = useTranslation();
  const isMobile = useIsMobile();
  useDialogKeys(close);
  // Danger confirms open with focus on Cancel (safe default); plain ones on Confirm.
  const cancelRef = useRef<HTMLButtonElement>(null);
  const confirmRef = useRef<HTMLButtonElement>(null);
  useDialogFocus(data.danger ? cancelRef : confirmRef);
  const mobileBtnStyle = isMobile ? { minHeight: 44 } : undefined;
  return (
    <div
      onClick={close}
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 350,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "rgba(0,0,0,0.45)",
        ...(isMobile ? { padding: 16 } : null),
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="uh-view"
        role="alertdialog"
        aria-modal="true"
        aria-label={data.title}
        style={{
          width: 400,
          maxWidth: "90vw",
          background: p.bg1,
          border: `1px solid ${p.line2}`,
          borderRadius: 16,
          padding: 22,
          boxShadow: p.shadow,
          ...(isMobile ? { width: "100%" } : null),
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
          <span
            style={{
              width: 34,
              height: 34,
              borderRadius: 10,
              flexShrink: 0,
              background: data.danger ? `${p.red}22` : p.accentSoft,
              border: `1px solid ${data.danger ? `${p.red}55` : p.accentLine}`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              color: data.danger ? p.red : p.accentText,
            }}
          >
            <Icon name={(data.icon as IconName) || (data.danger ? "alert" : "shield")} size={18} />
          </span>
          <div style={{ fontSize: 16, fontWeight: 700 }}>{data.title}</div>
        </div>
        {data.body && (
          <p style={{ margin: "0 0 18px", fontSize: 13, color: p.txt2, lineHeight: 1.5 }}>
            {data.body}
          </p>
        )}
        <div
          style={{
            display: "flex",
            gap: 10,
            justifyContent: "flex-end",
            // wrap so a long RU confirmLabel (e.g. "Сбросить и начать заново") doesn't spill a narrow card
            flexWrap: "wrap",
            flexDirection: isMobile ? "column-reverse" : undefined,
          }}
        >
          <Btn variant="ghost" full={isMobile} style={mobileBtnStyle} btnRef={cancelRef} onClick={close}>
            {t("common.cancel")}
          </Btn>
          <Btn
            variant={data.danger ? "danger" : "primary"}
            full={isMobile}
            style={mobileBtnStyle}
            btnRef={confirmRef}
            onClick={() => {
              data.onConfirm();
              close();
            }}
          >
            {data.confirmLabel || t("common.confirm")}
          </Btn>
        </div>
      </div>
    </div>
  );
}

const SHORTCUTS: [string, string][] = [
  ["⌘K", "feedback.shortcut.commandPalette"],
  ["⌘N", "feedback.shortcut.newHost"],
  ["⌘T", "feedback.shortcut.goToTerminal"],
  ["⌘L", "feedback.shortcut.lockInstance"],
  ["⌘1–9", "feedback.shortcut.switchSections"],
  ["⌘ +/−/0", "feedback.shortcut.termZoom"],
  ["⌘/", "feedback.shortcut.thisHelp"],
];

export function ShortcutsHelp() {
  const p = usePalette();
  const { t } = useTranslation();
  const shortcuts = useApp((s) => s.shortcuts);
  const setShortcuts = useApp((s) => s.setShortcuts);
  if (!shortcuts) return null;
  return (
    <div
      onClick={() => setShortcuts(false)}
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 340,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "rgba(0,0,0,0.45)",
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="uh-view"
        style={{
          width: 420,
          background: p.bg1,
          border: `1px solid ${p.line2}`,
          borderRadius: 16,
          padding: 22,
          boxShadow: p.shadow,
        }}
      >
        <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 16 }}>{t("feedback.shortcutsTitle")}</div>
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {SHORTCUTS.map(([k, label]) => (
            <div key={k} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
              {/* minWidth:0 lets a long RU shortcut description wrap instead of shoving the keycap */}
              <span style={{ fontSize: 13, color: p.txt2, minWidth: 0 }}>{tDyn(label)}</span>
              <span
                style={{
                  fontFamily: MONO,
                  fontSize: 12,
                  padding: "3px 9px",
                  borderRadius: 6,
                  background: p.bg3,
                  border: `1px solid ${p.line2}`,
                  color: p.txt,
                  flexShrink: 0, // keycap must never shrink/wrap
                }}
              >
                {k}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
