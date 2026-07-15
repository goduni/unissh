// Reusable overlay shells for views that raise their own dialogs (the global
// Modals.tsx system is a single payload-less slot, so it doesn't fit contextual
// dialogs like SFTP rename/conflict). Modal mirrors MShell's look; BottomSheet
// mirrors the mobile MSheet. Both use position:fixed so they cover the viewport
// even when rendered from deep inside a route.

import { useRef, useState, type ReactNode } from "react";
import { usePalette } from "@/theme/ThemeProvider";
import { useIsMobile } from "@/store/responsive";
import { Icon, type IconName } from "@/components/primitives";
import { useDialogFocus, useDialogKeys } from "@/components/a11y";
import { rgba } from "@/theme/tokens";
import { useTranslation } from "@/i18n";

export function Modal({
  icon,
  iconColor,
  title,
  subtitle,
  onClose,
  footer,
  children,
  w = 460,
  zIndex = 200,
  position = "fixed",
}: {
  icon: IconName;
  iconColor?: string;
  title: string;
  subtitle?: ReactNode;
  onClose: () => void;
  footer?: ReactNode;
  children: ReactNode;
  w?: number;
  zIndex?: number;
  // MShell (overlays/Modals.tsx) rendered its shell as position:absolute at
  // zIndex 150; components' own dialogs use position:fixed at 200. Kept as props
  // so the consolidated call sites render byte-identically to their originals.
  position?: "fixed" | "absolute";
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const isMobile = useIsMobile();
  useDialogKeys(onClose);
  // Move focus into the dialog on open and restore it on close.
  const cardRef = useDialogFocus<HTMLDivElement>();

  return (
    <div
      style={{
        position,
        inset: 0,
        zIndex,
        display: "flex",
        alignItems: isMobile ? "flex-start" : "center",
        justifyContent: "center",
        ...(isMobile
          ? { padding: "calc(env(safe-area-inset-top) + 16px) 12px 16px", boxSizing: "border-box" }
          : null),
      }}
    >
      <div
        onClick={onClose}
        style={{ position: "absolute", inset: 0, background: "rgba(6,7,11,0.55)", backdropFilter: "blur(3px)" }}
      />
      <div
        ref={cardRef}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
        style={{
          position: "relative",
          width: isMobile ? "100%" : `min(${w}px, calc(100% - 24px))`,
          maxHeight: isMobile ? "calc(100dvh - 80px)" : "90%",
          overflow: "auto",
          background: p.bg1,
          border: `1px solid ${p.line2}`,
          borderRadius: 18,
          boxShadow: p.shadow,
          outline: "none",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 11,
            padding: "18px 22px",
            borderBottom: `1px solid ${p.line}`,
          }}
        >
          <span
            style={{
              width: 36,
              height: 36,
              borderRadius: 10,
              background: rgba(iconColor || p.accent, 0.13),
              border: `1px solid ${rgba(iconColor || p.accent, 0.4)}`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <Icon name={icon} size={18} color={iconColor || p.accent} />
          </span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 17, fontWeight: 800, letterSpacing: -0.3 }}>{title}</div>
            {subtitle != null && <div style={{ fontSize: 12, color: p.txt3 }}>{subtitle}</div>}
          </div>
          <button
            onClick={onClose}
            title={t("common.close")}
            aria-label={t("common.close")}
            style={{
              width: 30,
              height: 30,
              borderRadius: 8,
              border: `1px solid ${p.line}`,
              background: p.bg2,
              color: p.txt3,
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <Icon name="x" size={15} />
          </button>
        </div>
        <div style={{ padding: isMobile ? 16 : 22, display: "flex", flexDirection: "column", gap: 16 }}>
          {children}
        </div>
        {footer != null && (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              padding: isMobile ? "14px 16px" : "14px 22px",
              borderTop: `1px solid ${p.line}`,
              background: p.bg0,
              // Always wrap: a narrow (or RU-labelled) footer drops trailing buttons
              // to a second row instead of pushing the primary action off-card behind
              // a horizontal scrollbar. No-op when the row already fits.
              flexWrap: "wrap",
            }}
          >
            {footer}
          </div>
        )}
      </div>
    </div>
  );
}

/** Bottom sheet with drag-to-dismiss — a viewport-fixed port of the mobile
 *  MSheet, usable from any view (e.g. the SFTP action sheet / queue). */
export function BottomSheet({
  children,
  onClose,
  zIndex = 200,
  position = "fixed",
}: {
  children: ReactNode;
  onClose: () => void;
  zIndex?: number;
  // The mobile MSheet used position:absolute at zIndex 40; the SFTP sheet uses
  // fixed at 200. Kept as a prop so both call sites render identically.
  position?: "fixed" | "absolute";
}) {
  const p = usePalette();
  const [dy, setDy] = useState(0);
  const startRef = useRef<number | null>(null);
  const onStart = (e: React.TouchEvent) => {
    startRef.current = e.touches[0].clientY;
  };
  const onMove = (e: React.TouchEvent) => {
    if (startRef.current != null) setDy(Math.max(0, e.touches[0].clientY - startRef.current));
  };
  const onEnd = () => {
    if (dy > 90) onClose();
    startRef.current = null;
    setDy(0);
  };
  const dragging = startRef.current != null;
  return (
    <div
      style={{
        position,
        inset: 0,
        zIndex,
        display: "flex",
        flexDirection: "column",
        justifyContent: "flex-end",
      }}
    >
      <div
        onClick={onClose}
        style={{
          position: "absolute",
          inset: 0,
          background: "rgba(0,0,0,0.4)",
          opacity: dy ? Math.max(0.2, 1 - dy / 400) : 1,
        }}
      />
      <div
        style={{
          position: "relative",
          background: p.bg1,
          borderTopLeftRadius: 22,
          borderTopRightRadius: 22,
          border: `1px solid ${p.line2}`,
          borderBottom: "none",
          padding: "10px 16px calc(30px + env(safe-area-inset-bottom))",
          transform: dy ? `translateY(${dy}px)` : "none",
          transition: dragging ? "none" : "transform .2s",
        }}
      >
        <div
          onTouchStart={onStart}
          onTouchMove={onMove}
          onTouchEnd={onEnd}
          style={{ touchAction: "none", margin: "-10px -16px 0", padding: "14px 16px 8px", cursor: "grab" }}
        >
          <div style={{ width: 38, height: 4, borderRadius: 2, background: p.line2, margin: "0 auto 12px" }} />
        </div>
        {children}
      </div>
    </div>
  );
}
