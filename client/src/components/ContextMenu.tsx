// ContextMenu — one API, two renderers: a positioned popover on desktop
// (right-click / ⋯) and a bottom action sheet on touch. Used by the SFTP file
// rows and tabs.

import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { usePalette } from "@/theme/ThemeProvider";
import { useIsMobile } from "@/store/responsive";
import { Icon, type IconName } from "@/components/primitives";
import { BottomSheet } from "@/components/Modal";

export interface MenuItem {
  icon?: IconName;
  label: string;
  danger?: boolean;
  disabled?: boolean;
  onClick: () => void;
}

export function ContextMenu({
  items,
  x,
  y,
  title,
  onClose,
}: {
  items: MenuItem[];
  x: number;
  y: number;
  title?: string;
  onClose: () => void;
}) {
  const p = usePalette();
  const isMobile = useIsMobile();
  const ref = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState({ left: x, top: y });

  // Clamp the desktop popover inside the viewport once measured.
  useLayoutEffect(() => {
    if (isMobile || !ref.current) return;
    const r = ref.current.getBoundingClientRect();
    const left = Math.min(x, window.innerWidth - r.width - 8);
    const top = Math.min(y, window.innerHeight - r.height - 8);
    setPos({ left: Math.max(8, left), top: Math.max(8, top) });
  }, [isMobile, x, y]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      // preventDefault so a dialog stack beneath this menu survives the Escape.
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  const run = (it: MenuItem) => {
    if (it.disabled) return;
    onClose();
    it.onClick();
  };

  const Row = ({ it }: { it: MenuItem }) => (
    <button
      onClick={() => run(it)}
      disabled={it.disabled}
      role="menuitem"
      style={{
        display: "flex",
        alignItems: "center",
        gap: 10,
        width: "100%",
        padding: isMobile ? "13px 12px" : "7px 10px",
        borderRadius: 8,
        border: "1px solid transparent",
        background: "transparent",
        color: it.disabled ? p.txt3 : it.danger ? p.red : p.txt,
        cursor: it.disabled ? "default" : "pointer",
        textAlign: "left",
        fontSize: isMobile ? 15 : 13,
        fontWeight: 500,
        opacity: it.disabled ? 0.5 : 1,
      }}
      onMouseEnter={(e) => {
        if (!it.disabled && !isMobile) e.currentTarget.style.background = p.bg2;
      }}
      onMouseLeave={(e) => {
        if (!isMobile) e.currentTarget.style.background = "transparent";
      }}
    >
      {it.icon && <Icon name={it.icon} size={isMobile ? 17 : 14} color={it.danger ? p.red : p.txt3} />}
      <span style={{ flex: 1 }}>{it.label}</span>
    </button>
  );

  if (isMobile) {
    return (
      <BottomSheet onClose={onClose}>
        {title && (
          <div style={{ fontSize: 13, fontWeight: 700, color: p.txt3, padding: "0 12px 8px" }}>{title}</div>
        )}
        <div role="menu" aria-label={title} style={{ display: "flex", flexDirection: "column", gap: 2 }}>
          {items.map((it, i) => (
            <Row key={i} it={it} />
          ))}
        </div>
      </BottomSheet>
    );
  }

  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 210 }}>
      <div
        onClick={onClose}
        onContextMenu={(e) => {
          e.preventDefault();
          onClose();
        }}
        style={{ position: "absolute", inset: 0 }}
      />
      <div
        ref={ref}
        role="menu"
        aria-label={title}
        style={{
          position: "fixed",
          left: pos.left,
          top: pos.top,
          minWidth: 190,
          background: p.bg1,
          border: `1px solid ${p.line2}`,
          borderRadius: 12,
          boxShadow: p.shadow,
          padding: 5,
        }}
      >
        {title && (
          <div style={{ fontSize: 11, fontWeight: 700, color: p.txt3, padding: "4px 10px 6px" }}>{title}</div>
        )}
        {items.map((it, i) => (
          <Row key={i} it={it} />
        ))}
      </div>
    </div>
  );
}
