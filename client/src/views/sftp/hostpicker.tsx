// Saved-host dropdown for the tab strip's "+" — port of the old HostPicker menu.

import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { usePalette } from "@/theme/ThemeProvider";
import { MONO } from "@/theme/tokens";
import { Icon, NO_AUTOCORRECT } from "@/components/primitives";
import { useCtx } from "@/store/ctx";
import { useTranslation } from "@/i18n";
import type { ConnectionProfile } from "@/bridge/types";

export function HostMenu({
  hosts,
  onPick,
  onClose,
  align = "right",
}: {
  hosts: ConnectionProfile[];
  onPick: (h: ConnectionProfile) => void;
  onClose: () => void;
  /** Which edge of the "+" to anchor to. Right (default) for a flush-right "+"
   *  (SFTP); left when the "+" sits just after the tabs (terminal), so the menu
   *  opens rightward into free space instead of leftward over the tabs. */
  align?: "left" | "right";
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const ctx = useCtx();
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    };
    const onKey = (e: KeyboardEvent) => {
      // preventDefault so a dialog stack beneath this picker survives the Escape.
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
      }
    };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [onClose]);

  const [q, setQ] = useState("");
  const ql = q.trim().toLowerCase();
  const filtered = ql
    ? hosts.filter((h) => `${h.label} ${h.user}@${h.host}:${h.port}`.toLowerCase().includes(ql))
    : hosts;
  const showSearch = hosts.length > 6;

  // Nudge the menu back inside the viewport if the anchor edge would push it off
  // (e.g. a left-anchored terminal "+" sitting far right, or vice-versa).
  const [shiftX, setShiftX] = useState(0);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    let dx = 0;
    if (r.right > window.innerWidth - 8) dx = window.innerWidth - 8 - r.right;
    if (r.left + dx < 8) dx = 8 - r.left;
    setShiftX(dx);
  }, []);

  return (
    <div
      ref={ref}
      style={{
        position: "absolute",
        top: "calc(100% + 6px)",
        ...(align === "left" ? { left: 0 } : { right: 0 }),
        transform: shiftX ? `translateX(${shiftX}px)` : undefined,
        zIndex: 40,
        minWidth: 240,
        maxHeight: 340,
        overflow: "auto",
        background: p.bg1,
        border: `1px solid ${p.line2}`,
        borderRadius: 11,
        boxShadow: p.shadow,
        padding: 5,
      }}
    >
      {showSearch && (
        <input
          autoFocus
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder={t("sftp.searchHosts")}
          {...NO_AUTOCORRECT}
          style={{
            width: "100%",
            boxSizing: "border-box",
            marginBottom: 5,
            padding: "6px 9px",
            borderRadius: 8,
            border: `1px solid ${p.line2}`,
            background: p.bg2,
            color: p.txt,
            fontSize: 13,
            outline: "none",
          }}
        />
      )}
      {hosts.length === 0 && (
        <button
          onClick={() => {
            onClose();
            ctx.onNewHost();
          }}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 9,
            width: "100%",
            padding: "8px 9px",
            borderRadius: 8,
            border: "1px solid transparent",
            background: "transparent",
            color: p.accentText,
            cursor: "pointer",
            textAlign: "left",
            fontSize: 13,
          }}
          onMouseEnter={(e) => (e.currentTarget.style.background = p.bg2)}
          onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
        >
          <Icon name="plus" size={15} color={p.accentText} />
          {t("sftp.addHost")}
        </button>
      )}
      {ql && filtered.length === 0 && hosts.length > 0 && (
        <div style={{ padding: "8px 10px", fontSize: 12.5, color: p.txt3 }}>{t("sftp.noMatches", { q })}</div>
      )}
      {filtered.map((h) => (
        <button
          key={h.profileId}
          onClick={() => onPick(h)}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 9,
            width: "100%",
            padding: "7px 9px",
            borderRadius: 8,
            border: "1px solid transparent",
            background: "transparent",
            color: p.txt,
            cursor: "pointer",
            textAlign: "left",
          }}
          onMouseEnter={(e) => (e.currentTarget.style.background = p.bg2)}
          onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
        >
          <Icon name="server" size={15} color={p.txt3} />
          <span style={{ flex: 1, minWidth: 0 }}>
            <span style={{ display: "block", fontSize: 13, fontWeight: 600 }}>{h.label}</span>
            <span style={{ display: "block", fontFamily: MONO, fontSize: 11, color: p.txt3 }}>
              {h.user}@{h.host}:{h.port}
            </span>
          </span>
        </button>
      ))}
    </div>
  );
}
