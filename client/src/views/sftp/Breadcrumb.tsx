// Breadcrumb path bar — clickable segments plus click-to-edit for typing/pasting
// a path. Replaces the old read-only mono path string.

import { useEffect, useRef, useState } from "react";
import { usePalette } from "@/theme/ThemeProvider";
import { MONO, rem, TEXT } from "@/theme/tokens";
import { Icon, NO_AUTOCORRECT } from "@/components/primitives";
import { useTranslation } from "@/i18n";
import type { Crumb } from "@/sftp/paths";

export function Breadcrumb({
  crumbs,
  onNavigate,
  onGoToPath,
  leading,
}: {
  crumbs: Crumb[];
  onNavigate: (path: string) => void;
  onGoToPath: (path: string) => void;
  /** Rendered before the path, outside the scrolling row (the local pane's
   *  volume picker) — a control that scrolls away with a long path would be
   *  worse than no control. */
  leading?: React.ReactNode;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const [editing, setEditing] = useState(false);
  const [text, setText] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);
  const fullPath = crumbs.length ? crumbs[crumbs.length - 1].path : "/";

  useEffect(() => {
    if (editing) inputRef.current?.focus();
  }, [editing]);

  const rowRef = useRef<HTMLDivElement>(null);
  // keep the current (deepest) folder visible on a long path
  useEffect(() => {
    const el = rowRef.current;
    if (el) el.scrollLeft = el.scrollWidth;
  }, [fullPath]);

  const startEdit = () => {
    setText(fullPath);
    setEditing(true);
  };

  if (editing) {
    return (
      <div style={{ padding: `${rem(6)} ${rem(12)}`, borderBottom: `1px solid ${p.line}` }}>
        <input
          ref={inputRef}
          value={text}
          onChange={(e) => setText(e.target.value)}
          onBlur={() => setEditing(false)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              setEditing(false);
              const v = text.trim();
              if (v) onGoToPath(v);
            } else if (e.key === "Escape") {
              setEditing(false);
            }
          }}
          placeholder={t("sftp.goToPath")}
          {...NO_AUTOCORRECT}
          style={{
            width: "100%",
            boxSizing: "border-box",
            padding: `${rem(5)} ${rem(9)}`,
            borderRadius: 8,
            border: `1px solid ${p.accentLine}`,
            background: p.bg2,
            color: p.txt,
            fontFamily: MONO,
            fontSize: TEXT.small,
            outline: "none",
          }}
        />
      </div>
    );
  }

  return (
    <div style={{ display: "flex", alignItems: "center", borderBottom: `1px solid ${p.line}` }}>
      {leading && <div style={{ display: "flex", alignItems: "center", paddingLeft: rem(8) }}>{leading}</div>}
      <div
        ref={rowRef}
        onClick={startEdit}
        title={t("sftp.goToPath")}
        style={{
          flex: 1,
          minWidth: 0,
          display: "flex",
          alignItems: "center",
          gap: rem(3),
          padding: `${rem(7)} ${rem(12)}`,
          fontFamily: MONO,
          fontSize: TEXT.small,
          color: p.txt2,
          whiteSpace: "nowrap",
          overflowX: "auto",
          cursor: "text",
        }}
      >
        <Icon name="folderOpen" size={13} color={p.txt2} />
      {crumbs.map((c, i) => {
        const last = i === crumbs.length - 1;
        return (
          <span key={c.path} style={{ display: "inline-flex", alignItems: "center", gap: rem(3) }}>
            {i > 0 && <span style={{ color: p.line2 }}>›</span>}
            <button
              onClick={(e) => {
                // Non-last segments navigate (and don't open the editor); a click
                // on the last/current segment falls through to the row → edit path.
                if (!last) {
                  e.stopPropagation();
                  onNavigate(c.path);
                }
              }}
              style={{
                background: "transparent",
                border: "none",
                padding: `${rem(1)} ${rem(3)}`,
                borderRadius: 6,
                cursor: last ? "default" : "pointer",
                fontFamily: MONO,
                fontSize: TEXT.small,
                color: last ? p.txt : p.txt2,
                fontWeight: last ? 700 : 400,
                whiteSpace: "nowrap",
              }}
              onMouseEnter={(e) => {
                if (!last) e.currentTarget.style.color = p.accent;
              }}
              onMouseLeave={(e) => {
                if (!last) e.currentTarget.style.color = p.txt2;
              }}
            >
              {c.label}
            </button>
          </span>
        );
      })}
      </div>
      <button
        onClick={startEdit}
        title={t("sftp.goToPath")}
        aria-label={t("sftp.goToPath")}
        style={{
          flexShrink: 0,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          width: rem(30),
          alignSelf: "stretch",
          background: "transparent",
          border: "none",
          borderLeft: `1px solid ${p.line}`,
          color: p.txt3,
          cursor: "pointer",
        }}
      >
        <Icon name="pencil" size={13} />
      </button>
    </div>
  );
}
