// Saved-host list. Two presentations of the same rows: HostMenu, the dropdown
// the tab strip's "+" opens, and HostList on its own, which an empty pane slot
// renders inline — a pane with nothing in it should already be showing what can
// go in it, rather than making the hosts a hover away.

import { useEffect, useLayoutEffect, useRef, useState, type CSSProperties } from "react";
import { usePalette } from "@/theme/ThemeProvider";
import { MONO } from "@/theme/tokens";
import { Icon, NO_AUTOCORRECT } from "@/components/primitives";
import { useCtx } from "@/store/ctx";
import { useTranslation } from "@/i18n";
import { nextRow, pickerRows } from "./pickerRows";
import type { ConnectionProfile } from "@/bridge/types";

export function HostList({
  hosts,
  onPick,
  onPickLocal,
  onNavigateAway,
  autoFocusSearch = false,
}: {
  hosts: ConnectionProfile[];
  onPick: (h: ConnectionProfile) => void;
  /** Offer "shell on this machine" above the hosts. Optional because this list
   *  is also the SFTP picker, where a local shell would mean nothing — passing
   *  it is what makes it a terminal picker. */
  onPickLocal?: () => void;
  /** Called before leaving for the new-host form, so a dropdown can close
   *  itself first instead of hanging over the view it just opened. */
  onNavigateAway?: () => void;
  /** Only the dropdown grabs focus: an inline list is part of the page, and a
   *  search box that steals the caret on every SFTP open would be a trap. */
  autoFocusSearch?: boolean;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const ctx = useCtx();

  const [q, setQ] = useState("");
  // The rows and the keyboard have to be computed from the same list, or Enter
  // opens something other than what is highlighted. See pickerRows.ts.
  const rows = pickerRows(
    hosts,
    q,
    onPickLocal ? `${t("terminal.localShell")} ${t("terminal.localShellHint")}` : null,
  );
  const [sel, setSel] = useState(0);
  const rowRefs = useRef<(HTMLButtonElement | null)[]>([]);
  // The dropdown scrolls at 340px; a highlight the arrows walked off the bottom
  // of it is a highlight the user cannot see.
  useEffect(() => {
    rowRefs.current[sel]?.scrollIntoView({ block: "nearest" });
  }, [sel]);

  const activate = (row: (typeof rows)[number]) => {
    if (row.kind === "local") onPickLocal?.();
    else onPick(row.host);
  };
  const onSearchKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      setSel(nextRow(sel, e.key === "ArrowDown" ? 1 : -1, rows.length));
    } else if (e.key === "Enter" && rows[sel]) {
      e.preventDefault();
      activate(rows[sel]);
    }
  };

  const rowStyle = (active: boolean): CSSProperties => ({
    display: "flex",
    alignItems: "center",
    gap: 9,
    width: "100%",
    padding: "7px 9px",
    borderRadius: 8,
    border: "1px solid transparent",
    background: active ? p.bg2 : "transparent",
    color: p.txt,
    cursor: "pointer",
    textAlign: "left",
  });

  return (
    <>
      {/* Always shown, not only past some list length: a picker whose search
          appears at the seventh host reads as a search that is broken at the
          sixth. It costs one row, and it is where the keyboard enters. */}
      <input
        autoFocus={autoFocusSearch}
        value={q}
        onChange={(e) => {
          setQ(e.target.value);
          // Every keystroke rebuilds the list; the highlight goes back to its top
          // match rather than to whatever now sits at the old index.
          setSel(0);
        }}
        onKeyDown={onSearchKey}
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
      {hosts.length === 0 && (
        <button
          onClick={() => {
            onNavigateAway?.();
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
      {rows.length === 0 && hosts.length > 0 && (
        <div style={{ padding: "8px 10px", fontSize: 13, color: p.txt3 }}>{t("sftp.noMatches", { q })}</div>
      )}
      {rows.map((row, i) =>
        row.kind === "local" ? (
          <div key="local">
            <button
              ref={(el) => {
                rowRefs.current[i] = el;
              }}
              onClick={() => activate(row)}
              onMouseEnter={() => setSel(i)}
              style={rowStyle(i === sel)}
            >
              <Icon name="laptop" size={15} color={p.txt3} />
              <span style={{ flex: 1, minWidth: 0 }}>
                <span style={{ display: "block", fontSize: 13, fontWeight: 600 }}>
                  {t("terminal.localShell")}
                </span>
                <span style={{ display: "block", fontFamily: MONO, fontSize: 11, color: p.txt3 }}>
                  {t("terminal.localShellHint")}
                </span>
              </span>
            </button>
            {/* Separated, not just listed first: this one does not go over the
                network, and the list below is entirely about things that do. */}
            {rows.length > 1 && (
              <div style={{ height: 1, background: p.line2, margin: "5px 4px" }} />
            )}
          </div>
        ) : (
          <button
            key={row.host.profileId}
            ref={(el) => {
              rowRefs.current[i] = el;
            }}
            onClick={() => activate(row)}
            onMouseEnter={() => setSel(i)}
            style={rowStyle(i === sel)}
          >
            <Icon name="server" size={15} color={p.txt3} />
            <span style={{ flex: 1, minWidth: 0 }}>
              <span style={{ display: "block", fontSize: 13, fontWeight: 600 }}>
                {row.host.label}
              </span>
              <span style={{ display: "block", fontFamily: MONO, fontSize: 11, color: p.txt3 }}>
                {row.host.user}@{row.host.host}:{row.host.port}
              </span>
            </span>
          </button>
        ),
      )}
    </>
  );
}

export function HostMenu({
  hosts,
  onPick,
  onPickLocal,
  onClose,
  align = "right",
}: {
  hosts: ConnectionProfile[];
  onPick: (h: ConnectionProfile) => void;
  onPickLocal?: () => void;
  onClose: () => void;
  /** Which edge of the "+" to anchor to. Right (default) for a flush-right "+"
   *  (SFTP); left when the "+" sits just after the tabs (terminal), so the menu
   *  opens rightward into free space instead of leftward over the tabs. */
  align?: "left" | "right";
}) {
  const p = usePalette();
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
        borderRadius: 12,
        boxShadow: p.shadow,
        padding: 5,
      }}
    >
      <HostList
        hosts={hosts}
        onPick={onPick}
        onPickLocal={onPickLocal}
        onNavigateAway={onClose}
        autoFocusSearch
      />
    </div>
  );
}
