// Desktop terminal tab strip: draggable reorder, overflow scroll, middle-click
// close, a right-click context menu (duplicate / rename / reconnect / close …),
// double-click to rename, and a "+" that opens saved hosts inline (no detour to
// the Hosts view). Mirrors the SFTP TabStrip's inline-host-picker pattern.

import { useEffect, useRef, useState } from "react";
import { usePalette } from "@/theme/ThemeProvider";
import { MONO } from "@/theme/tokens";
import { BTN_RESET, Icon, NO_AUTOCORRECT } from "@/components/primitives";
import { pressActivate } from "@/components/a11y";
import { ContextMenu, type MenuItem } from "@/components/ContextMenu";
import { HostMenu } from "@/views/sftp/hostpicker";
import { useTranslation, tDyn } from "@/i18n";
import type { ConnectionProfile } from "@/bridge/types";
import { useApp, type TerminalTab } from "@/store/app";

/** Aggregate a tab's pane statuses into one state: online if any pane is live,
 *  else error if any errored, else muted (connecting/closed). Colour AND shape
 *  of the dot plus the tab's title/aria-label all derive from this, so the
 *  connection state is never carried by colour alone. */
type TabState = "online" | "error" | "connecting" | "closed";
function tabState(tab: TerminalTab): TabState {
  const st = tab.panes.map((p) => p.status);
  if (st.includes("online")) return "online";
  if (st.includes("error")) return "error";
  if (st.includes("connecting")) return "connecting";
  return "closed";
}
const TAB_STATE_KEY: Record<TabState, string> = {
  online: "terminal.status.online",
  error: "terminal.status.error",
  connecting: "terminal.status.connecting",
  closed: "terminal.status.closed",
};

export function TermTabStrip({
  terminals,
  activeId,
  hosts,
  bg,
  onActivate,
  onClose,
  onCloseOthers,
  onCloseRight,
  onDuplicate,
  onRename,
  onReconnect,
  onReorder,
  onPickHost,
}: {
  terminals: TerminalTab[];
  activeId: string | null;
  hosts: ConnectionProfile[];
  bg: string;
  onActivate: (id: string) => void;
  onClose: (id: string) => void;
  onCloseOthers: (id: string) => void;
  onCloseRight: (id: string) => void;
  onDuplicate: (id: string) => void;
  onRename: (id: string, title: string) => void;
  onReconnect: (id: string) => void;
  onReorder: (id: string, toIndex: number) => void;
  onPickHost: (h: ConnectionProfile) => void;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const [adding, setAdding] = useState(false);
  const [menu, setMenu] = useState<{ x: number; y: number; id: string } | null>(null);
  const [renaming, setRenaming] = useState<string | null>(null);
  const [renameText, setRenameText] = useState("");
  const dragId = useRef<string | null>(null);
  const activeRef = useRef<HTMLDivElement>(null);
  const newTabNonce = useApp((s) => s.newTabNonce);
  const setDraggingTab = useApp((s) => s.setDraggingTab);

  // Keep the active tab in view when it changes (e.g. keyboard tab-jump).
  useEffect(() => {
    activeRef.current?.scrollIntoView({ inline: "nearest", block: "nearest" });
  }, [activeId]);

  // The keyboard "new tab" shortcut pokes this nonce → open the inline host picker.
  useEffect(() => {
    if (newTabNonce > 0) setAdding(true);
  }, [newTabNonce]);

  const commitRename = () => {
    if (renaming) onRename(renaming, renameText);
    setRenaming(null);
  };

  const menuItems = (id: string): MenuItem[] => {
    const idx = terminals.findIndex((x) => x.id === id);
    return [
      { icon: "copy", label: t("terminal.tab.duplicate"), onClick: () => onDuplicate(id) },
      {
        icon: "pencil",
        label: t("terminal.tab.rename"),
        onClick: () => {
          const tab = terminals.find((x) => x.id === id);
          setRenameText(tab?.title ?? "");
          setRenaming(id);
        },
      },
      { icon: "refresh", label: t("terminal.tab.reconnect"), onClick: () => onReconnect(id) },
      { icon: "x", label: t("terminal.tab.close"), danger: true, onClick: () => onClose(id) },
      {
        icon: "trash",
        label: t("terminal.tab.closeOthers"),
        danger: true,
        disabled: terminals.length <= 1,
        onClick: () => onCloseOthers(id),
      },
      {
        icon: "trash",
        label: t("terminal.tab.closeRight"),
        danger: true,
        disabled: idx < 0 || idx >= terminals.length - 1,
        onClick: () => onCloseRight(id),
      },
    ];
  };

  return (
    <div
      style={{
        display: "flex",
        alignItems: "stretch",
        background: bg,
        borderBottom: `1px solid ${p.line}`,
        flexShrink: 0,
        minHeight: 38,
      }}
    >
      {/* content-sized so the "+" sits right after the last tab (not shoved to the
          far edge); shrinks + scrolls only once the tabs overflow the strip. */}
      <div
        role="tablist"
        style={{ display: "flex", alignItems: "stretch", overflowX: "auto", flexShrink: 1, minWidth: 0 }}
      >
        {terminals.map((tab) => {
          const on = tab.id === activeId;
          const panes = tab.panes.length;
          const state = tabState(tab);
          const stateLabel = tDyn(TAB_STATE_KEY[state]);
          const dotColor = state === "online" ? p.green : state === "error" ? p.red : p.txt3;
          return (
            <div
              key={tab.id}
              ref={on ? activeRef : undefined}
              role="tab"
              aria-selected={on}
              tabIndex={0}
              title={`${tab.title} — ${stateLabel}`}
              aria-label={`${tab.title} — ${stateLabel}`}
              onKeyDown={pressActivate(() => onActivate(tab.id))}
              draggable={renaming !== tab.id}
              onDragStart={(e) => {
                dragId.current = tab.id;
                e.dataTransfer.effectAllowed = "move";
                e.dataTransfer.setData("text/plain", tab.id); // some engines need data to drop
                setDraggingTab(tab.id); // lets the terminal viewport accept a merge-drop
              }}
              onDragEnd={() => {
                dragId.current = null;
                setDraggingTab(null);
              }}
              onDragOver={(e) => {
                if (dragId.current && dragId.current !== tab.id) e.preventDefault();
              }}
              onDrop={(e) => {
                e.preventDefault();
                const from = dragId.current;
                dragId.current = null;
                if (!from || from === tab.id) return;
                // Drop before or after this tab depending on which half the pointer is on.
                const r = e.currentTarget.getBoundingClientRect();
                const after = e.clientX > r.left + r.width / 2;
                const targetIdx = terminals.findIndex((x) => x.id === tab.id);
                onReorder(from, after ? targetIdx + 1 : targetIdx);
              }}
              onClick={() => onActivate(tab.id)}
              onAuxClick={(e) => {
                if (e.button === 1) {
                  e.preventDefault();
                  onClose(tab.id);
                }
              }}
              onContextMenu={(e) => {
                e.preventDefault();
                setMenu({ x: e.clientX, y: e.clientY, id: tab.id });
              }}
              onDoubleClick={() => {
                setRenameText(tab.title);
                setRenaming(tab.id);
              }}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                padding: "0 12px",
                cursor: "pointer",
                flexShrink: 0,
                maxWidth: 220,
                borderRight: `1px solid ${p.line}`,
                background: on ? p.bg0 : "transparent",
                color: on ? p.txt : p.txt3,
                borderBottom: `2px solid ${on ? p.accent : "transparent"}`,
              }}
            >
              {/* solid dot = connected; hollow ring = not — shape backs up the colour */}
              <span
                style={{
                  width: 7,
                  height: 7,
                  flexShrink: 0,
                  borderRadius: "50%",
                  background: state === "online" ? dotColor : "transparent",
                  border: state === "online" ? "none" : `1.5px solid ${dotColor}`,
                  boxSizing: "border-box",
                }}
              />
              {renaming === tab.id ? (
                <input
                  autoFocus
                  value={renameText}
                  onChange={(e) => setRenameText(e.target.value)}
                  onClick={(e) => e.stopPropagation()}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") commitRename();
                    else if (e.key === "Escape") setRenaming(null);
                  }}
                  onBlur={commitRename}
                  {...NO_AUTOCORRECT}
                  style={{
                    width: 120,
                    background: p.bg2,
                    border: `1px solid ${p.line2}`,
                    borderRadius: 6,
                    color: p.txt,
                    fontFamily: MONO,
                    fontSize: 12.5,
                    padding: "2px 6px",
                    outline: "none",
                  }}
                />
              ) : (
                <span
                  style={{
                    fontFamily: MONO,
                    fontSize: 12.5,
                    whiteSpace: "nowrap",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                  }}
                >
                  {tab.title}
                </span>
              )}
              {panes > 1 && (
                <span
                  title={t("terminal.tab.paneCount", { n: panes })}
                  style={{
                    flexShrink: 0,
                    fontSize: 10,
                    fontWeight: 700,
                    lineHeight: 1,
                    padding: "2px 4px",
                    borderRadius: 5,
                    color: p.txt3,
                    background: p.bg2,
                  }}
                >
                  {panes}
                </span>
              )}
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  onClose(tab.id);
                }}
                title={t("terminal.tab.close")}
                aria-label={t("terminal.tab.close")}
                style={{ ...BTN_RESET, opacity: 0.6, display: "inline-flex", flexShrink: 0 }}
              >
                <Icon name="x" size={12} />
              </button>
            </div>
          );
        })}
      </div>

      {/* inline "+" host picker */}
      <div style={{ position: "relative", flexShrink: 0, display: "flex" }}>
        <button
          // Stop the mousedown reaching HostMenu's document outside-click handler,
          // otherwise clicking "+" while open would close-then-reopen (never close).
          onMouseDown={(e) => e.stopPropagation()}
          onClick={() => setAdding((v) => !v)}
          title={t("terminal.newSessionTitle")}
          aria-label={t("terminal.newSessionTitle")}
          aria-haspopup="menu"
          aria-expanded={adding}
          style={{
            width: 38,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            background: "transparent",
            border: "none",
            color: p.txt3,
            cursor: "pointer",
          }}
        >
          <Icon name="plus" size={15} />
        </button>
        {adding && (
          <HostMenu
            hosts={hosts}
            align="left"
            onClose={() => setAdding(false)}
            onPick={(h) => {
              setAdding(false);
              onPickHost(h);
            }}
          />
        )}
      </div>

      {menu && (
        <ContextMenu
          x={menu.x}
          y={menu.y}
          title={terminals.find((x) => x.id === menu.id)?.title}
          onClose={() => setMenu(null)}
          items={menuItems(menu.id)}
        />
      )}
    </div>
  );
}
