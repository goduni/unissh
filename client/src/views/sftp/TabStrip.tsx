// Location tabs for a pane slot: Local + each open remote session, plus a "+"
// that opens a saved host. Tabs are drop targets (drop a dragged row onto a tab
// to transfer it there — the primary gesture on narrow/mobile layouts).

import { useEffect, useRef, useState } from "react";
import { usePalette } from "@/theme/ThemeProvider";
import { UI } from "@/theme/tokens";
import { Icon } from "@/components/primitives";
import { useIsMobile } from "@/store/responsive";
import { useTranslation } from "@/i18n";
import type { ConnectionProfile } from "@/bridge/types";
import { HostMenu } from "./hostpicker";

export interface TabInfo {
  id: string; // "local" or a session id
  label: string;
  kind: "local" | "remote";
}

export function TabStrip({
  tabs,
  activeId,
  hosts,
  onActivate,
  onClose,
  onPickHost,
  dropTargetId,
  onTabDragEnter,
  onTabDragLeave,
  onTabDrop,
}: {
  tabs: TabInfo[];
  activeId: string;
  hosts: ConnectionProfile[];
  onActivate: (id: string) => void;
  onClose: (id: string) => void;
  onPickHost: (h: ConnectionProfile) => void;
  dropTargetId: string | null;
  onTabDragEnter: (id: string) => void;
  onTabDragLeave: (id: string) => void;
  onTabDrop: (id: string, e: React.DragEvent) => void;
}) {
  const p = usePalette();
  const isMobile = useIsMobile();
  const { t } = useTranslation();
  const [adding, setAdding] = useState(false);
  const activeRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    activeRef.current?.scrollIntoView({ inline: "nearest", block: "nearest" });
  }, [activeId]);

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 6,
        padding: "8px 10px",
        borderBottom: `1px solid ${p.line}`,
        background: p.bg2,
      }}
    >
      <div role="tablist" style={{ display: "flex", alignItems: "center", gap: 6, overflowX: "auto", flex: 1, minWidth: 0 }}>
        {tabs.map((tab) => {
        const on = tab.id === activeId;
        const drop = tab.id === dropTargetId;
        return (
          <div
            key={tab.id}
            ref={on ? activeRef : undefined}
            role="tab"
            tabIndex={0}
            aria-selected={on}
            onClick={() => onActivate(tab.id)}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                onActivate(tab.id);
              }
            }}
            onDragEnter={() => onTabDragEnter(tab.id)}
            onDragOver={(e) => e.preventDefault()}
            onDragLeave={(e) => {
              if (e.currentTarget.contains(e.relatedTarget as Node)) return;
              onTabDragLeave(tab.id);
            }}
            onDrop={(e) => onTabDrop(tab.id, e)}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 6,
              flexShrink: 0,
              padding: "5px 9px",
              borderRadius: 8,
              cursor: "pointer",
              fontFamily: UI,
              fontSize: 12.5,
              fontWeight: on ? 700 : 500,
              minHeight: isMobile ? 38 : undefined,
              color: on ? p.txt : p.txt2,
              background: drop ? p.bg3 : "transparent",
              boxShadow: drop
                ? `inset 0 0 0 1.5px ${p.accentLine}`
                : on
                  ? `inset 0 -2px 0 ${p.accent}`
                  : "none",
              transition: "background .12s, box-shadow .12s",
            }}
          >
            <Icon name={tab.kind === "local" ? "drive" : "server"} size={13} color={on ? p.txt2 : p.txt3} />
            <span style={{ whiteSpace: "nowrap", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis" }}>
              {tab.label}
            </span>
            {tab.kind === "remote" && (
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  onClose(tab.id);
                }}
                title={t("sftp.closeTab")}
                aria-label={t("sftp.closeTab")}
                style={{
                  display: "flex",
                  alignItems: "center",
                  background: "transparent",
                  border: "none",
                  padding: 0,
                  marginLeft: 1,
                  cursor: "pointer",
                  color: p.txt3,
                }}
              >
                <Icon name="x" size={11} />
              </button>
            )}
          </div>
        );
      })}
      </div>

      <div style={{ position: "relative", flexShrink: 0 }}>
        <button
          // Stop the mousedown reaching HostMenu's document outside-click handler,
          // otherwise clicking "+" while open would close-then-reopen (never close).
          onMouseDown={(e) => e.stopPropagation()}
          onClick={() => setAdding((v) => !v)}
          title={t("sftp.addLocation")}
          aria-label={t("sftp.addLocation")}
          aria-haspopup="menu"
          aria-expanded={adding}
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            width: isMobile ? 38 : 26,
            height: isMobile ? 38 : 26,
            borderRadius: 8,
            border: `1px solid ${p.line}`,
            background: p.bg1,
            color: p.txt2,
            cursor: "pointer",
            flexShrink: 0,
          }}
        >
          <Icon name="plus" size={isMobile ? 18 : 14} />
        </button>
        {adding && (
          <HostMenu
            hosts={hosts}
            onClose={() => setAdding(false)}
            onPick={(h) => {
              setAdding(false);
              onPickHost(h);
            }}
          />
        )}
      </div>
    </div>
  );
}
