// PaneSlot — one visible slot: its location tabs, a small toolbar (filter /
// refresh / new folder / selection count), the breadcrumb, and the file list.
// Presentational: browse state comes from a SlotCtl and cross-slot actions
// (send / drop / context menu) are raised to ViewSftp.

import { useState } from "react";
import { usePalette } from "@/theme/ThemeProvider";
import { UI } from "@/theme/tokens";
import { Icon, IconBtn, NO_AUTOCORRECT, type IconName } from "@/components/primitives";
import { MetaChip } from "@/components/mono";
import { ContextMenu, type MenuItem } from "@/components/ContextMenu";
import { useIsMobile } from "@/store/responsive";
import { useTranslation } from "@/i18n";
import type { ConnectionProfile } from "@/bridge/types";
import type { Entry, SortKey } from "@/store/sftp-types";
import type { SlotCtl } from "./useSlot";
import { TabStrip, type TabInfo } from "./TabStrip";
import { Breadcrumb } from "./Breadcrumb";
import { FileList } from "./FileList";
import { dragCtx } from "./drag";

export function PaneSlot({
  slot,
  slotKey,
  tabs,
  activeTabId,
  hosts,
  actionIcon,
  onActivateTab,
  onCloseTab,
  onPickHost,
  onSend,
  onRowContext,
  onEmptyContext,
  onNewFolder,
  onImport,
  onDropHere,
  onTabDrop,
  dropTargetTab,
  onTabDragEnter,
  onTabDragLeave,
}: {
  slot: SlotCtl;
  slotKey: string;
  tabs: TabInfo[];
  activeTabId: string;
  hosts: ConnectionProfile[];
  actionIcon?: IconName;
  onActivateTab: (id: string) => void;
  onCloseTab: (id: string) => void;
  onPickHost: (h: ConnectionProfile) => void;
  onSend: (entries: Entry[]) => void;
  onRowContext: (entry: Entry, x: number, y: number) => void;
  onEmptyContext: (x: number, y: number) => void;
  onNewFolder: () => void;
  onImport?: () => void;
  onDropHere: (targetCwd: string) => void;
  onTabDrop: (tabId: string) => void;
  dropTargetTab: string | null;
  onTabDragEnter: (id: string) => void;
  onTabDragLeave: (id: string) => void;
}) {
  const p = usePalette();
  const { t } = useTranslation();
  const isMobile = useIsMobile();
  const [bodyDrop, setBodyDrop] = useState(false);
  const [sortMenu, setSortMenu] = useState(false);
  const [dropDir, setDropDir] = useState<string | null>(null);
  const src = slot.source;
  const crumbs = src ? src.crumbs(slot.cwd) : [];
  const selCount = slot.selection.size;

  // Sort menu (mobile has no column header to sort by).
  const colKey = (k: SortKey): "name" | "size" | "modified" | "perms" =>
    k === "mtime" ? "modified" : k === "mode" ? "perms" : k;
  const sortItems: MenuItem[] = (["name", "size", "mtime"] as SortKey[]).map((k) => {
    const base = t(`sftp.col.${colKey(k)}` as "sftp.col.name");
    return {
      label: slot.sort.key === k ? `${base}  ${slot.sort.dir === "asc" ? "↑" : "↓"}` : base,
      onClick: () => slot.toggleSort(k),
    };
  });

  const beginDrag = (entry: Entry, e: React.DragEvent) => {
    const inSel = slot.selection.has(entry.name) && selCount > 1;
    const entries = inSel ? slot.selectedEntries() : [entry];
    dragCtx.set({ slotKey, loc: slot.location, cwd: slot.cwd, entries });
    // WebKit webviews (macOS/Linux) only initiate a drag when the native data
    // store is non-empty; the rich payload lives in dragCtx, this just arms it.
    try {
      e.dataTransfer.setData("application/x-unissh-sftp", slotKey);
      e.dataTransfer.effectAllowed = "copy";
    } catch {
      /* non-fatal */
    }
    // Drop the payload when the drag ends without a handled drop, so a stale
    // payload can't be consumed by a later unrelated drop.
    window.addEventListener("dragend", () => dragCtx.clear(), { once: true });
  };

  const dropOnBody = (e: React.DragEvent) => {
    e.preventDefault();
    setBodyDrop(false);
    onDropHere(slot.cwd);
  };
  const dropOnDir = async (name: string, e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDropDir(null);
    setBodyDrop(false);
    if (src) onDropHere(await src.join(slot.cwd, name));
  };

  return (
    <div
      style={{
        flex: "1 1 0",
        minWidth: isMobile ? 0 : 240,
        ...(isMobile ? { minHeight: 0 } : {}),
        display: "flex",
        flexDirection: "column",
        background: p.bg1,
        border: `1px solid ${p.line}`,
        borderRadius: 13,
        overflow: "hidden",
      }}
    >
      <TabStrip
        tabs={tabs}
        activeId={activeTabId}
        hosts={hosts}
        onActivate={onActivateTab}
        onClose={onCloseTab}
        onPickHost={onPickHost}
        dropTargetId={dropTargetTab}
        onTabDragEnter={onTabDragEnter}
        onTabDragLeave={onTabDragLeave}
        onTabDrop={(id) => onTabDrop(id)}
      />

      {slot.location.kind === "none" ? (
        <div
          style={{
            flex: 1,
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            gap: 10,
            padding: 24,
            textAlign: "center",
            minHeight: isMobile ? "52vh" : 0,
          }}
        >
          <span
            style={{
              width: 48,
              height: 48,
              borderRadius: 14,
              background: p.bg2,
              border: `1px solid ${p.line}`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <Icon name="server" size={22} color={p.txt3} />
          </span>
          <div style={{ fontSize: 14, fontWeight: 700, color: p.txt }}>{t("sftp.selectHost")}</div>
          <div style={{ fontSize: 12.5, color: p.txt3, maxWidth: 220 }}>{t("sftp.addFirstHint")}</div>
        </div>
      ) : (
        <>
      {/* toolbar */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          padding: "7px 10px",
          borderBottom: `1px solid ${p.line}`,
        }}
      >
        {/* minWidth:0 so the search box can shrink instead of pushing the toolbar icons off the pane */}
        <div style={{ position: "relative", flex: 1, minWidth: 0, display: "flex", alignItems: "center" }}>
          <Icon name="search" size={13} color={p.txt3} />
          <input
            value={slot.filter}
            onChange={(e) => slot.setFilter(e.target.value)}
            placeholder={t("sftp.filter")}
            {...NO_AUTOCORRECT}
            style={{
              flex: 1,
              minWidth: 0, // let the input shrink below its intrinsic width in a narrow pane
              marginLeft: 6,
              border: "none",
              background: "transparent",
              color: p.txt,
              fontFamily: UI,
              fontSize: isMobile ? 16 : 12.5, // ≥16px avoids iOS zoom-on-focus
              outline: "none",
            }}
          />
        </div>
        {slot.location.kind === "remote" && (
          <MetaChip icon="shield" tone="good">
            {t("sftp.verified")}
          </MetaChip>
        )}
        {selCount > 0 && (
          <button
            onClick={slot.clearSelection}
            title={t("common.cancel")}
            aria-label={t("common.cancel")}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 5,
              background: "transparent",
              border: "none",
              padding: "2px 4px",
              cursor: "pointer",
              flexShrink: 0,
            }}
          >
            <MetaChip>{t("sftp.selected", { count: selCount })}</MetaChip>
            <Icon name="x" size={10} color={p.txt3} />
          </button>
        )}
        {isMobile && <IconBtn icon="list" size={40} title={t("sftp.sortBy")} onClick={() => setSortMenu(true)} />}
        {onImport && <IconBtn icon="enter" size={isMobile ? 40 : 26} title={t("sftp.menu.import")} onClick={onImport} />}
        <IconBtn icon="folders" size={isMobile ? 40 : 26} title={t("sftp.menu.newFolder")} onClick={onNewFolder} />
        <IconBtn
          icon="refresh"
          size={isMobile ? 40 : 26}
          title={t("common.refresh")}
          onClick={slot.refresh}
          color={slot.loading ? p.accent : undefined}
        />
      </div>

      <Breadcrumb crumbs={crumbs} onNavigate={slot.goTo} onGoToPath={slot.goTo} />

      <div
        onContextMenu={(e) => {
          e.preventDefault();
          onEmptyContext(e.clientX, e.clientY);
        }}
        onDragOver={(e) => {
          e.preventDefault();
          if (!bodyDrop) setBodyDrop(true);
        }}
        onDragLeave={(e) => {
          if (!e.currentTarget.contains(e.relatedTarget as Node)) setBodyDrop(false);
        }}
        onDrop={dropOnBody}
        style={{
          flex: 1,
          minHeight: isMobile ? "52vh" : 0,
          display: "flex",
          flexDirection: "column",
          boxShadow: bodyDrop && !dropDir ? `inset 0 0 0 2px ${p.accentLine}` : "none",
          transition: "box-shadow .12s",
        }}
      >
        <FileList
          entries={slot.entries}
          loading={slot.loading}
          error={slot.error}
          showUp
          selection={slot.selection}
          sort={slot.sort}
          filter={slot.filter}
          actionIcon={actionIcon}
          onSort={slot.toggleSort}
          onOpenUp={slot.up}
          onOpenDir={slot.navigate}
          onSelect={slot.select}
          onActivate={(e) => onSend([e])}
          onContext={(entry, x, y) => entry && onRowContext(entry, x, y)}
          onRetry={slot.refresh}
          onRowDragStart={(entry, e) => beginDrag(entry, e)}
          onDropOnDir={(name, e) => dropOnDir(name, e)}
          dropDir={dropDir}
          onDragEnterDir={(name) => setDropDir(name)}
          onDragLeaveDir={(name) => setDropDir((d) => (d === name ? null : d))}
        />
      </div>
        </>
      )}
      {sortMenu && (
        <ContextMenu title={t("sftp.sortBy")} items={sortItems} x={0} y={0} onClose={() => setSortMenu(false)} />
      )}
    </div>
  );
}
