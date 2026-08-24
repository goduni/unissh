// FileList — the scrollable body of a pane: a sortable column header, the ".."
// row, and the filtered/sorted entries. Owns sort/selection-click interpretation
// and the empty/loading/error states; delegates the actual actions to the pane.

import { useEffect, useMemo, useRef, useState } from "react";
import { usePalette, useTheme } from "@/theme/ThemeProvider";
import { designPx, rem, TEXT, UI } from "@/theme/tokens";
import { Icon, type IconName } from "@/components/primitives";
import { useIsMobile } from "@/store/responsive";
import { useTranslation } from "@/i18n";
import type { Entry, SortKey, SortState } from "@/store/sftp-types";
import { FileRow } from "./FileRow";
import { displayEntries } from "./sortfilter";

export function FileList({
  entries,
  loading,
  error,
  showUp,
  selection,
  sort,
  filter,
  actionIcon,
  onSort,
  onOpenUp,
  onOpenDir,
  onSelect,
  onActivate,
  onContext,
  onRetry,
  onRowDragStart,
  onDropOnDir,
  dropDir,
  onDragEnterDir,
  onDragLeaveDir,
}: {
  entries: Entry[];
  loading: boolean;
  error: string | null;
  showUp: boolean;
  selection: Set<string>;
  sort: SortState;
  filter: string;
  actionIcon?: IconName;
  onSort: (key: SortKey) => void;
  onOpenUp: () => void;
  onOpenDir: (name: string) => void;
  onSelect: (name: string, additive: boolean, range: boolean) => void;
  onActivate: (entry: Entry) => void;
  onContext: (entry: Entry | null, x: number, y: number) => void;
  onRetry: () => void;
  onRowDragStart: (entry: Entry, e: React.DragEvent) => void;
  onDropOnDir: (dirName: string, e: React.DragEvent) => void;
  dropDir: string | null;
  onDragEnterDir: (name: string) => void;
  onDragLeaveDir: (name: string) => void;
}) {
  const p = usePalette();
  const isMobile = useIsMobile();
  const { t } = useTranslation();

  // Per-pane width: side-by-side panes get narrow independently of the window, so
  // drop the fixed metadata columns before they crowd the name / overflow the row —
  // modified (widest, RU dates) first, then perms. Keeps header + rows in sync since
  // both derive from showModified/showPerms.
  const { uiScale } = useTheme();
  const rootRef = useRef<HTMLDivElement>(null);
  const [paneW, setPaneW] = useState(0);
  useEffect(() => {
    const el = rootRef.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver((ents) => {
      for (const e of ents) setPaneW(e.contentRect.width);
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const hasMtime = useMemo(() => entries.some((e) => e.mtime != null), [entries]);
  const hasPerms = useMemo(() => entries.some((e) => e.mode != null), [entries]);
  // In DESIGN pixels: the columns being dropped are made of type, so the width at
  // which they crowd grows with it. Measured in CSS pixels the pane looks roomy at
  // 150 % while its own contents no longer fit.
  //
  // Derived from the scale rather than measured again, so this re-decides when
  // the type grows without the pane's CSS width changing — a full-width pane in
  // an unmoved window is exactly that case, and no ResizeObserver would fire.
  const paneDesign = paneW > 0 ? designPx(paneW, uiScale) : 0;
  const showModified = hasMtime && !isMobile && !(paneDesign > 0 && paneDesign < 400);
  const showPerms = hasPerms && !isMobile && !(paneDesign > 0 && paneDesign < 320);

  const display = useMemo(() => displayEntries(entries, filter, sort), [entries, filter, sort]);

  // Keyboard navigation: a focus cursor over [".." , ...display].
  const [focusIdx, setFocusIdx] = useState(0);
  const base = showUp ? 1 : 0;
  const navCount = base + display.length;
  useEffect(() => setFocusIdx(0), [entries]);

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setFocusIdx((i) => Math.min(navCount - 1, i + 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setFocusIdx((i) => Math.max(0, i - 1));
    } else if (e.key === "Home") {
      e.preventDefault();
      setFocusIdx(0);
    } else if (e.key === "End") {
      e.preventDefault();
      setFocusIdx(navCount - 1);
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (showUp && focusIdx === 0) return onOpenUp();
      const ent = display[focusIdx - base];
      if (ent) {
        if (ent.isDir) onOpenDir(ent.name);
        else onActivate(ent);
      }
    } else if (e.key === " ") {
      e.preventDefault();
      const ent = showUp && focusIdx === 0 ? null : display[focusIdx - base];
      if (ent) onSelect(ent.name, true, false);
    } else if (e.key === "ContextMenu" || (e.key === "F10" && e.shiftKey)) {
      // Keyboard access to the row actions (Send to…, open, rename, delete) — so a
      // keyboard-only operator can transfer folders / to a specific tab / a
      // multi-selection, not just Enter-send the focused file.
      e.preventDefault();
      const ent = showUp && focusIdx === 0 ? null : display[focusIdx - base];
      const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
      onContext(ent, r.left + 80, Math.min(r.bottom - 40, r.top + 60));
    }
  };

  const rowClick = (entry: Entry, e: React.MouseEvent) => {
    const additive = e.metaKey || e.ctrlKey;
    const range = e.shiftKey;
    if (entry.isDir && !additive && !range) {
      onOpenDir(entry.name);
      return;
    }
    onSelect(entry.name, additive, range);
  };

  const arrow = (key: SortKey) => (sort.key === key ? (sort.dir === "asc" ? " ↑" : " ↓") : "");
  const Col = ({ k, label, w, align }: { k: SortKey; label: string; w?: number; align?: "left" | "right" }) => (
    <button
      onClick={() => onSort(k)}
      style={{
        background: "transparent",
        border: "none",
        cursor: "pointer",
        padding: 0,
        fontFamily: UI,
        fontSize: TEXT.micro,
        fontWeight: 600,
        color: sort.key === k ? p.txt2 : p.txt3,
        // Design pixels — these have to stay equal to the matching column widths
        // in FileRow, which are `rem`. In CSS pixels the header would drift left
        // of its own column at every scale but 100 %.
        width: w ? rem(w) : undefined,
        textAlign: align ?? "left",
        flex: w ? undefined : 1,
      }}
    >
      {label}
      {arrow(k)}
    </button>
  );

  if (error) {
    return (
      <div
        style={{
          flex: 1,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          gap: rem(10),
          padding: rem(20),
          textAlign: "center",
        }}
      >
        <Icon name="alert" size={22} color={p.red} />
        <div style={{ fontSize: TEXT.base, color: p.txt2 }}>{t("sftp.loadFailed")}</div>
        {error && (
          <div style={{ fontSize: TEXT.small, color: p.txt3, maxWidth: rem(300), wordBreak: "break-word" }}>{error}</div>
        )}
        <button
          onClick={onRetry}
          style={{
            fontSize: TEXT.base,
            color: p.accentText,
            background: "transparent",
            border: `1px solid ${p.accentLine}`,
            borderRadius: 8,
            padding: `${rem(4)} ${rem(12)}`,
            cursor: "pointer",
          }}
        >
          {t("sftp.retry")}
        </button>
      </div>
    );
  }

  return (
    <div ref={rootRef} style={{ flex: 1, display: "flex", flexDirection: "column", minHeight: 0 }}>
      <div
        tabIndex={0}
        role="listbox"
        aria-label={t("nav.sftp")}
        onKeyDown={onKeyDown}
        style={{ flex: 1, overflow: "auto", padding: rem(6), outline: "none" }}
      >
        {/* Header lives INSIDE the scroll body (sticky) so it shares the rows'
            content box + scrollbar inset and stays aligned. Left pad 33 == a
            row's icon(14)+gap(9)+pad(10); right pad 10 == a row's right pad. */}
        {!isMobile && (
          <div
            style={{
              position: "sticky",
              top: 0,
              zIndex: 1,
              display: "flex",
              alignItems: "center",
              gap: rem(9),
              padding: `${rem(5)} ${rem(10)} ${rem(5)} ${rem(33)}`,
              background: p.bg1,
              borderBottom: `1px solid ${p.line}`,
            }}
          >
            <Col k="name" label={t("sftp.col.name")} />
            {showPerms && <Col k="mode" label={t("sftp.col.perms")} w={78} align="left" />}
            {showModified && <Col k="mtime" label={t("sftp.col.modified")} w={96} align="right" />}
            <Col k="size" label={t("sftp.col.size")} w={70} align="right" />
          </div>
        )}
        {showUp && (
          <FileRow
            entry={{ name: "..", isDir: true, size: 0 }}
            isUp
            focused={focusIdx === 0}
            onClick={onOpenUp}
          />
        )}

        {loading && entries.length === 0
          ? Array.from({ length: 6 }).map((_, i) => (
              <div
                key={i}
                style={{
                  height: isMobile ? rem(44) : rem(30),
                  margin: `0 ${rem(4)}`,
                  borderRadius: 8,
                  display: "flex",
                  alignItems: "center",
                  padding: `0 ${rem(10)}`,
                  gap: rem(9),
                }}
              >
                <div style={{ width: rem(14), height: rem(14), borderRadius: 6, background: p.bg2 }} />
                <div style={{ flex: 1, height: rem(9), borderRadius: 6, background: p.bg2, maxWidth: rem(120) + i * 18 }} />
              </div>
            ))
          : display.map((e, idx) => (
              <FileRow
                key={e.name}
                entry={e}
                selected={selection.has(e.name)}
                dropActive={dropDir === e.name}
                focused={focusIdx === base + idx}
                showModified={showModified}
                showPerms={showPerms}
                actionIcon={actionIcon}
                onClick={(ev) => rowClick(e, ev)}
                onDoubleClick={() => (e.isDir ? onOpenDir(e.name) : onActivate(e))}
                onContextAt={(x, y) => onContext(e, x, y)}
                onActivate={() => onActivate(e)}
                onDragStart={(ev) => onRowDragStart(e, ev)}
                onDragEnterDir={() => onDragEnterDir(e.name)}
                onDragLeaveDir={() => onDragLeaveDir(e.name)}
                onDropOnDir={(ev) => onDropOnDir(e.name, ev)}
              />
            ))}

        {!loading && display.length === 0 && (
          <div
            style={{
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              gap: rem(8),
              padding: `${rem(28)} ${rem(12)}`,
              textAlign: "center",
              color: p.txt3,
            }}
          >
            <Icon name={filter.trim() ? "search" : "folderOpen"} size={20} color={p.txt3} />
            <span style={{ fontSize: TEXT.base }}>
              {filter.trim() && entries.length > 0 ? t("sftp.noMatches", { q: filter.trim() }) : t("sftp.empty")}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
