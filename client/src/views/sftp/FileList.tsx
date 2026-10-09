// FileList — the scrollable body of a pane: a sortable column header, the ".."
// row, and the filtered/sorted entries. Owns sort/selection-click interpretation
// and the empty/loading/error states; delegates the actual actions to the pane.

import { useEffect, useId, useMemo, useRef, useState } from "react";
import { usePalette, useTheme } from "@/theme/ThemeProvider";
import { designPx, rem, TEXT, UI } from "@/theme/tokens";
import { Icon, type IconName } from "@/components/primitives";
import { useIsMobile } from "@/store/responsive";
import { useTranslation } from "@/i18n";
import { useFmt } from "@/i18n/format";
import type { Entry, SortKey, SortState } from "@/store/sftp-types";
import { FileRow } from "./FileRow";
import type { FolderSizes } from "./folderSizes";
import { displayEntries } from "./sortfilter";
import { useVirtualRows } from "./useVirtualRows";
import { pageRows } from "./virtualRows";
import { runFileListShortcut, type CursorRequest, type ListCursor, type ListShortcutHandler } from "./shortcuts";

export function FileList({
  entries,
  loading,
  error,
  showUp,
  selection,
  folderSizes,
  sort,
  filter,
  cursorOn,
  onCursorDone,
  actionIcon,
  onSort,
  onOpenUp,
  onOpenDir,
  onSelect,
  onActivate,
  onContext,
  onShortcut,
  onRetry,
  onRowDragStart,
}: {
  entries: Entry[];
  loading: boolean;
  error: string | null;
  showUp: boolean;
  selection: Set<string>;
  folderSizes: FolderSizes;
  sort: SortState;
  filter: string;
  /** Put the cursor on this entry, and scroll to it, once it is listed. */
  cursorOn?: CursorRequest | null;
  /** The request was honoured; the owner drops it, so that it is used once. */
  onCursorDone?: () => void;
  actionIcon?: IconName;
  onSort: (key: SortKey) => void;
  onOpenUp: () => void;
  onOpenDir: (name: string) => void;
  onSelect: (name: string, additive: boolean, range: boolean) => void;
  onActivate: (entry: Entry) => void;
  onContext: (entry: Entry | null, x: number, y: number) => void;
  /** Runs an `sftp`-scope shortcut pressed in this list; absent while something
   *  else (a menu, a dialog, the editor) owns the keyboard. */
  onShortcut?: ListShortcutHandler;
  onRetry: () => void;
  onRowDragStart: (entry: Entry, e: React.DragEvent) => void;
}) {
  const p = usePalette();
  const isMobile = useIsMobile();
  const { t } = useTranslation();
  const { fmtSize } = useFmt();

  // A finished folder total is spoken once. The running figure never is: it
  // changes several times a second, and the row's own label carries it.
  const [sizeNews, setSizeNews] = useState("");
  const sizesBefore = useRef(folderSizes);
  useEffect(() => {
    const before = sizesBefore.current;
    sizesBefore.current = folderSizes;
    const news: string[] = [];
    let started = false;
    for (const [name, size] of folderSizes) {
      const wasPending = before.get(name)?.state === "pending";
      if (size.state === "pending") started ||= !wasPending;
      else if (!wasPending) continue;
      else if (size.state === "failed") news.push(t("sftp.size.announceFailed", { name }));
      else {
        const total = fmtSize(size.bytes);
        news.push(t("sftp.size.announceDone", { name, size: size.partial ? t("sftp.size.partial", { size: total }) : total }));
      }
    }
    // Emptied when a walk starts, so the same total can be spoken again later.
    if (news.length) setSizeNews(news.join(". "));
    else if (started) setSizeNews("");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [folderSizes]);

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
  }, [error]);

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
  // The cursor ring marks the list the keys go to, so only the focused one draws it.
  const [hasFocus, setHasFocus] = useState(false);
  // The error state unmounts the list, and a removed element fires no blur.
  useEffect(() => setHasFocus(false), [error]);
  const base = showUp ? 1 : 0;
  const navCount = base + display.length;
  const [dragged, setDragged] = useState<Entry | null>(null);
  useEffect(() => {
    const clear = () => setDragged(null);
    window.addEventListener("dragend", clear);
    window.addEventListener("drop", clear);
    return () => {
      window.removeEventListener("dragend", clear);
      window.removeEventListener("drop", clear);
    };
  }, []);
  const listId = useId();
  const rowHeight = (isMobile ? 44 : 30) * uiScale / 100;
  const rows = useVirtualRows(display.length, rowHeight, display, error);
  const focusRow = (index: number) => {
    const next = Math.max(0, Math.min(navCount - 1, index));
    setFocusIdx(next);
    rows.reveal(next - base);
  };
  // Where the cursor goes when what is listed changes: onto the entry a request
  // names, if it is listed, else back to the top. A request can also arrive for
  // the rows already shown, and moves the cursor without them changing. It is
  // handed back as soon as it is honoured, so sorting or filtering later does
  // not drag the cursor back — nor does mounting the list again.
  const listed = useRef<Entry[] | null>(null);
  useEffect(() => {
    const changed = listed.current !== display;
    listed.current = display;
    const index = cursorOn ? display.findIndex((e) => e.name === cursorOn.name) : -1;
    if (index >= 0) {
      focusRow(base + index);
      onCursorDone?.();
    } else if (changed) setFocusIdx(0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [display, cursorOn]);
  // Keep a drag source mounted if autoscrolling takes it outside the window.
  // Removing that DOM node ends a native HTML drag in some WebViews.
  const visibleIndices = Array.from({ length: rows.end - rows.start }, (_, i) => rows.start + i);
  const dragIndex = dragged ? display.indexOf(dragged) : -1;
  if (dragIndex >= 0 && (dragIndex < rows.start || dragIndex >= rows.end)) {
    visibleIndices.push(dragIndex);
    visibleIndices.sort((a, b) => a - b);
  }
  const activeVisible = (showUp && focusIdx === 0) ||
    (focusIdx - base >= rows.start && focusIdx - base < rows.end);

  const cursorEntry = () => (showUp && focusIdx === 0 ? null : (display[focusIdx - base] ?? null));
  const cursorAt = (list: HTMLElement): ListCursor => {
    const r = list.getBoundingClientRect();
    const view = list.clientHeight - (rows.headerRef.current?.offsetHeight ?? 0);
    return {
      entry: cursorEntry(),
      x: r.left + 80,
      y: Math.min(r.bottom - 40, r.top + 60),
      page: (dir) => focusRow(focusIdx + dir * pageRows(view, rowHeight)),
    };
  };

  const onKeyDown = (e: React.KeyboardEvent<HTMLElement>) => {
    // Rebindable actions go through the shortcut registry; the keys below are
    // the list's fixed navigation.
    if (onShortcut && runFileListShortcut(e, onShortcut, () => cursorAt(e.currentTarget))) return;
    if (e.target !== e.currentTarget) return;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      focusRow(focusIdx + 1);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      focusRow(focusIdx - 1);
    } else if (e.key === "Home") {
      e.preventDefault();
      focusRow(0);
    } else if (e.key === "End") {
      e.preventDefault();
      focusRow(navCount - 1);
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
      const ent = cursorEntry();
      if (ent) onSelect(ent.name, true, false);
    } else if (e.key === "ContextMenu" || (e.key === "F10" && e.shiftKey)) {
      // Keyboard access to the row actions (Send to…, open, rename, delete) — so a
      // keyboard-only operator can transfer folders / to a specific tab / a
      // multi-selection, not just Enter-send the focused file.
      e.preventDefault();
      const at = cursorAt(e.currentTarget);
      onContext(at.entry, at.x, at.y);
    }
  };

  const rowClick = (entry: Entry, e: React.MouseEvent) => {
    setFocusIdx(base + display.indexOf(entry));
    // A click lands on a row, not on the list; make sure the list — and so the
    // cursor ring and the keys — follows the mouse in every WebView.
    rows.scrollRef.current?.focus({ preventScroll: true });
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
      {/* Off-screen rather than display:none — a hidden node is not announced. */}
      <span
        role="status"
        style={{ position: "absolute", width: 1, height: 1, overflow: "hidden", clip: "rect(0 0 0 0)", clipPath: "inset(50%)", whiteSpace: "nowrap" }}
      >
        {sizeNews}
      </span>
      <div
        ref={rows.scrollRef}
        onScroll={rows.measure}
        tabIndex={0}
        role="listbox"
        data-sftp-list=""
        aria-label={t("nav.sftp")}
        aria-multiselectable
        aria-activedescendant={activeVisible ? `${listId}-${focusIdx}` : undefined}
        onKeyDown={onKeyDown}
        onFocus={(e) => {
          if (e.target === e.currentTarget) setHasFocus(true);
        }}
        onBlur={(e) => {
          if (e.target === e.currentTarget) setHasFocus(false);
        }}
        style={{ flex: 1, overflow: "auto", padding: rem(6), outline: "none" }}
      >
        {/* Header lives INSIDE the scroll body (sticky) so it shares the rows'
            content box + scrollbar inset and stays aligned. Left pad 33 == a
            row's icon(14)+gap(9)+pad(10); right pad 10 == a row's right pad. */}
        {!isMobile && (
          <div
            ref={rows.headerRef}
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
            id={`${listId}-0`}
            position={1}
            total={navCount}
            focused={hasFocus && focusIdx === 0}
            onClick={onOpenUp}
          />
        )}

        <div
          ref={rows.rowsRef}
          style={loading && entries.length === 0 ? undefined : { position: "relative", height: display.length * rowHeight }}
        >
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
            : visibleIndices.map((idx) => {
                const entry = display[idx];
                return (
                  <div key={entry.name} style={{ position: "absolute", top: idx * rowHeight, width: "100%" }}>
                    <FileRow
                      id={`${listId}-${base + idx}`}
                      position={base + idx + 1}
                      total={navCount}
                      entry={entry}
                      selected={selection.has(entry.name)}
                      folderSize={folderSizes.get(entry.name)}
                      focused={hasFocus && focusIdx === base + idx}
                      showModified={showModified}
                      showPerms={showPerms}
                      actionIcon={actionIcon}
                      onClick={(ev) => rowClick(entry, ev)}
                      onDoubleClick={() => (entry.isDir ? onOpenDir(entry.name) : onActivate(entry))}
                      onContextAt={(x, y) => onContext(entry, x, y)}
                      onActivate={() => onActivate(entry)}
                      onDragStart={(ev) => {
                        setDragged(entry);
                        onRowDragStart(entry, ev);
                      }}
                    />
                  </div>
                );
              })}
        </div>

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
