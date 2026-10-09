// SearchDialog — find files and folders by name below a pane's folder. A thin
// view over the pane's search (useFileSearch): it owns the query box, the cursor
// in the result list and nothing else. The keyboard stays in the query box the
// whole time, combobox-style — typing searches, the arrows walk the results.

import { useEffect, useId, useRef, useState } from "react";
import { usePalette, useTheme } from "@/theme/ThemeProvider";
import { MONO, rem, TEXT, UI } from "@/theme/tokens";
import { Btn, Icon, Spinner, type IconName } from "@/components/primitives";
import { Modal } from "@/components/Modal";
import { useIsMobile } from "@/store/responsive";
import { useTranslation } from "@/i18n";
import { SEARCH_MAX_MATCHES, SEARCH_MAX_SCANNED, type SearchHit } from "@/sftp/tree-search";
import { TextInput } from "./dialogs";
import type { SearchSnapshot } from "./fileSearch";
import type { FileSearchCtl } from "./useFileSearch";
import { useVirtualRows } from "./useVirtualRows";
import { pageRows } from "./virtualRows";

/** How long the query has to rest before a search starts. */
const SEARCH_DEBOUNCE_MS = 300;

const iconOf = ({ entry }: SearchHit): IconName => (entry.isSymlink ? "link" : entry.isDir ? "folder" : "file");
/** The folder a result is in, relative to the search root; "" for the root itself. */
const folderOf = ({ rel, entry }: SearchHit): string => rel.slice(0, Math.max(0, rel.length - entry.name.length - 1));

export function SearchDialog({
  root,
  search,
  gone,
  onGoTo,
  onClose,
}: {
  /** The folder searched: the pane's, as it was when the dialog opened. */
  root: string;
  search: FileSearchCtl;
  /** The pane no longer shows `root`; there is nothing left to search or go to. */
  gone: boolean;
  onGoTo: (hit: SearchHit) => void;
  onClose: () => void;
}) {
  const p = usePalette();
  const { t, i18n } = useTranslation();
  const isMobile = useIsMobile();
  const { uiScale } = useTheme();
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const { result } = search;
  const { hits, state } = result;

  // The controller is rebuilt whenever any session opens or closes; a search
  // must not start over because of that, so effects reach it through a ref.
  const live = useRef(search);
  live.current = search;
  const close = useRef(onClose);
  close.current = onClose;

  useEffect(() => {
    if (gone) close.current();
  }, [gone]);
  // However the dialog goes away, the search goes with it.
  useEffect(() => () => live.current.reset(), []);
  useEffect(() => {
    if (!query.trim()) {
      live.current.reset();
      return;
    }
    const timer = setTimeout(() => live.current.start(root, query), SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [query, root]);

  const listId = useId();
  const rowHeight = ((isMobile ? 44 : 30) * uiScale) / 100;
  const rows = useVirtualRows(hits.length, rowHeight, result.run, null);
  useEffect(() => setActive(0), [result.run]);
  const current = hits[active];
  const moveTo = (index: number) => {
    const next = Math.max(0, Math.min(hits.length - 1, index));
    setActive(next);
    rows.reveal(next);
  };
  const page = () => pageRows(rows.scrollRef.current?.clientHeight ?? 0, rowHeight);

  const onKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.nativeEvent.isComposing) return;
    const step = e.key === "ArrowDown" ? 1 : e.key === "ArrowUp" ? -1 : e.key === "PageDown" ? page() : e.key === "PageUp" ? -page() : 0;
    if (step) {
      e.preventDefault();
      moveTo(active + step);
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (current) onGoTo(current);
    }
  };

  const num = (n: number) => new Intl.NumberFormat(i18n.language).format(n);
  const stateText = (s: SearchSnapshot): string => {
    switch (s.state) {
      case "idle": return "";
      case "searching": return t("sftp.search.state.searching");
      case "done": return t("sftp.search.state.done");
      case "cancelled": return t("sftp.search.state.cancelled");
      case "lost": return t("sftp.search.state.lost");
      case "failed": return t("sftp.search.state.failed", { reason: s.error ?? "" });
      case "limit":
        return s.limit === "matches"
          ? t("sftp.search.state.limitMatches", { n: num(SEARCH_MAX_MATCHES) })
          : t("sftp.search.state.limitScanned", { n: num(SEARCH_MAX_SCANNED) });
    }
  };
  const status = [
    stateText(result),
    t("sftp.search.scanned", { n: num(result.dirs) }),
    t("sftp.search.matches", { n: num(hits.length) }),
    ...(result.skipped ? [t("sftp.search.skipped", { count: result.skipped })] : []),
  ].join(" · ");
  const idle = state === "idle";
  const broken = state === "lost" || state === "failed";
  // Spoken when the state changes, never per batch: while a search runs this
  // text stands still, and the final line is composed once.
  const news = idle ? "" : state === "searching" ? stateText(result) : status;

  return (
    <Modal
      icon="search"
      title={t("sftp.search.title")}
      subtitle={
        <span title={root} style={{ display: "block", fontFamily: MONO, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
          {root}
        </span>
      }
      w={560}
      onClose={onClose}
      footer={
        <>
          {!isMobile && <span style={{ fontSize: TEXT.small, color: p.txt3 }}>{t("sftp.search.keys")}</span>}
          <div style={{ flex: 1 }} />
          {state === "searching" ? (
            <Btn variant="ghost" size="sm" onClick={search.stop}>
              {t("sftp.search.stop")}
            </Btn>
          ) : (
            !idle && (
              <Btn variant="ghost" size="sm" onClick={() => search.start(root, query)}>
                {t("sftp.search.again")}
              </Btn>
            )
          )}
          <Btn size="sm" disabled={!current} onClick={() => current && onGoTo(current)}>
            {t("sftp.search.goTo")}
          </Btn>
        </>
      }
    >
      <TextInput
        value={query}
        onChange={setQuery}
        onKeyDown={onKeyDown}
        placeholder={t("sftp.search.placeholder")}
        attrs={{
          role: "combobox",
          "aria-label": t("sftp.search.title"),
          "aria-autocomplete": "list",
          "aria-expanded": hits.length > 0,
          "aria-controls": listId,
          "aria-activedescendant": current ? `${listId}-${active}` : undefined,
        }}
      />

      <div
        ref={rows.scrollRef}
        onScroll={rows.measure}
        style={{
          height: `min(${rem(300)}, 42dvh)`,
          overflow: "auto",
          border: `1px solid ${p.line}`,
          borderRadius: 8,
          background: p.bg0,
        }}
      >
        <div
          ref={rows.rowsRef}
          id={listId}
          role="listbox"
          aria-label={t("sftp.search.results")}
          style={{ position: "relative", height: hits.length * rowHeight }}
        >
          {Array.from({ length: rows.end - rows.start }, (_, i) => rows.start + i).map((index) => {
            const hit = hits[index];
            const on = index === active;
            const folder = folderOf(hit);
            return (
              <div
                key={index}
                id={`${listId}-${index}`}
                role="option"
                aria-selected={on}
                aria-posinset={index + 1}
                aria-setsize={hits.length}
                title={hit.rel}
                // The keyboard stays in the query box: a click must not take focus.
                onMouseDown={(e) => e.preventDefault()}
                // A tap goes straight there; a mouse points first, as in the
                // file list, and goes on the second click.
                onClick={() => (isMobile ? onGoTo(hit) : setActive(index))}
                onDoubleClick={() => onGoTo(hit)}
                style={{
                  position: "absolute",
                  top: index * rowHeight,
                  left: 0,
                  right: 0,
                  height: rowHeight,
                  boxSizing: "border-box",
                  display: "flex",
                  alignItems: "center",
                  gap: rem(9),
                  padding: `0 ${rem(10)}`,
                  cursor: "pointer",
                  fontSize: TEXT.base,
                  background: on ? p.bg2 : "transparent",
                  boxShadow: on ? `inset 2px 0 0 ${p.accent}` : "none",
                }}
              >
                <Icon name={iconOf(hit)} size={14} color={hit.entry.isDir ? p.accentText : p.txt3} stroke={1.8} />
                <span
                  style={{
                    flex: "0 1 auto",
                    minWidth: 0,
                    fontFamily: hit.entry.isDir ? UI : MONO,
                    color: p.txt,
                    whiteSpace: "nowrap",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                  }}
                >
                  {hit.entry.name}
                </span>
                {folder && (
                  <span
                    style={{
                      flex: "1 1 0",
                      minWidth: 0,
                      fontFamily: MONO,
                      fontSize: TEXT.micro,
                      color: p.txt2,
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                    }}
                  >
                    {folder}
                  </span>
                )}
              </div>
            );
          })}
        </div>
        {hits.length === 0 && (
          <div style={{ padding: `${rem(28)} ${rem(14)}`, textAlign: "center", fontSize: TEXT.base, color: p.txt3 }}>
            {idle ? t("sftp.search.hint") : state === "searching" ? t("sftp.search.state.searching") : t("sftp.search.none")}
          </div>
        )}
      </div>

      {/* What is on screen moves several times a second, so it is not the live
          region; the off-screen one below changes only with the state. */}
      <div style={{ display: "flex", alignItems: "center", gap: rem(8), minHeight: rem(18), fontSize: TEXT.small, color: broken ? p.red : p.txt2 }}>
        {state === "searching" && <Spinner size={12} />}
        <span style={{ minWidth: 0, overflowWrap: "anywhere" }}>{idle ? "" : status}</span>
      </div>
      <span
        role="status"
        style={{ position: "absolute", width: 1, height: 1, overflow: "hidden", clip: "rect(0 0 0 0)", clipPath: "inset(50%)", whiteSpace: "nowrap" }}
      >
        {news}
      </span>
    </Modal>
  );
}
