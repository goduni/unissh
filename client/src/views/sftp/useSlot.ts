// useSlot — owns one pane slot's browsing state (cwd, listing, selection, sort,
// filter) and navigation/selection logic for whichever location it points at.
// Browse state is per-slot (not per-session) so two slots can show the same
// location at different paths. ViewSftp creates one per visible slot and wires
// transfers between them.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { documentDir, homeDir } from "@tauri-apps/api/path";
import { useIsMobile } from "@/store/responsive";
import { apiErrorMessage } from "@/bridge/types";
import { sourceFor, type FileSource } from "@/bridge/sources";
import type { Entry, LocationRef, SftpSession, SortKey, SortState } from "@/store/sftp-types";
import { displayEntries, shownNames } from "./sortfilter";
import type { FolderSizes } from "./folderSizes";
import { useFolderSizes } from "./useFolderSizes";
import { useFileSearch, type FileSearchCtl } from "./useFileSearch";

export interface SlotCtl {
  location: LocationRef;
  source: FileSource | null;
  cwd: string;
  entries: Entry[];
  loading: boolean;
  error: string | null;
  selection: Set<string>;
  filter: string;
  sort: SortState;
  setFilter: (v: string) => void;
  toggleSort: (key: SortKey) => void;
  navigate: (name: string) => void;
  up: () => void;
  goTo: (path: string) => void;
  refresh: () => void;
  /** Open `dir` and put the cursor on its entry `name`, selected — clearing
   *  the filter if it would hide the entry. */
  reveal: (dir: string, name: string) => void;
  /** The entry the last `reveal` asked the list to put its cursor on; null
   *  once any other listing was applied. */
  cursorOn: CursorRequest | null;
  select: (name: string, additive: boolean, range: boolean) => void;
  selectAll: () => void;
  clearSelection: () => void;
  selectedEntries: () => Entry[];
  /** On-demand totals of this listing's folders, by entry name. */
  folderSizes: FolderSizes;
  startFolderSizes: (names: string[]) => void;
  /** Stops the named pending totals, or all of them. */
  cancelFolderSizes: (names?: string[]) => void;
  /** The recursive search below this pane's folder. */
  search: FileSearchCtl;
}

/** One request to move a list's cursor; `seq` tells two for the same name apart. */
export interface CursorRequest {
  name: string;
  seq: number;
}

export function useSlot(location: LocationRef, sessions: SftpSession[]): SlotCtl {
  const isMobile = useIsMobile();
  const [cwd, setCwd] = useState("");
  const [entries, setEntries] = useState<Entry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selection, setSelection] = useState<Set<string>>(() => new Set());
  const [filter, setFilter] = useState("");
  const filterRef = useRef(filter);
  filterRef.current = filter;
  const [cursorOn, setCursorOn] = useState<CursorRequest | null>(null);
  const cursorSeq = useRef(0);
  const [sort, setSort] = useState<SortState>({ key: "name", dir: "asc" });
  const memo = useRef<Record<string, string>>({});
  const anchor = useRef<string | null>(null);
  const lastAttempt = useRef<string | null>(null);
  const gen = useRef(0);

  const locKey = location.kind === "remote" ? location.sessionId : location.kind;
  const source = useMemo(() => {
    try {
      return sourceFor(location, sessions);
    } catch {
      return null;
    }
  }, [location, sessions]);

  const entriesRef = useRef<Entry[]>(entries);
  entriesRef.current = entries;

  const { sizes: folderSizes, start: startFolderSizes, cancel: cancelFolderSizes, reset: resetFolderSizes } = useFolderSizes(source, cwd);
  // The totals belong to what the pane is showing. Leaving the location, or
  // losing the session behind it, ends them; `load` covers every other way the
  // listing can change. Keyed on the location rather than on `source`, which is
  // rebuilt whenever any session opens or closes.
  const hasSource = source != null;
  useEffect(() => resetFolderSizes, [locKey, hasSource, resetFolderSizes]);

  // A search belongs to the folder it was started in. Reloading the pane stops
  // it (see `load`) with its results kept; a pane that no longer shows the
  // location — or lost the session behind it — has no use for them.
  const search = useFileSearch(source);
  const { stop: stopSearch, reset: resetSearch } = search;
  useEffect(() => resetSearch, [locKey, hasSource, resetSearch]);

  const load = useCallback(
    async (dir: string, reveal?: string) => {
      if (!source) return;
      lastAttempt.current = dir; // remembered even on failure, so Retry re-attempts it
      const my = ++gen.current;
      stopSearch();
      // Totals are a snapshot of the listing being replaced (or re-read).
      resetFolderSizes();
      setLoading(true);
      setError(null);
      try {
        // RemoteSource self-heals a server-reaped SFTP channel (reopen+retry
        // once), so a plain list() already recovers here — and so does Retry.
        const list = await source.list(dir);
        if (my !== gen.current) return; // a newer navigation superseded this load
        // The rows stayed usable while this was in flight, so a total may have
        // been asked for on them since the reset above. It belongs to the old
        // listing: this one starts clean, as a new generation.
        resetFolderSizes();
        setEntries(list);
        setCwd(dir);
        // An entry that is gone by now is simply not there to point at.
        const found = reveal != null && list.some((e) => e.name === reveal) ? reveal : null;
        if (found && !shownNames(list, filterRef.current).has(found)) setFilter("");
        setSelection(new Set(found ? [found] : []));
        anchor.current = found;
        setCursorOn(found ? { name: found, seq: ++cursorSeq.current } : null);
        memo.current[locKey] = dir;
      } catch (e) {
        if (my === gen.current) setError(apiErrorMessage(e));
      } finally {
        if (my === gen.current) setLoading(false);
      }
    },
    [source, locKey, resetFolderSizes, stopSearch],
  );

  // (re)initialise the cwd whenever the slot's location changes
  useEffect(() => {
    if (!source) return;
    let cancelled = false;
    (async () => {
      let dir = memo.current[locKey];
      if (!dir) {
        if (location.kind === "remote") {
          dir = sessions.find((s) => s.id === location.sessionId)?.home ?? "/";
        } else {
          try {
            // Mobile (iOS) can't browse the OS filesystem — root the local tab at
            // the app's documents sandbox instead of the home directory.
            dir = isMobile ? await documentDir() : await homeDir();
          } catch {
            dir = "/";
          }
        }
      }
      if (!cancelled) load(dir);
    })();
    return () => {
      cancelled = true;
      gen.current += 1; // invalidate any in-flight load for the previous location
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [locKey]);

  const navigate = useCallback(
    async (name: string) => {
      if (!source) return;
      load(await source.join(cwd, name));
    },
    [source, cwd, load],
  );
  const up = useCallback(async () => {
    if (!source) return;
    load(await source.parent(cwd));
  }, [source, cwd, load]);
  const goTo = useCallback(
    async (path: string) => {
      if (!source) return;
      try {
        load(await source.realpath(path));
      } catch {
        load(path);
      }
    },
    [source, load],
  );
  const reveal = useCallback((dir: string, name: string) => void load(dir, name), [load]);
  const refresh = useCallback(() => {
    const dir = lastAttempt.current ?? cwd;
    if (dir) load(dir);
  }, [cwd, load]);

  const toggleSort = useCallback((key: SortKey) => {
    setSort((s) => (s.key === key ? { key, dir: s.dir === "asc" ? "desc" : "asc" } : { key, dir: "asc" }));
  }, []);

  const select = useCallback(
    (name: string, additive: boolean, range: boolean) => {
      setSelection((prev) => {
        const next = new Set(prev);
        if (range && anchor.current) {
          const order = displayEntries(entriesRef.current, filter, sort).map((e) => e.name);
          const i = order.indexOf(anchor.current);
          const j = order.indexOf(name);
          if (i >= 0 && j >= 0) {
            if (!additive) next.clear();
            const [lo, hi] = i < j ? [i, j] : [j, i];
            for (let k = lo; k <= hi; k++) next.add(order[k]);
            return next;
          }
        }
        if (additive) {
          if (next.has(name)) next.delete(name);
          else next.add(name);
        } else {
          next.clear();
          next.add(name);
        }
        anchor.current = name;
        return next;
      });
    },
    [filter, sort],
  );
  // Only what the filter shows: an operation must never reach a hidden entry.
  const selectAll = useCallback(() => setSelection(shownNames(entriesRef.current, filter)), [filter]);
  const clearSelection = useCallback(() => setSelection(new Set()), []);
  const selectedEntries = useCallback(
    () => entriesRef.current.filter((e) => selection.has(e.name)),
    [selection],
  );

  return {
    location,
    source,
    cwd,
    entries,
    loading,
    error,
    selection,
    filter,
    sort,
    setFilter,
    toggleSort,
    navigate,
    up,
    goTo,
    refresh,
    reveal,
    cursorOn,
    select,
    selectAll,
    clearSelection,
    selectedEntries,
    folderSizes,
    startFolderSizes,
    cancelFolderSizes,
    search,
  };
}
