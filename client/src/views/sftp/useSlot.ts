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
import { displayEntries, revealPlan, shownNames } from "./sortfilter";
import type { FolderSizes } from "./folderSizes";
import { useFolderSizes } from "./useFolderSizes";
import type { CursorRequest } from "./shortcuts";

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
   *  the filter if it would hide the entry. A folder the pane already shows
   *  with that entry in it is not listed again. */
  reveal: (dir: string, name: string) => void;
  /** The entry the last `reveal` asked the list to put its cursor on; null
   *  once the list did, or any other listing was applied. */
  cursorOn: CursorRequest | null;
  /** The list put its cursor where `cursorOn` asked. */
  cursorDone: () => void;
  select: (name: string, additive: boolean, range: boolean) => void;
  selectAll: () => void;
  clearSelection: () => void;
  selectedEntries: () => Entry[];
  /** On-demand totals of this listing's folders, by entry name. */
  folderSizes: FolderSizes;
  startFolderSizes: (names: string[]) => void;
  /** Stops the named pending totals, or all of them. */
  cancelFolderSizes: (names?: string[]) => void;
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
  const cursorDone = useCallback(() => setCursorOn(null), []);
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

  /** Point the pane at the entry `name` of `list`, the listing it shows — or
   *  at nothing, without a name or when the entry is not there. */
  const pointAt = useCallback((list: Entry[], name?: string) => {
    const plan = name == null ? null : revealPlan(list, filterRef.current, name);
    const found = plan && name != null ? name : null;
    if (plan?.clearFilter) setFilter("");
    // Selected as well as pointed at: touch has no cursor ring to show it by.
    setSelection(new Set(found ? [found] : []));
    anchor.current = found;
    setCursorOn(found ? { name: found } : null);
  }, []);

  const load = useCallback(
    async (dir: string, reveal?: string) => {
      if (!source) return;
      lastAttempt.current = dir; // remembered even on failure, so Retry re-attempts it
      const my = ++gen.current;
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
        pointAt(list, reveal);
        memo.current[locKey] = dir;
      } catch (e) {
        if (my === gen.current) setError(apiErrorMessage(e));
      } finally {
        if (my === gen.current) setLoading(false);
      }
    },
    [source, locKey, resetFolderSizes, pointAt],
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
  const reveal = useCallback(
    (dir: string, name: string) => {
      // Already there, and nothing newer on its way: the listing stays as it
      // is — and with it the folder totals worked out on it.
      const here = dir === cwd && !loading && revealPlan(entriesRef.current, filterRef.current, name) != null;
      if (here) pointAt(entriesRef.current, name);
      else void load(dir, name);
    },
    [cwd, loading, load, pointAt],
  );
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
    cursorDone,
    select,
    selectAll,
    clearSelection,
    selectedEntries,
    folderSizes,
    startFolderSizes,
    cancelFolderSizes,
  };
}
