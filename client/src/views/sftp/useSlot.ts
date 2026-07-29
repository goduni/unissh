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
import { displayEntries } from "./sortfilter";

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
  select: (name: string, additive: boolean, range: boolean) => void;
  clearSelection: () => void;
  selectedEntries: () => Entry[];
}

export function useSlot(location: LocationRef, sessions: SftpSession[]): SlotCtl {
  const isMobile = useIsMobile();
  const [cwd, setCwd] = useState("");
  const [entries, setEntries] = useState<Entry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selection, setSelection] = useState<Set<string>>(() => new Set());
  const [filter, setFilter] = useState("");
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

  const load = useCallback(
    async (dir: string) => {
      if (!source) return;
      lastAttempt.current = dir; // remembered even on failure, so Retry re-attempts it
      const my = ++gen.current;
      setLoading(true);
      setError(null);
      try {
        // RemoteSource self-heals a server-reaped SFTP channel (reopen+retry
        // once), so a plain list() already recovers here — and so does Retry.
        const list = await source.list(dir);
        if (my !== gen.current) return; // a newer navigation superseded this load
        setEntries(list);
        setCwd(dir);
        setSelection(new Set());
        anchor.current = null;
        memo.current[locKey] = dir;
      } catch (e) {
        if (my === gen.current) setError(apiErrorMessage(e));
      } finally {
        if (my === gen.current) setLoading(false);
      }
    },
    [source, locKey],
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
    select,
    clearSelection,
    selectedEntries,
  };
}
