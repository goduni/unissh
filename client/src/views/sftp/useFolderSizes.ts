// useFolderSizes — the on-demand folder totals of one pane's current listing.
// A total is a snapshot of that listing: the slot drops them all (and stops the
// walks still running) whenever the listing reloads or the pane stops showing
// it. Nothing is kept across panes or sessions.

import { useCallback, useEffect, useRef, useState } from "react";
import { apiErrorMessage } from "@/bridge/types";
import type { FileSource } from "@/bridge/sources";
import { folderSize } from "@/sftp/tree-walk";
import { makeTransferSemaphore } from "@/sftp/transfer-runner";

/** What a folder's size cell shows once a total was asked for. */
export type FolderSizeState =
  | { state: "pending"; bytes: number }
  | { state: "done"; bytes: number; partial: boolean }
  | { state: "failed"; error: string };

export type FolderSizes = ReadonlyMap<string, FolderSizeState>;

const NONE: FolderSizes = new Map();

export interface FolderSizesCtl {
  sizes: FolderSizes;
  /** Start (or start over) the walk for each named folder of the listing. */
  start: (names: string[]) => void;
  /** Stop the named walks, or every walk; a stopped folder shows no total.
   *  Finished totals stay. */
  cancel: (names?: string[]) => void;
  /** Stop every walk and forget every total. */
  reset: () => void;
}

export function useFolderSizes(source: FileSource | null, cwd: string): FolderSizesCtl {
  const [sizes, setSizes] = useState<FolderSizes>(NONE);
  // The walk that owns each name. A walk may only write while it is still the
  // one registered here, which is also what makes a late result harmless.
  const walks = useRef(new Map<string, AbortController>());

  const reset = useCallback(() => {
    for (const walk of walks.current.values()) walk.abort();
    walks.current.clear();
    setSizes((prev) => (prev.size ? NONE : prev));
  }, []);
  // No walk outlives the pane.
  useEffect(() => reset, [reset]);

  const cancel = useCallback((names?: string[]) => {
    const stopped = (names ?? [...walks.current.keys()]).filter((name) => walks.current.has(name));
    if (!stopped.length) return;
    for (const name of stopped) {
      walks.current.get(name)?.abort();
      walks.current.delete(name);
    }
    setSizes((prev) => {
      const next = new Map(prev);
      for (const name of stopped) next.delete(name);
      return next;
    });
  }, []);

  const start = useCallback(
    (names: string[]) => {
      if (!source || !names.length) return;
      // The pipeline's own gate: listings here and transfers together stay
      // within the channel pool instead of each bringing a budget of its own.
      const sem = makeTransferSemaphore();
      const begun = names.map((name) => {
        walks.current.get(name)?.abort();
        const walk = new AbortController();
        walks.current.set(name, walk);
        const put = (value: FolderSizeState) => {
          if (walks.current.get(name) === walk) setSizes((prev) => new Map(prev).set(name, value));
        };
        void (async () => {
          try {
            const root = await source.join(cwd, name);
            const total = await folderSize(source, root, {
              sem,
              signal: walk.signal,
              onProgress: ({ bytes }) => put({ state: "pending", bytes }),
            });
            put({ state: "done", bytes: total.bytes, partial: total.partial });
          } catch (error) {
            put({ state: "failed", error: apiErrorMessage(error) });
          } finally {
            if (walks.current.get(name) === walk) walks.current.delete(name);
          }
        })();
        return name;
      });
      setSizes((prev) => {
        const next = new Map(prev);
        for (const name of begun) next.set(name, { state: "pending", bytes: 0 });
        return next;
      });
    },
    [source, cwd],
  );

  return { sizes, start, cancel, reset };
}
