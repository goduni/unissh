// useFileSearch — the recursive search of one pane. A thin adapter: the
// controller (fileSearch.ts) owns the walk and the rules; this binds it to the
// pane's source and to React state. The slot stops it whenever the pane reloads
// and clears it when the pane stops showing that location.

import { useCallback, useEffect, useMemo, useState } from "react";
import type { FileSource } from "@/bridge/sources";
import { makeTransferSemaphore } from "@/sftp/transfer-runner";
import { nameMatcher, searchTree } from "@/sftp/tree-search";
import { FileSearch, NO_SEARCH, type SearchSnapshot } from "./fileSearch";

export interface FileSearchCtl {
  result: SearchSnapshot;
  /** Search below `root` for `query`, in place of whatever was running or
   *  shown. A blank query clears the search instead. */
  start: (root: string, query: string) => void;
  /** Stop the running search; what it found stays. */
  stop: () => void;
  /** Stop the running search and forget every result. */
  reset: () => void;
}

export function useFileSearch(source: FileSource | null): FileSearchCtl {
  const [result, setResult] = useState(NO_SEARCH);
  const [search] = useState(() => new FileSearch(setResult));

  const stop = useCallback(() => search.stop(), [search]);
  const reset = useCallback(() => search.reset(), [search]);
  // No walk outlives the pane.
  useEffect(() => reset, [reset]);

  const start = useCallback(
    (root: string, query: string) => {
      const match = nameMatcher(query);
      if (!source || !match) return search.reset();
      // The pipeline's own gate, as for folder totals: listings here and
      // transfers together stay within the channel pool.
      const sem = makeTransferSemaphore();
      search.start((signal, onProgress) => searchTree(source, root, { sem, signal, match, onProgress }));
    },
    [search, source],
  );

  return useMemo(() => ({ result, start, stop, reset }), [result, start, stop, reset]);
}
