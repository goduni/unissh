// useFileSearch — the recursive search of the search dialog. A thin adapter:
// the controller (fileSearch.ts) owns the walk and the rules; this binds it to
// a source and to React state, and ends it with the component that uses it.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
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
  // Read when a search starts: the source object is rebuilt whenever any
  // session opens or closes, and a search must not start over because of that.
  const from = useRef(source);
  from.current = source;

  const stop = useCallback(() => search.stop(), [search]);
  const reset = useCallback(() => search.reset(), [search]);
  // No walk outlives its owner.
  useEffect(() => reset, [reset]);

  const start = useCallback(
    (root: string, query: string) => {
      const source = from.current;
      const match = nameMatcher(query);
      if (!source || !match) return search.reset();
      // The pipeline's own gate, as for folder totals: listings here and
      // transfers together stay within the channel pool.
      const sem = makeTransferSemaphore();
      search.start((signal, onProgress) => searchTree(source, root, { sem, signal, match, onProgress }));
    },
    [search],
  );

  return useMemo(() => ({ result, start, stop, reset }), [result, start, stop, reset]);
}
