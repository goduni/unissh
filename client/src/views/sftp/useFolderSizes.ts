// useFolderSizes — the on-demand folder totals of one pane's current listing.
// A thin adapter: the registry (folderSizes.ts) owns the walks and the rules;
// this binds it to the pane's source and directory and to React state. The slot
// resets it whenever the listing reloads or the pane stops showing it. Nothing
// is kept across panes or sessions.

import { useCallback, useEffect, useState } from "react";
import type { FileSource } from "@/bridge/sources";
import { makeTransferSemaphore } from "@/sftp/transfer-runner";
import { FolderSizeRegistry, measureFolder, NO_FOLDER_SIZES, type FolderSizes } from "./folderSizes";

export interface FolderSizesCtl {
  sizes: FolderSizes;
  /** Start (or start over) the walk for each named folder of the listing. */
  start: (names: string[]) => void;
  /** Stop the named walks, or every walk; a stopped folder shows no total.
   *  Finished totals stay. */
  cancel: (names?: string[]) => void;
  /** Stop every walk and forget every total; what is listed next is a new
   *  listing, and nothing started before this point may write into it. */
  reset: () => void;
}

export function useFolderSizes(source: FileSource | null, cwd: string): FolderSizesCtl {
  const [snapshot, setSnapshot] = useState(NO_FOLDER_SIZES);
  const [registry] = useState(() => new FolderSizeRegistry(setSnapshot));

  const reset = useCallback(() => registry.reset(), [registry]);
  const cancel = useCallback((names?: string[]) => registry.cancel(names), [registry]);
  // No walk outlives the pane.
  useEffect(() => reset, [reset]);

  // The generation is the one this render's rows belong to: `source` and `cwd`
  // here are theirs, so a call from rows already replaced must not start.
  const { generation } = snapshot;
  const start = useCallback(
    (names: string[]) => {
      if (!source) return;
      // The pipeline's own gate: listings here and transfers together stay
      // within the channel pool instead of each bringing a budget of its own.
      const sem = makeTransferSemaphore();
      registry.start(names, (name, signal, onProgress) => measureFolder(source, cwd, name, sem, signal, onProgress), generation);
    },
    [registry, source, cwd, generation],
  );

  return { sizes: snapshot.sizes, start, cancel, reset };
}
