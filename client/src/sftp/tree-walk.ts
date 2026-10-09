// Read-only walk over a directory subtree through FileSource — the same for the
// local filesystem and a remote session. `walkTree` is the primitive: it lists
// every directory under a root with bounded concurrency and hands each listing
// to a visitor. `folderSize` is one consumer of it; anything else that has to
// look at a whole subtree (a recursive name search, say) is meant to be another.
//
// Unlike the transfer scan (`collectTree`), which must fail as a whole so a copy
// never starts from a partial plan, a walk here survives a directory it cannot
// read, and holds only the paths of the level it is listing and of the next one
// it is collecting — never the tree.

import type { Entry } from "@/store/sftp-types";
import { apiErrorMessage } from "@/bridge/types";
import { isSftpDisconnect, type FileSource } from "@/bridge/sources";
import { isSafeName, isWalkableDir } from "@/sftp/paths";
import { abortable, mapWorkers, type Semaphore } from "@/sftp/transfer-engine";

/** One listed directory of the walk. */
export interface DirBatch {
  /** The directory's path on the source. */
  path: string;
  /** Its path relative to the walk root, joined with "/"; "" is the root. */
  rel: string;
  /** Everything in it, links included. Names that could escape the tree or
   *  recurse into it ("."/".."/separators) are left out. */
  entries: Entry[];
}

export interface WalkOptions {
  /** Caps listings in flight. Share one across walks (and with the transfer
   *  pipeline) to keep the whole pane within the session's channel pool. */
  sem: Semaphore;
  /** Aborting rejects the walk with the signal's reason; nothing is listed after. */
  signal?: AbortSignal;
  /** Called once per directory that could be listed, in no particular order
   *  within a level; a parent always comes before its children. */
  onDir: (batch: DirBatch) => void;
  /** Called for a subdirectory (`rel`, relative to the root) that could not be
   *  listed; the walk goes on without it. Two failures are not covered and fail
   *  the walk: the root's, and a remote one that means the session is gone —
   *  nothing below would be readable either. */
  onSkip?: (rel: string, error: unknown) => void;
}

/** List `root` and every directory below it on `src`, level by level. */
export async function walkTree(src: FileSource, root: string, { sem, signal, onDir, onSkip }: WalkOptions): Promise<void> {
  let level = [{ path: root, rel: "" }];
  while (level.length) {
    const next: typeof level = [];
    await mapWorkers(level, sem.capacity, async ({ path, rel }) => {
      let listed: Entry[];
      try {
        // `abortable` because not every source can interrupt a listing itself.
        listed = await sem.run(() => abortable(signal ? src.list(path, signal) : src.list(path), signal), signal);
      } catch (error) {
        if (signal?.aborted) throw signal.reason;
        if (rel === "") throw error;
        // Only a remote source has a session to lose; a local error text can
        // carry a path, which must not be read as one.
        if (src.kind === "remote" && isSftpDisconnect(apiErrorMessage(error))) throw error;
        onSkip?.(rel, error);
        return;
      }
      const entries = listed.filter((e) => isSafeName(e.name));
      onDir({ path, rel, entries });
      for (const e of entries) {
        if (!isWalkableDir(e)) continue;
        const childRel = rel ? `${rel}/${e.name}` : e.name;
        try {
          next.push({ path: await src.join(path, e.name), rel: childRel });
        } catch (error) {
          // A name the source cannot address (a local Windows alias, say).
          onSkip?.(childRel, error);
        }
      }
    }, signal);
    level = next;
  }
}

export interface FolderSizeProgress {
  /** Bytes in the files seen so far. */
  bytes: number;
  /** Entries seen so far: files, folders and links alike. */
  entries: number;
}

export interface FolderSizeResult extends FolderSizeProgress {
  /** Subdirectories that could not be read. */
  skipped: number;
  /** True when something was skipped, so `bytes` is a lower bound. */
  partial: boolean;
}

export interface FolderSizeOptions {
  sem: Semaphore;
  signal?: AbortSignal;
  /** Running totals, at most once per `throttleMs`. The final figures are the
   *  returned result, not a last progress call. */
  onProgress?: (progress: FolderSizeProgress) => void;
  throttleMs?: number;
  now?: () => number;
}

/** Whether an entry's size counts towards a total: a regular file — an entry
 *  whose listing carries no type is read as one, as the transfer scan does —
 *  with a size the source vouches for. */
function countedSize(e: Entry): number {
  const kind = e.fileKind ?? "unknown";
  const regular = !e.isDir && !e.isSymlink && (kind === "file" || kind === "unknown");
  return regular && e.sizeKnown !== false && Number.isFinite(e.size) && e.size >= 0 ? e.size : 0;
}

/** Total size of the regular files under `root`. Links count as nothing (the
 *  target is either elsewhere or already counted) and so do directories
 *  themselves, devices, sockets and pipes. */
export async function folderSize(
  src: FileSource,
  root: string,
  { sem, signal, onProgress, throttleMs = 250, now = Date.now }: FolderSizeOptions,
): Promise<FolderSizeResult> {
  let bytes = 0;
  let entries = 0;
  let skipped = 0;
  let reported = -Infinity;
  await walkTree(src, root, {
    sem,
    signal,
    onSkip: () => { skipped += 1; },
    onDir: (batch) => {
      entries += batch.entries.length;
      for (const e of batch.entries) bytes += countedSize(e);
      const at = now();
      if (!onProgress || at - reported < throttleMs) return;
      reported = at;
      onProgress({ bytes, entries });
    },
  });
  return { bytes, entries, skipped, partial: skipped > 0 };
}
