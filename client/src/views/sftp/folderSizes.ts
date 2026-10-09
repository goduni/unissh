// The on-demand folder totals of one pane, without React: which walk owns which
// folder, what its size cell shows, and when that reaches the screen.
//
// A total is a snapshot of one listing. Every listing the pane applies is a new
// generation; a walk belongs to the generation it was started under and may
// write only while it is both of the current generation and still the walk
// registered for its folder. That is what makes a late result — from a stopped
// walk, a restarted one, or one begun on rows that have since been replaced —
// harmless.

import * as api from "@/bridge/api";
import { apiErrorMessage } from "@/bridge/types";
import type { FileSource } from "@/bridge/sources";
import type { Semaphore } from "@/sftp/transfer-engine";
import { folderSize, type FolderSizeResult } from "@/sftp/tree-walk";

/** What a folder's size cell shows once a total was asked for. */
export type FolderSizeState =
  | { state: "pending"; bytes: number }
  | { state: "done"; bytes: number; partial: boolean }
  | { state: "failed"; error: string };

export type FolderSizes = ReadonlyMap<string, FolderSizeState>;

/** The totals of one listing generation, by entry name. */
export interface FolderSizeSnapshot {
  generation: number;
  sizes: FolderSizes;
}

const NONE: FolderSizes = new Map();
export const NO_FOLDER_SIZES: FolderSizeSnapshot = { generation: 0, sizes: NONE };

/** Totals one folder; `onProgress` takes the bytes counted so far. */
export type MeasureFolder = (name: string, signal: AbortSignal, onProgress: (bytes: number) => void) => Promise<Pick<FolderSizeResult, "bytes" | "partial">>;

export class FolderSizeRegistry {
  private generation = NO_FOLDER_SIZES.generation;
  private sizes = NONE;
  /** The walk that owns each name. */
  private readonly walks = new Map<string, AbortController>();
  /** Running figures not on screen yet; one timer commits them all. */
  private readonly running = new Map<string, number>();
  private timer: ReturnType<typeof setTimeout> | undefined;

  constructor(
    private readonly onChange: (snapshot: FolderSizeSnapshot) => void,
    private readonly flushMs = 250,
  ) {}

  /** Start (or start over) the walk for each named folder. `generation` is the
   *  one of the listing the caller was looking at: a request made from rows
   *  that have been replaced since is dropped. */
  start(names: string[], measure: MeasureFolder, generation: number): void {
    if (generation !== this.generation || !names.length) return;
    const next = new Map(this.sizes);
    for (const name of names) {
      this.walks.get(name)?.abort();
      this.running.delete(name);
      const walk = new AbortController();
      this.walks.set(name, walk);
      next.set(name, { state: "pending", bytes: 0 });
      const owns = () => generation === this.generation && this.walks.get(name) === walk;
      const finish = (value: FolderSizeState) => {
        if (!owns()) return;
        this.walks.delete(name);
        this.running.delete(name);
        this.commit(new Map(this.sizes).set(name, value));
      };
      measure(name, walk.signal, (bytes) => {
        if (!owns()) return;
        this.running.set(name, bytes);
        this.timer ??= setTimeout(() => this.flush(), this.flushMs);
      }).then(
        (total) => finish({ state: "done", bytes: total.bytes, partial: total.partial }),
        (error) => finish({ state: "failed", error: apiErrorMessage(error) }),
      );
    }
    this.commit(next);
  }

  /** Stop the named walks, or every walk; a stopped folder shows no total.
   *  Finished totals stay. */
  cancel(names?: string[]): void {
    const stopped = (names ?? [...this.walks.keys()]).filter((name) => this.walks.has(name));
    if (!stopped.length) return;
    const next = new Map(this.sizes);
    for (const name of stopped) {
      this.walks.get(name)?.abort();
      this.walks.delete(name);
      this.running.delete(name);
      next.delete(name);
    }
    this.commit(next);
  }

  /** A listing was applied (or is being replaced, or the pane is going away):
   *  stop every walk, forget every total and open a new generation. */
  reset(): void {
    for (const walk of this.walks.values()) walk.abort();
    this.walks.clear();
    this.running.clear();
    this.generation += 1;
    this.commit(this.sizes.size ? NONE : this.sizes);
  }

  /** Put the running figures on screen. Only folders still being counted are
   *  in `running`, so this can never overwrite a total, a failure or a stop. */
  private flush(): void {
    this.timer = undefined;
    if (!this.running.size) return;
    const next = new Map(this.sizes);
    for (const [name, bytes] of this.running) next.set(name, { state: "pending", bytes });
    this.running.clear();
    this.commit(next);
  }

  private commit(sizes: FolderSizes): void {
    this.sizes = sizes;
    // No timer is left behind once nothing is waiting for it.
    if (!this.running.size && this.timer !== undefined) {
      clearTimeout(this.timer);
      this.timer = undefined;
    }
    this.onChange({ generation: this.generation, sizes });
  }
}

/** Total the folder `name` of `cwd` on `source` under one cancel token for the
 *  whole walk, the way a transfer runs: the token is triggered when `signal`
 *  aborts, which stops the listings in flight on either kind of source, and is
 *  disposed when the walk ends. */
export async function measureFolder(
  source: FileSource,
  cwd: string,
  name: string,
  sem: Semaphore,
  signal: AbortSignal,
  onProgress: (bytes: number) => void,
): Promise<FolderSizeResult> {
  let token: string | undefined;
  const trigger = () => { if (token) api.cancelTrigger(token).catch(() => {}); };
  signal.addEventListener("abort", trigger, { once: true });
  try {
    let src = source;
    if (source.withCancelToken) {
      token = await api.cancelNew();
      signal.throwIfAborted();
      src = source.withCancelToken(token);
    }
    return await folderSize(src, await src.join(cwd, name), {
      sem,
      signal,
      // The registry paces what reaches the screen; a second throttle here
      // would only add delay.
      throttleMs: 0,
      onProgress: ({ bytes }) => onProgress(bytes),
    });
  } finally {
    signal.removeEventListener("abort", trigger);
    if (token) await api.cancelDispose(token).catch(() => {});
  }
}
