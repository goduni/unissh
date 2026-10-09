// Transfer logic — conflict/resume decisions, rolling speed/ETA, and recursive
// directory enumeration through FileSource. No store access; time is passed in
// by the caller so throughput calculations stay deterministic in tests.

import type { Entry } from "@/store/sftp-types";
import type { FileSource } from "@/bridge/sources";
import { isSafeName } from "@/sftp/paths";

/** A name collision exists at the destination. */
export function hasConflict(target: Entry | null): boolean {
  return target != null;
}

/** Resume only makes sense when a strictly shorter, non-dir partial exists; the
 *  core's resumable upload/download appends from `offset` keeping the prefix. */
export function canResume(target: Entry | null, sourceSize: number): boolean {
  return target != null && !target.isDir && !target.isSymlink && target.size > 0 && target.size < sourceSize;
}

/** Rolling throughput over a real time window, independent of callback frequency.
 * Only newly transferred bytes belong here, never skipped/resumed prefixes. */
export class Speedometer {
  private samples: Array<{ bytes: number; time: number }> = [];

  sample(bytes: number, nowMs: number): void {
    const last = this.samples[this.samples.length - 1];
    if (last && nowMs < last.time) return;
    if (last && nowMs === last.time) last.bytes = bytes;
    else this.samples.push({ bytes, time: nowMs });
    // Keep one sample at/before the window boundary.
    while (this.samples.length > 2 && this.samples[1].time <= nowMs - 3000) this.samples.shift();
  }

  speed(): number {
    const first = this.samples[0];
    const last = this.samples[this.samples.length - 1];
    if (!first || !last || last.time - first.time < 250) return 0;
    return Math.max(0, (last.bytes - first.bytes) * 1000 / (last.time - first.time));
  }

  eta(remaining: number): number {
    const bps = this.speed();
    return remaining <= 0 ? 0 : bps > 0 ? remaining / bps : Infinity;
  }
}

/** Interrupt a read-only wait. The underlying call may finish later; its result
 * is ignored. Never use this to detach a write that a retry could race. */
export function abortable<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (!signal) return promise;
  return new Promise<T>((resolve, reject) => {
    const abort = () => reject(signal.reason);
    if (signal.aborted) abort();
    else signal.addEventListener("abort", abort, { once: true });
    promise.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
  });
}

/** Bounded-concurrency gate. `run(fn)` waits for a free slot, runs `fn`, and
 *  releases the slot. `capacity` slots run at once; the rest queue FIFO. Used to
 *  cap concurrent SFTP operations to the channel-pool size so file transfers,
 *  directory listings, and mkdirs across a whole batch never exceed K in flight
 *  (more would just block on the core's pool anyway). Pure and self-contained. */
export class Semaphore {
  readonly capacity: number;
  private avail: number;
  private readonly waiters = new Set<() => void>();

  constructor(capacity: number) {
    this.capacity = Number.isFinite(capacity) ? Math.min(16, Math.max(1, Math.floor(capacity))) : 1;
    this.avail = this.capacity;
  }

  async run<T>(fn: () => Promise<T>, signal?: AbortSignal): Promise<T> {
    await this.acquire(signal);
    try {
      signal?.throwIfAborted();
      return await fn();
    } finally {
      this.release();
    }
  }

  private acquire(signal?: AbortSignal): Promise<void> {
    signal?.throwIfAborted();
    if (this.avail > 0) {
      this.avail -= 1;
      return Promise.resolve();
    }
    return new Promise<void>((resolve, reject) => {
      const ready = () => {
        signal?.removeEventListener("abort", abort);
        resolve();
      };
      const abort = () => {
        this.waiters.delete(ready);
        reject(signal?.reason);
      };
      this.waiters.add(ready);
      signal?.addEventListener("abort", abort, { once: true });
    });
  }

  private release(): void {
    const next = this.waiters.values().next().value;
    if (next) { this.waiters.delete(next); next(); }
    else this.avail += 1;
  }
}

/** Fixed workers keep promises and abort listeners proportional to concurrency.
 * Wait for every worker on failure so no writer survives into a retry. */
export async function mapWorkers<T, R>(items: readonly T[], concurrency: number, fn: (item: T, index: number) => Promise<R>, signal?: AbortSignal): Promise<R[]> {
  const results = new Array<R>(items.length);
  let cursor = 0;
  let failed = false;
  let failure: unknown;
  await Promise.all(Array.from({ length: Math.min(items.length, concurrency) }, async () => {
    try {
      while (!failed) {
        signal?.throwIfAborted();
        const index = cursor++;
        if (index >= items.length) return;
        results[index] = await fn(items[index], index);
      }
    } catch (error) { if (!failed) { failed = true; failure = error; } }
  }));
  if (failed) throw failure;
  return results;
}

/** Whether `path` is `dir` itself or lies inside it. Both must be normalized
 *  the same way and carry no trailing separator. */
export function isWithin(dir: string, path: string): boolean {
  return path === dir || path.startsWith(`${dir}/`);
}

/** After a folder move: the source directories that may be removed, deepest
 *  first, as paths relative to the moved root ("" is the root itself). A
 *  directory stays if anything listed in `stayed` (a file that was not moved, or
 *  a directory that could not be removed) is inside it. */
export function emptiedDirs(dirs: readonly string[], stayed: readonly string[]): string[] {
  const depth = (rel: string): number => rel === "" ? 0 : rel.split("/").length;
  return ["", ...dirs]
    .filter((dir) => !stayed.some((rel) => dir === "" || isWithin(dir, rel)))
    .sort((a, b) => depth(b) - depth(a));
}

export interface WalkItem {
  relPath: string; // path relative to the walk root, joined with "/"
  isDir: boolean;
  isSymlink?: boolean;
  size: number;
}

/** Result of scanning a directory tree: every sub-directory (relative paths,
 *  each listed AFTER its parent so a consumer can create them parent-first) and
 *  every file with its size. */
export interface TreeScan {
  dirs: string[];
  files: WalkItem[];
  directoryMetadata: Map<string, Entry>;
}

/** Recursively enumerate `root` on `src`, listing sibling sub-directories
 *  concurrently (bounded by `sem`) instead of one-round-trip-at-a-time. Cuts the
 *  scan "prologue" stall on wide/deep trees while still returning honest totals.
 *  Invariant: a directory always appears in `dirs` before any of its descendants
 *  (its parent pushes it before recursing), so `dirs` can be created parent-first.
 *  Names that could self-recurse or escape the tree ("."/".."/separators) are
 *  skipped, matching the old `walk`. */
export async function collectTree(
  src: FileSource,
  root: string,
  sem: Semaphore,
  signal?: AbortSignal,
): Promise<TreeScan> {
  const dirs: string[] = [];
  const files: WalkItem[] = [];
  const directoryMetadata = new Map<string, Entry>();
  let pending = [{ abs: root, rel: "" }];
  while (pending.length) {
    const next: typeof pending = [];
    await mapWorkers(pending, sem.capacity, async ({ abs, rel }) => {
      const entries = await sem.run(() => signal ? src.list(abs, signal) : src.list(abs), signal);
      for (const e of entries) {
        signal?.throwIfAborted();
        if (e.name === "." || e.name === "..") continue;
        if (!isSafeName(e.name)) throw new Error(`Invalid filename: ${e.name}`);
        const childRel = rel ? `${rel}/${e.name}` : e.name;
        if (e.isDir && !e.isSymlink) {
          dirs.push(childRel);
          directoryMetadata.set(childRel, e);
          next.push({ abs: await src.join(abs, e.name), rel: childRel });
        } else {
          if (!e.isSymlink && e.mode && (e.mode & 0o170000) !== 0o100000) throw new Error(`Unsupported file type: ${childRel}`);
          files.push({ relPath: childRel, isDir: false, size: e.isSymlink ? 0 : e.size, ...(e.isSymlink ? { isSymlink: true } : {}) });
        }
      }
    }, signal);
    pending = next;
  }
  return { dirs, files, directoryMetadata };
}

/** Recursively enumerate `root` on `src`, yielding each directory BEFORE its
 *  contents so a consumer can mkdir the tree top-down. Relative paths use "/"
 *  regardless of source kind; the consumer rejoins against the target source. */
export async function* walk(src: FileSource, root: string, rel = ""): AsyncGenerator<WalkItem> {
  const entries = await src.list(root);
  entries.sort((a, b) => (a.isDir === b.isDir ? a.name.localeCompare(b.name) : a.isDir ? -1 : 1));
  for (const e of entries) {
    // Never recurse into "."/".." or a name with a separator — guards against a
    // server triggering infinite recursion or a path-traversal write.
    if (!isSafeName(e.name)) continue;
    const childRel = rel ? `${rel}/${e.name}` : e.name;
    if (e.isDir && !e.isSymlink) {
      const childAbs = await src.join(root, e.name);
      yield { relPath: childRel, isDir: true, size: 0 };
      yield* walk(src, childAbs, childRel);
    } else {
      yield { relPath: childRel, isDir: false, size: e.isSymlink ? 0 : e.size, ...(e.isSymlink ? { isSymlink: true } : {}) };
    }
  }
}
