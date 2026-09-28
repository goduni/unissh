// Transfer runner — drives a Transfer against the bridge and the store. Handles
// the four source/target combinations, live progress, cancel/pause/resume, and
// recursive directory transfers. Pure decisions live in transfer-engine.ts; this
// file is the imperative glue (bridge calls + store patches + cancel tokens).

import * as api from "@/bridge/api";
import { apiErrorMessage } from "@/bridge/types";
import { useApp } from "@/store/app";
import type { Entry, Transfer } from "@/store/sftp-types";
import { sourceFor, type FileSource } from "@/bridge/sources";
import { abortable, canResume, collectTree, Semaphore, Speedometer, type WalkItem } from "@/sftp/transfer-engine";
import { dedupeName } from "@/sftp/paths";
import { join, tempDir } from "@tauri-apps/api/path";
import { copyFile, remove, stat } from "@tauri-apps/plugin-fs";

export interface ConflictResolution {
  choice: "overwrite" | "skip" | "keepboth" | "resume";
  applyAll: boolean;
}
export type ConflictResolver = (info: {
  name: string;
  targetSize: number;
  sourceSize: number;
  resumable: boolean;
  sameSize: boolean;
}, signal?: AbortSignal) => Promise<ConflictResolution>;

interface Control {
  abort: AbortController;
  moved: number;
  pendingConflicts: number;
  lastProgressAt: number;
  patch: (patch: Partial<Transfer>) => void;
  paused: boolean;
  cancelled: boolean;
  /** Cancel tokens of every file leg currently in flight for this transfer. A
   *  directory transfer runs up to K legs at once, so pause/cancel must trigger
   *  ALL of them, not just "the active one". */
  cancelIds: Set<string>;
}
const controls = new Map<string, Control>();

/** Trigger every in-flight cancel token for a control (pause or cancel). */
function triggerAll(ctrl: Control): void {
  ctrl.abort.abort();
  for (const cid of ctrl.cancelIds) api.cancelTrigger(cid).catch(() => {});
}

/** Serialize a resolver so at most one conflict prompt is pending at a time:
 *  parallel file legs would otherwise race the single conflict dialog. Once the
 *  user picks "apply to all", the underlying resolver returns synchronously, so
 *  this adds no latency to the common case. */
export function serializeResolver(r: ConflictResolver): ConflictResolver {
  let tail: Promise<unknown> = Promise.resolve();
  return (info, signal) => {
    const result = tail.then(() => {
      signal?.throwIfAborted();
      return abortable(r(info, signal), signal);
    });
    tail = result.catch(() => undefined);
    return result;
  };
}

/** Folder legs may wait on multiple serialized prompts at once. Keep the
 * transfer waiting until all decisions are settled, including queued prompts. */
async function resolveConflict(
  resolver: ConflictResolver,
  info: Parameters<ConflictResolver>[0],
  ctrl: Control,
): Promise<ConflictResolution> {
  ctrl.pendingConflicts += 1;
  ctrl.patch({ state: "waiting", stalled: false });
  try {
    const resolution = await abortable(resolver(info, ctrl.abort.signal), ctrl.abort.signal);
    ctrl.abort.signal.throwIfAborted();
    return resolution;
  } finally {
    ctrl.pendingConflicts -= 1;
    if (ctrl.pendingConflicts === 0) {
      // Time spent answering a prompt is not a network stall.
      ctrl.lastProgressAt = now();
      ctrl.patch({ state: "active", stalled: false });
    }
  }
}

const now = (): number => performance.now();
/** Coalesce store progress writes to ~10/sec so a fast (LAN) transfer doesn't
 *  re-render the whole queue per 32 KiB chunk. */
const PATCH_MS = 100;

/** Bumped on every cancelAll() (vault switch / lock) so an in-flight batch loop
 *  can notice teardown and stop enqueuing further items. */
let teardownGen = 0;
export const teardownGeneration = (): number => teardownGen;

/** Resolver used by the resume/retry buttons: never prompts — a destination
 *  that's already complete (same size) is skipped, a partial is resumed, else
 *  overwritten. */
const autoResume: ConflictResolver = async ({ resumable, sameSize }) => ({
  choice: sameSize ? "skip" : resumable ? "resume" : "overwrite",
  applyAll: true,
});

/** Resume-from-offset only works on the legs that actually seek/append in the
 *  core: upload (local→remote) and download (remote→local). The temp-hop and
 *  local→local copy paths can't resume, so we never offer/apply an offset there
 *  (doing so would re-transfer the whole file while inflating the progress). */
function legResumable(from: FileSource, to: FileSource): boolean {
  return (from.kind === "local" && to.kind === "remote") || (from.kind === "remote" && to.kind === "local");
}

/** Stream one file between two sources. Returns true if it completed, false if a
 *  cancel token fired (pause or cancel). */
async function fileLeg(
  from: FileSource,
  to: FileSource,
  fromPath: string,
  toPath: string,
  offset: number,
  knownSize: number | null,
  onProgress: (transferred: number, total: number) => void,
  ctrl: Control,
): Promise<boolean> {
  if (ctrl.abort.signal.aborted) return false;
  const cancelId = await api.cancelNew();
  ctrl.cancelIds.add(cancelId);
  try {
    if (ctrl.abort.signal.aborted) return false;
    if (from.kind === "local" && to.kind === "remote") {
      return await api.sftpUpload(
        to.id,
        fromPath,
        toPath,
        offset,
        (p) => onProgress(p.transferred, p.total),
        cancelId,
      );
    }
    if (from.kind === "remote" && to.kind === "local") {
      return await api.sftpDownload(
        from.id,
        fromPath,
        toPath,
        offset,
        knownSize,
        (p) => onProgress(p.transferred, p.total),
        cancelId,
      );
    }
    if (from.kind === "remote" && to.kind === "remote") {
      // No direct server→server relay in the core: hop through a local temp file.
      const tmp = await join(await tempDir(), `unissh-sftp-${cancelId}.part`);
      try {
        const down = await api.sftpDownload(
          from.id,
          fromPath,
          tmp,
          0,
          knownSize,
          (p) => onProgress(p.transferred, p.total * 2),
          cancelId,
        );
        if (!down || ctrl.abort.signal.aborted) return false;
        const cancelId2 = await api.cancelNew();
        ctrl.cancelIds.add(cancelId2);
        try {
          if (ctrl.abort.signal.aborted) return false;
          return await api.sftpUpload(
            to.id,
            tmp,
            toPath,
            0,
            (p) => onProgress(p.total + p.transferred, p.total * 2),
            cancelId2,
          );
        } finally {
          ctrl.cancelIds.delete(cancelId2);
          await api.cancelDispose(cancelId2).catch(() => {});
        }
      } finally {
        await remove(tmp).catch(() => {});
      }
    }
    // local → local
    await copyFile(fromPath, toPath);
    const s = await stat(toPath).catch(() => null);
    onProgress(s?.size ?? 0, s?.size ?? 0);
    return true;
  } finally {
    ctrl.cancelIds.delete(cancelId);
    await api.cancelDispose(cancelId).catch(() => {});
  }
}

async function ensureDir(src: FileSource, path: string): Promise<void> {
  await src.mkdir(path).catch(() => {
    /* already exists (or a parent does) — listing/transfer will surface real errors */
  });
}

/** Join a "/"-relative path onto a base, segment by segment, using the source's
 *  own path semantics (so local Windows separators stay correct). */
async function joinRel(src: FileSource, base: string, rel: string): Promise<string> {
  let p = base;
  for (const seg of rel.split("/").filter(Boolean)) p = await src.join(p, seg);
  return p;
}

async function runFile(
  t: Transfer,
  from: FileSource,
  to: FileSource,
  resolver: ConflictResolver,
  ctrl: Control,
  sem: Semaphore,
): Promise<void> {
  // Hold ONE semaphore permit for the whole stat→resolve→transfer sequence: this
  // caps concurrent single-file transfers in a batch to the pool size, and the
  // rest wait cheaply in the semaphore's JS queue rather than as blocked FFI
  // calls. The permit is the same shared limiter a folder transfer's legs use, so
  // a mixed batch never exceeds the pool globally.
  await sem.run(async () => {
    ctrl.patch({ state: "active" });
    let name = t.label;
    let toPath = await to.join(t.toDir, name);
    const target = await abortable(to.stat(toPath), ctrl.abort.signal);
    let offset = 0;

    if (target?.isDir) throw new Error(`"${name}" already exists as a folder`);
    if (target) {
      const resumable = canResume(target, t.bytesTotal) && legResumable(from, to);
      const res = await resolveConflict(resolver, {
        name,
        targetSize: target.size,
        sourceSize: t.bytesTotal,
        resumable,
        sameSize: target.size === t.bytesTotal,
      }, ctrl);
      if (res.choice === "skip") {
        ctrl.patch({ filesDone: 1, bytesDone: t.bytesTotal, bytesTotal: t.bytesTotal });
        return;
      }
      if (res.choice === "resume") offset = resumable ? target.size : 0;
      if (res.choice === "keepboth") {
        const listing = await abortable(to.list(t.toDir), ctrl.abort.signal);
        name = dedupeName(
          name,
          listing.map((e) => e.name),
        );
        toPath = await to.join(t.toDir, name);
        offset = 0;
      }
      // overwrite → offset stays 0
    }

    ctrl.patch({ state: "active", offset, label: name });
    ctrl.abort.signal.throwIfAborted();
    let previous = offset;
    let finalTotal = from.kind === "remote" && to.kind === "remote" ? t.bytesTotal * 2 : t.bytesTotal;
    ctrl.patch({ bytesDone: offset, bytesTotal: finalTotal });
    let lastPatch = 0;
    // Source size is known from the listing (remote → skip a per-file stat in core).
    const knownSize = from.kind === "remote" ? t.bytesTotal : null;
    const ok = await fileLeg(
      from,
      to,
      t.fromPath,
      toPath,
      offset,
      knownSize,
      (transferred, total) => {
        finalTotal = total > 0 ? total : finalTotal;
        const done = transferred; // core reports the absolute position (incl. offset)
        if (ctrl.abort.signal.aborted) return;
        ctrl.moved += Math.max(0, done - previous);
        if (done > previous) ctrl.lastProgressAt = now();
        previous = done;
        const ts = now();
        if (ts - lastPatch < PATCH_MS) return;
        lastPatch = ts;
        ctrl.patch({
          bytesDone: done,
          bytesTotal: finalTotal,
        });
      },
      ctrl,
    );
    if (!ok && !ctrl.abort.signal.aborted) throw new Error("Transfer interrupted");
    if (ok) ctrl.patch({ filesDone: 1, bytesDone: finalTotal });
  }, ctrl.abort.signal);
}

async function runDir(
  t: Transfer,
  from: FileSource,
  to: FileSource,
  resolver: ConflictResolver,
  ctrl: Control,
  sem: Semaphore,
): Promise<void> {

  // 1. Scan for honest totals. Sibling listings run concurrently (bounded by the
  //    shared semaphore) so a wide/deep tree doesn't stall on a serial prologue.
  if (ctrl.cancelled || ctrl.paused) return;
  const { dirs, files } = await collectTree(from, t.fromPath, sem, ctrl.abort.signal);
  if (ctrl.cancelled || ctrl.paused) return;
  const legs = from.kind === "remote" && to.kind === "remote" ? 2 : 1;
  const bytesTotal = files.reduce((a, f) => a + f.size * legs, 0);
  ctrl.patch({ state: "active", filesTotal: files.length, bytesTotal });

  // 2. Mirror the directory tree, parents before children. Each mkdir waits only
  //    on its parent's, so independent branches are created concurrently (bounded
  //    by the semaphore) instead of one round-trip at a time.
  const targetRoot = await to.join(t.toDir, t.label);
  ctrl.abort.signal.throwIfAborted();
  await ensureDir(to, targetRoot);
  const dirDone = new Map<string, Promise<void>>();
  dirDone.set("", Promise.resolve());
  for (const rel of dirs) {
    const cut = rel.lastIndexOf("/");
    const parent = dirDone.get(cut >= 0 ? rel.slice(0, cut) : "") ?? Promise.resolve();
    dirDone.set(
      rel,
      parent.then(async () => {
        if (ctrl.cancelled || ctrl.paused) return;
        await sem.run(async () => {
          const path = await joinRel(to, targetRoot, rel);
          ctrl.abort.signal.throwIfAborted();
          await ensureDir(to, path);
        }, ctrl.abort.signal);
      }),
    );
  }
  await settleWrites([...dirDone.values()], ctrl);
  if (ctrl.cancelled || ctrl.paused) return;

  // 3. Transfer files concurrently. Progress is aggregated across all in-flight
  //    legs: `bytesDone`/`filesDone` are shared counters (JS is single-threaded,
  //    so `+=` is race-free) patched at most ~10/s. Each file holds one semaphore
  //    permit for its whole stat→resolve→transfer sequence, so global concurrency
  //    (this transfer plus any others in the batch) never exceeds the pool size.
  let bytesDone = 0;
  let filesDone = 0;
  let lastPatch = 0;
  const bump = (delta: number, transferred = true): void => {
    if (delta <= 0 || ctrl.abort.signal.aborted) return;
    bytesDone += delta;
    if (transferred) {
      ctrl.moved += delta;
      ctrl.lastProgressAt = now();
    }
    const ts = now();
    if (ts - lastPatch < PATCH_MS) return;
    lastPatch = ts;
    ctrl.patch({
      bytesDone,
    });
  };

  const transferOne = async (it: WalkItem): Promise<boolean> => {
    if (ctrl.abort.signal.aborted) return false;
    let absTo = await joinRel(to, targetRoot, it.relPath);
    const absFrom = await joinRel(from, t.fromPath, it.relPath);
    const existing: Entry | null = await abortable(to.stat(absTo), ctrl.abort.signal);
    let offset = 0;
    if (existing && !existing.isDir) {
      // A collision: let the resolver decide (same-size files auto-skip under the
      // resume/retry resolver; the interactive one honours a standing apply-all).
      const resumable = canResume(existing, it.size) && legResumable(from, to);
      const res = await resolveConflict(resolver, {
        name: it.relPath,
        targetSize: existing.size,
        sourceSize: it.size,
        resumable,
        sameSize: existing.size === it.size,
      }, ctrl);
      if (res.choice === "skip") {
        filesDone += 1;
        bump(it.size * legs, false);
        ctrl.patch({ filesDone, bytesDone });
        return true;
      }
      if (res.choice === "keepboth") {
        const segs = it.relPath.split("/").filter(Boolean);
        const base = segs.pop() ?? it.relPath;
        const parentDir = segs.length ? await joinRel(to, targetRoot, segs.join("/")) : targetRoot;
        const listing = await abortable(to.list(parentDir), ctrl.abort.signal);
        absTo = await to.join(
          parentDir,
          dedupeName(
            base,
            listing.map((e) => e.name),
          ),
        );
        offset = 0;
      } else {
        offset = res.choice === "resume" && resumable ? existing.size : 0;
      }
    }
    // A resumed prefix already exists on the target — count it as done up front.
    if (offset > 0) bump(offset, false);
    let prev = offset; // last absolute position reported for THIS file
    const knownSize = from.kind === "remote" ? it.size : null;
    const ok = await fileLeg(
      from,
      to,
      absFrom,
      absTo,
      offset,
      knownSize,
      (transferred) => {
        bump(transferred - prev); // core reports absolute position; feed the delta
        prev = transferred;
      },
      ctrl,
    );
    if (!ok && !ctrl.abort.signal.aborted) throw new Error("Transfer interrupted");
    if (!ok) return false; // paused or cancelled mid-file
    if (it.size * legs > prev) bump(it.size * legs - prev, false); // true up if the last tick was short
    filesDone += 1;
    ctrl.patch({ filesDone, bytesDone });
    return true;
  };

  // Launch every file; the semaphore caps how many legs actually run at once. One
  // permit spans each file's stat→resolve→transfer so total in-flight ≤ pool size.
  await settleWrites(files.map((it) => sem.run(() => transferOne(it), ctrl.abort.signal)), ctrl);
}

/** Stop sibling legs on the first failure, but wait for writes to settle before
 * enabling retry. Otherwise an old leg can overwrite a new attempt. */
async function settleWrites(jobs: Promise<unknown>[], ctrl: Control): Promise<void> {
  let failure: unknown;
  let failed = false;
  await Promise.allSettled(jobs.map((job) => job.catch((error: unknown) => {
    if (!failed) { failed = true; failure = error; triggerAll(ctrl); }
  })));
  if (failed) throw failure;
}

/** How many files this transfer may move at once. A folder transfer draws its
 *  legs from `sem`; if the caller shares one `Semaphore` across a whole batch,
 *  the pool size is honoured globally. Standalone callers (resume/retry) pass a
 *  fresh semaphore sized to the current setting. */
export function makeTransferSemaphore(): Semaphore {
  return new Semaphore(useApp.getState().sftpParallelism);
}

/** Run a transfer to completion (or until paused/cancelled). Used for fresh
 *  drops (interactive `resolver`) and resume/retry (auto resolver). `sem` bounds
 *  concurrent file legs to the pool size; share it across a batch to cap globally. */
export async function startTransfer(
  t: Transfer,
  from: FileSource,
  to: FileSource,
  resolver: ConflictResolver,
  sem: Semaphore = makeTransferSemaphore(),
): Promise<void> {
  if (controls.has(t.id)) return;
  const { patchTransfer } = useApp.getState();
  const ctrl: Control = {
    paused: false, cancelled: false, cancelIds: new Set(), abort: new AbortController(),
    moved: 0, pendingConflicts: 0, lastProgressAt: now(),
    patch: (patch) => {
      if (controls.get(t.id) === ctrl && !ctrl.abort.signal.aborted) patchTransfer(t.id, patch);
    },
  };
  controls.set(t.id, ctrl);
  // A remote relay counts two network legs; preserve the original source size
  // so retry never mistakes that work total for the file size.
  t = { ...t, bytesTotal: t.sourceSize ?? t.bytesTotal };
  ctrl.patch({ state: t.kind === "dir" ? "scanning" : "queued", error: undefined,
    sourceSize: t.bytesTotal, bytesDone: 0, filesDone: 0, speedBps: 0, etaSec: Infinity, stalled: false });
  let spd = new Speedometer();
  spd.sample(0, now());
  const timer = setInterval(() => {
    const current = useApp.getState().transfers.find((x) => x.id === t.id);
    if (!current || ctrl.abort.signal.aborted) return;
    if (current.state !== "active" && current.state !== "waiting") {
      spd = new Speedometer();
      spd.sample(ctrl.moved, now());
      return;
    }
    spd.sample(ctrl.moved, now());
    ctrl.patch({
      speedBps: spd.speed(), etaSec: spd.eta(current.bytesTotal - current.bytesDone),
      stalled: current.state === "active" && now() - ctrl.lastProgressAt >= 5000,
    });
  }, 250);
  let failure: string | undefined;
  try {
    if (t.kind === "file") await runFile(t, from, to, resolver, ctrl, sem);
    else await runDir(t, from, to, resolver, ctrl, sem);
  } catch (e) {
    if (!ctrl.cancelled && !ctrl.paused) failure = apiErrorMessage(e);
    triggerAll(ctrl);
  } finally {
    clearInterval(timer);
    if (controls.get(t.id) === ctrl) {
      controls.delete(t.id);
      patchTransfer(t.id, { state: ctrl.cancelled ? "cancelled" : ctrl.paused ? "paused" : failure ? "error" : "done",
        error: failure, speedBps: 0, etaSec: 0, stalled: false });
    }
  }
}

export function pauseTransfer(id: string): void {
  const c = controls.get(id);
  if (!c || c.cancelled) return;
  useApp.getState().patchTransfer(id, { state: "pausing", speedBps: 0, etaSec: 0, stalled: false });
  c.paused = true;
  triggerAll(c);
}

export function cancelTransfer(id: string): void {
  const c = controls.get(id);
  if (c) {
    useApp.getState().patchTransfer(id, { state: "cancelling", speedBps: 0, etaSec: 0, stalled: false });
    c.cancelled = true;
    triggerAll(c);
  } else {
    // queued or already finished — just record the terminal state
    useApp.getState().patchTransfer(id, { state: "cancelled" });
  }
}

/** Abort every in-flight transfer — used by vault switch / lock teardown so a
 *  running copy doesn't outlive the state it was operating on. */
export function cancelAll(): void {
  teardownGen += 1;
  for (const c of controls.values()) {
    c.cancelled = true;
    triggerAll(c);
  }
}

/** Resume a paused transfer or retry a failed one — re-runs from its offset,
 *  resuming partials and overwriting otherwise, without prompting. */
export async function resumeTransfer(id: string): Promise<void> {
  const st = useApp.getState();
  const t = st.transfers.find((x) => x.id === id);
  if (!t || controls.has(id) || (t.state !== "paused" && t.state !== "error")) return;
  try {
    const from = sourceFor(t.from, st.sftpSessions);
    const to = sourceFor(t.to, st.sftpSessions);
    await startTransfer(t, from, to, autoResume);
  } catch (e) {
    st.patchTransfer(id, { state: "error", error: apiErrorMessage(e) });
  }
}

export const retryTransfer = resumeTransfer;
