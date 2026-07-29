// Transfer runner — drives a Transfer against the bridge and the store. Handles
// the four source/target combinations, live progress, cancel/pause/resume, and
// recursive directory transfers. Pure decisions live in transfer-engine.ts; this
// file is the imperative glue (bridge calls + store patches + cancel tokens).

import * as api from "@/bridge/api";
import { apiErrorMessage } from "@/bridge/types";
import { useApp } from "@/store/app";
import type { Entry, Transfer } from "@/store/sftp-types";
import { sourceFor, type FileSource } from "@/bridge/sources";
import { canResume, collectTree, Semaphore, Speedometer, type WalkItem } from "@/sftp/transfer-engine";
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
}) => Promise<ConflictResolution>;

interface Control {
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
  for (const cid of ctrl.cancelIds) api.cancelTrigger(cid).catch(() => {});
}

/** Serialize a resolver so at most one conflict prompt is pending at a time:
 *  parallel file legs would otherwise race the single conflict dialog. Once the
 *  user picks "apply to all", the underlying resolver returns synchronously, so
 *  this adds no latency to the common case. */
export function serializeResolver(r: ConflictResolver): ConflictResolver {
  let tail: Promise<unknown> = Promise.resolve();
  return (info) => {
    const result = tail.then(() => r(info));
    tail = result.catch(() => undefined);
    return result;
  };
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
  if (ctrl.cancelled || ctrl.paused) return false;
  const cancelId = await api.cancelNew();
  ctrl.cancelIds.add(cancelId);
  try {
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
        if (!down) return false;
        const cancelId2 = await api.cancelNew();
        ctrl.cancelIds.add(cancelId2);
        try {
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
  spd: Speedometer,
  sem: Semaphore,
): Promise<void> {
  const { patchTransfer } = useApp.getState();
  // Hold ONE semaphore permit for the whole stat→resolve→transfer sequence: this
  // caps concurrent single-file transfers in a batch to the pool size, and the
  // rest wait cheaply in the semaphore's JS queue rather than as blocked FFI
  // calls. The permit is the same shared limiter a folder transfer's legs use, so
  // a mixed batch never exceeds the pool globally.
  await sem.run(async () => {
    let name = t.label;
    let toPath = await to.join(t.toDir, name);
    const target = await to.stat(toPath);
    let offset = 0;

    if (target?.isDir) throw new Error(`"${name}" already exists as a folder`);
    if (target) {
      const resumable = canResume(target, t.bytesTotal) && legResumable(from, to);
      const res = await resolver({
        name,
        targetSize: target.size,
        sourceSize: t.bytesTotal,
        resumable,
        sameSize: target.size === t.bytesTotal,
      });
      if (res.choice === "skip") {
        patchTransfer(t.id, { filesDone: 1, bytesDone: t.bytesTotal });
        return;
      }
      if (res.choice === "resume") offset = resumable ? target.size : 0;
      if (res.choice === "keepboth") {
        const listing = await to.list(t.toDir);
        name = dedupeName(
          name,
          listing.map((e) => e.name),
        );
        toPath = await to.join(t.toDir, name);
        offset = 0;
      }
      // overwrite → offset stays 0
    }

    patchTransfer(t.id, { state: "active", offset, label: name });
    let finalTotal = t.bytesTotal;
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
        spd.sample(done, now());
        const ts = now();
        if (ts - lastPatch < PATCH_MS) return;
        lastPatch = ts;
        patchTransfer(t.id, {
          bytesDone: done,
          bytesTotal: finalTotal,
          speedBps: spd.speed(),
          etaSec: spd.eta(Math.max(0, finalTotal - done)),
        });
      },
      ctrl,
    );
    if (ok) patchTransfer(t.id, { filesDone: 1, bytesDone: finalTotal });
  });
}

async function runDir(
  t: Transfer,
  from: FileSource,
  to: FileSource,
  resolver: ConflictResolver,
  ctrl: Control,
  spd: Speedometer,
  sem: Semaphore,
): Promise<void> {
  const { patchTransfer } = useApp.getState();

  // 1. Scan for honest totals. Sibling listings run concurrently (bounded by the
  //    shared semaphore) so a wide/deep tree doesn't stall on a serial prologue.
  if (ctrl.cancelled || ctrl.paused) return;
  const { dirs, files } = await collectTree(from, t.fromPath, sem);
  if (ctrl.cancelled || ctrl.paused) return;
  const bytesTotal = files.reduce((a, f) => a + f.size, 0);
  patchTransfer(t.id, { state: "active", filesTotal: files.length, bytesTotal });

  // 2. Mirror the directory tree, parents before children. Each mkdir waits only
  //    on its parent's, so independent branches are created concurrently (bounded
  //    by the semaphore) instead of one round-trip at a time.
  const targetRoot = await to.join(t.toDir, t.label);
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
        await sem.run(async () => ensureDir(to, await joinRel(to, targetRoot, rel)));
      }),
    );
  }
  await Promise.all(dirDone.values());
  if (ctrl.cancelled || ctrl.paused) return;

  // 3. Transfer files concurrently. Progress is aggregated across all in-flight
  //    legs: `bytesDone`/`filesDone` are shared counters (JS is single-threaded,
  //    so `+=` is race-free) patched at most ~10/s. Each file holds one semaphore
  //    permit for its whole stat→resolve→transfer sequence, so global concurrency
  //    (this transfer plus any others in the batch) never exceeds the pool size.
  let bytesDone = 0;
  let filesDone = 0;
  let lastPatch = 0;
  const bump = (delta: number): void => {
    if (delta <= 0) return;
    bytesDone += delta;
    spd.sample(bytesDone, now());
    const ts = now();
    if (ts - lastPatch < PATCH_MS) return;
    lastPatch = ts;
    patchTransfer(t.id, {
      bytesDone,
      speedBps: spd.speed(),
      etaSec: spd.eta(Math.max(0, bytesTotal - bytesDone)),
    });
  };

  const transferOne = async (it: WalkItem): Promise<boolean> => {
    if (ctrl.cancelled || ctrl.paused) return false;
    let absTo = await joinRel(to, targetRoot, it.relPath);
    const absFrom = await joinRel(from, t.fromPath, it.relPath);
    const existing: Entry | null = await to.stat(absTo);
    let offset = 0;
    if (existing && !existing.isDir) {
      // A collision: let the resolver decide (same-size files auto-skip under the
      // resume/retry resolver; the interactive one honours a standing apply-all).
      const resumable = canResume(existing, it.size) && legResumable(from, to);
      const res = await resolver({
        name: it.relPath,
        targetSize: existing.size,
        sourceSize: it.size,
        resumable,
        sameSize: existing.size === it.size,
      });
      if (res.choice === "skip") {
        filesDone += 1;
        bump(it.size);
        patchTransfer(t.id, { filesDone, bytesDone });
        return true;
      }
      if (res.choice === "keepboth") {
        const segs = it.relPath.split("/").filter(Boolean);
        const base = segs.pop() ?? it.relPath;
        const parentDir = segs.length ? await joinRel(to, targetRoot, segs.join("/")) : targetRoot;
        const listing = await to.list(parentDir);
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
    if (offset > 0) bump(offset);
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
    if (!ok) return false; // paused or cancelled mid-file
    if (it.size > prev) bump(it.size - prev); // true up if the last tick was short
    filesDone += 1;
    patchTransfer(t.id, { filesDone, bytesDone });
    return true;
  };

  // Launch every file; the semaphore caps how many legs actually run at once. One
  // permit spans each file's stat→resolve→transfer so total in-flight ≤ pool size.
  await Promise.all(files.map((it) => sem.run(() => transferOne(it))));
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
  const { patchTransfer } = useApp.getState();
  const ctrl: Control = { paused: false, cancelled: false, cancelIds: new Set() };
  controls.set(t.id, ctrl);
  patchTransfer(t.id, { state: t.kind === "dir" ? "scanning" : "active", error: undefined });
  const spd = new Speedometer();
  try {
    if (t.kind === "file") await runFile(t, from, to, resolver, ctrl, spd, sem);
    else await runDir(t, from, to, resolver, ctrl, spd, sem);
    if (ctrl.cancelled) patchTransfer(t.id, { state: "cancelled", speedBps: 0, etaSec: 0 });
    else if (ctrl.paused) patchTransfer(t.id, { state: "paused", speedBps: 0, etaSec: 0 });
    else patchTransfer(t.id, { state: "done", speedBps: 0, etaSec: 0 });
  } catch (e) {
    patchTransfer(t.id, { state: "error", error: apiErrorMessage(e), speedBps: 0, etaSec: 0 });
  } finally {
    controls.delete(t.id);
  }
}

export function pauseTransfer(id: string): void {
  const c = controls.get(id);
  if (!c) return;
  c.paused = true;
  triggerAll(c);
}

export function cancelTransfer(id: string): void {
  const c = controls.get(id);
  if (c) {
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
  if (!t) return;
  try {
    const from = sourceFor(t.from, st.sftpSessions);
    const to = sourceFor(t.to, st.sftpSessions);
    await startTransfer(t, from, to, autoResume);
  } catch (e) {
    st.patchTransfer(id, { state: "error", error: apiErrorMessage(e) });
  }
}

export const retryTransfer = resumeTransfer;
