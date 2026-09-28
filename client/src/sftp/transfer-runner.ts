// Transfer runner — drives a Transfer against the bridge and the store. Handles
// the four source/target combinations, live progress, cancel/pause/resume, and
// recursive directory transfers. Pure decisions live in transfer-engine.ts; this
// file is the imperative glue (bridge calls + store patches + cancel tokens).

import * as api from "@/bridge/api";
import { apiErrorMessage } from "@/bridge/types";
import { useApp } from "@/store/app";
import type { Entry, Transfer } from "@/store/sftp-types";
import { sourceFor, type FileSource } from "@/bridge/sources";
import { abortable, collectTree, mapWorkers, Semaphore, Speedometer, type WalkItem } from "@/sftp/transfer-engine";
import { dedupeName } from "@/sftp/paths";

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

interface PlannedLeaf {
  path: string;
  existing: Entry | null;
  completed: boolean;
  skipped?: boolean;
  source?: Entry;
}
const manifests = new Map<string, Map<string, PlannedLeaf>>();
const reservedPaths = new Map<string, string>();
const destinationKey = (source: FileSource, path: string): string => `${source.kind}:${source.identity ?? source.id}:${path.normalize("NFC").toLowerCase()}`;

interface Control {
  id: string;
  manifest: Map<string, PlannedLeaf>;
  tick?: (current: Transfer) => Partial<Transfer> | undefined;
  abort: AbortController;
  moved: number;
  pendingConflicts: number;
  lastProgressAt: number;
  patch: (patch: Partial<Transfer>) => void;
  paused: boolean;
  cancelled: boolean;
  /** One native flag covers every file in this transfer. Keep it alive until
   * all writes settle; creating/discarding a token per file adds two IPCs. */
  cancelId?: string;
  cancelToken?: Promise<string>;
}
const controls = new Map<string, Control>();

/** Abort planning and trigger the shared native token (pause or cancel). */
function triggerAll(ctrl: Control): void {
  ctrl.abort.abort();
  if (ctrl.cancelId) api.cancelTrigger(ctrl.cancelId).catch(() => {});
}

/** Serialize a resolver so at most one conflict prompt is pending at a time:
 *  parallel file legs would otherwise race the single conflict dialog. Once the
 *  user picks "apply to all", the underlying resolver returns synchronously, so
 *  this adds no latency to the common case. */
let conflictTail: Promise<unknown> = Promise.resolve();
export function serializeResolver(r: ConflictResolver): ConflictResolver {
  return (info, signal) => {
    const result = conflictTail.then(() => {
      signal?.throwIfAborted();
      return abortable(r(info, signal), signal);
    });
    conflictTail = result.catch(() => undefined);
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
  // Retry decisions are automatic and per-file; they never open a dialog.
  if (resolver === autoResume) return resolver(info, ctrl.abort.signal);
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

/** Retry can only execute a saved decision. Unknown conflicts need a new prompt. */
const autoResume: ConflictResolver = async () => { throw new Error("The transfer plan is unavailable. Start a new transfer to resolve conflicts."); };

function reserve(to: FileSource, path: string, ctrl: Control): void {
  const key = destinationKey(to, path);
  const owner = reservedPaths.get(key);
  if (owner && owner !== ctrl.id) throw new Error("Another transfer is writing this destination");
  reservedPaths.set(key, ctrl.id);
}

async function availableName(to: FileSource, parent: string, name: string, names: Iterable<string>, ctrl: Control): Promise<string> {
  const taken = new Set(names);
  taken.add(name);
  while (true) {
    const candidate = dedupeName(name, taken);
    const path = await to.join(parent, candidate);
    const key = destinationKey(to, path);
    if (!reservedPaths.has(key)) { reservedPaths.set(key, ctrl.id); return candidate; }
    taken.add(candidate);
  }
}

function unchanged(a: Entry | null, b: Entry | null): boolean {
  return a === null ? b === null : b !== null && a.size === b.size && a.mtime === b.mtime && a.mode === b.mode
    && !!a.isSymlink === !!b.isSymlink && a.isDir === b.isDir;
}

/** Reject same-object and descendant copies at the shared entry point. */
async function validateTarget(t: Transfer, from: FileSource, to: FileSource): Promise<void> {
  if (from.kind !== to.kind || (from.identity ?? from.id) !== (to.identity ?? to.id)) return;
  const source = await from.realpath(t.fromPath);
  const parent = await to.realpath(t.toDir);
  const target = await to.join(parent, t.label);
  const normalized = (p: string) => p.replace(/\\/g, "/").replace(/\/+$/, "");
  const a = normalized(source), b = normalized(target);
  if (a === b || (t.kind === "dir" && b.startsWith(`${a}/`))) throw new Error("Cannot copy a path into itself");
  const existing = await to.lstat(target);
  if (existing && !existing.isSymlink && await to.realpath(target) === source) throw new Error("Cannot copy a file onto itself");
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
  ctrl.cancelToken ??= api.cancelNew().then((id) => {
    ctrl.cancelId = id;
    return id;
  });
  const cancelId = await ctrl.cancelToken;
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
    return api.sftpRelay(from.id, to.id, fromPath, toPath,
      (p) => onProgress(p.transferred, p.total), cancelId);
  }
  // local → local
  const size = await api.localCopyPrepared(fromPath, toPath);
  onProgress(size, size);
  return true;
}

/** Build a sibling completely, then publish it atomically. A failed write or
 * unsupported symlink never removes the user's previous destination. */
async function transferLeaf(
  from: FileSource, to: FileSource, fromPath: string, plan: PlannedLeaf,
  isSymlink: boolean, size: number, ctrl: Control,
  progress: (done: number, total: number) => void,
): Promise<boolean> {
  const source = await from.lstat(fromPath);
  if (!source) throw new Error("Source no longer exists");
  if (plan.completed) {
    if (!plan.skipped && plan.source && !unchanged(plan.source, source)) throw new Error("Source changed since the previous attempt");
    return true;
  }
  if (!isSymlink && (source.fileKind === "unknown" || source.fileKind === "unsupported" || source.isDir || (source.mode && (source.mode & 0o170000) !== 0o100000))) throw new Error("Source is not a regular file");
  reserve(to, plan.path, ctrl);
  const parent = await to.parent(plan.path);
  const stage = await to.join(parent, `.unissh-${crypto.randomUUID()}.part`);
  let created = false;
  try {
    ctrl.abort.signal.throwIfAborted();
    if (isSymlink) {
      const target = await from.readlink(fromPath);
      const dir = to.kind === "local" ? (await from.stat(fromPath).catch(() => null))?.isDir ?? false : false;
      await to.symlink(target, stage, dir);
      created = true;
    } else {
      await to.createNew(stage);
      created = true;
      if (!await fileLeg(from, to, fromPath, stage, 0, size, progress, ctrl)) return false;
      const after = await from.lstat(fromPath);
      if (!unchanged(source, after)) throw new Error("Source changed during transfer");
      await to.setMetadata(stage, source.mode, source.mtime);
    }
    ctrl.abort.signal.throwIfAborted();
    if (plan.existing && !unchanged(plan.existing, await to.lstat(plan.path))) throw new Error("Destination changed after the conflict decision");
    await to.commit(stage, plan.path, plan.existing !== null);
    created = false;
    plan.completed = true;
    plan.source = source;
    return true;
  } finally {
    if (created) await (isSymlink ? to.unlink(stage) : to.remove(stage)).catch(() => {});
  }
}

async function ensureDir(src: FileSource, path: string): Promise<void> {
  await src.mkdir(path).catch(async (error: unknown) => {
    // Only an existing directory is harmless. A swallowed mkdir failure made
    // later file writes fail with an unrelated, context-free SFTP status 4.
    const existing = await src.lstat(path).catch(() => null);
    if (!existing?.isDir || existing.isSymlink) throw new Error(`${path}: ${apiErrorMessage(error)}`);
  });
}

/** Resolve each parent once, retaining native Windows path semantics. */
function treePaths(src: FileSource, root: string): (rel: string) => Promise<string> {
  const paths = new Map<string, Promise<string>>([["", Promise.resolve(root)]]);
  const resolve = (rel: string): Promise<string> => {
    let path = paths.get(rel);
    if (!path) {
      const cut = rel.lastIndexOf("/");
      path = resolve(cut < 0 ? "" : rel.slice(0, cut)).then((parent) => src.join(parent, rel.slice(cut + 1)));
      paths.set(rel, path);
    }
    return path;
  };
  return resolve;
}

async function runFile(
  t: Transfer,
  from: FileSource,
  to: FileSource,
  resolver: ConflictResolver,
  ctrl: Control,
  sem: Semaphore,
): Promise<void> {
    ctrl.patch({ state: "active" });
    let name = t.label;
    let toPath = await to.join(t.toDir, name);
    let saved = ctrl.manifest.get(t.fromPath);
    if (saved?.completed) {
      if (!saved.skipped) await transferLeaf(from, to, t.fromPath, saved, !!t.isSymlink, t.bytesTotal, ctrl, () => {});
      ctrl.patch({ filesDone: 1, bytesDone: t.bytesTotal }); return;
    }
    if (saved) toPath = saved.path;
    const target = await sem.run(() => abortable(to.lstat(toPath), ctrl.abort.signal), ctrl.abort.signal);
    let replaceTarget = target;
    let offset = 0;

    if (target?.isDir) throw new Error(`"${name}" already exists as a folder`);
    if (target && !saved) {
      const resumable = false;
      const res = await resolveConflict(resolver, {
        name,
        targetSize: target.size,
        sourceSize: t.bytesTotal,
        resumable,
        sameSize: !t.isSymlink && !target.isSymlink && target.size === t.bytesTotal,
      }, ctrl);
      if (res.choice === "skip") {
        ctrl.manifest.set(t.fromPath, { path: toPath, existing: target, completed: true, skipped: true });
        ctrl.patch({ filesDone: 1, bytesDone: t.bytesTotal, bytesTotal: t.bytesTotal });
        return;
      }
      if (res.choice === "resume") offset = resumable ? target.size : 0;
      if (res.choice === "keepboth") {
        const listing = await abortable(to.list(t.toDir), ctrl.abort.signal);
        name = await availableName(to, t.toDir, name, listing.map((e) => e.name), ctrl);
        toPath = await to.join(t.toDir, name);
        replaceTarget = null;
        offset = 0;
      }
      // overwrite → offset stays 0
    }

    ctrl.patch({ state: "active", offset, label: name });
    ctrl.abort.signal.throwIfAborted();
    saved ??= { path: toPath, existing: replaceTarget, completed: false };
    reserve(to, saved.path, ctrl);
    ctrl.manifest.set(t.fromPath, saved);
    await sem.run(async () => {
    let previous = offset;
    let finalTotal = from.kind === "remote" && to.kind === "remote" ? t.bytesTotal * 2 : t.bytesTotal;
    ctrl.patch({ bytesDone: offset, bytesTotal: finalTotal });
    let lastPatch = 0;
    // Source size is known from the listing (remote → skip a per-file stat in core).
    const ok = await transferLeaf(from, to, t.fromPath, saved!, !!t.isSymlink, t.bytesTotal, ctrl,
      (transferred, total) => {
        finalTotal = total;
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
  const { dirs, files, directoryMetadata } = await collectTree(from, t.fromPath, sem, ctrl.abort.signal);
  if (ctrl.cancelled || ctrl.paused) return;
  const legs = from.kind === "remote" && to.kind === "remote" ? 2 : 1;
  const bytesTotal = files.reduce((a, f) => a + f.size * legs, 0);
  ctrl.patch({ state: "active", filesTotal: files.length, bytesTotal });

  // 2. Mirror the directory tree, parents before children. Each mkdir waits only
  //    on its parent's, so independent branches are created concurrently (bounded
  //    by the semaphore) instead of one round-trip at a time.
  const dirAliases = new Set<string>();
  for (const dir of dirs) {
    const folded = dir.normalize("NFC").toLowerCase();
    if (dirAliases.has(folded)) throw new Error(`Directory names may alias on the destination: ${dir}`);
    dirAliases.add(folded);
  }
  const rootMetadata = await from.lstat(t.fromPath);
  const targetRoot = await to.join(t.toDir, t.label);
  const sourcePath = treePaths(from, t.fromPath);
  const targetPath = treePaths(to, targetRoot);
  ctrl.abort.signal.throwIfAborted();
  await ensureDir(to, targetRoot);
  const byDepth = new Map<number, string[]>();
  for (const rel of dirs) {
    const depth = rel.split("/").length;
    const group = byDepth.get(depth) ?? [];
    group.push(rel); byDepth.set(depth, group);
  }
  for (const group of byDepth.values()) {
    await mapWorkers(group, 8, (rel) => sem.run(async () => {
      const path = await targetPath(rel);
      ctrl.abort.signal.throwIfAborted();
      await ensureDir(to, path);
    }, ctrl.abort.signal), ctrl.abort.signal);
  }
  if (ctrl.cancelled || ctrl.paused) return;

  // 3. Prepare destinations, resolve conflicts, then transfer files. Aggregate
  //    progress across concurrent legs, coalescing byte updates to ~10/s.
  let bytesDone = 0;
  let filesDone = 0;
  let lastPatch = 0;
  const publishProgress = (): void => {
    const ts = now();
    if (ts - lastPatch < PATCH_MS) return;
    lastPatch = ts;
    ctrl.patch({ bytesDone, filesDone });
  };
  const bump = (delta: number, transferred = true): void => {
    if (delta <= 0 || ctrl.abort.signal.aborted) return;
    bytesDone += delta;
    if (transferred) {
      ctrl.moved += delta;
      ctrl.lastProgressAt = now();
    }
    publishProgress();
  };

  // Read each destination directory once, instead of one SFTP STAT round trip
  // per file. Fall back to stat when a server allows writes but denies listing.
  const listings = new Map<string, Promise<Map<string, Entry> | null>>();
  const foldedNames = new Map<string, Set<string>>();
  const foldName = (name: string): string => name.normalize("NFC").toLowerCase();
  const listingFor = (parent: string): Promise<Map<string, Entry> | null> => {
    let pending = listings.get(parent);
    if (!pending) {
      pending = abortable(to.list(parent), ctrl.abort.signal)
        .then((entries) => {
          foldedNames.set(parent, new Set(entries.map((entry) => foldName(entry.name))));
          return new Map(entries.map((entry) => [entry.name, entry]));
        })
        .catch(() => { ctrl.abort.signal.throwIfAborted(); return null; });
      listings.set(parent, pending);
    }
    return pending;
  };
  const prepared = await mapWorkers(files, 8, (it) => sem.run(async () => {
    const cut = it.relPath.lastIndexOf("/");
    const name = it.relPath.slice(cut + 1);
    const parent = await targetPath(cut < 0 ? "" : it.relPath.slice(0, cut));
    const absTo = await targetPath(it.relPath);
    const entries = await listingFor(parent);
    let existing = entries?.get(name) ?? null;
    // Preserve link metadata; never follow it when deciding what to replace.
    // Local filesystems may also alias names by case or Unicode normalization.
    const regular = existing?.mode !== undefined && (existing.mode & 0o170000) === 0o100000;
    const possibleAlias = !existing && foldedNames.get(parent)?.has(foldName(name));
    if (!entries || to.kind === "local" || possibleAlias || (existing && !existing.isDir && !regular)) {
      existing = await abortable(to.lstat(absTo), ctrl.abort.signal);
    }
    if (existing?.isDir) throw new Error(`"${it.relPath}" already exists as a folder`);
    return { it, name, parent, absTo, entries, existing };
  }, ctrl.abort.signal), ctrl.abort.signal);

  // Reserve incoming names too: "keep both" must not pick the name of another
  // file in this batch that has not been written yet.
  const reserved = new Map<string, Set<string>>();
  for (const file of prepared) {
    let names = reserved.get(file.parent);
    if (!names) {
      names = new Set(file.entries?.keys());
      reserved.set(file.parent, names);
    }
    names.add(file.name);
  }
  const plan: { it: WalkItem; absTo: string; offset: number; replaceTarget: Entry | null }[] = [];
  const plannedPaths = new Set<string>();
  let allConflicts: ConflictResolution | undefined;
  // Settle every conflict BEFORE starting file writes. Previously one leg could
  // fail and abort a sibling's dialog while the user was choosing an action.
  for (const file of prepared) {
    ctrl.abort.signal.throwIfAborted();
    const { it, existing } = file;
    let { absTo } = file;
    let replaceTarget = existing;
    let offset = 0;
    const saved = ctrl.manifest.get(it.relPath);
    if (saved) {
      plan.push({ it, absTo: saved.path, offset: 0, replaceTarget: saved.existing });
      continue;
    }
    if (existing) {
      const resumable = false;
      // The batch resolver also remembers apply-all across top-level transfers.
      // Cache it here to avoid toggling waiting/active and synchronously rendering
      // the queue twice for every remaining file in this folder.
      const res = allConflicts ?? await resolveConflict(resolver, {
        name: it.relPath, targetSize: existing.size, sourceSize: it.size,
        resumable, sameSize: !it.isSymlink && !existing.isSymlink && existing.size === it.size,
      }, ctrl);
      if (res.applyAll) allConflicts = res;
      if (res.choice === "skip") {
        ctrl.manifest.set(it.relPath, { path: absTo, existing, completed: true, skipped: true });
        filesDone += 1;
        bump(it.size * legs, false);
        continue;
      }
      if (res.choice === "keepboth") {
        const names = reserved.get(file.parent)!;
        // A failed listing still needs a fresh listing for safe name allocation.
        if (!file.entries) {
          for (const entry of await abortable(to.list(file.parent), ctrl.abort.signal)) names.add(entry.name);
        }
        const name = await availableName(to, file.parent, file.name, names, ctrl);
        names.add(name);
        absTo = await to.join(file.parent, name);
        replaceTarget = null;
      } else {
        offset = res.choice === "resume" && resumable ? existing.size : 0;
      }
    }
    // Conservatively separate incoming case/Unicode aliases, even on an
    // endpoint whose case rules are unknown.
    if (plannedPaths.has(destinationKey(to, absTo))) {
      const name = await availableName(to, file.parent, file.name, reserved.get(file.parent)!, ctrl);
      reserved.get(file.parent)!.add(name);
      absTo = await to.join(file.parent, name);
      replaceTarget = null;
    }
    plannedPaths.add(destinationKey(to, absTo));
    reserve(to, absTo, ctrl);
    ctrl.manifest.set(it.relPath, { path: absTo, existing: replaceTarget, completed: false });
    plan.push({ it, absTo, offset, replaceTarget });
  }
  ctrl.patch({ state: "active", bytesDone, filesDone });

  const transferOne = async ({ it }: typeof plan[number]): Promise<boolean> => {
    if (ctrl.abort.signal.aborted) return false;
    const absFrom = await sourcePath(it.relPath);
    const saved = ctrl.manifest.get(it.relPath)!;
    let prev = 0;
    const ok = await transferLeaf(from, to, absFrom, saved, !!it.isSymlink, it.size, ctrl, (transferred) => {
      bump(transferred - prev);
      prev = transferred;
    });
    if (!ok && !ctrl.abort.signal.aborted) throw new Error("Transfer interrupted");
    if (ok) { filesDone += 1; publishProgress(); }
    return ok;
  };

  // Each file holds a shared semaphore permit until its write settles, so
  // concurrent file legs across this batch never exceed the pool size.
  await mapWorkers(plan, 8, (file) => sem.run(() => transferOne(file).catch((error: unknown) => {
    triggerAll(ctrl);
    throw new Error(`${file.it.relPath}: ${apiErrorMessage(error)}`);
  }), ctrl.abort.signal), ctrl.abort.signal);
  for (const group of [...byDepth.values()].reverse()) {
    await mapWorkers(group, 8, (rel) => sem.run(async () => {
      const metadata = directoryMetadata.get(rel)!;
      await to.setMetadata(await targetPath(rel), metadata.mode, metadata.mtime);
    }, ctrl.abort.signal), ctrl.abort.signal);
  }
  if (rootMetadata) await to.setMetadata(targetRoot, rootMetadata.mode, rootMetadata.mtime);
  ctrl.patch({ filesDone, bytesDone, bytesTotal: bytesDone });
}

/** How many files this transfer may move at once. A folder transfer draws its
 *  legs from `sem`; if the caller shares one `Semaphore` across a whole batch,
 *  the pool size is honoured globally. Standalone callers (resume/retry) pass a
 *  fresh semaphore sized to the current setting. */
let sharedSemaphore: Semaphore | undefined;
let sharedCapacity = 0;
export function makeTransferSemaphore(): Semaphore {
  const capacity = useApp.getState().sftpParallelism;
  if (!sharedSemaphore || (controls.size === 0 && capacity !== sharedCapacity)) {
    sharedCapacity = capacity; sharedSemaphore = new Semaphore(capacity);
  }
  return sharedSemaphore;
}
let progressTimer: ReturnType<typeof setInterval> | undefined;
function scheduleProgress(): void {
  progressTimer ??= setInterval(() => {
    const state = useApp.getState();
    const patches = new Map<string, Partial<Transfer>>();
    for (const transfer of state.transfers) {
      const patch = controls.get(transfer.id)?.tick?.(transfer);
      if (patch) patches.set(transfer.id, patch);
    }
    if (patches.size) state.patchTransfers(patches);
  }, 250);
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
    id: t.id, manifest: manifests.get(t.id) ?? new Map(),
    paused: false, cancelled: false, abort: new AbortController(),
    moved: 0, pendingConflicts: 0, lastProgressAt: now(),
    patch: (patch) => {
      if (controls.get(t.id) === ctrl && !ctrl.abort.signal.aborted) patchTransfer(t.id, patch);
    },
  };
  controls.set(t.id, ctrl);
  manifests.set(t.id, ctrl.manifest);
  // A remote relay counts two network legs; preserve the original source size
  // so retry never mistakes that work total for the file size.
  t = { ...t, bytesTotal: t.isSymlink ? 0 : t.sourceSize ?? t.bytesTotal };
  ctrl.patch({ state: t.kind === "dir" ? "scanning" : "queued", error: undefined,
    sourceSize: t.bytesTotal, bytesDone: 0, filesDone: 0, speedBps: 0, etaSec: Infinity, stalled: false });
  let spd = new Speedometer();
  spd.sample(0, now());
  ctrl.tick = (current) => {
    if (!current || ctrl.abort.signal.aborted) return;
    if (current.state !== "active" && current.state !== "waiting") {
      spd = new Speedometer();
      spd.sample(ctrl.moved, now());
      return;
    }
    spd.sample(ctrl.moved, now());
    return {
      speedBps: spd.speed(), etaSec: spd.eta(current.bytesTotal - current.bytesDone),
      stalled: current.state === "active" && now() - ctrl.lastProgressAt >= 5000,
    };
  };
  scheduleProgress();
  let failure: string | undefined;
  try {
    await validateTarget(t, from, to);
    if (from.withCancelToken || to.withCancelToken) {
      ctrl.cancelToken = api.cancelNew().then((id) => { ctrl.cancelId = id; return id; });
      const token = await ctrl.cancelToken;
      ctrl.abort.signal.throwIfAborted();
      from = from.withCancelToken?.(token) ?? from;
      to = to.withCancelToken?.(token) ?? to;
    }
    if (t.kind === "file") await runFile(t, from, to, resolver, ctrl, sem);
    else await runDir(t, from, to, resolver, ctrl, sem);
  } catch (e) {
    if (!ctrl.cancelled && !ctrl.paused) failure = apiErrorMessage(e);
    triggerAll(ctrl);
  } finally {
    ctrl.tick = undefined;
    if (ctrl.cancelId) await api.cancelDispose(ctrl.cancelId).catch(() => {});
    if (controls.get(t.id) === ctrl) {
      controls.delete(t.id);
      if (controls.size === 0) { clearInterval(progressTimer); progressTimer = undefined; }
      for (const [path, owner] of reservedPaths) if (owner === t.id) reservedPaths.delete(path);
      if (ctrl.cancelled || (!ctrl.paused && !failure)) manifests.delete(t.id);
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
  manifests.clear();
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
