// Transfer runner — drives a Transfer against the bridge and the store. Handles
// the four source/target combinations, live progress, cancel/pause/resume, and
// recursive directory transfers. Pure decisions live in transfer-engine.ts; this
// file is the imperative glue (bridge calls + store patches + cancel tokens).

import * as api from "@/bridge/api";
import { apiErrorMessage } from "@/bridge/types";
import { useApp } from "@/store/app";
import type { Entry, Transfer } from "@/store/sftp-types";
import { sourceFor, type FileSource } from "@/bridge/sources";
import { abortable, collectTree, emptiedDirs, isWithin, mapWorkers, Semaphore, Speedometer, type WalkItem } from "@/sftp/transfer-engine";
import { dedupeName } from "@/sftp/paths";
import { i18n } from "@/i18n";

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
  /** Move only: the source is gone, so there is nothing left to verify or redo. */
  removed?: boolean;
  /** Move only: the destination is the source itself under another path, or
   *  nothing proved that it is not. The source is never removed. When the two
   *  were positively shown to be one file the commit was withheld as well, so
   *  `completed` then only means "there is nothing left to do here". */
  aliased?: boolean;
  /** Move only: the destination that was replaced was proved to be another file
   *  — which includes that its directory is not the source's directory. */
  distinct?: boolean;
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
  /** Remove each source once its copy is committed at the destination. */
  move: boolean;
  /** Network legs per byte of file: a relay between two servers downloads and
   *  then uploads. The queue shows file bytes; only speed and ETA count legs. */
  legs: number;
  /** Move only: sources that arrived but could not be removed. They are
   *  reported when the transfer settles; none of them stops the others. */
  kept: string[];
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

/** Do `fromDir` on `from` and `toDir` on `to` name one directory? The two panes
 *  may show the same place — a bind mount or a network share of the server in
 *  the local pane, two sessions to one host — and no path comparison sees that.
 *  The one test that works for every pair of sources: an entry that exists in
 *  `toDir` under a random name is looked up in `fromDir`. `staged` names such
 *  an entry that is already there (a transfer's staged copy); without it an
 *  empty probe file is created in `toDir` and removed again.
 *
 *  The contract, which every caller's decision to delete rests on:
 *  - PRESENT is proof of one directory. Nothing else can put a 122-bit random
 *    name beside the source.
 *  - ABSENT is evidence of two directories, and weaker: a network mount that
 *    caches lookups may not show a new entry at once. It is enough to remove a
 *    source whose listing also differs from the destination's; it is not enough
 *    on its own when a remote side is involved (see sameFileVerdict).
 *  - A probe that could not be made or looked up proves nothing, and throws
 *    with the path it failed on; the caller keeps the source.
 *
 *  Two local directories are first compared by identity, which writes nothing:
 *  `local_same_file` opens both paths and compares device and inode (volume and
 *  file index on Windows, where the same-file crate opens with
 *  FILE_FLAG_BACKUP_SEMANTICS, so directories work there too). Only its "same"
 *  is taken. "Different" still runs the probe: one directory reached directly
 *  and through a network mount of this very machine has two device numbers.
 *
 *  `left` reports a probe that could not be removed again (path and reason).
 *  If the destination refuses, and the probe is visible from the source side,
 *  it is removed through that side: it is this call's own empty file. */
async function sharesDirectory(from: FileSource, fromDir: string, to: FileSource, toDir: string, staged?: string): Promise<{ shared: boolean; left?: string }> {
  if (staged === undefined && from.kind === "local" && to.kind === "local" && from.sameFile
    && await from.sameFile(fromDir, toDir).catch(() => false)) return { shared: true };
  const name = staged ?? `.unissh-${crypto.randomUUID()}.part`;
  const probe = await to.join(toDir, name);
  const mirror = await from.join(fromDir, name);
  if (staged === undefined) {
    await to.createNew(probe).catch((error: unknown) => { throw new Error(`${probe}: ${apiErrorMessage(error)}`); });
  }
  let seen: Entry | null = null;
  let failure: string | undefined;
  try {
    seen = await from.lstat(mirror);
  } catch (error) {
    failure = `${mirror}: ${apiErrorMessage(error)}`;
  }
  let left: string | undefined;
  if (staged === undefined) {
    let stuck = await to.remove(probe).then(() => undefined, (error: unknown) => error);
    if (stuck !== undefined && seen) stuck = await from.remove(mirror).then(() => undefined, () => stuck);
    if (stuck !== undefined) left = `${probe}: ${apiErrorMessage(stuck)}`;
  }
  if (failure !== undefined) {
    throw new Error(left === undefined ? failure : `${failure}; ${i18n.t("sftp.moveError.probeLeft", { detail: left })}`);
  }
  return { shared: seen !== null, left };
}

/** Move only, asked just before a staged copy replaces `plan.existing`: is the
 *  file about to be replaced the source itself, under another path? Once the
 *  commit has happened an aliased source IS the new file and passes every later
 *  check, so its removal would delete the only copy.
 *
 *  "same" — positively one file: two local paths with one file identity, or
 *  the staged copy showing up beside the source (sharesDirectory). The caller
 *  must not even commit: the file would only be replaced by a copy of itself,
 *  under a new inode and without its owner, group and special bits.
 *
 *  "distinct" — proved to be two files, and only then may the source go. The
 *  staged copy must NOT show up beside the source, and on top of that either
 *  - the two listings differ in size or modification time, or
 *  - both sides are local and file identity says they are two files. That is
 *    what lets "copy A to B, later move A onto B" finish: the two then agree in
 *    size and time down to the second.
 *
 *  "unknown" — everything else: equal size and time with a remote side
 *  involved (or with no usable identity). Equal listings prove nothing either
 *  way, the times are whole seconds, and the probe's absence alone is too weak
 *  there. The file is replaced as the user asked, and the source is kept.
 *
 *  Mode is deliberately not consulted: a local Windows mode is synthetic and
 *  never equals the remote one. Two hard links to one inode count as "same":
 *  replacing one would in fact leave the other intact, but identity cannot tell
 *  a second link from a second path to the same entry, so the move is refused
 *  rather than guessed at. */
async function sameFileVerdict(from: FileSource, to: FileSource, fromPath: string, source: Entry, plan: PlannedLeaf, stageName: string): Promise<"same" | "distinct" | "unknown"> {
  const existing = plan.existing;
  if (!existing) return "distinct";
  // Identity needs both files opened, which blocks on a FIFO and follows a link.
  const regular = (e: Entry): boolean => !e.isDir && !e.isSymlink && (e.mode === undefined || (e.mode & 0o170000) === 0o100000);
  let identity: boolean | undefined;
  if (from.kind === "local" && to.kind === "local" && from.sameFile && regular(source) && regular(existing)) {
    identity = await from.sameFile(fromPath, plan.path).then((same) => same, () => undefined);
  }
  if (identity) return "same";
  if ((await sharesDirectory(from, await from.parent(fromPath), to, await to.parent(plan.path), stageName)).shared) return "same";
  const sizesDiffer = source.sizeKnown !== false && existing.sizeKnown !== false && source.size !== existing.size;
  const timesDiffer = source.mtime !== undefined && existing.mtime !== undefined && source.mtime !== existing.mtime;
  return sizesDiffer || timesDiffer || identity === false ? "distinct" : "unknown";
}

/** Reject same-object and descendant copies at the shared entry point. */
async function validateTarget(t: Transfer, from: FileSource, to: FileSource): Promise<void> {
  if (from.kind !== to.kind || (from.identity ?? from.id) !== (to.identity ?? to.id)) return;
  const windows = !!from.windows;
  const name = t.fromPath.split(windows ? /[\\/]/ : /\//).pop()!;
  const source = t.isSymlink
    ? await from.join(await from.realpath(await from.parent(t.fromPath)), name)
    : await from.realpath(t.fromPath);
  const parent = await to.realpath(t.toDir);
  const target = await to.join(parent, t.label);
  const normalized = (p: string) => (windows ? p.replace(/\\/g, "/").toLowerCase() : p).replace(/\/+$/, "");
  const a = normalized(source), b = normalized(target);
  const verb = t.move ? "move" : "copy";
  if (a === b || (t.kind === "dir" && isWithin(a, b))) throw new Error(t.move ? i18n.t("sftp.moveError.intoItself") : "Cannot copy a path into itself");
  const existing = await to.lstat(target);
  if (existing && !t.isSymlink && !existing.isSymlink && (await to.realpath(target) === source || await from.sameFile?.(t.fromPath, target))) throw new Error(`Cannot ${verb} a file onto itself`);
}

/** The second half of a move, for one file. Its only callers are the places in
 *  transferLeaf where `plan.completed` is known to be true — the copy has been
 *  committed at the destination, or was withheld because the destination is the
 *  source itself (`plan.aliased`, which keeps the source) — so nothing that
 *  failed, was cancelled before its commit, or was skipped can reach it. `plan.completed` is only a memory of
 *  that commit, and a retry may come much later, so the copy is looked at again
 *  here. Never throws: a source that cannot be removed is a copy, which is
 *  reported but must not stop the other files. */
async function removeMovedSource(from: FileSource, to: FileSource, path: string, plan: PlannedLeaf, isSymlink: boolean, ctrl: Control): Promise<void> {
  // After pause/cancel nothing more is deleted; a resume picks this file up again.
  if (!ctrl.move || ctrl.abort.signal.aborted) return;
  try {
    // Removing a source that is the destination under another name removes the only copy.
    if (plan.aliased) throw new Error(i18n.t("sftp.moveError.sameFile"));
    // Whatever was written to the source after it was read exists nowhere else.
    if (!unchanged(plan.source ?? null, await from.lstat(path))) throw new Error(i18n.t("sftp.moveError.sourceChanged"));
    const landed = await to.lstat(plan.path);
    const intact = landed !== null && (isSymlink
      ? !!landed.isSymlink
      : !landed.isDir && !landed.isSymlink && landed.sizeKnown !== false && landed.size === plan.source?.size);
    if (!intact) throw new Error(i18n.t("sftp.moveError.destinationMissing"));
    await (isSymlink ? from.unlink(path) : from.remove(path));
    plan.removed = true;
  } catch (error) {
    ctrl.kept.push(`${path}: ${apiErrorMessage(error)}`);
  }
}

/** A move inside one session needs no copy: rename the entry into place. Returns
 *  false when that is not possible, and the caller moves it the long way (copy,
 *  then remove the source) — a rename across filesystems fails on every platform,
 *  and a folder landing on an existing folder is a per-file merge. A rename that
 *  failed for any other reason fails the move: the source decides which is
 *  which (FileSource.renameNeedsCopy). Never
 *  replaces a destination the user was not asked about. */
async function renameInPlace(t: Transfer, src: FileSource, resolver: ConflictResolver, ctrl: Control): Promise<boolean> {
  ctrl.patch({ state: "active" });
  let target = await src.join(t.toDir, t.label);
  const existing = await abortable(src.lstat(target), ctrl.abort.signal);
  if (existing && (t.kind === "dir" || existing.isDir)) return false;
  let replace = false;
  if (existing) {
    const res = await resolveConflict(resolver, {
      name: t.label, targetSize: existing.size, sourceSize: t.bytesTotal, resumable: false,
      sameSize: !t.isSymlink && !existing.isSymlink && existing.size === t.bytesTotal,
    }, ctrl);
    if (res.choice === "skip") {
      ctrl.patch({ filesDone: 1, bytesDone: t.bytesTotal });
      return true;
    }
    if (res.choice === "keepboth") {
      const listing = await abortable(src.list(t.toDir), ctrl.abort.signal);
      t.label = await availableName(src, t.toDir, t.label, listing.map((e) => e.name), ctrl);
      target = await src.join(t.toDir, t.label);
    } else replace = true;
  }
  ctrl.abort.signal.throwIfAborted();
  reserve(src, target, ctrl);
  if (replace && !unchanged(existing, await abortable(src.lstat(target), ctrl.abort.signal))) throw new Error("Destination changed after the conflict decision");
  try {
    // commit(…, false) publishes only onto a free name. A directory cannot be
    // hard-linked locally, so it takes the plain rename after the check above.
    if (t.kind === "dir") await src.rename(t.fromPath, target);
    else await src.commit(t.fromPath, target, replace);
  } catch (error) {
    // A pause or cancel is not a refused rename: nothing more may start.
    if (ctrl.abort.signal.aborted) throw error;
    if (!src.renameNeedsCopy(error, t.kind === "file" && !replace)) throw error;
    // Carry the decision over, so the copy path does not ask a second time.
    if (t.kind === "file") ctrl.manifest.set(t.fromPath, { path: target, existing: replace ? existing : null, completed: false });
    return false;
  }
  ctrl.patch({ label: t.label, filesDone: 1, bytesDone: t.bytesTotal });
  return true;
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
  if (plan.removed) return true;
  const source = await from.lstat(fromPath);
  if (!source) throw new Error("Source no longer exists");
  if (plan.completed) {
    if (!plan.skipped && plan.source && !unchanged(plan.source, source)) throw new Error("Source changed since the previous attempt");
    // A retry of a move whose copy landed but whose source was left behind.
    if (!plan.skipped) await removeMovedSource(from, to, fromPath, plan, isSymlink, ctrl);
    return true;
  }
  if (!isSymlink && (source.fileKind === "unknown" || source.fileKind === "unsupported" || source.isDir || (source.mode && (source.mode & 0o170000) !== 0o100000))) throw new Error("Source is not a regular file");
  reserve(to, plan.path, ctrl);
  const parent = await to.parent(plan.path);
  const stageName = `.unissh-${crypto.randomUUID()}.part`;
  const stage = await to.join(parent, stageName);
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
    // Decided here, while the staged copy still sits beside the destination.
    if (ctrl.move && plan.existing) {
      const verdict = await sameFileVerdict(from, to, fromPath, source, plan, stageName);
      if (verdict === "same") {
        // Proved to be the source itself: it is left exactly as it is. Nothing
        // is committed; the staged copy is dropped on the way out.
        plan.aliased = true;
        plan.completed = true;
        plan.source = source;
        await removeMovedSource(from, to, fromPath, plan, isSymlink, ctrl);
        return true;
      }
      if (verdict === "distinct") plan.distinct = true;
      else plan.aliased = true;
    }
    ctrl.abort.signal.throwIfAborted();
    if (plan.existing && !unchanged(plan.existing, await to.lstat(plan.path))) throw new Error("Destination changed after the conflict decision");
    await to.commit(stage, plan.path, plan.existing !== null);
    created = false;
    plan.completed = true;
    plan.source = source;
    await removeMovedSource(from, to, fromPath, plan, isSymlink, ctrl);
    return true;
  } finally {
    if (created) await (isSymlink ? to.unlink(stage) : to.remove(stage)).catch(() => {});
  }
}

/** Make sure `path` is a directory. Resolves true when this call created it,
 *  false when it was already there. */
async function ensureDir(src: FileSource, path: string): Promise<boolean> {
  return src.mkdir(path).then(() => true, async (error: unknown) => {
    // Only an existing directory is harmless. A swallowed mkdir failure made
    // later file writes fail with an unrelated, context-free SFTP status 4.
    const existing = await src.lstat(path).catch(() => null);
    if (!existing?.isDir || existing.isSymlink) throw new Error(`${path}: ${apiErrorMessage(error)}`);
    return false;
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
    let finalTotal = t.bytesTotal;
    ctrl.patch({ bytesDone: offset, bytesTotal: finalTotal });
    let lastPatch = 0;
    // Source size is known from the listing (remote → skip a per-file stat in core).
    const ok = await transferLeaf(from, to, t.fromPath, saved!, !!t.isSymlink, t.bytesTotal, ctrl,
      (transferred, total) => {
        // A relay reports both of its legs; the row shows the file once.
        finalTotal = Math.floor(total / ctrl.legs);
        const done = transferred; // core reports the absolute position (incl. offset)
        if (ctrl.abort.signal.aborted) return;
        ctrl.moved += Math.max(0, done - previous);
        if (done > previous) ctrl.lastProgressAt = now();
        previous = done;
        const ts = now();
        if (ts - lastPatch < PATCH_MS) return;
        lastPatch = ts;
        ctrl.patch({
          bytesDone: Math.floor(done / ctrl.legs),
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
  const legs = ctrl.legs;
  const bytesTotal = files.reduce((a, f) => a + f.size, 0);
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
  // Move only: a destination directory this run created is a new directory, so
  // it cannot be the source directory under another path. Step 4 relies on it.
  const fresh = new Set<string>();
  if (await ensureDir(to, targetRoot)) fresh.add("");
  const byDepth = new Map<number, string[]>();
  for (const rel of dirs) {
    const depth = rel.split("/").length;
    const group = byDepth.get(depth) ?? [];
    group.push(rel); byDepth.set(depth, group);
  }
  for (const group of byDepth.values()) {
    await mapWorkers(group, sem.capacity, (rel) => sem.run(async () => {
      const path = await targetPath(rel);
      ctrl.abort.signal.throwIfAborted();
      if (await ensureDir(to, path)) fresh.add(rel);
    }, ctrl.abort.signal), ctrl.abort.signal);
  }
  if (ctrl.cancelled || ctrl.paused) return;

  // 3. Prepare destinations, resolve conflicts, then transfer files. Aggregate
  //    progress across concurrent legs, coalescing byte updates to ~10/s.
  //    `bytesDone` counts network legs, as the core reports them; the row shows
  //    file bytes, so a relayed folder is not twice its size.
  let bytesDone = 0;
  let filesDone = 0;
  let lastPatch = 0;
  const shown = (): number => Math.floor(bytesDone / legs);
  const publishProgress = (): void => {
    const ts = now();
    if (ts - lastPatch < PATCH_MS) return;
    lastPatch = ts;
    ctrl.patch({ bytesDone: shown(), filesDone });
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
  const prepared = await mapWorkers(files, sem.capacity, (it) => sem.run(async () => {
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
  ctrl.patch({ state: "active", bytesDone: shown(), filesDone });

  const transferOne = async ({ it }: typeof plan[number]): Promise<boolean> => {
    if (ctrl.abort.signal.aborted) return false;
    const absFrom = await sourcePath(it.relPath);
    const saved = ctrl.manifest.get(it.relPath)!;
    let prev = 0;
    const alreadyComplete = saved.completed;
    const ok = await transferLeaf(from, to, absFrom, saved, !!it.isSymlink, it.size, ctrl, (transferred) => {
      bump(transferred - prev);
      prev = transferred;
    });
    if (!ok && !ctrl.abort.signal.aborted) throw new Error("Transfer interrupted");
    if (ok) {
      if (alreadyComplete) bump((saved.source?.size ?? it.size) * legs, false);
      filesDone += 1; publishProgress();
    }
    return ok;
  };

  // Each file holds a shared semaphore permit until its write settles, so
  // concurrent file legs across this batch never exceed the pool size.
  await mapWorkers(plan, sem.capacity, (file) => sem.run(() => transferOne(file).catch((error: unknown) => {
    triggerAll(ctrl);
    throw new Error(`${file.it.relPath}: ${apiErrorMessage(error)}`);
  }), ctrl.abort.signal), ctrl.abort.signal);
  // 4. Move only: drop the source directories that are now empty, children
  //    before parents — unless one may BE its destination directory (see
  //    sharesDirectory for how that happens). Files are guarded one by one in
  //    transferLeaf and an aliased file keeps its folder, but a folder without
  //    files has no such guard, and removing it would remove the very folder
  //    that was just "moved" into place. So a source directory goes only when
  //    its destination is proved to be another directory:
  //    - one this run created is new;
  //    - one from which a file was moved over an existing file that was proved
  //      distinct has been through the very same probe already (`distinct`; a
  //      file that merely landed on a free name proves nothing about its
  //      folder — "keep both" lands beside its own source);
  //    - any other is probed now. A probe that fails proves nothing, and one
  //      that could not be removed again is reason enough to touch nothing
  //      else there: either way the directory stays, and the row says why,
  //      naming the destination path it happened on.
  //    Probed before the metadata pass, which restores the times a probe
  //    disturbs.
  const stayed = files.filter((file) => !ctrl.manifest.get(file.relPath)?.removed).map((file) => file.relPath);
  const unproven = new Map<string, string>();
  if (ctrl.move) {
    const proven = new Set<string>();
    for (const file of files) {
      const leaf = ctrl.manifest.get(file.relPath);
      if (leaf?.removed && leaf.distinct) proven.add(file.relPath.slice(0, Math.max(0, file.relPath.lastIndexOf("/"))));
    }
    const merged = emptiedDirs(dirs, stayed).filter((rel) => !fresh.has(rel) && !proven.has(rel));
    await mapWorkers(merged, sem.capacity, (rel) => sem.run(async () => {
      try {
        const { shared, left } = await sharesDirectory(from, await sourcePath(rel), to, await targetPath(rel));
        const why = [
          ...(shared ? [i18n.t("sftp.moveError.sameFolder")] : []),
          ...(left === undefined ? [] : [i18n.t("sftp.moveError.probeLeft", { detail: left })]),
        ];
        if (why.length) unproven.set(rel, why.join("; "));
      } catch (error) {
        unproven.set(rel, i18n.t("sftp.moveError.folderUnchecked", { detail: apiErrorMessage(error) }));
      }
    }, ctrl.abort.signal), ctrl.abort.signal);
  }
  for (const group of [...byDepth.values()].reverse()) {
    await mapWorkers(group, sem.capacity, (rel) => sem.run(async () => {
      const metadata = directoryMetadata.get(rel)!;
      await to.setMetadata(await targetPath(rel), metadata.mode, metadata.mtime);
    }, ctrl.abort.signal), ctrl.abort.signal);
  }
  if (rootMetadata) await to.setMetadata(targetRoot, rootMetadata.mode, rootMetadata.mtime);

  // Each removal is non-recursive, so a directory that still holds anything —
  // a skipped file, one that could not be removed, or one that appeared
  // meanwhile — refuses and stays, along with its parents.
  if (ctrl.move) {
    for (const [rel, why] of unproven) ctrl.kept.push(`${await sourcePath(rel)}: ${why}`);
    const stuck: string[] = [];
    for (const rel of emptiedDirs(dirs, [...stayed, ...unproven.keys()])) {
      if (ctrl.abort.signal.aborted) break;
      if (stuck.some((child) => rel === "" || isWithin(rel, child))) continue;
      const path = await sourcePath(rel);
      await from.removeEmptyDir(path).catch((error: unknown) => {
        stuck.push(rel);
        ctrl.kept.push(`${path}: ${apiErrorMessage(error)}`);
      });
    }
  }
  ctrl.patch({ filesDone, bytesDone: shown(), bytesTotal: shown() });
}

/** How many files this transfer may move at once. A folder transfer draws its
 *  legs from `sem`; if the caller shares one `Semaphore` across a whole batch,
 *  the pool size is honoured globally. Standalone callers (resume/retry) pass a
 *  fresh semaphore sized to the current setting. */
let sharedSemaphore: Semaphore | undefined;
let sharedCapacity = 0;
/** The one budget for everything that uses the session's SFTP channels: transfers and read-only walks alike. */
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
    moved: 0, pendingConflicts: 0, lastProgressAt: now(), move: !!t.move, kept: [],
    legs: from.kind === "remote" && to.kind === "remote" ? 2 : 1,
    patch: (patch) => {
      if (controls.get(t.id) === ctrl && !ctrl.abort.signal.aborted) patchTransfer(t.id, patch);
    },
  };
  controls.set(t.id, ctrl);
  manifests.set(t.id, ctrl.manifest);
  // The total in the store follows what the core reports while a file runs;
  // a retry starts again from the size the listing gave.
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
      speedBps: spd.speed(), etaSec: spd.eta((current.bytesTotal - current.bytesDone) * ctrl.legs),
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
    // A saved plan means the copy path already started: finish it that way.
    // Keyed on the session `id`, not `identity`: a rename is one request on one
    // SFTP channel, and two sessions to the same host are still two channels.
    const renamed = ctrl.move && ctrl.manifest.size === 0 && from.kind === to.kind && from.id === to.id
      && await renameInPlace(t, from, resolver, ctrl);
    if (renamed) { /* moved without copying */ }
    else if (t.kind === "file") await runFile(t, from, to, resolver, ctrl, sem);
    else await runDir(t, from, to, resolver, ctrl, sem);
    if (ctrl.kept.length) {
      failure = ctrl.kept.length > 1
        ? i18n.t("sftp.moveError.keptMore", { detail: ctrl.kept[0], more: ctrl.kept.length - 1 })
        : i18n.t("sftp.moveError.kept", { detail: ctrl.kept[0] });
    }
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

/** Release retained retry state when its queue row is dismissed. */
export function forgetTransfer(id: string): void {
  if (!controls.has(id)) manifests.delete(id);
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
