// External-editor sessions: a remote file is copied to a private local scratch
// directory, handed to whatever the OS opens it with, and pushed back on every
// save until the user stops watching it.
//
// Why polling and not a filesystem watcher: editors save atomically (write a
// temp file, rename over the target), so an inode watch dies silently after the
// first save and a directory watch has to debounce a burst of events. Two
// identical (size, mtime) readings 500ms apart tell us the same thing, cost
// nothing at this scale — one or two files, never a tree — and need no new
// dependency. `SETTLE_TICKS` is what makes a half-written file wait.
//
// Desktop only. There is nothing on a phone to open the copy with.

import { create } from "zustand";
import { mkdir, remove, stat } from "@tauri-apps/plugin-fs";
import { join, tempDir } from "@tauri-apps/api/path";
import { openPath } from "@tauri-apps/plugin-opener";
import * as api from "@/bridge/api";
import { apiErrorMessage } from "@/bridge/types";
import { toast } from "@/store/toast";
import { tDyn } from "@/i18n";
import type { FileSource } from "@/bridge/sources";
import { dedupeName, remoteParent } from "@/sftp/paths";

/** How often we look at the local copy. */
const POLL_MS = 500;
/** Consecutive identical readings before a change counts as "the editor is done". */
const SETTLE_TICKS = 2;
/** Consecutive readings where the copy is missing before we give up on it. Not
 *  every editor renames over the target — some unlink and recreate, which leaves
 *  a real window where the path does not exist. */
const MAX_MISSES = 6;

export type EditState = "watching" | "uploading" | "conflict" | "error";

/** A (size, mtime) pair — the whole of what we compare. */
interface Stamp {
  size: number;
  mtime: number;
}

export interface LiveEdit {
  id: string;
  /** SFTP session the file belongs to. */
  sessionId: string;
  remotePath: string;
  /** The edit's own scratch directory — removed whole when the edit stops. */
  localDir: string;
  localPath: string;
  name: string;
  state: EditState;
  /** The remote file as we last knew it — set on download, refreshed on upload.
   *  A remote stamp that no longer matches this is somebody else's write.
   *  `undefined` means we could not read it: unknown, not unchanged. */
  base?: Stamp;
  /** The local copy as of the last upload. A difference is an unsaved edit. */
  local: Stamp;
  /** Candidate local stamp, waiting to repeat before we trust it. */
  settling?: Stamp & { ticks: number };
  /** Consecutive ticks that could not see the copy at all. */
  misses?: number;
  /** Host the file belongs to. A reconnect mints a new session id, so this is
   *  what lets an orphaned edit find its way back to a live session. */
  profileId: string;
  /** Size of the last upload, kept when the post-upload stat failed: the remote
   *  file is ours and therefore that long, which is enough to re-derive a
   *  baseline instead of writing blind. */
  expectSize?: number;
  /** Successful pushes so far — the only progress this feature has to show. */
  saves: number;
  /** One of our own failures, as a translation key under `sftp.extEdit.err`. */
  errorKey?: "localGone" | "sessionClosed" | "checkFailed";
  /** A message from the bridge, already human-readable and already localised as
   *  far as it ever will be. */
  error?: string;
}

/** What the row shows for a failed edit. */
export const editErrorText = (edit: LiveEdit): string | undefined =>
  edit.errorKey ? tDyn(`sftp.extEdit.err.${edit.errorKey}`) : edit.error;

interface EditStore {
  edits: LiveEdit[];
}

export const useExternalEdits = create<EditStore>(() => ({ edits: [] }));

const setEdits = (fn: (edits: LiveEdit[]) => LiveEdit[]) =>
  useExternalEdits.setState((s) => ({ edits: fn(s.edits) }));

const patch = (id: string, p: Partial<LiveEdit>) =>
  setEdits((edits) => edits.map((e) => (e.id === id ? { ...e, ...p } : e)));

const find = (id: string): LiveEdit | undefined => useExternalEdits.getState().edits.find((e) => e.id === id);

// Crypto-free, like the transfer ids: crypto.randomUUID throws in a webview that
// isn't a secure context, and an id that throws would strand the whole edit.
let editSeq = 0;
/** `sessionId\0remotePath` of every edit whose download is still in flight. */
const starting = new Set<string>();

/** The scratch root. NOT under $APPLOCALDATA: the fs plugin's default permission
 *  set pulls in `deny-webview-data-linux`, whose `$APPLOCALDATA/**` deny has no
 *  platform key and so applies everywhere — and a deny beats any allow, which
 *  would make every operation here fail with "path forbidden". */
const scratchRoot = async (): Promise<string> => join(await tempDir(), "unissh-external-edit");

/** `<temp>/unissh-external-edit/<n>` — one directory per edit, so two files with
 *  the same basename can't collide, and stopping one edit can remove its
 *  directory whole. */
async function scratchDir(id: string): Promise<string> {
  const root = await scratchRoot();
  // 0700: the copy is the remote file in the clear, and this is the one place
  // it exists unencrypted. Ignored on Windows, where the profile is already
  // per-user.
  await mkdir(root, { recursive: true, mode: 0o700 });
  const dir = await join(root, id);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  return dir;
}

async function localStamp(path: string): Promise<Stamp | null> {
  try {
    const s = await stat(path);
    return { size: s.size, mtime: s.mtime ? s.mtime.getTime() : 0 };
  } catch {
    return null;
  }
}

async function remoteStamp(source: FileSource, path: string): Promise<Stamp | null> {
  const e = await source.stat(path);
  return e ? { size: e.size, mtime: (e.mtime ?? 0) * 1000 } : null;
}

const same = (a: Stamp, b: Stamp): boolean => a.size === b.size && a.mtime === b.mtime;

/**
 * Does `path` really not exist, or did we merely fail to look?
 *
 * `FileSource.stat` answers null to both, and the difference decides whether a
 * save may proceed: a deleted file should be re-created, an unreadable one must
 * not be overwritten blind. Listing the parent separates them — it throws on a
 * transport failure instead of shrugging.
 */
async function confirmedAbsent(source: FileSource, path: string): Promise<boolean> {
  const dir = remoteParent(path);
  const name = path.slice(dir === "/" ? 1 : dir.length + 1);
  const entries = await source.list(dir);
  return !entries.some((e) => e.name === name);
}

/** What a tick concluded about one edit. */
export type SettleStep =
  /** Nothing to do: the copy still matches what we last uploaded. */
  | { action: "none" }
  /** It moved and moved back — drop the candidate. */
  | { action: "clear" }
  /** Changed, but not yet stable enough to trust. */
  | { action: "wait"; settling: Stamp & { ticks: number } }
  /** The same change has now been seen SETTLE_TICKS times: the editor is done. */
  | { action: "push" };

/**
 * The whole watch policy, as a pure function of the three stamps involved.
 *
 * Kept out of the tick so it can be reasoned about (and tested) without a
 * filesystem: everything subtle about this feature — the write-then-rename save,
 * the still-streaming large file, the editor that touches and reverts — is a
 * question about this transition table, not about I/O.
 */
export function settleStep(
  uploaded: Stamp,
  settling: (Stamp & { ticks: number }) | undefined,
  now: Stamp,
): SettleStep {
  if (same(now, uploaded)) return settling ? { action: "clear" } : { action: "none" };
  // A different reading restarts the count: the file is still being written.
  if (!settling || !same(settling, now)) return { action: "wait", settling: { ...now, ticks: 1 } };
  const ticks = settling.ticks + 1;
  return ticks >= SETTLE_TICKS ? { action: "push" } : { action: "wait", settling: { ...now, ticks } };
}

/**
 * Copy `remotePath` down, open it with the OS, and watch it until stopped.
 *
 * @param source the remote file's source — used for stat and for the copy check
 * @returns the new edit's id, or null if it could not be started
 */
export async function startExternalEdit(
  source: FileSource,
  sessionId: string,
  profileId: string,
  remotePath: string,
  name: string,
): Promise<string | null> {
  const existing = useExternalEdits
    .getState()
    .edits.find((e) => e.sessionId === sessionId && e.remotePath === remotePath);
  if (existing) {
    // Already open — bring the editor forward rather than making a second copy
    // that would race the first one on save.
    await openPath(existing.localPath);
    return existing.id;
  }
  // The store check above cannot see an edit whose download is still running,
  // and a big file makes that window minutes long — during which a second click
  // would start a rival copy of the same file. Claim the path up front.
  const claim = `${sessionId}\u0000${remotePath}`;
  if (starting.has(claim)) return null;
  starting.add(claim);

  const id = `ee${++editSeq}`;
  const dir = await scratchDir(id);
  try {
    const localPath = await join(dir, name);
    await api.sftpDownload(sessionId, remotePath, localPath, 0, null, () => {});

    // Both stamps are the baselines every later decision is measured against.
    // A sentinel here would be a lie the first save pays for: a bogus conflict
    // (remote) or an immediate pointless re-upload (local). Fail the open
    // instead — nothing has been handed to an editor yet, so nothing is lost.
    const base = await remoteStamp(source, remotePath);
    const local = await localStamp(localPath);
    if (!base || !local) throw new Error(tDyn("sftp.extEdit.err.openFailed"));

    setEdits((edits) => [
      ...edits,
        {
        id,
        sessionId,
        profileId,
        remotePath,
        localDir: dir,
        localPath,
        name,
        state: "watching",
        base,
        local,
        saves: 0,
      },
    ]);
    ensurePolling();
    await openPath(localPath);
    return id;
  } catch (e) {
    // A half-written copy is still the remote file in the clear. Take the
    // directory with us rather than leaving it for the next launch to purge.
    await remove(dir, { recursive: true }).catch(() => {});
    throw e;
  } finally {
    starting.delete(claim);
  }
}

/** Put an errored edit back under watch. The local copy is untouched, so this
 *  simply resumes: the next tick sees the unsaved change and pushes it. */
export function retryExternalEdit(id: string): void {
  const edit = find(id);
  if (!edit || edit.state !== "error") return;
  patch(id, { state: "watching", error: undefined, errorKey: undefined, misses: 0 });
  ensurePolling();
}

/** Stop watching and delete the local copy. */
export async function stopExternalEdit(id: string): Promise<void> {
  const edit = find(id);
  setEdits((edits) => edits.filter((e) => e.id !== id));
  stopPollingIfIdle();
  if (!edit) return;
  try {
    // The whole directory: the editor may have left backups (`file~`, `.swp`)
    // beside our copy, and those hold the same plaintext.
    await remove(edit.localDir, { recursive: true });
  } catch {
    /* best effort — a copy we cannot delete is still better reported than thrown */
  }
}

/** Stop everything and remove the scratch root. For app shutdown. */
export async function stopAllExternalEdits(): Promise<void> {
  const ids = useExternalEdits.getState().edits.map((e) => e.id);
  for (const id of ids) await stopExternalEdit(id);
  await purgeExternalEditScratch();
}

/** Delete the scratch root outright. Safe at startup — an edit only exists while
 *  the app that made it is running, so anything on disk is a leftover. */
export async function purgeExternalEditScratch(): Promise<void> {
  try {
    await remove(await scratchRoot(), { recursive: true });
  } catch {
    /* nothing to remove */
  }
}

export type ConflictChoice = "overwrite" | "copy" | "cancel";

/**
 * Answer a `conflict` state.
 *
 * `copy` re-points the edit at a free name beside the original, so every later
 * save follows the copy instead of repeatedly asking about a file the user has
 * already decided not to touch.
 */
export async function resolveConflict(id: string, choice: ConflictChoice, source: FileSource): Promise<void> {
  const edit = find(id);
  if (!edit || edit.state !== "conflict") return;
  if (choice === "cancel") {
    // Adopt the current local stamp as the baseline: the edit the user declined
    // to push must not re-trigger the prompt on the next tick.
    const local = (await localStamp(edit.localPath)) ?? edit.local;
    const base = await remoteStamp(source, edit.remotePath);
    patch(id, { state: "watching", local, base: base ?? undefined });
    return;
  }
  if (choice === "copy") {
    const dir = remoteParent(edit.remotePath);
    const taken = (await source.list(dir)).map((e) => e.name);
    const copyName = dedupeName(edit.name, taken);
    patch(id, { remotePath: await source.join(dir, copyName), name: copyName });
  }
  await push(id, source, true);
}

/** Upload the local copy over the remote file. */
async function push(id: string, source: FileSource, force: boolean): Promise<void> {
  const edit = find(id);
  if (!edit) return;
  patch(id, { state: "uploading" });
  try {
    if (!force) {
      const now = await remoteStamp(source, edit.remotePath);
      if (!now) {
        // Could not read it, and it is still listed: refuse rather than
        // overwrite a file whose state we do not know. Genuinely gone is fine —
        // re-creating it is what saving means.
        if (!(await confirmedAbsent(source, edit.remotePath))) {
          patch(id, { state: "error", errorKey: "checkFailed" });
          announce(edit, "checkFailed");
          return;
        }
      } else if (edit.base) {
        if (!same(now, edit.base)) {
          patch(id, { state: "conflict" });
          announce(edit, "conflict");
          return;
        }
      } else if (now.size !== edit.expectSize) {
        // No baseline — the stat after our own upload failed. The remote file
        // is still ours, and ours was exactly `expectSize` long, so a different
        // size is somebody else's write. Same length, and we have nothing to go
        // on but the fact that we wrote it: adopt it and move on.
        patch(id, { state: "conflict" });
        announce(edit, "conflict");
        return;
      }
    }
    // Snapshot BEFORE the upload: what we are about to send is this state, not
    // whatever the file looks like when the upload finishes. Reading it after
    // would adopt a save made mid-upload as already-sent and silently drop it.
    const sent = (await localStamp(edit.localPath)) ?? edit.local;
    await api.sftpUpload(edit.sessionId, edit.localPath, edit.remotePath, 0, () => {});
    const current = find(id);
    if (!current) return; // stopped mid-upload
    // Deliberately not falling back to the old baseline: it describes the file
    // as it was BEFORE our upload, so keeping it would make the next save report
    // a conflict against our own write. Unknown is the honest value, and the
    // guard skips a baseline it does not have.
    const base = await remoteStamp(source, current.remotePath);
    patch(id, {
      state: "watching",
      local: sent,
      base: base ?? undefined,
      expectSize: sent.size,
      saves: current.saves + 1,
      error: undefined,
      errorKey: undefined,
      settling: undefined,
      misses: 0,
    });
  } catch (e) {
    patch(id, { state: "error", error: apiErrorMessage(e), errorKey: undefined });
    const current = find(id);
    if (current) toast(tDyn("sftp.extEdit.pushFailed", { name: current.name }), "err");
  }
}

/** Say it out loud. The list lives on the SFTP route, and a save that stopped
 *  reaching the server is not something to discover by navigating back. */
function announce(edit: LiveEdit, what: "conflict" | "checkFailed"): void {
  toast(
    what === "conflict"
      ? tDyn("sftp.extEdit.conflictToast", { name: edit.name })
      : tDyn("sftp.extEdit.err.checkFailed"),
    "warn",
  );
}

// ── the tick ───────────────────────────────────────────────────
// One timer for every edit: a handful of stats twice a second is cheaper than a
// timer each, and it keeps start/stop in one place.

let timer: ReturnType<typeof setInterval> | null = null;
/** A live session for an edit, which may not be the one it started on: a
 *  reconnect mints a new id, so the resolver matches on the host as well and
 *  reports which session it actually found. Set by the view — sessions live in
 *  the app store. */
export interface ResolvedSession {
  source: FileSource;
  sessionId: string;
}
let resolveSource: ((sessionId: string, profileId: string) => ResolvedSession | null) | null = null;

export function setSourceResolver(fn: (sessionId: string, profileId: string) => ResolvedSession | null): void {
  resolveSource = fn;
}

/** Stop the poll without touching the copies — for locking the vault, where
 *  deleting a file the user still has open in an editor would destroy work. */
export function suspendExternalEdits(): void {
  if (timer !== null) {
    clearInterval(timer);
    timer = null;
  }
}

/** Resume after an unlock. */
export function resumeExternalEdits(): void {
  if (useExternalEdits.getState().edits.length > 0) ensurePolling();
}

function ensurePolling(): void {
  if (timer !== null) return;
  timer = setInterval(() => void tick(), POLL_MS);
}

function stopPollingIfIdle(): void {
  if (timer !== null && useExternalEdits.getState().edits.length === 0) {
    clearInterval(timer);
    timer = null;
  }
}

/** A tick can outlast its interval — every step here is an IPC round trip — and
 *  two overlapping passes would each see the same edit as `watching` and start
 *  their own upload of it. */
let ticking = false;

async function tick(): Promise<void> {
  if (ticking) return;
  ticking = true;
  try {
    await tickOnce();
  } finally {
    ticking = false;
  }
}

async function tickOnce(): Promise<void> {
  for (const edit of useExternalEdits.getState().edits) {
    if (edit.state !== "watching") continue;
    const now = await localStamp(edit.localPath);
    if (!now) {
      // Not necessarily gone: an editor that unlinks and recreates instead of
      // renaming leaves a real gap here. Only give up once it persists.
      const misses = (edit.misses ?? 0) + 1;
      if (misses < MAX_MISSES) patch(edit.id, { misses });
      else {
        patch(edit.id, { state: "error", errorKey: "localGone" });
        toast(tDyn("sftp.extEdit.err.localGone"), "err");
      }
      continue;
    }
    if (edit.misses) patch(edit.id, { misses: 0 });
    const step = settleStep(edit.local, edit.settling, now);
    if (step.action === "none") continue;
    if (step.action === "clear") {
      patch(edit.id, { settling: undefined });
      continue;
    }
    if (step.action === "wait") {
      patch(edit.id, { settling: step.settling });
      continue;
    }
    const resolved = resolveSource?.(edit.sessionId, edit.profileId);
    if (!resolved) {
      // Session closed under us. Keep the copy and say so — the edit is not
      // lost, it just has nowhere to go until the host is reconnected. Retry
      // re-binds it to whatever session that host has by then.
      patch(edit.id, { state: "error", errorKey: "sessionClosed" });
      toast(tDyn("sftp.extEdit.err.sessionClosed"), "warn");
      continue;
    }
    // Rebound to a different session for the same host (a reconnect).
    if (resolved.sessionId !== edit.sessionId) patch(edit.id, { sessionId: resolved.sessionId });
    patch(edit.id, { settling: undefined });
    await push(edit.id, resolved.source, false);
  }
}
