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
import { lstat, mkdir, readDir, remove, stat, writeTextFile } from "@tauri-apps/plugin-fs";
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
/** How long a change must read identically before it counts as finished. Two
 *  readings are always required — one alone cannot tell a settled file from a
 *  half-written one — but the wait between them is wall-clock, like every other
 *  budget here, so a throttled poll does not silently multiply it. */
const SETTLE_MS = 800;
// Every budget below is WALL-CLOCK, not a tick count. A hidden webview's timers
// are throttled to roughly one a minute, and this window is hidden for most of
// an external edit by definition — the user is in another application. Counting
// ticks would stretch "three seconds" into six minutes without a word of it
// showing up anywhere.

/** How long the copy may stay missing before we give up on it. Not every editor
 *  renames over the target — some unlink and recreate, which leaves a real
 *  window where the path does not exist. */
const MISSING_GRACE_MS = 3_000;
/** …re-checked within the tick rather than across them, because the next tick
 *  can be a throttled minute away and would blow the budget on one sample. */
const MISSING_RETRIES = 6;
const MISSING_RETRY_MS = 400;
/** How long to wait for a host to come back before parking the edit. Unlocking
 *  the vault drops every SFTP session, so without this grace an edit would be
 *  errored out before the user could reconnect — and an errored edit no longer
 *  re-binds itself. */
const SESSION_GRACE_MS = 60_000;
/** How long a copy must stay empty before we believe emptying it was the point.
 *  Long enough to outlast an in-place truncate that stalls, short enough that
 *  deleting a file's contents still reaches the server while you watch. */
const ZERO_HOLD_MS = 10_000;

export type EditState = "downloading" | "watching" | "uploading" | "conflict" | "error";

/** Extensions the OS launcher RUNS rather than opens. Handing one of these to
 *  `openPath` turns "let me look at this file on the server" into executing
 *  code from that server as the user — Windows ShellExecute on .exe/.bat/.js/
 *  .lnk, a Linux .desktop, a macOS .command. An editor is not what would open
 *  them, so refusing costs nothing this feature is for.
 *
 *  A deny-list is the wrong shape in general, but the alternative — allowing
 *  only known-inert extensions — would refuse the extensionless config files
 *  that are most of what people edit over SSH. */
const EXECUTABLE_EXTS = new Set([
  "action", "apk", "app", "appimage", "bat", "bin", "cmd", "com", "command", "cpl", "deb", "desktop",
  "dll", "dmg", "exe", "gadget", "hta", "inf", "ins", "ipa", "iso", "jar", "js", "jse", "ksh", "lnk",
  "msc", "msi", "msp", "mst", "out", "pif", "pkg", "ps1", "psm1", "reg", "rpm", "run", "scf", "scr",
  "sct", "sh", "shs", "url", "vb", "vbe", "vbs", "wsf", "wsh",
]);

/** True when the OS would execute `name` rather than open it. */
export function isExecutableName(name: string): boolean {
  const dot = name.lastIndexOf(".");
  if (dot <= 0) return false; // no extension, or a dotfile like `.bashrc`
  return EXECUTABLE_EXTS.has(name.slice(dot + 1).toLowerCase());
}

/** Refuse to copy down something no editor will open anyway. The in-app editor
 *  stops at 2 MiB; this is far looser because an external editor can genuinely
 *  handle a large file — it exists so a mis-click on a multi-gigabyte log can't
 *  quietly fill $TEMP. */
const MAX_EDIT_BYTES = 256 * 1024 * 1024;

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
  /** Candidate local stamp, waiting to hold still before we trust it. */
  settling?: Stamp & { since: number };
  /** When the copy first went missing (epoch ms). */
  missingSince?: number;
  /** When this host first had no live session (epoch ms). */
  sessionLostSince?: number;
  /** When the copy first read as empty while the remote is not (epoch ms). */
  zeroSince?: number;
  /** A remote path this edit has already claimed with an exclusive create, so a
   *  retry after a failed copy-upload reuses it rather than reserving another. */
  reservedPath?: string;
  /** Core cancel token, while the copy is still coming down. */
  cancelId?: string;
  /** Host the file belongs to. A reconnect mints a new session id, so this is
   *  what lets an orphaned edit find its way back to a live session. */
  profileId: string;
  /** Successful pushes so far — the only progress this feature has to show. */
  saves: number;
  /** Why the push stopped: somebody else's write, or a baseline we lost and
   *  therefore cannot compare against. The dialog must not claim the first when
   *  it means the second. */
  conflictReason?: "changed" | "unknown";
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
/** Scratch directories whose edit was stopped while an upload was reading from
 *  them. Removed once the upload returns — deleting a file the core is
 *  streaming would leave the remote half-rewritten and the local one gone. */
const removeAfterUpload = new Set<string>();

/** The scratch root. NOT under $APPLOCALDATA: the fs plugin's default permission
 *  set pulls in `deny-webview-data-linux`, whose `$APPLOCALDATA/**` deny has no
 *  platform key and so applies everywhere — and a deny beats any allow, which
 *  would make every operation here fail with "path forbidden". */
const scratchRoot = async (): Promise<string> => join(await tempDir(), "unissh-external-edit");

/** This run's own subtree. The root is shared with any other UniSSH running on
 *  the machine — nothing stops a second instance — so a run may only ever delete
 *  its own directory and ones it has watched fall silent.
 *
 *  Random, not time-derived: a collision means one run deleting another's live
 *  copies, and clocks at process start are far too similar to rely on.
 *  crypto.randomUUID is out — it throws outside a secure context. */
const runId = `run-${Math.random().toString(36).slice(2, 10)}${Math.random().toString(36).slice(2, 10)}`;
const runRoot = async (): Promise<string> => join(await scratchRoot(), runId);

/** How often a run says it is still here. The purge samples this twice, so it
 *  also sets how long collecting leftovers takes. */
const HEARTBEAT_MS = 20 * 1000;
/** How long a run must have been silent before it is even a candidate for
 *  collection. Webview timers are throttled hard in a hidden window — Chromium
 *  drops to roughly one per minute — so a window measured in beats would call a
 *  minimised instance dead and delete the copies its editor still has open.
 *  Deleting live work is far worse than a leftover waiting for a later start. */
const MIN_SILENCE_MS = 5 * 60 * 1000;
/** And it must stay silent across this probe. Sized well beyond one throttled
 *  beat: a minimised peer coming out of sleep gets only the beats that fit in
 *  here to prove it is alive, and the cost of being wrong is deleting files its
 *  editor has open. The purge is fire-and-forget, so the wait is free. */
const PROBE_MS = 3 * 60 * 1000;
/** Deliberately NOT dotted. Tauri's fs scope sets `require_literal_leading_dot`
 *  on unix, so a `**` allow does not match a dot-leading name — a `.alive` here
 *  is unwritable and unreadable, which the purge would read as "this run is
 *  dead" and act on. */
const HEARTBEAT_FILE = "alive";
let heartbeat: ReturnType<typeof setInterval> | null = null;

async function beat(): Promise<void> {
  try {
    await writeTextFile(await join(await runRoot(), HEARTBEAT_FILE), String(Date.now()));
  } catch {
    /* the purge treats an unreadable heartbeat as stale, which is the safe side */
  }
}

function startHeartbeat(): void {
  if (heartbeat !== null) return;
  void beat();
  heartbeat = setInterval(() => void beat(), HEARTBEAT_MS);
  // Timers do not run while the machine sleeps; beat on the way back so the
  // gap does not read as a dead run.
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") void beat();
  });
}

/** `mkdir` with a mode is a no-op on a directory that already exists, so the
 *  0700 says nothing about a root somebody else created first. On a shared box
 *  $TEMP is /tmp, where anyone can pre-create our root — as a world-writable
 *  directory, or as a symlink into one of theirs — and then own the parent of
 *  every copy this feature decrypts. Check before trusting it. */
async function assertSafeRoot(root: string): Promise<void> {
  let info: Awaited<ReturnType<typeof lstat>> | null = null;
  let failure: string | null = null;
  try {
    info = await lstat(root);
  } catch (e) {
    failure = String(e instanceof Error ? e.message : e).toLowerCase();
  }
  if (failure !== null) {
    // Absent is fine: mkdir will make it ours, with our mode. Anything else —
    // a permission error, a scope rejection, an I/O failure — means we could
    // not look, and this is the ONE check between a hostile $TEMP root and a
    // directory full of decrypted files. Not looking is not the same as safe.
    const absent =
      failure.includes("not found") || failure.includes("no such file") || failure.includes("os error 2");
    if (absent) return;
    throw new Error(`${tDyn("sftp.extEdit.err.unsafeRoot")} (${failure})`);
  }
  if (!info || info.isSymlink || !info.isDirectory) throw new Error(tDyn("sftp.extEdit.err.unsafeRoot"));
  // Windows reports no mode; there the per-user profile carries the isolation.
  if (typeof info.mode === "number" && (info.mode & 0o077) !== 0) {
    throw new Error(tDyn("sftp.extEdit.err.unsafeRoot"));
  }
}

/** `<temp>/unissh-external-edit/<run>/<n>` — one directory per edit, so two
 *  files with the same basename can't collide, and stopping one edit can remove
 *  its directory whole. */
async function scratchDir(id: string): Promise<string> {
  // 0700: the copy is the remote file in the clear, and this is the one place
  // it exists unencrypted. Ignored on Windows, where the profile is already
  // per-user.
  const root = await scratchRoot();
  await assertSafeRoot(root);
  await mkdir(root, { recursive: true, mode: 0o700 });
  // Again, after creating it: the check and the mkdir are two syscalls, and on
  // a shared /tmp the root can be swapped for a symlink in between — which
  // `create_dir_all` would follow, putting every decrypted copy in somebody
  // else's tree.
  await assertSafeRoot(root);
  const mine = await runRoot();
  await mkdir(mine, { recursive: true, mode: 0o700 });
  // Awaited: an instance launching right now purges directories with no
  // heartbeat, and ours must exist before this returns a path to copy into.
  await beat();
  startHeartbeat();
  const dir = await join(mine, id);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  return dir;
}

/** Re-checks a few times before answering null. An editor that unlinks and
 *  recreates leaves a gap of milliseconds, and the next poll may be a throttled
 *  minute away — so the gap has to be ridden out here, not across ticks. */
async function localStamp(path: string, retries = 0): Promise<Stamp | null> {
  for (let attempt = 0; ; attempt++) {
    try {
      const s = await stat(path);
      return { size: s.size, mtime: s.mtime ? s.mtime.getTime() : 0 };
    } catch {
      if (attempt >= retries) return null;
      await new Promise((resolve) => setTimeout(resolve, MISSING_RETRY_MS));
    }
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

/** What to do about a copy that currently reads as empty. */
export type ZeroHold =
  /** Not the empty case, and the mark needs clearing. */
  | { action: "reset" }
  /** Not the empty case, nothing to clear. */
  | { action: "none" }
  /** Empty and not yet trusted — wait, having first started the clock. */
  | { action: "hold"; since: number };

/**
 * An editor that truncates in place and then stalls reads as a settled 0-byte
 * file, and pushing that would empty the remote one until the next save. So an
 * empty copy waits.
 *
 * But only for a while: emptying a file IS a real edit, and a guard with no
 * bound would drop that change silently and then delete the copy at quit. Once
 * the wait is served this returns `none`, NOT `reset` — clearing the counter
 * here would wipe the settling progress on the following tick and the push
 * would never be reached.
 */
export function zeroHold(
  nowSize: number,
  uploadedSize: number,
  since: number | undefined,
  now: number,
): ZeroHold {
  if (nowSize !== 0 || uploadedSize === 0) return since ? { action: "reset" } : { action: "none" };
  if (since === undefined) return { action: "hold", since: now };
  return now - since < ZERO_HOLD_MS ? { action: "hold", since } : { action: "none" };
}

/** What a tick concluded about one edit. */
export type SettleStep =
  /** Nothing to do: the copy still matches what we last uploaded. */
  | { action: "none" }
  /** It moved and moved back — drop the candidate. */
  | { action: "clear" }
  /** Changed, but not yet stable enough to trust. */
  | { action: "wait"; settling: Stamp & { since: number } }
  /** The same change has now held still long enough: the editor is done. */
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
  settling: (Stamp & { since: number }) | undefined,
  now: Stamp,
  nowMs: number,
): SettleStep {
  if (same(now, uploaded)) return settling ? { action: "clear" } : { action: "none" };
  // A different reading restarts the clock: the file is still being written.
  if (!settling || !same(settling, now)) return { action: "wait", settling: { ...now, since: nowMs } };
  return nowMs - settling.since >= SETTLE_MS ? { action: "push" } : { action: "wait", settling };
}

/**
 * Copy `remotePath` down, open it with the OS, and watch it until stopped.
 *
 * @param source the remote file's source — used for stat and for the copy check
 * @returns the new edit's id, or null if it could not be started
 */
/** Why an open produced no new edit. `cancelled` is the user's own doing and
 *  wants no message at all; `already` is worth one. */
export type StartResult =
  | { ok: true; id: string }
  | { ok: false; reason: "already" | "cancelled" };

export async function startExternalEdit(
  source: FileSource,
  sessionId: string,
  profileId: string,
  remotePath: string,
  name: string,
): Promise<StartResult> {
  // Keyed on the HOST, not the session: the same host open in two panes has two
  // session ids, and two edits of one remote path would push over each other.
  const existing = useExternalEdits
    .getState()
    .edits.find(
      (e) => e.remotePath === remotePath && (profileId ? e.profileId === profileId : e.sessionId === sessionId),
    );
  if (existing) {
    // Still copying: the local path already exists and is GROWING, so neither
    // branch below is safe — opening it would hand an editor a truncated file
    // (and a save would push the truncation), and dropping it would delete the
    // download out from under the first call.
    if (existing.state === "downloading") return { ok: false, reason: "already" };
    // Already open — bring the editor forward rather than making a second copy
    // that would race the first one on save. Unless the copy is gone: then the
    // row is a leftover, and re-matching it would fail on the same missing path
    // forever. Drop it and start again.
    if (await localStamp(existing.localPath)) {
      // Re-opening a parked edit is the natural "start it again" gesture, so
      // treat it as one. Without this the row stays errored, the tick keeps
      // skipping it, and every later save goes nowhere in silence.
      if (existing.state === "error") retryExternalEdit(existing.id);
      await openPath(existing.localPath);
      return { ok: true, id: existing.id };
    }
    await stopExternalEdit(existing.id);
  }
  // The store check above cannot see an edit whose download is still running,
  // and a big file makes that window minutes long — during which a second click
  // would start a rival copy of the same file. Claim the path up front.
  if (isExecutableName(name)) throw new Error(tDyn("sftp.extEdit.err.executable"));

  const claim = `${profileId || sessionId}\u0000${remotePath}`;
  if (starting.has(claim)) return { ok: false, reason: "already" };
  starting.add(claim);

  const id = `ee${++editSeq}`;
  let dir: string | null = null;
  try {
    const remote = await remoteStamp(source, remotePath);
    // No size means we could not read it, not that it is small. Copying a file
    // of unknown length into $TEMP is exactly what the cap exists to prevent.
    if (!remote) throw new Error(tDyn("sftp.extEdit.err.sizeUnknown"));
    if (remote.size > MAX_EDIT_BYTES) throw new Error(tDyn("sftp.extEdit.err.tooLarge"));
    // Inside the try: a mkdir that fails must still release the claim, or this
    // file becomes silently un-openable for the rest of the process.
    dir = await scratchDir(id);
    const localDir = dir;
    const localPath = await join(localDir, name);

    // Minted before the row exists: the row is stoppable the moment it appears,
    // and a stop that found no token yet would delete the directory while the
    // core kept streaming into it — then blame the user with an error toast.
    const cancelId = await api.cancelNew();

    // Listed BEFORE the copy starts: a large file takes minutes, and a menu item
    // that shows nothing for minutes reads as broken. The tick ignores
    // `downloading`, so nothing acts on the row until there is a file.
    setEdits((edits) => [
      ...edits,
      {
        id,
        sessionId,
        profileId,
        remotePath,
        localDir,
        localPath,
        name,
        state: "downloading",
        cancelId,
        base: remote ?? undefined,
        local: { size: 0, mtime: 0 },
        saves: 0,
      },
    ]);

    try {
      // Resolves false on cancellation rather than throwing. Stopping the row is
      // the user's own action, so walk out quietly — reading on would either
      // blame them with an error toast or, if the directory removal lost the
      // race, hand an editor a half-downloaded file.
      const completed = await api.sftpDownload(sessionId, remotePath, localPath, 0, null, () => {}, cancelId);
      if (!completed) {
        // The user stopped it. The row is already gone; the directory is ours
        // to remove now that nothing is writing into it.
        await remove(localDir, { recursive: true }).catch(() => {});
        return { ok: false, reason: "cancelled" };
      }
    } finally {
      patch(id, { cancelId: undefined });
      await api.cancelDispose(cancelId).catch(() => {});
    }

    // Stop may have landed while the transfer was finishing — cancellation is
    // cooperative, so the core can still report success. Without this check the
    // patches below would be silent no-ops and we would hand the user's editor
    // the very file they just cancelled, with no row left to stop it.
    if (!find(id)) {
      await remove(localDir, { recursive: true }).catch(() => {});
      return { ok: false, reason: "cancelled" };
    }

    // Both stamps are the baselines every later decision is measured against.
    // A sentinel here would be a lie the first save pays for: a bogus conflict
    // (remote) or an immediate pointless re-upload (local). Fail the open
    // instead — nothing has been handed to an editor yet, so nothing is lost.
    const base = await remoteStamp(source, remotePath);
    const local = await localStamp(localPath);
    // Checked again: a Stop landing during those two stats deletes the copy, and
    // reporting that as "couldn't read the file" blames the user for their own
    // action.
    if (!find(id)) return { ok: false, reason: "cancelled" };
    if (!base || !local) throw new Error(tDyn("sftp.extEdit.err.openFailed"));
    patch(id, { state: "watching", base, local });
    ensurePolling();
    await openPath(localPath);
    return { ok: true, id };
  } catch (e) {
    // Anything registered so far goes with the failure: a row nothing is
    // watching would sit there reporting its own copy missing. A half-written
    // copy is still the remote file in the clear, so the directory goes too.
    setEdits((edits) => edits.filter((x) => x.id !== id));
    stopPollingIfIdle();
    if (dir) await remove(dir, { recursive: true }).catch(() => {});
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
  // Clear the counters too: the error message tells the user to reconnect and
  // then Retry, so arriving here with the grace already spent would re-error on
  // the first tick — exactly when the reconnect is still in flight.
  patch(id, {
    state: "watching",
    error: undefined,
    errorKey: undefined,
    missingSince: undefined,
    sessionLostSince: undefined,
    zeroSince: undefined,
    settling: undefined,
  });
  ensurePolling();
}

/** Stop watching and delete the local copy. */
export async function stopExternalEdit(id: string): Promise<void> {
  const edit = find(id);
  setEdits((edits) => edits.filter((e) => e.id !== id));
  stopPollingIfIdle();
  if (!edit) return;
  if (edit.state === "uploading") {
    // The upload is reading this exact file. Let it finish and clean up after
    // itself; taking the file away mid-stream damages both copies.
    removeAfterUpload.add(edit.localDir);
    return;
  }
  if (edit.cancelId) {
    // Cancellation is cooperative — the core notices between chunks — so the
    // directory must NOT be removed here: on Windows the removal would fail
    // while the file is still held, and on Unix it would race the writes and
    // turn the user's own Stop into an error. `startExternalEdit` cleans up
    // once the download has actually returned.
    await api.cancelTrigger(edit.cancelId).catch(() => {});
    return;
  }
  try {
    // The whole directory: the editor may have left backups (`file~`, `.swp`)
    // beside our copy, and those hold the same plaintext.
    await remove(edit.localDir, { recursive: true });
  } catch (e) {
    const msg = String(e instanceof Error ? e.message : e).toLowerCase();
    const absent =
      msg.includes("not found") || msg.includes("no such file") || msg.includes("os error 2");
    // Already gone is the outcome we wanted. Windows refusing while an editor
    // holds the file open is not — say so, because the whole point of this row
    // was telling the user where the plaintext is.
    if (!absent) toast(tDyn("sftp.extEdit.err.removeFailed", { path: edit.localDir }), "warn");
  }
}

/** Stop everything and remove the scratch root. For app shutdown. */
export async function stopAllExternalEdits(): Promise<void> {
  const ids = useExternalEdits.getState().edits.map((e) => e.id);
  for (const id of ids) await stopExternalEdit(id);
  // Our own subtree, wholesale. Not the sibling sweep — that samples other runs
  // across a heartbeat interval, and a quit has no time for it. This also
  // catches an edit still downloading, whose directory `stopExternalEdit`
  // deliberately leaves to a continuation that a quit never runs.
  try {
    await remove(await runRoot(), { recursive: true });
  } catch {
    /* nothing to remove */
  }
}

/** Remove this run's copies, plus any left by a run that is no longer beating.
 *
 *  Deliberately NOT the whole root: another UniSSH may be running with files
 *  open in an editor right now, and deleting those would destroy work that only
 *  exists there. A run silent for `ALIVE_STALE_MS` is gone, and its copies are
 *  the leftovers this is for. */
export async function purgeExternalEditScratch(): Promise<void> {
  let root: string;
  try {
    root = await scratchRoot();
  } catch {
    return; // no path API — nothing was ever written either
  }
  try {
    // BEFORE touching anything. This function recursively deletes directories
    // it finds by walking the root, and it runs at every launch — so if the
    // root is a symlink somebody planted in a shared /tmp, walking it would
    // aim that delete at whatever they pointed it to. `scratchDir` checks the
    // same thing, but it only runs once an edit is opened, which is far too
    // late to be the only check.
    await assertSafeRoot(root);
  } catch {
    return;
  }

  // Liveness is OBSERVED, not inferred from a timestamp. Sample every other
  // run's heartbeat, wait longer than one beat, and sample again: a run that
  // moved is alive, a run that didn't is gone. This is what makes the check
  // survive a suspend — if this process is running, the machine is awake, so
  // any live instance's timer is running too — and it needs no guess about
  // which directory used to be ours.
  let before: Array<{ dir: string; beat: number | null }>;
  try {
    before = await Promise.all(
      (await readDir(root))
        .filter((e) => e.isDirectory && e.name !== runId)
        .map(async (e) => {
          const dir = await join(root, e.name);
          return { dir, beat: await beatAt(dir) };
        }),
    );
  } catch {
    return; // no root yet
  }
  if (before.length === 0) return;

  // Only ones already long silent are worth probing at all.
  const cutoff = Date.now() - MIN_SILENCE_MS;
  const candidates = before.filter((c) => c.beat !== null && c.beat < cutoff);
  if (candidates.length === 0) return;

  await new Promise((resolve) => setTimeout(resolve, PROBE_MS));

  for (const { dir, beat } of candidates) {
    // Positive evidence of death only. A heartbeat we could not read means we
    // could not look — a scope rejection, a permission error, a directory from
    // before this scheme — and deleting on "we don't know" is exactly how a
    // live instance's open files get destroyed.
    const now = await beatAt(dir);
    if (now === null || now !== beat) continue; // it moved, or went unreadable
    await remove(dir, { recursive: true }).catch(() => {});
  }
}

/** Epoch ms of a run directory's last heartbeat, or null if it has none. */
async function beatAt(dir: string): Promise<number | null> {
  try {
    const info = await stat(await join(dir, HEARTBEAT_FILE));
    return info.mtime ? info.mtime.getTime() : 0;
  } catch {
    return null;
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
export async function resolveConflict(
  id: string,
  choice: ConflictChoice,
  session: ResolvedSession,
): Promise<boolean> {
  const edit = find(id);
  if (!edit || edit.state !== "conflict") return false;
  // Synchronously, before the first await. "Keep both" lists the directory
  // first — hundreds of milliseconds over SFTP — and a second click in that
  // window would reserve a second name, leaving the first as litter, and start
  // a rival upload.
  patch(id, { state: "uploading" });
  // The dialog may have been open across a reconnect: push through whatever
  // session the host has now, not the one the conflict was raised on.
  if (session.sessionId !== edit.sessionId) patch(id, { sessionId: session.sessionId });
  try {
    return await applyConflictChoice(id, edit, choice, session.source);
  } catch (e) {
    // Anything here — a dead channel, an unwritable directory — must put the
    // row back somewhere the user can act on. Leaving it "uploading" hides it
    // from the tick, from both buttons, and from the rail badge, and every
    // later save disappears in silence.
    if (find(id)) patch(id, { state: "conflict" });
    else await drainDeferredRemoval(edit.localDir);
    throw e;
  }
}

async function applyConflictChoice(
  id: string,
  edit: LiveEdit,
  choice: ConflictChoice,
  source: FileSource,
): Promise<boolean> {
  // Stop can land while this is awaiting — the row goes to "uploading" before
  // the first await, so stopExternalEdit defers the directory removal to a push
  // that may never happen. Anything that leaves without pushing must drain it.
  const gone = async (): Promise<false> => {
    await drainDeferredRemoval(edit.localDir);
    return false;
  };
  const giveUp = (): false => {
    patch(id, { state: "conflict" });
    return false;
  };
  if (choice === "cancel") {
    // Adopt the current local stamp as the baseline: the edit the user declined
    // to push must not re-trigger the prompt on the next tick.
    const local = await localStamp(edit.localPath);
    // Without a reading we cannot say what the user is declining to send. The
    // old value would be wrong in the one direction that matters: the next tick
    // would treat the file as freshly changed and push it — over the very
    // version they just chose to keep. Leave the conflict standing instead.
    if (!find(id)) return gone();
    if (!local) return giveUp();
    const base = await remoteStamp(source, edit.remotePath);
    patch(id, { state: "watching", local, base: base ?? undefined });
    return true;
  }
  if (choice === "copy") {
    // Already reserved on an earlier attempt whose upload failed: reuse it.
    // Deduping again would leave the previous empty reservation on the server
    // as litter, once per failed attempt.
    if (edit.reservedPath === edit.remotePath) {
      await push(id, source, true);
      return true;
    }
    const dir = remoteParent(edit.remotePath);
    const taken = (await source.list(dir)).map((e) => e.name);
    let copyName = dedupeName(edit.name, taken);
    // Reserve it, don't just pick it. The listing is already a moment old, and
    // the forced push that follows opens with CREAT|TRUNC — so a name taken in
    // between would be overwritten by the branch that promises to save yours
    // BESIDE theirs. createNew is O_CREAT|O_EXCL; if it loses, look again.
    for (let attempt = 0; ; attempt++) {
      try {
        await source.createNew(await source.join(dir, copyName));
        break;
      } catch (e) {
        if (attempt >= 3) throw e;
        const again = (await source.list(dir)).map((x) => x.name);
        copyName = dedupeName(edit.name, again);
      }
    }
    // The LOCAL path deliberately stays put. The editor has that exact path
    // open, and most editors save by path — renaming it under them would leave
    // them re-creating the old name, which we would no longer be watching, and
    // every later save would vanish. The strip labels the two separately.
    // `base` described the ORIGINAL path; against the copy it means nothing, and
    // keeping it would raise a conflict against our own upload if this one fails
    // partway and gets retried.
    if (!find(id)) return gone();
    const reservedPath = await source.join(dir, copyName);
    patch(id, { remotePath: reservedPath, reservedPath, name: copyName, base: undefined });
  }
  await push(id, source, true);
  return true;
}

/** Upload the local copy over the remote file. */
/** True when the edit was stopped while this push was in its pre-flight — which
 *  parks the directory removal on us, and means any toast we were about to fire
 *  would be about something the user just cancelled. */
async function stoppedDuringPush(id: string, edit: LiveEdit): Promise<boolean> {
  if (find(id)) return false;
  await drainDeferredRemoval(edit.localDir);
  return true;
}

/** Remove a scratch directory whose edit was stopped while an upload held it. */
async function drainDeferredRemoval(localDir: string): Promise<void> {
  if (removeAfterUpload.delete(localDir)) {
    await remove(localDir, { recursive: true }).catch(() => {});
  }
}

async function push(id: string, source: FileSource, force: boolean): Promise<void> {
  const edit = find(id);
  if (!edit) return;
  patch(id, { state: "uploading" });
  // Whether we got as far as writing anything. The pre-flight check throws on a
  // transport failure, and that must NOT be treated like a half-finished
  // upload: clearing the baseline there would raise a bogus "can't tell what's
  // on the server" on the next save, for a file nobody else touched.
  let uploaded = false;
  try {
    // A read through the source first: it carries the reopen-and-retry that a
    // bare api.sftpUpload does not, and external editing is exactly the
    // long-idle case where the server has reaped the channel. The non-forced
    // path gets this from its own conflict stat.
    if (force) await source.stat(edit.remotePath);
    if (!force) {
      const now = await remoteStamp(source, edit.remotePath);
      if (!now) {
        // Could not read it, and it is still listed: refuse rather than
        // overwrite a file whose state we do not know. Genuinely gone is fine —
        // re-creating it is what saving means.
        if (!(await confirmedAbsent(source, edit.remotePath))) {
          if (await stoppedDuringPush(id, edit)) return;
          patch(id, { state: "error", errorKey: "checkFailed" });
          announce(edit, "checkFailed");
          return;
        }
      } else if (edit.base) {
        if (!same(now, edit.base)) {
          if (await stoppedDuringPush(id, edit)) return;
          patch(id, { state: "conflict", conflictReason: "changed" });
          announce(edit, "changed");
          return;
        }
      } else {
        // No baseline: the stat behind our last decision failed, so we do not
        // know whose version is on the server. Matching sizes would be weak
        // evidence — a one-character edit keeps the length — and this guard
        // exists precisely to stop a blind write. Ask.
        if (await stoppedDuringPush(id, edit)) return;
        patch(id, { state: "conflict", conflictReason: "unknown" });
        announce(edit, "unknown");
        return;
      }
    }
    uploaded = true;
    // Snapshot BEFORE the upload: what we are about to send is this state, not
    // whatever the file looks like when the upload finishes. Reading it after
    // would adopt a save made mid-upload as already-sent and silently drop it.
    const sent = (await localStamp(edit.localPath)) ?? edit.local;
    await api.sftpUpload(edit.sessionId, edit.localPath, edit.remotePath, 0, () => {});
    const current = find(id);
    if (!current) {
      // Stopped mid-upload. The upload has returned, so the directory is safe
      // to remove now — which stopExternalEdit deliberately deferred.
      await drainDeferredRemoval(edit.localDir);
      return;
    }
    // Deliberately not falling back to the old baseline: it describes the file
    // as it was BEFORE our upload, so keeping it would make the next save report
    // a conflict against our own write. Unknown is the honest value, and the
    // guard skips a baseline it does not have.
    const base = await remoteStamp(source, current.remotePath);
    patch(id, {
      state: "watching",
      local: sent,
      base: base ?? undefined,
      saves: current.saves + 1,
      // Spent: a later "Keep both" must reserve a fresh name, not short-circuit
      // into a forced write over whatever is at this one now.
      reservedPath: undefined,
      error: undefined,
      errorKey: undefined,
      settling: undefined,
    });
  } catch (e) {
    // The upload opens the remote with TRUNC at offset 0, so a drop partway
    // leaves it rewritten in part. Our baseline described the file BEFORE that,
    // and keeping it would make Retry conflict against our own half-write. If
    // nothing was written, the baseline is still good.
    if (!find(id)) {
      await drainDeferredRemoval(edit.localDir);
      return;
    }
    patch(id, {
      state: "error",
      error: apiErrorMessage(e),
      errorKey: undefined,
      ...(uploaded ? { base: undefined } : {}),
    });
    const current = find(id);
    if (current) toast(tDyn("sftp.extEdit.pushFailed", { name: current.name }), "err");
  }
}

/** Say it out loud. The list lives on the SFTP route, and a save that stopped
 *  reaching the server is not something to discover by navigating back. */
function announce(edit: LiveEdit, what: "changed" | "unknown" | "checkFailed"): void {
  const text =
    what === "changed"
      ? tDyn("sftp.extEdit.conflictToast", { name: edit.name })
      : what === "unknown"
        ? tDyn("sftp.extEdit.unknownToast", { name: edit.name })
        : tDyn("sftp.extEdit.err.checkFailed");
  toast(text, "warn");
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
    document.removeEventListener("visibilitychange", pollOnReturn);
  }
}

/** Resume after an unlock. */
export function resumeExternalEdits(): void {
  if (useExternalEdits.getState().edits.length > 0) ensurePolling();
}

function ensurePolling(): void {
  if (timer !== null) return;
  timer = setInterval(() => void tick(), POLL_MS);
  // A hidden window's timers are throttled to roughly one a minute, and this
  // window is hidden for most of an external edit. Nothing here can make the
  // OS run our timer faster, but coming back to UniSSH should not then wait on
  // a throttled tick: catch up at once.
  document.addEventListener("visibilitychange", pollOnReturn);
}

const pollOnReturn = () => {
  if (document.visibilityState === "visible") void tick();
};

function stopPollingIfIdle(): void {
  if (timer !== null && useExternalEdits.getState().edits.length === 0) {
    clearInterval(timer);
    timer = null;
    document.removeEventListener("visibilitychange", pollOnReturn);
  }
}

/** Edits currently being processed. Per-edit rather than one global flag: a tick
 *  can outlast its interval (every step is an IPC round trip, and an upload over
 *  a black-holed connection can hang for minutes), and a single flag would let
 *  one stuck file stop every other one from being watched. */
const inFlight = new Set<string>();

async function tick(): Promise<void> {
  await Promise.all(
    useExternalEdits.getState().edits.map(async (edit) => {
      if (inFlight.has(edit.id)) return;
      inFlight.add(edit.id);
      try {
        await stepEdit(edit.id);
      } finally {
        inFlight.delete(edit.id);
      }
    }),
  );
}

async function stepEdit(editId: string): Promise<void> {
  for (const edit of useExternalEdits.getState().edits.filter((e) => e.id === editId)) {
    if (edit.state !== "watching") continue;
    const now = await localStamp(edit.localPath, MISSING_RETRIES);
    if (!now) {
      // Not necessarily gone: an editor that unlinks and recreates instead of
      // renaming leaves a real gap here. Only give up once it persists.
      const since = edit.missingSince ?? Date.now();
      if (Date.now() - since < MISSING_GRACE_MS) patch(edit.id, { missingSince: since });
      else {
        patch(edit.id, { state: "error", errorKey: "localGone" });
        toast(tDyn("sftp.extEdit.err.localGone"), "err");
      }
      continue;
    }
    if (edit.missingSince) patch(edit.id, { missingSince: undefined });
    const zero = zeroHold(now.size, edit.local.size, edit.zeroSince, Date.now());
    if (zero.action === "reset") patch(edit.id, { zeroSince: undefined });
    // Resolved every tick, not only when there is something to push: an edit
    // whose host went away is not "watching" anything, and saying so only at
    // the next save means the row and the rail badge both lie until then.
    const resolved = resolveSource?.(edit.sessionId, edit.profileId);
    if (!resolved) {
      const since = edit.sessionLostSince ?? Date.now();
      if (Date.now() - since < SESSION_GRACE_MS) patch(edit.id, { sessionLostSince: since });
      else {
        patch(edit.id, { state: "error", errorKey: "sessionClosed" });
        toast(tDyn("sftp.extEdit.err.sessionClosed"), "warn");
      }
      continue;
    }
    if (edit.sessionLostSince) patch(edit.id, { sessionLostSince: undefined });

    // AFTER the session check, so a host that went away is still noticed while
    // an empty copy is being held.
    if (zero.action === "hold") {
      patch(edit.id, { zeroSince: zero.since, settling: undefined });
      continue;
    }

    const step = settleStep(edit.local, edit.settling, now, Date.now());
    if (step.action === "none") continue;
    if (step.action === "clear") {
      patch(edit.id, { settling: undefined });
      continue;
    }
    if (step.action === "wait") {
      patch(edit.id, { settling: step.settling });
      continue;
    }
    // Rebound to a different session for the same host (a reconnect).
    if (resolved.sessionId !== edit.sessionId) patch(edit.id, { sessionId: resolved.sessionId });
    patch(edit.id, { settling: undefined });
    await push(edit.id, resolved.source, false);
  }
}
