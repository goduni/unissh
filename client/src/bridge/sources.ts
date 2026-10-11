// FileSource — a uniform façade over a browsable file location so the panes,
// drag/drop, and the transfer engine don't care whether a slot is the local OS
// filesystem or a remote SFTP session. Local fs calls go through the native
// api.local* commands, which reach every path the pane can browse (the fs
// plugin's scope stops at $HOME); remote calls go through the bridge api.sftp*.

import * as api from "@/bridge/api";
import { apiErrorMessage, type SftpEntry } from "@/bridge/types";
import type { Entry, LocationRef, SftpSession } from "@/store/sftp-types";
import { breadcrumbSegments, isSafeName, isPortableWindowsName, remoteJoin, remoteParent, type Crumb } from "@/sftp/paths";
import { isWindows } from "@/bridge/platform";
import { dirname, join } from "@tauri-apps/api/path";

/** An error that looks like the SFTP channel/connection dropped (server reaped
 *  an idle channel, EOF, broken pipe, "channel closed") rather than a real
 *  filesystem error (no such file / permission denied). Worth one reopen+retry.
 *  Note: russh surfaces a dead-channel write as the literal message
 *  "channel closed" (io BrokenPipe), so "closed" must be in this list. And once
 *  the whole connection is dead, opening a channel yields russh's exact "Channel
 *  send error", so that specific phrase is here too — the core's reopen() then
 *  does a full reconnect, so this path (and Retry) recovers instead of erroring
 *  forever. (Match the whole phrase, not a bare "send", so a server status
 *  message that merely contains "send" — a filename, say — isn't misread as a
 *  disconnect and needlessly torn down.) */
export function isSftpDisconnect(msg: string): boolean {
  const m = msg.toLowerCase();
  return [
    "eof",
    "closed",
    "timeout",
    "broken pipe",
    "reset",
    "disconnect",
    "not connected",
    "channel send error",
  ].some((k) => m.includes(k));
}

/** The status code of an SFTP error as the core words it — "sftp error: status
 *  N", optionally followed by ": " and the server's own text — or null for any
 *  other failure. Anchored to that prefix on purpose: everything after the code
 *  is supplied by the server, and a message or file name in it that happens to
 *  read "status 2" must not be taken for one. */
export function sftpStatus(message: string): number | null {
  const match = /^sftp error: status (\d+)(?::|$)/.exec(message);
  return match ? Number(match[1]) : null;
}

/** SSH_FX_NO_SUCH_FILE: the one answer that means "this path is not there". */
export const isNoSuchFile = (message: string): boolean => sftpStatus(message) === 2;

/** Whether a refused rename on a remote source means "these two paths cannot be
 *  joined by a rename", so a move has to copy and then remove — as opposed to a
 *  rename that was simply not allowed, or never reached the other end.
 *
 *  An SFTP server has no status for "across filesystems": OpenSSH reports EXDEV
 *  as the generic SSH_FX_FAILURE (4), which cannot be narrowed further, and a
 *  server without the operation answers SSH_FX_OP_UNSUPPORTED (8). Permission
 *  denied (3), no such file (2) and a dropped channel are none of these, and
 *  copying would only hide them — and re-create the file under the user's own
 *  owner and group. Neither is the core's "server does not support atomic
 *  replacement": the copy path ends in the very same replacing commit, so it
 *  cannot succeed where this one was refused, and the refusal is the answer. */
export function remoteRenameNeedsCopy(message: string): boolean {
  const status = sftpStatus(message);
  return status === 4 || status === 8;
}

/** The local counterpart of remoteRenameNeedsCopy. It mirrors `local_commit`
 *  in client/src-tauri/src/commands.rs, and has to change with it:
 *
 *  - A replacing commit and a folder rename are one rename(2) / MoveFileExW.
 *    Only "across filesystems" qualifies: EXDEV, errno 18 on Linux, macOS,
 *    Android and iOS, and ERROR_NOT_SAME_DEVICE (17) on Windows.
 *  - A commit onto a free name (`exclusive`) is, on unix, link(2) followed by
 *    removing the old name, and link(2) is refused by filesystems that have no
 *    hard links although source and destination are on the same one: EPERM (1)
 *    on FAT/exFAT and many FUSE and SMB mounts (and under Linux
 *    protected_hardlinks), EOPNOTSUPP (95, Linux) or ENOTSUP (45, macOS), and
 *    EMLINK (31) once the inode has no link left to give. Each of these also
 *    takes the copy path. That path publishes with the same exclusive commit
 *    and removes the source only after its own checks, so it can neither
 *    overwrite nor delete anything the rename could not have. On Windows the
 *    exclusive commit is MoveFileExW too, and nothing is added.
 *
 *  The number is read from the suffix the OS error carries, because the text in
 *  front of it is localised. The same numbers mean other things on the other
 *  family (17 is EEXIST on unix), hence `windows`. */
export function localRenameNeedsCopy(message: string, windows: boolean, exclusive: boolean): boolean {
  const code = /\(os error (\d+)\)/.exec(message)?.[1];
  if (code === undefined) return false;
  if (windows) return code === "17";
  return code === "18" || (exclusive && ["1", "31", "45", "95"].includes(code));
}

export interface FileSource {
  /** Paths on this source follow Windows rules: a backslash separates, and
   *  names compare without regard to case. Known from the platform the app runs on,
   *  never guessed from the look of a path — a unix file name may hold a
   *  backslash or start with "c:". Absent means no. */
  windows?: boolean;
  /** Whether a failed in-place move (`rename`, or `commit` of an entry that is
   *  already here) means the two paths cannot be joined by a rename, so the
   *  move has to copy and then remove. `exclusive` says the request was a
   *  `commit(…, false)` of a file. Any other failure is the move's failure. */
  renameNeedsCopy(error: unknown, exclusive: boolean): boolean;
  sameFile?(from: string, to: string): Promise<boolean>;
  withCancelToken?(id: string): FileSource;
  kind: "local" | "remote";
  id: string;
  identity?: string;
  label: string;
  list(path: string, signal?: AbortSignal): Promise<Entry[]>;
  commit(from: string, to: string, replace: boolean): Promise<void>;
  setMetadata(path: string, mode?: number, mtime?: number): Promise<void>;
  /** Stat one path, following links, or null if it does not exist. */
  stat(path: string): Promise<Entry | null>;
  /** Metadata for the link itself, including dangling links. */
  lstat(path: string): Promise<Entry | null>;
  readlink(path: string): Promise<string>;
  symlink(target: string, path: string, targetIsDir: boolean): Promise<void>;
  unlink(path: string): Promise<void>;
  realpath(path: string): Promise<string>;
  mkdir(path: string): Promise<void>;
  /** Create an empty file, failing if the path is already taken. */
  createNew(path: string): Promise<void>;
  /** Remove a file. */
  remove(path: string): Promise<void>;
  /** Remove a directory and everything inside it — recursive on both kinds. */
  rmdir(path: string): Promise<void>;
  /** Remove a directory only if it is empty; never recursive. */
  removeEmptyDir(path: string): Promise<void>;
  rename(from: string, to: string): Promise<void>;
  /** Change unix permissions — remote only (local FS chmod isn't exposed). */
  chmod?(path: string, mode: number): Promise<void>;
  readText(path: string): Promise<string>;
  writeText(path: string, text: string, expected?: string): Promise<void>;
  join(base: string, name: string): Promise<string>;
  parent(path: string): Promise<string>;
  /** Clickable breadcrumb segments for `path` (sync; for display). */
  crumbs(path: string): Crumb[];
}

/** Run `run` over `source` under one cancel token for all of it, the way a
 *  transfer runs: the token is triggered when `signal` aborts, which stops the
 *  calls in flight on either kind of source, and is disposed when `run` ends.
 *  A source that takes no token is handed to `run` as it is. */
export async function underCancelToken<T>(source: FileSource, signal: AbortSignal, run: (src: FileSource) => Promise<T>): Promise<T> {
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
    return await run(src);
  } finally {
    signal.removeEventListener("abort", trigger);
    if (token) await api.cancelDispose(token).catch(() => {});
  }
}

function fileKind(mode?: number): Entry["fileKind"] {
  switch ((mode ?? 0) & 0o170000) {
    case 0o100000: return "file";
    case 0o040000: return "directory";
    case 0o120000: return "symlink";
    case 0: return "unknown";
    default: return "unsupported";
  }
}

function baseName(path: string): string {
  const parts = path.split(/[\\/]/).filter(Boolean);
  return parts.length ? parts[parts.length - 1] : path;
}

// ── remote (SFTP session) ──────────────────────────────────────
class RemoteSource implements FileSource {
  readonly kind = "remote" as const;
  readonly id: string;
  readonly identity: string;
  readonly label: string;
  constructor(private readonly session: SftpSession, private readonly cancelId?: string) {
    this.id = session.id;
    this.identity = `${session.user}@${session.host.toLowerCase()}:${session.port}`;
    this.label = session.label;
  }
  withCancelToken(id: string): FileSource { return new RemoteSource(this.session, id); }
  /** Run a remote op; if it fails because the SFTP channel was reaped by the
   *  server (e.g. "channel closed" on an idle session), reopen the channel once
   *  on the still-live SSH connection and retry. So a random mid-session drop
   *  self-heals instead of erroring, and Retry actually recovers. */
  private async withReopen<T>(fn: () => Promise<T>, signal?: AbortSignal): Promise<T> {
    try {
      return await fn();
    } catch (e) {
      if (/cancelled|session closed|generation changed/i.test(apiErrorMessage(e)) || !isSftpDisconnect(apiErrorMessage(e))) throw e;
      // An aborted caller gets its own failure back: no reopen, no second try.
      if (signal?.aborted) throw e;
      await api.sftpReopen(this.id);
      if (signal?.aborted) throw e;
      return await fn(); // single retry — a truly dead SSH connection still throws
    }
  }
  /** withReopen for a request that takes something away (REMOVE, RMDIR). The
   *  channel can die after the server acted but before its reply arrived, and
   *  the second try then finds nothing: "no such file" on the SECOND try means
   *  the first one did it, so it is success. On the first try it stays an
   *  error. Repeating is safe either way — the request names one path, is never
   *  recursive, and can remove at most the entry the caller meant.
   *
   *  What this cannot tell apart: a first try that died before it was sent, for
   *  a path that was never there. That too ends as "no such file" on the second
   *  try and is reported as removed. For a removal the outcome is the same —
   *  the path is not there — but a caller must not read it as "there was
   *  something, and it is gone now". */
  private async gone(run: () => Promise<void>): Promise<void> {
    let retry = false;
    await this.withReopen(async () => {
      const second = retry;
      retry = true;
      try {
        await run();
      } catch (error) {
        if (!second || !isNoSuchFile(apiErrorMessage(error))) throw error;
      }
    });
  }
  /** withReopen for a request that renames `from` onto `to` (RENAME, and the
   *  posix-rename behind a replacing commit). It is NOT repeated blindly: if
   *  the reply was lost after the server acted, `from` is gone and a second
   *  request would fail with "no such file" although the move happened — and
   *  the caller would report a failed move, or copy what is no longer there.
   *  So after the reopen the outcome is looked at first: `from` gone and `to`
   *  present means the first request landed, and nothing is sent again. With
   *  `from` still in place the first request did nothing a second one cannot
   *  redo: posix-rename is atomic, and a plain RENAME that stopped between its
   *  link and unlink makes the second one fail on the existing `to`, which is
   *  the truth.
   *
   *  The two halves of that test do not weigh the same. For a replacing commit
   *  `to` was there before the request, so "`to` present" is no evidence at
   *  all; the proof is only "`from` gone", and it rests on nothing else taking
   *  `from` away in the meantime — every caller passes a path of its own (a
   *  staged `.unissh-*.part`, or an entry the user is moving right now). "`to`
   *  present" only guards the case where both are gone, which is no rename. */
  private async moved(from: string, to: string, run: () => Promise<void>): Promise<void> {
    let retry = false;
    await this.withReopen(async () => {
      if (retry && await this.lstat(from) === null && await this.lstat(to) !== null) return;
      retry = true;
      await run();
    });
  }
  async list(path: string, signal?: AbortSignal): Promise<Entry[]> {
    let list: SftpEntry[];
    // A cancellable listing heals a reaped channel exactly like a plain one. The
    // token outlives the retry: it is the caller's (or disposed below), and
    // only an abort triggers it.
    if (this.cancelId) {
      const token = this.cancelId;
      list = await this.withReopen(() => api.sftpListDirCancel(this.id, path, token), signal);
    } else if (signal) {
      const token = await api.cancelNew();
      const cancel = () => { void api.cancelTrigger(token); };
      signal.addEventListener("abort", cancel, { once: true });
      try {
        signal.throwIfAborted();
        list = await this.withReopen(() => api.sftpListDirCancel(this.id, path, token), signal);
      } finally {
        signal.removeEventListener("abort", cancel);
        await api.cancelDispose(token);
      }
    } else list = await this.withReopen(() => api.sftpListDir(this.id, path));
    return list
      .filter((e: SftpEntry) => e.filename !== "." && e.filename !== "..")
      .map((e: SftpEntry) => {
        if (!isSafeName(e.filename)) throw new Error("Invalid remote filename");
        return ({
        name: e.filename,
        isDir: e.isDir,
        isSymlink: (e.mode & 0o170000) === 0o120000,
        size: e.size,
        sizeKnown: e.sizeKnown,
        mtime: e.mtime || undefined,
        mode: e.mode || undefined,
        fileKind: fileKind(e.mode),
        uid: e.uid || undefined,
        gid: e.gid || undefined,
      }); });
  }
  stat(path: string): Promise<Entry | null> {
    return this.metadata(path, true);
  }
  lstat(path: string): Promise<Entry | null> {
    return this.metadata(path, false);
  }
  private async metadata(path: string, follow: boolean): Promise<Entry | null> {
    try {
      const s = await this.withReopen(() => follow ? api.sftpStat(this.id, path, this.cancelId) : api.sftpLstat(this.id, path, this.cancelId));
      return {
        name: baseName(path),
        isDir: s.isDir,
        isSymlink: (s.mode & 0o170000) === 0o120000,
        size: s.size,
        sizeKnown: s.sizeKnown,
        mtime: s.mtime || undefined,
        mode: s.mode || undefined,
        fileKind: fileKind(s.mode),
      };
    } catch (error) {
      // Only SSH_FX_NO_SUCH_FILE means absent. Treating permission/network/
      // generic status-4 errors as absence bypassed the overwrite decision.
      if (isNoSuchFile(apiErrorMessage(error))) return null;
      throw error;
    }
  }
  readlink(path: string): Promise<string> {
    return this.withReopen(() => api.sftpReadlink(this.id, path, this.cancelId));
  }
  symlink(target: string, path: string): Promise<void> {
    return api.sftpSymlink(this.id, target, path, this.cancelId);
  }
  unlink(path: string): Promise<void> {
    return this.remove(path);
  }
  realpath(path: string): Promise<string> {
    return this.withReopen(() => api.sftpRealpath(this.id, path));
  }
  mkdir(path: string): Promise<void> {
    return api.sftpMkdir(this.id, path, this.cancelId);
  }
  createNew(path: string): Promise<void> {
    return api.sftpCreateNewFile(this.id, path, this.cancelId);
  }
  remove(path: string): Promise<void> {
    return this.gone(() => api.sftpRemove(this.id, path));
  }
  rmdir(path: string): Promise<void> {
    // Recursive — SFTP RMDIR only removes empty dirs (a non-empty one returns
    // SSH_FX_FAILURE / status 4); the core walks the tree bottom-up.
    return api.sftpRmdirRecursive(this.id, path);
  }
  removeEmptyDir(path: string): Promise<void> {
    return this.gone(() => api.sftpRmdir(this.id, path));
  }
  rename(from: string, to: string): Promise<void> {
    return this.moved(from, to, () => api.sftpRename(this.id, from, to));
  }
  commit(from: string, to: string, replace: boolean): Promise<void> {
    return this.moved(from, to, () => api.sftpCommit(this.id, from, to, replace, this.cancelId));
  }
  renameNeedsCopy(error: unknown): boolean {
    return remoteRenameNeedsCopy(apiErrorMessage(error));
  }
  setMetadata(path: string, mode?: number, mtime?: number): Promise<void> { return api.sftpSetMetadata(this.id, path, mode === undefined ? undefined : mode & 0o777, mtime, this.cancelId); }
  chmod(path: string, mode: number): Promise<void> {
    return api.sftpChmod(this.id, path, mode);
  }
  async readText(path: string): Promise<string> {
    const buf = await this.withReopen(() => api.sftpReadFile(this.id, path));
    return new TextDecoder().decode(new Uint8Array(buf));
  }
  async writeText(path: string, text: string, expected?: string): Promise<void> {
    const original = expected ?? await this.readText(path);
    const metadata = await this.lstat(path);
    if (metadata?.isSymlink) throw new Error("Open the symbolic link target to edit it");
    const stage = await this.join(await this.parent(path), `.unissh-${crypto.randomUUID()}.part`);
    await this.createNew(stage);
    try {
      const data = Array.from(new TextEncoder().encode(text));
      await api.sftpWriteFile(this.id, stage, data);
      await this.setMetadata(stage, metadata?.mode);
      if (await this.readText(path) !== original) throw new Error("File changed on the server. Reopen it before saving.");
      await this.commit(stage, path, metadata !== null);
    } finally { await this.remove(stage).catch(() => {}); }
  }
  async join(base: string, name: string): Promise<string> {
    return remoteJoin(base, name);
  }
  async parent(path: string): Promise<string> {
    return remoteParent(path);
  }
  crumbs(path: string): Crumb[] {
    return breadcrumbSegments(path);
  }
}

// ── local (OS filesystem via native local_* commands) ──────────
class LocalSource implements FileSource {
  readonly kind = "local" as const;
  readonly id = "local";
  readonly label: string;
  readonly windows = isWindows();
  constructor(label: string, private readonly cancelId?: string) {
    this.label = label;
  }
  withCancelToken(id: string): FileSource { return new LocalSource(this.label, id); }
  async list(path: string): Promise<Entry[]> {
    // One IPC (name+isDir+size+mtime) instead of readDir + a stat per file.
    const list = await api.localListDir(path, this.cancelId);
    return list
      .filter((e) => isSafeName(e.name))
      .map((e) => ({ name: e.name, isDir: e.isDir && !e.isSymlink, isSymlink: e.isSymlink, size: e.size, fileKind: fileKind(e.mode), mode: e.mode, mtime: e.mtime || undefined }));
  }
  async stat(path: string): Promise<Entry | null> {
    const s = await api.localStat(path);
    return s ? { name: baseName(path), isDir: s.isDir, size: s.size, mtime: s.mtime || undefined } : null;
  }
  async lstat(path: string): Promise<Entry | null> {
    const entry = await api.localLstat(path);
    return entry ? { ...entry, fileKind: fileKind(entry.mode), isDir: entry.isDir && !entry.isSymlink } : null;
  }
  readlink(path: string): Promise<string> {
    return api.localReadlink(path);
  }
  symlink(target: string, path: string, targetIsDir: boolean): Promise<void> {
    return api.localSymlink(target, path, targetIsDir);
  }
  unlink(path: string): Promise<void> {
    return api.localUnlink(path);
  }
  realpath(path: string): Promise<string> { return api.localRealpath(path); }
  sameFile(from: string, to: string): Promise<boolean> { return api.localSameFile(from, to); }
  commit(from: string, to: string, replace: boolean): Promise<void> { return api.localCommit(from, to, replace); }
  renameNeedsCopy(error: unknown, exclusive: boolean): boolean {
    return localRenameNeedsCopy(apiErrorMessage(error), this.windows, exclusive);
  }
  setMetadata(path: string, mode?: number, mtime?: number): Promise<void> { return api.localSetMetadata(path, mode === undefined ? undefined : mode & 0o777, mtime); }
  async mkdir(path: string): Promise<void> {
    await api.localMkdir(path);
  }
  async createNew(path: string): Promise<void> {
    // O_CREAT|O_EXCL. writeTextFile would truncate an existing file instead.
    await api.localCreatePrivate(path);
  }
  async remove(path: string): Promise<void> {
    await api.localRemove(path, false);
  }
  async rmdir(path: string): Promise<void> {
    await api.localRemove(path, true);
  }
  async removeEmptyDir(path: string): Promise<void> {
    // The native non-recursive remove also deletes a file or a link, so a
    // directory swapped for one since it was scanned must be refused here.
    const entry = await this.lstat(path);
    if (!entry?.isDir || entry.isSymlink) throw new Error("Not a directory");
    await api.localRemove(path, false);
  }
  async rename(from: string, to: string): Promise<void> {
    // A plain rename(2): replaces an existing destination, as it always has.
    await api.localCommit(from, to, true);
  }
  async readText(path: string): Promise<string> {
    return api.localReadText(path);
  }
  async writeText(path: string, text: string, expected?: string): Promise<void> {
    const original = expected ?? await this.readText(path);
    const metadata = await this.lstat(path);
    if (metadata?.isSymlink) throw new Error("Open the symbolic link target to edit it");
    const stage = await this.join(await this.parent(path), `.unissh-${crypto.randomUUID()}.part`);
    await this.createNew(stage);
    try {
      await api.localWriteText(stage, text);
      await this.setMetadata(stage, metadata?.mode);
      if (await this.readText(path) !== original) throw new Error("File changed on disk. Reopen it before saving.");
      await this.commit(stage, path, metadata !== null);
    } finally { await this.remove(stage).catch(() => {}); }
  }
  async join(base: string, name: string): Promise<string> {
    if (name === "..") return this.parent(base);
    if (!isSafeName(name) || (/^[a-z]:|\\/i.test(base) && !isPortableWindowsName(name))) throw new Error(`Unsupported destination filename: ${name}`);
    return join(base, name);
  }
  async parent(path: string): Promise<string> {
    try {
      return await dirname(path);
    } catch {
      return path;
    }
  }
  crumbs(path: string): Crumb[] {
    // Windows paths lead with a drive ("C:\…"); unix paths lead with "/".
    const win = path.includes("\\");
    const parts = path.split(/[\\/]/).filter(Boolean);
    const crumbs: Crumb[] = [];
    if (!win) {
      crumbs.push({ label: "/", path: "/" });
      let acc = "";
      for (const part of parts) {
        acc += `/${part}`;
        crumbs.push({ label: part, path: acc });
      }
    } else {
      let acc = "";
      parts.forEach((part, i) => {
        acc = i === 0 ? part : `${acc}\\${part}`;
        crumbs.push({ label: part, path: acc });
      });
    }
    return crumbs.length ? crumbs : [{ label: path, path }];
  }
}

/** Build the FileSource for a location ref. `sessions` resolves a remote ref to
 *  its live SftpSession; throws if the session is gone. */
export function sourceFor(
  ref: LocationRef,
  sessions: SftpSession[],
  localLabel = "Local",
): FileSource {
  if (ref.kind === "local") return new LocalSource(localLabel);
  if (ref.kind === "remote") {
    const session = sessions.find((s) => s.id === ref.sessionId);
    if (!session) throw new Error(`sftp session ${ref.sessionId} not found`);
    return new RemoteSource(session);
  }
  throw new Error("sftp: no source for an empty slot");
}
