// FileSource — a uniform façade over a browsable file location so the panes,
// drag/drop, and the transfer engine don't care whether a slot is the local OS
// filesystem or a remote SFTP session. Local path/fs calls go through the Tauri
// plugins (dynamically imported, matching the rest of the client); remote calls
// go through the bridge api.sftp*.

import * as api from "@/bridge/api";
import { apiErrorMessage, type SftpEntry } from "@/bridge/types";
import type { Entry, LocationRef, SftpSession } from "@/store/sftp-types";
import { breadcrumbSegments, isSafeName, isPortableWindowsName, remoteJoin, remoteParent, type Crumb } from "@/sftp/paths";
import { dirname, join } from "@tauri-apps/api/path";
import { mkdir, remove, rename, stat, writeTextFile } from "@tauri-apps/plugin-fs";

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

export interface FileSource {
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
  /** Remove a directory (local: recursive; remote: empty-only until Phase 2). */
  rmdir(path: string): Promise<void>;
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
  private async withReopen<T>(fn: () => Promise<T>): Promise<T> {
    try {
      return await fn();
    } catch (e) {
      if (/cancelled|session closed|generation changed/i.test(apiErrorMessage(e)) || !isSftpDisconnect(apiErrorMessage(e))) throw e;
      await api.sftpReopen(this.id);
      return await fn(); // single retry — a truly dead SSH connection still throws
    }
  }
  async list(path: string, signal?: AbortSignal): Promise<Entry[]> {
    let list: SftpEntry[];
    if (this.cancelId) list = await api.sftpListDirCancel(this.id, path, this.cancelId);
    else if (signal) {
      const token = await api.cancelNew();
      const cancel = () => { void api.cancelTrigger(token); };
      signal.addEventListener("abort", cancel, { once: true });
      try {
        signal.throwIfAborted();
        list = await api.sftpListDirCancel(this.id, path, token);
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
      if (/\bstatus 2\b/.test(apiErrorMessage(error))) return null;
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
    return api.sftpRemove(this.id, path);
  }
  rmdir(path: string): Promise<void> {
    // Recursive — SFTP RMDIR only removes empty dirs (a non-empty one returns
    // SSH_FX_FAILURE / status 4); the core walks the tree bottom-up.
    return api.sftpRmdirRecursive(this.id, path);
  }
  rename(from: string, to: string): Promise<void> {
    return api.sftpRename(this.id, from, to);
  }
  commit(from: string, to: string, replace: boolean): Promise<void> { return api.sftpCommit(this.id, from, to, replace, this.cancelId); }
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
      await this.setMetadata(stage, metadata?.mode, metadata?.mtime);
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

// ── local (OS filesystem via @tauri-apps/plugin-fs) ────────────
class LocalSource implements FileSource {
  readonly kind = "local" as const;
  readonly id = "local";
  readonly label: string;
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
    try {
      const s = await stat(path);
      return {
        name: baseName(path),
        isDir: s.isDirectory,
        size: s.size,
        mtime: s.mtime ? Math.floor(s.mtime.getTime() / 1000) : undefined,
      };
    } catch (error) {
      if (/\bos error [23]\b|\bENOENT\b/i.test(apiErrorMessage(error))) return null;
      throw error;
    }
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
  commit(from: string, to: string, replace: boolean): Promise<void> { return api.localCommit(from, to, replace); }
  setMetadata(path: string, mode?: number, mtime?: number): Promise<void> { return api.localSetMetadata(path, mode === undefined ? undefined : mode & 0o777, mtime); }
  async mkdir(path: string): Promise<void> {
    await mkdir(path);
  }
  async createNew(path: string): Promise<void> {
    // O_CREAT|O_EXCL. writeTextFile would truncate an existing file instead.
    await api.localCreatePrivate(path);
  }
  async remove(path: string): Promise<void> {
    await remove(path);
  }
  async rmdir(path: string): Promise<void> {
    await remove(path, { recursive: true });
  }
  async rename(from: string, to: string): Promise<void> {
    await rename(from, to);
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
      await writeTextFile(stage, text);
      await this.setMetadata(stage, metadata?.mode, metadata?.mtime);
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
