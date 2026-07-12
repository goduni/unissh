// FileSource — a uniform façade over a browsable file location so the panes,
// drag/drop, and the transfer engine don't care whether a slot is the local OS
// filesystem or a remote SFTP session. Local path/fs calls go through the Tauri
// plugins (dynamically imported, matching the rest of the client); remote calls
// go through the bridge api.sftp*.

import * as api from "@/bridge/api";
import { apiErrorMessage, type SftpEntry } from "@/bridge/types";
import type { Entry, LocationRef, SftpSession } from "@/store/sftp-types";
import { breadcrumbSegments, isSafeName, remoteJoin, remoteParent, type Crumb } from "@/sftp/paths";

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
  kind: "local" | "remote";
  id: string;
  label: string;
  list(path: string): Promise<Entry[]>;
  /** Stat one path, or null if it does not exist (used for conflict checks). */
  stat(path: string): Promise<Entry | null>;
  realpath(path: string): Promise<string>;
  mkdir(path: string): Promise<void>;
  /** Remove a file. */
  remove(path: string): Promise<void>;
  /** Remove a directory (local: recursive; remote: empty-only until Phase 2). */
  rmdir(path: string): Promise<void>;
  rename(from: string, to: string): Promise<void>;
  /** Change unix permissions — remote only (local FS chmod isn't exposed). */
  chmod?(path: string, mode: number): Promise<void>;
  readText(path: string): Promise<string>;
  writeText(path: string, text: string): Promise<void>;
  join(base: string, name: string): Promise<string>;
  parent(path: string): Promise<string>;
  /** Clickable breadcrumb segments for `path` (sync; for display). */
  crumbs(path: string): Crumb[];
}

function baseName(path: string): string {
  const parts = path.split(/[\\/]/).filter(Boolean);
  return parts.length ? parts[parts.length - 1] : path;
}

// ── remote (SFTP session) ──────────────────────────────────────
class RemoteSource implements FileSource {
  readonly kind = "remote" as const;
  readonly id: string;
  readonly label: string;
  constructor(session: SftpSession) {
    this.id = session.id;
    this.label = session.label;
  }
  /** Run a remote op; if it fails because the SFTP channel was reaped by the
   *  server (e.g. "channel closed" on an idle session), reopen the channel once
   *  on the still-live SSH connection and retry. So a random mid-session drop
   *  self-heals instead of erroring, and Retry actually recovers. */
  private async withReopen<T>(fn: () => Promise<T>): Promise<T> {
    try {
      return await fn();
    } catch (e) {
      if (!isSftpDisconnect(apiErrorMessage(e))) throw e;
      await api.sftpReopen(this.id);
      return await fn(); // single retry — a truly dead SSH connection still throws
    }
  }
  async list(path: string): Promise<Entry[]> {
    const list = await this.withReopen(() => api.sftpListDir(this.id, path));
    return list
      .filter((e: SftpEntry) => isSafeName(e.filename)) // drop "."/".." and unsafe names
      .map((e: SftpEntry) => ({
        name: e.filename,
        isDir: e.isDir,
        size: e.size,
        mtime: e.mtime || undefined,
        mode: e.mode || undefined,
        uid: e.uid || undefined,
        gid: e.gid || undefined,
      }));
  }
  async stat(path: string): Promise<Entry | null> {
    try {
      const s = await this.withReopen(() => api.sftpStat(this.id, path));
      return {
        name: baseName(path),
        isDir: s.isDir,
        size: s.size,
        mtime: s.mtime || undefined,
        mode: s.mode || undefined,
      };
    } catch {
      return null;
    }
  }
  realpath(path: string): Promise<string> {
    return this.withReopen(() => api.sftpRealpath(this.id, path));
  }
  mkdir(path: string): Promise<void> {
    return this.withReopen(() => api.sftpMkdir(this.id, path));
  }
  remove(path: string): Promise<void> {
    return this.withReopen(() => api.sftpRemove(this.id, path));
  }
  rmdir(path: string): Promise<void> {
    // Recursive — SFTP RMDIR only removes empty dirs (a non-empty one returns
    // SSH_FX_FAILURE / status 4); the core walks the tree bottom-up.
    return this.withReopen(() => api.sftpRmdirRecursive(this.id, path));
  }
  rename(from: string, to: string): Promise<void> {
    return this.withReopen(() => api.sftpRename(this.id, from, to));
  }
  chmod(path: string, mode: number): Promise<void> {
    return this.withReopen(() => api.sftpChmod(this.id, path, mode));
  }
  async readText(path: string): Promise<string> {
    const buf = await this.withReopen(() => api.sftpReadFile(this.id, path));
    return new TextDecoder().decode(new Uint8Array(buf));
  }
  writeText(path: string, text: string): Promise<void> {
    const data = Array.from(new TextEncoder().encode(text));
    return this.withReopen(() => api.sftpWriteFile(this.id, path, data));
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
  constructor(label: string) {
    this.label = label;
  }
  async list(path: string): Promise<Entry[]> {
    // One IPC (name+isDir+size+mtime) instead of readDir + a stat per file.
    const list = await api.localListDir(path);
    return list
      .filter((e) => isSafeName(e.name))
      .map((e) => ({ name: e.name, isDir: e.isDir, size: e.size, mtime: e.mtime || undefined }));
  }
  async stat(path: string): Promise<Entry | null> {
    try {
      const { stat } = await import("@tauri-apps/plugin-fs");
      const s = await stat(path);
      return {
        name: baseName(path),
        isDir: s.isDirectory,
        size: s.size,
        mtime: s.mtime ? Math.floor(s.mtime.getTime() / 1000) : undefined,
      };
    } catch {
      return null;
    }
  }
  async realpath(path: string): Promise<string> {
    return path;
  }
  async mkdir(path: string): Promise<void> {
    const { mkdir } = await import("@tauri-apps/plugin-fs");
    await mkdir(path);
  }
  async remove(path: string): Promise<void> {
    const { remove } = await import("@tauri-apps/plugin-fs");
    await remove(path);
  }
  async rmdir(path: string): Promise<void> {
    const { remove } = await import("@tauri-apps/plugin-fs");
    await remove(path, { recursive: true });
  }
  async rename(from: string, to: string): Promise<void> {
    const { rename } = await import("@tauri-apps/plugin-fs");
    await rename(from, to);
  }
  async readText(path: string): Promise<string> {
    const { readTextFile } = await import("@tauri-apps/plugin-fs");
    return readTextFile(path);
  }
  async writeText(path: string, text: string): Promise<void> {
    const { writeTextFile } = await import("@tauri-apps/plugin-fs");
    await writeTextFile(path, text);
  }
  async join(base: string, name: string): Promise<string> {
    if (name === "..") return this.parent(base);
    const { join } = await import("@tauri-apps/api/path");
    return join(base, name);
  }
  async parent(path: string): Promise<string> {
    const { dirname } = await import("@tauri-apps/api/path");
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
