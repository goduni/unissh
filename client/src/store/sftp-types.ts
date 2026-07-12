// SFTP redesign — shared types for the multi-location, drag-first file manager.
// Kept out of app.ts so the store file stays lean; consumed by the store slice,
// the FileSource adapters, the transfer engine, and the views.

/** A single row in a pane — unified across local FS and remote SFTP. `mtime`
 *  (epoch seconds) and `mode` (unix permission bits) are optional: the remote
 *  listing only carries them once the core surfaces them (redesign Phase 3),
 *  and the local adapter fills what the OS gives. */
export interface Entry {
  name: string;
  isDir: boolean;
  size: number;
  mtime?: number;
  mode?: number;
  /** Numeric owner uid/gid from the remote listing (once the core surfaces them). */
  uid?: number;
  gid?: number;
}

/** Which location a pane-slot / tab points at. "local" is a single virtual
 *  location; every remote tab maps 1:1 to an open SftpSession by id. */
export type LocationRef =
  | { kind: "local" }
  | { kind: "remote"; sessionId: string }
  | { kind: "none" }; // empty slot showing a "pick a host" prompt

/** A live remote SFTP session — held in the store like terminals/tunnels so it
 *  survives route changes and is torn down on vault switch/lock. Holds only the
 *  connection identity; per-slot browsing state (cwd/entries/selection) lives in
 *  the pane, since two slots may show the same session at different paths. */
export interface SftpSession {
  id: string; // opaque bridge session id (api.sftpOpen)
  profileId: string;
  host: string;
  user: string;
  port: number;
  label: string; // "user@host"
  home: string; // realpath('.') — the initial directory
}

export type SortKey = "name" | "size" | "mtime" | "mode";
export interface SortState {
  key: SortKey;
  dir: "asc" | "desc";
}

export type TransferState =
  | "queued"
  | "scanning"
  | "active"
  | "paused"
  | "done"
  | "error"
  | "cancelled";

/** How a name collision at the destination is resolved. `resume` is only
 *  offered when a strictly shorter partial already exists at the target. */
export type ConflictChoice = "overwrite" | "skip" | "keepboth" | "resume";

/** One queued/active transfer. A `dir` transfer is a group whose totals are the
 *  sum of its recursively-enumerated files (filled in during `scanning`). */
export interface Transfer {
  id: string;
  label: string; // display name (file/folder name)
  from: LocationRef;
  to: LocationRef;
  toDir: string; // destination directory on the target source
  fromPath: string; // absolute source path
  kind: "file" | "dir";
  bytesDone: number;
  bytesTotal: number;
  filesDone: number;
  filesTotal: number;
  speedBps: number;
  etaSec: number;
  state: TransferState;
  error?: string;
  cancelId?: string; // bridge cancel-token id for the active leg
  offset: number; // resume point in bytes
}
