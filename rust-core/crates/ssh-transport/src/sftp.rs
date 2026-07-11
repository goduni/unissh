//! A minimal SFTP client (protocol version 3) on top of the SSH `sftp` subsystem.
//!
//! This is **not our own cryptography** — SFTP runs over the already-encrypted SSH
//! channel (russh). There is no `russh-sftp` available in the offline environment, so
//! the minimum of the protocol we need (draft-ietf-secsh-filexfer-02, v3) is
//! implemented by hand: directory listing, file read/write, stat, mkdir/rmdir, remove,
//! rename, realpath. One operation at a time (a single outstanding request) — the
//! client is sequential, which is enough for file-manager UI scenarios.
//!
//! Each packet: `uint32 length` + `byte type` + body. Requests carry a `uint32 id`.

use std::collections::{BTreeMap, HashMap};
use std::io::SeekFrom;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{timeout, Duration};

use crate::error::TransportError;

/// Transfer progress callback (implemented by the consumer, e.g. FFI).
pub trait SftpProgress: Send + Sync {
    /// `transferred` bytes out of `total` (total=0 if the size is unknown).
    fn on_progress(&self, transferred: u64, total: u64);
}

/// Cooperative transfer cancellation (checked between chunks).
pub trait SftpCancel: Send + Sync {
    /// Whether cancellation has been requested.
    fn is_cancelled(&self) -> bool;
}

/// The outcome of a resumable transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferOutcome {
    /// The transfer completed fully.
    Completed,
    /// Interrupted by a cancellation request (can be resumed from the current offset).
    Cancelled,
}

// --- packet types ---
const FXP_INIT: u8 = 1;
const FXP_VERSION: u8 = 2;
const FXP_OPEN: u8 = 3;
const FXP_CLOSE: u8 = 4;
const FXP_READ: u8 = 5;
const FXP_WRITE: u8 = 6;
const FXP_SETSTAT: u8 = 9;
const FXP_OPENDIR: u8 = 11;
const FXP_READDIR: u8 = 12;
const FXP_REMOVE: u8 = 13;
const FXP_MKDIR: u8 = 14;
const FXP_RMDIR: u8 = 15;
const FXP_REALPATH: u8 = 16;
const FXP_STAT: u8 = 17;
const FXP_RENAME: u8 = 18;
const FXP_STATUS: u8 = 101;
const FXP_HANDLE: u8 = 102;
const FXP_DATA: u8 = 103;
const FXP_NAME: u8 = 104;
const FXP_ATTRS: u8 = 105;

// --- status codes ---
const FX_OK: u32 = 0;
const FX_EOF: u32 = 1;

// --- file open flags ---
const FXF_READ: u32 = 0x1;
const FXF_WRITE: u32 = 0x2;
const FXF_CREAT: u32 = 0x8;
const FXF_TRUNC: u32 = 0x10;

// --- ATTRS flags ---
const ATTR_SIZE: u32 = 0x1;
const ATTR_UIDGID: u32 = 0x2;
const ATTR_PERMISSIONS: u32 = 0x4;
const ATTR_ACMODTIME: u32 = 0x8;
const ATTR_EXTENDED: u32 = 0x8000_0000;

// POSIX S_IFMT/S_IFDIR for determining "is a directory".
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;

/// Read/write chunk size. Larger than OpenSSH's classic 32 KiB: on "fat, long"
/// channels (high BDP) a bigger chunk reduces the share of per-packet overhead and
/// keeps the channel fuller. Must fit within russh's per-channel
/// `maximum_packet_size` (see `client_config`).
const CHUNK: usize = 128 * 1024;
/// Outstanding READ/WRITE requests kept in flight during a streaming transfer.
/// Throughput scales as WINDOW*CHUNK/RTT, so this lifts the per-RTT ceiling that
/// a single-request-at-a-time protocol imposes. Reorder buffer is WINDOW*CHUNK.
/// WINDOW*CHUNK (2 MiB here) must fit within russh's per-channel `window_size`,
/// otherwise the stream would hit SSH window control before the pipeline.
const WINDOW: usize = 16;
/// Protection against absurd packet lengths.
const MAX_PACKET: usize = 4 * 1024 * 1024;
/// Timeout for a single network exchange (protection against a hung/silent server:
/// otherwise the calling FFI thread would block forever).
const IO_TIMEOUT: Duration = Duration::from_secs(30);
/// Ceiling on the file size for `read_file` (we read it entirely into memory) —
/// protection against OOM when a malicious server sends an endless stream.
const MAX_READ_FILE: usize = 1024 * 1024 * 1024;
/// Ceiling on the pre-allocation of directory entries (the count in the reply is server-supplied).
const MAX_DIR_PREALLOC: usize = 4096;

/// A directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// File name (without the path).
    pub filename: String,
    /// Whether it is a directory.
    pub is_dir: bool,
    /// Size in bytes (if the server reported it).
    pub size: u64,
    /// Unix mode bits (full st_mode), 0 if the server did not report it.
    pub mode: u32,
    /// Modification time, seconds since the epoch; 0 if the server did not report it.
    pub mtime: u64,
}

/// The result of stat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileStat {
    /// Size in bytes.
    pub size: u64,
    /// Whether it is a directory.
    pub is_dir: bool,
    /// Unix mode bits (full st_mode), 0 if the server did not report it.
    pub mode: u32,
    /// Modification time, seconds since the epoch; 0 if the server did not report it.
    pub mtime: u64,
}

/// An SFTP session over an SSH channel stream.
pub struct Sftp<S> {
    stream: S,
    next_id: u32,
    /// The stream is desynchronized: an I/O break/timeout or an interrupted pipeline
    /// (unread replies remain). Such a channel must not be reused — the next
    /// operation would read someone else's/a stale reply. The pool owner checks this
    /// via [`Sftp::is_poisoned`] and discards the channel. A clean file error (the
    /// server sent FXP_STATUS, the stream is on a packet boundary) does NOT poison
    /// the channel — it stays usable.
    poisoned: bool,
}

impl<S> Sftp<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Starts the session: sends INIT(v3), awaits VERSION.
    pub(crate) async fn start(stream: S) -> Result<Self, TransportError> {
        let mut s = Sftp {
            stream,
            next_id: 0,
            poisoned: false,
        };
        let mut init = Vec::with_capacity(5);
        init.push(FXP_INIT);
        init.extend_from_slice(&3u32.to_be_bytes());
        s.send(&init).await?;
        let (typ, body) = s.read_packet().await?;
        if typ != FXP_VERSION {
            return Err(sftp_err("expected VERSION after INIT"));
        }
        // The server replies min(client, server); we read the version number (we
        // requested v3 — it is the lower bound, accept it as is).
        let mut r = Reader::new(&body);
        let _server_version = r.u32()?;
        Ok(s)
    }

    /// Lists a directory.
    pub async fn list_dir(&mut self, path: &str) -> Result<Vec<DirEntry>, TransportError> {
        let handle = self.opendir(path).await?;
        let mut out = Vec::new();
        while let Some(batch) = self.readdir(&handle).await? {
            out.extend(batch);
        }
        let _ = self.close(&handle).await;
        Ok(out)
    }

    /// Downloads a whole file.
    pub async fn read_file(&mut self, path: &str) -> Result<Vec<u8>, TransportError> {
        let handle = self.open(path, FXF_READ).await?;
        let mut out = Vec::with_capacity(CHUNK);
        let mut offset: u64 = 0;
        while let Some(data) = self.read_chunk(&handle, offset, CHUNK as u32).await? {
            if out.len().saturating_add(data.len()) > MAX_READ_FILE {
                let _ = self.close(&handle).await;
                return Err(sftp_err("file exceeds maximum in-memory read size"));
            }
            offset += data.len() as u64;
            out.extend_from_slice(&data);
        }
        let _ = self.close(&handle).await;
        Ok(out)
    }

    /// Uploads a file (creates/overwrites).
    pub async fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), TransportError> {
        let handle = self.open(path, FXF_WRITE | FXF_CREAT | FXF_TRUNC).await?;
        let mut offset: u64 = 0;
        for chunk in data.chunks(CHUNK) {
            self.write_chunk(&handle, offset, chunk).await?;
            offset += chunk.len() as u64;
        }
        self.close(&handle).await
    }

    /// Resumable download of `remote` → the local file `local_path`, starting
    /// from `start_offset` (for resuming). Writes in a streaming manner (removes the
    /// in-memory read limit), reports progress, checks for cancellation between chunks.
    /// On completion, truncates the local file to its actual end (if it was
    /// longer). Cancellation preserves the already-downloaded prefix.
    pub async fn download_to(
        &mut self,
        remote: &str,
        local_path: &str,
        start_offset: u64,
        known_size: Option<u64>,
        progress: Option<Arc<dyn SftpProgress>>,
        cancel: Option<Arc<dyn SftpCancel>>,
    ) -> Result<TransferOutcome, TransportError> {
        // The size is needed only to know how far to send READs. A recursive folder
        // walk already did a listing with sizes — then `known_size` provides it, and we
        // save a separate `stat` round-trip for EVERY file (the dominant
        // latency on "many files"). The EOF branch below correctly stops
        // reading if the file is actually shorter than the passed size (a stale listing).
        let total = match known_size {
            Some(sz) => sz,
            None => self.stat(remote).await?.size,
        };
        // start_offset past the end of remote → resuming is impossible, otherwise we
        // would silently get a corrupt/sparse local file reported as a success.
        if start_offset > total {
            return Err(sftp_err("resume offset is beyond remote file size"));
        }
        let handle = self.open(remote, FXF_READ).await?;
        // create(true) below won't make parent dirs — ensure them so a recursive
        // folder download (whose subdirs may not exist locally yet) can't fail.
        if let Some(parent) = std::path::Path::new(local_path).parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let mut f = tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(local_path)
            .await?;
        f.seek(SeekFrom::Start(start_offset)).await?;
        // Pipelined: keep WINDOW reads in flight; buffer out-of-order replies in
        // `reorder` and write to the local file only in contiguous order.
        let mut in_flight: HashMap<u32, (u64, u32)> = HashMap::new();
        let mut reorder: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        let mut write_offset = start_offset; // next contiguous byte to write
        let mut next_req = start_offset; // next byte to request
        let mut eof = false; // server signalled EOF (file shorter than stat)
        let mut outcome = TransferOutcome::Completed;
        loop {
            if cancel.as_ref().is_some_and(|c| c.is_cancelled()) {
                outcome = TransferOutcome::Cancelled;
                break;
            }
            while in_flight.len() < WINDOW && !eof && next_req < total {
                let len = std::cmp::min(CHUNK as u64, total - next_req) as u32;
                let id = self.send_read(&handle, next_req, len).await?;
                in_flight.insert(id, (next_req, len));
                next_req += len as u64;
            }
            if in_flight.is_empty() {
                break; // nothing pending and nothing left to request
            }
            let (typ, id, body) = self.recv_any().await?;
            // The errors below arrive with a NON-empty in_flight (unretrieved
            // replies remain) → the stream is desynchronized, the channel must not be reused.
            let Some((off, len)) = in_flight.remove(&id) else {
                return Err(self.poison(sftp_err("SFTP response id mismatch")));
            };
            match typ {
                FXP_DATA => {
                    let mut r = Reader::new(&body);
                    r.u32()?; // id
                    let data = r.string()?;
                    if data.is_empty() {
                        return Err(self.poison(sftp_err("empty DATA chunk")));
                    }
                    let got = data.len() as u64;
                    // Short read (legal): re-request the remaining sub-range.
                    if got < len as u64 && off + got < total {
                        let rlen = std::cmp::min(len as u64 - got, total - (off + got)) as u32;
                        let id2 = self.send_read(&handle, off + got, rlen).await?;
                        in_flight.insert(id2, (off + got, rlen));
                    }
                    reorder.insert(off, data);
                    while let Some(buf) = reorder.remove(&write_offset) {
                        f.write_all(&buf).await?;
                        write_offset += buf.len() as u64;
                    }
                    if let Some(p) = &progress {
                        p.on_progress(write_offset, total);
                    }
                }
                FXP_STATUS => {
                    let mut r = Reader::new(&body);
                    r.u32()?; // id
                    let code = r.u32()?;
                    if code == FX_EOF {
                        eof = true; // shorter than stat said; stop requesting, drain rest
                    } else {
                        let e = status_to_err(code, &mut r);
                        return Err(self.poison(e));
                    }
                }
                _ => return Err(self.poison(sftp_err("unexpected reply to READ"))),
            }
        }
        // Drain replies still in flight (cancel/short) so the channel is left
        // clean for the next operation; bounded by the per-read IO timeout.
        while !in_flight.is_empty() {
            match self.recv_any().await {
                Ok((_, id, _)) => {
                    in_flight.remove(&id);
                }
                Err(_) => break,
            }
        }
        let _ = self.close(&handle).await;
        if outcome == TransferOutcome::Completed {
            // Truncate any old tail beyond the actual end.
            f.set_len(write_offset).await?;
        }
        f.flush().await?;
        Ok(outcome)
    }

    /// Resumable upload of the local `local_path` → `remote`, starting from
    /// `start_offset`. Opens the remote file `WRITE|CREAT` **without TRUNC** (so as
    /// not to wipe the already-uploaded prefix when resuming). Progress/cancellation as in
    /// [`Sftp::download_to`].
    pub async fn upload_from(
        &mut self,
        local_path: &str,
        remote: &str,
        start_offset: u64,
        progress: Option<Arc<dyn SftpProgress>>,
        cancel: Option<Arc<dyn SftpCancel>>,
    ) -> Result<TransferOutcome, TransportError> {
        let mut f = tokio::fs::File::open(local_path).await?;
        let total = f.metadata().await?.len();
        f.seek(SeekFrom::Start(start_offset)).await?;
        // A fresh write (offset 0) truncates so a smaller file can't leave the
        // larger previous file's stale tail behind; a resume (offset > 0) keeps
        // the already-uploaded prefix.
        let mut flags = FXF_WRITE | FXF_CREAT;
        if start_offset == 0 {
            flags |= FXF_TRUNC;
        }
        let handle = self.open(remote, flags).await?;
        // Pipelined: keep WINDOW writes in flight; progress tracks acked bytes.
        let mut in_flight: HashMap<u32, u32> = HashMap::new();
        let mut acked = start_offset;
        let mut next_offset = start_offset;
        let mut eof = false;
        let mut outcome = TransferOutcome::Completed;
        let mut buf = vec![0u8; CHUNK];
        loop {
            if cancel.as_ref().is_some_and(|c| c.is_cancelled()) {
                outcome = TransferOutcome::Cancelled;
                break;
            }
            while in_flight.len() < WINDOW && !eof {
                let n = f.read(&mut buf).await?;
                if n == 0 {
                    eof = true;
                    break;
                }
                let id = self.send_write(&handle, next_offset, &buf[..n]).await?;
                in_flight.insert(id, n as u32);
                next_offset += n as u64;
            }
            if in_flight.is_empty() {
                break;
            }
            let (typ, id, body) = self.recv_any().await?;
            // As in download_to: errors with a non-empty in_flight desynchronize the
            // stream → the channel is unfit for reuse.
            let Some(len) = in_flight.remove(&id) else {
                return Err(self.poison(sftp_err("SFTP response id mismatch")));
            };
            if typ != FXP_STATUS {
                return Err(self.poison(sftp_err("expected STATUS")));
            }
            let mut r = Reader::new(&body);
            r.u32()?; // id
            let code = r.u32()?;
            if code != FX_OK {
                let e = status_to_err(code, &mut r);
                return Err(self.poison(e));
            }
            acked += len as u64;
            if let Some(p) = &progress {
                p.on_progress(acked, total);
            }
        }
        while !in_flight.is_empty() {
            match self.recv_any().await {
                Ok((_, id, _)) => {
                    in_flight.remove(&id);
                }
                Err(_) => break,
            }
        }
        self.close(&handle).await?;
        Ok(outcome)
    }

    /// stat by path.
    pub async fn stat(&mut self, path: &str) -> Result<FileStat, TransportError> {
        let id = self.alloc_id();
        let mut b = vec![FXP_STAT];
        b.extend_from_slice(&id.to_be_bytes());
        put_string(&mut b, path.as_bytes());
        self.send(&b).await?;
        let (typ, body) = self.read_for(id).await?;
        if typ != FXP_ATTRS {
            return Err(self.as_status_err(typ, &body));
        }
        let mut r = Reader::new(&body);
        r.u32()?; // id
        let (size, perms, mtime) = parse_attrs(&mut r)?;
        Ok(FileStat {
            size: size.unwrap_or(0),
            is_dir: perms.map(is_dir_perm).unwrap_or(false),
            mode: perms.unwrap_or(0),
            mtime: mtime.map(u64::from).unwrap_or(0),
        })
    }

    /// Creates a directory.
    pub async fn mkdir(&mut self, path: &str) -> Result<(), TransportError> {
        let id = self.alloc_id();
        let mut b = vec![FXP_MKDIR];
        b.extend_from_slice(&id.to_be_bytes());
        put_string(&mut b, path.as_bytes());
        b.extend_from_slice(&0u32.to_be_bytes()); // ATTRS flags = 0
        self.send(&b).await?;
        self.expect_ok(id).await
    }

    /// Removes a directory.
    pub async fn rmdir(&mut self, path: &str) -> Result<(), TransportError> {
        self.one_path(FXP_RMDIR, path).await
    }

    /// Removes a file.
    pub async fn remove(&mut self, path: &str) -> Result<(), TransportError> {
        self.one_path(FXP_REMOVE, path).await
    }

    /// Recursively removes a directory with all its contents (like `rm -rf`): bottom-up
    /// — first the contents of subdirectories and files, then the directory itself. SFTP
    /// `RMDIR` removes only an **empty** directory (otherwise the server returns
    /// FAILURE/status 4), so we walk the tree by hand. We do not dereference symlinks —
    /// they arrive as `is_dir == false` and are deleted by `remove` (unlink does not
    /// touch the target).
    pub async fn remove_tree(&mut self, path: &str) -> Result<(), TransportError> {
        for e in self.list_dir(path).await? {
            // readdir also returns "."/"..": skip them, otherwise we loop / wipe the parent.
            if e.filename == "." || e.filename == ".." {
                continue;
            }
            let child = format!("{}/{}", path.trim_end_matches('/'), e.filename);
            if e.is_dir {
                // Recursion in async requires boxing the future.
                Box::pin(self.remove_tree(&child)).await?;
            } else {
                self.remove(&child).await?;
            }
        }
        self.rmdir(path).await
    }

    /// Renames/moves.
    pub async fn rename(&mut self, from: &str, to: &str) -> Result<(), TransportError> {
        let id = self.alloc_id();
        let mut b = vec![FXP_RENAME];
        b.extend_from_slice(&id.to_be_bytes());
        put_string(&mut b, from.as_bytes());
        put_string(&mut b, to.as_bytes());
        self.send(&b).await?;
        self.expect_ok(id).await
    }

    /// Changes access permissions (chmod) via FXP_SETSTAT with ATTR_PERMISSIONS. `mode`
    /// is masked to the low 12 bits (rwx + setuid/setgid/sticky), just as the
    /// stock OpenSSH sftp client does.
    pub async fn chmod(&mut self, path: &str, mode: u32) -> Result<(), TransportError> {
        let id = self.alloc_id();
        let mut b = vec![FXP_SETSTAT];
        b.extend_from_slice(&id.to_be_bytes());
        put_string(&mut b, path.as_bytes());
        b.extend_from_slice(&ATTR_PERMISSIONS.to_be_bytes()); // flags = 0x4
        b.extend_from_slice(&(mode & 0o7777).to_be_bytes());
        self.send(&b).await?;
        self.expect_ok(id).await
    }

    /// Canonicalizes a path (`realpath`).
    pub async fn realpath(&mut self, path: &str) -> Result<String, TransportError> {
        let id = self.alloc_id();
        let mut b = vec![FXP_REALPATH];
        b.extend_from_slice(&id.to_be_bytes());
        put_string(&mut b, path.as_bytes());
        self.send(&b).await?;
        let (typ, body) = self.read_for(id).await?;
        if typ != FXP_NAME {
            return Err(self.as_status_err(typ, &body));
        }
        let mut r = Reader::new(&body);
        r.u32()?; // id
        let count = r.u32()?;
        if count == 0 {
            return Err(sftp_err("empty realpath response"));
        }
        let name = r.string_utf8()?;
        Ok(name)
    }

    // --- internal: handle operations ---

    async fn open(&mut self, path: &str, pflags: u32) -> Result<Vec<u8>, TransportError> {
        let id = self.alloc_id();
        let mut b = vec![FXP_OPEN];
        b.extend_from_slice(&id.to_be_bytes());
        put_string(&mut b, path.as_bytes());
        b.extend_from_slice(&pflags.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes()); // ATTRS flags = 0
        self.send(&b).await?;
        self.expect_handle(id).await
    }

    async fn opendir(&mut self, path: &str) -> Result<Vec<u8>, TransportError> {
        let id = self.alloc_id();
        let mut b = vec![FXP_OPENDIR];
        b.extend_from_slice(&id.to_be_bytes());
        put_string(&mut b, path.as_bytes());
        self.send(&b).await?;
        self.expect_handle(id).await
    }

    async fn close(&mut self, handle: &[u8]) -> Result<(), TransportError> {
        let id = self.alloc_id();
        let mut b = vec![FXP_CLOSE];
        b.extend_from_slice(&id.to_be_bytes());
        put_string(&mut b, handle);
        self.send(&b).await?;
        self.expect_ok(id).await
    }

    async fn read_chunk(
        &mut self,
        handle: &[u8],
        offset: u64,
        len: u32,
    ) -> Result<Option<Vec<u8>>, TransportError> {
        let id = self.alloc_id();
        let mut b = vec![FXP_READ];
        b.extend_from_slice(&id.to_be_bytes());
        put_string(&mut b, handle);
        b.extend_from_slice(&offset.to_be_bytes());
        b.extend_from_slice(&len.to_be_bytes());
        self.send(&b).await?;
        let (typ, body) = self.read_for(id).await?;
        match typ {
            FXP_DATA => {
                let mut r = Reader::new(&body);
                r.u32()?; // id
                let data = r.string()?;
                // A conformant server signals EOF via STATUS/EOF; an empty DATA does
                // not advance the offset → we treat it as an anomaly (otherwise an endless loop).
                if data.is_empty() {
                    return Err(sftp_err("empty DATA chunk"));
                }
                Ok(Some(data))
            }
            FXP_STATUS => {
                let mut r = Reader::new(&body);
                r.u32()?; // id
                let code = r.u32()?;
                if code == FX_EOF {
                    Ok(None)
                } else {
                    Err(status_to_err(code, &mut r))
                }
            }
            _ => Err(sftp_err("unexpected reply to READ")),
        }
    }

    async fn write_chunk(
        &mut self,
        handle: &[u8],
        offset: u64,
        data: &[u8],
    ) -> Result<(), TransportError> {
        let id = self.alloc_id();
        let mut b = vec![FXP_WRITE];
        b.extend_from_slice(&id.to_be_bytes());
        put_string(&mut b, handle);
        b.extend_from_slice(&offset.to_be_bytes());
        put_string(&mut b, data);
        self.send(&b).await?;
        self.expect_ok(id).await
    }

    /// Send a READ without awaiting its reply (returns the request id). Used by
    /// the pipelined `download_to`.
    async fn send_read(
        &mut self,
        handle: &[u8],
        offset: u64,
        len: u32,
    ) -> Result<u32, TransportError> {
        let id = self.alloc_id();
        let mut b = vec![FXP_READ];
        b.extend_from_slice(&id.to_be_bytes());
        put_string(&mut b, handle);
        b.extend_from_slice(&offset.to_be_bytes());
        b.extend_from_slice(&len.to_be_bytes());
        self.send(&b).await?;
        Ok(id)
    }

    /// Send a WRITE without awaiting its STATUS (returns the request id). Used by
    /// the pipelined `upload_from`.
    async fn send_write(
        &mut self,
        handle: &[u8],
        offset: u64,
        data: &[u8],
    ) -> Result<u32, TransportError> {
        let id = self.alloc_id();
        let mut b = vec![FXP_WRITE];
        b.extend_from_slice(&id.to_be_bytes());
        put_string(&mut b, handle);
        b.extend_from_slice(&offset.to_be_bytes());
        put_string(&mut b, data);
        self.send(&b).await?;
        Ok(id)
    }

    /// Receive the next reply without requiring a specific id (for pipelined
    /// transfers with multiple requests in flight).
    async fn recv_any(&mut self) -> Result<(u8, u32, Vec<u8>), TransportError> {
        let (typ, body) = self.read_packet().await?;
        if body.len() < 4 {
            return Err(self.poison(sftp_err("short SFTP reply")));
        }
        let id = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
        Ok((typ, id, body))
    }

    async fn readdir(&mut self, handle: &[u8]) -> Result<Option<Vec<DirEntry>>, TransportError> {
        let id = self.alloc_id();
        let mut b = vec![FXP_READDIR];
        b.extend_from_slice(&id.to_be_bytes());
        put_string(&mut b, handle);
        self.send(&b).await?;
        let (typ, body) = self.read_for(id).await?;
        match typ {
            FXP_NAME => {
                let mut r = Reader::new(&body);
                r.u32()?; // id
                let count = r.u32()?;
                // count is server-supplied; we bound the pre-allocation (the Vec will grow
                // if needed), otherwise a malicious count → OOM.
                let mut out = Vec::with_capacity((count as usize).min(MAX_DIR_PREALLOC));
                for _ in 0..count {
                    let filename = r.string_utf8()?;
                    r.skip_string()?; // longname (ls -l) — not needed, do not allocate
                    let (size, perms, mtime) = parse_attrs(&mut r)?;
                    out.push(DirEntry {
                        filename,
                        is_dir: perms.map(is_dir_perm).unwrap_or(false),
                        size: size.unwrap_or(0),
                        mode: perms.unwrap_or(0),
                        mtime: mtime.map(u64::from).unwrap_or(0),
                    });
                }
                Ok(Some(out))
            }
            FXP_STATUS => {
                let mut r = Reader::new(&body);
                r.u32()?; // id
                let code = r.u32()?;
                if code == FX_EOF {
                    Ok(None)
                } else {
                    Err(status_to_err(code, &mut r))
                }
            }
            _ => Err(sftp_err("unexpected reply to READDIR")),
        }
    }

    async fn one_path(&mut self, typ: u8, path: &str) -> Result<(), TransportError> {
        let id = self.alloc_id();
        let mut b = vec![typ];
        b.extend_from_slice(&id.to_be_bytes());
        put_string(&mut b, path.as_bytes());
        self.send(&b).await?;
        self.expect_ok(id).await
    }

    // --- internal: receiving/parsing replies ---

    async fn expect_handle(&mut self, id: u32) -> Result<Vec<u8>, TransportError> {
        let (typ, body) = self.read_for(id).await?;
        if typ != FXP_HANDLE {
            return Err(self.as_status_err(typ, &body));
        }
        let mut r = Reader::new(&body);
        r.u32()?; // id
        r.string()
    }

    async fn expect_ok(&mut self, id: u32) -> Result<(), TransportError> {
        let (typ, body) = self.read_for(id).await?;
        if typ != FXP_STATUS {
            return Err(sftp_err("expected STATUS"));
        }
        let mut r = Reader::new(&body);
        r.u32()?; // id
        let code = r.u32()?;
        if code == FX_OK {
            Ok(())
        } else {
            Err(status_to_err(code, &mut r))
        }
    }

    /// Turns an unexpected reply (not the one awaited) into a meaningful error:
    /// if it is a STATUS — extracts the code/message.
    fn as_status_err(&self, typ: u8, body: &[u8]) -> TransportError {
        if typ == FXP_STATUS {
            let mut r = Reader::new(body);
            if r.u32().is_ok() {
                if let Ok(code) = r.u32() {
                    return status_to_err(code, &mut r);
                }
            }
        }
        sftp_err("unexpected SFTP reply")
    }

    /// Reads the packet belonging to request `want_id` (a sequential client:
    /// the reply id must match).
    async fn read_for(&mut self, want_id: u32) -> Result<(u8, Vec<u8>), TransportError> {
        let (typ, body) = self.read_packet().await?;
        if body.len() < 4 {
            return Err(self.poison(sftp_err("short SFTP reply")));
        }
        let id = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
        if id != want_id {
            return Err(self.poison(sftp_err("SFTP response id mismatch")));
        }
        Ok((typ, body))
    }

    fn alloc_id(&mut self) -> u32 {
        self.next_id = self.next_id.wrapping_add(1);
        self.next_id
    }

    /// Whether the channel is poisoned (see [`Sftp::poisoned`]). The pool owner checks this
    /// before returning the channel to the pool: a poisoned one is discarded, a usable one
    /// is reused even after an operation error.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Marks the channel poisoned and returns the passed error — for concise
    /// `return self.poison(err)` on paths where the stream is desynchronized.
    fn poison(&mut self, e: TransportError) -> TransportError {
        self.poisoned = true;
        e
    }

    async fn send(&mut self, body: &[u8]) -> Result<(), TransportError> {
        let r = self.send_raw(body).await;
        if r.is_err() {
            // A write/flush error = a partial write, the stream is in an unknown state.
            self.poisoned = true;
        }
        r
    }

    async fn send_raw(&mut self, body: &[u8]) -> Result<(), TransportError> {
        // Length and body — in a single buffer/write (otherwise two channel packets per one
        // SFTP packet). With a timeout, so that a hung channel does not block forever.
        let mut framed = Vec::with_capacity(4 + body.len());
        framed.extend_from_slice(&(body.len() as u32).to_be_bytes());
        framed.extend_from_slice(body);
        timeout(IO_TIMEOUT, self.stream.write_all(&framed))
            .await
            .map_err(|_| sftp_err("write timeout"))??;
        timeout(IO_TIMEOUT, self.stream.flush())
            .await
            .map_err(|_| sftp_err("flush timeout"))??;
        Ok(())
    }

    async fn read_packet(&mut self) -> Result<(u8, Vec<u8>), TransportError> {
        let r = self.read_packet_raw().await;
        if r.is_err() {
            // A break/timeout/corrupt length = the position in the stream is unknown.
            self.poisoned = true;
        }
        r
    }

    async fn read_packet_raw(&mut self) -> Result<(u8, Vec<u8>), TransportError> {
        let mut len_buf = [0u8; 4];
        timeout(IO_TIMEOUT, self.stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| sftp_err("read timeout"))??;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 || len > MAX_PACKET {
            return Err(sftp_err("invalid SFTP packet length"));
        }
        let mut buf = vec![0u8; len];
        timeout(IO_TIMEOUT, self.stream.read_exact(&mut buf))
            .await
            .map_err(|_| sftp_err("read timeout"))??;
        let typ = buf[0];
        Ok((typ, buf.split_off(1)))
    }
}

// --- encoding/decoding helpers ---

fn put_string(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

fn is_dir_perm(perms: u32) -> bool {
    perms & S_IFMT == S_IFDIR
}

fn sftp_err(msg: &str) -> TransportError {
    TransportError::Sftp(msg.to_string())
}

fn status_to_err(code: u32, r: &mut Reader<'_>) -> TransportError {
    let msg = r.string_utf8().unwrap_or_default();
    if msg.is_empty() {
        TransportError::Sftp(format!("status {code}"))
    } else {
        TransportError::Sftp(format!("status {code}: {msg}"))
    }
}

/// `(size, permissions, mtime)` from the ATTRS block; a field is `None` if the server did not send it.
type ParsedAttrs = (Option<u64>, Option<u32>, Option<u32>);

/// Parses the ATTRS block, advancing the cursor. Returns `(size, permissions, mtime)`.
fn parse_attrs(r: &mut Reader<'_>) -> Result<ParsedAttrs, TransportError> {
    let flags = r.u32()?;
    let mut size = None;
    let mut perms = None;
    let mut mtime = None;
    if flags & ATTR_SIZE != 0 {
        size = Some(r.u64()?);
    }
    if flags & ATTR_UIDGID != 0 {
        r.u32()?;
        r.u32()?;
    }
    if flags & ATTR_PERMISSIONS != 0 {
        perms = Some(r.u32()?);
    }
    if flags & ATTR_ACMODTIME != 0 {
        r.u32()?; // atime — not needed
        mtime = Some(r.u32()?); // mtime (seconds since the epoch)
    }
    if flags & ATTR_EXTENDED != 0 {
        let count = r.u32()?;
        for _ in 0..count {
            r.string()?;
            r.string()?;
        }
    }
    Ok((size, perms, mtime))
}

/// A read cursor over the bytes of a reply (big-endian, SSH strings).
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], TransportError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| sftp_err("length overflow"))?;
        if end > self.data.len() {
            return Err(sftp_err("truncated SFTP field"));
        }
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u32(&mut self) -> Result<u32, TransportError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64, TransportError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }

    fn string(&mut self) -> Result<Vec<u8>, TransportError> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }

    /// Skips an SSH string without allocating (for unneeded fields, e.g. longname).
    fn skip_string(&mut self) -> Result<(), TransportError> {
        let n = self.u32()? as usize;
        self.take(n)?;
        Ok(())
    }

    fn string_utf8(&mut self) -> Result<String, TransportError> {
        let bytes = self.string()?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_attrs_extracts_size_perms_mtime() {
        let mut buf = Vec::new();
        let flags = ATTR_SIZE | ATTR_PERMISSIONS | ATTR_ACMODTIME;
        buf.extend_from_slice(&flags.to_be_bytes());
        buf.extend_from_slice(&1234u64.to_be_bytes()); // size
        buf.extend_from_slice(&0o100644u32.to_be_bytes()); // perms: regular file rw-r--r--
        buf.extend_from_slice(&111u32.to_be_bytes()); // atime — discarded
        buf.extend_from_slice(&1_700_000_000u32.to_be_bytes()); // mtime
        let mut r = Reader::new(&buf);
        let (size, perms, mtime) = parse_attrs(&mut r).unwrap();
        assert_eq!(size, Some(1234));
        assert_eq!(perms, Some(0o100644));
        assert_eq!(mtime, Some(1_700_000_000));
        assert!(!is_dir_perm(perms.unwrap()));
    }

    #[test]
    fn parse_attrs_handles_absent_mtime_and_perms() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&ATTR_SIZE.to_be_bytes()); // size only
        buf.extend_from_slice(&42u64.to_be_bytes());
        let mut r = Reader::new(&buf);
        let (size, perms, mtime) = parse_attrs(&mut r).unwrap();
        assert_eq!(size, Some(42));
        assert_eq!(perms, None);
        assert_eq!(mtime, None);
    }
}
