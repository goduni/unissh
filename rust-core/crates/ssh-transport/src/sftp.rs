//! A minimal SFTP client (protocol version 3) on top of the SSH `sftp` subsystem.
//!
//! This is **not our own cryptography** — SFTP runs over the already-encrypted SSH
//! channel (russh). There is no `russh-sftp` available in the offline environment, so
//! the minimum of the protocol we need (draft-ietf-secsh-filexfer-02, v3) is
//! implemented by hand: directory listing, file read/write, stat, mkdir/rmdir, remove,
//! rename, realpath. File transfers pipeline requests with bounded buffering;
//! independent operations use separate channels leased by the FFI pool.
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

/// Cooperative transfer cancellation (also checked while waiting for network I/O).
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
const FXP_LSTAT: u8 = 7;
const FXP_SETSTAT: u8 = 9;
const FXP_OPENDIR: u8 = 11;
const FXP_READDIR: u8 = 12;
const FXP_REMOVE: u8 = 13;
const FXP_MKDIR: u8 = 14;
const FXP_RMDIR: u8 = 15;
const FXP_REALPATH: u8 = 16;
const FXP_STAT: u8 = 17;
const FXP_RENAME: u8 = 18;
const FXP_READLINK: u8 = 19;
const FXP_SYMLINK: u8 = 20;
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
const FXF_EXCL: u32 = 0x20;

// --- ATTRS flags ---
const ATTR_SIZE: u32 = 0x1;
const ATTR_UIDGID: u32 = 0x2;
const ATTR_PERMISSIONS: u32 = 0x4;
const ATTR_ACMODTIME: u32 = 0x8;
const ATTR_EXTENDED: u32 = 0x8000_0000;

// POSIX S_IFMT/S_IFDIR for determining "is a directory".
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;

/// Conservative SFTP v3 payload size; SSH packet limits do not imply SFTP limits.
const CHUNK: usize = 32 * 1024;
/// Outstanding READ/WRITE requests kept in flight during a streaming transfer.
/// Throughput scales as WINDOW*CHUNK/RTT, so this lifts the per-RTT ceiling that
/// a single-request-at-a-time protocol imposes. Reorder buffer is WINDOW*CHUNK.
/// WINDOW*CHUNK (512 KiB here) must fit within russh's per-channel `window_size`,
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
    /// Whether the server supplied SIZE; zero without this flag is not an empty file.
    pub size_known: bool,
    /// Unix mode bits (full st_mode), 0 if the server did not report it.
    pub mode: u32,
    /// Modification time, seconds since the epoch; 0 if the server did not report it.
    pub mtime: u64,
    /// Owner uid (numeric), 0 if the server did not report it.
    pub uid: u32,
    /// Owner gid (numeric), 0 if the server did not report it.
    pub gid: u32,
}

/// The result of stat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileStat {
    /// Size in bytes.
    pub size: u64,
    /// Whether the server supplied SIZE; zero without this flag is not an empty file.
    pub size_known: bool,
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
    cancel: Option<Arc<dyn SftpCancel>>,
    posix_rename: bool,
    lifetime_cancel: Option<Arc<dyn SftpCancel>>,
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
            cancel: None,
            posix_rename: false,
            lifetime_cancel: None,
        };
        let mut init = Vec::with_capacity(5);
        init.push(FXP_INIT);
        init.extend_from_slice(&3u32.to_be_bytes());
        s.send(&init).await?;
        let (typ, body) = s.read_packet().await?;
        if typ != FXP_VERSION {
            return Err(sftp_err("expected VERSION after INIT"));
        }
        let mut r = Reader::new(&body);
        if r.u32()? != 3 {
            return Err(sftp_err("unsupported SFTP version (expected v3)"));
        }
        while r.pos < body.len() {
            let name = r.string_utf8()?;
            let version = r.string_utf8()?;
            if name == "posix-rename@openssh.com" && version == "1" {
                s.posix_rename = true;
            }
        }
        Ok(s)
    }

    /// Cancellation shared by every leased channel of this session.
    pub fn set_lifetime_cancel(&mut self, cancel: Arc<dyn SftpCancel>) {
        self.lifetime_cancel = Some(cancel);
    }

    /// Set/clear the cancellation scope of one metadata operation.
    pub fn set_operation_cancel(&mut self, cancel: Option<Arc<dyn SftpCancel>>) {
        self.cancel = cancel;
    }

    /// Lists a directory.
    pub async fn list_dir(&mut self, path: &str) -> Result<Vec<DirEntry>, TransportError> {
        let handle = self.opendir(path).await?;
        let result = timeout(Duration::from_secs(300), async {
            let mut out = Vec::new();
            while let Some(batch) = self.readdir(&handle).await? {
                out.extend(batch);
            }
            Ok(out)
        })
        .await;
        match result {
            Err(_) => Err(self.poison(sftp_err("directory listing deadline exceeded"))),
            Ok(result) => {
                let close = self.close(&handle).await;
                if close.is_err() {
                    self.poisoned = true;
                }
                result.and_then(|out| close.map(|()| out))
            }
        }
    }

    /// Downloads a whole file with a hard allocation bound.
    pub async fn read_file(&mut self, path: &str) -> Result<Vec<u8>, TransportError> {
        self.read_file_bounded(path, MAX_READ_FILE).await
    }

    /// The limit is checked against actual DATA, including when metadata is stale.
    pub async fn read_file_bounded(
        &mut self,
        path: &str,
        limit: usize,
    ) -> Result<Vec<u8>, TransportError> {
        let handle = self.open(path, FXF_READ).await?;
        let result = async {
            let mut out = Vec::with_capacity(CHUNK.min(limit));
            while let Some(data) = self
                .read_chunk(&handle, out.len() as u64, CHUNK as u32)
                .await?
            {
                if out.len().saturating_add(data.len()) > limit {
                    return Err(sftp_err("file exceeds maximum in-memory read size"));
                }
                out.extend_from_slice(&data);
            }
            Ok(out)
        }
        .await;
        let close = self.close(&handle).await;
        if close.is_err() {
            self.poisoned = true;
        }
        result.and_then(|out| close.map(|()| out))
    }

    /// Hash actual content without allocating a whole editor file.
    pub async fn fingerprint(&mut self, path: &str) -> Result<Vec<u8>, TransportError> {
        use sha2::{Digest, Sha256};
        let handle = self.open(path, FXF_READ).await?;
        let result = async {
            let mut digest = Sha256::new();
            let mut offset = 0;
            while let Some(data) = self.read_chunk(&handle, offset, CHUNK as u32).await? {
                offset += data.len() as u64;
                if offset > 256 * 1024 * 1024 {
                    return Err(sftp_err("file exceeds editor size limit"));
                }
                digest.update(data);
            }
            Ok(digest.finalize().to_vec())
        }
        .await;
        let close = self.close(&handle).await;
        if close.is_err() {
            self.poisoned = true;
        }
        result.and_then(|hash| close.map(|()| hash))
    }

    /// Uploads a file (creates/overwrites).
    pub async fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), TransportError> {
        let handle = self.open(path, FXF_WRITE | FXF_CREAT | FXF_TRUNC).await?;
        let result = async {
            let mut offset: u64 = 0;
            for chunk in data.chunks(CHUNK) {
                self.write_chunk(&handle, offset, chunk).await?;
                offset += chunk.len() as u64;
            }
            self.close(&handle).await
        }
        .await;
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    /// Creates an empty file, failing if `path` already exists.
    ///
    /// The exclusivity is the server's to enforce: a stat-then-write from the
    /// caller has a window in which another writer wins the race and gets its
    /// file truncated. `EXCL` closes it inside the one OPEN.
    pub async fn create_new(&mut self, path: &str) -> Result<(), TransportError> {
        let handle = self.open(path, FXF_WRITE | FXF_CREAT | FXF_EXCL).await?;
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
        self.download_with_file(
            remote,
            local_path,
            start_offset,
            known_size,
            progress,
            cancel,
            None,
        )
        .await
    }

    /// Download into an already open private file (e.g. an anonymous relay scratch).
    pub async fn download_to_file(
        &mut self,
        remote: &str,
        file: tokio::fs::File,
        progress: Option<Arc<dyn SftpProgress>>,
        cancel: Option<Arc<dyn SftpCancel>>,
    ) -> Result<TransferOutcome, TransportError> {
        self.download_with_file(remote, "", 0, None, progress, cancel, Some(file))
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn download_with_file(
        &mut self,
        remote: &str,
        local_path: &str,
        start_offset: u64,
        known_size: Option<u64>,
        progress: Option<Arc<dyn SftpProgress>>,
        cancel: Option<Arc<dyn SftpCancel>>,
        file: Option<tokio::fs::File>,
    ) -> Result<TransferOutcome, TransportError> {
        if cancel.as_ref().is_some_and(|c| c.is_cancelled()) {
            return Ok(TransferOutcome::Cancelled);
        }
        self.cancel = cancel.clone();
        let result = self
            .download_to_inner(
                remote,
                local_path,
                start_offset,
                known_size,
                progress,
                cancel,
                file,
            )
            .await;
        let cancelled = self.cancel.take().is_some_and(|c| c.is_cancelled());
        if cancelled {
            // An interrupted frame or pipeline leaves unread replies. Discard
            // this channel; never wait for a silent peer to drain them.
            self.poisoned = true;
            Ok(TransferOutcome::Cancelled)
        } else {
            if result.is_err() {
                self.poisoned = true;
            }
            result
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn download_to_inner(
        &mut self,
        remote: &str,
        local_path: &str,
        start_offset: u64,
        known_size: Option<u64>,
        progress: Option<Arc<dyn SftpProgress>>,
        cancel: Option<Arc<dyn SftpCancel>>,
        file: Option<tokio::fs::File>,
    ) -> Result<TransferOutcome, TransportError> {
        // A listing size is a progress hint only. Always read to EOF.
        let metadata = self.stat(remote).await?;
        if metadata.mode != 0 && metadata.mode & S_IFMT != 0o100000 {
            return Err(sftp_err("source is not a regular file"));
        }
        let total = if metadata.size_known {
            metadata.size
        } else {
            known_size.unwrap_or(0)
        };
        if start_offset > 0 && !metadata.size_known {
            return Err(sftp_err("cannot resume without a known source size"));
        }
        if metadata.size_known && start_offset > metadata.size {
            return Err(sftp_err("resume offset is beyond remote file size"));
        }
        let mut f = if let Some(file) = file {
            file
        } else {
            if let Some(parent) = std::path::Path::new(local_path).parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            let mut options = tokio::fs::OpenOptions::new();
            options.write(true).create(true).truncate(false);
            #[cfg(unix)]
            {
                options
                    .mode(0o600)
                    .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
            }
            let file = options.open(local_path).await?;
            if !file.metadata().await?.is_file() {
                return Err(sftp_err("destination is not a regular file"));
            }
            if start_offset == 0 {
                file.set_len(0).await?;
            }
            file
        };
        if f.metadata().await?.len() < start_offset {
            return Err(sftp_err("local partial is shorter than resume offset"));
        }
        let handle = self.open(remote, FXF_READ).await?;
        // Every exit after opening the local file must wait for its buffered
        // writes. In particular, cancelling a network wait returns through `?`
        // inside this block; dropping tokio::fs::File alone does not join writes.
        let result = async {
            f.seek(SeekFrom::Start(start_offset)).await?;
            // Pipelined: keep WINDOW reads in flight; buffer out-of-order replies in
            // `reorder` and write to the local file only in contiguous order.
            let mut in_flight: HashMap<u32, (u64, u32)> = HashMap::new();
            let mut reorder: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
            let mut write_offset = start_offset; // next contiguous byte to write
            let mut next_req = start_offset; // next byte to request
                                             // For a small known file, send only its payload and one EOF probe,
                                             // rather than a full window of redundant reads beyond its end.
            let mut request_limit = if metadata.size_known {
                metadata.size
            } else {
                u64::MAX
            };
            let mut eof: Option<u64> = None; // smallest offset confirmed past EOF
            let mut outcome = TransferOutcome::Completed;
            loop {
                if cancel.as_ref().is_some_and(|c| c.is_cancelled()) {
                    outcome = TransferOutcome::Cancelled;
                    break;
                }
                while in_flight.len() < WINDOW
                    && eof.is_none()
                    && next_req <= request_limit
                    && next_req.saturating_sub(write_offset) < (WINDOW * CHUNK) as u64
                {
                    let len = if next_req < request_limit {
                        (request_limit - next_req).min(CHUNK as u64) as u32
                    } else {
                        CHUNK as u32
                    };
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
                        if data.is_empty() || data.len() > len as usize {
                            return Err(self.poison(sftp_err("invalid DATA chunk length")));
                        }
                        let got = data.len() as u64;
                        request_limit = request_limit.max(off + got);
                        // Short read (legal): re-request the remaining sub-range.
                        if got < len as u64 {
                            let rlen = len - got as u32;
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
                            eof = Some(eof.map_or(off, |previous| previous.min(off)));
                        } else {
                            let e = status_to_err(code, &mut r);
                            return Err(self.poison(e));
                        }
                    }
                    _ => return Err(self.poison(sftp_err("unexpected reply to READ"))),
                }
            }
            if outcome == TransferOutcome::Cancelled {
                self.poisoned = true;
                return Ok(outcome);
            }
            if eof != Some(write_offset) || !reorder.is_empty() {
                return Err(self.poison(sftp_err(
                    "non-contiguous download or source changed during transfer",
                )));
            }
            self.close(&handle).await?;
            let after = self.stat(remote).await?;
            if (after.size_known && after.size != write_offset) || metadata.mtime != after.mtime {
                return Err(sftp_err("source changed during download"));
            }
            f.set_len(write_offset).await?;
            if let Some(p) = &progress {
                p.on_progress(write_offset, write_offset);
            }
            Ok(outcome)
        }
        .await;
        f.flush().await?;
        result
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
        self.upload_with_file(local_path, remote, start_offset, progress, cancel, None)
            .await
    }

    /// Upload an anonymous scratch without exposing a temporary pathname.
    pub async fn upload_file(
        &mut self,
        file: tokio::fs::File,
        remote: &str,
        progress: Option<Arc<dyn SftpProgress>>,
        cancel: Option<Arc<dyn SftpCancel>>,
    ) -> Result<TransferOutcome, TransportError> {
        self.upload_with_file("", remote, 0, progress, cancel, Some(file))
            .await
    }

    async fn upload_with_file(
        &mut self,
        local_path: &str,
        remote: &str,
        start_offset: u64,
        progress: Option<Arc<dyn SftpProgress>>,
        cancel: Option<Arc<dyn SftpCancel>>,
        file: Option<tokio::fs::File>,
    ) -> Result<TransferOutcome, TransportError> {
        if cancel.as_ref().is_some_and(|c| c.is_cancelled()) {
            return Ok(TransferOutcome::Cancelled);
        }
        self.cancel = cancel.clone();
        let result = self
            .upload_from_inner(local_path, remote, start_offset, progress, cancel, file)
            .await;
        let cancelled = self.cancel.take().is_some_and(|c| c.is_cancelled());
        if cancelled {
            // An interrupted frame or pipeline leaves unread replies. Discard
            // this channel; never wait for a silent peer to drain them.
            self.poisoned = true;
            Ok(TransferOutcome::Cancelled)
        } else {
            if result.is_err() {
                self.poisoned = true;
            }
            result
        }
    }

    async fn upload_from_inner(
        &mut self,
        local_path: &str,
        remote: &str,
        start_offset: u64,
        progress: Option<Arc<dyn SftpProgress>>,
        cancel: Option<Arc<dyn SftpCancel>>,
        file: Option<tokio::fs::File>,
    ) -> Result<TransferOutcome, TransportError> {
        let mut f = if let Some(file) = file {
            file
        } else {
            if !tokio::fs::metadata(local_path).await?.is_file() {
                return Err(sftp_err("source is not a regular file"));
            }
            let mut options = tokio::fs::OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
            options.open(local_path).await?
        };
        let metadata = f.metadata().await?;
        if !metadata.is_file() {
            return Err(sftp_err("source is not a regular file"));
        }
        let total = metadata.len();
        if start_offset > total {
            return Err(sftp_err("resume offset is beyond local file size"));
        }
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
        if outcome == TransferOutcome::Cancelled {
            self.poisoned = true;
            return Ok(outcome);
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
        if next_offset != total || f.metadata().await?.modified()? != metadata.modified()? {
            return Err(sftp_err("source changed during upload"));
        }
        if let Some(progress) = &progress {
            progress.on_progress(total, total);
        }
        Ok(outcome)
    }

    /// stat by path.
    pub async fn stat(&mut self, path: &str) -> Result<FileStat, TransportError> {
        self.path_stat(FXP_STAT, path).await
    }

    /// Metadata for the link itself, including dangling links.
    pub async fn lstat(&mut self, path: &str) -> Result<FileStat, TransportError> {
        self.path_stat(FXP_LSTAT, path).await
    }

    async fn path_stat(&mut self, request: u8, path: &str) -> Result<FileStat, TransportError> {
        let id = self.alloc_id();
        let mut b = vec![request];
        b.extend_from_slice(&id.to_be_bytes());
        put_string(&mut b, path.as_bytes());
        self.send(&b).await?;
        let (typ, body) = self.read_for(id).await?;
        if typ != FXP_ATTRS {
            return Err(self.as_status_err(typ, &body));
        }
        let mut r = Reader::new(&body);
        r.u32()?; // id
        let (size, perms, mtime, _, _) = parse_attrs(&mut r)?;
        Ok(FileStat {
            size: size.unwrap_or(0),
            size_known: size.is_some(),
            is_dir: perms.map(is_dir_perm).unwrap_or(false),
            mode: perms.unwrap_or(0),
            mtime: mtime.map(u64::from).unwrap_or(0),
        })
    }

    /// Read the literal target without resolving relative or dangling links.
    pub async fn readlink(&mut self, path: &str) -> Result<String, TransportError> {
        let id = self.alloc_id();
        let mut b = vec![FXP_READLINK];
        b.extend_from_slice(&id.to_be_bytes());
        put_string(&mut b, path.as_bytes());
        self.send(&b).await?;
        let (typ, body) = self.read_for(id).await?;
        if typ != FXP_NAME {
            return Err(self.as_status_err(typ, &body));
        }
        let mut r = Reader::new(&body);
        r.u32()?;
        if r.u32()? != 1 {
            return Err(sftp_err("invalid readlink name count"));
        }
        String::from_utf8(r.string()?)
            .map_err(|_| sftp_err("symbolic link target is not valid UTF-8"))
    }

    /// Create a link. OpenSSH v3 uses target then link path on the wire.
    pub async fn symlink(&mut self, target: &str, path: &str) -> Result<(), TransportError> {
        let id = self.alloc_id();
        let mut b = vec![FXP_SYMLINK];
        b.extend_from_slice(&id.to_be_bytes());
        put_string(&mut b, target.as_bytes());
        put_string(&mut b, path.as_bytes());
        self.send(&b).await?;
        self.expect_ok(id).await
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

    /// Commit a prepared sibling. Standard v3 rename refuses an existing name;
    /// replacement requires the advertised OpenSSH atomic rename extension.
    pub async fn commit(
        &mut self,
        from: &str,
        to: &str,
        replace: bool,
    ) -> Result<(), TransportError> {
        if !replace {
            return self.rename(from, to).await;
        }
        if !self.posix_rename {
            return Err(sftp_err(
                "server does not support atomic replacement (posix-rename)",
            ));
        }
        let id = self.alloc_id();
        let mut b = vec![200]; // SSH_FXP_EXTENDED
        b.extend_from_slice(&id.to_be_bytes());
        put_string(&mut b, b"posix-rename@openssh.com");
        put_string(&mut b, from.as_bytes());
        put_string(&mut b, to.as_bytes());
        self.send(&b).await?;
        self.expect_ok(id).await
    }

    /// Preserve ordinary permission bits and mtime, never owner or privilege bits.
    pub async fn set_metadata(
        &mut self,
        path: &str,
        mode: Option<u32>,
        mtime: Option<u32>,
    ) -> Result<(), TransportError> {
        let id = self.alloc_id();
        let mut b = vec![FXP_SETSTAT];
        b.extend_from_slice(&id.to_be_bytes());
        put_string(&mut b, path.as_bytes());
        let flags = if mode.is_some() { ATTR_PERMISSIONS } else { 0 }
            | if mtime.is_some() { ATTR_ACMODTIME } else { 0 };
        b.extend_from_slice(&flags.to_be_bytes());
        if let Some(mode) = mode {
            b.extend_from_slice(&(mode & 0o777).to_be_bytes());
        }
        if let Some(mtime) = mtime {
            b.extend_from_slice(&mtime.to_be_bytes());
            b.extend_from_slice(&mtime.to_be_bytes());
        }
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
        b.extend_from_slice(&ATTR_PERMISSIONS.to_be_bytes());
        b.extend_from_slice(&0o600u32.to_be_bytes());
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
                if data.is_empty() || data.len() > len as usize {
                    return Err(sftp_err("invalid DATA chunk length"));
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
                    if filename.is_empty() || filename.contains('/') || filename.contains('\0') {
                        return Err(sftp_err("invalid directory entry name"));
                    }
                    r.skip_string()?; // longname (ls -l) — not needed, do not allocate
                    let (size, perms, mtime, uid, gid) = parse_attrs(&mut r)?;
                    out.push(DirEntry {
                        filename,
                        is_dir: perms.map(is_dir_perm).unwrap_or(false),
                        size: size.unwrap_or(0),
                        size_known: size.is_some(),
                        mode: perms.unwrap_or(0),
                        mtime: mtime.map(u64::from).unwrap_or(0),
                        uid: uid.unwrap_or(0),
                        gid: gid.unwrap_or(0),
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
        let cancel = self.cancel.clone();
        let lifetime = self.lifetime_cancel.clone();
        let r = tokio::select! {
            biased;
            _ = wait_cancelled(cancel) => Err(sftp_err("transfer cancelled")),
            _ = wait_cancelled(lifetime) => Err(sftp_err("session closed")),
            result = self.send_raw(body) => result,
        };
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
        let cancel = self.cancel.clone();
        let lifetime = self.lifetime_cancel.clone();
        let r = tokio::select! {
            biased;
            _ = wait_cancelled(cancel) => Err(sftp_err("transfer cancelled")),
            _ = wait_cancelled(lifetime) => Err(sftp_err("session closed")),
            result = self.read_packet_raw() => result,
        };
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

// The public cancellation contract is a synchronous flag (also used by FFI).
// Poll it only during a pending network wait; no timer on ordinary metadata I/O.
async fn wait_cancelled(cancel: Option<Arc<dyn SftpCancel>>) {
    let Some(cancel) = cancel else {
        return std::future::pending().await;
    };
    loop {
        if cancel.is_cancelled() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
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
type ParsedAttrs = (
    Option<u64>,
    Option<u32>,
    Option<u32>,
    Option<u32>,
    Option<u32>,
);

/// Parses the ATTRS block, advancing the cursor. Returns `(size, permissions, mtime, uid, gid)`.
fn parse_attrs(r: &mut Reader<'_>) -> Result<ParsedAttrs, TransportError> {
    let flags = r.u32()?;
    let mut size = None;
    let mut perms = None;
    let mut mtime = None;
    let mut uid = None;
    let mut gid = None;
    if flags & ATTR_SIZE != 0 {
        size = Some(r.u64()?);
    }
    if flags & ATTR_UIDGID != 0 {
        uid = Some(r.u32()?);
        gid = Some(r.u32()?);
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
    Ok((size, perms, mtime, uid, gid))
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
        String::from_utf8(bytes).map_err(|_| sftp_err("filename or text is not valid UTF-8"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestCancel(std::sync::atomic::AtomicBool);
    impl SftpCancel for TestCancel {
        fn is_cancelled(&self) -> bool {
            self.0.load(std::sync::atomic::Ordering::SeqCst)
        }
    }
    impl SftpProgress for TestCancel {
        fn on_progress(&self, _: u64, _: u64) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn test_session(stream: tokio::io::DuplexStream) -> Sftp<tokio::io::DuplexStream> {
        Sftp {
            stream,
            next_id: 1,
            poisoned: false,
            cancel: None,
            posix_rename: false,
            lifetime_cancel: None,
        }
    }

    #[tokio::test]
    async fn cancellation_interrupts_silent_metadata_reply() {
        let (client, server) = tokio::io::duplex(1024);
        let mut client = test_session(client);
        let mut peer = test_session(server);
        let flag = Arc::new(TestCancel(std::sync::atomic::AtomicBool::new(false)));
        let cancel = flag.clone();
        let server = async move {
            let (typ, _) = peer.read_packet().await.unwrap();
            assert_eq!(typ, FXP_STAT);
            cancel.0.store(true, std::sync::atomic::Ordering::SeqCst);
            // Keep the connection open without ever replying.
            tokio::time::sleep(Duration::from_secs(2)).await;
        };
        let file = tempfile::NamedTempFile::new().unwrap();
        let transfer = async {
            let outcome = timeout(
                Duration::from_secs(1),
                client.download_to(
                    "/file",
                    file.path().to_str().unwrap(),
                    0,
                    None,
                    None,
                    Some(flag),
                ),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(outcome, TransferOutcome::Cancelled);
            assert!(client.is_poisoned());
        };
        tokio::select! {
            _ = server => panic!("transfer waited for the silent server"),
            _ = transfer => {},
        }
    }

    #[tokio::test]
    async fn cancellation_interrupts_blocked_upload_write() {
        let (client, server) = tokio::io::duplex(1024);
        let mut client = test_session(client);
        let mut peer = test_session(server);
        let flag = Arc::new(TestCancel(std::sync::atomic::AtomicBool::new(false)));
        let cancel = flag.clone();
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), vec![42; CHUNK * 2]).unwrap();
        let server = async move {
            let (typ, body) = peer.read_packet().await.unwrap();
            assert_eq!(typ, FXP_OPEN);
            let mut reply = vec![FXP_HANDLE];
            reply.extend_from_slice(&body[..4]);
            put_string(&mut reply, b"handle");
            peer.send(&reply).await.unwrap();
            // The upload fills the duplex buffer with a partial WRITE frame.
            let mut length = [0; 4];
            peer.stream.read_exact(&mut length).await.unwrap();
            cancel.0.store(true, std::sync::atomic::Ordering::SeqCst);
            tokio::time::sleep(Duration::from_secs(2)).await;
        };
        let transfer = async {
            let outcome = timeout(
                Duration::from_secs(1),
                client.upload_from(file.path().to_str().unwrap(), "/file", 0, None, Some(flag)),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(outcome, TransferOutcome::Cancelled);
            assert!(client.is_poisoned());
        };
        tokio::select! {
            _ = server => panic!("transfer waited for the blocked writer"),
            _ = transfer => {},
        }
    }

    #[tokio::test]
    async fn cancelled_download_preserves_prefix_without_draining_pipeline() {
        let (client, server) = tokio::io::duplex(CHUNK * 2);
        let mut client = test_session(client);
        let mut peer = test_session(server);
        let flag = Arc::new(TestCancel(std::sync::atomic::AtomicBool::new(false)));
        let file = tempfile::NamedTempFile::new().unwrap();
        let server = async move {
            reply_test_stat(&mut peer, (CHUNK * 2) as u64).await;
            let (_, body) = peer.read_packet().await.unwrap();
            let mut reply = vec![FXP_HANDLE];
            reply.extend_from_slice(&body[..4]);
            put_string(&mut reply, b"handle");
            peer.send(&reply).await.unwrap();
            let (typ, body) = peer.read_packet().await.unwrap();
            assert_eq!(typ, FXP_READ);
            let mut reply = vec![FXP_DATA];
            reply.extend_from_slice(&body[..4]);
            put_string(&mut reply, &vec![42; CHUNK]);
            peer.send(&reply).await.unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
        };
        let transfer = async {
            let outcome = timeout(
                Duration::from_secs(1),
                client.download_to(
                    "/file",
                    file.path().to_str().unwrap(),
                    0,
                    Some((CHUNK * 2) as u64),
                    Some(flag.clone()),
                    Some(flag),
                ),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(outcome, TransferOutcome::Cancelled);
            assert!(client.is_poisoned());
            assert_eq!(std::fs::read(file.path()).unwrap(), vec![42; CHUNK]);
        };
        tokio::select! {
            _ = server => panic!("cancel tried to drain the pipeline"),
            _ = transfer => {},
        }
    }

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
        let (size, perms, mtime, _, _) = parse_attrs(&mut r).unwrap();
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
        let (size, perms, mtime, _, _) = parse_attrs(&mut r).unwrap();
        assert_eq!(size, Some(42));
        assert_eq!(perms, None);
        assert_eq!(mtime, None);
    }
}

#[cfg(test)]
mod download_flush_tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    };
    struct Flag(AtomicBool);
    impl SftpCancel for Flag {
        fn is_cancelled(&self) -> bool {
            self.0.load(Ordering::SeqCst)
        }
    }
    struct Progress(Mutex<Option<tokio::sync::oneshot::Sender<()>>>);
    impl SftpProgress for Progress {
        fn on_progress(&self, _: u64, _: u64) {
            if let Some(tx) = self.0.lock().unwrap().take() {
                let _ = tx.send(());
            }
        }
    }

    #[test]
    fn cancellation_waits_for_buffered_local_write() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        rt.block_on(async {
            let (client, server) = tokio::io::duplex(CHUNK * 2);
            let mut client = Sftp {
                stream: client,
                next_id: 1,
                poisoned: false,
                cancel: None,
                posix_rename: false,
                lifetime_cancel: None,
            };
            let mut peer = Sftp {
                stream: server,
                next_id: 1,
                poisoned: false,
                cancel: None,
                posix_rename: false,
                lifetime_cancel: None,
            };
            let flag = Arc::new(Flag(AtomicBool::new(false)));
            let cancel = flag.clone();
            let file = tempfile::NamedTempFile::new().unwrap();
            let (progress_tx, progress_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let (done_tx, done_rx) = tokio::sync::oneshot::channel();
            let server = async move {
                reply_test_stat(&mut peer, (CHUNK * 2) as u64).await;
                let (_, body) = peer.read_packet().await.unwrap();
                let mut reply = vec![FXP_HANDLE];
                reply.extend_from_slice(&body[..4]);
                put_string(&mut reply, b"handle");
                peer.send(&reply).await.unwrap();
                let (typ, body) = peer.read_packet().await.unwrap();
                assert_eq!(typ, FXP_READ);
                // Local open/seek have finished. Occupy the only blocking worker
                // before DATA queues its local file write.
                let (started_tx, started_rx) = tokio::sync::oneshot::channel();
                let blocker = tokio::task::spawn_blocking(move || {
                    let _ = started_tx.send(());
                    let _ = release_rx.recv();
                });
                started_rx.await.unwrap();
                let mut reply = vec![FXP_DATA];
                reply.extend_from_slice(&body[..4]);
                put_string(&mut reply, &vec![42; CHUNK]);
                peer.send(&reply).await.unwrap();
                progress_rx.await.unwrap();
                tokio::time::sleep(Duration::from_millis(100)).await;
                cancel.0.store(true, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(200)).await;
                let _ = release_tx.send(());
                let _ = done_rx.await;
                blocker.await.unwrap();
            };
            let transfer = async {
                let result = timeout(
                    Duration::from_secs(1),
                    client.download_to(
                        "/file",
                        file.path().to_str().unwrap(),
                        0,
                        Some((CHUNK * 2) as u64),
                        Some(Arc::new(Progress(Mutex::new(Some(progress_tx))))),
                        Some(flag),
                    ),
                )
                .await;
                let size_when_returned = std::fs::metadata(file.path()).unwrap().len();
                let _ = done_tx.send(());
                assert_eq!(result.unwrap().unwrap(), TransferOutcome::Cancelled);
                assert_eq!(
                    size_when_returned, CHUNK as u64,
                    "cancellation must finish the queued local write before returning"
                );
                assert_eq!(std::fs::read(file.path()).unwrap(), vec![42; CHUNK]);
            };
            tokio::join!(server, transfer);
        });
    }
}

#[cfg(test)]
async fn reply_test_stat(peer: &mut Sftp<tokio::io::DuplexStream>, size: u64) {
    let (typ, body) = peer.read_packet().await.unwrap();
    assert_eq!(typ, FXP_STAT);
    let mut reply = vec![FXP_ATTRS];
    reply.extend_from_slice(&body[..4]);
    reply.extend_from_slice(&ATTR_SIZE.to_be_bytes());
    reply.extend_from_slice(&size.to_be_bytes());
    peer.send(&reply).await.unwrap();
}

#[cfg(test)]
mod integrity_tests {
    use super::*;

    async fn peer(
        mut peer: Sftp<tokio::io::DuplexStream>,
        bytes: Vec<u8>,
        unknown_size: bool,
        oversized: bool,
    ) -> usize {
        let mut reads = 0;
        while let Ok((typ, body)) = peer.read_packet().await {
            let mut r = Reader::new(&body);
            let id = r.u32().unwrap();
            let mut response = Vec::new();
            match typ {
                FXP_STAT => {
                    response.push(FXP_ATTRS);
                    response.extend_from_slice(&id.to_be_bytes());
                    response.extend_from_slice(
                        &(if unknown_size { 0 } else { ATTR_SIZE }).to_be_bytes(),
                    );
                    if !unknown_size {
                        response.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
                    }
                }
                FXP_OPEN => {
                    response.push(FXP_HANDLE);
                    response.extend_from_slice(&id.to_be_bytes());
                    put_string(&mut response, b"h");
                }
                FXP_READ => {
                    reads += 1;
                    r.string().unwrap();
                    let offset = r.u64().unwrap() as usize;
                    let len = r.u32().unwrap() as usize;
                    assert!(len <= 32768);
                    if oversized || offset < bytes.len() {
                        response.push(FXP_DATA);
                        response.extend_from_slice(&id.to_be_bytes());
                        if oversized {
                            put_string(&mut response, &vec![0; len + 1]);
                        } else {
                            put_string(
                                &mut response,
                                &bytes[offset..(offset + len).min(bytes.len())],
                            );
                        }
                    } else {
                        response.push(FXP_STATUS);
                        response.extend_from_slice(&id.to_be_bytes());
                        response.extend_from_slice(&FX_EOF.to_be_bytes());
                    }
                }
                FXP_CLOSE => {
                    response.push(FXP_STATUS);
                    response.extend_from_slice(&id.to_be_bytes());
                    response.extend_from_slice(&FX_OK.to_be_bytes());
                }
                _ => panic!("unexpected request {typ}"),
            }
            if peer.send(&response).await.is_err() {
                return reads;
            }
        }
        reads
    }

    fn session(stream: tokio::io::DuplexStream) -> Sftp<tokio::io::DuplexStream> {
        Sftp {
            stream,
            next_id: 0,
            poisoned: false,
            cancel: None,
            posix_rename: false,
            lifetime_cancel: None,
        }
    }

    #[tokio::test]
    async fn download_ignores_stale_and_missing_listing_sizes() {
        for (hint, unknown, length) in [
            (0, false, CHUNK + 7),
            (999999, false, 12),
            (0, true, CHUNK + 7),
            (55, true, 0),
        ] {
            let bytes = vec![37; length];
            let (client, server) = tokio::io::duplex(CHUNK * WINDOW * 2);
            let server = tokio::spawn(peer(session(server), bytes.clone(), unknown, false));
            let mut client = session(client);
            let file = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(file.path(), vec![99; CHUNK * 3]).unwrap();
            assert_eq!(
                client
                    .download_to(
                        "/file",
                        file.path().to_str().unwrap(),
                        0,
                        Some(hint),
                        None,
                        None
                    )
                    .await
                    .unwrap(),
                TransferOutcome::Completed
            );
            assert_eq!(std::fs::read(file.path()).unwrap(), bytes);
            assert!(!client.is_poisoned());
            drop(client);
            let reads = server.await.unwrap();
            if !unknown {
                assert_eq!(reads, length.div_ceil(CHUNK) + 1);
            }
        }
    }

    #[tokio::test]
    async fn delayed_first_reply_bounds_the_entire_read_window() {
        let (client, server) = tokio::io::duplex(CHUNK * WINDOW * 2);
        let mut remote = session(server);
        let server = tokio::spawn(async move {
            reply_test_stat(&mut remote, (CHUNK * WINDOW) as u64).await;
            let (typ, body) = remote.read_packet().await.unwrap();
            assert_eq!(typ, FXP_OPEN);
            let mut reply = vec![FXP_HANDLE];
            reply.extend_from_slice(&body[..4]);
            put_string(&mut reply, b"h");
            remote.send(&reply).await.unwrap();
            let mut ids = Vec::new();
            for _ in 0..WINDOW {
                let (typ, body) = remote.read_packet().await.unwrap();
                assert_eq!(typ, FXP_READ);
                ids.push(body[..4].to_vec());
            }
            for id in ids.iter().skip(1).rev() {
                let mut data = vec![FXP_DATA];
                data.extend_from_slice(id);
                put_string(&mut data, &vec![7; CHUNK]);
                remote.send(&data).await.unwrap();
            }
            // No refill is allowed while all later DATA waits for offset zero.
            assert!(timeout(Duration::from_millis(100), remote.read_packet())
                .await
                .is_err());
            let mut data = vec![FXP_DATA];
            data.extend_from_slice(&ids[0]);
            put_string(&mut data, &vec![7; CHUNK]);
            remote.send(&data).await.unwrap();
            peer(remote, vec![7; CHUNK * WINDOW], false, false).await;
        });
        let mut client = session(client);
        let file = tempfile::NamedTempFile::new().unwrap();
        client
            .download_to("/file", file.path().to_str().unwrap(), 0, None, None, None)
            .await
            .unwrap();
        assert_eq!(std::fs::read(file.path()).unwrap(), vec![7; CHUNK * WINDOW]);
        drop(client);
        server.await.unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn local_write_failure_discards_pending_replies() {
        let (client, server) = tokio::io::duplex(CHUNK * WINDOW * 2);
        let server = tokio::spawn(peer(session(server), vec![42; CHUNK * 2], false, false));
        let mut client = session(client);
        assert!(client
            .download_to_file(
                "/file",
                tokio::fs::File::from_std(
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open("/dev/full")
                        .unwrap()
                ),
                None,
                None
            )
            .await
            .is_err());
        assert!(client.is_poisoned());
        drop(client);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn oversized_data_poisons_the_channel() {
        let (client, server) = tokio::io::duplex(CHUNK * WINDOW * 2);
        let server = tokio::spawn(peer(session(server), vec![42; 10], false, true));
        let mut client = session(client);
        let file = tempfile::NamedTempFile::new().unwrap();
        assert!(client
            .download_to("/file", file.path().to_str().unwrap(), 0, None, None, None)
            .await
            .is_err());
        assert!(client.is_poisoned());
        drop(client);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn bounded_read_checks_actual_data_and_closes_handle() {
        let (client, server) = tokio::io::duplex(CHUNK * 2);
        let server = tokio::spawn(peer(session(server), vec![42; 33], true, false));
        let mut client = session(client);
        assert!(client.read_file_bounded("/file", 32).await.is_err());
        // CLOSE consumed its reply, so a subsequent request is synchronized.
        assert_eq!(
            client.read_file_bounded("/file", 33).await.unwrap(),
            vec![42; 33]
        );
        drop(client);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn unsupported_atomic_replace_sends_no_mutation() {
        let (client, _server) = tokio::io::duplex(1024);
        let mut client = session(client);
        assert!(client
            .commit("/stage", "/original", true)
            .await
            .unwrap_err()
            .to_string()
            .contains("atomic replacement"));
        assert_eq!(client.next_id, 0);
    }

    #[tokio::test]
    async fn rejects_unsupported_version() {
        let (client, server) = tokio::io::duplex(1024);
        let mut peer = session(server);
        let server = async {
            assert_eq!(peer.read_packet().await.unwrap().0, FXP_INIT);
            peer.send(&[FXP_VERSION, 0, 0, 0, 6]).await.unwrap();
        };
        let (result, ()) = tokio::join!(Sftp::start(client), server);
        assert!(result
            .err()
            .unwrap()
            .to_string()
            .contains("unsupported SFTP version"));
    }

    #[test]
    fn refuses_lossy_filename_conversion() {
        assert!(Reader::new(&[0, 0, 0, 1, 255]).string_utf8().is_err());
    }
}
