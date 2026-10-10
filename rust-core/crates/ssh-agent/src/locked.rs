//! Secret-material buffer: `mlock` the pages (don't leak into swap) + `zeroize`.
//!
//! `mlock` is best-effort: on platforms/environments without the right to lock
//! memory (no `CAP_IPC_LOCK`, `RLIMIT_MEMLOCK` exceeded, non-Unix) the lock may
//! fail — in that case the buffer is still used and zeroized, but the
//! `is_locked()` flag will be `false`. Zeroization is always performed.

use zeroize::Zeroize;

/// A heap of bytes, locked into RAM where possible and zeroized on Drop.
pub(crate) struct LockedBuffer {
    data: Box<[u8]>,
    locked: bool,
}

impl LockedBuffer {
    /// Copies `bytes` into an owned buffer and tries to `mlock` its pages.
    pub(crate) fn new(bytes: &[u8]) -> Self {
        let data = bytes.to_vec().into_boxed_slice();
        let locked = lock_pages(&data);
        Self { data, locked }
    }

    /// Access to the bytes.
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Whether the memory was successfully locked into RAM.
    #[expect(
        dead_code,
        reason = "diagnostic accessor for the best-effort mlock result; no caller reads it yet"
    )]
    pub(crate) const fn is_locked(&self) -> bool {
        self.locked
    }
}

impl Drop for LockedBuffer {
    fn drop(&mut self) {
        self.data.zeroize();
        if self.locked {
            unlock_pages(&self.data);
        }
    }
}

#[cfg(unix)]
fn lock_pages(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    // SAFETY: the pointer and length describe a valid, live allocation that we
    // own; mlock does not modify the contents.
    let ret = unsafe { libc::mlock(data.as_ptr() as *const libc::c_void, data.len()) };
    // Best-effort: exclude the secret pages from the core dump (Linux). mlock does
    // not protect against a process memory dump — MADV_DONTDUMP closes that channel.
    // Does not affect the lock result (a separate guarantee).
    #[cfg(target_os = "linux")]
    // SAFETY: the same valid region; madvise does not change the contents.
    unsafe {
        libc::madvise(
            data.as_ptr() as *mut libc::c_void,
            data.len(),
            libc::MADV_DONTDUMP,
        );
    }
    ret == 0
}

#[cfg(unix)]
fn unlock_pages(data: &[u8]) {
    if data.is_empty() {
        return;
    }
    // SAFETY: the same region that was locked in `lock_pages`.
    unsafe {
        libc::munlock(data.as_ptr() as *const libc::c_void, data.len());
    }
}

#[cfg(not(unix))]
fn lock_pages(_data: &[u8]) -> bool {
    false
}

#[cfg(not(unix))]
fn unlock_pages(_data: &[u8]) {}
