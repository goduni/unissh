//! Who is on the other end of an agent connection, for the approval prompt.
//!
//! Best effort, and display only: the socket's `0600` mode is the access
//! control. The pid comes from the kernel (`SO_PEERCRED` on Linux,
//! `LOCAL_PEEREPID` on macOS, both through tokio's `peer_cred`); the executable
//! is looked up from it (`/proc/<pid>/exe`, `proc_pidpath`). A process that
//! exits before the lookup, or an OS that reports neither, gives an unknown
//! process. Never logged.

use unissh_ffi::AgentCaller;

pub fn caller(stream: &tokio::net::UnixStream) -> AgentCaller {
    let pid = stream
        .peer_cred()
        .ok()
        .and_then(|cred| cred.pid())
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid > 0);
    AgentCaller {
        pid,
        executable: pid.and_then(executable),
    }
}

#[cfg(target_os = "linux")]
fn executable(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
}

#[cfg(target_os = "macos")]
fn executable(pid: u32) -> Option<String> {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: `buf` is writable for `buf.len()` bytes, and `proc_pidpath`
    // writes at most that many and returns how many it wrote.
    let written = unsafe {
        libc::proc_pidpath(
            pid as libc::c_int,
            buf.as_mut_ptr().cast(),
            buf.len() as u32,
        )
    };
    if written <= 0 {
        return None;
    }
    buf.truncate(written as usize);
    String::from_utf8(buf).ok()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn executable(_pid: u32) -> Option<String> {
    None
}
