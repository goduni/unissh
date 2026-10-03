//! Windows: the system agent's named pipe, who may open it, and who did.
//!
//! The pipe is `\\.\pipe\unissh-agent`. The default OpenSSH pipe
//! (`\\.\pipe\openssh-ssh-agent`) is deliberately left alone: UniSSH's own
//! "system agent" host auth dials that one, so it keeps reaching the real
//! OpenSSH agent and can never loop back here.
//!
//! Access control is the pipe's DACL, the Windows counterpart of the Unix
//! socket's `0700` directory and `0600` mode. It is protected (nothing
//! inherited) and holds exactly one ACE: full access for the current user's own
//! SID, read from the process token. Deliberately not the SDDL aliases:
//! `OW` (owner rights) follows whoever owns the object, and under an elevated
//! token the default owner is the Administrators group, not the user; `CO`
//! (creator owner) only means something in inheritable ACEs. An explicit SID
//! says exactly who, whatever token the app runs with. The default mandatory
//! label still applies on top, so a low-integrity process of the same user
//! (a sandboxed renderer) cannot write to it either.
//!
//! The first instance is created with `FILE_FLAG_FIRST_PIPE_INSTANCE`: if the
//! name already exists — another UniSSH, or anything squatting on it — creation
//! fails and the status says "in use", rather than this app joining (or being
//! mistaken for) someone else's pipe. Remote clients are rejected (tokio's
//! default, kept explicit).
//!
//! The caller's pid (`GetNamedPipeClientProcessId`) and executable
//! (`QueryFullProcessImageNameW`) are best effort and display only, as on Unix.
//! Never logged.

use std::ffi::OsStr;
use std::io;
use std::os::windows::io::AsRawHandle;

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use unissh_ffi::AgentCaller;
use windows_sys::core::PWSTR;
use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_ACCESS_DENIED, ERROR_PIPE_BUSY, HANDLE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW,
    PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// The pipe the system agent listens on. Pipe names are case-insensitive; this
/// one must stay distinct from `openssh-ssh-agent` (see the module docs).
pub const NAME: &str = r"\\.\pipe\unissh-agent";

/// A self-relative security descriptor granting the current user, and no one
/// else, access to the pipe. Owned; freed on drop.
pub struct Security {
    descriptor: PSECURITY_DESCRIPTOR,
}

// SAFETY: the descriptor is a private heap allocation that is never written
// after `current_user` builds it; the pipe creation only reads it.
unsafe impl Send for Security {}
// SAFETY: as above — shared access is read-only.
unsafe impl Sync for Security {}

impl Security {
    /// `D:P(A;;GA;;;<user SID>)`: protected DACL, generic-all for this user.
    pub fn current_user() -> io::Result<Self> {
        let sid = current_user_sid()?;
        let sddl: Vec<u16> = format!("D:P(A;;GA;;;{sid})")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `sddl` is NUL-terminated and outlives the call; `descriptor`
        // is written on success and then owned by us (freed with LocalFree).
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || descriptor.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { descriptor })
    }
}

impl Drop for Security {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW
        // with LocalAlloc, freed exactly once here.
        unsafe { LocalFree(self.descriptor) };
    }
}

/// Closes a kernel handle on drop.
struct Owned(HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: a handle this module opened and nothing else closes.
        unsafe { CloseHandle(self.0) };
    }
}

/// The current user's SID in string form (`S-1-5-21-…`), from the process
/// token.
fn current_user_sid() -> io::Result<String> {
    // SAFETY: every out-pointer is valid for the call it is passed to; the
    // token buffer is sized by the first GetTokenInformation call and aligned
    // for TOKEN_USER (u64 storage); the SID it points into lives in that
    // buffer, which outlives ConvertSidToStringSidW; the string that call
    // allocates is read up to its NUL and then freed with LocalFree.
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = Owned(token);
        let mut len = 0u32;
        // Expected to fail with ERROR_INSUFFICIENT_BUFFER, reporting the size.
        GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut len);
        if len == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        if GetTokenInformation(token.0, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) == 0 {
            return Err(io::Error::last_os_error());
        }
        let user = &*buf.as_ptr().cast::<TOKEN_USER>();
        let mut string: PWSTR = std::ptr::null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut string) == 0 || string.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut n = 0;
        while *string.add(n) != 0 {
            n += 1;
        }
        let sid = String::from_utf16(std::slice::from_raw_parts(string, n));
        LocalFree(string.cast());
        sid.map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "SID is not UTF-16"))
    }
}

/// Creates one instance of the pipe with `security`'s DACL. `first` asks for
/// `FILE_FLAG_FIRST_PIPE_INSTANCE` (the listener's first instance only; every
/// later instance joins the pipe it already owns). Must run inside the tokio
/// runtime: the instance is registered with its reactor here.
pub fn create(name: &OsStr, security: &Security, first: bool) -> io::Result<NamedPipeServer> {
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security.descriptor,
        bInheritHandle: 0,
    };
    // SAFETY: `attributes` is a valid SECURITY_ATTRIBUTES whose descriptor
    // `security` keeps alive for the duration of the call.
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(name, std::ptr::from_mut(&mut attributes).cast())
    }
}

/// Whether creating the first instance failed because the name is taken.
/// With `FILE_FLAG_FIRST_PIPE_INSTANCE` an existing pipe gives access denied;
/// one at its instance limit gives pipe busy.
pub fn in_use(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(code)
        if code as u32 == ERROR_ACCESS_DENIED || code as u32 == ERROR_PIPE_BUSY)
}

/// Who connected to this pipe instance, as far as Windows says.
pub fn caller(pipe: &NamedPipeServer) -> AgentCaller {
    let mut pid = 0u32;
    // SAFETY: the handle is valid while `pipe` is borrowed; `pid` is writable.
    let ok = unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle(), &mut pid) };
    let pid = (ok != 0 && pid > 0).then_some(pid);
    AgentCaller {
        pid,
        executable: pid.and_then(executable),
    }
}

/// The caller's executable path. A process gone or not ours to query gives
/// `None` (the prompt then says the process is unknown).
fn executable(pid: u32) -> Option<String> {
    // SAFETY: the process handle is checked, closed by `Owned`; `buf` is
    // writable for `len` UTF-16 units and the call reports how many it wrote
    // (without the NUL).
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() {
            return None;
        }
        let process = Owned(process);
        let mut buf = vec![0u16; 32_768];
        let mut len = buf.len() as u32;
        if QueryFullProcessImageNameW(process.0, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len)
            == 0
        {
            return None;
        }
        buf.truncate(len as usize);
        Some(String::from_utf16_lossy(&buf))
    }
}
