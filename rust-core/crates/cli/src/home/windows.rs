//! Owner-private Windows storage, including explicitly selected device paths.
//! Creation applies a protected DACL before any secret is written. Reads check
//! the opened handle, not a path that could have been replaced in between.

#![expect(
    unsafe_code,
    reason = "Win32 security descriptors and handle creation; each call documents ownership"
)]

use std::fs::{self, File};
use std::io;
use std::os::windows::{
    ffi::OsStrExt,
    io::{AsRawHandle, FromRawHandle},
};
use std::path::Path;

use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetAce, GetTokenInformation, TokenUser, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
    DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_SHARE_DELETE,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

struct Allocation(PSECURITY_DESCRIPTOR);
impl Drop for Allocation {
    fn drop(&mut self) {
        // SAFETY: these descriptors/strings are returned by LocalAlloc-based APIs.
        unsafe {
            LocalFree(self.0);
        }
    }
}

struct Token(HANDLE);
impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: this module owns this token handle and closes it once.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn sid_string(sid: PSID) -> io::Result<String> {
    let mut string = std::ptr::null_mut();
    // SAFETY: callers pass a SID owned by a live token/security descriptor;
    // string is initialized by the API and owned by Allocation on success.
    if unsafe { ConvertSidToStringSidW(sid, &mut string) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _allocation = Allocation(string.cast());
    let mut length = 0;
    // SAFETY: ConvertSidToStringSidW returns a NUL-terminated allocated UTF-16 string.
    while unsafe { *string.wrapping_add(length) } != 0 {
        length += 1;
    }
    // SAFETY: the loop counted initialized UTF-16 units in that live allocation.
    let text = unsafe { std::slice::from_raw_parts(string, length) };
    String::from_utf16(text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn current_user() -> io::Result<String> {
    let mut token = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a borrowed pseudo-handle, never closed here.
    let process = unsafe { GetCurrentProcess() };
    // SAFETY: token is a valid out-pointer for this live process handle.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = Token(token);
    let mut length = 0;
    // SAFETY: a null buffer with length zero asks for the required buffer size.
    unsafe {
        GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut length);
    }
    if length == 0 {
        return Err(io::Error::last_os_error());
    }
    let size = usize::try_from(length).map_err(io::Error::other)?;
    let mut buffer = vec![0_u64; size.div_ceil(8)];
    // SAFETY: u64 storage is aligned for TOKEN_USER and at least length bytes long.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful GetTokenInformation initialized a TOKEN_USER; its SID
    // points into buffer, which remains alive throughout sid_string.
    sid_string(unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid })
}

fn descriptor() -> io::Result<Allocation> {
    let sid = current_user()?;
    // Explicit owner works under elevated tokens too. Administrators/SYSTEM
    // are Windows' privileged OS identities, like root on Unix.
    let sddl: Vec<u16> = format!("O:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: sddl is NUL-terminated; descriptor is writable and then owned by Allocation.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(Allocation(descriptor))
}

fn attributes(descriptor: &Allocation) -> io::Result<SECURITY_ATTRIBUTES> {
    Ok(SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).map_err(io::Error::other)?,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    })
}

fn path_wide(path: &Path) -> io::Result<Vec<u16>> {
    let mut text: Vec<u16> = path.as_os_str().encode_wide().collect();
    if text.contains(&0) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    text.push(0);
    Ok(text)
}

pub(super) fn create_dir(path: &Path) -> io::Result<()> {
    if path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let descriptor = descriptor()?;
    let attributes = attributes(&descriptor)?;
    let name = path_wide(path)?;
    // SAFETY: name and attributes (including descriptor) outlive this call.
    if unsafe { CreateDirectoryW(name.as_ptr(), &attributes) } == 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::AlreadyExists {
            return Err(error);
        }
    }
    Ok(())
}

pub(super) fn create_file(path: &Path) -> io::Result<File> {
    let descriptor = descriptor()?;
    let attributes = attributes(&descriptor)?;
    let name = path_wide(path)?;
    // GENERIC_WRITE | READ_CONTROL. CREATE_NEW never follows an existing link.
    // Sharing deletion lets a private tempfile be atomically persisted while
    // open; the protected DACL still limits who may replace it.
    // SAFETY: all pointed-to values outlive the call; a successful handle is
    // transferred exactly once to File, which closes it.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            0x4002_0000,
            FILE_SHARE_DELETE,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful CreateFileW returns an owned file handle.
    Ok(unsafe { File::from_raw_handle(handle) })
}

pub(super) fn check_dir(path: &Path) -> io::Result<bool> {
    use std::os::windows::fs::OpenOptionsExt;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    is_private(&file)
}

pub(super) fn is_private(file: &File) -> io::Result<bool> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut acl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: File owns the handle; all out-pointers are valid. The returned
    // owner/ACL live inside descriptor until Allocation frees it.
    let error = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut acl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(
            i32::try_from(error).map_err(io::Error::other)?,
        ));
    }
    let _descriptor = Allocation(descriptor);
    if owner.is_null() || acl.is_null() {
        return Ok(false);
    }
    let user = current_user()?;
    if sid_string(owner)? != user {
        return Ok(false);
    }
    // SAFETY: successful GetSecurityInfo returned a valid ACL inside descriptor.
    let count = unsafe { (*acl).AceCount };
    for index in 0..u32::from(count) {
        let mut ace = std::ptr::null_mut();
        // SAFETY: acl is live; index is below AceCount; ace is a valid out-pointer.
        if unsafe { GetAce(acl, index, &mut ace) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful GetAce returns a valid ACE headed by ACE_HEADER.
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceType == 1 {
            continue;
        }
        // Only simple allow ACEs can be interpreted here. Unknown object or
        // conditional grants are refused rather than guessed safe.
        if header.AceType != 0 {
            return Ok(false);
        }
        // SAFETY: AceType 0 identifies ACCESS_ALLOWED_ACE; SidStart is the
        // beginning of its variable-length SID, contained in the live ACL.
        let sid = unsafe {
            std::ptr::addr_of!((*ace.cast::<ACCESS_ALLOWED_ACE>()).SidStart)
                .cast_mut()
                .cast()
        };
        let trustee = sid_string(sid)?;
        if trustee != user && trustee != "S-1-5-18" && trustee != "S-1-5-32-544" {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    #[test]
    fn secrets_and_directories_readable_by_everyone_are_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let directory = tmp.path().join("device");
        super::create_dir(&directory).unwrap();
        let path = directory.join("secret");
        drop(super::create_file(&path).unwrap());
        for path in [&path, &directory] {
            let result = std::process::Command::new("icacls")
                .arg(path)
                .args(["/grant", "*S-1-1-0:(R)"])
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "icacls could not grant the test ACL"
            );
        }
        assert!(!super::is_private(&std::fs::File::open(path).unwrap()).unwrap());
        assert!(!super::check_dir(&directory).unwrap());
    }

    #[test]
    fn private_temporary_files_can_be_atomically_persisted() {
        use std::io::Write;
        let tmp = tempfile::tempdir().unwrap();
        let mut file = tempfile::Builder::new()
            .make_in(tmp.path(), super::create_file)
            .unwrap();
        assert!(super::is_private(file.as_file()).unwrap());
        file.write_all(b"private export").unwrap();
        let path = tmp.path().join("recording.cast");
        drop(file.persist(&path).unwrap());
        assert!(super::is_private(&std::fs::File::open(&path).unwrap()).unwrap());
        assert_eq!(std::fs::read(path).unwrap(), b"private export");
    }

    #[test]
    fn new_secrets_and_device_directories_are_private() {
        let tmp = tempfile::tempdir().unwrap();
        let directory = tmp.path().join("device");
        super::create_dir(&directory).unwrap();
        assert!(super::check_dir(&directory).unwrap());
        let file = super::create_file(&directory.join("secret")).unwrap();
        assert!(super::is_private(&file).unwrap());
        assert!(super::create_file(&directory.join("secret")).is_err());
    }
}
