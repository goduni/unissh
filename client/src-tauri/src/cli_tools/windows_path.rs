//! Per-user PATH registration. Preserve its original registry type and every
//! unrelated entry; broadcast the change so newly opened terminals inherit it.

use std::io;
use std::path::Path;

use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
    HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_EXPAND_SZ, REG_OPTION_NON_VOLATILE,
    REG_SZ,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE,
};

struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: this module owns a registry key returned by Open/CreateKey.
        unsafe {
            RegCloseKey(self.0);
        }
    }
}

fn check(error: u32) -> io::Result<()> {
    if error == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(
            i32::try_from(error).map_err(io::Error::other)?,
        ))
    }
}

fn key(create: bool) -> io::Result<Option<Key>> {
    let name: Vec<u16> = "Environment\0".encode_utf16().collect();
    let mut handle = std::ptr::null_mut();
    // SAFETY: name is NUL-terminated and handle is a valid out-pointer. HKCU
    // is borrowed; only the returned key is owned by Key.
    let result = unsafe {
        if create {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                name.as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_QUERY_VALUE | KEY_SET_VALUE,
                std::ptr::null(),
                &mut handle,
                std::ptr::null_mut(),
            )
        } else {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                name.as_ptr(),
                0,
                KEY_QUERY_VALUE,
                &mut handle,
            )
        }
    };
    if !create && result == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    check(result)?;
    Ok(Some(Key(handle)))
}

fn read(key: &Key) -> io::Result<(String, u32)> {
    let name: Vec<u16> = "Path\0".encode_utf16().collect();
    let mut bytes = 0;
    let mut kind = REG_EXPAND_SZ;
    // SAFETY: a null data buffer queries its size and type.
    let result = unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            std::ptr::null(),
            &mut kind,
            std::ptr::null_mut(),
            &mut bytes,
        )
    };
    if result == ERROR_FILE_NOT_FOUND {
        return Ok((String::new(), REG_EXPAND_SZ));
    }
    check(result)?;
    if !matches!(kind, REG_SZ | REG_EXPAND_SZ) || bytes % 2 != 0 {
        return Err(io::Error::other("the user PATH is not a Unicode string"));
    }
    let mut text = vec![
        0_u16;
        usize::try_from(bytes)
            .map_err(io::Error::other)?
            .div_ceil(2)
    ];
    // SAFETY: text has at least bytes of initialized, aligned storage; pointers
    // remain live for this call. A concurrent resize returns ERROR_MORE_DATA.
    check(unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            std::ptr::null(),
            &mut kind,
            text.as_mut_ptr().cast(),
            &mut bytes,
        )
    })?;
    let used = usize::try_from(bytes / 2).map_err(io::Error::other)?;
    text.truncate(used);
    while text.last() == Some(&0) {
        text.pop();
    }
    Ok((String::from_utf16(&text).map_err(io::Error::other)?, kind))
}

fn matches(entry: &str, directory: &str) -> bool {
    entry
        .trim()
        .trim_matches('"')
        .trim_end_matches(['\\', '/'])
        .eq_ignore_ascii_case(directory.trim_end_matches(['\\', '/']))
}

pub(super) fn contains(directory: &Path) -> io::Result<bool> {
    let Some(key) = key(false)? else {
        return Ok(false);
    };
    let (path, _) = read(&key)?;
    Ok(path
        .split(';')
        .any(|entry| matches(entry, &directory.to_string_lossy())))
}

pub(super) fn add(directory: &Path) -> io::Result<()> {
    change(directory, true)
}
pub(super) fn remove(directory: &Path) -> io::Result<()> {
    change(directory, false)
}

fn change(directory: &Path, add: bool) -> io::Result<()> {
    let text = directory
        .to_str()
        .ok_or_else(|| io::Error::other("the CLI installation path is not Unicode"))?;
    if text.contains([';', '%']) {
        return Err(io::Error::other(
            "the CLI path cannot contain a PATH separator or environment expansion",
        ));
    }
    let key = key(true)?.ok_or_else(|| io::Error::other("user environment is unavailable"))?;
    let (original, kind) = read(&key)?;
    let found = original.split(';').any(|entry| matches(entry, text));
    if add == found {
        return Ok(());
    }
    let value = if add {
        if original.is_empty() {
            text.to_owned()
        } else {
            format!("{original};{text}")
        }
    } else {
        original
            .split(';')
            .filter(|entry| !matches(entry, text))
            .collect::<Vec<_>>()
            .join(";")
    };
    let name: Vec<u16> = "Path\0".encode_utf16().collect();
    let value: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    let bytes = u32::try_from(
        value
            .len()
            .checked_mul(2)
            .ok_or_else(|| io::Error::other("PATH is too long"))?,
    )
    .map_err(io::Error::other)?;
    // SAFETY: name is terminated; value has bytes of UTF-16 storage and is live
    // for the call. The original string type (including %VAR% expansion) stays.
    check(unsafe { RegSetValueExW(key.0, name.as_ptr(), 0, kind, value.as_ptr().cast(), bytes) })?;
    let environment: Vec<u16> = "Environment\0".encode_utf16().collect();
    // SAFETY: the string stays alive during this synchronous bounded broadcast;
    // no receiving process owns it. The return value is advisory only.
    unsafe {
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            environment.as_ptr() as isize,
            SMTO_ABORTIFHUNG,
            1000,
            std::ptr::null_mut(),
        )
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn path_matching_handles_case_quotes_and_trailing_separators() {
        assert!(super::matches(
            r#" "C:\Users\Alex\cli\" "#,
            r"c:\users\alex\cli"
        ));
        assert!(!super::matches(
            r"C:\Users\Alex\cli-other",
            r"C:\Users\Alex\cli"
        ));
    }
}
