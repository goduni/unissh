//! Where the system agent's Unix socket lives, and getting it ready to bind.
//! Plain `std`, so it can be tested without the app.

use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

/// The socket's file name inside its directory.
const SOCKET: &str = "agent.sock";

/// Resolves the socket path.
///
/// The per-user runtime directory (`$XDG_RUNTIME_DIR` on Linux) is preferred:
/// it is private to the user, lives in memory and is cleared at logout, which
/// is exactly the lifetime a socket wants. Where the OS has none (macOS), the
/// app's local data directory is used instead. Either way the socket sits in a
/// directory of its own, so that directory's mode can gate it.
pub fn socket_path(runtime_dir: Option<&Path>, local_data_dir: &Path) -> PathBuf {
    match runtime_dir {
        Some(dir) => dir.join("unissh"),
        None => local_data_dir.join("agent"),
    }
    .join(SOCKET)
}

/// Creates the socket's directory if needed and makes it `0700`, so only this
/// user can reach anything inside it, whatever mode the socket itself ends up
/// with between `bind` and `chmod`.
pub fn prepare_dir(dir: &Path) -> io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    // Not followed through a symlink: the directory must be a directory.
    if !fs::symlink_metadata(dir)?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "the agent directory is not a directory",
        ));
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
}

/// Removes a socket left behind by a run that did not shut down cleanly, so
/// that `bind` does not fail on it.
///
/// Only a socket nobody answers on is removed: a live one belongs to another
/// running instance and is reported as in use, and a path that is not a socket
/// at all is never deleted.
pub fn clear_stale_socket(path: &Path) -> io::Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if !meta.file_type().is_socket() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "the agent socket path is taken by something that is not a socket",
        ));
    }
    if UnixStream::connect(path).is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "another agent is listening on this socket",
        ));
    }
    fs::remove_file(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_path_prefers_the_runtime_dir() {
        let data = Path::new("/home/u/.local/share/me.goduni.unissh");
        assert_eq!(
            socket_path(Some(Path::new("/run/user/1000")), data),
            Path::new("/run/user/1000/unissh/agent.sock")
        );
        assert_eq!(socket_path(None, data), data.join("agent/agent.sock"));
    }

    #[test]
    fn a_stale_socket_is_removed_so_bind_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(SOCKET);
        // A crashed run: the listener is gone, its file is not.
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
        assert!(path.exists());

        clear_stale_socket(&path).unwrap();
        std::os::unix::net::UnixListener::bind(&path).expect("bind after cleanup");
    }
}
