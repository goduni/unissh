//! The optional `unissh` command stays independent of GTK and AppImage mounts.

use std::fs;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

pub(super) struct Launcher {
    path: PathBuf,
    bytes: Vec<u8>,
}

impl Launcher {
    pub(super) fn new(cli: &Path, desktop: &Path) -> io::Result<Self> {
        let mut bytes = b"#!/bin/sh\n# UniSSH command-line tools\ncase \"${1-}\" in\n  --gui)\n    shift\n    exec ".to_vec();
        quote_path(&mut bytes, desktop)?;
        bytes.extend_from_slice(b" \"$@\"\n    ;;\n  --help|-h)\n    ");
        quote_path(&mut bytes, cli)?;
        bytes.extend_from_slice(b" \"$@\" || exit $?\n    printf '\\nDesktop: unissh --gui opens the desktop application.\\n'\n    exit 0\n    ;;\nesac\nexec ");
        quote_path(&mut bytes, cli)?;
        bytes.extend_from_slice(b" \"$@\"\n");
        Ok(Self {
            path: super::parent(cli)?.join("unissh"),
            bytes,
        })
    }

    fn hash(&self) -> String {
        format!("{:x}", Sha256::digest(&self.bytes))
    }

    fn exists(&self) -> io::Result<bool> {
        match fs::symlink_metadata(&self.path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn owned(&self, saved: Option<&str>) -> io::Result<bool> {
        let Some(saved) = saved else {
            return Ok(false);
        };
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) if metadata.is_file() => Ok(super::digest(&self.path)? == saved),
            Ok(_) => Ok(false),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub(super) fn current(&self, saved: Option<&str>) -> io::Result<bool> {
        Ok(saved == Some(self.hash().as_str()) && self.owned(saved)?)
    }

    pub(super) fn check_replace(&self, saved: Option<&str>) -> io::Result<()> {
        // A failed marker write can leave the exact generated launcher behind.
        // Allow retrying that installation, but never adopt a symlink.
        let identical = fs::symlink_metadata(&self.path).is_ok_and(|metadata| metadata.is_file())
            && super::digest(&self.path).ok().as_deref() == Some(self.hash().as_str());
        if self.exists()? && !self.owned(saved)? && !identical {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "an unrelated unissh command already exists in ~/.local/bin; it was left untouched",
            ));
        }
        Ok(())
    }

    pub(super) fn install(&self) -> io::Result<String> {
        let mut temporary = tempfile::NamedTempFile::new_in(super::parent(&self.path)?)?;
        temporary.write_all(&self.bytes)?;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o755))?;
        temporary.as_file().sync_all()?;
        temporary.persist(&self.path).map_err(|e| e.error)?;
        Ok(self.hash())
    }

    pub(super) fn remove(&self, saved: Option<&str>) -> io::Result<()> {
        if !self.exists()? {
            return Ok(());
        }
        if !self.owned(saved)? {
            return Err(io::Error::other(
                "the installed unissh launcher has changed; it was left untouched",
            ));
        }
        fs::remove_file(&self.path)
    }
}

// Shell single quotes preserve every path byte, including whitespace, newlines,
// dollar signs and non-UTF-8 filenames. Only the exec target is generated here;
// all user arguments and standard streams pass through unchanged.
fn quote_path(output: &mut Vec<u8>, path: &Path) -> io::Result<()> {
    if !path.is_absolute() || path.as_os_str().as_bytes().contains(&0) {
        return Err(io::Error::other(
            "the launcher target must be an absolute path",
        ));
    }
    output.push(b'\'');
    for byte in path.as_os_str().as_bytes() {
        if *byte == b'\'' {
            output.extend_from_slice(b"'\\''");
        } else {
            output.push(*byte);
        }
    }
    output.push(b'\'');
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};

    #[test]
    fn dispatch_preserves_arguments_pipes_exit_codes_and_literal_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join(std::ffi::OsString::from_vec(
            b"tools '$(touch INJECTED)\n\xff".to_vec(),
        ));
        std::fs::create_dir_all(&root).unwrap();
        let cli = root.join("unissh-cli");
        let desktop = root.join("UniSSH AppImage");
        std::fs::write(&cli, b"#!/bin/sh\nif [ \"${1-}\" = --help ]; then printf 'Native CLI help\\n'; exit 0; fi\nprintf 'CLI\\n'\nprintf '<%s>\\n' \"$@\"\n/bin/cat\nexit 23\n").unwrap();
        std::fs::write(
            &desktop,
            b"#!/bin/sh\nprintf 'GUI\\n'\nprintf '<%s>\\n' \"$@\"\n",
        )
        .unwrap();
        for path in [&cli, &desktop] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let launcher = super::Launcher::new(&cli, &desktop).unwrap();
        launcher.check_replace(None).unwrap();
        let hash = launcher.install().unwrap();
        assert!(launcher.current(Some(&hash)).unwrap());
        // A missing installation marker is recoverable when bytes match exactly.
        launcher.check_replace(None).unwrap();

        let mut child = Command::new(&launcher.path)
            .args([
                "ssh",
                "host with spaces",
                "--",
                "--gui",
                "$(touch INJECTED)",
            ])
            .env("PATH", "/no-programs-on-path")
            .current_dir(tmp.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"PIPE_SENTINEL\n")
            .unwrap();
        let result = child.wait_with_output().unwrap();
        assert_eq!(result.status.code(), Some(23));
        assert_eq!(
            result.stdout,
            b"CLI\n<ssh>\n<host with spaces>\n<-->\n<--gui>\n<$(touch INJECTED)>\nPIPE_SENTINEL\n"
        );
        assert!(result.stderr.is_empty());

        let gui = Command::new(&launcher.path)
            .args(["--gui", "argument with spaces", "$(touch INJECTED)"])
            .current_dir(tmp.path())
            .output()
            .unwrap();
        assert!(gui.status.success());
        assert_eq!(
            gui.stdout,
            b"GUI\n<argument with spaces>\n<$(touch INJECTED)>\n"
        );
        assert!(!tmp.path().join("INJECTED").exists());

        let help = Command::new(&launcher.path).arg("--help").output().unwrap();
        assert!(help.status.success());
        let help = String::from_utf8(help.stdout).unwrap();
        assert!(help.starts_with("Native CLI help\n"));
        assert!(help.contains("unissh --gui"));
    }
}
