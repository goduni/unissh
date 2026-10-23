//! Where this machine's UniSSH device lives on disk, and what is kept there.
//!
//! One directory, private to the user (created 0700):
//!
//! - `unissh.db`, `unissh-keyset.bin` — the core's encrypted instance;
//! - `link.json` — which server and account this device belongs to (nothing secret);
//! - `secret-key` — the account Secret Key, when the user lets this machine
//!   remember it (0600, and refused when anyone else can read it);
//! - `last-sync` — when the vaults were last synced;
//! - `sync.lock` — held while syncing, so two commands never sync at once.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::failure::{best_effort, Failure, Res};

const DB: &str = "unissh.db";
const DB_JOURNAL: &str = "unissh.db-journal";
const KEYSET: &str = "unissh-keyset.bin";
const LINK: &str = "link.json";
const SECRET_KEY: &str = "secret-key";
const LAST_SYNC: &str = "last-sync";
const SYNC_LOCK: &str = "sync.lock";

/// How the account on this machine got here. Decides what `logout` warns about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Origin {
    /// Paired with a signed-in device: the same account as that device.
    Paired,
    /// Recovered from the server's escrow: the same account, signed in by password.
    Escrow,
    /// A separate account created here and joined through an invite.
    Joined,
}

/// The server and account this device belongs to. Nothing in it is secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Link {
    /// Server base URL.
    pub base_url: String,
    /// Opaque server-instance id (base64).
    pub instance_id: String,
    /// The space cloud vaults are bound to on this server (base64).
    pub space_id: String,
    /// The account (base64).
    pub account_id: String,
    /// This device (base64).
    pub device_id: String,
    /// The account's handle, when known.
    pub handle: Option<String>,
    /// How the account came to this machine.
    pub origin: Origin,
}

/// The device directory.
#[derive(Clone)]
pub struct Home {
    dir: PathBuf,
}

impl Home {
    /// The directory to use: `explicit` (`--home` / `UNISSH_HOME`), else
    /// `$XDG_DATA_HOME/unissh`, else `~/.local/share/unissh`.
    pub fn locate(explicit: Option<PathBuf>) -> Res<Self> {
        let dir = explicit
            .or_else(|| absolute_env("XDG_DATA_HOME").map(|d| d.join("unissh")))
            .or_else(|| absolute_env("HOME").map(|h| h.join(".local").join("share").join("unissh")))
            .or_else(|| absolute_env("APPDATA").map(|d| d.join("unissh")))
            .ok_or_else(|| Failure::msg("cannot find a home directory: set UNISSH_HOME"))?;
        Ok(Self { dir })
    }

    /// The directory itself.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The core's encrypted database.
    pub fn db(&self) -> PathBuf {
        self.dir.join(DB)
    }

    /// The core's encrypted keyset.
    pub fn keyset(&self) -> PathBuf {
        self.dir.join(KEYSET)
    }

    /// Whether this machine holds an instance — complete or half-written.
    pub fn has_instance(&self) -> bool {
        self.db().exists() || self.keyset().exists()
    }

    /// Creates the directory, private to the user.
    pub fn create(&self) -> Res<()> {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&self.dir)?;
        Ok(())
    }

    /// The server link, if this machine is signed in.
    pub fn link(&self) -> Res<Option<Link>> {
        let bytes = match fs::read(self.dir.join(LINK)) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| Failure::msg(format!("{} is damaged: {e}", self.dir.join(LINK).display())))
    }

    /// Records the server link.
    pub fn save_link(&self, link: &Link) -> Res<()> {
        let bytes = serde_json::to_vec_pretty(link)
            .map_err(|e| Failure::msg(format!("cannot encode the server link: {e}")))?;
        write_private(&self.dir.join(LINK), &bytes)
    }

    /// The remembered Secret Key, if any.
    ///
    /// Refused, like `ssh` refuses a private key, when the file is readable by
    /// anyone but its owner: a Secret Key that others can read is one the user
    /// should rotate, not one to keep using quietly.
    pub fn secret_key(&self) -> Res<Option<Zeroizing<String>>> {
        let Some(text) = read_private(&self.dir.join(SECRET_KEY))? else {
            return Ok(None);
        };
        Ok(Some(Zeroizing::new(text.trim().to_owned())))
    }

    /// Remembers the Secret Key on this machine (owner-only file).
    pub fn remember_secret_key(&self, key: &str) -> Res<()> {
        write_private(&self.dir.join(SECRET_KEY), key.as_bytes())
    }

    /// Whether a Secret Key is remembered here.
    pub fn remembers_secret_key(&self) -> bool {
        self.dir.join(SECRET_KEY).exists()
    }

    /// When the vaults were last synced, if ever.
    pub fn last_sync(&self) -> Option<SystemTime> {
        let text = fs::read_to_string(self.dir.join(LAST_SYNC)).ok()?;
        let secs = text.trim().parse::<u64>().ok()?;
        UNIX_EPOCH.checked_add(Duration::from_secs(secs))
    }

    /// Records that the vaults were synced now.
    pub fn mark_synced(&self) -> Res<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        write_private(&self.dir.join(LAST_SYNC), now.to_string().as_bytes())
    }

    /// Waits for, then holds, the sync lock until the returned file is dropped.
    pub fn sync_lock(&self) -> Res<File> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(self.dir.join(SYNC_LOCK))?;
        file.lock()?;
        Ok(file)
    }

    /// Deletes everything this tool keeps here, then the directory if it is
    /// left empty. Files it does not know are left alone.
    pub fn wipe(&self) -> Res<()> {
        let leftovers = [LINK, SECRET_KEY, LAST_SYNC].map(|n| Path::new(n).with_extension("tmp"));
        let ours = [
            DB, DB_JOURNAL, KEYSET, LINK, SECRET_KEY, LAST_SYNC, SYNC_LOCK,
        ]
        .map(PathBuf::from);
        for name in ours.iter().chain(&leftovers) {
            let path = self.dir.join(name);
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(Failure::msg(format!(
                        "could not delete {}: {e}",
                        path.display()
                    )))
                }
            }
        }
        // Fails when the user keeps other files here — then it stays, as it should.
        best_effort(fs::remove_dir(&self.dir));
        Ok(())
    }
}

/// Reads a secret file, `None` when it does not exist. Refused when anyone but
/// its owner can read it — the file is then no longer a secret, and the user
/// has to know that rather than have it used quietly.
pub fn read_private(path: &Path) -> Res<Option<Zeroizing<String>>> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Failure::msg(format!("cannot read {}: {e}", path.display()))),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if file.metadata()?.permissions().mode() & 0o077 != 0 {
            return Err(Failure::msg(format!(
                "{} can be read by other users. Restrict it with `chmod 600 {}` — \
                 and if anyone else could have read it, treat what it holds as exposed",
                path.display(),
                path.display()
            )));
        }
    }
    let mut text = Zeroizing::new(String::new());
    file.read_to_string(&mut text)?;
    Ok(Some(text))
}

/// An environment variable holding an absolute path; empty or relative is unset
/// (the XDG rule: a relative value is invalid and must be ignored).
fn absolute_env(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

/// Writes `bytes` to `path` readable by the owner only, replacing it atomically.
fn write_private(path: &Path, bytes: &[u8]) -> Res<()> {
    let tmp = path.with_extension("tmp");
    // A leftover from an interrupted write may carry other permissions, and
    // `mode` below only applies to a file being created.
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home() -> (tempfile::TempDir, Home) {
        let dir = tempfile::tempdir().unwrap();
        let home = Home {
            dir: dir.path().join("unissh"),
        };
        home.create().unwrap();
        (dir, home)
    }

    /// The Secret Key file is the one thing here that unlocks the account with
    /// the master password: it must be created owner-only, and a copy someone
    /// loosened must be refused rather than used.
    #[cfg(unix)]
    #[test]
    fn secret_key_is_private_and_a_readable_one_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, home) = home();
        home.remember_secret_key("00ff").unwrap();
        let path = home.dir().join(SECRET_KEY);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "created owner-only"
        );
        assert_eq!(
            home.secret_key().unwrap().as_deref().map(String::as_str),
            Some("00ff")
        );

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let err = home
            .secret_key()
            .expect_err("a world-readable key is refused");
        assert!(
            err.message.contains("chmod 600"),
            "says how to fix it: {err}"
        );
    }

    /// `logout` must leave nothing of the device behind, and nothing of the
    /// user's that it does not own.
    #[test]
    fn wipe_removes_every_device_file_and_keeps_foreign_ones() {
        let (_dir, home) = home();
        for name in [DB, KEYSET, LINK, SECRET_KEY, LAST_SYNC, SYNC_LOCK] {
            fs::write(home.dir().join(name), b"x").unwrap();
        }
        fs::write(home.dir().join("notes.txt"), b"mine").unwrap();
        home.wipe().unwrap();
        for name in [DB, KEYSET, LINK, SECRET_KEY, LAST_SYNC, SYNC_LOCK] {
            assert!(!home.dir().join(name).exists(), "{name} survived the wipe");
        }
        assert!(
            home.dir().join("notes.txt").exists(),
            "a foreign file was deleted"
        );
    }
}
