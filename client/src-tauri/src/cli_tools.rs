//! Optional per-user installation of the CLI shipped alongside the desktop app.
//! Copies the binary out of the bundle (an AppImage mount is temporary), never
//! overwrites an unrelated command, and only refreshes copies the user installed.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::Manager;

use crate::commands::blocking_api;
use crate::error::{ApiError, ApiResult};

#[cfg(windows)]
#[path = "cli_tools/windows_path.rs"]
mod windows_path;

const COMMAND: &str = if cfg!(windows) {
    "unissh-cli.exe"
} else {
    "unissh-cli"
};
static INSTALLATION: std::sync::Mutex<()> = std::sync::Mutex::new(());

const MARKER: &str = "cli-install.json";
#[cfg(unix)]
const PROFILE_START: &str = "# >>> UniSSH command-line tools >>>";
#[cfg(unix)]
const PROFILE_END: &str = "# <<< UniSSH command-line tools <<<";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CliStatus {
    available: bool,
    installed: bool,
    update_available: bool,
    path_configured: bool,
    install_path: String,
}

#[derive(Serialize, Deserialize)]
struct Installed {
    sha256: String,
}

struct Layout {
    source: PathBuf,
    binary: PathBuf,
    marker: PathBuf,
    #[cfg(unix)]
    home: PathBuf,
}

impl Layout {
    fn for_app(app: &tauri::AppHandle) -> ApiResult<Self> {
        let source = app
            .path()
            .resource_dir()
            .map_err(ApiError::other)?
            .join("cli")
            .join(COMMAND);
        #[cfg(unix)]
        let home = app.path().home_dir().map_err(ApiError::other)?;
        #[cfg(windows)]
        let bin = app
            .path()
            .app_local_data_dir()
            .map_err(ApiError::other)?
            .join("cli-bin");
        #[cfg(unix)]
        let bin = home.join(".local/bin");
        Ok(Self {
            source,
            binary: bin.join(COMMAND),
            marker: app
                .path()
                .app_data_dir()
                .map_err(ApiError::other)?
                .join(MARKER),
            #[cfg(unix)]
            home,
        })
    }

    fn saved(&self) -> io::Result<Option<Installed>> {
        match fs::read(&self.marker) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(io::Error::other),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn owned(&self) -> io::Result<bool> {
        let Some(saved) = self.saved()? else {
            return Ok(false);
        };
        if self
            .binary
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink())
        {
            return Ok(false);
        }
        match digest(&self.binary) {
            Ok(hash) => Ok(hash == saved.sha256),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn status(&self) -> io::Result<CliStatus> {
        let available = self.source.is_file();
        let installed = self.owned()?;
        let update_available =
            installed && available && digest(&self.source)? != digest(&self.binary)?;
        Ok(CliStatus {
            available,
            installed,
            update_available,
            path_configured: self.path_configured()?,
            install_path: self.binary.to_string_lossy().into_owned(),
        })
    }

    fn install_files(&self) -> io::Result<()> {
        let hash = digest(&self.source)?;
        let metadata = self.binary.symlink_metadata().ok();
        if metadata
            .as_ref()
            .is_some_and(|m| m.file_type().is_symlink())
            || (metadata.is_some() && !self.owned()? && digest(&self.binary)? != hash)
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "an unrelated unissh-cli command already exists; it was left untouched",
            ));
        }
        let parent = parent(&self.binary)?;
        fs::create_dir_all(parent)?;
        if digest(&self.binary).ok().as_deref() != Some(hash.as_str()) {
            let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
            io::copy(&mut File::open(&self.source)?, &mut temporary)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                temporary
                    .as_file()
                    .set_permissions(fs::Permissions::from_mode(0o755))?;
            }
            temporary.as_file().sync_all()?;
            temporary.persist(&self.binary).map_err(|e| e.error)?;
        }
        let record = serde_json::to_vec(&Installed { sha256: hash }).map_err(io::Error::other)?;
        atomic_write(&self.marker, &record)
    }

    fn remove_files(&self) -> io::Result<()> {
        if !self.owned()? {
            return Err(io::Error::other(
                "the installed command has changed; it was left untouched",
            ));
        }
        fs::remove_file(&self.binary)?;
        fs::remove_file(&self.marker)
    }

    fn path_configured(&self) -> io::Result<bool> {
        #[cfg(windows)]
        {
            windows_path::contains(parent(&self.binary)?)
        }
        #[cfg(unix)]
        {
            if std::env::var_os("PATH").is_some_and(|value| {
                std::env::split_paths(&value)
                    .any(|p| p == self.binary.parent().unwrap_or(Path::new("")))
            }) {
                return Ok(true);
            }
            let (path, _) = shell_profile(&self.home);
            match fs::read_to_string(path) {
                Ok(text) => Ok(text.contains(PROFILE_START) && text.contains(PROFILE_END)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
                Err(e) => Err(e),
            }
        }
    }

    fn configure_path(&self) -> io::Result<()> {
        #[cfg(windows)]
        {
            windows_path::add(parent(&self.binary)?)
        }
        #[cfg(unix)]
        {
            if self.path_configured()? {
                return Ok(());
            }
            let (path, fish) = shell_profile(&self.home);
            let mut text = match fs::read_to_string(&path) {
                Ok(text) => text,
                Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
                Err(e) => return Err(e),
            };
            text = profile_with_path(&text, fish);
            atomic_write(&path, text.as_bytes())
        }
    }
}

fn parent(path: &Path) -> io::Result<&Path> {
    path.parent()
        .ok_or_else(|| io::Error::other("installation directory is unavailable"))
}

fn digest(path: &Path) -> io::Result<String> {
    let mut hash = Sha256::new();
    let mut file = File::open(path)?;
    let mut buffer = [0_u8; 65536];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(
            buffer
                .get(..n)
                .ok_or_else(|| io::Error::other("invalid read length"))?,
        );
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    fs::create_dir_all(parent(path)?)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent(path)?)?;
    if let Ok(metadata) = fs::metadata(path) {
        temporary
            .as_file()
            .set_permissions(metadata.permissions())?;
    }
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|e| e.error)?;
    Ok(())
}

#[cfg(unix)]
fn shell_profile(home: &Path) -> (PathBuf, bool) {
    let shell = std::env::var_os("SHELL").map(PathBuf::from);
    match shell
        .as_deref()
        .and_then(Path::file_name)
        .and_then(|n| n.to_str())
    {
        Some("zsh") => (home.join(".zshrc"), false),
        Some("bash") => (home.join(".bashrc"), false),
        Some("fish") => (home.join(".config/fish/conf.d/unissh-cli.fish"), true),
        #[cfg(target_os = "macos")]
        _ => (home.join(".zshrc"), false),
        #[cfg(not(target_os = "macos"))]
        _ => (home.join(".profile"), false),
    }
}

#[cfg(unix)]
fn profile_with_path(existing: &str, fish: bool) -> String {
    if existing.contains(PROFILE_START) {
        return existing.to_owned();
    }
    let command = if fish {
        "fish_add_path --path \"$HOME/.local/bin\""
    } else {
        "case \":$PATH:\" in\n  *\":$HOME/.local/bin:\"*) ;;\n  *) export PATH=\"$HOME/.local/bin:$PATH\" ;;\nesac"
    };
    format!("{existing}\n{PROFILE_START}\n{command}\n{PROFILE_END}\n")
}

#[tauri::command]
pub async fn cli_tools_status(app: tauri::AppHandle) -> ApiResult<CliStatus> {
    blocking_api(move || {
        let _installation = INSTALLATION.lock().map_err(ApiError::other)?;
        Layout::for_app(&app)?.status().map_err(ApiError::other)
    })
    .await
}

#[tauri::command]
pub async fn cli_tools_install(app: tauri::AppHandle) -> ApiResult<CliStatus> {
    blocking_api(move || {
        let _installation = INSTALLATION.lock().map_err(ApiError::other)?;
        let layout = Layout::for_app(&app)?;
        layout.install_files().map_err(ApiError::other)?;
        layout.configure_path().map_err(ApiError::other)?;
        layout.status().map_err(ApiError::other)
    })
    .await
}

#[tauri::command]
pub async fn cli_tools_remove(app: tauri::AppHandle) -> ApiResult<CliStatus> {
    blocking_api(move || {
        let _installation = INSTALLATION.lock().map_err(ApiError::other)?;
        let layout = Layout::for_app(&app)?;
        layout.remove_files().map_err(ApiError::other)?;
        #[cfg(windows)]
        windows_path::remove(parent(&layout.binary).map_err(ApiError::other)?)
            .map_err(ApiError::other)?;
        layout.status().map_err(ApiError::other)
    })
    .await
}

/// Updates only a previously opted-in, unmodified installation. The app never
/// enables CLI installation or changes PATH merely because it was launched.
pub fn refresh_installed(app: tauri::AppHandle) {
    std::thread::spawn(move || {
        let refresh = || -> ApiResult<()> {
            let _installation = INSTALLATION.lock().map_err(ApiError::other)?;
            let layout = Layout::for_app(&app)?;
            if layout.owned().map_err(ApiError::other)? && layout.source.is_file() {
                layout.install_files().map_err(ApiError::other)?;
            }
            Ok(())
        };
        if refresh().is_err() {
            log::warn!("the installed CLI could not be refreshed; retry from Settings");
        }
    });
}

#[cfg(test)]
mod tests {
    fn layout(root: &std::path::Path) -> super::Layout {
        super::Layout {
            source: root.join("bundle/cli"),
            binary: root.join("bin/cli"),
            marker: root.join("app/cli.json"),
            #[cfg(unix)]
            home: root.to_path_buf(),
        }
    }

    #[test]
    fn installation_is_opt_in_updatable_and_does_not_overwrite_other_commands() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = layout(tmp.path());
        std::fs::create_dir_all(layout.source.parent().unwrap()).unwrap();
        std::fs::write(&layout.source, b"first CLI").unwrap();
        assert!(!layout.binary.exists());
        layout.install_files().unwrap();
        assert!(layout.owned().unwrap());
        std::fs::write(&layout.source, b"updated CLI").unwrap();
        layout.install_files().unwrap();
        assert_eq!(std::fs::read(&layout.binary).unwrap(), b"updated CLI");
        std::fs::write(&layout.binary, b"a user's different command").unwrap();
        assert!(!layout.owned().unwrap());
        assert!(layout.install_files().is_err());
        assert!(layout.remove_files().is_err());
        assert_eq!(
            std::fs::read(&layout.binary).unwrap(),
            b"a user's different command"
        );
    }

    #[test]
    fn removal_only_removes_the_managed_copy() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = layout(tmp.path());
        std::fs::create_dir_all(layout.source.parent().unwrap()).unwrap();
        std::fs::write(&layout.source, b"CLI").unwrap();
        layout.install_files().unwrap();
        layout.remove_files().unwrap();
        assert!(!layout.binary.exists());
        assert!(!layout.marker.exists());
        assert!(layout.source.exists());
    }

    #[cfg(unix)]
    #[test]
    fn shell_configuration_preserves_existing_text_and_never_stacks_blocks() {
        let original = "# user's settings\nexport EDITOR=vim\n";
        let configured = super::profile_with_path(original, false);
        assert!(configured.starts_with(original));
        assert_eq!(super::profile_with_path(&configured, false), configured);
        assert!(super::profile_with_path(original, true).contains("fish_add_path --path"));
    }
}
