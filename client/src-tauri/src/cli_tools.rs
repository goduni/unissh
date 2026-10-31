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

#[cfg(target_os = "linux")]
mod linux_launcher;

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
    command: &'static str,
    available: bool,
    installed: bool,
    update_available: bool,
    path_configured: bool,
    install_path: String,
}

#[derive(Serialize, Deserialize)]
struct Installed {
    sha256: String,
    #[cfg(target_os = "linux")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    launcher_sha256: Option<String>,
}

struct Layout {
    source: PathBuf,
    binary: PathBuf,
    marker: PathBuf,
    #[cfg(unix)]
    home: PathBuf,
    #[cfg(target_os = "linux")]
    desktop: PathBuf,
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
            #[cfg(target_os = "linux")]
            desktop: std::env::var_os("APPIMAGE")
                .map(PathBuf::from)
                .map_or_else(std::env::current_exe, |path| fs::canonicalize(path))
                .map_err(ApiError::other)?,
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
        #[cfg(target_os = "linux")]
        let update_available = update_available
            || (installed
                && !self.launcher()?.current(
                    self.saved()?
                        .as_ref()
                        .and_then(|s| s.launcher_sha256.as_deref()),
                )?);
        Ok(CliStatus {
            command: if cfg!(target_os = "linux") {
                "unissh"
            } else {
                "unissh-cli"
            },
            available,
            installed,
            update_available,
            path_configured: self.path_configured()?,
            install_path: if cfg!(target_os = "linux") {
                parent(&self.binary)?.join("unissh")
            } else {
                self.binary.clone()
            }
            .to_string_lossy()
            .into_owned(),
        })
    }

    fn install_files(&self) -> io::Result<()> {
        let hash = digest(&self.source)?;
        #[cfg(target_os = "linux")]
        let launcher = self.launcher()?;
        #[cfg(target_os = "linux")]
        launcher.check_replace(
            self.saved()?
                .as_ref()
                .and_then(|s| s.launcher_sha256.as_deref()),
        )?;
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
        let record = serde_json::to_vec(&Installed {
            sha256: hash,
            #[cfg(target_os = "linux")]
            launcher_sha256: Some(launcher.install()?),
        })
        .map_err(io::Error::other)?;
        atomic_write(&self.marker, &record)
    }

    fn remove_files(&self) -> io::Result<()> {
        if !self.owned()? {
            return Err(io::Error::other(
                "the installed command has changed; it was left untouched",
            ));
        }
        #[cfg(target_os = "linux")]
        self.launcher()?.remove(
            self.saved()?
                .as_ref()
                .and_then(|s| s.launcher_sha256.as_deref()),
        )?;
        fs::remove_file(&self.binary)?;
        fs::remove_file(&self.marker)
    }

    #[cfg(target_os = "linux")]
    fn launcher(&self) -> io::Result<linux_launcher::Launcher> {
        linux_launcher::Launcher::new(&self.binary, &self.desktop)
    }

    fn path_configured(&self) -> io::Result<bool> {
        #[cfg(windows)]
        {
            windows_path::contains(parent(&self.binary)?)
        }
        #[cfg(unix)]
        {
            let directory = parent(&self.binary)?;
            if std::env::var_os("PATH").is_some_and(|value| {
                let mut paths = std::env::split_paths(&value);
                if cfg!(target_os = "linux") {
                    paths.next().is_some_and(|p| p == directory)
                } else {
                    paths.any(|p| p == directory)
                }
            }) {
                return Ok(true);
            }
            let (path, fish) = shell_profile(&self.home);
            match fs::read_to_string(path) {
                Ok(text) => Ok(text.contains(PROFILE_START)
                    && text.contains(PROFILE_END)
                    && (!cfg!(target_os = "linux") || profile_with_path(&text, fish) == text)),
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
            // Dotfile managers commonly symlink shell profiles. Update the
            // target atomically and preserve the link; a dangling link fails
            // before any profile is replaced.
            let path = if path.is_symlink() {
                fs::canonicalize(path)?
            } else {
                path
            };
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
        #[cfg(target_os = "macos")]
        Some("bash") => (home.join(".bash_profile"), false),
        #[cfg(not(target_os = "macos"))]
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
    let command = if fish {
        if cfg!(target_os = "linux") {
            "fish_add_path --path --move --prepend \"$HOME/.local/bin\""
        } else {
            "fish_add_path --path \"$HOME/.local/bin\""
        }
    } else if cfg!(target_os = "linux") {
        "case \"$PATH\" in\n  \"$HOME/.local/bin\"|\"$HOME/.local/bin:\"*) ;;\n  *) export PATH=\"$HOME/.local/bin:$PATH\" ;;\nesac"
    } else {
        "case \":$PATH:\" in\n  *\":$HOME/.local/bin:\"*) ;;\n  *) export PATH=\"$HOME/.local/bin:$PATH\" ;;\nesac"
    };
    let block = format!("{PROFILE_START}\n{command}\n{PROFILE_END}");
    if let Some((before, rest)) = existing.split_once(PROFILE_START) {
        if let Some((_, after)) = rest.split_once(PROFILE_END) {
            return format!("{before}{block}{after}");
        }
        return existing.to_owned();
    }
    format!("{existing}\n{block}\n")
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
        #[cfg(windows)]
        {
            if !layout.owned().map_err(ApiError::other)? {
                return Err(ApiError::other(
                    "the installed command has changed; it was left untouched",
                ));
            }
            // If PATH cannot be updated, keep the managed copy and marker so
            // removal can be retried. Never alter PATH for an unrelated file.
            windows_path::remove(parent(&layout.binary).map_err(ApiError::other)?)
                .map_err(ApiError::other)?;
        }
        layout.remove_files().map_err(ApiError::other)?;
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
            #[cfg(target_os = "linux")]
            desktop: root.join("application/UniSSH.AppImage"),
        }
    }

    #[test]
    fn installation_is_opt_in_updatable_and_does_not_overwrite_other_commands() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = layout(tmp.path());
        std::fs::create_dir_all(layout.source.parent().unwrap()).unwrap();
        std::fs::write(&layout.source, b"first CLI").unwrap();
        assert!(!layout.binary.exists());
        assert!(!layout.status().unwrap().installed);
        layout.install_files().unwrap();
        assert!(layout.owned().unwrap());
        assert!(!layout.status().unwrap().update_available);
        std::fs::write(&layout.source, b"updated CLI").unwrap();
        assert!(layout.status().unwrap().update_available);
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
        #[cfg(target_os = "linux")]
        assert!(!layout.binary.parent().unwrap().join("unissh").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn legacy_installation_can_add_the_unified_launcher() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = layout(tmp.path());
        std::fs::create_dir_all(layout.source.parent().unwrap()).unwrap();
        std::fs::write(&layout.source, b"CLI").unwrap();
        layout.install_files().unwrap();
        let launcher = layout.binary.parent().unwrap().join("unissh");
        std::fs::remove_file(&launcher).unwrap();
        let old = serde_json::json!({"sha256": super::digest(&layout.binary).unwrap()});
        std::fs::write(&layout.marker, serde_json::to_vec(&old).unwrap()).unwrap();
        assert!(layout.status().unwrap().installed);
        assert!(layout.status().unwrap().update_available);
        layout.install_files().unwrap();
        assert_eq!(layout.status().unwrap().command, "unissh");
        assert!(!layout.status().unwrap().update_available);
        assert!(launcher.is_file());
        let original = std::fs::read(&launcher).unwrap();
        let moved = super::Layout {
            desktop: tmp.path().join("moved/UniSSH.AppImage"),
            ..layout
        };
        assert!(moved.status().unwrap().update_available);
        moved.install_files().unwrap();
        assert_ne!(std::fs::read(&launcher).unwrap(), original);
        assert!(!moved.status().unwrap().update_available);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn installed_launcher_runs_the_bundled_cli_without_a_display() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = super::Layout {
            source: std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("binaries/cli/unissh-cli"),
            ..layout(tmp.path())
        };
        layout.install_files().unwrap();
        let status = layout.status().unwrap();
        let output = std::process::Command::new(&status.install_path)
            .arg("--version")
            .env("DISPLAY", "")
            .env("WAYLAND_DISPLAY", "")
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!("unissh {}\n", env!("CARGO_PKG_VERSION"))
        );
        let help = std::process::Command::new(status.install_path)
            .arg("--help")
            .output()
            .unwrap();
        assert!(help.status.success());
        assert!(String::from_utf8(help.stdout)
            .unwrap()
            .contains("unissh --gui"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn path_registration_promotes_the_launcher_and_upgrades_only_its_own_block() {
        let tmp = tempfile::tempdir().unwrap();
        let old = format!(
            "# before\n{}\nexport PATH=\"$PATH:$HOME/.local/bin\"\n{}\n# after\n",
            super::PROFILE_START,
            super::PROFILE_END
        );
        let configured = super::profile_with_path(&old, false);
        assert!(configured.starts_with("# before\n"));
        assert!(configured.ends_with("# after\n"));
        assert_eq!(super::profile_with_path(&configured, false), configured);
        let profile = tmp.path().join("profile");
        std::fs::write(&profile, configured).unwrap();
        let result = std::process::Command::new("/bin/sh")
            .args(["-c", "PATH=\"/usr/bin:$HOME/.local/bin\"; . \"$UNISSH_TEST_PROFILE\"; . \"$UNISSH_TEST_PROFILE\"; printf '%s' \"$PATH\""])
            .env("HOME", tmp.path())
            .env("UNISSH_TEST_PROFILE", profile)
            .output().unwrap();
        assert!(result.status.success());
        assert!(String::from_utf8(result.stdout)
            .unwrap()
            .starts_with(&format!("{}/.local/bin:/usr/bin:", tmp.path().display())));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn foreign_unissh_commands_and_links_are_preserved() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = layout(tmp.path());
        std::fs::create_dir_all(layout.source.parent().unwrap()).unwrap();
        std::fs::create_dir_all(layout.binary.parent().unwrap()).unwrap();
        std::fs::write(&layout.source, b"CLI").unwrap();
        let launcher = layout.binary.parent().unwrap().join("unissh");
        std::fs::write(&launcher, b"user command").unwrap();
        assert!(layout.install_files().is_err());
        assert!(!layout.binary.exists());
        assert_eq!(std::fs::read(&launcher).unwrap(), b"user command");
        std::fs::remove_file(&launcher).unwrap();
        std::os::unix::fs::symlink(&layout.source, &launcher).unwrap();
        assert!(layout.install_files().is_err());
        assert!(launcher.is_symlink());
        std::fs::remove_file(&launcher).unwrap();
        layout.install_files().unwrap();
        std::fs::write(&launcher, b"user-modified launcher").unwrap();
        assert!(layout.install_files().is_err());
        assert!(layout.remove_files().is_err());
        assert_eq!(std::fs::read(&launcher).unwrap(), b"user-modified launcher");
        assert!(layout.owned().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn installation_never_adopts_a_symbolic_link() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = layout(tmp.path());
        std::fs::create_dir_all(layout.source.parent().unwrap()).unwrap();
        std::fs::create_dir_all(layout.binary.parent().unwrap()).unwrap();
        std::fs::write(&layout.source, b"CLI").unwrap();
        std::os::unix::fs::symlink(&layout.source, &layout.binary).unwrap();
        assert!(layout.install_files().is_err());
        assert!(!layout.owned().unwrap());
        assert!(layout.remove_files().is_err());
        assert!(layout.binary.is_symlink());
    }

    #[cfg(unix)]
    #[test]
    fn path_registration_preserves_the_profile_and_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = layout(tmp.path());
        let (profile, _) = super::shell_profile(&layout.home);
        std::fs::create_dir_all(profile.parent().unwrap()).unwrap();
        std::fs::write(&profile, "# user's settings\nexport EDITOR=vim\n").unwrap();
        assert!(!layout.path_configured().unwrap());
        layout.configure_path().unwrap();
        assert!(layout.path_configured().unwrap());
        let configured = std::fs::read(&profile).unwrap();
        layout.configure_path().unwrap();
        assert_eq!(std::fs::read(&profile).unwrap(), configured);
        assert!(configured.starts_with(b"# user's settings\nexport EDITOR=vim\n"));
    }

    #[cfg(unix)]
    #[test]
    fn path_registration_preserves_symlinked_dotfiles_and_refuses_dangling_links() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = layout(tmp.path());
        let (profile, _) = super::shell_profile(&layout.home);
        std::fs::create_dir_all(profile.parent().unwrap()).unwrap();
        let target = tmp.path().join("shell-settings");
        std::fs::write(&target, "# dotfiles\n").unwrap();
        std::os::unix::fs::symlink(&target, &profile).unwrap();
        layout.configure_path().unwrap();
        assert!(profile.is_symlink());
        assert!(std::fs::read_to_string(&target)
            .unwrap()
            .starts_with("# dotfiles\n"));
        assert!(layout.path_configured().unwrap());
        std::fs::remove_file(&target).unwrap();
        assert!(layout.configure_path().is_err());
        assert!(profile.is_symlink());
        assert!(!target.exists());
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
