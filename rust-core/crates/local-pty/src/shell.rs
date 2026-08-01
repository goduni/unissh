//! Which shell to start, and who/where we are — the environment facts a local
//! terminal needs before it can open one.

use std::path::{Path, PathBuf};

/// The program a local terminal starts when the user has not named one, plus the
/// arguments that make it behave the way that platform's users expect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellChoice {
    /// Absolute path to the shell binary.
    pub program: String,
    /// Arguments passed before the shell goes interactive.
    pub args: Vec<String>,
}

/// The default shell for this machine, resolved from the environment.
///
/// unix: `$SHELL` → the user's `/etc/passwd` entry → `/bin/sh`.
/// Windows: `pwsh.exe` → `powershell.exe` → `cmd.exe`.
pub fn resolve_default_shell() -> ShellChoice {
    ShellChoice {
        program: default_program(),
        args: default_args(),
    }
}

/// Splits an argument string the way a shell would — so `-c "echo hi"` is two
/// arguments, not three.
///
/// An unbalanced quote is a mistake worth reporting rather than guessing at, so
/// it comes back as `None` and the caller can leave the settings field flagged.
pub fn split_args(text: &str) -> Option<Vec<String>> {
    shell_words::split(text).ok()
}

/// The OS account this process runs as. `"unknown"` when the environment does
/// not say — a made-up name would be worse than an admitted gap, since this
/// string is shown as the identity a local session ran under.
pub fn os_username() -> String {
    #[cfg(windows)]
    let vars = ["USERNAME"];
    #[cfg(not(windows))]
    let vars = ["USER", "LOGNAME"];
    for v in vars {
        if let Some(name) = std::env::var_os(v) {
            let name = name.to_string_lossy().trim().to_string();
            if !name.is_empty() {
                return name;
            }
        }
    }
    "unknown".to_string()
}

/// This machine's hostname — what tells a local pane apart from a remote one in
/// the status line.
pub fn machine_name() -> String {
    let name = gethostname::gethostname().to_string_lossy().to_string();
    if name.trim().is_empty() {
        "localhost".to_string()
    } else {
        name
    }
}

/// The user's home directory, or `None` if the environment does not name one or
/// names one that is not there.
///
/// Deliberately not the process's working directory: that is wherever the bundle
/// was launched from (`/` under a desktop launcher), which is not a place anyone
/// wants a shell to open in. `None` therefore means "we do not know", not "use
/// the current directory" — though the current directory is what a child with no
/// `cwd` set inherits, and with `$HOME`/`%USERPROFILE%` unset there is nothing
/// better to offer. See `LocalPty::spawn`.
pub fn home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    let var = "USERPROFILE";
    #[cfg(not(windows))]
    let var = "HOME";
    std::env::var_os(var)
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
}

#[cfg(not(windows))]
fn default_program() -> String {
    if let Some(sh) = std::env::var_os("SHELL") {
        let sh = sh.to_string_lossy().to_string();
        if Path::new(&sh).is_absolute() {
            return sh;
        }
    }
    // A login shell started from a desktop launcher may have no `$SHELL`; the
    // passwd entry is the same answer `login` would have used. (On macOS regular
    // accounts live in Directory Services rather than `/etc/passwd`, so this
    // simply finds nothing there and the fallback below applies — `$SHELL` is
    // set in every practical macOS session anyway.)
    if let Some(sh) = passwd_shell(&os_username()) {
        return sh;
    }
    "/bin/sh".to_string()
}

/// The login shell recorded for `user` in `/etc/passwd`, if that file names one.
#[cfg(not(windows))]
fn passwd_shell(user: &str) -> Option<String> {
    passwd_shell_in(&std::fs::read_to_string("/etc/passwd").ok()?, user)
}

/// The parse behind [`passwd_shell`], over the file's text.
#[cfg(not(windows))]
fn passwd_shell_in(passwd: &str, user: &str) -> Option<String> {
    if user.is_empty() {
        return None;
    }
    for line in passwd.lines() {
        let mut fields = line.split(':');
        if fields.next() != Some(user) {
            continue;
        }
        // name:passwd:uid:gid:gecos:home:shell — five fields past the name.
        let shell = fields.nth(5)?;
        if Path::new(shell).is_absolute() {
            return Some(shell.to_string());
        }
    }
    None
}

#[cfg(windows)]
fn default_program() -> String {
    for candidate in ["pwsh.exe", "powershell.exe"] {
        if let Some(found) = which(candidate) {
            return found;
        }
    }
    std::env::var("ComSpec").unwrap_or_else(|_| "cmd.exe".to_string())
}

/// First match for `name` on `PATH`. Only used on Windows, where the candidates
/// carry their own `.exe`, so `PATHEXT` never enters into it.
#[cfg(windows)]
fn which(name: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
        .map(|p| p.to_string_lossy().to_string())
}

#[cfg(target_os = "macos")]
fn default_args() -> Vec<String> {
    // A login shell is the norm on macOS: Terminal.app and iTerm both start one,
    // and without it `~/.zprofile` — where Homebrew puts the PATH — never runs,
    // so half the user's tools would appear to be missing.
    vec!["-l".to_string()]
}

#[cfg(not(target_os = "macos"))]
fn default_args() -> Vec<String> {
    Vec::new()
}

/// The name a tab shows for a shell: the program's file name, without the path
/// or a Windows `.exe`.
///
/// Both separators are handled regardless of the host platform — the string
/// being labelled is a path the *user* typed, and a Windows path pasted into the
/// settings on any machine should still label as `pwsh`. Only `.exe` is trimmed,
/// not every extension: `python3.11` is the program's name, not `python3`.
pub fn program_label(program: &str) -> String {
    let tail = program
        .trim_end_matches(['/', '\\'])
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(program);
    let stem = if tail.len() > 4 && tail[tail.len() - 4..].eq_ignore_ascii_case(".exe") {
        &tail[..tail.len() - 4]
    } else {
        tail
    };
    if stem.is_empty() {
        program.to_string()
    } else {
        stem.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_quoted_arguments() {
        assert_eq!(
            split_args(r#"-c "echo hi""#),
            Some(vec!["-c".to_string(), "echo hi".to_string()])
        );
        assert_eq!(split_args(""), Some(Vec::new()));
    }

    #[test]
    fn rejects_an_unbalanced_quote() {
        assert_eq!(split_args("\"oops"), None);
    }

    #[test]
    fn label_is_the_bare_program_name() {
        assert_eq!(program_label("/bin/zsh"), "zsh");
        assert_eq!(program_label("zsh"), "zsh");
        assert_eq!(
            program_label(r"C:\Program Files\PowerShell\pwsh.exe"),
            "pwsh"
        );
        assert_eq!(program_label("cmd.EXE"), "cmd");
        // Not an extension to strip — that is the program's name.
        assert_eq!(program_label("/usr/bin/python3.11"), "python3.11");
        // Nothing sensible to shorten to; keep what we were given.
        assert_eq!(program_label("/"), "/");
    }

    #[test]
    fn a_resolved_shell_is_named() {
        let choice = resolve_default_shell();
        assert!(!choice.program.is_empty());
    }

    #[cfg(not(windows))]
    #[test]
    fn passwd_lookup_reads_the_shell_field() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\n\
                      someone:x:1000:1000:Some One:/home/someone:/usr/bin/fish\n";
        assert_eq!(
            passwd_shell_in(passwd, "someone"),
            Some("/usr/bin/fish".to_string())
        );
        assert_eq!(passwd_shell_in(passwd, "nobody"), None);
        assert_eq!(passwd_shell_in(passwd, ""), None);
    }

    #[cfg(not(windows))]
    #[test]
    fn passwd_lookup_ignores_a_relative_shell() {
        // A relative shell would be resolved against the *child's* cwd, which is
        // not what the passwd entry meant; better to fall through to /bin/sh.
        let passwd = "someone:x:1000:1000::/home/someone:sh\n";
        assert_eq!(passwd_shell_in(passwd, "someone"), None);
    }
}
