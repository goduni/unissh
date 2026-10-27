//! This machine's instance: the core over the device directory, and unlocking it.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use unissh_ffi::{AuthPromptRequest, AuthPrompter, Core};
use zeroize::Zeroizing;

use crate::failure::{Failure, Res};
use crate::home::{read_private, Home, Link};
use crate::server::Sessions;
use crate::tty::{lines, one_line, Tty};

/// What the user said about where the master password comes from.
pub struct Credentials {
    /// A file holding the master password, for unattended use.
    pub password_file: Option<PathBuf>,
}

/// A signed-in device: its directory, its server link, its (locked) core and
/// the process's server session.
pub struct Device {
    /// The device directory.
    pub home: Home,
    /// The server and account it belongs to.
    pub link: Link,
    /// The core over its instance.
    pub core: Arc<Core>,
    sessions: Sessions,
}

/// What to do when this machine is not signed in.
pub const NOT_SIGNED_IN: &str = "this machine is not signed in to UniSSH. Sign in with one of:\n  \
     unissh login pair                     (pair with a signed-in UniSSH app)\n  \
     unissh login escrow <server> <handle> (your password and Secret Key)\n  \
     unissh login join <server>            (a separate account for this machine; asks for the invite)";

impl Device {
    /// The device signed in at `home`.
    pub fn open(home: Home) -> Res<Self> {
        home.check_private()?;
        let link = home.link()?;
        let complete = home.db().exists() && home.keyset().exists();
        let partial = home.has_instance() || link.is_some();
        match link {
            Some(link) if complete => {
                let core = open_core(&home);
                Ok(Self::new(home, link, core))
            }
            Some(_) | None if partial => Err(Failure::msg(format!(
                "the UniSSH data in {} is incomplete (an interrupted sign-in?). \
                 Remove it with `unissh logout --local` and sign in again",
                home.dir().display()
            ))),
            Some(_) | None => Err(Failure::msg(NOT_SIGNED_IN)),
        }
    }

    /// A device over parts already at hand (a sign-in that just made them).
    pub fn new(home: Home, link: Link, core: Arc<Core>) -> Self {
        Self {
            home,
            link,
            core,
            sessions: Sessions::default(),
        }
    }

    /// A bearer for a call to the server, signing in first when needed. The
    /// core must be unlocked.
    pub fn access(&self) -> Res<String> {
        self.sessions.access(&self.core, &self.link)
    }

    /// Unlocks the instance for this process.
    pub fn unlock(&self, credentials: &Credentials) -> Res<()> {
        unlock(&self.core, &self.home, credentials)
    }
}

/// A core over the instance in `home` (locked), asking the terminal for any
/// second factor a server wants.
pub fn open_core(home: &Home) -> Arc<Core> {
    let core = Core::new(path_text(&home.db()), path_text(&home.keyset()));
    core.set_auth_prompter(Some(Arc::new(TtyPrompter)));
    core
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Unlocks `core` with the master password (when the instance has one) and the
/// Secret Key — the remembered one, else asked for.
pub fn unlock(core: &Core, home: &Home, credentials: &Credentials) -> Res<()> {
    let needs_password = core.instance_requires_password().ok_or_else(|| {
        Failure::msg(format!(
            "cannot read {} — the UniSSH data here is damaged",
            home.keyset().display()
        ))
    })?;
    let password = needs_password
        .then(|| master_password(credentials, "Master password: "))
        .transpose()?;
    let secret_key = match home.secret_key()? {
        Some(key) => key,
        None => ask_secret(
            "Secret Key: ",
            "the Secret Key",
            "it is asked at every unlock because this machine does not keep it",
        )?,
    };
    core.unlock(
        password.map(|mut p| std::mem::take(&mut *p)),
        normalize_secret_key(&secret_key),
    )?;
    Ok(())
}

/// The master password: from `--password-file` when given, else asked for.
pub fn master_password(credentials: &Credentials, prompt: &str) -> Res<Zeroizing<String>> {
    let Some(path) = &credentials.password_file else {
        return ask_secret(
            prompt,
            "the master password",
            "run interactively, or pass --password-file",
        );
    };
    let text = read_private(path)?
        .ok_or_else(|| Failure::msg(format!("{} does not exist", path.display())))?;
    Ok(Zeroizing::new(without_line_ending(&text).to_owned()))
}

/// `text` without one trailing `\n` or `\r\n`: the line ending a file (or
/// the Enter that ended a line) adds is not part of a secret, anything
/// beyond that one is.
pub fn without_line_ending(text: &str) -> &str {
    let line = text.strip_suffix('\n').unwrap_or(text);
    line.strip_suffix('\r').unwrap_or(line)
}

/// Asks the terminal for a secret. Without a terminal the error names `what`
/// was needed and `hint`s at the way around.
pub fn ask_secret(prompt: &str, what: &str, hint: &str) -> Res<Zeroizing<String>> {
    let mut tty = Tty::open()
        .map_err(|e| Failure::msg(format!("no terminal to ask for {what} ({e}); {hint}")))?;
    Ok(tty.secret(prompt)?)
}

/// The Secret Key as the core takes it: the Emergency Kit prints it in
/// groups, and people copy the dashes and spaces along.
pub fn normalize_secret_key(key: &str) -> String {
    key.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect()
}

/// The Emergency Kit form of a Secret Key: uppercase, in groups of five.
pub fn format_secret_key(hex: &str) -> String {
    let upper = Zeroizing::new(hex.to_ascii_uppercase());
    let groups: Vec<&str> = upper
        .as_bytes()
        .chunks(5)
        .filter_map(|c| std::str::from_utf8(c).ok())
        .collect();
    groups.join("-")
}

/// Answers a server's keyboard-interactive questions (one-time codes, push
/// confirmations) on the terminal.
struct TtyPrompter;

/// What a keyboard-interactive request says before its fields: who asks, then
/// the server's title and instruction. Everything in it comes from the remote
/// host (or the vault), so it is without control characters: it cannot rewrite
/// the line that says who is asking.
pub fn prompt_intro(request: &AuthPromptRequest) -> String {
    let mut text = format!(
        "{}@{}:{} asks:\n",
        one_line(&request.user),
        one_line(&request.host),
        request.port
    );
    for part in [one_line(&request.name), lines(&request.instruction)] {
        if !part.trim().is_empty() {
            text.push_str(&part);
            text.push('\n');
        }
    }
    text
}

/// Whether a request carries neither a title nor an instruction.
pub fn is_silent(request: &AuthPromptRequest) -> bool {
    one_line(&request.name).trim().is_empty() && lines(&request.instruction).trim().is_empty()
}

impl AuthPrompter for TtyPrompter {
    fn prompt(&self, request: AuthPromptRequest) -> Option<Vec<String>> {
        let mut tty = Tty::open().ok()?;
        // A request with nothing to ask and nothing to say (the last round of a
        // keyboard-interactive exchange) is answered without a word.
        if request.prompts.is_empty() && is_silent(&request) {
            return Some(Vec::new());
        }
        tty.say(&prompt_intro(&request)).ok()?;
        let mut answers = Vec::with_capacity(request.prompts.len());
        for field in request.prompts {
            let prompt = one_line(&field.prompt);
            let answer = if field.echo {
                tty.line(&prompt).ok()?
            } else {
                let mut secret = tty.secret(&prompt).ok()?;
                std::mem::take(&mut *secret)
            };
            answers.push(answer);
        }
        Some(answers)
    }
}

#[cfg(test)]
mod tests {
    use super::{format_secret_key, normalize_secret_key, Device};
    use crate::home::Home;

    /// A sign-in cut short leaves files without a link (or a link without
    /// files): that is said as such, distinct from a machine never signed in.
    #[test]
    fn a_half_written_device_is_told_apart_from_a_signed_out_one() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::locate(Some(dir.path().join("u"))).unwrap();
        home.create().unwrap();
        let Err(empty) = Device::open(home.clone()) else {
            panic!("nothing here to open");
        };
        assert!(empty.message.contains("not signed in"), "{empty}");
        std::fs::write(home.keyset(), b"k").unwrap();
        let Err(partial) = Device::open(home) else {
            panic!("half an instance is not a device");
        };
        assert!(partial.message.contains("incomplete"), "{partial}");
    }

    /// `echo pw > file` adds a line ending that is not part of the password;
    /// anything beyond that one is.
    #[cfg(unix)]
    #[test]
    fn a_password_file_loses_exactly_one_line_ending() {
        use super::{master_password, Credentials};
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let dir = tempfile::tempdir().unwrap();
        let read = |name: &str, content: &[u8]| {
            let path = dir.path().join(name);
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            file.write_all(content).unwrap();
            let credentials = Credentials {
                password_file: Some(path),
            };
            master_password(&credentials, "")
                .unwrap()
                .as_str()
                .to_owned()
        };
        assert_eq!(read("crlf", b"pw\r\n"), "pw");
        assert_eq!(read("two", b"pw\n\n"), "pw\n");
        assert_eq!(read("none", b" pw "), " pw ", "spaces are the password's");
    }

    /// What the kit prints is what the core reads back.
    #[test]
    fn a_secret_key_typed_from_the_kit_reads_back_as_the_key() {
        let hex = "0a1b2c3d4e5f60718293a4b5c6d7e8f9";
        let printed = format_secret_key(hex);
        assert_eq!(printed, "0A1B2-C3D4E-5F607-18293-A4B5C-6D7E8-F9");
        let typed = format!(" {}\n", printed.replace('-', " - "));
        assert_eq!(normalize_secret_key(&typed).to_ascii_lowercase(), hex);
    }
}
