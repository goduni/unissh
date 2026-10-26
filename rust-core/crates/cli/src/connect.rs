//! Connecting: an interactive terminal, a one-off command, a file copy.

use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use unissh_ffi::{
    AuthMethod, Core, ExecHandleFfi, ExecObserver, FillEvent, PasswordFillMode, RecordingRequest,
    SessionObserver, SftpFfi, SftpProgressObserver, SshSession,
};
use zeroize::Zeroize;

use crate::device::ask_secret;
use crate::escape::{Escape, Escapes, HELP};
use crate::failure::{best_effort, Failure, Res, EXIT_CONNECT};
use crate::hosts::{Host, Target};
use crate::tree;
use crate::tty::{self, RawMode, INPUT_TICK};

/// How a session or command ended, handed over from the core's thread (the
/// remote's status) or the key reader (a hang-up) to the one waiting.
struct Ended {
    state: Mutex<Ending>,
    changed: Condvar,
}

#[derive(Default)]
struct Ending {
    status: Option<i32>,
    hung_up: bool,
}

impl Ended {
    fn new() -> Self {
        Self {
            state: Mutex::default(),
            changed: Condvar::new(),
        }
    }

    fn update(&self, change: impl FnOnce(&mut Ending)) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        change(&mut state);
        drop(state);
        self.changed.notify_all();
    }

    /// The remote's exit status arrived; the first one counts.
    fn closed(&self, status: i32) {
        self.update(|e| {
            if e.status.is_none() {
                e.status = Some(status);
            }
        });
    }

    /// We are leaving (`~.`, or nobody can type any more).
    fn hang_up(&self) {
        self.update(|e| e.hung_up = true);
    }

    /// Waits for the end. `(status, hung_up)`: the remote's status, or 255
    /// when we hung up before it gave one.
    fn wait(&self) -> (i32, bool) {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let state = self
            .changed
            .wait_while(state, |e| e.status.is_none() && !e.hung_up)
            .unwrap_or_else(PoisonError::into_inner);
        (
            state.status.unwrap_or_else(|| i32::from(EXIT_CONNECT)),
            state.hung_up,
        )
    }

    /// After a hang-up: gives the close up to `timeout` to come through.
    fn wait_closed(&self, timeout: Duration) {
        let (state, _) = self
            .changed
            .wait_timeout_while(
                self.state.lock().unwrap_or_else(PoisonError::into_inner),
                timeout,
                |e| e.status.is_none(),
            )
            .unwrap_or_else(PoisonError::into_inner);
        drop(state);
    }
}

/// The exit code a remote status becomes here: as is when it fits, else 255.
pub fn exit_code(status: i32) -> u8 {
    u8::try_from(status).unwrap_or(EXIT_CONNECT)
}

/// Asks for the password a host wants typed at every connection.
fn fill_password(target: &mut Target) -> Res<()> {
    if target.ask_password {
        let prompt = format!(
            "Password for {}@{}: ",
            tty::one_line(&target.user),
            tty::one_line(&target.host)
        );
        let mut password = ask_secret(
            &prompt,
            "the password",
            "this host asks for it at every connection",
        )?;
        target.auth = AuthMethod::Password {
            password: std::mem::take(&mut *password),
        };
    }
    Ok(())
}

/// Forgets a typed password once the connection no longer needs it.
fn forget_password(target: &mut Target) {
    if let AuthMethod::Password { password } = &mut target.auth {
        password.zeroize();
    }
}

/// Whether this machine has pinned a key for `host:port` already.
fn is_known(core: &Core, host: &str, port: u16) -> bool {
    core.list_known_hosts()
        .map(|known| {
            known
                .iter()
                .any(|k| k.port == port && k.host.eq_ignore_ascii_case(host))
        })
        .unwrap_or(true)
}

/// Says that a first connection pinned the host's key — trust on first use is
/// a decision, and the person making it should see the fingerprint once.
fn announce_pinned(core: &Core, host: &str, port: u16) {
    let Ok(known) = core.list_known_hosts() else {
        return;
    };
    if let Some(k) = known
        .iter()
        .find(|k| k.port == port && k.host.eq_ignore_ascii_case(host))
    {
        eprintln!(
            "unissh: first connection to {}:{port}; pinned its key {} on this machine",
            tty::one_line(host),
            k.fingerprint
        );
    }
}

/// Connects to `target` and runs `connect`, announcing a newly pinned key.
fn connecting<T>(core: &Core, target: &Target, connect: impl FnOnce() -> Res<T>) -> Res<T> {
    let new_host = !is_known(core, &target.host, target.port);
    let connected = connect().map_err(Failure::connecting)?;
    if new_host {
        announce_pinned(core, &target.host, target.port);
    }
    Ok(connected)
}

/// The terminal type to ask the remote for.
fn term() -> String {
    std::env::var("TERM")
        .ok()
        .filter(|t| !t.trim().is_empty())
        .unwrap_or_else(|| "xterm-256color".to_owned())
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis())
}

/// Session output, straight to the terminal.
struct Screen {
    ended: Arc<Ended>,
}

impl SessionObserver for Screen {
    fn on_data(&self, data: Vec<u8>) {
        let mut out = io::stdout().lock();
        best_effort(out.write_all(&data).and_then(|()| out.flush()));
    }

    fn on_close(&self, exit_status: i32) {
        self.ended.closed(exit_status);
    }

    // Saved-password fill is off for CLI sessions: nothing is ever offered.
    fn on_fill(&self, _event: FillEvent) {}
}

/// An interactive terminal on `host`. Returns the remote shell's exit status.
///
/// The session is recorded when the host asks for it, as in the app; agent
/// forwarding is not offered here, because approving each signature needs a
/// prompt the raw terminal cannot show.
pub fn shell(core: &Core, host: &Host, mut target: Target) -> Res<i32> {
    if !tty::SUPPORTED {
        return Err(Failure::msg(
            "an interactive session needs a Unix terminal here; give a command to run instead",
        ));
    }
    if !io::stdin().is_terminal() {
        return Err(Failure::msg(
            "stdin is not a terminal: give a command to run (`unissh ssh <host> -- <command>`)",
        ));
    }
    if host.profile.agent_forward {
        eprintln!("unissh: agent forwarding is not available in the CLI; connecting without it");
    }
    fill_password(&mut target)?;
    let size = tty::window_size().unwrap_or((80, 24));
    let recorded = host.profile.record_sessions;
    let recording = recorded.then(|| RecordingRequest {
        vault_id: host.vault_id.clone(),
        recording_id: format!("rec-{}-{}", host.profile.profile_id, now_millis()),
        label: host.profile.label.clone(),
    });
    let ended = Arc::new(Ended::new());
    let observer: Arc<dyn SessionObserver> = Arc::new(Screen {
        ended: Arc::clone(&ended),
    });
    let session = connecting(core, &target, || {
        Ok(core.open_session(
            target.host.clone(),
            target.port,
            target.user.clone(),
            target.auth.clone(),
            target.jumps.clone(),
            target.proxy.clone(),
            term(),
            size.0,
            size.1,
            observer,
            recording,
            false,
            PasswordFillMode::Off,
        )?)
    })?;
    forget_password(&mut target);

    let (status, hung_up) = {
        // Raw only while the session runs: the terminal is back to normal
        // before anything below prints.
        let _raw = RawMode::enter()?;
        let stop = Arc::new(AtomicBool::new(false));
        let input = {
            let session = Arc::clone(&session);
            let stop = Arc::clone(&stop);
            let ended = Arc::clone(&ended);
            thread::spawn(move || pump_keys(&session, &stop, &ended, size))
        };
        let end = ended.wait();
        stop.store(true, Ordering::SeqCst);
        best_effort(input.join());
        end
    };
    if hung_up {
        // `~.` is the way out of a remote that stopped answering, so the close
        // runs on a thread of its own and gets a few seconds to come through —
        // the recording, if any, is written when it does.
        let closing = Arc::clone(&session);
        thread::spawn(move || best_effort(closing.close()));
        ended.wait_closed(CLOSE_GRACE);
    }
    if recorded && !core.wait_for_recordings(RECORDING_GRACE_MS) {
        eprintln!("unissh: the session recording is still being written and may be lost");
    }
    eprintln!("Connection to {} closed.", tty::one_line(&target.host));
    Ok(status)
}

/// How long a hang-up waits for the remote to confirm the close.
const CLOSE_GRACE: Duration = Duration::from_secs(3);

/// How long the end of a recorded session waits for the recording's write.
const RECORDING_GRACE_MS: u32 = 15_000;

/// Sends keys to the session until it ends, following window resizes and
/// acting on `~` escapes.
fn pump_keys(session: &SshSession, stop: &AtomicBool, ended: &Ended, mut size: (u32, u32)) {
    let mut escapes = Escapes::new();
    let mut buf = [0_u8; 4096];
    // Set by `~.` and by stdin ending: we are leaving, whatever the remote says.
    let mut hang_up = false;
    while !stop.load(Ordering::SeqCst) {
        if let Some(now) = tty::window_size().filter(|now| *now != size) {
            size = now;
            best_effort(session.resize(now.0, now.1));
        }
        match tty::wait_for_input(INPUT_TICK) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(_) => {
                hang_up = true;
                break;
            }
        }
        let typed = match tty::read_stdin(&mut buf) {
            Ok(n) if n > 0 => buf.get(..n).unwrap_or_default(),
            Ok(_) | Err(_) => {
                hang_up = true;
                break;
            }
        };
        let (send, escape) = escapes.feed(typed);
        // A failed write means the session is going away; its close reports
        // the status.
        if !send.is_empty() && session.write(send).is_err() {
            break;
        }
        match escape {
            Some(Escape::Disconnect) => {
                hang_up = true;
                break;
            }
            Some(Escape::Help) => {
                let mut out = io::stdout().lock();
                best_effort(out.write_all(HELP.as_bytes()).and_then(|()| out.flush()));
            }
            None => {}
        }
    }
    if hang_up {
        ended.hang_up();
    }
}

/// Command output, to our stdout and stderr.
struct Streams {
    ended: Arc<Ended>,
}

/// The status of a command whose output nobody reads any more, as a shell
/// reports one killed by SIGPIPE (128 + 13) — what `ssh` itself would die of.
const EXIT_BROKEN_PIPE: i32 = 141;

impl ExecObserver for Streams {
    fn on_stdout(&self, data: Vec<u8>) {
        let mut out = io::stdout().lock();
        match out.write_all(&data).and_then(|()| out.flush()) {
            // `| head`, `| grep -m1`: the reader is gone, and Rust ignores
            // SIGPIPE, so ending here is ours to do — or a `tail -f` streams on
            // into nothing until the remote command ends.
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => self.ended.closed(EXIT_BROKEN_PIPE),
            Ok(()) | Err(_) => {}
        }
    }

    fn on_stderr(&self, data: Vec<u8>) {
        let mut err = io::stderr().lock();
        best_effort(err.write_all(&data).and_then(|()| err.flush()));
    }

    fn on_exit(&self, exit_status: i32) {
        self.ended.closed(exit_status);
    }
}

/// Runs `command` on the target without a terminal, like `ssh host command`.
/// Our stdin goes to the command unless `no_stdin`; returns its exit status.
pub fn run(core: &Core, mut target: Target, command: String, no_stdin: bool) -> Res<i32> {
    fill_password(&mut target)?;
    let ended = Arc::new(Ended::new());
    let observer: Arc<dyn ExecObserver> = Arc::new(Streams {
        ended: Arc::clone(&ended),
    });
    let handle = connecting(core, &target, || {
        Ok(core.ssh_exec_stream(
            target.host.clone(),
            target.port,
            target.user.clone(),
            target.auth.clone(),
            command,
            target.jumps.clone(),
            target.proxy.clone(),
            observer,
        )?)
    })?;
    forget_password(&mut target);
    if no_stdin {
        handle.close_stdin()?;
    } else {
        let handle = Arc::clone(&handle);
        // Left blocked in a read when the command ends without wanting input;
        // the process exits around it.
        thread::spawn(move || pump_stdin(&handle));
    }
    let (status, _) = ended.wait();
    best_effort(handle.close());
    Ok(status)
}

/// Copies our stdin into the command's, then ends it.
fn pump_stdin(handle: &ExecHandleFfi) {
    let mut buf = vec![0_u8; 32 * 1024];
    loop {
        match tty::read_stdin(&mut buf) {
            Ok(n) if n > 0 => {
                let chunk = buf.get(..n).unwrap_or_default().to_vec();
                if handle.write_stdin(chunk).is_err() {
                    return;
                }
            }
            Ok(_) | Err(_) => break,
        }
    }
    best_effort(handle.close_stdin());
}

/// One end of a copy.
#[derive(Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// A path on this machine.
    Local(PathBuf),
    /// `host:path` — a path on a host (relative to the login directory).
    Remote {
        /// The host, as `unissh ssh` takes it (`user@` allowed).
        host: String,
        /// The path there.
        path: String,
    },
}

impl Endpoint {
    /// `host:path` is remote — as with `scp`, a `/` before the first `:`
    /// makes it a local path that merely contains a colon.
    pub fn parse(spec: &str) -> Self {
        match spec.split_once(':') {
            Some((host, path)) if !host.is_empty() && !host.contains('/') => Self::Remote {
                host: host.to_owned(),
                path: path.strip_prefix("~/").unwrap_or(path).to_owned(),
            },
            Some(_) | None => Self::Local(PathBuf::from(spec)),
        }
    }
}

/// Which way a copy goes.
pub enum Direction {
    /// Remote path to local path.
    Download {
        /// Remote source.
        remote: String,
        /// Local destination (a directory takes the remote file's name).
        local: PathBuf,
    },
    /// Local path to remote path.
    Upload {
        /// Local source.
        local: PathBuf,
        /// Remote destination (a directory takes the local file's name).
        remote: String,
    },
}

/// Copies one file over SFTP, or with `recursive` a directory and what is in
/// it, `parallel` files at a time. An existing destination file is replaced
/// only with `force`.
pub fn copy(
    core: &Core,
    mut target: Target,
    direction: Direction,
    force: bool,
    recursive: bool,
    parallel: u32,
) -> Res<()> {
    fill_password(&mut target)?;
    // One channel is all a single file uses; a tree keeps `parallel` of them
    // over the one connection, as the app's SFTP pane does.
    let channels = if recursive { parallel } else { 1 };
    let sftp = connecting(core, &target, || {
        Ok(core.open_sftp(
            target.host.clone(),
            target.port,
            target.user.clone(),
            target.auth.clone(),
            target.jumps.clone(),
            target.proxy.clone(),
            channels,
        )?)
    })?;
    forget_password(&mut target);
    let done = transfer(&sftp, direction, force, recursive.then_some(parallel));
    sftp.close();
    done
}

/// `recursive`: `Some(parallel)` when a directory may be copied, with what is
/// in it.
fn transfer(sftp: &SftpFfi, direction: Direction, force: bool, recursive: Option<u32>) -> Res<()> {
    let progress = io::stderr()
        .is_terminal()
        .then(|| -> Arc<dyn SftpProgressObserver> { Arc::new(Progress) });
    let completed = match direction {
        Direction::Download { remote, local } => {
            let local = if local.is_dir() {
                local.join(base_name(&remote))
            } else {
                local
            };
            // `web:` is the login directory, as the walk names it.
            let is_dir = || {
                sftp.stat(tree::remote_path(&remote, ""))
                    .is_ok_and(|s| s.is_dir)
            };
            if let Some(parallel) = recursive.filter(|_| is_dir()) {
                return tree::download_tree(sftp, &remote, &local, force, parallel);
            }
            if local.exists() && !force {
                return Err(exists(&local.display().to_string()));
            }
            download(sftp, remote.clone(), &local, None, progress).map_err(|e| {
                if recursive.is_none() && is_dir() {
                    Failure::msg(format!(
                        "{} is a directory; pass -r to copy it",
                        tty::one_line(&remote)
                    ))
                } else {
                    e
                }
            })?
        }
        Direction::Upload { local, remote } => {
            let name = local
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .ok_or_else(|| Failure::msg(format!("{} is not a file", local.display())));
            if let (Some(parallel), true) = (recursive, local.is_dir()) {
                // `.` and `..` have no name of their own; the directory they are does.
                let name = name.or_else(|_| dir_name(&local))?;
                let remote = into_remote(sftp, remote, &name);
                return tree::upload_tree(sftp, &local, &remote, force, parallel);
            }
            let remote = into_remote(sftp, remote, &name?);
            if !force && sftp.stat(remote.clone()).is_ok() {
                return Err(exists(&remote));
            }
            sftp.sftp_upload(
                local.to_string_lossy().into_owned(),
                remote,
                0,
                progress,
                None,
            )?
        }
    };
    if io::stderr().is_terminal() {
        eprintln!();
    }
    if completed {
        Ok(())
    } else {
        Err(Failure::msg("the copy was interrupted"))
    }
}

/// The remote path a local file or directory named `name` is copied to: into
/// `remote` when that is a directory (or the login directory), else `remote`.
fn into_remote(sftp: &SftpFfi, remote: String, name: &str) -> String {
    let into_dir = remote.is_empty()
        || remote.ends_with('/')
        || sftp.stat(remote.clone()).is_ok_and(|s| s.is_dir);
    if into_dir {
        join_remote(&remote, name)
    } else {
        remote
    }
}

/// The name of a local directory given as `.`, `..` or the like.
fn dir_name(local: &Path) -> Res<String> {
    std::fs::canonicalize(local)?
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .ok_or_else(|| Failure::msg(format!("{} has no name to copy it as", local.display())))
}

/// Downloads into a file beside `local` and renames it over `local` only once
/// the whole file is there: a copy that fails — a remote file that cannot be
/// read, a connection that drops — leaves whatever `local` was untouched and
/// no partial file behind. `known_size` is the size a listing gave, which
/// spares the core a `stat` for its progress.
pub fn download(
    sftp: &SftpFfi,
    remote: String,
    local: &Path,
    known_size: Option<u64>,
    progress: Option<Arc<dyn SftpProgressObserver>>,
) -> Res<bool> {
    let name = local
        .file_name()
        .map_or_else(|| "download".into(), |n| n.to_string_lossy());
    let part = local.with_file_name(format!(".{name}.{}.unissh-part", std::process::id()));
    let result = sftp.sftp_download(
        remote,
        part.to_string_lossy().into_owned(),
        0,
        known_size,
        progress,
        None,
    );
    let completed = match result {
        Ok(true) => std::fs::rename(&part, local).map(|()| true).map_err(|e| {
            Failure::msg(format!(
                "the file arrived but could not be moved to {}: {e}",
                local.display()
            ))
        }),
        Ok(false) => Ok(false),
        Err(e) => Err(e.into()),
    };
    if !matches!(completed, Ok(true)) {
        best_effort(std::fs::remove_file(&part));
    }
    completed
}

pub fn exists(path: &str) -> Failure {
    Failure::msg(format!("{path} exists; pass --force to replace it"))
}

fn base_name(remote: &str) -> &str {
    remote
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|n| !n.is_empty())
        .unwrap_or("download")
}

pub fn join_remote(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_owned()
    } else {
        format!("{}/{name}", dir.trim_end_matches('/'))
    }
}

/// Progress on the terminal: bytes so far of the total.
struct Progress;

impl SftpProgressObserver for Progress {
    fn on_progress(&self, transferred: u64, total: u64) {
        let line = if total > 0 {
            format!("\r  {} / {}", human(transferred), human(total))
        } else {
            format!("\r  {}", human(transferred))
        };
        let mut err = io::stderr().lock();
        best_effort(err.write_all(line.as_bytes()).and_then(|()| err.flush()));
    }
}

pub fn human(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len().saturating_sub(1) {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS.get(unit).unwrap_or(&"TiB"))
}

#[cfg(test)]
mod tests {
    use super::{base_name, exit_code, human, join_remote, Endpoint};
    use std::path::PathBuf;

    #[test]
    fn endpoint_is_remote_only_for_host_colon_path() {
        assert_eq!(
            Endpoint::parse("web:~/logs/app.log"),
            Endpoint::Remote {
                host: "web".to_owned(),
                path: "logs/app.log".to_owned()
            },
            "a home-relative path is relative to the login directory"
        );
        assert_eq!(
            Endpoint::parse("./a:b"),
            Endpoint::Local(PathBuf::from("./a:b")),
            "a / before the colon makes it local, as with scp"
        );
        assert_eq!(
            Endpoint::parse("notes.txt"),
            Endpoint::Local(PathBuf::from("notes.txt"))
        );
    }

    #[test]
    fn remote_names_and_joins() {
        assert_eq!(base_name("/var/log/app.log"), "app.log");
        assert_eq!(base_name("dir/"), "dir");
        assert_eq!(join_remote("/tmp/", "a.txt"), "/tmp/a.txt");
        assert_eq!(join_remote("", "a.txt"), "a.txt");
    }

    /// A remote status that does not fit an exit code must not wrap into a
    /// different, possibly successful, one.
    #[test]
    fn exit_code_passes_through_or_saturates_to_255() {
        assert_eq!(exit_code(3), 3);
        assert_eq!(exit_code(-1), 255);
        assert_eq!(exit_code(256), 255);
    }

    #[test]
    fn sizes_read_as_people_write_them() {
        assert_eq!(human(512), "512 B");
        assert_eq!(human(1536), "1.5 KiB");
        assert_eq!(human(5 * 1024 * 1024), "5.0 MiB");
    }
}
