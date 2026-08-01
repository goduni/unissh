//! # unissh-local-pty
//!
//! A local terminal: an interactive shell running on the user's own machine,
//! behind the same shape of API as a remote SSH session.
//!
//! One [`LocalPty`] owns one pty and one child process. Output is pushed to a
//! [`PtySink`] from a reader thread; input, resize and close come in from
//! whatever thread the UI happens to be on.
//!
//! The platform work is [`portable_pty`]'s (wezterm's): unix `openpty` and
//! Windows ConPTY behind one interface. What is here is the lifecycle around it
//! — threads, exit codes, and a teardown that actually kills what it started.
//!
//! ## What is not here
//!
//! No SSH, no vault, no recording. This crate does not know what a session is;
//! `unissh-ffi` bridges [`PtySink`] to the recorder and to the UI's observer.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod shell;

pub use shell::{
    home_dir, machine_name, os_username, program_label, resolve_default_shell, split_args,
    ShellChoice,
};

use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use portable_pty::{native_pty_system, ChildKiller, CommandBuilder, MasterPty, PtySize};

/// How long the shell's last output is waited for after the child exits, before
/// the close is reported anyway.
///
/// On a normal exit the reader sees EOF immediately and this costs nothing. It
/// only comes into play when something the shell left behind still holds the pty
/// open, and then the point is to report the exit rather than wait forever.
const DRAIN_TIMEOUT: Duration = Duration::from_millis(300);

/// How long [`LocalPty::close`] waits for the child to be gone and the close
/// callback delivered.
///
/// Bounded on purpose: this runs on the thread that is closing a tab (and, on
/// auto-lock, on the thread about to lock the vault), and a shell whose
/// grandchildren keep the pty open must not be able to wedge either.
const CLOSE_TIMEOUT: Duration = Duration::from_millis(1_500);

/// Read buffer size. A pty hands over whatever fits, so this only bounds how
/// much one read can carry.
const READ_BUF: usize = 16 * 1024;

/// What to start, and how big its terminal is to begin with.
#[derive(Debug, Clone)]
pub struct LocalSpec {
    /// Absolute path to the program (a shell, normally).
    pub program: String,
    /// Arguments, already split into words.
    pub args: Vec<String>,
    /// Working directory; `None` means the user's home.
    pub cwd: Option<PathBuf>,
    /// Initial terminal width in cells.
    pub cols: u16,
    /// Initial terminal height in cells.
    pub rows: u16,
}

/// Everything that can go wrong opening or driving a local shell.
#[derive(Debug, thiserror::Error)]
pub enum LocalPtyError {
    /// The OS refused to give us a pty.
    #[error("could not open a terminal device: {0}")]
    Open(String),
    /// The program could not be started — missing, not executable, not a program.
    #[error("could not start {program}: {message}")]
    Spawn {
        /// The program we tried to start.
        program: String,
        /// What the OS said.
        message: String,
    },
    /// The configured starting directory is not a directory.
    #[error("starting directory {0} does not exist")]
    Cwd(String),
    /// Writing to, or resizing, a shell that is no longer there.
    #[error("the local shell is no longer running: {0}")]
    Gone(String),
}

/// Where a local shell's output goes.
///
/// The same shape as `OutputSink` in `unissh-ssh-transport`, deliberately
/// declared here instead of imported: a local pty has no business depending on
/// the SSH stack for the sake of one trait. `unissh-ffi` bridges the two.
pub trait PtySink: Send + Sync {
    /// Bytes the shell wrote.
    fn on_data(&self, data: Vec<u8>);
    /// The shell is gone, with its exit code.
    ///
    /// Always ≥ 0. A negative code means "the link dropped" to the UI, which
    /// then offers to reconnect — and a local shell never drops, it exits.
    fn on_close(&self, exit_status: i32);
}

/// A running local shell.
///
/// Dropping this kills the child: a shell that outlived the tab it was opened in
/// would be invisible and unkillable from the app.
pub struct LocalPty {
    /// Held for `resize`. `MasterPty` is `Send` but not `Sync`, hence the lock.
    master: Mutex<Box<dyn MasterPty + Send>>,
    writer: Mutex<Box<dyn Write + Send>>,
    killer: Mutex<Box<dyn ChildKiller + Send + Sync>>,
    /// Set once the child has been waited for. After that the pid may be reused
    /// by the OS, so it must never be signalled again.
    reaped: Arc<AtomicBool>,
    /// Set by `close` so the second call (from `Drop`) is a no-op.
    closing: AtomicBool,
    /// Disconnects when the waiter thread ends — how `close` waits for the exit
    /// without an unbounded `join`.
    exited: Mutex<Receiver<Never>>,
    waiter: Mutex<Option<JoinHandle<()>>>,
}

/// A channel that only ever carries its own disconnection.
enum Never {}

impl LocalPty {
    /// Opens a pty and starts `spec.program` in it.
    ///
    /// Returns as soon as the child is running; output starts arriving at `sink`
    /// on a reader thread immediately after.
    pub fn spawn(spec: LocalSpec, sink: Arc<dyn PtySink>) -> Result<Self, LocalPtyError> {
        // No cwd asked for means the user's home. If the environment does not
        // name one, nothing is set and the child inherits this process's
        // directory — not ideal, but the only remaining answer, and better than
        // refusing to open a shell over it.
        let cwd = match spec.cwd {
            Some(dir) => {
                if !dir.is_dir() {
                    return Err(LocalPtyError::Cwd(dir.display().to_string()));
                }
                Some(dir)
            }
            None => home_dir(),
        };

        let pair = native_pty_system()
            .openpty(PtySize {
                rows: spec.rows.max(1),
                cols: spec.cols.max(1),
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| LocalPtyError::Open(e.to_string()))?;

        let mut cmd = CommandBuilder::new(&spec.program);
        cmd.args(&spec.args);
        if let Some(dir) = cwd {
            cmd.cwd(dir);
        }
        // The parent environment carries over as-is (that is what makes the
        // local terminal feel like the user's own machine); only the two
        // variables that describe *this* terminal are set on top.
        cmd.env("TERM", "xterm-256color");
        cmd.env("COLORTERM", "truecolor");

        let mut child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| LocalPtyError::Spawn {
                program: spec.program.clone(),
                message: e.to_string(),
            })?;
        // Let go of the slave now. While this process holds it open the master
        // never reaches EOF, so the reader thread would block forever after the
        // shell exits and the session would never look closed.
        drop(pair.slave);

        // Past the spawn, every failure has to take the child with it. Returning
        // an error while a shell we started keeps running would leave exactly the
        // orphan this type exists to prevent — invisible to the UI and alive
        // until the app exits.
        let (reader, writer) = match (pair.master.try_clone_reader(), pair.master.take_writer()) {
            (Ok(reader), Ok(writer)) => (reader, writer),
            (reader, writer) => {
                let _ = child.kill();
                let _ = child.wait();
                let e = reader
                    .err()
                    .or_else(|| writer.err())
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "pty handles unavailable".to_string());
                return Err(LocalPtyError::Open(e));
            }
        };
        let killer = child.clone_killer();

        let reaped = Arc::new(AtomicBool::new(false));
        let notified = Arc::new(AtomicBool::new(false));

        let (eof_tx, eof_rx) = channel::<Never>();
        let reader_handle = spawn_reader(reader, Arc::clone(&sink), Arc::clone(&notified), eof_tx);

        let (exit_tx, exit_rx) = channel::<Never>();
        let waiter = spawn_waiter(
            child,
            sink,
            Arc::clone(&reaped),
            notified,
            eof_rx,
            reader_handle,
            exit_tx,
        );

        Ok(LocalPty {
            master: Mutex::new(pair.master),
            writer: Mutex::new(writer),
            killer: Mutex::new(killer),
            reaped,
            closing: AtomicBool::new(false),
            exited: Mutex::new(exit_rx),
            waiter: Mutex::new(Some(waiter)),
        })
    }

    /// Sends input (keystrokes) to the shell.
    pub fn write(&self, data: &[u8]) -> Result<(), LocalPtyError> {
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| LocalPtyError::Gone("writer".to_string()))?;
        writer
            .write_all(data)
            .and_then(|()| writer.flush())
            .map_err(|e| LocalPtyError::Gone(e.to_string()))
    }

    /// Tells the kernel the window changed size, which is what makes the shell
    /// send `SIGWINCH` and full-screen programs redraw.
    pub fn resize(&self, cols: u16, rows: u16) -> Result<(), LocalPtyError> {
        let master = self
            .master
            .lock()
            .map_err(|_| LocalPtyError::Gone("pty".to_string()))?;
        master
            .resize(PtySize {
                rows: rows.max(1),
                cols: cols.max(1),
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| LocalPtyError::Gone(e.to_string()))
    }

    /// Kills the shell and waits for it to be gone.
    ///
    /// Synchronous by design. Auto-lock drops every live session and then locks
    /// the vault; if this returned early, the shell would outlive the app that
    /// started it and a session recording would never reach storage.
    ///
    /// Idempotent, and bounded by [`CLOSE_TIMEOUT`] — see the constant.
    pub fn close(&self) {
        if self.closing.swap(true, Ordering::SeqCst) {
            return;
        }
        // Never signal a pid that has already been waited for: the OS is free to
        // hand that number to somebody else, and killing a stranger's process is
        // not a thing this should be capable of.
        if !self.reaped.load(Ordering::SeqCst) {
            if let Ok(mut killer) = self.killer.lock() {
                let _ = killer.kill();
            }
        }
        // The waiter thread is what delivers on_close (and, through it, writes
        // the recording), so waiting for its channel to disconnect is waiting
        // for that to have happened. Disconnected — the only non-timeout outcome
        // a `Receiver<Never>` can have — means the thread is at its last
        // instruction, so joining it then is immediate rather than a second wait.
        let done = match self.exited.lock() {
            Ok(exited) => matches!(
                exited.recv_timeout(CLOSE_TIMEOUT),
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
            ),
            Err(_) => false,
        };
        if let Ok(mut waiter) = self.waiter.lock() {
            if let Some(handle) = waiter.take() {
                if done {
                    let _ = handle.join();
                } else {
                    // Timed out. Leaving the thread detached is the lesser evil:
                    // it is parked on a read from a pty something else is holding
                    // open, and blocking the UI on that is worse than one idle
                    // thread until the process exits.
                    log::warn!("local shell did not exit within the close timeout");
                }
            }
        }
    }
}

impl Drop for LocalPty {
    fn drop(&mut self) {
        self.close();
    }
}

impl std::fmt::Debug for LocalPty {
    /// Nothing here is printable (a pty handle, two locks and a thread), so the
    /// only honest thing to report is whether the shell is still running.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalPty")
            .field("running", &!self.reaped.load(Ordering::SeqCst))
            .finish()
    }
}

/// Reads the pty until EOF, pushing everything it sees at the sink.
fn spawn_reader(
    mut reader: Box<dyn Read + Send>,
    sink: Arc<dyn PtySink>,
    notified: Arc<AtomicBool>,
    eof: Sender<Never>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        // Held only so that dropping it — when this thread ends — is what tells
        // the waiter the output has run dry.
        let _eof = eof;
        let mut buf = vec![0u8; READ_BUF];
        loop {
            match reader.read(&mut buf) {
                // EOF: every slave handle is closed, so nothing can write again.
                Ok(0) => break,
                Ok(n) => {
                    // Past the close callback the observer is gone and the
                    // recording is written; anything still arriving is noise.
                    if notified.load(Ordering::SeqCst) {
                        break;
                    }
                    sink.on_data(buf[..n].to_vec());
                }
                // On some platforms a closed pty surfaces as EIO rather than
                // EOF; either way there is nothing left to read.
                Err(_) => break,
            }
        }
    })
}

/// Waits for the child, then reports the exit exactly once.
fn spawn_waiter(
    mut child: Box<dyn portable_pty::Child + Send + Sync>,
    sink: Arc<dyn PtySink>,
    reaped: Arc<AtomicBool>,
    notified: Arc<AtomicBool>,
    eof: Receiver<Never>,
    reader: JoinHandle<()>,
    exited: Sender<Never>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let _exited = exited;
        let status = child.wait();
        reaped.store(true, Ordering::SeqCst);
        let code = match &status {
            Ok(status) => exit_code_of(status),
            // The child is gone but we could not learn how. 1 rather than 0: it
            // did not end well, and claiming success would be a lie.
            Err(e) => {
                log::warn!("local shell exit status unavailable: {e}");
                1
            }
        };
        // Let the reader finish handing over what the shell printed on its way
        // out — a recording that stops one line early is a recording that lies.
        let _ = eof.recv_timeout(DRAIN_TIMEOUT);
        if !notified.swap(true, Ordering::SeqCst) {
            sink.on_close(code);
        }
        if reader.is_finished() {
            let _ = reader.join();
        }
    })
}

/// The exit code to report, always ≥ 0 (see [`PtySink::on_close`]).
fn exit_code_of(status: &portable_pty::ExitStatus) -> i32 {
    if status.signal().is_some() {
        // portable-pty renders the signal as a localised name rather than a
        // number, so the exact `128 + n` cannot be reconstructed. 128 is the
        // shell convention for "terminated by a signal" and stays in that
        // family instead of pretending to a precision we do not have.
        return 128;
    }
    i32::try_from(status.exit_code()).unwrap_or(1)
}
