//! What a local shell has to actually do: produce output, report how it ended,
//! respect the size and the starting directory it was given, and die when told.
//!
//! These run a real pty against real programs, so they are unix-only — the
//! ConPTY path is exercised by the Windows build jobs and by hand (there is no
//! Windows runner in `cargo test --workspace`, and claiming otherwise in a test
//! name would be worse than admitting the gap).

#![cfg(unix)]

use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use unissh_local_pty::{LocalPty, LocalPtyError, LocalSpec, PtySink};

/// Collects everything a session produced, and lets a test block until the
/// session ends instead of sleeping and hoping.
#[derive(Default)]
struct Collector {
    out: Mutex<Vec<u8>>,
    exit: AtomicI32,
    done: Mutex<bool>,
    signal: Condvar,
}

impl Collector {
    fn new() -> Arc<Self> {
        Arc::new(Collector {
            exit: AtomicI32::new(i32::MIN),
            ..Default::default()
        })
    }

    /// Waits for the shell to close; `false` if it never did in time.
    fn wait_closed(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut done = self.done.lock().expect("done");
        while !*done {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            let (guard, _) = self.signal.wait_timeout(done, left).expect("wait");
            done = guard;
        }
        true
    }

    /// Waits until the output contains `needle` (a shell takes a moment to boot).
    fn wait_for(&self, needle: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.text().contains(needle) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        self.text().contains(needle)
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.out.lock().expect("out")).to_string()
    }

    fn exit_code(&self) -> i32 {
        self.exit.load(Ordering::SeqCst)
    }
}

impl PtySink for Collector {
    fn on_data(&self, data: Vec<u8>) {
        self.out.lock().expect("out").extend_from_slice(&data);
    }
    fn on_close(&self, exit_status: i32) {
        self.exit.store(exit_status, Ordering::SeqCst);
        *self.done.lock().expect("done") = true;
        self.signal.notify_all();
    }
}

fn spec(program: &str, args: &[&str]) -> LocalSpec {
    LocalSpec {
        program: program.to_string(),
        args: args.iter().map(|a| (*a).to_string()).collect(),
        cwd: None,
        cols: 80,
        rows: 24,
    }
}

#[test]
fn output_and_exit_code_reach_the_sink() {
    let sink = Collector::new();
    let pty = LocalPty::spawn(
        spec("/bin/sh", &["-c", "echo hello-from-pty; exit 7"]),
        Arc::clone(&sink) as Arc<dyn PtySink>,
    )
    .expect("spawn");

    assert!(sink.wait_closed(Duration::from_secs(10)), "never closed");
    assert!(
        sink.text().contains("hello-from-pty"),
        "output was {:?}",
        sink.text()
    );
    assert_eq!(sink.exit_code(), 7);
    drop(pty);
}

#[test]
fn exit_code_is_never_negative_when_signalled() {
    // A negative code means "the link dropped" to the UI, and a local shell has
    // no link to drop — so even a killed shell must report ≥ 0.
    let sink = Collector::new();
    let pty = LocalPty::spawn(
        spec("/bin/sh", &["-c", "kill -TERM $$; sleep 30"]),
        Arc::clone(&sink) as Arc<dyn PtySink>,
    )
    .expect("spawn");

    assert!(sink.wait_closed(Duration::from_secs(10)), "never closed");
    assert!(sink.exit_code() >= 0, "exit was {}", sink.exit_code());
    drop(pty);
}

#[test]
fn resize_reaches_the_child() {
    let sink = Collector::new();
    // `stty size` reads the winsize the kernel holds for the pty — the same
    // thing a full-screen program consults, so this checks the resize actually
    // landed rather than that we called something.
    let pty = LocalPty::spawn(
        spec(
            "/bin/sh",
            &["-c", "sleep 0.4; stty size; sleep 0.4; stty size"],
        ),
        Arc::clone(&sink) as Arc<dyn PtySink>,
    )
    .expect("spawn");

    pty.resize(132, 43).expect("resize");
    assert!(sink.wait_closed(Duration::from_secs(10)), "never closed");
    assert!(
        sink.text().contains("43 132"),
        "stty never reported the new size: {:?}",
        sink.text()
    );
}

#[test]
fn initial_size_is_the_one_asked_for() {
    let sink = Collector::new();
    let mut s = spec("/bin/sh", &["-c", "stty size"]);
    s.cols = 100;
    s.rows = 37;
    let _pty = LocalPty::spawn(s, Arc::clone(&sink) as Arc<dyn PtySink>).expect("spawn");

    assert!(sink.wait_closed(Duration::from_secs(10)), "never closed");
    assert!(
        sink.text().contains("37 100"),
        "stty reported {:?}",
        sink.text()
    );
}

#[test]
fn input_reaches_the_shell() {
    let sink = Collector::new();
    let pty = LocalPty::spawn(
        spec("/bin/sh", &["-c", "read line; echo got:$line"]),
        Arc::clone(&sink) as Arc<dyn PtySink>,
    )
    .expect("spawn");

    pty.write(b"ping\n").expect("write");
    assert!(sink.wait_closed(Duration::from_secs(10)), "never closed");
    assert!(sink.text().contains("got:ping"), "output {:?}", sink.text());
}

#[test]
fn close_kills_the_child() {
    let sink = Collector::new();
    let pty = LocalPty::spawn(
        spec("/bin/sh", &["-c", "echo alive; sleep 120"]),
        Arc::clone(&sink) as Arc<dyn PtySink>,
    )
    .expect("spawn");
    assert!(
        sink.wait_for("alive", Duration::from_secs(10)),
        "the shell never started"
    );

    let started = Instant::now();
    pty.close();
    // close() is synchronous: by the time it returns the child is gone and the
    // close callback has been delivered. Auto-lock depends on exactly this.
    assert!(
        sink.wait_closed(Duration::from_millis(50)),
        "close returned before the shell was gone"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "close took {:?}",
        started.elapsed()
    );
}

#[test]
fn close_is_idempotent() {
    let sink = Collector::new();
    let pty = LocalPty::spawn(
        spec("/bin/sh", &["-c", "sleep 120"]),
        Arc::clone(&sink) as Arc<dyn PtySink>,
    )
    .expect("spawn");
    pty.close();
    pty.close();
    drop(pty); // Drop calls close() a third time
    assert!(sink.wait_closed(Duration::from_secs(5)), "never closed");
}

#[test]
fn a_missing_program_is_an_error_not_a_session() {
    let sink = Collector::new();
    let err = LocalPty::spawn(
        spec("/nonexistent/definitely-not-a-shell", &[]),
        Arc::clone(&sink) as Arc<dyn PtySink>,
    )
    .expect_err("a missing program must not produce a session");
    assert!(
        matches!(err, LocalPtyError::Spawn { .. }),
        "unexpected error: {err}"
    );
}

#[test]
fn a_missing_cwd_is_reported_before_anything_starts() {
    let sink = Collector::new();
    let mut s = spec("/bin/sh", &["-c", "true"]);
    s.cwd = Some(std::path::PathBuf::from("/nonexistent/starting/directory"));
    let err = LocalPty::spawn(s, Arc::clone(&sink) as Arc<dyn PtySink>)
        .expect_err("a missing starting directory must not produce a session");
    assert!(matches!(err, LocalPtyError::Cwd(_)), "unexpected: {err}");
}

#[test]
fn cwd_is_where_the_shell_starts() {
    let dir = tempfile::tempdir().expect("tempdir");
    // macOS hands out /var/… symlinked to /private/var, and `pwd` in a shell
    // prints the resolved path, so compare against the resolved one.
    let want = dir.path().canonicalize().expect("canonicalize");
    let sink = Collector::new();
    let mut s = spec("/bin/sh", &["-c", "pwd"]);
    s.cwd = Some(dir.path().to_path_buf());
    let _pty = LocalPty::spawn(s, Arc::clone(&sink) as Arc<dyn PtySink>).expect("spawn");

    assert!(sink.wait_closed(Duration::from_secs(10)), "never closed");
    assert!(
        sink.text().contains(&want.display().to_string()),
        "pwd printed {:?}, wanted {:?}",
        sink.text(),
        want
    );
}

#[test]
fn the_terminal_describes_itself_to_the_child() {
    let sink = Collector::new();
    let _pty = LocalPty::spawn(
        spec("/bin/sh", &["-c", "echo term=$TERM colorterm=$COLORTERM"]),
        Arc::clone(&sink) as Arc<dyn PtySink>,
    )
    .expect("spawn");

    assert!(sink.wait_closed(Duration::from_secs(10)), "never closed");
    let text = sink.text();
    assert!(text.contains("term=xterm-256color"), "output {text:?}");
    assert!(text.contains("colorterm=truecolor"), "output {text:?}");
}
