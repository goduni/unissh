//! The terminal side of `unissh mcp`: command approvals, sign-in prompts for
//! the hosts an agent connects to, and the stderr log.
//!
//! Questions are asked only by an HTTP server the user started in a terminal of
//! their own (stdin is the controlling terminal), and only on `/dev/tty`. Over
//! stdio the terminal belongs to the client that launched the process, so
//! nothing is asked at all ([`attended`]). The broker decides; this only asks
//! the person and reports back through its native API ([`Broker::approve`]).

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use unissh_automation::{core::PromptFactory, visible, Broker, Cancel, PendingApproval};
use unissh_ffi::{AuthPromptRequest, AuthPrompter};
use unissh_mcp::contract::ToolError;

use crate::device::{is_silent, prompt_intro};
use crate::tty::{lines, one_line, stdin_is_foreground, Tty};

/// How often the approver looks for new requests.
const POLL: Duration = Duration::from_millis(200);

/// How long a withdrawn question stays on screen before the next one, so that
/// an answer being typed to it does not land on its successor.
const SWAP_PAUSE: Duration = Duration::from_secs(1);

/// Whether anyone may be asked: only an HTTP server whose stdin is the
/// controlling terminal and that runs in its foreground, i.e. one the user
/// started in a terminal of their own and is looking at. A stdio server shares
/// its terminal with the client that spawned it (a full-screen agent, say),
/// where whatever types into the terminal could answer; a server started with
/// `&` shares it with whatever runs in the foreground instead. Checked again
/// before each question ([`still_attended`]).
#[cfg_attr(
    not(unix),
    expect(
        clippy::missing_const_for_fn,
        reason = "only off Unix is the answer fixed; on Unix it asks the terminal"
    )
)]
pub fn attended(http: bool) -> bool {
    http && stdin_is_foreground()
}

/// Before each question: whether the server is still in the terminal's
/// foreground. Sent to the background (Ctrl-Z, `bg`), it asks nothing: the
/// question would stop it, or be answered by whoever has the terminal now.
fn still_attended(what: &str) -> bool {
    let attended = stdin_is_foreground();
    if !attended {
        log::warn!("not in the terminal's foreground; {what} not asked");
    }
    attended
}

/// One question on the terminal at a time: an approval and a sign-in prompt
/// for another connection must not interleave.
#[derive(Default)]
pub struct Terminal {
    turn: Mutex<()>,
}

impl Terminal {
    /// Waits for the terminal until `deadline` or until `gone` says the
    /// question is no longer wanted.
    fn turn(&self, deadline: Instant, gone: &dyn Fn() -> bool) -> Option<MutexGuard<'_, ()>> {
        loop {
            match self.turn.try_lock() {
                Ok(guard) => return Some(guard),
                // A question that panicked left nothing half-done to protect.
                Err(TryLockError::Poisoned(poisoned)) => return Some(poisoned.into_inner()),
                Err(TryLockError::WouldBlock) => {}
            }
            if gone() || Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// Asks about every command that waits for approval, oldest first, until
/// `stop`. A question nobody answers lets the request expire, as the desktop
/// dialog does; one the agent withdraws (cancel, revocation) is dropped.
pub fn approve_until_stopped(broker: &Arc<Broker>, terminal: &Terminal, stop: &AtomicBool) {
    let mut asked = BTreeSet::new();
    while !stop.load(Ordering::SeqCst) {
        let pending = broker.pending_approvals();
        asked.retain(|id: &String| pending.iter().any(|p| &p.run_id == id));
        let next = pending.into_iter().find(|p| !asked.contains(&p.run_id));
        let Some(request) = next else {
            std::thread::sleep(POLL);
            continue;
        };
        asked.insert(request.run_id.clone());
        if ask(broker, terminal, stop, &request) == Asked::Withdrawn {
            // The next question's prompt also discards what was typed meanwhile
            // (`line_until` flushes type-ahead).
            std::thread::sleep(SWAP_PAUSE);
        }
    }
}

/// `at` as a time of day in UTC, `14:32:05 UTC`: the CLI keeps no time zone
/// data (recordings are listed in UTC too).
fn clock_utc(at: SystemTime) -> String {
    let seconds = at
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs() % 86_400);
    format!(
        "{:02}:{:02}:{:02} UTC",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    )
}

/// How a question ended.
#[derive(PartialEq, Eq)]
enum Asked {
    /// Answered, or refused for want of an answer.
    Decided,
    /// Withdrawn (cancelled, revoked, expired) or never shown.
    Withdrawn,
}

fn ask(
    broker: &Arc<Broker>,
    terminal: &Terminal,
    stop: &AtomicBool,
    request: &PendingApproval,
) -> Asked {
    let deadline = Instant::now() + request.expires_in;
    let gone = || stop.load(Ordering::SeqCst) || !broker.is_pending(&request.run_id);
    let Some(_turn) = terminal.turn(deadline, &gone) else {
        return Asked::Withdrawn;
    };
    if !still_attended("a command approval") {
        // The agent learns that nobody could be asked, not that someone said no.
        let _ = broker.approval_unavailable(&request.run_id);
        return Asked::Decided;
    }
    let mut decided = false;
    let asked = Tty::open().and_then(|mut tty| {
        tty.say(&question(request).replace('\n', "\r\n"))?;
        // A clock time, not a count that would go stale on screen; counted
        // from the deadline, since waiting for the terminal took some of it.
        let prompt = format!(
            "Allow it? Type yes to allow, anything else denies (answer by {}): ",
            clock_utc(SystemTime::now() + deadline.saturating_duration_since(Instant::now()))
        );
        let outcome = match tty.line_until(&prompt, true, deadline, &gone) {
            Ok(Some(text)) => {
                decided = true;
                decide(broker, &request.run_id, allows(&text))
            }
            Ok(None) if stop.load(Ordering::SeqCst) => "The server is stopping; not run.",
            Ok(None) => "No answer: the request expired or was withdrawn; not run.",
            // Ctrl-C or Ctrl-D at the question, or a terminal that failed:
            // nobody said yes.
            Err(_) => {
                decided = true;
                decide(broker, &request.run_id, false)
            }
        };
        tty.say(&format!("{outcome}\r\n"))
    });
    if asked.is_err() && !decided {
        // No terminal to ask after all: nobody approved it.
        decide(broker, &request.run_id, false);
        decided = true;
    }
    if decided {
        Asked::Decided
    } else {
        Asked::Withdrawn
    }
}

/// Records the decision; the words for the person at the terminal.
fn decide(broker: &Arc<Broker>, run_id: &str, allowed: bool) -> &'static str {
    let decided = broker.approve(run_id, allowed);
    if decided.is_ok() {
        if allowed {
            "Allowed."
        } else {
            "Denied."
        }
    } else if decided == Err(ToolError::ApprovalExpired) {
        "Too late: the request expired or was withdrawn."
    } else {
        "Not run: the grant no longer covers it."
    }
}

/// Only an explicit `yes` allows; Enter alone, `y` or anything else is no.
fn allows(answer: &str) -> bool {
    answer.trim().eq_ignore_ascii_case("yes")
}

/// The question for one request: the exact command and inputs in escaped
/// string notation (a newline or a terminal escape in them is shown, not
/// acted on), where it runs, and which application asks.
fn question(request: &PendingApproval) -> String {
    let t = &request.target;
    let mut text = format!(
        "\nUniSSH MCP: \"{}\" asks to run a command.\n  host     {}  {}@{}:{}  (vault {})\n  command  {}\n",
        one_line(&request.application),
        one_line(&t.label),
        one_line(&t.user),
        one_line(&t.host),
        t.port,
        one_line(&t.vault),
        visible(&request.command),
    );
    if let Some(cwd) = &request.cwd {
        text.push_str(&format!("  cwd      {}\n", visible(cwd)));
    }
    for (name, value) in &request.env {
        text.push_str(&format!(
            "  env      {}={}\n",
            one_line(name),
            visible(value)
        ));
    }
    if let Some(stdin) = &request.stdin {
        text.push_str(&format!("  stdin    {}\n", visible(stdin)));
    }
    text.push_str(&format!(
        "  runs for up to {} s, in its own shell on that host\n\
         Its output can reach the AI provider.\n",
        request.timeout_ms.div_ceil(1000)
    ));
    text
}

/// Sign-in prompts (keyboard-interactive, a typed password) of the
/// connections an agent opens, attributed to its application, on the
/// terminal; declined without one, or when the broker gives up on them.
pub struct Prompts(pub Arc<Terminal>);

impl PromptFactory for Prompts {
    fn for_connection(
        &self,
        attribution: &str,
        cancel: Cancel,
        deadline: Instant,
    ) -> Arc<dyn AuthPrompter> {
        Arc::new(AttributedPrompt {
            terminal: self.0.clone(),
            label: attribution.to_owned(),
            cancel,
            deadline,
        })
    }
}

struct AttributedPrompt {
    terminal: Arc<Terminal>,
    label: String,
    cancel: Cancel,
    deadline: Instant,
}

impl AuthPrompter for AttributedPrompt {
    fn prompt(&self, mut request: AuthPromptRequest) -> Option<Vec<String>> {
        // The silent last round of a keyboard-interactive exchange takes no
        // turn at the terminal.
        if request.prompts.is_empty() && is_silent(&request) {
            return Some(Vec::new());
        }
        let gone = || self.cancel.load(Ordering::SeqCst);
        let _turn = self.terminal.turn(self.deadline, &gone)?;
        if !still_attended("a sign-in prompt") {
            return None;
        }
        let mut tty = Tty::open().ok()?;
        request.name = format!("MCP · {} · {}", self.label, request.name);
        tty.say(&format!("\n{}", prompt_intro(&request)).replace('\n', "\r\n"))
            .ok()?;
        let mut answers = Vec::with_capacity(request.prompts.len());
        for field in &request.prompts {
            let mut answer = tty
                .line_until(&one_line(&field.prompt), field.echo, self.deadline, &gone)
                .ok()??;
            answers.push(std::mem::take(&mut *answer));
        }
        Some(answers)
    }
}

/// The stderr log of `unissh mcp`. The MCP SDK's own diagnostics carry raw
/// tool arguments and output at every level, so their targets never pass
/// ([`unissh_mcp::diagnostics_allowed`]), whatever the level.
struct StderrLog;

/// Whether a record passes the log at `max`: never the SDK's diagnostics.
fn passes(metadata: &log::Metadata<'_>, max: log::LevelFilter) -> bool {
    metadata.level() <= max && unissh_mcp::diagnostics_allowed(metadata.target())
}

impl log::Log for StderrLog {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        passes(metadata, log::max_level())
    }

    fn log(&self, record: &log::Record<'_>) {
        if self.enabled(record.metadata()) {
            // A message can quote a remote host: no control characters.
            eprintln!(
                "unissh mcp: {}: {}",
                record.level().as_str().to_lowercase(),
                lines(&record.args().to_string())
            );
        }
    }

    fn flush(&self) {}
}

static LOG: StderrLog = StderrLog;

/// Sends warnings (and with `verbose`, the broker's audit lines: grants and
/// authorized runs, by id) to stderr. Never stdout: it may be the protocol.
pub fn log_to_stderr(verbose: bool) {
    if log::set_logger(&LOG).is_ok() {
        log::set_max_level(if verbose {
            log::LevelFilter::Info
        } else {
            log::LevelFilter::Warn
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{allows, clock_utc, passes, question};
    use std::time::Duration;
    use unissh_automation::{PendingApproval, TargetInfo};
    use zeroize::Zeroizing;

    fn request(command: &str) -> PendingApproval {
        PendingApproval {
            run_id: "r".into(),
            integration_id: "i".into(),
            application: "Claude \u{1b}[31mCode".into(),
            target: TargetInfo {
                vault_id: "v".into(),
                profile_id: "p".into(),
                vault: "Prod".into(),
                groups: vec![],
                tags: vec![],
                label: "web".into(),
                host: "web.example.com".into(),
                port: 2222,
                user: "deploy".into(),
            },
            command: Zeroizing::new(command.into()),
            cwd: Some(Zeroizing::new("/srv/app".into())),
            stdin: None,
            env: vec![("MODE".into(), Zeroizing::new("a\nb".into()))],
            timeout_ms: 120_000,
            expires_in: Duration::from_secs(120),
        }
    }

    /// What the person decides on: the exact command with its line breaks and
    /// escapes spelled out, the destination, the inputs and who asks — and
    /// nothing from the vault or the agent can drive the terminal.
    #[test]
    fn the_question_shows_the_exact_command_host_and_application() {
        let text = question(&request("echo ok\nrm -rf /\u{1b}[1A"));
        assert!(
            text.contains(r#"command  "echo ok\nrm -rf /\u001b[1A""#),
            "{text}"
        );
        assert!(text.contains("host     web  deploy@web.example.com:2222  (vault Prod)"));
        assert!(text.contains(r#"cwd      "/srv/app""#));
        assert!(text.contains(r#"env      MODE="a\nb""#));
        assert!(text.contains("\"Claude [31mCode\" asks"));
        assert!(
            !text.contains('\u{1b}'),
            "no raw escape reaches the terminal"
        );
    }

    /// The default is no: only a typed `yes` runs the command.
    #[test]
    fn only_a_typed_yes_allows() {
        assert!(allows("yes"));
        assert!(allows(" YES "));
        for no in ["", "y", "no", "yes please", "\u{3}"] {
            assert!(!allows(no), "{no:?} must not allow");
        }
    }

    /// The SDK's diagnostics hold raw commands and output; no level lets them out.
    #[test]
    fn mcp_sdk_diagnostics_never_reach_the_log() {
        let at = |target: &str, level| {
            passes(
                &log::Metadata::builder().target(target).level(level).build(),
                log::LevelFilter::Info,
            )
        };
        assert!(!at("rmcp", log::Level::Error));
        assert!(!at("rmcp::service", log::Level::Warn));
        assert!(at("unissh_automation", log::Level::Info));
        assert!(!at("unissh_automation", log::Level::Debug));
    }

    /// The approval prompt names the time the question expires, not a count
    /// that goes stale on screen.
    #[test]
    fn the_approval_deadline_reads_as_a_clock_time() {
        let at = std::time::UNIX_EPOCH + Duration::from_secs(20_000 * 86_400 + 52_325);
        assert_eq!(clock_utc(at), "14:32:05 UTC");
    }
}
