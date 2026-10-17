//! Offering a session's saved login password at an interactive password prompt.
//!
//! The invariant everything here exists to keep: a session can type exactly one
//! secret — the vault password item it authenticated with — into exactly that
//! session, only while the core itself sees a recognised password prompt at the
//! end of the output, at most once per prompt, never followed by Enter. The
//! plaintext never crosses the FFI/IPC boundary and never reaches the UI, the
//! clipboard, the scrollback or a recording.
//!
//! The pieces, and what each one is for:
//!
//! - [`classify_tail`] decides whether the output ends with a prompt the login
//!   password may answer. It lives in the core, not the UI, because the UI is
//!   exactly the party that must not be able to point the password at a prompt
//!   of its choosing — and it is an allow-list, because a nested
//!   `ssh other-host` asks for *another machine's* password in words that look
//!   just like ours.
//! - [`FillGuard`] is the per-session state machine: one offer per prompt
//!   instance, withdrawn by any keystroke, refused once the same prompt comes
//!   straight back after a fill (the saved password was wrong, and typing it
//!   again is how accounts get locked by PAM faillock or fail2ban).
//! - [`EchoMask`] is the net under a prompt that was mis-detected and echoes:
//!   for a few seconds after a fill the password is masked out of the output
//!   before the recorder or the UI sees it.
//!
//! Kept free of the SSH and vault layers on purpose: this is pure state over
//! bytes and instants, with the clock passed in, so it is tested exactly.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use zeroize::{Zeroize, Zeroizing};

use crate::{lock_recover, FfiError, SessionObserver};

/// How soon after a fill the same kind of prompt coming back means the saved
/// password was refused.
///
/// Language-agnostic on purpose: "Sorry, try again." is translated, the prompt
/// reappearing within seconds is not. PAM's failure delay is a couple of
/// seconds; this leaves room for a slow link without swallowing a genuinely new
/// prompt a minute later.
const REJECT_WINDOW: Duration = Duration::from_secs(15);

/// How long after a fill the output is searched for the password echoing back.
///
/// A real password prompt never echoes, so this only ever matters for a prompt
/// that was mis-detected — and that program echoes what it read straight away.
const ECHO_WINDOW: Duration = Duration::from_secs(5);

/// How much of the output the classifier keeps to look back over. A prompt is
/// one short line; this only has to outlast the longest accepted one plus the
/// escape sequences a program may wrap it in.
const TAIL_MAX: usize = 512;

/// A last line longer than this is not a prompt the core recognises.
const PROMPT_MAX_CHARS: usize = 160;

/// Bare prompts that name no account, compared case-insensitively: `su`,
/// `login`, `passwd`'s first question and their common translations.
///
/// Deliberately not here: `Enter password:` (database and archive clients ask
/// for *their* passwords that way), `New password:`, key passphrases and
/// anything naming another user or host.
const GENERIC_PROMPTS: [&str; 10] = [
    "Password:",
    "Пароль:",
    "Passwort:",
    "Mot de passe :",
    "Mot de passe:",
    "Contraseña:",
    "Senha:",
    "Hasło:",
    "密码：",
    "密码:",
];

/// Which recognised prompt is waiting for a password.
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum FillPromptKind {
    /// `[sudo] password for <login user>:`, in any sudo locale.
    Sudo,
    /// `doas (<login user>@host) password:`.
    Doas,
    /// A bare `Password:` (or a translation of it) that names no account.
    Generic,
}

/// What the core tells the UI about a session's password-fill offer.
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum FillEvent {
    /// A password prompt the session's login password may answer is at the end of the output.
    Offered {
        /// Which prompt it is.
        kind: FillPromptKind,
    },
    /// The offer is gone (prompt answered, user typed, output moved on, filled).
    Withdrawn,
    /// The prompt came back right after a fill: the saved password was rejected. Not offerable.
    Rejected,
    /// The remote echoed the filled password; it was masked in output/recording.
    Echoed,
}

/// Classifies the end of a session's output: is the cursor sitting right after a
/// prompt that `login_user`'s password may answer?
///
/// The output must *end* with the prompt — a prompt that has already been
/// answered (a newline after it) or scrolled past is not waiting for anything.
/// Escape sequences and stray control characters are stripped first, since
/// shells and `sudo` alike may colour or retitle around a prompt.
pub(crate) fn classify_tail(tail: &[u8], login_user: &str) -> Option<FillPromptKind> {
    let text = strip_controls(&String::from_utf8_lossy(tail));
    if text.ends_with('\n') {
        return None;
    }
    let line = text.rsplit_once('\n').map_or(text.as_str(), |(_, l)| l);
    // A carriage return mid-line is a redraw from column 0: what follows the
    // last one is what is on screen. One at the very end moves nothing visible.
    let line = line.trim_end_matches('\r');
    let line = line.rsplit_once('\r').map_or(line, |(_, l)| l).trim_end();
    if line.is_empty() || line.chars().count() > PROMPT_MAX_CHARS {
        return None;
    }
    // sudo and doas name whose password they want; it is ours only when that is
    // the account the session logged in as. `sudo -u bob` still asks for the
    // caller's password, so the named user is the one to compare.
    if let Some(user) = sudo_user(line) {
        return (user == login_user).then_some(FillPromptKind::Sudo);
    }
    if let Some(user) = doas_user(line) {
        return (user == login_user).then_some(FillPromptKind::Doas);
    }
    let lower = line.to_lowercase();
    GENERIC_PROMPTS
        .iter()
        .any(|p| p.to_lowercase() == lower)
        .then_some(FillPromptKind::Generic)
}

/// The user a `[sudo] … <user>:` prompt names, in whatever language the rest of
/// it is in (`password for alice:`, `пароль для alice:`, `Mot de passe de alice :`).
fn sudo_user(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("[sudo] ")?.strip_suffix(':')?;
    // French puts a space before the colon.
    let rest = rest.strip_suffix(char::is_whitespace).unwrap_or(rest);
    let (head, user) = rest.rsplit_once(' ')?;
    (!head.is_empty() && !user.is_empty() && !user.contains(char::is_whitespace)).then_some(user)
}

/// The user a `doas (<user>@<host>) password:` prompt names.
fn doas_user(line: &str) -> Option<&str> {
    let inner = line.strip_prefix("doas (")?.strip_suffix(") password:")?;
    if inner.contains(char::is_whitespace) {
        return None;
    }
    let (user, host) = inner.split_once('@')?;
    (!user.is_empty() && !host.is_empty()).then_some(user)
}

/// Drops escape sequences (CSI, OSC and the other string sequences, two-byte
/// escapes) and control characters other than `\n` and `\r`.
fn strip_controls(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\u{1b}' => skip_escape(&mut chars),
            '\n' | '\r' => out.push(c),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

/// Consumes the rest of an escape sequence whose ESC was just read.
fn skip_escape(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    match chars.next() {
        // CSI: parameter and intermediate bytes up to one final byte.
        Some('[') => {
            for c in chars.by_ref() {
                if ('\u{40}'..='\u{7e}').contains(&c) {
                    break;
                }
            }
        }
        // OSC, DCS, SOS, PM, APC: a string ended by BEL or ST (`ESC \`).
        Some(']' | 'P' | 'X' | '^' | '_') => {
            while let Some(c) = chars.next() {
                if c == '\u{7}' {
                    break;
                }
                if c == '\u{1b}' {
                    if chars.peek() == Some(&'\\') {
                        chars.next();
                    }
                    break;
                }
            }
        }
        // nF: intermediate bytes, then one final byte.
        Some(c) if ('\u{20}'..='\u{2f}').contains(&c) => {
            for c in chars.by_ref() {
                if !('\u{20}'..='\u{2f}').contains(&c) {
                    break;
                }
            }
        }
        // Any other two-character escape (`ESC 7`, `ESC =`, …), or a lone ESC.
        Some(_) | None => {}
    }
}

/// Masks the filled password out of the output for a short while after a fill.
///
/// Every occurrence is replaced by one `*` per character, so the line keeps its
/// shape. An occurrence can straddle two chunks, so the longest end of a chunk
/// that could be the start of the password is held back until the next chunk
/// shows whether it was. Known limit: those held bytes (never more than the
/// password's length minus one) wait for the next chunk, however long it takes;
/// after the window the next chunk flushes them.
pub(crate) struct EchoMask {
    secret: Zeroizing<Vec<u8>>,
    /// One `*` per character of the secret, not per byte.
    stars: usize,
    deadline: Instant,
    /// The end of the last chunk that might be the start of the secret.
    held: Zeroizing<Vec<u8>>,
    /// Whether an echo has already been reported: the UI clears the line once.
    reported: bool,
}

/// One chunk through the mask.
struct Masked {
    out: Vec<u8>,
    /// The secret was found for the first time.
    echoed: bool,
    /// The window is over: nothing is held, and the mask can go.
    expired: bool,
}

impl EchoMask {
    /// `None` for an empty secret: there is nothing to mask, and an empty
    /// pattern would match everywhere.
    fn new(secret: &str, deadline: Instant) -> Option<Self> {
        if secret.is_empty() {
            return None;
        }
        Some(Self {
            secret: Zeroizing::new(secret.as_bytes().to_vec()),
            stars: secret.chars().count(),
            deadline,
            held: Zeroizing::new(Vec::new()),
            reported: false,
        })
    }

    fn feed(&mut self, chunk: &[u8], now: Instant) -> Masked {
        let mut data = Zeroizing::new(Vec::with_capacity(self.held.len() + chunk.len()));
        data.extend_from_slice(&self.held);
        data.extend_from_slice(chunk);
        self.held.zeroize();

        let mut out = Vec::with_capacity(data.len());
        // Where the bytes after the last mask start: only those can begin an
        // occurrence that continues into the next chunk.
        let mut raw_from = 0;
        let mut found = false;
        let mut rest = data.as_slice();
        loop {
            if let Some(after) = rest.strip_prefix(self.secret.as_slice()) {
                out.resize(out.len() + self.stars, b'*');
                raw_from = out.len();
                found = true;
                rest = after;
            } else if let Some((&b, after)) = rest.split_first() {
                out.push(b);
                rest = after;
            } else {
                break;
            }
        }
        let echoed = found && !self.reported;
        self.reported |= found;

        if now >= self.deadline {
            return Masked {
                out,
                echoed,
                expired: true,
            };
        }
        let raw = out.get(raw_from..).unwrap_or_default();
        let cut = out.len() - held_back_len(raw, &self.secret);
        if let Some(tail) = out.get_mut(cut..) {
            self.held.extend_from_slice(tail);
            tail.zeroize();
        }
        out.truncate(cut);
        Masked {
            out,
            echoed,
            expired: false,
        }
    }
}

/// The length of the longest end of `raw` that is a proper start of `secret`.
fn held_back_len(raw: &[u8], secret: &[u8]) -> usize {
    let max = secret.len().saturating_sub(1).min(raw.len());
    (1..=max)
        .rev()
        .find(|&k| secret.get(..k).is_some_and(|p| raw.ends_with(p)))
        .unwrap_or(0)
}

/// One appearance of a recognised prompt at the end of the output.
#[derive(Clone, Copy)]
struct PromptInstance {
    kind: FillPromptKind,
    /// Whether this instance may be filled at all (a rejected one may not).
    offerable: bool,
    /// Filled, or the user started typing: either way, not again.
    consumed: bool,
}

impl PromptInstance {
    const fn is_live(self) -> bool {
        self.offerable && !self.consumed
    }
}

/// The last fill, for telling a rejected password from a new prompt.
#[derive(Clone, Copy)]
struct LastFill {
    at: Instant,
    kind: FillPromptKind,
    /// Already reported as rejected. Kept rather than forgotten: sudo asks three
    /// times, and the third prompt inside the window must not offer the password
    /// the second one just proved wrong.
    rejected: bool,
}

#[derive(Default)]
struct GuardState {
    /// The last [`TAIL_MAX`] bytes of output, after masking.
    tail: Vec<u8>,
    current: Option<PromptInstance>,
    last_fill: Option<LastFill>,
    echo: Option<EchoMask>,
}

impl GuardState {
    fn on_output(
        &mut self,
        data: Vec<u8>,
        login_user: &str,
        now: Instant,
        events: &mut Vec<FillEvent>,
    ) -> Vec<u8> {
        let out = match self.echo.as_mut() {
            None => data,
            Some(mask) => {
                // The unmasked chunk may hold the password; it is wiped, not dropped.
                let data = Zeroizing::new(data);
                let masked = mask.feed(&data, now);
                if masked.echoed {
                    events.push(FillEvent::Echoed);
                }
                if masked.expired {
                    self.echo = None;
                }
                masked.out
            }
        };
        self.push_tail(&out);
        let next = classify_tail(&self.tail, login_user);
        // A newline in the chunk means the line the old prompt was on has been
        // left, even when the chunk ends on the same kind of prompt again
        // (`\nSorry, try again.\n[sudo] password for alice: ` in one read): that
        // is a new instance, and the rejection check has to see it.
        if out.contains(&b'\n') {
            self.transition(None, now, events);
        }
        self.transition(next, now, events);
        out
    }

    fn push_tail(&mut self, out: &[u8]) {
        self.tail.extend_from_slice(out);
        let excess = self.tail.len().saturating_sub(TAIL_MAX);
        if excess > 0 {
            self.tail.drain(..excess);
        }
    }

    fn transition(
        &mut self,
        next: Option<FillPromptKind>,
        now: Instant,
        events: &mut Vec<FillEvent>,
    ) {
        match (self.current, next) {
            (None, None) => {}
            // The same prompt is still waiting: nothing has changed.
            (Some(cur), Some(kind)) if cur.kind == kind => {}
            (prev, next) => {
                if prev.is_some_and(PromptInstance::is_live) {
                    events.push(FillEvent::Withdrawn);
                }
                self.current =
                    next.map(|kind| open_instance(kind, &mut self.last_fill, now, events));
            }
        }
    }

    /// The live offer's kind, if there is one.
    fn live_kind(&self) -> Option<FillPromptKind> {
        let p = self.current?;
        p.is_live().then_some(p.kind)
    }

    /// Marks the live offer consumed and returns its kind.
    const fn take_offer(&mut self) -> Option<FillPromptKind> {
        match self.current.as_mut() {
            Some(p) if p.is_live() => {
                p.consumed = true;
                Some(p.kind)
            }
            Some(_) | None => None,
        }
    }

    /// Takes the live offer for a fill and arms everything that watches the
    /// result, in one step under the lock — so two racing fills cannot both
    /// pass, and an echo that arrives before the write returns is still masked.
    fn claim(&mut self, secret: &str, now: Instant) -> Option<FillPromptKind> {
        let kind = self.take_offer()?;
        self.echo = EchoMask::new(secret, now.checked_add(ECHO_WINDOW).unwrap_or(now));
        self.last_fill = Some(LastFill {
            at: now,
            kind,
            rejected: false,
        });
        Some(kind)
    }
}

/// A new prompt instance: offered, unless it is the prompt a fill just answered
/// coming straight back.
fn open_instance(
    kind: FillPromptKind,
    last_fill: &mut Option<LastFill>,
    now: Instant,
    events: &mut Vec<FillEvent>,
) -> PromptInstance {
    let refused = last_fill
        .as_mut()
        .filter(|f| f.kind == kind && now.saturating_duration_since(f.at) < REJECT_WINDOW);
    match refused {
        Some(fill) => {
            if !fill.rejected {
                fill.rejected = true;
                events.push(FillEvent::Rejected);
            }
            PromptInstance {
                kind,
                offerable: false,
                consumed: false,
            }
        }
        None => {
            events.push(FillEvent::Offered { kind });
            PromptInstance {
                kind,
                offerable: true,
                consumed: false,
            }
        }
    }
}

fn no_offer() -> FfiError {
    FfiError::other("no password prompt is waiting for the saved password")
}

/// The password-fill state of one SSH session that logged in with a vault
/// password item.
///
/// Bound at `open_session` to that item and that login user and to nothing else:
/// no call takes an item, so nothing the UI sends can point a fill at another
/// secret. Events go to the session's own observer, always outside the lock —
/// an observer that calls back into the session must not deadlock it.
pub(crate) struct FillGuard {
    /// The vault holding the login password item.
    pub(crate) vault_id: String,
    /// The login password item: the only secret this session can ever type.
    pub(crate) item_id: String,
    login_user: String,
    observer: Arc<dyn SessionObserver>,
    state: Mutex<GuardState>,
}

impl FillGuard {
    pub(crate) fn new(
        vault_id: String,
        item_id: String,
        login_user: String,
        observer: Arc<dyn SessionObserver>,
    ) -> Self {
        Self {
            vault_id,
            item_id,
            login_user,
            observer,
            state: Mutex::new(GuardState::default()),
        }
    }

    /// Runs one output chunk through the mask and the classifier, hands the
    /// (masked) bytes to `forward`, then reports what changed. The data goes
    /// first so the prompt is on screen by the time the offer appears.
    pub(crate) fn on_output(&self, data: Vec<u8>, now: Instant, forward: impl FnOnce(Vec<u8>)) {
        let mut events = Vec::new();
        let out = lock_recover(&self.state).on_output(data, &self.login_user, now, &mut events);
        if !out.is_empty() {
            forward(out);
        }
        self.emit(events);
    }

    /// The user typed into the session: whatever offer was live is gone. A
    /// password half-typed by hand must not get the saved one appended to it.
    pub(crate) fn note_input(&self) {
        let taken = lock_recover(&self.state).take_offer();
        if taken.is_some() {
            self.emit(vec![FillEvent::Withdrawn]);
        }
    }

    /// Whether a fill would be accepted right now — checked before the vault is
    /// touched, so a refused fill does not decrypt anything.
    pub(crate) fn check_offer(&self) -> Result<FillPromptKind, FfiError> {
        lock_recover(&self.state).live_kind().ok_or_else(no_offer)
    }

    /// Claims the live offer for `secret`, which the caller then writes. The
    /// authoritative check: [`Self::check_offer`] only spared a vault read.
    pub(crate) fn claim(&self, secret: &str, now: Instant) -> Result<FillPromptKind, FfiError> {
        let claimed = lock_recover(&self.state).claim(secret, now);
        let kind = claimed.ok_or_else(no_offer)?;
        self.emit(vec![FillEvent::Withdrawn]);
        Ok(kind)
    }

    /// The write after [`Self::claim`] failed: nothing was typed, so there is no
    /// echo to watch for and no rejection to expect. The prompt instance stays
    /// consumed — a dead channel is not worth a second try.
    pub(crate) fn abort_fill(&self) {
        let mut st = lock_recover(&self.state);
        st.echo = None;
        st.last_fill = None;
    }

    fn emit(&self, events: Vec<FillEvent>) {
        for event in events {
            self.observer.on_fill(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: &str = "alice";

    #[derive(Default)]
    struct Events(Mutex<Vec<FillEvent>>);

    impl SessionObserver for Events {
        fn on_data(&self, _data: Vec<u8>) {}
        fn on_close(&self, _exit_status: i32) {}
        fn on_fill(&self, event: FillEvent) {
            self.0.lock().unwrap().push(event);
        }
    }

    impl Events {
        fn take(&self) -> Vec<FillEvent> {
            std::mem::take(&mut *self.0.lock().unwrap())
        }
    }

    fn guard() -> (FillGuard, Arc<Events>) {
        let events = Arc::new(Events::default());
        let g = FillGuard::new("v".into(), "pw".into(), ALICE.into(), events.clone());
        (g, events)
    }

    /// Feeds one chunk and returns what was forwarded.
    fn feed(g: &FillGuard, data: &[u8], now: Instant) -> Vec<u8> {
        let mut out = Vec::new();
        g.on_output(data.to_vec(), now, |d| out = d);
        out
    }

    const SUDO: &[u8] = b"$ sudo su\r\n[sudo] password for alice: ";
    const OFFERED_SUDO: FillEvent = FillEvent::Offered {
        kind: FillPromptKind::Sudo,
    };

    #[test]
    fn recognised_prompts_are_classified() {
        let cases: [(&str, FillPromptKind); 13] = [
            ("[sudo] password for alice: ", FillPromptKind::Sudo),
            ("[sudo] пароль для alice: ", FillPromptKind::Sudo),
            ("[sudo] Passwort für alice: ", FillPromptKind::Sudo),
            ("[sudo] Mot de passe de alice : ", FillPromptKind::Sudo),
            ("doas (alice@web1) password: ", FillPromptKind::Doas),
            ("Password: ", FillPromptKind::Generic),
            ("password:", FillPromptKind::Generic),
            ("Пароль: ", FillPromptKind::Generic),
            ("Mot de passe : ", FillPromptKind::Generic),
            ("Contraseña: ", FillPromptKind::Generic),
            ("Hasło: ", FillPromptKind::Generic),
            ("密码：", FillPromptKind::Generic),
            ("last login\r\nPassword: ", FillPromptKind::Generic),
        ];
        for (line, kind) in cases {
            assert_eq!(
                classify_tail(line.as_bytes(), ALICE),
                Some(kind),
                "{line:?}"
            );
        }
    }

    #[test]
    fn prompts_for_another_account_or_purpose_are_not_classified() {
        let cases = [
            "bob@db1's password: ",
            "Enter passphrase for key '/x': ",
            "Password for 'https://u@github.com': ",
            "Enter password: ",
            "New password: ",
            "[sudo] password for bob: ",
            "doas (bob@web1) password: ",
            "alice@h:~$ ",
        ];
        for line in cases {
            assert_eq!(classify_tail(line.as_bytes(), ALICE), None, "{line:?}");
        }
    }

    #[test]
    fn a_prompt_wrapped_in_escape_sequences_is_recognised() {
        let tail = b"\x1b]0;alice@h\x07\x1b[1m[sudo] password for alice:\x1b[0m ";
        assert_eq!(classify_tail(tail, ALICE), Some(FillPromptKind::Sudo));
    }

    #[test]
    fn a_prompt_followed_by_a_newline_is_not_waiting() {
        assert_eq!(classify_tail(b"Password: \r\n", ALICE), None);
    }

    #[test]
    fn an_overlong_line_is_not_a_prompt() {
        let line = format!("[sudo] {} for alice:", "x".repeat(PROMPT_MAX_CHARS));
        assert_eq!(classify_tail(line.as_bytes(), ALICE), None);
    }

    #[test]
    fn a_prompt_is_offered_once() {
        let (g, ev) = guard();
        let now = Instant::now();
        feed(&g, b"$ sudo su\r\n[sudo] password for ", now);
        feed(&g, b"alice: ", now);
        feed(&g, b"", now);
        assert_eq!(ev.take(), vec![OFFERED_SUDO]);
    }

    #[test]
    fn output_moving_on_withdraws_the_offer() {
        let (g, ev) = guard();
        let now = Instant::now();
        feed(&g, SUDO, now);
        feed(&g, b"\r\nsudo: timed out\r\n$ ", now);
        assert_eq!(ev.take(), vec![OFFERED_SUDO, FillEvent::Withdrawn]);
    }

    #[test]
    fn typing_withdraws_the_offer_and_refuses_a_fill() {
        let (g, ev) = guard();
        let now = Instant::now();
        feed(&g, SUDO, now);
        g.note_input();
        assert_eq!(ev.take(), vec![OFFERED_SUDO, FillEvent::Withdrawn]);
        assert!(g.claim("s3cret", now).is_err());
    }

    #[test]
    fn a_fill_without_a_prompt_is_refused() {
        let (g, _ev) = guard();
        let now = Instant::now();
        feed(&g, b"alice@h:~$ ", now);
        assert!(g.check_offer().is_err());
        assert!(g.claim("s3cret", now).is_err());
    }

    #[test]
    fn a_second_fill_of_the_same_prompt_is_refused() {
        let (g, _ev) = guard();
        let now = Instant::now();
        feed(&g, SUDO, now);
        assert_eq!(g.claim("s3cret", now).unwrap(), FillPromptKind::Sudo);
        assert!(g.claim("s3cret", now).is_err());
    }

    #[test]
    fn the_prompt_returning_inside_the_window_is_rejected() {
        let (g, ev) = guard();
        let t0 = Instant::now();
        feed(&g, SUDO, t0);
        g.claim("s3cret", t0).unwrap();
        ev.take();
        // The answer and the re-prompt in a single read.
        feed(
            &g,
            b"\r\nSorry, try again.\r\n[sudo] password for alice: ",
            t0 + Duration::from_secs(2),
        );
        assert_eq!(ev.take(), vec![FillEvent::Rejected]);
        assert!(g.check_offer().is_err());
    }

    #[test]
    fn a_third_prompt_inside_the_window_stays_unoffered() {
        let (g, ev) = guard();
        let t0 = Instant::now();
        feed(&g, SUDO, t0);
        g.claim("s3cret", t0).unwrap();
        let again = b"\r\nSorry, try again.\r\n[sudo] password for alice: ";
        feed(&g, again, t0 + Duration::from_secs(2));
        ev.take();
        feed(&g, again, t0 + Duration::from_secs(5));
        assert_eq!(ev.take(), vec![]);
        assert!(g.check_offer().is_err());
    }

    #[test]
    fn the_prompt_returning_after_the_window_is_offered_again() {
        let (g, ev) = guard();
        let t0 = Instant::now();
        feed(&g, SUDO, t0);
        g.claim("s3cret", t0).unwrap();
        ev.take();
        feed(&g, b"\r\n$ ", t0 + Duration::from_secs(1));
        feed(&g, SUDO, t0 + REJECT_WINDOW + Duration::from_secs(1));
        assert_eq!(ev.take(), vec![OFFERED_SUDO]);
    }

    #[test]
    fn an_echo_in_one_chunk_is_masked() {
        let (g, ev) = guard();
        let t0 = Instant::now();
        feed(&g, b"Password: ", t0);
        g.claim("pässword", t0).unwrap();
        ev.take();
        let out = feed(&g, "pässword\r\n".as_bytes(), t0);
        assert_eq!(out, b"********\r\n");
        assert_eq!(ev.take(), vec![FillEvent::Echoed]);
    }

    #[test]
    fn an_echo_split_across_chunks_is_masked() {
        let (g, _ev) = guard();
        let t0 = Instant::now();
        feed(&g, b"Password: ", t0);
        g.claim("s3cret", t0).unwrap();
        let first = feed(&g, b"s3c", t0);
        let second = feed(&g, b"ret\r\n", t0);
        assert_eq!([first, second].concat(), b"******\r\n");
    }

    #[test]
    fn output_without_an_echo_passes_through_unchanged() {
        let (g, ev) = guard();
        let t0 = Instant::now();
        feed(&g, b"Password: ", t0);
        g.claim("s3cret", t0).unwrap();
        ev.take();
        assert_eq!(feed(&g, b"\r\nroot@h:~# ", t0), b"\r\nroot@h:~# ");
        assert_eq!(ev.take(), vec![]);
    }

    #[test]
    fn the_end_of_the_window_flushes_held_bytes() {
        let (g, _ev) = guard();
        let t0 = Instant::now();
        feed(&g, b"Password: ", t0);
        g.claim("s3cret", t0).unwrap();
        assert_eq!(feed(&g, b"ls s3", t0), b"ls ");
        let later = t0 + ECHO_WINDOW + Duration::from_secs(1);
        assert_eq!(feed(&g, b"\r\n", later), b"s3\r\n");
    }
}
