//! Offering a session's saved login password at an interactive password prompt.
//!
//! The invariant everything here exists to keep: a session can type exactly one
//! secret — the vault password item it authenticated with — into exactly that
//! session, only while the core itself sees a recognised password prompt at the
//! end of the output, at most once per prompt, never followed by Enter. The
//! plaintext never crosses the FFI/IPC boundary and never reaches the UI, the
//! clipboard, the scrollback or a recording.
//!
//! What it does *not* know: which machine or program is asking. Anything that
//! prints into this session — a nested `ssh`, `telnet`, `ftp`, a keyboard-
//! interactive prompt of another server — can draw a prompt the classifier
//! accepts, and the login password would go there. That is why bare
//! `Password:` prompts are opt-in ([`PasswordFillMode::SudoAndGeneric`]) and the
//! offer never claims a destination.
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
//!   instance, each with its own id the fill must name, withdrawn by any
//!   keystroke, and a password the remote rejected is never typed again on the
//!   session (retrying it is how accounts get locked by PAM faillock or
//!   fail2ban).
//! - [`EchoMask`] is the net under a prompt that was mis-detected and echoes:
//!   for a while after a fill the password is masked out of the output before
//!   the recorder or the UI sees it, and the line is killed.
//!
//! Kept free of the SSH and vault layers on purpose: this is pure state over
//! bytes and instants, with the clock passed in, so it is tested exactly.

use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
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

/// The longest the output is searched for the password echoing back after a fill.
///
/// A real password prompt never echoes, so this only ever matters for a prompt
/// that was mis-detected — and that program echoes what it read straight away,
/// though a slow link or a loaded host can hold the echo back for a while.
const ECHO_WINDOW: Duration = Duration::from_secs(30);

/// Once the user types after a fill (normally: Enter), the echo window closes
/// this long after that keystroke. The echo of the fill itself is long out by
/// then; past it, what the user types is not ours to search.
const ECHO_AFTER_INPUT: Duration = Duration::from_secs(3);

/// The most output held back as a possible start of an echo. An echo the remote
/// spreads over more than this (escape sequences between the characters) is
/// flushed unmasked rather than stalling the terminal.
const HOLD_MAX: usize = 4096;

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

/// Which password prompts a session may offer its login password at.
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordFillMode {
    /// No offers at all; the session has no fill state.
    Off,
    /// `sudo` and `doas` prompts that name the login user.
    SudoOnly,
    /// Those, and bare `Password:` prompts (`su`, `login`, …) that name no one.
    /// A bare prompt can be any program's on any machine this session reaches,
    /// hence a separate opt-in.
    SudoAndGeneric,
}

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
#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum FillEvent {
    /// A password prompt the session's login password may answer is at the end of the output.
    Offered {
        /// Which prompt it is.
        kind: FillPromptKind,
        /// This offer; a fill must name it. Increases with every offer of the session.
        offer_id: u64,
        /// The account a sudo/doas prompt names (always the login user); none for a bare prompt.
        user: Option<String>,
        /// A saved password was rejected on this session before: the fill is refused
        /// unless the saved password has changed since.
        rejected_before: bool,
    },
    /// The offer is gone (prompt answered, user typed, output moved on, filled).
    Withdrawn {
        /// The offer that is gone.
        offer_id: u64,
    },
    /// The prompt came back right after a fill: the saved password was rejected,
    /// and will not be typed again on this session.
    Rejected,
    /// The remote echoed the filled password; it was masked in output/recording
    /// and the line was killed (Ctrl-U).
    Echoed,
}

/// Classifies the end of a session's output: is the cursor sitting right after a
/// prompt that `login_user`'s password may answer?
///
/// The output must *end* with the prompt — a prompt that has already been
/// answered (a newline after it) or scrolled past is not waiting for anything.
/// Escape sequences and stray control characters are stripped first, since
/// shells and `sudo` alike may colour or retitle around a prompt. Bare prompts
/// count only with `allow_generic`.
pub(crate) fn classify_tail(
    tail: &[u8],
    login_user: &str,
    allow_generic: bool,
) -> Option<FillPromptKind> {
    let text = strip_controls(&String::from_utf8_lossy(tail));
    if text.ends_with('\n') {
        return None;
    }
    let line = text.rsplit_once('\n').map_or(text.as_str(), |(_, l)| l);
    // A carriage return returns to column 0 and what follows overwrites what
    // was there — `(bob@evil) \rPassword: ` shows `Password: ` over someone
    // else's prompt. Only a return with nothing visible before it is harmless.
    let line = match line.rsplit_once('\r') {
        Some((before, _)) if !before.trim().is_empty() => return None,
        Some((_, after)) => after,
        None => line,
    }
    .trim_end();
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
    if !allow_generic {
        return None;
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

/// What a terminal may put between two echoed characters without changing what
/// they spell, at the start of some output.
enum Skip {
    /// A sequence this many bytes long.
    Len(usize),
    /// The output ends inside what may be such a sequence.
    Incomplete,
    /// Not one.
    No,
}

/// Recognises a line break (an echo wrapped at the right margin: `\r\n`, `\r`,
/// `\n`) or a CSI/OSC sequence (colour, cursor and erase-line around each
/// character, as syntax highlighters redraw it) at the start of `rest`.
fn skip_at(rest: &[u8]) -> Skip {
    match rest {
        [b'\r' | b'\n', ..] => Skip::Len(1),
        [0x1b] => Skip::Incomplete,
        [0x1b, b'[', params @ ..] => {
            for (i, &b) in params.iter().enumerate() {
                match b {
                    0x40..=0x7e => return Skip::Len(i.saturating_add(3)),
                    0x20..=0x3f => {}
                    _ => return Skip::No,
                }
            }
            Skip::Incomplete
        }
        [0x1b, b']', body @ ..] => {
            for (i, &b) in body.iter().enumerate() {
                match (b, body.get(i.saturating_add(1))) {
                    (0x07, _) => return Skip::Len(i.saturating_add(3)),
                    (0x1b, Some(b'\\')) => return Skip::Len(i.saturating_add(4)),
                    (0x1b, Some(_)) => return Skip::No,
                    (0x1b, None) => return Skip::Incomplete,
                    _ => {}
                }
            }
            Skip::Incomplete
        }
        _ => Skip::No,
    }
}

/// One try at reading the secret out of the output from a given position.
enum Attempt {
    /// Spelled out in full, at these byte positions.
    Full(Vec<usize>),
    /// The output ends while it still could be.
    Partial,
    /// It is not here.
    Miss,
}

/// Reads `secret` out of `data` starting at `start`, letting line breaks and
/// CSI/OSC sequences sit between its bytes (never before the first).
fn attempt(data: &[u8], start: usize, secret: &[u8]) -> Attempt {
    let mut positions = Vec::with_capacity(secret.len());
    let mut j = start;
    for &want in secret {
        loop {
            let Some(&b) = data.get(j) else {
                return Attempt::Partial;
            };
            if b == want {
                positions.push(j);
                j = j.saturating_add(1);
                break;
            }
            if positions.is_empty() {
                return Attempt::Miss;
            }
            match skip_at(data.get(j..).unwrap_or_default()) {
                Skip::Len(n) => j = j.saturating_add(n),
                Skip::Incomplete => return Attempt::Partial,
                Skip::No => return Attempt::Miss,
            }
        }
    }
    Attempt::Full(positions)
}

/// Masks the filled password out of the output for a while after a fill.
///
/// Each character of an occurrence is replaced by one `*` in place, and whatever
/// the remote put between the characters (line wraps, colour, cursor moves) is
/// kept, so the screen keeps its shape. An occurrence can straddle two chunks,
/// so a possible start at the end of a chunk is held back (at most
/// [`HOLD_MAX`] bytes) until the next chunk shows whether it was.
///
/// Known limits. Held bytes wait for the next chunk, however long it takes;
/// that is bounded by the window only in the sense that after it, the next
/// chunk flushes them. An echo the remote *transforms* (readline's `\303\244`
/// for a non-ASCII byte in the C locale, `^X` or `M-x` for control and meta
/// characters) is not the password's bytes and is not found.
pub(crate) struct EchoMask {
    secret: Zeroizing<Vec<u8>>,
    deadline: Instant,
    /// The window has already been cut short by a keystroke.
    shortened: bool,
    /// The end of the last chunk that might be the start of the secret.
    held: Zeroizing<Vec<u8>>,
}

/// One chunk through the mask.
struct Masked {
    out: Vec<u8>,
    /// The secret was found (and masked) in this chunk.
    echoed: bool,
    /// The window is over: nothing is held, and the mask can go.
    expired: bool,
}

impl EchoMask {
    /// `None` for an empty secret: there is nothing to mask, and an empty
    /// pattern would match everywhere.
    fn new(secret: &str, now: Instant) -> Option<Self> {
        if secret.is_empty() {
            return None;
        }
        Some(Self {
            secret: Zeroizing::new(secret.as_bytes().to_vec()),
            deadline: now.checked_add(ECHO_WINDOW).unwrap_or(now),
            shortened: false,
            held: Zeroizing::new(Vec::new()),
        })
    }

    /// Ends the mask, handing back what it held so it can be forwarded.
    fn into_held(mut self) -> Vec<u8> {
        std::mem::take(&mut *self.held)
    }

    /// The first keystroke after the fill closes the window soon after it.
    fn note_input(&mut self, now: Instant) {
        if !self.shortened {
            self.shortened = true;
            let cut = now.checked_add(ECHO_AFTER_INPUT).unwrap_or(now);
            self.deadline = self.deadline.min(cut);
        }
    }

    fn feed(&mut self, chunk: &[u8], now: Instant) -> Masked {
        let mut data = Zeroizing::new(Vec::with_capacity(self.held.len() + chunk.len()));
        data.extend_from_slice(&self.held);
        data.extend_from_slice(chunk);
        self.held.zeroize();
        let expired = now >= self.deadline;

        let mut out = Vec::with_capacity(data.len());
        let mut echoed = false;
        let mut i = 0;
        while let Some(&b) = data.get(i) {
            match attempt(&data, i, &self.secret) {
                Attempt::Full(positions) => {
                    let mut stars = positions.iter().zip(self.secret.iter()).peekable();
                    let last = positions.last().copied().unwrap_or(i);
                    for (at, &byte) in data.iter().enumerate().take(last.saturating_add(1)).skip(i)
                    {
                        match stars.next_if(|(p, _)| **p == at) {
                            // One star per character: a UTF-8 continuation byte adds none.
                            Some((_, s)) if s & 0xc0 != 0x80 => out.push(b'*'),
                            Some(_) => {}
                            None => out.push(byte),
                        }
                    }
                    echoed = true;
                    i = last.saturating_add(1);
                }
                Attempt::Partial if !expired && data.len().saturating_sub(i) <= HOLD_MAX => {
                    self.held
                        .extend_from_slice(data.get(i..).unwrap_or_default());
                    break;
                }
                Attempt::Partial | Attempt::Miss => {
                    out.push(b);
                    i = i.saturating_add(1);
                }
            }
        }
        Masked {
            out,
            echoed,
            expired,
        }
    }
}

/// A keyed digest of a password, for remembering that it was rejected without
/// keeping it. The key is random per session and never leaves memory, so the
/// digest is not a way to test guesses.
fn secret_digest(key: &[u8; 32], secret: &str) -> [u8; 32] {
    Sha256::new()
        .chain_update(key)
        .chain_update(secret.as_bytes())
        .finalize()
        .into()
}

/// One appearance of a recognised prompt at the end of the output.
#[derive(Clone, Copy)]
struct PromptInstance {
    /// The offer id, when this instance was offered.
    id: u64,
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

/// What the user has typed since the last fill.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TypedSince {
    Nothing,
    /// Only line endings: the filled password was submitted, nothing else.
    Enter,
    /// Something else: a prompt after this is a new command's, not a retry.
    Other,
}

/// The last fill, for telling a rejected password from a new prompt.
#[derive(Clone, Copy)]
struct LastFill {
    at: Instant,
    kind: FillPromptKind,
    digest: [u8; 32],
    typed: TypedSince,
    /// Already reported as rejected. Kept rather than forgotten: sudo asks three
    /// times, and the third prompt inside the window must not offer the password
    /// the second one just proved wrong.
    rejected: bool,
}

struct GuardState {
    /// The last [`TAIL_MAX`] bytes of output, after masking.
    tail: Vec<u8>,
    current: Option<PromptInstance>,
    last_fill: Option<LastFill>,
    echo: Option<EchoMask>,
    /// The id the next offer gets.
    next_id: u64,
    /// Digests of the passwords the remote rejected on this session.
    rejected: Vec<[u8; 32]>,
}

impl GuardState {
    const fn new() -> Self {
        Self {
            tail: Vec::new(),
            current: None,
            last_fill: None,
            echo: None,
            next_id: 1,
            rejected: Vec::new(),
        }
    }

    fn on_output(
        &mut self,
        data: Vec<u8>,
        cfg: &Config,
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
        let next = classify_tail(&self.tail, &cfg.login_user, cfg.allow_generic);
        // A newline in the chunk means the line the old prompt was on has been
        // left, even when the chunk ends on the same kind of prompt again
        // (`\nSorry, try again.\n[sudo] password for alice: ` in one read): that
        // is a new instance, and the rejection check has to see it.
        if out.contains(&b'\n') {
            self.transition(None, cfg, now, events);
        }
        self.transition(next, cfg, now, events);
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
        cfg: &Config,
        now: Instant,
        events: &mut Vec<FillEvent>,
    ) {
        match (self.current, next) {
            (None, None) => {}
            // The same prompt is still waiting: nothing has changed.
            (Some(cur), Some(kind)) if cur.kind == kind => {}
            (prev, next) => {
                if let Some(p) = prev.filter(|p| p.is_live()) {
                    events.push(FillEvent::Withdrawn { offer_id: p.id });
                }
                let opened = next.map(|kind| self.open_instance(kind, cfg, now, events));
                self.current = opened;
            }
        }
    }

    /// A new prompt instance: offered, unless it is the prompt a fill just
    /// answered coming straight back with nothing but Enter typed in between.
    fn open_instance(
        &mut self,
        kind: FillPromptKind,
        cfg: &Config,
        now: Instant,
        events: &mut Vec<FillEvent>,
    ) -> PromptInstance {
        let refused = self.last_fill.as_mut().filter(|f| {
            f.kind == kind
                && f.typed != TypedSince::Other
                && now.saturating_duration_since(f.at) < REJECT_WINDOW
        });
        if let Some(fill) = refused {
            if !fill.rejected {
                fill.rejected = true;
                events.push(FillEvent::Rejected);
                if !self.rejected.contains(&fill.digest) {
                    self.rejected.push(fill.digest);
                }
            }
            return PromptInstance {
                id: 0,
                kind,
                offerable: false,
                consumed: false,
            };
        }
        let id = self.next_id;
        self.next_id = id.saturating_add(1);
        events.push(FillEvent::Offered {
            kind,
            offer_id: id,
            user: (kind != FillPromptKind::Generic).then(|| cfg.login_user.clone()),
            rejected_before: !self.rejected.is_empty(),
        });
        PromptInstance {
            id,
            kind,
            offerable: true,
            consumed: false,
        }
    }

    /// The live offer, if it is `offer_id`.
    fn live(&self, offer_id: u64) -> Option<PromptInstance> {
        self.current.filter(|p| p.is_live() && p.id == offer_id)
    }

    /// The user typed `data`: the live offer is spent, the echo window closes
    /// soon, and a prompt coming back is a retry only if all they typed was Enter.
    fn note_input(&mut self, data: &[u8], now: Instant, events: &mut Vec<FillEvent>) {
        if let Some(mask) = self.echo.as_mut() {
            mask.note_input(now);
        }
        if let Some(fill) = self.last_fill.as_mut() {
            let enter = data.iter().all(|&b| b == b'\r' || b == b'\n');
            fill.typed = match (fill.typed, enter) {
                (TypedSince::Other, _) | (_, false) => TypedSince::Other,
                (TypedSince::Nothing | TypedSince::Enter, true) => TypedSince::Enter,
            };
        }
        if let Some(p) = self.current.as_mut().filter(|p| p.is_live()) {
            p.consumed = true;
            events.push(FillEvent::Withdrawn { offer_id: p.id });
        }
    }

    /// Takes the live offer `offer_id` for a fill of `secret` and arms everything
    /// that watches the result, in one step under the lock — so two racing fills
    /// cannot both pass, and an echo that arrives before the write returns is
    /// still masked.
    fn claim(
        &mut self,
        offer_id: u64,
        secret: &str,
        digest: [u8; 32],
        now: Instant,
        events: &mut Vec<FillEvent>,
        flushed: &mut Vec<u8>,
    ) -> Result<FillPromptKind, FfiError> {
        let offer = self.live(offer_id).ok_or_else(no_offer)?;
        // Not consumed: the user may still answer this prompt by hand.
        if self.rejected.contains(&digest) {
            return Err(FfiError::other(
                "saved password was rejected on this session",
            ));
        }
        if let Some(p) = self.current.as_mut() {
            p.consumed = true;
        }
        // A mask still running from an earlier fill goes, but what it held
        // back is output like any other.
        *flushed = self
            .echo
            .take()
            .map(EchoMask::into_held)
            .unwrap_or_default();
        self.echo = EchoMask::new(secret, now);
        self.last_fill = Some(LastFill {
            at: now,
            kind: offer.kind,
            digest,
            typed: TypedSince::Nothing,
            rejected: false,
        });
        events.push(FillEvent::Withdrawn { offer_id });
        Ok(offer.kind)
    }
}

fn no_offer() -> FfiError {
    FfiError::other("no password prompt is waiting for the saved password")
}

/// What a guard is bound to at `open_session` and never changes.
struct Config {
    login_user: String,
    allow_generic: bool,
    digest_key: Zeroizing<[u8; 32]>,
}

/// Hands output on down the session's sink chain.
pub(crate) type Forward = Box<dyn Fn(Vec<u8>) + Send + Sync>;

/// Sends Ctrl-U into the session without blocking: called from the reader task.
pub(crate) type LineKill = Box<dyn Fn() + Send + Sync>;

/// The password-fill state of one SSH session that logged in with a vault
/// password item.
///
/// Bound at `open_session` to that item and that login user and to nothing else:
/// no call takes an item, so nothing the UI sends can point a fill at another
/// secret.
///
/// Output and events leave outside the state lock, in the order the state
/// changed: whoever changes the state takes the next order lock before letting
/// go of the previous one (state, then `out_order` while output is forwarded,
/// then `emit_order` while events are delivered). Keystrokes produce no output
/// and go from the state lock straight to `emit_order`, so a withdrawal can
/// overtake the offer it withdraws; the UI drops offers older than the newest
/// id it has seen. An observer must not call back into the session from
/// `on_fill` on the same thread — it would wait on itself.
pub(crate) struct FillGuard {
    /// The vault holding the login password item.
    pub(crate) vault_id: String,
    /// The login password item: the only secret this session can ever type.
    pub(crate) item_id: String,
    cfg: Config,
    observer: Arc<dyn SessionObserver>,
    state: Mutex<GuardState>,
    out_order: Mutex<()>,
    emit_order: Mutex<()>,
    /// Kills the line when the password echoed. Set once the shell is open.
    line_kill: OnceLock<LineKill>,
    /// Where output held back by a mask goes when the mask ends outside the
    /// output path (a new fill, a failed write). Set with the sink chain.
    forward: OnceLock<Forward>,
}

/// Exactly the bytes a terminal sends on its own when it gains or loses focus
/// (focus reporting, `CSI ?1004 h`): not the user typing.
fn is_focus_report(data: &[u8]) -> bool {
    data == b"\x1b[I" || data == b"\x1b[O"
}

impl FillGuard {
    /// `digest_key` keys the digests rejected passwords are remembered by; it
    /// must be random and must not outlive the guard.
    pub(crate) fn new(
        vault_id: String,
        item_id: String,
        login_user: String,
        allow_generic: bool,
        digest_key: Zeroizing<[u8; 32]>,
        observer: Arc<dyn SessionObserver>,
    ) -> Self {
        Self {
            vault_id,
            item_id,
            cfg: Config {
                login_user,
                allow_generic,
                digest_key,
            },
            observer,
            state: Mutex::new(GuardState::new()),
            out_order: Mutex::new(()),
            emit_order: Mutex::new(()),
            line_kill: OnceLock::new(),
            forward: OnceLock::new(),
        }
    }

    /// How to kill the line once the password echoes. Must not block.
    pub(crate) fn set_line_kill(&self, kill: LineKill) {
        if self.line_kill.set(kill).is_err() {
            // Set once per session, right after the shell opens.
        }
    }

    /// Where held-back output goes when a mask ends off the output path.
    pub(crate) fn set_forward(&self, forward: Forward) {
        if self.forward.set(forward).is_err() {
            // Set once per session, with the sink chain.
        }
    }

    /// Lets go of the state, forwards `out`, then delivers `events` — each step
    /// taken before the previous lock is released (see the type's docs).
    fn release(
        &self,
        st: MutexGuard<'_, GuardState>,
        out: Vec<u8>,
        forward: impl FnOnce(Vec<u8>),
        events: Vec<FillEvent>,
    ) {
        let out_order = lock_recover(&self.out_order);
        drop(st);
        if !out.is_empty() {
            forward(out);
        }
        let emit_order = lock_recover(&self.emit_order);
        drop(out_order);
        self.deliver(emit_order, events);
    }

    /// Hands `events` to the observer while `_order` keeps their place in line.
    fn deliver(&self, _order: MutexGuard<'_, ()>, events: Vec<FillEvent>) {
        for event in events {
            if event == FillEvent::Echoed {
                // Before Enter can run the hidden password as a command.
                if let Some(kill) = self.line_kill.get() {
                    kill();
                }
            }
            self.observer.on_fill(event);
        }
    }

    /// Forwards through the stored sink chain, for output that leaves off the
    /// output path.
    fn forward_stored(&self, out: Vec<u8>) {
        if let Some(forward) = self.forward.get() {
            forward(out);
        }
    }

    /// Runs one output chunk through the mask and the classifier, hands the
    /// (masked) bytes to `forward`, then reports what changed. The data goes
    /// first so the prompt is on screen by the time the offer appears.
    pub(crate) fn on_output(&self, data: Vec<u8>, now: Instant, forward: impl FnOnce(Vec<u8>)) {
        let mut events = Vec::new();
        let mut st = lock_recover(&self.state);
        let out = st.on_output(data, &self.cfg, now, &mut events);
        self.release(st, out, forward, events);
    }

    /// The user typed `data` into the session: whatever offer was live is gone.
    /// A password half-typed by hand must not get the saved one appended to it.
    /// A focus report is the terminal's, not the user's, and changes nothing.
    pub(crate) fn note_input(&self, data: &[u8], now: Instant) {
        if is_focus_report(data) {
            return;
        }
        let mut events = Vec::new();
        let mut st = lock_recover(&self.state);
        st.note_input(data, now, &mut events);
        let emit_order = lock_recover(&self.emit_order);
        drop(st);
        self.deliver(emit_order, events);
    }

    /// Whether offer `offer_id` would be filled right now — checked before the
    /// vault is touched, so a refused fill does not decrypt anything.
    pub(crate) fn check_offer(&self, offer_id: u64) -> Result<FillPromptKind, FfiError> {
        let p = lock_recover(&self.state).live(offer_id);
        p.map(|p| p.kind).ok_or_else(no_offer)
    }

    /// Claims offer `offer_id` for `secret`, which the caller then writes. The
    /// authoritative check: [`Self::check_offer`] only spared a vault read.
    /// Refuses a password the remote already rejected on this session.
    pub(crate) fn claim(
        &self,
        offer_id: u64,
        secret: &str,
        now: Instant,
    ) -> Result<FillPromptKind, FfiError> {
        let digest = secret_digest(&self.cfg.digest_key, secret);
        let mut events = Vec::new();
        let mut flushed = Vec::new();
        let mut st = lock_recover(&self.state);
        let kind = st.claim(offer_id, secret, digest, now, &mut events, &mut flushed);
        self.release(st, flushed, |out| self.forward_stored(out), events);
        kind
    }

    /// The write after [`Self::claim`] failed: nothing was typed, so there is no
    /// echo to watch for and no rejection to expect — what the mask held back
    /// is forwarded. The prompt instance stays consumed — a dead channel is not
    /// worth a second try.
    pub(crate) fn abort_fill(&self) {
        let mut st = lock_recover(&self.state);
        let flushed = st.echo.take().map(EchoMask::into_held).unwrap_or_default();
        st.last_fill = None;
        self.release(st, flushed, |out| self.forward_stored(out), Vec::new());
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

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
        let g = FillGuard::new(
            "v".into(),
            "pw".into(),
            ALICE.into(),
            true,
            Zeroizing::new([7; 32]),
            events.clone(),
        );
        (g, events)
    }

    /// Feeds one chunk and returns what was forwarded.
    fn feed(g: &FillGuard, data: &[u8], now: Instant) -> Vec<u8> {
        let mut out = Vec::new();
        g.on_output(data.to_vec(), now, |d| out = d);
        out
    }

    /// The id of the live offer, from the last `Offered` event.
    fn offer_id(ev: &Events) -> u64 {
        ev.0.lock()
            .unwrap()
            .iter()
            .rev()
            .find_map(|e| match e {
                FillEvent::Offered { offer_id, .. } => Some(*offer_id),
                FillEvent::Withdrawn { .. } | FillEvent::Rejected | FillEvent::Echoed => None,
            })
            .expect("an offer")
    }

    /// A guard whose bare `Password:` prompt was just filled with `secret`.
    fn filled(secret: &str) -> (FillGuard, Arc<Events>, Instant) {
        let (g, ev) = guard();
        let t0 = Instant::now();
        feed(&g, b"Password: ", t0);
        g.claim(offer_id(&ev), secret, t0).unwrap();
        ev.take();
        (g, ev, t0)
    }

    const SUDO: &[u8] = b"$ sudo su\r\n[sudo] password for alice: ";
    const AGAIN: &[u8] = b"\r\nSorry, try again.\r\n[sudo] password for alice: ";

    fn offered_sudo(offer_id: u64, rejected_before: bool) -> FillEvent {
        FillEvent::Offered {
            kind: FillPromptKind::Sudo,
            offer_id,
            user: Some(ALICE.into()),
            rejected_before,
        }
    }

    /// A sudo prompt filled with `secret`, Enter pressed, and the prompt back
    /// inside the window: the password is remembered as rejected.
    fn rejected(secret: &str) -> (FillGuard, Arc<Events>, Instant) {
        let (g, ev) = guard();
        let t0 = Instant::now();
        feed(&g, SUDO, t0);
        g.claim(offer_id(&ev), secret, t0).unwrap();
        g.note_input(b"\r", t0);
        feed(&g, AGAIN, t0 + Duration::from_secs(2));
        feed(
            &g,
            b"\r\nsudo: 3 incorrect password attempts\r\n$ ",
            t0 + Duration::from_secs(4),
        );
        ev.take();
        (g, ev, t0)
    }

    #[test]
    fn recognised_prompts_are_classified() {
        let cases: [(&str, FillPromptKind); 14] = [
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
            ("\rPassword: ", FillPromptKind::Generic),
        ];
        for (line, kind) in cases {
            assert_eq!(
                classify_tail(line.as_bytes(), ALICE, true),
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
            assert_eq!(
                classify_tail(line.as_bytes(), ALICE, true),
                None,
                "{line:?}"
            );
        }
    }

    #[test]
    fn a_prompt_drawn_over_other_text_with_a_carriage_return_is_not_classified() {
        for tail in [
            &b"(bob@evil) \rPassword: "[..],
            b"bob@evil's password: \r[sudo] password for alice: ",
        ] {
            assert_eq!(classify_tail(tail, ALICE, true), None, "{tail:?}");
        }
    }

    #[test]
    fn bare_prompts_are_classified_only_when_allowed() {
        assert_eq!(classify_tail(b"Password: ", ALICE, false), None);
        assert_eq!(
            classify_tail(b"[sudo] password for alice: ", ALICE, false),
            Some(FillPromptKind::Sudo)
        );
    }

    #[test]
    fn a_prompt_wrapped_in_escape_sequences_is_recognised() {
        let tail = b"\x1b]0;alice@h\x07\x1b[1m[sudo] password for alice:\x1b[0m ";
        assert_eq!(classify_tail(tail, ALICE, true), Some(FillPromptKind::Sudo));
    }

    #[test]
    fn a_prompt_followed_by_a_newline_is_not_waiting() {
        assert_eq!(classify_tail(b"Password: \r\n", ALICE, true), None);
    }

    #[test]
    fn an_overlong_line_is_not_a_prompt() {
        let line = format!("[sudo] {} for alice:", "x".repeat(PROMPT_MAX_CHARS));
        assert_eq!(classify_tail(line.as_bytes(), ALICE, true), None);
    }

    #[test]
    fn a_prompt_is_offered_once() {
        let (g, ev) = guard();
        let now = Instant::now();
        feed(&g, b"$ sudo su\r\n[sudo] password for ", now);
        feed(&g, b"alice: ", now);
        feed(&g, b"", now);
        assert_eq!(ev.take(), vec![offered_sudo(1, false)]);
    }

    #[test]
    fn output_moving_on_withdraws_the_offer() {
        let (g, ev) = guard();
        let now = Instant::now();
        feed(&g, SUDO, now);
        feed(&g, b"\r\nsudo: timed out\r\n$ ", now);
        assert_eq!(
            ev.take(),
            vec![offered_sudo(1, false), FillEvent::Withdrawn { offer_id: 1 }]
        );
    }

    #[test]
    fn typing_withdraws_the_offer_and_refuses_a_fill() {
        let (g, ev) = guard();
        let now = Instant::now();
        feed(&g, SUDO, now);
        g.note_input(b"h", now);
        assert_eq!(
            ev.take(),
            vec![offered_sudo(1, false), FillEvent::Withdrawn { offer_id: 1 }]
        );
        assert!(g.claim(1, "s3cret", now).is_err());
    }

    #[test]
    fn a_fill_without_a_prompt_is_refused() {
        let (g, _ev) = guard();
        let now = Instant::now();
        feed(&g, b"alice@h:~$ ", now);
        assert!(g.check_offer(1).is_err());
        assert!(g.claim(1, "s3cret", now).is_err());
    }

    #[test]
    fn a_second_fill_of_the_same_prompt_is_refused() {
        let (g, ev) = guard();
        let now = Instant::now();
        feed(&g, SUDO, now);
        let id = offer_id(&ev);
        assert_eq!(g.claim(id, "s3cret", now).unwrap(), FillPromptKind::Sudo);
        assert!(g.claim(id, "s3cret", now).is_err());
    }

    #[test]
    fn a_fill_naming_a_superseded_offer_is_refused() {
        let (g, ev) = guard();
        let t = Instant::now();
        feed(&g, b"[sudo] password for alice: ", t);
        let sudo = offer_id(&ev);
        // The user agreed to sudo; by the time the fill arrives, ftp is asking.
        feed(&g, b"\r\nsudo: timed out\r\n$ ftp x\r\nPassword:", t);
        assert!(g.check_offer(sudo).is_err());
        assert!(g.claim(sudo, "s", t).is_err());
    }

    #[test]
    fn the_prompt_returning_inside_the_window_is_rejected() {
        let (g, ev) = guard();
        let t0 = Instant::now();
        feed(&g, SUDO, t0);
        g.claim(offer_id(&ev), "s3cret", t0).unwrap();
        g.note_input(b"\r", t0);
        ev.take();
        // The answer and the re-prompt in a single read.
        feed(&g, AGAIN, t0 + Duration::from_secs(2));
        assert_eq!(ev.take(), vec![FillEvent::Rejected]);
        assert!(g.check_offer(2).is_err());
    }

    #[test]
    fn a_third_prompt_inside_the_window_stays_unoffered() {
        let (g, ev) = guard();
        let t0 = Instant::now();
        feed(&g, SUDO, t0);
        g.claim(offer_id(&ev), "s3cret", t0).unwrap();
        feed(&g, AGAIN, t0 + Duration::from_secs(2));
        ev.take();
        feed(&g, AGAIN, t0 + Duration::from_secs(5));
        assert_eq!(ev.take(), vec![]);
    }

    #[test]
    fn the_prompt_returning_after_the_window_is_offered_again() {
        let (g, ev) = guard();
        let t0 = Instant::now();
        feed(&g, SUDO, t0);
        g.claim(offer_id(&ev), "s3cret", t0).unwrap();
        ev.take();
        feed(&g, b"\r\n$ ", t0 + Duration::from_secs(1));
        feed(&g, SUDO, t0 + REJECT_WINDOW + Duration::from_secs(1));
        assert_eq!(ev.take(), vec![offered_sudo(2, false)]);
    }

    #[test]
    fn a_prompt_after_the_user_typed_a_new_command_is_not_a_rejection() {
        let (g, ev, t0) = filled("ok");
        g.note_input(b"\r", t0);
        feed(&g, b"\r\nuid=0(root)\r\n$ ", t0 + Duration::from_secs(1));
        g.note_input(b"su -c id\r", t0 + Duration::from_secs(2));
        feed(&g, b"su -c id\r\nPassword: ", t0 + Duration::from_secs(3));
        assert!(!ev.take().contains(&FillEvent::Rejected));
        assert!(g.check_offer(2).is_ok());
    }

    #[test]
    fn a_rejected_password_is_never_typed_again_on_the_session() {
        let (g, ev, t0) = rejected("wrong");
        // A minute later, a fresh sudo: offered, flagged, and the same password refused.
        feed(&g, SUDO, t0 + Duration::from_secs(60));
        let id = offer_id(&ev);
        assert_eq!(ev.take(), vec![offered_sudo(id, true)]);
        assert!(g.claim(id, "wrong", t0 + Duration::from_secs(61)).is_err());
        assert!(
            g.check_offer(id).is_ok(),
            "the prompt is still the user's to answer"
        );
    }

    #[test]
    fn an_edited_password_may_be_filled_after_a_rejection() {
        let (g, ev, t0) = rejected("wrong");
        feed(&g, SUDO, t0 + Duration::from_secs(60));
        let id = offer_id(&ev);
        assert!(g.claim(id, "right", t0 + Duration::from_secs(61)).is_ok());
    }

    #[test]
    fn a_failed_write_disarms_the_mask_and_the_rejection_check() {
        let (g, ev, t0) = filled("s3cret");
        g.abort_fill();
        assert_eq!(
            feed(&g, b"s3cret\r\nPassword: ", t0),
            b"s3cret\r\nPassword: "
        );
        let events = ev.take();
        assert!(!events.contains(&FillEvent::Echoed), "{events:?}");
        assert!(!events.contains(&FillEvent::Rejected), "{events:?}");
        assert!(
            g.claim(1, "s3cret", t0).is_err(),
            "the aborted offer stays spent"
        );
    }

    #[test]
    fn a_focus_report_leaves_the_offer_alone() {
        let (g, ev) = guard();
        let now = Instant::now();
        feed(&g, SUDO, now);
        let id = offer_id(&ev);
        g.note_input(b"\x1b[O", now);
        g.note_input(b"\x1b[I", now);
        assert_eq!(ev.take(), vec![offered_sudo(id, false)]);
        assert!(g.check_offer(id).is_ok());
    }

    #[test]
    fn a_failed_write_forwards_what_the_mask_held_back() {
        let (g, _ev, t0) = filled("s3cret");
        let forwarded = Arc::new(Mutex::new(Vec::new()));
        let f = forwarded.clone();
        g.set_forward(Box::new(move |d| f.lock().unwrap().extend(d)));
        assert_eq!(feed(&g, b"ls s3", t0), b"ls ");
        g.abort_fill();
        assert_eq!(*forwarded.lock().unwrap(), b"s3");
    }

    #[test]
    fn an_echo_in_one_chunk_is_masked() {
        let (g, ev, t0) = filled("pässword");
        let out = feed(&g, "pässword\r\n".as_bytes(), t0);
        assert_eq!(out, b"********\r\n");
        assert_eq!(ev.take(), vec![FillEvent::Echoed]);
    }

    #[test]
    fn every_echo_is_reported() {
        let (g, ev, t0) = filled("s3cret");
        feed(&g, b"s3cret\r\n", t0);
        feed(&g, b"s3cret", t0 + Duration::from_secs(1));
        assert_eq!(ev.take(), vec![FillEvent::Echoed, FillEvent::Echoed]);
    }

    #[test]
    fn an_echo_split_across_chunks_is_masked() {
        let (g, _ev, t0) = filled("s3cret");
        let first = feed(&g, b"s3c", t0);
        let second = feed(&g, b"ret\r\n", t0);
        assert_eq!([first, second].concat(), b"******\r\n");
    }

    #[test]
    fn an_echo_with_escape_sequences_between_its_characters_is_masked() {
        let (g, ev, t0) = filled("pa\"ss word");
        let out = feed(&g, b"pa\x1b[33m\"ss word\x1b]0;t\x07\x1b[0m", t0);
        assert_eq!(out, b"**\x1b[33m********\x1b]0;t\x07\x1b[0m");
        assert_eq!(ev.take(), vec![FillEvent::Echoed]);
    }

    #[test]
    fn an_echo_wrapped_at_the_margin_is_masked() {
        let (g, _ev, t0) = filled("hunter2!");
        let first = feed(&g, b"hunt\r", t0);
        let second = feed(&g, b"\ner2!", t0);
        assert_eq!([first, second].concat(), b"****\r\n****");
    }

    #[test]
    fn a_possible_echo_longer_than_the_hold_bound_is_flushed() {
        let (g, _ev, t0) = filled("ab");
        let mut chunk = b"a".to_vec();
        chunk.extend(std::iter::repeat_n(b'\n', HOLD_MAX));
        assert_eq!(feed(&g, &chunk, t0), chunk);
    }

    #[test]
    fn output_without_an_echo_passes_through_unchanged() {
        let (g, ev, t0) = filled("s3cret");
        assert_eq!(feed(&g, b"\r\nroot@h:~# ", t0), b"\r\nroot@h:~# ");
        assert_eq!(ev.take(), vec![]);
    }

    #[test]
    fn the_end_of_the_window_flushes_held_bytes() {
        let (g, _ev, t0) = filled("s3cret");
        assert_eq!(feed(&g, b"ls s3", t0), b"ls ");
        let later = t0 + ECHO_WINDOW + Duration::from_secs(1);
        assert_eq!(feed(&g, b"\r\n", later), b"s3\r\n");
    }

    #[test]
    fn typing_after_a_fill_closes_the_echo_window_soon() {
        let (g, _ev, t0) = filled("s3cret");
        g.note_input(b"\r", t0 + Duration::from_secs(1));
        let after = t0 + Duration::from_secs(1) + ECHO_AFTER_INPUT;
        assert_eq!(
            feed(&g, b"s3cret", after),
            b"******",
            "the last masked chunk"
        );
        assert_eq!(feed(&g, b"s3cret", after), b"s3cret");
    }

    #[test]
    fn an_echo_kills_the_line() {
        let (g, _ev, t0) = filled("s3cret");
        let kills = Arc::new(AtomicUsize::new(0));
        let k = kills.clone();
        g.set_line_kill(Box::new(move || {
            k.fetch_add(1, Ordering::SeqCst);
        }));
        feed(&g, b"s3cret", t0);
        assert_eq!(kills.load(Ordering::SeqCst), 1);
    }
}
