//! Guided key rotation, the part every client shares: the plan (which machines
//! get the candidate key, which hosts merely follow, which are out of scope),
//! the per-target state machine deploy → verify → remove → confirm, what each
//! step runs on the machine and when it counts as passed, and a driver that
//! runs the steps through [`Core::ssh_exec_multi`]. The app's rotation dialog
//! and `unissh keys rotation` both drive it; the staged candidate itself lives
//! in [`crate::key_rotation`].
//!
//! The safety rule lives here: `remove` (dropping the old public key from a
//! machine) is reachable only from a passed `verify` (a login with the
//! candidate key) on that same machine within the same run, so no machine is
//! ever left accepting neither key. And a machine is called switched only after
//! `confirm`: a login with the OLD key was attempted and refused. A line gone
//! from `~/.ssh/authorized_keys` does not prove that — sshd may accept the key
//! from another file, a command or a CA.
//!
//! Nothing here touches private key material: the steps carry public-key
//! lines and log in through the embedded agent by key item id.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::key_usage::{auth_uses, logs_in_with};
use crate::{
    AuthMethod, ConnectionProfile, Core, FfiError, JumpHost, KeyLoginFailure, MultiExecResult,
    MultiExecTarget, ProfileAuth, ProxyConfig, ProxyKind,
};

// ---------- remote authorized_keys edits ----------
//
// Shell commands run over a host's exec channel. One builder per edit so the
// copy-key dialog and the guided rotation run the exact same command.
//
// Each command is handed to `sh -c`: the exec channel runs it through the
// account's login shell, and a fish or csh login shell would not parse POSIX
// `{ …; }`, `$?` or `$(…)`. That login shell still reads the whole line first,
// and csh/tcsh expand `!word` as history even inside single quotes — so the
// scripts never write `!` in front of anything but a blank. The awk programs
// stick to what POSIX awk has (BSD awk, mawk, gawk and busybox all run them).

/// Exit status of [`authorized_keys_remove_command`] when the old key's plain
/// lines are gone but its blob is still on a line sshd reads, in a form this
/// command does not touch: a line with an options prefix (`from=…`,
/// `command=…`), which still authorizes the key, or the same blob under
/// another key type name. Nothing else was changed; what is left has to be
/// looked at and removed by hand.
pub const REMOVE_EXIT_STILL_PRESENT: i32 = 3;
/// Exit status of [`authorized_keys_remove_command`] when there is no
/// `authorized_keys`.
pub const REMOVE_EXIT_NO_FILE: i32 = 4;

/// Single-quotes a string for a POSIX shell.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Runs `script` under POSIX sh whatever the login shell is.
fn posix(script: &str) -> String {
    format!("sh -c {}", sh_quote(script))
}

/// A line that is not an OpenSSH public key (`<type> <base64> [comment]`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not an OpenSSH public key line")]
pub struct NotAPublicKey;

/// The `<type>` and `<base64 blob>` of a public-key line, each quoted for the
/// shell. Both are checked against the alphabet OpenSSH writes: they are
/// handed to `awk -v`, which would expand a backslash escape.
fn key_fields(openssh: &str) -> Result<(String, String), NotAPublicKey> {
    let mut fields = openssh.split_whitespace();
    let (Some(kind), Some(blob)) = (fields.next(), fields.next()) else {
        return Err(NotAPublicKey);
    };
    let kind_ok = kind
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '@' | '.' | '_' | '+' | '-'));
    let blob_ok = blob
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='));
    if !kind_ok || !blob_ok {
        return Err(NotAPublicKey);
    }
    Ok((sh_quote(kind), sh_quote(blob)))
}

/// Idempotent ssh-copy-id: appends the key only if an identical line is not
/// already there. Running it twice leaves one line. A file whose last line has
/// no newline gets one first, as ssh-copy-id does — otherwise the key would be
/// glued onto that line, breaking it and installing nothing.
///
/// `~/.ssh` and the file get the permissions sshd's `StrictModes` requires
/// only when this command creates them: an existing directory or file keeps
/// the mode its owner chose. The append goes through `>>`, so a symlinked
/// `authorized_keys` stays a symlink and its target is what grows.
pub fn authorized_keys_append_command(openssh: &str) -> String {
    let q = sh_quote(openssh.trim());
    posix(
        &[
            "d=~/.ssh; f=$d/authorized_keys; ",
            r#"{ [ -d "$d" ] || { mkdir -p "$d" && chmod 700 "$d"; }; } && "#,
            r#"{ [ -e "$f" ] || { touch "$f" && chmod 600 "$f"; }; } && "#,
            "{ grep -qxF ",
            &q,
            r#" "$f" || { "#,
            r#"{ [ ! -s "$f" ] || [ -z "$(tail -c1 "$f")" ] || echo >> "$f"; } && "#,
            r"printf '%s\n' ",
            &q,
            r#" >> "$f"; }; }"#,
        ]
        .concat(),
    )
}

/// awk pattern: this line is a plain public-key line for key type `t` and blob
/// `b` — the key type is the first field (no options prefix), the blob the
/// second, whatever comment follows and whether or not the line ends in CR.
const AWK_KEY_LINE: &str = r#"{ k = $2; sub(/\r$/, "", k) } $1 == t && k == b"#;

/// Removes the old key's plain lines from `authorized_keys`, nothing else:
/// every line whose key type and blob are `old_openssh`'s, whatever its
/// trailing comment (ssh-copy-id writes `user@host` there) and line ending (LF
/// or CRLF). A line that authorizes the old key behind an options prefix
/// (`from=…`, `command=…`) is left alone — it was put there deliberately and
/// is reported, see below.
///
/// Refuses unless `keep_openssh` (the key that replaces it) is present as a
/// plain line, so the file can never be left without either key; the filtered
/// copy is checked for it again before it replaces anything. The rewrite is
/// atomic: the copy goes to a temp file beside the real file — created by
/// `cp -p`, so it keeps the original's mode — then `mv` replaces it in one
/// step. A symlinked `authorized_keys` is followed first, so the link stays
/// and its target is what gets rewritten.
///
/// Afterwards, if the old key's base64 blob still appears on any line sshd
/// reads, it exits with [`REMOVE_EXIT_STILL_PRESENT`] rather than claim the
/// key is gone. A comment line (first non-blank character `#`) is not one of
/// those: sshd skips it, so it accepts nothing and may keep the blob. A key
/// that is truly absent is a success, so a rerun converges.
pub fn authorized_keys_remove_command(
    old_openssh: &str,
    keep_openssh: &str,
) -> Result<String, NotAPublicKey> {
    let (o_type, o_blob) = key_fields(old_openssh)?;
    let (k_type, k_blob) = key_fields(keep_openssh)?;
    let no_file = REMOVE_EXIT_NO_FILE.to_string();
    let still_present = REMOVE_EXIT_STILL_PRESENT.to_string();
    Ok(posix(
        &[
            "f=~/.ssh/authorized_keys; ",
            r#"[ -f "$f" ] || { echo 'no ~/.ssh/authorized_keys on this host' >&2; exit "#,
            &no_file,
            "; }; ",
            r#"while [ -L "$f" ]; do "#,
            r#"l=$(readlink "$f") || { echo 'cannot resolve the authorized_keys symlink; old key left in place' >&2; exit 1; }; "#,
            r#"case $l in /*) f=$l ;; *) f=$(dirname "$f")/$l ;; esac; done; "#,
            r#"has() { awk -v t="$1" -v b="$2" '"#,
            AWK_KEY_LINE,
            r#" { found = 1 } END { exit found ? 0 : 1 }' "$3"; }; "#,
            "has ",
            &k_type,
            " ",
            &k_blob,
            r#" "$f" || { echo 'new key is not in authorized_keys; old key left in place' >&2; exit 1; }; "#,
            r#"t=$(mktemp "$f.XXXXXX") || exit 1; "#,
            r#"cp -p "$f" "$t" && "#,
            "awk -v t=",
            &o_type,
            " -v b=",
            &o_blob,
            " '",
            AWK_KEY_LINE,
            r#" { next } { print }' "$f" > "$t" && "#,
            "has ",
            &k_type,
            " ",
            &k_blob,
            r#" "$t" && mv -f "$t" "$f" || { rm -f "$t"; exit 1; }; "#,
            "if awk -v b=",
            &o_blob,
            r#" '/^[ \t]*#/ { next } index($0, b) { found = 1 } END { exit found ? 0 : 1 }' "$f"; then "#,
            "echo 'old key data still in authorized_keys: a line with options, or the same key under another key type' >&2; exit ",
            &still_present,
            "; fi",
        ]
        .concat(),
    ))
}

// ---------- the plan ----------

/// One step of a target's rotation, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RotationStep {
    /// Append the candidate's public key, logged in with the old key.
    Deploy,
    /// A key-only login with the candidate.
    Verify,
    /// Drop the old key's line, logged in with the candidate.
    Remove,
    /// A key-only login with the old key, which must be refused.
    Confirm,
}

/// Every step, in order.
pub const ROTATION_STEPS: [RotationStep; 4] = [
    RotationStep::Deploy,
    RotationStep::Verify,
    RotationStep::Remove,
    RotationStep::Confirm,
];

impl RotationStep {
    /// The step before this one, `None` before the first.
    pub const fn previous(self) -> Option<Self> {
        match self {
            Self::Deploy => None,
            Self::Verify => Some(Self::Deploy),
            Self::Remove => Some(Self::Verify),
            Self::Confirm => Some(Self::Remove),
        }
    }

    /// The step after this one, `None` after the last.
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::Deploy => Some(Self::Verify),
            Self::Verify => Some(Self::Remove),
            Self::Remove => Some(Self::Confirm),
            Self::Confirm => None,
        }
    }

    /// Its name in lower case (`deploy`), for messages.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Deploy => "deploy",
            Self::Verify => "verify",
            Self::Remove => "remove",
            Self::Confirm => "confirm",
        }
    }
}

/// Why a host is out of a rotation's scope: it does not log in with a vault key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationSkipReason {
    /// Its login is a personal identity, which the rotation does not own.
    Personal,
    /// Its key lives in the operating system's agent, not the vault.
    SystemAgent,
    /// It logs in with a password (stored or asked).
    Password,
}

/// A machine whose `authorized_keys` must learn the candidate key: one SSH
/// login (user@host:port, reached over one route) that authenticates with the
/// rotated key.
#[derive(Clone)]
pub struct RotationTarget {
    /// The login and the route to it: `user@host:port` (host lower-cased),
    /// then the hops and the proxy in front of it when there are any. The
    /// route is part of the identity because an address means nothing without
    /// it: `root@10.0.0.5` behind two different bastions is two machines.
    pub id: String,
    /// The saved profile when the target is a host of its own, else `None` (a
    /// bare inline jump hop, which has no profile).
    pub profile: Option<ConnectionProfile>,
    /// Address.
    pub host: String,
    /// Port.
    pub port: u16,
    /// User.
    pub user: String,
    /// The hops in front of it: the profile's own chain, or for a hop the
    /// chain of the host it came from, up to that hop.
    pub jumps: Vec<JumpHost>,
    /// The proxy the first dial of that route goes through (its own, else the
    /// proxy of a saved bastion used as hop #1).
    pub proxy: Option<ProxyConfig>,
    /// `jumps` as the logins they land on (a saved bastion resolved), for display.
    pub route: Vec<String>,
    /// For a hop: the host whose chain it was found in.
    pub via: Option<ConnectionProfile>,
}

impl RotationTarget {
    /// What the target is called: its host's label, or `user@host[:port]` for
    /// a bare hop.
    pub fn label(&self) -> String {
        match &self.profile {
            Some(p) => p.label.clone(),
            None if self.port == 22 => format!("{}@{}", self.user, self.host),
            None => format!("{}@{}:{}", self.user, self.host, self.port),
        }
    }
}

/// A host that only hops with the key: nothing to deploy on it, it starts
/// using the new key when the hop target(s) it goes through switch.
#[derive(Clone)]
pub struct RotationDependent {
    /// The host.
    pub host: ConnectionProfile,
    /// The targets it goes through.
    pub target_ids: Vec<String>,
}

/// A host the rotation leaves alone, and why.
#[derive(Clone)]
pub struct RotationSkip {
    /// The host.
    pub host: ConnectionProfile,
    /// Why.
    pub reason: RotationSkipReason,
}

/// Where the candidate's public key has to go for a rotation of one key.
#[derive(Clone)]
pub struct RotationPlan {
    /// The vault's hosts the plan was made from — hop refs resolve against them.
    hosts: Vec<ConnectionProfile>,
    /// The vault ids those hosts' references name that are this vault.
    same_vault: BTreeSet<String>,
    /// The vault.
    pub vault_id: String,
    /// The rotated key item.
    pub key_item_id: String,
    /// The machines to switch, direct hosts first.
    pub targets: Vec<RotationTarget>,
    /// Hosts that only hop with the key.
    pub dependents: Vec<RotationDependent>,
    /// Hosts out of scope.
    pub skipped: Vec<RotationSkip>,
}

/// How a plan reads the vault's hosts: which of them use the rotated key and
/// where each hop lands. The key-use rule is the core's one answer, shared
/// with `Core::key_usage` (see [`crate::key_usage`]): a host logs in with the
/// key; an inline hop authenticates with it, naming this vault; a `hop_ref` hop
/// points into this vault (by any id that names it) at a saved profile whose
/// own login is the key — the core resolves it by vault + uid and logs in with
/// THAT profile's auth, so a ref hop's inline auth is a placeholder and is
/// ignored. `hosts` are the vault's own.
struct Routes<'h> {
    by_uid: HashMap<&'h str, &'h ConnectionProfile>,
    same_vault: &'h BTreeSet<String>,
    key_item_id: &'h str,
}

impl<'h> Routes<'h> {
    fn new(
        hosts: &'h [ConnectionProfile],
        same_vault: &'h BTreeSet<String>,
        key_item_id: &'h str,
    ) -> Self {
        // A uid listed twice resolves to its last profile, as the app's map does.
        let by_uid = hosts.iter().map(|h| (h.uid.as_str(), h)).collect();
        Self {
            by_uid,
            same_vault,
            key_item_id,
        }
    }

    fn of(plan: &'h RotationPlan) -> Self {
        Self::new(&plan.hosts, &plan.same_vault, &plan.key_item_id)
    }

    fn is_this_vault(&self, vault_id: &str) -> bool {
        self.same_vault.contains(vault_id)
    }

    fn uses_key(&self, h: &ConnectionProfile) -> bool {
        logs_in_with(&h.auth, self.key_item_id)
    }

    /// The saved profile a ref hop resolves to, when it is in this vault.
    fn ref_profile(&self, j: &JumpHost) -> Option<&'h ConnectionProfile> {
        let r = j.hop_ref.as_ref()?;
        if !self.is_this_vault(&r.vault_id) {
            return None;
        }
        self.by_uid.get(r.profile_uid.as_str()).copied()
    }

    fn hop_uses_key(&self, j: &JumpHost) -> bool {
        if j.hop_ref.is_some() {
            return self.ref_profile(j).is_some_and(|r| self.uses_key(r));
        }
        auth_uses(&j.auth, self.key_item_id, &|v: &str| self.is_this_vault(v))
    }

    /// The machine a hop lands on. A `hop_ref` resolves to the saved profile's
    /// endpoint, so a ref hop and an inline hop to the same login are one hop;
    /// a ref this vault cannot resolve is identified by the reference itself.
    fn hop_endpoint(&self, j: &JumpHost) -> String {
        if let Some(r) = self.ref_profile(j) {
            return endpoint_id(&r.user, &r.host, r.port);
        }
        match &j.hop_ref {
            Some(r) => format!("ref:{}/{}", r.vault_id, r.profile_uid),
            None => endpoint_id(&j.user, &j.host, j.port),
        }
    }

    /// The proxy a connection's first TCP dial goes through: its own, else the
    /// proxy of a saved bastion used as hop #1. Mirrors `connect_with_options`
    /// in `lib.rs` — keep in step.
    fn first_dial_proxy(
        &self,
        jumps: &[JumpHost],
        proxy: Option<&ProxyConfig>,
    ) -> Option<ProxyConfig> {
        proxy
            .cloned()
            .or_else(|| self.ref_profile(jumps.first()?)?.proxy.clone())
    }

    /// Identity of the login `endpoint` reached through `jumps` behind `proxy`
    /// (the first-dial proxy). No route at all is just the endpoint.
    fn target_id(
        &self,
        endpoint: String,
        jumps: &[JumpHost],
        proxy: Option<&ProxyConfig>,
    ) -> String {
        let mut id = endpoint;
        if !jumps.is_empty() {
            let hops: Vec<String> = jumps.iter().map(|j| self.hop_endpoint(j)).collect();
            id.push_str(" via ");
            id.push_str(&hops.join(" > "));
        }
        if let Some(p) = proxy {
            let user = p
                .username
                .as_deref()
                .filter(|u| !u.is_empty())
                .map(|u| format!("{u}@"))
                .unwrap_or_default();
            id.push_str(&format!(
                " proxy {}://{user}{}:{}",
                proxy_scheme(p.kind),
                p.host.to_lowercase(),
                p.port
            ));
        }
        id
    }

    /// Identity of hop `i` of the chain `jumps` behind first-dial `proxy`:
    /// that hop's endpoint, reached through the hops before it.
    fn hop_target_id(
        &self,
        jumps: &[JumpHost],
        proxy: Option<&ProxyConfig>,
        i: usize,
    ) -> Option<String> {
        let hop = jumps.get(i)?;
        Some(self.target_id(self.hop_endpoint(hop), jumps.get(..i)?, proxy))
    }
}

const fn proxy_scheme(kind: ProxyKind) -> &'static str {
    match kind {
        ProxyKind::Http => "http",
        ProxyKind::Socks4 => "socks4",
        ProxyKind::Socks5 => "socks5",
    }
}

fn endpoint_id(user: &str, host: &str, port: u16) -> String {
    format!("{user}@{}:{port}", host.to_lowercase())
}

/// Where the candidate's public key has to go for a rotation of `key_item_id`.
///
/// The key must be authorized on the machine that authenticates with it:
///  - a host logging in with the key → the host itself, over its own chain;
///  - a jump hop using the key (inline, or a `hop_ref` to a saved bastion that
///    logs in with it) → that hop's endpoint, reached through the chain of the
///    host it was found in up to (not including) the hop.
///
/// Targets are deduplicated by login AND route (see [`RotationTarget::id`]),
/// direct hosts first: two hosts with the same user@host:port behind different
/// bastions or proxies are two machines and both get the key, while a saved
/// bastion and a hop that reaches it the same way are one. The same machine
/// listed twice over two routes is harmless — every step is idempotent — where
/// a machine dropped from the plan would be locked out. Hosts that only hop
/// with the key become dependents of the hop targets they go through. Hosts
/// not using the key whose login is Personal, the system agent or a password
/// are listed as skipped with that reason.
///
/// A reference names this vault only by `vault_id` itself here;
/// [`Core::plan_key_rotation`] also accepts every other id that names it.
pub fn plan_rotation(
    hosts: Vec<ConnectionProfile>,
    vault_id: &str,
    key_item_id: &str,
) -> RotationPlan {
    plan_rotation_in(
        hosts,
        vault_id,
        key_item_id,
        BTreeSet::from([vault_id.to_owned()]),
    )
}

/// [`plan_rotation`], a reference naming this vault by any id in `same_vault`.
fn plan_rotation_in(
    hosts: Vec<ConnectionProfile>,
    vault_id: &str,
    key_item_id: &str,
    same_vault: BTreeSet<String>,
) -> RotationPlan {
    let (targets, dependents, skipped) = {
        let m = Routes::new(&hosts, &same_vault, key_item_id);
        let mut targets: Vec<RotationTarget> = Vec::new();
        let mut add = |t: RotationTarget| {
            if !targets.iter().any(|x| x.id == t.id) {
                targets.push(t);
            }
        };
        for h in hosts.iter().filter(|h| m.uses_key(h)) {
            let proxy = m.first_dial_proxy(&h.jumps, h.proxy.as_ref());
            add(RotationTarget {
                id: m.target_id(
                    endpoint_id(&h.user, &h.host, h.port),
                    &h.jumps,
                    proxy.as_ref(),
                ),
                profile: Some(h.clone()),
                host: h.host.clone(),
                port: h.port,
                user: h.user.clone(),
                jumps: h.jumps.clone(),
                proxy,
                route: h.jumps.iter().map(|j| m.hop_endpoint(j)).collect(),
                via: None,
            });
        }

        let mut dependents = Vec::new();
        let mut skipped = Vec::new();
        for h in &hosts {
            let mut ids: Vec<String> = Vec::new();
            let proxy = m.first_dial_proxy(&h.jumps, h.proxy.as_ref());
            for (i, j) in h.jumps.iter().enumerate() {
                if !m.hop_uses_key(j) {
                    continue;
                }
                let Some(id) = m.hop_target_id(&h.jumps, proxy.as_ref(), i) else {
                    continue;
                };
                let (host, port, user) = match m.ref_profile(j) {
                    Some(r) => (r.host.clone(), r.port, r.user.clone()),
                    None => (j.host.clone(), j.port, j.user.clone()),
                };
                let jumps: Vec<JumpHost> = h.jumps.iter().take(i).cloned().collect();
                let route = jumps.iter().map(|b| m.hop_endpoint(b)).collect();
                add(RotationTarget {
                    id: id.clone(),
                    profile: None,
                    host,
                    port,
                    user,
                    jumps,
                    proxy: proxy.clone(),
                    route,
                    via: Some(h.clone()),
                });
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
            if m.uses_key(h) {
                continue;
            }
            if !ids.is_empty() {
                dependents.push(RotationDependent {
                    host: h.clone(),
                    target_ids: ids,
                });
                continue;
            }
            let reason = match &h.auth {
                ProfileAuth::Personal => Some(RotationSkipReason::Personal),
                ProfileAuth::SystemAgent { .. } => Some(RotationSkipReason::SystemAgent),
                ProfileAuth::VaultPassword { .. } | ProfileAuth::PromptPassword => {
                    Some(RotationSkipReason::Password)
                }
                ProfileAuth::Key { .. } => None,
            };
            if let Some(reason) = reason {
                skipped.push(RotationSkip {
                    host: h.clone(),
                    reason,
                });
            }
        }
        (targets, dependents, skipped)
    };
    RotationPlan {
        hosts,
        same_vault,
        vault_id: vault_id.to_owned(),
        key_item_id: key_item_id.to_owned(),
        targets,
        dependents,
        skipped,
    }
}

impl RotationPlan {
    /// The target with id `id`.
    pub fn target(&self, id: &str) -> Option<&RotationTarget> {
        self.targets.iter().find(|t| t.id == id)
    }

    /// Whether two targets of the plan are the same login reached over
    /// different routes. They may well be one machine (a bastion with two ways
    /// in): each route is then switched and reported on its own, so a route
    /// that fails is listed as not switched although the machine behind it
    /// already is.
    pub fn has_shared_endpoint(&self) -> bool {
        let endpoints: BTreeSet<String> = self
            .targets
            .iter()
            .map(|t| endpoint_id(&t.user, &t.host, t.port))
            .collect();
        endpoints.len() < self.targets.len()
    }

    /// The targets of the plan in front of target `id` as jump hops that use
    /// the rotated key, first hop first: each logs in with the old key until it
    /// has verified, and with the candidate after.
    pub fn key_hops(&self, id: &str) -> Vec<String> {
        let Some(t) = self.target(id) else {
            return Vec::new();
        };
        let m = Routes::of(self);
        t.jumps
            .iter()
            .enumerate()
            .filter(|(_, j)| m.hop_uses_key(j))
            .filter_map(|(i, _)| m.hop_target_id(&t.jumps, t.proxy.as_ref(), i))
            .filter(|hop| self.target(hop).is_some())
            .collect()
    }

    /// The hosts that reach the key only through target `id` as a hop: they
    /// follow it.
    pub fn dependents_of(&self, id: &str) -> Vec<&ConnectionProfile> {
        self.dependents
            .iter()
            .filter(|d| d.target_ids.iter().any(|t| t == id))
            .map(|d| &d.host)
            .collect()
    }
}

// ---------- the run ----------

/// Why a step did not pass. Clients word it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepFailure {
    /// Nothing came back for the target.
    NoResult,
    /// The command ran past its deadline.
    TimedOut,
    /// The connection or the command failed, in its own words.
    Error {
        /// What it said.
        message: String,
    },
    /// The vault locked while the step ran.
    Locked,
    /// Remove: the old key's blob is still in the file ([`REMOVE_EXIT_STILL_PRESENT`]).
    OldKeyStillPresent,
    /// Remove: there is no `~/.ssh/authorized_keys`.
    NoAuthorizedKeys,
    /// Remove: the candidate cannot get a shell without a second factor, and
    /// the old key is still accepted — its line has to be removed by hand.
    RemoveNeedsSecondFactor,
    /// Confirm: the old key still logs in.
    OldKeyStillAccepted,
    /// The old-key login failed for a reason that says nothing about the key.
    OldKeyCheckFailed {
        /// What the login failed with, when anything was said.
        message: Option<String>,
    },
}

impl StepFailure {
    /// The failure in English, for a terminal.
    pub fn describe(&self) -> String {
        match self {
            Self::NoResult => "nothing came back from the machine".to_owned(),
            Self::TimedOut => "timed out".to_owned(),
            Self::Error { message } => message.clone(),
            Self::Locked => "the vault locked".to_owned(),
            Self::OldKeyStillPresent => "the old key's data is still in authorized_keys in a form \
                 that is not removed automatically: a line with options (from=…, command=…) or \
                 the same key under another type name — check it and remove it by hand"
                .to_owned(),
            Self::NoAuthorizedKeys => "no ~/.ssh/authorized_keys on this machine".to_owned(),
            Self::RemoveNeedsSecondFactor => "new key accepted; remove the old line by hand \
                 (the machine needs a second factor)"
                .to_owned(),
            Self::OldKeyStillAccepted => "new key works, old key is STILL accepted (not through \
                 ~/.ssh/authorized_keys: authorized_keys2, another AuthorizedKeysFile, \
                 AuthorizedKeysCommand or a CA) — revoke it on the server"
                .to_owned(),
            Self::OldKeyCheckFailed { message } => format!(
                "could not check that the old key is refused: {}",
                message.as_deref().unwrap_or("unknown error")
            ),
        }
    }
}

/// One target's place in a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetState {
    /// Waiting to run `step`.
    Pending {
        /// The next step.
        step: RotationStep,
    },
    /// `step` is in flight.
    Running {
        /// The step in flight.
        step: RotationStep,
    },
    /// `step` failed. Up to `remove` the old key has to be taken as still
    /// authorized: a failed remove either did not rewrite the file at all (the
    /// rewrite is atomic), or removed the plain lines and found the old key's
    /// blob still in the file. A failed `confirm` means the old line is gone
    /// from `~/.ssh/authorized_keys` but the old key was not seen refused.
    Failed {
        /// The step that failed.
        step: RotationStep,
        /// Why.
        failure: StepFailure,
    },
    /// The candidate logs in and the old key was refused.
    Switched,
    /// The run was stopped before this target's old key was removed; the old
    /// key is still authorized (and the candidate too if it got that far).
    KeptOld {
        /// The last step that passed, `None` for none.
        after: Option<RotationStep>,
    },
    /// The run was stopped after the old line was removed and before the old
    /// key was tried: nobody checked that it is refused.
    Unconfirmed,
}

/// Which steps a run takes and on which targets. The app's dialog runs every
/// step on every target; `unissh keys rotation run` stops each target after
/// `verify`, and `finish` starts at `verify` again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunScope {
    /// The step each target starts at.
    pub first: RotationStep,
    /// The last step a target may take; it then waits as pending at the next.
    pub last: RotationStep,
    /// The targets to run, `None` for all of them.
    pub only: Option<BTreeSet<String>>,
}

impl RunScope {
    /// Every step on every target.
    pub const fn full() -> Self {
        Self {
            first: RotationStep::Deploy,
            last: RotationStep::Confirm,
            only: None,
        }
    }
}

/// A run's state: each target's place, and where the candidate was proven.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationRun {
    /// In plan order.
    states: Vec<(String, TargetState)>,
    /// Targets where a login with the candidate key passed in this run. Only
    /// these may run `remove`, and only these are reached with the candidate
    /// as a hop.
    verified: BTreeSet<String>,
    /// Each target's key hops in this run ([`RotationPlan::key_hops`]).
    hops: BTreeMap<String, Vec<String>>,
    cancelled: bool,
    last: RotationStep,
}

/// What a step came to: passed, or why not.
pub type StepOutcome = Result<(), StepFailure>;

/// The state of a target the run stops at, `after` being its last passed
/// step: the old key is still authorized until the remove went through, and
/// merely unchecked from then on.
const fn stopped_at(after: Option<RotationStep>) -> TargetState {
    match after {
        Some(RotationStep::Remove) => TargetState::Unconfirmed,
        Some(RotationStep::Deploy | RotationStep::Verify | RotationStep::Confirm) | None => {
            TargetState::KeptOld { after }
        }
    }
}

/// Whether a target waits for, or runs, its deploy or verify.
const fn at_deploy_or_verify(s: &TargetState) -> bool {
    matches!(
        s,
        TargetState::Pending {
            step: RotationStep::Deploy | RotationStep::Verify
        } | TargetState::Running {
            step: RotationStep::Deploy | RotationStep::Verify
        }
    )
}

/// What finishing the rotation now would leave behind, machine by machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinishOutlook {
    /// No login with the candidate passed here: once the key item holds the
    /// candidate, these machines refuse it — a lockout until they get it.
    pub unproven: Vec<String>,
    /// The candidate logs in here, but the route runs through a jump hop in
    /// `unproven`: once that hop refuses the key, this machine cannot be
    /// reached either — locked out as well.
    pub cut_off: Vec<String>,
    /// The candidate logs in, but the old key was not seen refused: the
    /// machine keeps working and may still accept the old key.
    pub old_not_refused: Vec<String>,
}

impl FinishOutlook {
    /// The machines a finish now locks out: [`Self::unproven`], then
    /// [`Self::cut_off`].
    pub fn locked_out(&self) -> impl Iterator<Item = &String> {
        self.unproven.iter().chain(&self.cut_off)
    }
}

impl RotationRun {
    /// A run of `plan` in `scope`: every chosen target waits for `scope.first`.
    pub fn start(plan: &RotationPlan, scope: &RunScope) -> Self {
        let states: Vec<(String, TargetState)> = plan
            .targets
            .iter()
            .filter(|t| scope.only.as_ref().is_none_or(|o| o.contains(&t.id)))
            .map(|t| (t.id.clone(), TargetState::Pending { step: scope.first }))
            .collect();
        let hops = states
            .iter()
            .map(|(id, _)| {
                let in_run = plan
                    .key_hops(id)
                    .into_iter()
                    .filter(|h| states.iter().any(|(x, _)| x == h))
                    .collect();
                (id.clone(), in_run)
            })
            .collect();
        Self {
            states,
            verified: BTreeSet::new(),
            hops,
            cancelled: false,
            last: scope.last,
        }
    }

    /// Each target of the run and its state, in plan order.
    pub fn states(&self) -> impl Iterator<Item = (&str, &TargetState)> {
        self.states.iter().map(|(id, s)| (id.as_str(), s))
    }

    /// Target `id`'s state, `None` when it is not in the run.
    pub fn state(&self, id: &str) -> Option<&TargetState> {
        self.states.iter().find(|(x, _)| x == id).map(|(_, s)| s)
    }

    /// Whether a login with the candidate passed on target `id` in this run.
    pub fn is_verified(&self, id: &str) -> bool {
        self.verified.contains(id)
    }

    /// The targets the candidate was proven on.
    pub const fn verified(&self) -> &BTreeSet<String> {
        &self.verified
    }

    /// Whether the run was stopped.
    pub const fn cancelled(&self) -> bool {
        self.cancelled
    }

    /// Target `id`'s key hops in this run.
    fn hops_of(&self, id: &str) -> &[String] {
        self.hops.get(id).map(Vec::as_slice).unwrap_or_default()
    }

    fn set(&mut self, id: &str, state: TargetState) {
        if let Some((_, s)) = self.states.iter_mut().find(|(x, _)| x == id) {
            *s = state;
        }
    }

    /// Steps that may start now. None once cancelled, and none past the
    /// scope's last step. Removes never overlap a deploy or verify: those may
    /// route through another target as a jump hop with the OLD key, which a
    /// concurrent remove would pull from under them. So removes wait until no
    /// deploy/verify is waiting or in flight, and a deploy/verify waits while
    /// a remove is in flight. A remove on a target also waits while any step
    /// runs through it as a jump hop: that step may have set out with the old
    /// key on it. A deploy/verify of a target waits while one of its key hops
    /// is still at deploy/verify: once the hop has verified the step goes
    /// through it with the candidate — a hop an earlier run already moved off
    /// the old key can be passed no other way. A confirm starts whenever it is
    /// due: its hops are either verified (and use the candidate) or have not
    /// reached remove.
    pub fn startable(&self) -> Vec<(String, RotationStep)> {
        if self.cancelled {
            return Vec::new();
        }
        let early = self.states.iter().any(|(_, s)| at_deploy_or_verify(s));
        let hop_early = |id: &str| {
            self.hops_of(id)
                .iter()
                .any(|h| self.state(h).is_some_and(at_deploy_or_verify))
        };
        let routed_through = |id: &str| {
            self.states.iter().any(|(t, s)| {
                matches!(s, TargetState::Running { .. })
                    && self.hops_of(t.as_str()).iter().any(|h| h == id)
            })
        };
        let removing = self.states.iter().any(|(_, s)| {
            matches!(
                s,
                TargetState::Running {
                    step: RotationStep::Remove
                }
            )
        });
        self.states
            .iter()
            .filter_map(|(id, s)| {
                let TargetState::Pending { step } = s else {
                    return None;
                };
                if *step > self.last {
                    return None;
                }
                let ok = match step {
                    RotationStep::Remove => {
                        !early && self.verified.contains(id) && !routed_through(id)
                    }
                    RotationStep::Confirm => true,
                    RotationStep::Deploy | RotationStep::Verify => !removing && !hop_early(id),
                };
                ok.then(|| (id.clone(), *step))
            })
            .collect()
    }

    /// Marks target `id`'s pending step as in flight and returns that step. A
    /// no-op (`None`) unless that step is startable now — in particular
    /// `remove` never starts without a passed verify.
    pub fn begin_step(&mut self, id: &str) -> Option<RotationStep> {
        let (_, step) = self.startable().into_iter().find(|(x, _)| x == id)?;
        self.set(id, TargetState::Running { step });
        Some(step)
    }

    /// Feeds back the outcome of target `id`'s in-flight `step`. Ignored
    /// unless that step is in flight. A passed verify counts as verified
    /// whenever it lands. After a cancel an in-flight step still lands
    /// honestly, and nothing follows it: a passed confirm is `Switched`, a
    /// failed one keeps its failure (the old key may still log in), a remove
    /// that went through is `Unconfirmed`, anything else is `KeptOld`.
    pub fn record_step(&mut self, id: &str, step: RotationStep, outcome: StepOutcome) {
        if self.state(id) != Some(&TargetState::Running { step }) {
            return;
        }
        let passed = outcome.is_ok();
        if passed && step == RotationStep::Verify {
            self.verified.insert(id.to_owned());
        }
        let next = match (outcome, self.cancelled) {
            (Ok(()), _) if step == RotationStep::Confirm => TargetState::Switched,
            (Err(failure), cancelled) if step == RotationStep::Confirm || !cancelled => {
                TargetState::Failed { step, failure }
            }
            (_, true) => stopped_at(if passed { Some(step) } else { step.previous() }),
            (_, false) => match step.next() {
                Some(next) => TargetState::Pending { step: next },
                None => TargetState::Switched,
            },
        };
        self.set(id, next);
    }

    /// Puts a failed target back in the queue at the step that failed.
    pub fn retry(&mut self, id: &str) {
        if self.cancelled {
            return;
        }
        if let Some(TargetState::Failed { step, .. }) = self.state(id) {
            let step = *step;
            self.set(id, TargetState::Pending { step });
        }
    }

    /// Stops the run: nothing new starts, every target waiting for a step up
    /// to remove keeps the old key, and one waiting for its confirm is left
    /// `Unconfirmed`. Switched targets stay switched; failed ones keep their
    /// failure; in-flight steps land through [`Self::record_step`]. The key
    /// item itself is not touched here.
    pub fn cancel(&mut self) {
        for (_, s) in &mut self.states {
            if let TargetState::Pending { step } = *s {
                *s = stopped_at(step.previous());
            }
        }
        self.cancelled = true;
    }

    /// Lets the run go on to step `last`: a target waiting at a step past the
    /// scope's last one may take it now (a remove still only after a passed
    /// verify in this run). Never narrows the scope; a stopped run stays
    /// stopped.
    pub fn extend_to(&mut self, last: RotationStep) {
        self.last = self.last.max(last);
    }

    /// Nothing in flight and nothing left to start.
    pub fn settled(&self) -> bool {
        !self
            .states
            .iter()
            .any(|(_, s)| matches!(s, TargetState::Running { .. }))
            && self.startable().is_empty()
    }

    /// What finishing now would leave behind, over every target of `plan`.
    pub fn finish_outlook(&self, plan: &RotationPlan) -> FinishOutlook {
        let mut unproven = Vec::new();
        let mut cut_off = Vec::new();
        let mut old_not_refused = Vec::new();
        for t in &plan.targets {
            if !self.verified.contains(&t.id) {
                unproven.push(t.id.clone());
            } else if plan
                .key_hops(&t.id)
                .iter()
                .any(|h| !self.verified.contains(h))
            {
                cut_off.push(t.id.clone());
            } else if self.state(&t.id) != Some(&TargetState::Switched) {
                old_not_refused.push(t.id.clone());
            }
        }
        FinishOutlook {
            unproven,
            cut_off,
            old_not_refused,
        }
    }
}

// ---------- the steps ----------

/// The two keys of a rotation: the public halves as OpenSSH lines, and the
/// candidate's item id. Made by `Core::key_rotation_keys` from the rotation
/// recorded on this device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationKeys {
    /// The key item's current public key.
    pub old: String,
    /// The candidate's public key.
    pub candidate: String,
    /// The candidate key item.
    pub candidate_id: String,
}

impl RotationKeys {
    /// Whether the key item already holds the candidate's key: a finish was
    /// interrupted after its first write. There is no old key left to move
    /// machines off — a run would deploy and "check" the candidate against
    /// itself — so the only thing to do is complete that finish. Compared by
    /// key type and blob; the comment is not part of a key.
    pub fn committed(&self) -> bool {
        let key = |line: &str| {
            line.split_whitespace()
                .take(2)
                .collect::<Vec<_>>()
                .join(" ")
        };
        key(&self.old) == key(&self.candidate)
    }
}

/// How a key-only login with one key ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyLogin {
    /// The session was established and the command ran.
    Accepted,
    /// The server took the key and asked for a second factor.
    AcceptedNeedsMore,
    /// The server does not accept the key.
    Refused,
    /// The attempt failed for another reason and says nothing.
    Unknown,
}

/// Reads a key-only login's outcome off the exec result of its target. The two
/// answers about the key come from the core as a value (`key_login`), never
/// from the error text.
const fn key_login(r: Option<&MultiExecResult>) -> KeyLogin {
    let Some(r) = r else {
        return KeyLogin::Unknown;
    };
    if r.error.is_none() {
        return KeyLogin::Accepted;
    }
    match r.key_login {
        Some(KeyLoginFailure::Refused) => KeyLogin::Refused,
        Some(KeyLoginFailure::AcceptedNeedsMore) => KeyLogin::AcceptedNeedsMore,
        None => KeyLogin::Unknown,
    }
}

/// A command's result as a step outcome: only a clean exit passes.
fn ran(r: Option<&MultiExecResult>, step: RotationStep) -> StepOutcome {
    let Some(r) = r else {
        return Err(StepFailure::NoResult);
    };
    if r.timed_out {
        return Err(StepFailure::TimedOut);
    }
    if let Some(message) = &r.error {
        return Err(StepFailure::Error {
            message: message.clone(),
        });
    }
    if step == RotationStep::Remove && r.exit_status == REMOVE_EXIT_STILL_PRESENT {
        return Err(StepFailure::OldKeyStillPresent);
    }
    if step == RotationStep::Remove && r.exit_status == REMOVE_EXIT_NO_FILE {
        return Err(StepFailure::NoAuthorizedKeys);
    }
    if r.exit_status != 0 {
        let stderr = r.stderr.trim();
        let message = if stderr.is_empty() {
            format!("exit {}", r.exit_status)
        } else {
            stderr.to_owned()
        };
        return Err(StepFailure::Error { message });
    }
    Ok(())
}

/// Runs `cmd` on the target, connected the way [`step_connect`] says for the
/// given step. `Ok(None)` when nothing came back for the target; `Err` when
/// the call itself failed (the vault locked).
pub type StepExec<'e> =
    dyn FnMut(RotationStep, &str) -> Result<Option<MultiExecResult>, StepFailure> + 'e;

/// Runs one step on one target and says whether it passed.
///
/// - deploy — append the candidate, logged in with the old key. When
///   continuing a rotation (`resumed`), first with the candidate, key-only: a
///   machine an earlier run got to already takes it — and may no longer take
///   the old key, which would only earn a password prompt — while one without
///   it just says no and gets the old-key deploy.
/// - verify — a key-only login with the candidate. A server that takes the
///   key and wants a second factor on top has accepted it: the key is proven,
///   the login is not completed (nothing answers that prompt).
/// - remove — drop the old line, logged in with the candidate. Where a second
///   factor stands between the candidate and a shell the line cannot be
///   removed from here; the step then passes only if the old key is already
///   refused (it was removed by hand).
/// - confirm — a key-only login with the OLD key, which must be refused. A
///   login that failed for any other reason proves nothing and is reported
///   apart from one where the old key was accepted.
pub fn run_step(
    step: RotationStep,
    keys: &RotationKeys,
    resumed: bool,
    exec: &mut StepExec<'_>,
) -> StepOutcome {
    match step {
        RotationStep::Verify => {
            let r = exec(RotationStep::Verify, "true")?;
            if key_login(r.as_ref()) == KeyLogin::AcceptedNeedsMore {
                return Ok(());
            }
            ran(r.as_ref(), step)
        }
        RotationStep::Remove => {
            let cmd = authorized_keys_remove_command(&keys.old, &keys.candidate).map_err(|e| {
                StepFailure::Error {
                    message: e.to_string(),
                }
            })?;
            let r = exec(RotationStep::Remove, &cmd)?;
            if key_login(r.as_ref()) != KeyLogin::AcceptedNeedsMore {
                return ran(r.as_ref(), step);
            }
            old_key_refused(exec, StepFailure::RemoveNeedsSecondFactor)
        }
        RotationStep::Confirm => old_key_refused(exec, StepFailure::OldKeyStillAccepted),
        RotationStep::Deploy => {
            let append = authorized_keys_append_command(&keys.candidate);
            if resumed {
                let r = exec(RotationStep::Verify, &append)?;
                if key_login(r.as_ref()) == KeyLogin::AcceptedNeedsMore
                    || ran(r.as_ref(), step).is_ok()
                {
                    return Ok(());
                }
            }
            let r = exec(RotationStep::Deploy, &append)?;
            ran(r.as_ref(), step)
        }
    }
}

/// Passes only when the machine refuses the old key; `accepted` is the failure
/// for a machine that still takes it.
fn old_key_refused(exec: &mut StepExec<'_>, accepted: StepFailure) -> StepOutcome {
    let r = exec(RotationStep::Confirm, "true")?;
    match key_login(r.as_ref()) {
        KeyLogin::Refused => Ok(()),
        KeyLogin::Unknown => Err(StepFailure::OldKeyCheckFailed {
            message: r.and_then(|r| r.error),
        }),
        KeyLogin::Accepted | KeyLogin::AcceptedNeedsMore => Err(accepted),
    }
}

/// How to reach target `id` for `step`, `None` for a target not in the plan.
/// The target itself logs in with the old key to deploy, with the candidate
/// to verify and remove (verify is the proof; remove then runs under that same
/// proven login), and with the old key again to confirm — a login that must be
/// refused. A hop in front of it that uses the rotated key logs in with the
/// candidate once that hop's own target has verified (`verified`) — it may
/// already have dropped the old key — and with the old key before. A
/// `hop_ref` hop switched that way is written out inline (the core would
/// resolve it to the old key); the proxy the core would have taken from that
/// bastion is already the target's own. That inline copy mirrors the core's
/// `hop_ref` resolution in `connect_with_options` (a ref hop takes the
/// referenced profile's host/port/user/auth) — keep the two in step.
pub fn step_connect(
    plan: &RotationPlan,
    verified: &BTreeSet<String>,
    id: &str,
    step: RotationStep,
    candidate_id: &str,
) -> Option<MultiExecTarget> {
    let t = plan.target(id)?;
    let m = Routes::of(plan);
    let candidate = AuthMethod::Agent {
        vault_id: plan.vault_id.clone(),
        key_item_id: candidate_id.to_owned(),
    };
    let old = AuthMethod::Agent {
        vault_id: plan.vault_id.clone(),
        key_item_id: plan.key_item_id.clone(),
    };
    let jumps = t
        .jumps
        .iter()
        .enumerate()
        .map(|(i, j)| {
            let switched = m.hop_uses_key(j)
                && m.hop_target_id(&t.jumps, t.proxy.as_ref(), i)
                    .is_some_and(|hop| verified.contains(&hop));
            if !switched {
                return j.clone();
            }
            match m.ref_profile(j) {
                None => JumpHost {
                    auth: candidate.clone(),
                    ..j.clone()
                },
                Some(r) => JumpHost {
                    host: r.host.clone(),
                    port: r.port,
                    user: r.user.clone(),
                    auth: candidate.clone(),
                    hop_ref: None,
                },
            }
        })
        .collect();
    let auth = match step {
        RotationStep::Deploy | RotationStep::Confirm => old,
        RotationStep::Verify | RotationStep::Remove => candidate,
    };
    // Verify, remove and confirm must log in with that one key and nothing
    // else: a keyboard-interactive fallback would let a typed password pass
    // for the key. Deploy logs in with the old key the user already uses,
    // prompts and all.
    Some(MultiExecTarget {
        host: t.host.clone(),
        port: t.port,
        user: t.user.clone(),
        auth,
        jumps,
        proxy: t.proxy.clone(),
        publickey_only: step != RotationStep::Deploy,
    })
}

// ---------- the driver ----------

/// A run in progress over SSH: the plan, the two public keys, and the run's
/// state behind a lock, so that a client can stop it or read it from another
/// thread while [`Self::drive`] works.
pub struct RotationDriver {
    plan: RotationPlan,
    keys: RotationKeys,
    resumed: bool,
    run: Mutex<RotationRun>,
}

impl RotationDriver {
    /// A run of `plan` in `scope`, moving the machines to the candidate of
    /// `keys`. `resumed`: the rotation was begun before this run (see
    /// [`run_step`], deploy).
    pub fn new(plan: RotationPlan, keys: RotationKeys, resumed: bool, scope: &RunScope) -> Self {
        let run = RotationRun::start(&plan, scope);
        Self {
            plan,
            keys,
            resumed,
            run: Mutex::new(run),
        }
    }

    /// The plan the run works off.
    pub const fn plan(&self) -> &RotationPlan {
        &self.plan
    }

    fn lock(&self) -> MutexGuard<'_, RotationRun> {
        // Every change to the run is one assignment; a poisoned lock still
        // holds a consistent run.
        self.run.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The run as it stands.
    pub fn snapshot(&self) -> RotationRun {
        self.lock().clone()
    }

    /// Stops the run (see [`RotationRun::cancel`]) and returns it.
    pub fn stop(&self) -> RotationRun {
        let mut run = self.lock();
        run.cancel();
        run.clone()
    }

    /// Puts failed target `id` back in the queue (see [`RotationRun::retry`])
    /// and returns the run. [`Self::drive`] then runs it.
    pub fn retry(&self, id: &str) -> RotationRun {
        let mut run = self.lock();
        run.retry(id);
        run.clone()
    }

    /// Lets the run go on to step `last` (see [`RotationRun::extend_to`]);
    /// [`Self::drive`] then takes the further steps.
    pub fn extend_to(&self, last: RotationStep) {
        self.lock().extend_to(last);
    }

    /// Runs round after round of whatever may start now, at most
    /// `concurrency` steps at once, until the run settles; returns it.
    /// `on_change` sees the run after every change, with the id of the target
    /// that changed; it is called with the run locked, so it must not call
    /// back into this driver. A step whose exec call fails lands as that
    /// step's failure.
    pub fn drive(
        &self,
        core: &Core,
        concurrency: usize,
        timeout_secs: u32,
        on_change: &(dyn Fn(&str, &RotationRun) + Sync),
    ) -> RotationRun {
        loop {
            let steps = self.lock().startable();
            if steps.is_empty() {
                break;
            }
            let workers = concurrency.clamp(1, steps.len());
            let queue = Mutex::new(VecDeque::from(steps));
            std::thread::scope(|s| {
                for _ in 0..workers {
                    s.spawn(|| self.work(core, &queue, timeout_secs, on_change));
                }
            });
        }
        self.snapshot()
    }

    /// One worker of a round: takes steps off `queue` until it is empty.
    fn work(
        &self,
        core: &Core,
        queue: &Mutex<VecDeque<(String, RotationStep)>>,
        timeout_secs: u32,
        on_change: &(dyn Fn(&str, &RotationRun) + Sync),
    ) {
        loop {
            let next = queue
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pop_front();
            let Some((id, step)) = next else {
                return;
            };
            let verified = {
                let mut run = self.lock();
                // Only the step queued for it, and only while it may start.
                if run.state(&id) != Some(&TargetState::Pending { step })
                    || run.begin_step(&id).is_none()
                {
                    continue;
                }
                on_change(&id, &run);
                run.verified().clone()
            };
            let outcome = run_step(step, &self.keys, self.resumed, &mut |as_step, cmd| {
                self.exec(core, &verified, &id, as_step, cmd, timeout_secs)
            });
            let mut run = self.lock();
            run.record_step(&id, step, outcome);
            on_change(&id, &run);
            drop(run);
        }
    }

    /// One command on target `id`, logged in as `step` does.
    fn exec(
        &self,
        core: &Core,
        verified: &BTreeSet<String>,
        id: &str,
        step: RotationStep,
        cmd: &str,
        timeout_secs: u32,
    ) -> Result<Option<MultiExecResult>, StepFailure> {
        let Some(target) = step_connect(&self.plan, verified, id, step, &self.keys.candidate_id)
        else {
            return Ok(None);
        };
        match core.ssh_exec_multi(vec![target], cmd.to_owned(), 0, timeout_secs) {
            Ok(mut results) => Ok(results.pop()),
            Err(FfiError::Locked) => Err(StepFailure::Locked),
            Err(e) => Err(StepFailure::Error {
                message: e.to_string(),
            }),
        }
    }
}

impl Core {
    /// The plan for rotating key `key_id` of vault `vault_id`, made from the
    /// vault's hosts as they are now (see [`plan_rotation`]).
    pub fn plan_key_rotation(
        &self,
        vault_id: String,
        key_id: String,
    ) -> Result<RotationPlan, FfiError> {
        let mut hosts = self.list_connections(vault_id.clone())?;
        for host in &mut hosts {
            if let Some(resolved) =
                self.personal_key_profile(&vault_id, host, &vault_id, &key_id)?
            {
                *host = resolved;
            }
        }
        for other in self.list_vaults()? {
            if self.same_vault_id(&other.vault_id, &vault_id)? {
                continue;
            }
            for host in self.list_connections(other.vault_id.clone())? {
                if let Some(mut resolved) =
                    self.personal_key_profile(&other.vault_id, &host, &vault_id, &key_id)?
                {
                    if resolved.jumps.iter().any(|j| j.hop_ref.is_some()) {
                        return Err(FfiError::other(format!(
                            "{} / {} uses this key through a personal identity and saved jump hosts; move that route to inline hops before rotating",
                            other.name, host.label
                        )));
                    }
                    resolved.label = format!("{} / {}", other.name, resolved.label);
                    hosts.push(resolved);
                }
            }
        }
        let same_vault = self.names_of_vault(&vault_id, &hosts)?;
        Ok(plan_rotation_in(hosts, &vault_id, &key_id, same_vault))
    }

    /// Whether two external ids name the same vault.
    pub(crate) fn same_vault_id(&self, left: &str, right: &str) -> Result<bool, FfiError> {
        self.with_state(|state| {
            Ok(crate::resolve_vid(&state.storage, left)
                == crate::resolve_vid(&state.storage, right))
        })
    }

    /// A personal host using this key, resolved through the ordinary pinned
    /// identity path. A broken pin is an error, never a silently skipped target.
    pub(crate) fn personal_key_profile(
        &self,
        host_vault: &str,
        host: &ConnectionProfile,
        key_vault: &str,
        key_id: &str,
    ) -> Result<Option<ConnectionProfile>, FfiError> {
        if !matches!(host.auth, ProfileAuth::Personal) {
            return Ok(None);
        }
        let Some(personal_vault) = self.find_binding_vault(host_vault, &host.uid)? else {
            return Ok(None);
        };
        if !self.same_vault_id(&personal_vault, key_vault)? {
            return Ok(None);
        }
        let Some(binding) = self.get_binding(
            personal_vault.clone(),
            host_vault.to_owned(),
            host.uid.clone(),
        )?
        else {
            return Ok(None);
        };
        let identity = self.get_identity(personal_vault, binding.identity_item_id)?;
        if identity.key_item_id.as_deref() != Some(key_id) {
            return Ok(None);
        }
        let resolved = self.resolve_profile(host_vault, host)?;
        let mut target = host.clone();
        target.user = resolved.user;
        target.username_template = None;
        target.auth = ProfileAuth::Key {
            key_item_id: key_id.to_owned(),
        };
        Ok(Some(target))
    }

    /// Restricts a run to already pinned machines. Omitted targets remain
    /// unproven in the finish outlook, so finishing still needs the lockout warning.
    pub fn pinned_rotation_scope(
        &self,
        plan: &RotationPlan,
        scope: &RunScope,
    ) -> Result<RunScope, FfiError> {
        let unpinned: BTreeSet<String> = self.key_rotation_unpinned(plan)?.into_iter().collect();
        let only = plan
            .targets
            .iter()
            .filter(|t| {
                scope.only.as_ref().is_none_or(|ids| ids.contains(&t.id))
                    && !unpinned.contains(&t.id)
            })
            .map(|t| t.id.clone())
            .collect();
        Ok(RunScope {
            only: Some(only),
            ..scope.clone()
        })
    }

    /// The targets of `plan` reached over a machine whose host key is not
    /// pinned yet: the target itself or a jump hop in front of it. A rotation
    /// must not be what pins it — it would trust whatever key answers there
    /// first, and hand that machine logins with both keys. A connect to the
    /// host (for a hop: to the host it is a hop of) pins every machine on the
    /// way. The proxy is no SSH endpoint and has no host key.
    pub fn key_rotation_unpinned(&self, plan: &RotationPlan) -> Result<Vec<String>, FfiError> {
        let m = Routes::of(plan);
        for target in &plan.targets {
            if target
                .jumps
                .iter()
                .any(|j| j.hop_ref.is_some() && m.ref_profile(j).is_none())
            {
                return Err(FfiError::other(format!(
                    "{} has a missing or foreign saved jump host; repair its route before rotating",
                    target.label()
                )));
            }
        }
        let endpoints = |t: &RotationTarget| -> Vec<(String, u16)> {
            let hops = t.jumps.iter().map(|j| match m.ref_profile(j) {
                Some(r) => (r.host.clone(), r.port),
                None => (j.host.clone(), j.port),
            });
            hops.chain(std::iter::once((t.host.clone(), t.port)))
                .collect()
        };
        self.with_state(|state| {
            let mut out = Vec::new();
            for t in &plan.targets {
                for (host, port) in endpoints(t) {
                    let pinned = state
                        .storage
                        .get_known_host(&host, port)
                        .map_err(FfiError::other)?
                        .is_some();
                    if !pinned {
                        out.push(t.id.clone());
                        break;
                    }
                }
            }
            Ok(out)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HopRef;

    const OLD: &str = "ssh-ed25519 AAAAC3OLD";
    const CAND: &str = "ssh-ed25519 AAAAC3CAND rotation";
    const OTHER: &str = "ssh-rsa AAAAB3OTHER someone@else";

    fn key() -> ProfileAuth {
        ProfileAuth::Key {
            key_item_id: "k".to_owned(),
        }
    }

    fn host(name: &str, auth: ProfileAuth, jumps: Vec<JumpHost>) -> ConnectionProfile {
        ConnectionProfile {
            profile_id: name.to_owned(),
            uid: name.to_owned(),
            label: name.to_owned(),
            host: format!("{name}.example"),
            port: 22,
            user: "root".to_owned(),
            auth,
            username_template: None,
            jumps,
            proxy: None,
            tags: Vec::new(),
            startup_snippet_ids: Vec::new(),
            record_sessions: false,
            agent_forward: false,
            color: None,
            icon: None,
        }
    }

    fn agent(key_item_id: &str) -> AuthMethod {
        AuthMethod::Agent {
            vault_id: "v".to_owned(),
            key_item_id: key_item_id.to_owned(),
        }
    }

    fn inline_hop(name: &str, key_item_id: &str) -> JumpHost {
        JumpHost {
            host: format!("{name}.example"),
            port: 22,
            user: "ops".to_owned(),
            auth: agent(key_item_id),
            hop_ref: None,
        }
    }

    fn ref_hop(profile_uid: &str) -> JumpHost {
        JumpHost {
            hop_ref: Some(HopRef {
                vault_id: "v".to_owned(),
                profile_uid: profile_uid.to_owned(),
            }),
            ..inline_hop("ignored", "")
        }
    }

    fn socks(host: &str) -> ProxyConfig {
        ProxyConfig {
            kind: ProxyKind::Socks5,
            host: host.to_owned(),
            port: 1080,
            username: None,
            password: None,
        }
    }

    fn plan(hosts: Vec<ConnectionProfile>) -> RotationPlan {
        plan_rotation(hosts, "v", "k")
    }

    fn named(names: &[&str]) -> RotationPlan {
        plan(names.iter().map(|n| host(n, key(), Vec::new())).collect())
    }

    const A: &str = "root@a.example:22";
    const B: &str = "root@b.example:22";

    fn fail(message: &str) -> StepOutcome {
        Err(StepFailure::Error {
            message: message.to_owned(),
        })
    }

    /// Runs every startable step until the run settles, answering each from `answer`.
    fn drive(run: &mut RotationRun, mut answer: impl FnMut(&str, RotationStep) -> StepOutcome) {
        loop {
            let steps = run.startable();
            if steps.is_empty() {
                return;
            }
            for (id, _) in &steps {
                run.begin_step(id);
            }
            for (id, step) in &steps {
                let outcome = answer(id, *step);
                run.record_step(id, *step, outcome);
            }
        }
    }

    /// Each target's state as `kind[:step]`.
    fn kinds(run: &RotationRun) -> Vec<(String, String)> {
        run.states()
            .map(|(id, s)| {
                let kind = match s {
                    TargetState::Pending { step } => format!("pending:{}", step.name()),
                    TargetState::Running { step } => format!("running:{}", step.name()),
                    TargetState::Failed { step, .. } => format!("failed:{}", step.name()),
                    TargetState::Switched => "switched".to_owned(),
                    TargetState::KeptOld { .. } => "keptOld".to_owned(),
                    TargetState::Unconfirmed => "unconfirmed".to_owned(),
                };
                (id.to_owned(), kind)
            })
            .collect()
    }

    fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
        items
            .iter()
            .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
            .collect()
    }

    fn full(plan: &RotationPlan) -> RotationRun {
        RotationRun::start(plan, &RunScope::full())
    }

    // ---------- the remote commands ----------

    #[test]
    fn the_remote_commands_are_the_text_the_app_ran() {
        // Captured from the app's TypeScript builders before they moved here.
        let append = r#"sh -c 'd=~/.ssh; f=$d/authorized_keys; { [ -d "$d" ] || { mkdir -p "$d" && chmod 700 "$d"; }; } && { [ -e "$f" ] || { touch "$f" && chmod 600 "$f"; }; } && { grep -qxF '\''ssh-ed25519 AAAAC3CAND rotation'\'' "$f" || { { [ ! -s "$f" ] || [ -z "$(tail -c1 "$f")" ] || echo >> "$f"; } && printf '\''%s\n'\'' '\''ssh-ed25519 AAAAC3CAND rotation'\'' >> "$f"; }; }'"#;
        let remove = r#"sh -c 'f=~/.ssh/authorized_keys; [ -f "$f" ] || { echo '\''no ~/.ssh/authorized_keys on this host'\'' >&2; exit 4; }; while [ -L "$f" ]; do l=$(readlink "$f") || { echo '\''cannot resolve the authorized_keys symlink; old key left in place'\'' >&2; exit 1; }; case $l in /*) f=$l ;; *) f=$(dirname "$f")/$l ;; esac; done; has() { awk -v t="$1" -v b="$2" '\''{ k = $2; sub(/\r$/, "", k) } $1 == t && k == b { found = 1 } END { exit found ? 0 : 1 }'\'' "$3"; }; has '\''ssh-ed25519'\'' '\''AAAAC3CAND'\'' "$f" || { echo '\''new key is not in authorized_keys; old key left in place'\'' >&2; exit 1; }; t=$(mktemp "$f.XXXXXX") || exit 1; cp -p "$f" "$t" && awk -v t='\''ssh-ed25519'\'' -v b='\''AAAAC3OLD'\'' '\''{ k = $2; sub(/\r$/, "", k) } $1 == t && k == b { next } { print }'\'' "$f" > "$t" && has '\''ssh-ed25519'\'' '\''AAAAC3CAND'\'' "$t" && mv -f "$t" "$f" || { rm -f "$t"; exit 1; }; if awk -v b='\''AAAAC3OLD'\'' '\''/^[ \t]*#/ { next } index($0, b) { found = 1 } END { exit found ? 0 : 1 }'\'' "$f"; then echo '\''old key data still in authorized_keys: a line with options, or the same key under another key type'\'' >&2; exit 3; fi'"#;
        assert_eq!(authorized_keys_append_command(CAND), append, "append");
        assert_eq!(
            authorized_keys_remove_command(OLD, CAND).unwrap(),
            remove,
            "remove"
        );
    }

    #[test]
    fn the_remote_commands_survive_a_csh_login_shell() {
        // csh/tcsh expand `!` even inside single quotes, unless a blank follows it.
        for cmd in [
            authorized_keys_append_command(CAND),
            authorized_keys_remove_command(OLD, CAND).unwrap(),
        ] {
            let bang = cmd.as_bytes().windows(2).any(|w| {
                w.first() == Some(&b'!') && !matches!(w.get(1), Some(b' ' | b'\t' | b'\n'))
            });
            assert!(!bang, "a `!` csh would expand in {cmd}");
        }
    }

    /// The remote commands run under `/bin/sh` with each awk this machine
    /// has: the system's own, and mawk, gawk, BSD awk and busybox where installed.
    #[cfg(unix)]
    mod shell {
        use std::fs;
        use std::os::unix::fs::{symlink, PermissionsExt};
        use std::path::{Path, PathBuf};
        use std::process::Command;

        use super::{CAND, OLD, OTHER};
        use crate::key_rotation_plan::{
            authorized_keys_append_command, authorized_keys_remove_command,
            REMOVE_EXIT_STILL_PRESENT,
        };

        /// An awk to run the commands with: a directory whose `awk` is it.
        struct Awk {
            name: String,
            bin: Option<tempfile::TempDir>,
        }

        fn on_path(bin: &str) -> Option<PathBuf> {
            let path = std::env::var_os("PATH")?;
            std::env::split_paths(&path)
                .map(|d| d.join(bin))
                .find(|f| f.is_file())
        }

        fn awks() -> Vec<Awk> {
            let mut out = vec![Awk {
                name: "awk".to_owned(),
                bin: None,
            }];
            for (name, bin, args) in [
                ("mawk", "mawk", ""),
                ("gawk", "gawk", ""),
                ("bsd awk", "original-awk", ""),
                ("nawk", "nawk", ""),
                ("busybox awk", "busybox", " awk"),
            ] {
                let Some(path) = on_path(bin) else {
                    continue;
                };
                let dir = tempfile::tempdir().unwrap();
                let wrapper = dir.path().join("awk");
                fs::write(
                    &wrapper,
                    format!("#!/bin/sh\nexec '{}'{args} \"$@\"\n", path.display()),
                )
                .unwrap();
                fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
                out.push(Awk {
                    name: name.to_owned(),
                    bin: Some(dir),
                });
            }
            out
        }

        /// Runs `cmd` the way the exec channel does, with HOME at `home`.
        fn run(awk: &Awk, home: &Path, cmd: &str) -> i32 {
            let mut c = Command::new("/bin/sh");
            c.arg("-c").arg(cmd).env("HOME", home);
            if let Some(dir) = &awk.bin {
                let path = std::env::var_os("PATH").unwrap_or_default();
                let mut dirs = vec![dir.path().to_path_buf()];
                dirs.extend(std::env::split_paths(&path));
                c.env("PATH", std::env::join_paths(dirs).unwrap());
            }
            c.status().unwrap().code().unwrap_or(-1)
        }

        /// A throwaway HOME — with a space in its path, as a real one may
        /// have — holding `~/.ssh/authorized_keys` with `content` (none for `None`).
        fn home(content: Option<&str>) -> (tempfile::TempDir, PathBuf) {
            let home = tempfile::Builder::new()
                .prefix("unissh ak-")
                .tempdir()
                .unwrap();
            fs::create_dir_all(home.path().join(".ssh")).unwrap();
            let file = home.path().join(".ssh").join("authorized_keys");
            if let Some(content) = content {
                fs::write(&file, content).unwrap();
            }
            (home, file)
        }

        fn mode(p: &Path) -> u32 {
            fs::metadata(p).unwrap().permissions().mode() & 0o777
        }

        fn read(p: &Path) -> String {
            fs::read_to_string(p).unwrap()
        }

        /// Runs `check` once per awk, unless there is no `/bin/sh`.
        fn each_awk(check: impl Fn(&Awk)) {
            if !Path::new("/bin/sh").exists() {
                eprintln!("no /bin/sh: the shell runs are skipped");
                return;
            }
            for awk in awks() {
                check(&awk);
            }
        }

        #[test]
        fn append_puts_the_key_on_its_own_line_after_a_missing_newline() {
            each_awk(|awk| {
                let (h, file) = home(Some("ssh-ed25519 AAAAOLD old"));
                let cmd = authorized_keys_append_command("ssh-ed25519 AAAACAND cand");
                assert_eq!(run(awk, h.path(), &cmd), 0, "{}", awk.name);
                assert_eq!(
                    read(&file),
                    "ssh-ed25519 AAAAOLD old\nssh-ed25519 AAAACAND cand\n",
                    "{}",
                    awk.name
                );
            });
        }

        #[test]
        fn append_leaves_the_modes_of_an_existing_ssh_dir_and_file_alone() {
            each_awk(|awk| {
                let (h, file) = home(Some(&format!("{OTHER}\n")));
                let dir = h.path().join(".ssh");
                fs::set_permissions(&dir, fs::Permissions::from_mode(0o750)).unwrap();
                fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
                let cmd = authorized_keys_append_command(CAND);
                assert_eq!(run(awk, h.path(), &cmd), 0, "{}", awk.name);
                assert_eq!(
                    (mode(&dir), mode(&file), read(&file)),
                    (0o750, 0o640, format!("{OTHER}\n{CAND}\n")),
                    "{}",
                    awk.name
                );
            });
        }

        #[test]
        fn remove_drops_the_old_keys_plain_lines_whatever_their_comment_and_ending() {
            each_awk(|awk| {
                let (h, file) = home(Some(&format!(
                    "{OLD}\n{OTHER}\r\n{OLD} user@laptop\r\n\t{OLD} second copy\n{OLD}\r\n{CAND}\n"
                )));
                let old = format!("{OLD} vault comment");
                let cmd = authorized_keys_remove_command(&old, CAND).unwrap();
                assert_eq!(
                    (run(awk, h.path(), &cmd), read(&file)),
                    (0, format!("{OTHER}\r\n{CAND}\n")),
                    "{}",
                    awk.name
                );
            });
        }

        #[test]
        fn remove_leaves_an_old_key_line_with_options_in_place_and_reports_it() {
            each_awk(|awk| {
                let restricted =
                    format!(r#"from="10.0.0.0/8",command="/usr/bin/backup" {OLD} backup"#);
                let (h, file) = home(Some(&format!("{OLD} user@laptop\n{restricted}\n{CAND}\n")));
                let cmd = authorized_keys_remove_command(OLD, CAND).unwrap();
                assert_eq!(
                    (run(awk, h.path(), &cmd), read(&file)),
                    (REMOVE_EXIT_STILL_PRESENT, format!("{restricted}\n{CAND}\n")),
                    "{}",
                    awk.name
                );
            });
        }

        #[test]
        fn remove_takes_a_commented_out_old_key_for_none_but_not_one_under_another_type() {
            // sshd skips the first line and reads the second, whatever it makes of it.
            let commented = format!(" \t# {OLD} retired 2026");
            let retyped = "ssh-rsa AAAAC3OLD".to_owned();
            each_awk(|awk| {
                let left = |extra: &str| {
                    let (h, file) = home(Some(&format!("{OLD} user@laptop\n{extra}\n{CAND}\n")));
                    let cmd = authorized_keys_remove_command(OLD, CAND).unwrap();
                    (run(awk, h.path(), &cmd), read(&file))
                };
                assert_eq!(
                    (left(&commented), left(&retyped)),
                    (
                        (0, format!("{commented}\n{CAND}\n")),
                        (REMOVE_EXIT_STILL_PRESENT, format!("{retyped}\n{CAND}\n"))
                    ),
                    "{}",
                    awk.name
                );
            });
        }

        #[test]
        fn remove_touches_nothing_unless_the_new_key_is_there_as_a_plain_line() {
            // The candidate behind an options prefix is a restricted login, not a replacement.
            each_awk(|awk| {
                let before = format!("{OLD} user@laptop\ncommand=\"/bin/false\" {CAND}\n");
                let (h, file) = home(Some(&before));
                let cmd = authorized_keys_remove_command(OLD, CAND).unwrap();
                assert_eq!(
                    (run(awk, h.path(), &cmd), read(&file)),
                    (1, before),
                    "{}",
                    awk.name
                );
            });
        }

        #[test]
        fn remove_rewrites_a_symlinked_file_through_the_link_keeping_link_and_mode() {
            each_awk(|awk| {
                let (h, file) = home(None);
                let real = h.path().join("keys of mine");
                fs::write(&real, format!("{OLD} user@laptop\n{CAND}\n")).unwrap();
                fs::set_permissions(&real, fs::Permissions::from_mode(0o640)).unwrap();
                // Relative, as a dotfiles manager links it: resolved against ~/.ssh.
                symlink("../keys of mine", &file).unwrap();
                let cmd = authorized_keys_remove_command(OLD, CAND).unwrap();
                let status = run(awk, h.path(), &cmd);
                let linked = fs::symlink_metadata(&file)
                    .unwrap()
                    .file_type()
                    .is_symlink();
                assert_eq!(
                    (status, linked, mode(&real), read(&real)),
                    (0, true, 0o640, format!("{CAND}\n")),
                    "{}",
                    awk.name
                );
            });
        }
    }

    // ---------- the plan ----------

    #[test]
    fn plan_targets_the_machines_that_log_in_with_the_key_and_makes_hop_only_hosts_follow() {
        let p = plan(vec![
            host("bastion", key(), Vec::new()),
            // hop-only through the saved bastion profile → follows the bastion
            host("db", ProfileAuth::PromptPassword, vec![ref_hop("bastion")]),
            // inline hop with the key, reached directly
            host(
                "app",
                ProfileAuth::VaultPassword {
                    password_item_id: "p".to_owned(),
                },
                vec![inline_hop("jump", "k")],
            ),
            // the same inline endpoint over the same (empty) route again → one target
            host(
                "cache",
                ProfileAuth::Personal,
                vec![inline_hop("jump", "k")],
            ),
            // a direct host that also hops with the key is a target, not a dependent
            host("web", key(), vec![inline_hop("jump", "k")]),
        ]);
        let j = "ops@jump.example:22";
        let label = |h: Option<&ConnectionProfile>| h.map(|h| h.label.clone());
        let targets: Vec<(String, Option<String>, Option<String>)> = p
            .targets
            .iter()
            .map(|t| {
                (
                    t.id.clone(),
                    label(t.profile.as_ref()),
                    label(t.via.as_ref()),
                )
            })
            .collect();
        let some = |s: &str| Some(s.to_owned());
        assert_eq!(
            targets,
            vec![
                ("root@bastion.example:22".to_owned(), some("bastion"), None),
                (format!("root@web.example:22 via {j}"), some("web"), None),
                (j.to_owned(), None, some("app")),
            ],
            "targets"
        );
        let dependents: Vec<(String, Vec<String>)> = p
            .dependents
            .iter()
            .map(|d| (d.host.label.clone(), d.target_ids.clone()))
            .collect();
        assert_eq!(
            dependents,
            vec![
                ("db".to_owned(), vec!["root@bastion.example:22".to_owned()]),
                ("app".to_owned(), vec![j.to_owned()]),
                ("cache".to_owned(), vec![j.to_owned()]),
            ],
            "dependents"
        );
        assert!(!p.has_shared_endpoint(), "no login reached two ways");
    }

    #[test]
    fn plan_keeps_one_login_behind_different_routes_as_separate_machines_and_one_route_as_one() {
        let at = |name: &str, jumps: Vec<JumpHost>, proxy: Option<ProxyConfig>| ConnectionProfile {
            host: "10.0.0.5".to_owned(),
            proxy,
            ..host(name, key(), jumps)
        };
        let p = plan(vec![
            at("prod-db", vec![inline_hop("prod-bastion", "x")], None),
            at("stage-db", vec![inline_hop("stage-bastion", "x")], None),
            at("office-db", Vec::new(), Some(socks("px"))),
            // the same login over the very route prod-db uses → the same machine
            at("prod-db-alias", vec![inline_hop("prod-bastion", "x")], None),
            // the key as a hop: the same hop login behind different first hops
            host(
                "app",
                ProfileAuth::PromptPassword,
                vec![inline_hop("prod-bastion", "x"), inline_hop("inner", "k")],
            ),
            host(
                "stage-app",
                ProfileAuth::PromptPassword,
                vec![inline_hop("stage-bastion", "x"), inline_hop("inner", "k")],
            ),
        ]);
        let targets: Vec<(String, String, Vec<String>, bool)> = p
            .targets
            .iter()
            .map(|t| {
                let name = t
                    .profile
                    .as_ref()
                    .or(t.via.as_ref())
                    .map(|h| h.label.clone());
                (
                    t.id.clone(),
                    name.unwrap_or_default(),
                    t.jumps.iter().map(|j| j.host.clone()).collect(),
                    t.proxy.is_some(),
                )
            })
            .collect();
        let row = |id: &str, name: &str, hops: &[&str], proxied: bool| {
            (
                id.to_owned(),
                name.to_owned(),
                hops.iter().map(|h| (*h).to_owned()).collect::<Vec<_>>(),
                proxied,
            )
        };
        let prod = "ops@prod-bastion.example:22";
        let stage = "ops@stage-bastion.example:22";
        assert_eq!(
            targets,
            vec![
                row(
                    &format!("root@10.0.0.5:22 via {prod}"),
                    "prod-db",
                    &["prod-bastion.example"],
                    false
                ),
                row(
                    &format!("root@10.0.0.5:22 via {stage}"),
                    "stage-db",
                    &["stage-bastion.example"],
                    false
                ),
                row(
                    "root@10.0.0.5:22 proxy socks5://px:1080",
                    "office-db",
                    &[],
                    true
                ),
                row(
                    &format!("ops@inner.example:22 via {prod}"),
                    "app",
                    &["prod-bastion.example"],
                    false
                ),
                row(
                    &format!("ops@inner.example:22 via {stage}"),
                    "stage-app",
                    &["stage-bastion.example"],
                    false
                ),
            ],
            "one target per login and route"
        );
        // The dialog says so: one machine reached two ways is reported per route.
        assert!(p.has_shared_endpoint(), "10.0.0.5 is reached three ways");
    }

    #[test]
    fn plan_skips_hosts_that_log_in_with_personal_the_system_agent_or_a_password() {
        let p = plan(vec![
            host("a", key(), Vec::new()),
            host("p", ProfileAuth::Personal, Vec::new()),
            host(
                "s",
                ProfileAuth::SystemAgent {
                    public_key: "ssh-ed25519 AAAA".to_owned(),
                },
                Vec::new(),
            ),
            host(
                "vp",
                ProfileAuth::VaultPassword {
                    password_item_id: "x".to_owned(),
                },
                Vec::new(),
            ),
            host("ask", ProfileAuth::PromptPassword, Vec::new()),
            host(
                "other",
                ProfileAuth::Key {
                    key_item_id: "other".to_owned(),
                },
                Vec::new(),
            ),
        ]);
        let skipped: Vec<(String, RotationSkipReason)> = p
            .skipped
            .iter()
            .map(|s| (s.host.label.clone(), s.reason))
            .collect();
        assert_eq!(
            skipped,
            vec![
                ("p".to_owned(), RotationSkipReason::Personal),
                ("s".to_owned(), RotationSkipReason::SystemAgent),
                ("vp".to_owned(), RotationSkipReason::Password),
                ("ask".to_owned(), RotationSkipReason::Password),
            ],
            "skipped with a reason; another key's host is not listed"
        );
    }

    // ---------- the run ----------

    #[test]
    fn a_run_switches_every_target_through_deploy_verify_remove_and_confirm() {
        let mut run = full(&named(&["a", "b"]));
        drive(&mut run, |_, _| Ok(()));
        assert_eq!(
            (kinds(&run), run.settled()),
            (pairs(&[(A, "switched"), (B, "switched")]), true),
            "both switched"
        );
    }

    #[test]
    fn a_failed_deploy_on_one_host_stops_that_host_and_no_other() {
        let mut seen = Vec::new();
        let mut run = full(&named(&["a", "b"]));
        drive(&mut run, |id, step| {
            seen.push((id.to_owned(), step));
            if id == A {
                fail("denied")
            } else {
                Ok(())
            }
        });
        let on_a: Vec<RotationStep> = seen
            .iter()
            .filter(|(id, _)| id == A)
            .map(|(_, s)| *s)
            .collect();
        assert_eq!(
            on_a,
            vec![RotationStep::Deploy],
            "nothing after the failed deploy"
        );
        let denied = TargetState::Failed {
            step: RotationStep::Deploy,
            failure: StepFailure::Error {
                message: "denied".to_owned(),
            },
        };
        assert_eq!(
            (run.state(A), run.state(B)),
            (Some(&denied), Some(&TargetState::Switched)),
            "a failed, b switched"
        );
    }

    #[test]
    fn a_failed_verify_keeps_the_old_key() {
        let mut run = full(&named(&["a", "b"]));
        drive(&mut run, |id, step| {
            if id == A && step == RotationStep::Verify {
                fail("Permission denied")
            } else {
                Ok(())
            }
        });
        assert_eq!(
            (kinds(&run).first().cloned(), run.is_verified(A)),
            (Some((A.to_owned(), "failed:verify".to_owned())), false),
            "a stopped at verify, unproven"
        );
    }

    #[test]
    fn a_cancel_leaves_switched_targets_switched_and_every_other_one_on_the_old_key() {
        let p = named(&["a", "b", "c", "d"]);
        let (a, b, c, d) = (
            "root@a.example:22",
            "root@b.example:22",
            "root@c.example:22",
            "root@d.example:22",
        );
        // a switches; c fails deploy; b's remove and d's verify fail and are retried
        let mut run = full(&p);
        drive(&mut run, |id, step| {
            let bad = (id == c && step == RotationStep::Deploy)
                || (id == b && step == RotationStep::Remove)
                || (id == d && step == RotationStep::Verify);
            if bad {
                fail("x")
            } else {
                Ok(())
            }
        });
        run.retry(b);
        run.retry(d);
        run.begin_step(d); // d's verify in flight; b's remove waits for it
        run.cancel();
        assert!(run.startable().is_empty(), "nothing starts after a cancel");
        run.record_step(d, RotationStep::Verify, Ok(()));
        assert_eq!(
            kinds(&run),
            pairs(&[
                (a, "switched"),
                (b, "keptOld"),
                (c, "failed:deploy"),
                (d, "keptOld")
            ]),
            "states after the cancel"
        );
        // b was waiting to remove, d's verify landed after the cancel: both passed verify.
        let after_verify = TargetState::KeptOld {
            after: Some(RotationStep::Verify),
        };
        assert_eq!(
            (run.state(b), run.state(d), run.is_verified(d)),
            (Some(&after_verify), Some(&after_verify), true),
            "kept the old key after a passed verify"
        );
        let before = run.clone();
        run.retry(c);
        assert_eq!(
            (run.settled(), run),
            (true, before),
            "no retry after a cancel"
        );
    }

    #[test]
    fn a_host_is_switched_only_once_the_old_key_was_seen_refused() {
        let mut run = full(&named(&["a", "b"]));
        drive(&mut run, |id, step| {
            if id == A && step == RotationStep::Confirm {
                Err(StepFailure::OldKeyStillAccepted)
            } else {
                Ok(())
            }
        });
        let still = TargetState::Failed {
            step: RotationStep::Confirm,
            failure: StepFailure::OldKeyStillAccepted,
        };
        assert_eq!(
            (run.state(A), run.is_verified(A), run.state(B)),
            (Some(&still), true, Some(&TargetState::Switched)),
            "a not switched while the old key logs in"
        );
        // The retry runs the check again, not the remove.
        let mut seen = Vec::new();
        run.retry(A);
        drive(&mut run, |id, step| {
            seen.push((id.to_owned(), step));
            Ok(())
        });
        assert_eq!(
            (seen, run.state(A)),
            (
                vec![(A.to_owned(), RotationStep::Confirm)],
                Some(&TargetState::Switched)
            ),
            "only the check reran"
        );
    }

    #[test]
    fn a_cancel_between_remove_and_the_old_key_check_leaves_the_host_unconfirmed() {
        // a's check is waiting to be retried, b's remove lands after the cancel
        let mut run = full(&named(&["a", "b"]));
        for step in [RotationStep::Deploy, RotationStep::Verify] {
            for id in [A, B] {
                run.begin_step(id);
                run.record_step(id, step, Ok(()));
            }
        }
        run.begin_step(A);
        run.record_step(A, RotationStep::Remove, Ok(()));
        run.begin_step(A);
        run.record_step(A, RotationStep::Confirm, fail("x"));
        run.retry(A);
        run.begin_step(B);
        run.cancel();
        run.record_step(B, RotationStep::Remove, Ok(()));
        assert_eq!(
            kinds(&run),
            pairs(&[(A, "unconfirmed"), (B, "unconfirmed")]),
            "nobody checked the old key"
        );
    }

    #[test]
    fn a_retried_host_resumes_at_the_step_that_failed() {
        let fail_verify = std::cell::Cell::new(true);
        let seen = std::cell::RefCell::new(Vec::new());
        let answer = |id: &str, step: RotationStep| {
            seen.borrow_mut().push((id.to_owned(), step));
            if id == A && step == RotationStep::Verify && fail_verify.get() {
                fail("timeout")
            } else {
                Ok(())
            }
        };
        let mut run = full(&named(&["a", "b"]));
        drive(&mut run, answer);
        fail_verify.set(false);
        seen.borrow_mut().clear();
        run.retry(A);
        drive(&mut run, answer);
        let a = |s: RotationStep| (A.to_owned(), s);
        assert_eq!(
            (seen.take(), run.state(A)),
            (
                vec![
                    a(RotationStep::Verify),
                    a(RotationStep::Remove),
                    a(RotationStep::Confirm)
                ],
                Some(&TargetState::Switched)
            ),
            "verify again, then on"
        );
    }

    #[test]
    fn no_host_reaches_remove_without_a_passed_verify_whatever_the_results() {
        // xorshift64: a seeded generator, so a failure reproduces.
        let mut seed: u64 = 0x5eed;
        let mut rand = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            usize::try_from(seed % 1000).unwrap()
        };
        let p = named(&["a", "b", "c", "d", "e"]);
        let ids: Vec<String> = p.targets.iter().map(|t| t.id.clone()).collect();
        let mut switched = 0_usize;
        for _ in 0..300 {
            let mut run = full(&p);
            let mut passed_verify = BTreeSet::new();
            for _ in 0..60 {
                let running: Vec<(String, RotationStep)> = run
                    .states()
                    .filter_map(|(id, s)| {
                        if let TargetState::Running { step } = s {
                            Some((id.to_owned(), *step))
                        } else {
                            None
                        }
                    })
                    .collect();
                let failed: Vec<String> = run
                    .states()
                    .filter(|(_, s)| matches!(s, TargetState::Failed { .. }))
                    .map(|(id, _)| id.to_owned())
                    .collect();
                let startable = run.startable();
                let r = rand();
                if r < 400 && !startable.is_empty() {
                    let (id, _) = &startable[rand() % startable.len()];
                    run.begin_step(id);
                } else if r < 850 && !running.is_empty() {
                    let (id, step) = &running[rand() % running.len()];
                    let ok = rand() < 700;
                    if ok && *step == RotationStep::Verify && !run.cancelled() {
                        passed_verify.insert(id.clone());
                    }
                    run.record_step(id, *step, if ok { Ok(()) } else { fail("e") });
                } else if r < 950 && !failed.is_empty() {
                    run.retry(&failed[rand() % failed.len()]);
                } else if r >= 990 {
                    run.cancel();
                } else {
                    // an arbitrary begin, allowed or not
                    run.begin_step(&ids[rand() % ids.len()]);
                }
                for (id, s) in run.states() {
                    let removed = matches!(
                        s,
                        TargetState::Running {
                            step: RotationStep::Remove
                        } | TargetState::Switched
                    );
                    assert!(
                        !removed || passed_verify.contains(id),
                        "{id} reached remove without a passed verify"
                    );
                }
            }
            switched += run
                .states()
                .filter(|(_, s)| **s == TargetState::Switched)
                .count();
        }
        assert!(switched > 0, "the sweep did exercise remove");
    }

    #[test]
    fn a_machine_is_safe_to_finish_only_once_the_candidate_logged_in_there() {
        let p = named(&["a", "b", "c"]);
        let (a, b, c) = (
            "root@a.example:22",
            "root@b.example:22",
            "root@c.example:22",
        );
        let mut run = full(&p);
        drive(&mut run, |id, step| {
            let bad = (id == a && step == RotationStep::Deploy)
                || (id == c && step == RotationStep::Confirm);
            if bad {
                fail("x")
            } else {
                Ok(())
            }
        });
        assert_eq!(
            (run.state(b), run.finish_outlook(&p)),
            (
                Some(&TargetState::Switched),
                FinishOutlook {
                    unproven: vec![a.to_owned()],
                    cut_off: Vec::new(),
                    old_not_refused: vec![c.to_owned()],
                }
            ),
            "a locked out, c may still take the old key"
        );
    }

    #[test]
    fn an_interrupted_finish_is_recognised_by_the_key_item_holding_the_candidate() {
        let keys = |old: &str| RotationKeys {
            old: old.to_owned(),
            candidate: "ssh-ed25519 AAAANEW rotation\n".to_owned(),
            candidate_id: "k (rotation)".to_owned(),
        };
        assert_eq!(
            (
                keys("ssh-ed25519 AAAANEW user@laptop").committed(),
                keys("ssh-ed25519 AAAAOLD user@laptop").committed()
            ),
            (true, false),
            "compared by type and blob"
        );
    }

    #[test]
    fn a_run_scoped_to_verify_leaves_each_proven_target_waiting_with_nothing_removed() {
        let p = named(&["a", "b"]);
        let scope = RunScope {
            last: RotationStep::Verify,
            ..RunScope::full()
        };
        let mut run = RotationRun::start(&p, &scope);
        let mut seen = BTreeSet::new();
        drive(&mut run, |id, step| {
            seen.insert(step);
            if id == B {
                fail("x")
            } else {
                Ok(())
            }
        });
        assert_eq!(
            (
                seen.into_iter().collect::<Vec<_>>(),
                kinds(&run),
                run.is_verified(A),
                run.settled()
            ),
            (
                vec![RotationStep::Deploy, RotationStep::Verify],
                pairs(&[(A, "pending:remove"), (B, "failed:deploy")]),
                true,
                true
            ),
            "deploy and verify only"
        );
    }

    #[test]
    fn a_run_may_start_at_verify_and_then_goes_on_to_remove_and_confirm() {
        let p = named(&["a"]);
        let scope = RunScope {
            first: RotationStep::Verify,
            ..RunScope::full()
        };
        let mut run = RotationRun::start(&p, &scope);
        let mut seen = Vec::new();
        drive(&mut run, |_, step| {
            seen.push(step);
            Ok(())
        });
        assert_eq!(
            (seen, kinds(&run)),
            (
                vec![
                    RotationStep::Verify,
                    RotationStep::Remove,
                    RotationStep::Confirm
                ],
                pairs(&[(A, "switched")])
            ),
            "no deploy"
        );
    }

    #[test]
    fn a_run_of_chosen_targets_leaves_the_others_out() {
        let p = named(&["a", "b"]);
        let scope = RunScope {
            only: Some(BTreeSet::from([B.to_owned()])),
            ..RunScope::full()
        };
        let run = RotationRun::start(&p, &scope);
        assert_eq!(
            (run.state(A), kinds(&run)),
            (None, pairs(&[(B, "pending:deploy")])),
            "only b"
        );
    }

    #[test]
    fn a_run_extended_past_verify_removes_only_where_verify_passed() {
        let p = named(&["a", "b"]);
        let scope = RunScope {
            first: RotationStep::Verify,
            last: RotationStep::Verify,
            only: None,
        };
        let mut run = RotationRun::start(&p, &scope);
        drive(&mut run, |id, _| if id == B { fail("x") } else { Ok(()) });
        run.extend_to(RotationStep::Confirm);
        let mut seen = Vec::new();
        drive(&mut run, |id, step| {
            seen.push((id.to_owned(), step));
            Ok(())
        });
        assert_eq!(
            (seen, kinds(&run)),
            (
                vec![
                    (A.to_owned(), RotationStep::Remove),
                    (A.to_owned(), RotationStep::Confirm)
                ],
                pairs(&[(A, "switched"), (B, "failed:verify")])
            ),
            "b stays on the old key"
        );
    }

    /// A bastion that logs in with the key, and a host behind it that does too.
    fn behind_bastion() -> (RotationPlan, &'static str, &'static str) {
        let p = plan(vec![
            host("bastion", key(), Vec::new()),
            host("db", key(), vec![ref_hop("bastion")]),
        ]);
        (
            p,
            "root@bastion.example:22",
            "root@db.example:22 via root@bastion.example:22",
        )
    }

    #[test]
    fn a_target_behind_a_key_hop_starts_only_once_that_hop_has_verified() {
        let (p, bastion, db) = behind_bastion();
        // As `unissh keys rotation finish` resumes a rotation whose earlier run
        // may already have taken the old key off the bastion.
        let scope = RunScope {
            first: RotationStep::Verify,
            ..RunScope::full()
        };
        let mut run = RotationRun::start(&p, &scope);
        let first = run.startable();
        run.begin_step(bastion);
        run.record_step(bastion, RotationStep::Verify, Ok(()));
        assert_eq!(
            (first, run.startable(), run.is_verified(bastion)),
            (
                vec![(bastion.to_owned(), RotationStep::Verify)],
                vec![(db.to_owned(), RotationStep::Verify)],
                true
            ),
            "db waits for the bastion, then goes through it with the candidate"
        );
        // A step under way through the bastion holds back the bastion's remove.
        run.begin_step(db);
        run.record_step(db, RotationStep::Verify, Ok(()));
        run.begin_step(db);
        assert_eq!(
            run.startable(),
            Vec::new(),
            "no remove on the bastion while db's remove runs through it"
        );
    }

    #[test]
    fn a_machine_behind_an_unproven_hop_is_locked_out_too() {
        let (p, bastion, db) = behind_bastion();
        let mut run = full(&p);
        drive(&mut run, |id, step| {
            if id == bastion && step == RotationStep::Verify {
                fail("x")
            } else {
                Ok(())
            }
        });
        let outlook = run.finish_outlook(&p);
        assert_eq!(
            (
                outlook.clone(),
                outlook.locked_out().cloned().collect::<Vec<_>>()
            ),
            (
                FinishOutlook {
                    unproven: vec![bastion.to_owned()],
                    cut_off: vec![db.to_owned()],
                    old_not_refused: Vec::new(),
                },
                vec![bastion.to_owned(), db.to_owned()]
            ),
            "db took the new key through the bastion's old one"
        );
    }

    #[test]
    fn the_hosts_following_a_machine_are_those_that_hop_through_it_only() {
        let p = plan(vec![
            host("bastion", key(), Vec::new()),
            host("db", ProfileAuth::PromptPassword, vec![ref_hop("bastion")]),
            host("web", key(), vec![ref_hop("bastion")]),
            host("cache", ProfileAuth::PromptPassword, Vec::new()),
        ]);
        let labels = |id: &str| {
            p.dependents_of(id)
                .into_iter()
                .map(|h| h.label.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            (
                labels("root@bastion.example:22"),
                labels("root@web.example:22 via root@bastion.example:22")
            ),
            (vec!["db".to_owned()], Vec::<String>::new()),
            "web is a machine of its own, cache does not hop"
        );
    }

    #[test]
    fn a_target_is_unpinned_until_it_and_every_hop_in_front_have_a_host_key() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::new(
            dir.path().join("i.db").to_string_lossy().into_owned(),
            dir.path().join("i.keyset").to_string_lossy().into_owned(),
        );
        core.create_account(None).unwrap();
        core.create_vault("v".to_owned(), "V".to_owned()).unwrap();
        // Any valid public key serves as a host key.
        let line = core
            .generate_ssh_key("v".to_owned(), "hostkey".to_owned())
            .unwrap();
        let host_key = line
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        let pin = |host: &str| {
            core.import_known_hosts(format!("{host} {host_key}"))
                .unwrap();
        };
        let p = plan(vec![host("db", key(), vec![inline_hop("jump", "x")])]);
        let db = vec!["root@db.example:22 via ops@jump.example:22".to_owned()];
        let unpinned = || core.key_rotation_unpinned(&p).unwrap();
        let before = unpinned();
        pin("db.example");
        let hop_unpinned = unpinned();
        pin("jump.example");
        assert_eq!(
            (before, hop_unpinned, unpinned()),
            (db.clone(), db, Vec::new()),
            "the machine, then the hop in front of it"
        );
    }

    // ---------- the steps ----------

    fn result(exit_status: i32) -> MultiExecResult {
        MultiExecResult {
            host: "h".to_owned(),
            stdout: String::new(),
            stderr: String::new(),
            exit_status,
            error: None,
            duration_ms: 0,
            timed_out: false,
            key_login: None,
        }
    }

    fn failed_login(error: &str, key_login: Option<KeyLoginFailure>) -> MultiExecResult {
        MultiExecResult {
            error: Some(error.to_owned()),
            key_login,
            ..result(-1)
        }
    }

    fn refused() -> MultiExecResult {
        failed_login("the server refused the key", Some(KeyLoginFailure::Refused))
    }

    fn needs_more() -> MultiExecResult {
        failed_login(
            "the server accepted the key but requires further authentication",
            Some(KeyLoginFailure::AcceptedNeedsMore),
        )
    }

    /// A hop that failed, the network, a lock: says nothing about the key.
    fn unreachable_host() -> MultiExecResult {
        failed_login("connection reset", None)
    }

    /// Runs `step`, answering each exec by the login it was made with, and
    /// returns the outcome and the logins made.
    fn step(
        step: RotationStep,
        mut answers: Vec<(RotationStep, MultiExecResult)>,
        resumed: bool,
    ) -> (StepOutcome, Vec<RotationStep>) {
        let keys = RotationKeys {
            old: "ssh-ed25519 AAAAOLD".to_owned(),
            candidate: "ssh-ed25519 AAAACAND".to_owned(),
            candidate_id: "cand".to_owned(),
        };
        let mut logins = Vec::new();
        let out = run_step(step, &keys, resumed, &mut |as_step, _cmd| {
            logins.push(as_step);
            let at = answers.iter().position(|(s, _)| *s == as_step);
            Ok(at.map(|i| answers.remove(i).1))
        });
        (out, logins)
    }

    fn passed(logins: &[RotationStep]) -> (StepOutcome, Vec<RotationStep>) {
        (Ok(()), logins.to_vec())
    }

    #[test]
    fn verify_counts_the_candidate_proven_when_the_server_takes_it_and_asks_for_more() {
        let verify = |r| step(RotationStep::Verify, vec![(RotationStep::Verify, r)], false).0;
        assert_eq!(
            [verify(result(0)), verify(needs_more()), verify(refused())],
            [Ok(()), Ok(()), fail("the server refused the key")],
            "accepted, accepted with a second factor, refused"
        );
    }

    #[test]
    fn remove_says_what_it_left_behind_and_makes_no_old_key_login_of_its_own() {
        let remove = |r| step(RotationStep::Remove, vec![(RotationStep::Remove, r)], false);
        let stderr = MultiExecResult {
            stderr: "new key is not in authorized_keys\n".to_owned(),
            ..result(1)
        };
        let once = vec![RotationStep::Remove];
        assert_eq!(
            [
                remove(result(0)),
                remove(result(3)),
                remove(result(4)),
                remove(stderr)
            ],
            [
                passed(&once),
                (Err(StepFailure::OldKeyStillPresent), once.clone()),
                (Err(StepFailure::NoAuthorizedKeys), once.clone()),
                (fail("new key is not in authorized_keys"), once.clone()),
            ],
            "one login each"
        );
    }

    #[test]
    fn remove_on_a_host_that_wants_a_second_factor_passes_only_once_the_old_key_is_refused() {
        let remove = |old| {
            let answers = vec![
                (RotationStep::Remove, needs_more()),
                (RotationStep::Confirm, old),
            ];
            step(RotationStep::Remove, answers, false).0
        };
        assert_eq!(
            [
                remove(refused()),
                remove(needs_more()),
                remove(unreachable_host())
            ],
            [
                Ok(()),
                Err(StepFailure::RemoveNeedsSecondFactor),
                // Not "remove it by hand": nobody learned whether the old key still works.
                Err(StepFailure::OldKeyCheckFailed {
                    message: Some("connection reset".to_owned())
                }),
            ],
            "the old key decides"
        );
    }

    #[test]
    fn confirm_passes_only_on_a_refusal_and_tells_a_key_still_accepted_from_a_failed_check() {
        let confirm = |r| {
            step(
                RotationStep::Confirm,
                vec![(RotationStep::Confirm, r)],
                false,
            )
            .0
        };
        assert_eq!(
            [
                confirm(refused()),
                confirm(result(0)),
                confirm(needs_more()),
                confirm(unreachable_host())
            ],
            [
                Ok(()),
                Err(StepFailure::OldKeyStillAccepted),
                Err(StepFailure::OldKeyStillAccepted),
                Err(StepFailure::OldKeyCheckFailed {
                    message: Some("connection reset".to_owned())
                }),
            ],
            "refused, accepted, accepted with more, unknown"
        );
    }

    #[test]
    fn a_continued_deploy_logs_in_with_the_old_key_only_where_the_candidate_is_not_accepted_yet() {
        let (verify, deploy) = (RotationStep::Verify, RotationStep::Deploy);
        assert_eq!(
            [
                step(deploy, vec![(verify, needs_more())], true),
                step(deploy, vec![(verify, refused()), (deploy, result(0))], true),
                step(deploy, vec![(deploy, result(0))], false),
            ],
            [
                passed(&[verify]),
                passed(&[verify, deploy]),
                passed(&[deploy])
            ],
            "candidate first when continuing"
        );
    }

    #[test]
    fn an_exec_call_that_fails_lands_as_that_steps_failure() {
        let keys = RotationKeys {
            old: OLD.to_owned(),
            candidate: CAND.to_owned(),
            candidate_id: "cand".to_owned(),
        };
        let out = run_step(RotationStep::Confirm, &keys, false, &mut |_, _| {
            Err(StepFailure::Locked)
        });
        assert_eq!(
            out,
            Err(StepFailure::Locked),
            "the lock, not an old-key verdict"
        );
    }

    // ---------- connecting ----------

    /// The key item id an auth logs in with, empty for one that is no vault key.
    fn key_of(a: &AuthMethod) -> String {
        match a {
            AuthMethod::Agent { key_item_id, .. } => key_item_id.clone(),
            AuthMethod::Password { .. }
            | AuthMethod::VaultPassword { .. }
            | AuthMethod::SystemAgent { .. } => String::new(),
        }
    }

    #[test]
    fn steps_reach_a_target_through_hops_that_verified_and_prove_the_candidate_key_only() {
        let bastion = ConnectionProfile {
            proxy: Some(socks("px")),
            ..host("bastion", key(), Vec::new())
        };
        let p = plan(vec![
            bastion,
            host(
                "db",
                key(),
                vec![ref_hop("bastion"), inline_hop("mid", "k")],
            ),
        ]);
        let db = "root@db.example:22 via root@bastion.example:22 > ops@mid.example:22 \
                  proxy socks5://px:1080";
        let verified =
            BTreeSet::from(["root@bastion.example:22 proxy socks5://px:1080".to_owned()]);
        let deploy = step_connect(&p, &verified, db, RotationStep::Deploy, "cand").unwrap();
        let hops: Vec<(String, String, bool)> = deploy
            .jumps
            .iter()
            .map(|j| (j.host.clone(), key_of(&j.auth), j.hop_ref.is_some()))
            .collect();
        assert_eq!(
            (
                key_of(&deploy.auth),
                deploy.publickey_only,
                deploy.proxy.map(|x| x.host),
                hops
            ),
            (
                "k".to_owned(),
                false,
                Some("px".to_owned()),
                vec![
                    ("bastion.example".to_owned(), "cand".to_owned(), false),
                    ("mid.example".to_owned(), "k".to_owned(), false),
                ]
            ),
            "deploy: old key, the proven bastion written out inline with the candidate"
        );
        let verify = step_connect(&p, &verified, db, RotationStep::Verify, "cand").unwrap();
        assert_eq!(
            (key_of(&verify.auth), verify.publickey_only),
            ("cand".to_owned(), true),
            "verify: the candidate, key-only"
        );
    }

    #[test]
    fn the_old_key_check_is_a_key_only_login_with_it_through_hops_that_switched() {
        let p = plan(vec![
            host("bastion", key(), Vec::new()),
            host("db", key(), vec![ref_hop("bastion")]),
        ]);
        let verified = BTreeSet::from(["root@bastion.example:22".to_owned()]);
        let db = "root@db.example:22 via root@bastion.example:22";
        let confirm = step_connect(&p, &verified, db, RotationStep::Confirm, "cand").unwrap();
        assert_eq!(
            (
                key_of(&confirm.auth),
                confirm.publickey_only,
                confirm
                    .jumps
                    .iter()
                    .map(|j| key_of(&j.auth))
                    .collect::<Vec<_>>()
            ),
            ("k".to_owned(), true, vec!["cand".to_owned()]),
            "old key at the target, the candidate on the switched hop"
        );
    }
    #[test]
    fn a_personal_host_using_the_rotated_key_is_a_target_with_its_resolved_user() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::new(
            dir.path().join("i.db").to_string_lossy().into_owned(),
            dir.path().join("i.keyset").to_string_lossy().into_owned(),
        );
        core.create_account(None).unwrap();
        core.create_vault("v".into(), "V".into()).unwrap();
        core.create_identity(
            "v".into(),
            crate::Identity {
                identity_id: "me".into(),
                label: "Me".into(),
                user: "alice".into(),
                key_item_id: Some("k".into()),
                password_item_id: None,
            },
        )
        .unwrap();
        let profile = host("personal", ProfileAuth::Personal, Vec::new());
        core.save_connection("v".into(), profile.clone()).unwrap();
        let pin =
            core.personal_destination(profile.host.clone(), profile.port, None, Vec::new(), None);
        core.set_binding(
            "v".into(),
            crate::IdentityBinding {
                team_vault_id: "v".into(),
                profile_uid: profile.uid,
                identity_item_id: "me".into(),
                destination_pin: pin,
            },
            false,
        )
        .unwrap();
        let plan = core.plan_key_rotation("v".into(), "k".into()).unwrap();
        assert_eq!(plan.targets.len(), 1);
        assert_eq!(plan.targets[0].user, "alice");
        assert!(plan.skipped.is_empty());
    }
    #[test]
    fn an_unpinned_target_is_not_contacted_but_remains_in_the_lockout_warning() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::new(
            dir.path().join("i.db").to_string_lossy().into_owned(),
            dir.path().join("i.keyset").to_string_lossy().into_owned(),
        );
        core.create_account(None).unwrap();
        let plan = plan(vec![host("retired", key(), Vec::new())]);
        let scope = core
            .pinned_rotation_scope(&plan, &RunScope::full())
            .unwrap();
        let run = RotationRun::start(&plan, &scope);
        assert!(run.startable().is_empty());
        assert!(run.settled());
        assert_eq!(
            run.finish_outlook(&plan).unproven,
            vec!["root@retired.example:22"]
        );
    }
}
