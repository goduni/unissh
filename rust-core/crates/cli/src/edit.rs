//! What every vault edit shares: the vault it goes to, the flags that set or
//! clear a field, reading a secret it stores, and sending the change to the
//! server the way the app does after an edit.
//!
//! The item kinds (`hosts`, `groups`, `secrets`, `keys`, `identities`,
//! `snippets`) each map their own flags onto the core's records; finding an
//! item by name is [`take`] over [`crate::hosts::find_named`], the same
//! lookup `unissh ssh` uses for hosts.

use std::fmt::Write as _;
use std::io;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, ValueEnum};
use unissh_ffi::{Core, FfiError, FfiSyncTarget, VaultInfo};
use zeroize::Zeroizing;

use crate::device::{without_line_ending, Device};
use crate::failure::{Failure, Res};
use crate::home::read_private;
use crate::hosts::{find_named, Named};
use crate::server;
use crate::tty::{self, one_line, Tty};

/// `--vault`: the vault a command works in.
#[derive(Args, Clone, Default)]
pub struct VaultArg {
    /// The vault to work in, by name or id. Needed when the account has
    /// several; for an existing item it narrows where its name is looked up.
    #[arg(long, value_name = "VAULT")]
    pub vault: Option<String>,
}

impl VaultArg {
    /// The vault a new item goes into: the one `--vault` names, else
    /// `preferred` (the personal vault, for identities) when there is one,
    /// else the account's only vault.
    pub fn pick(&self, core: &Core, preferred: Option<&str>) -> Res<VaultInfo> {
        choose_vault(core.list_vaults()?, self.vault.as_deref(), preferred)
    }

    /// The id of the vault `--vault` names, when it names one: lookups of
    /// existing items keep to it.
    pub fn scope(&self, core: &Core) -> Res<Option<String>> {
        self.vault
            .as_deref()
            .map(|wanted| choose_vault(core.list_vaults()?, Some(wanted), None).map(|v| v.vault_id))
            .transpose()
    }
}

/// Whether an item of vault `vault_id` is within `scope` (no scope: all are).
pub fn in_scope(scope: Option<&str>, vault_id: &str) -> bool {
    scope.is_none_or(|s| s == vault_id)
}

/// The one of `items` that `query` names, taken out of the list: the item
/// whose id (`id_of`) is exactly `query` when only one is — so "web" beside
/// "web-2" is not ambiguous — else [`find_named`]'s lookup by name.
pub fn take<T: Named>(mut items: Vec<T>, query: &str, id_of: impl Fn(&T) -> &str) -> Res<T> {
    let mut exact = items
        .iter()
        .enumerate()
        .filter(|(_, item)| id_of(item) == query)
        .map(|(i, _)| i);
    let index = match (exact.next(), exact.next()) {
        (Some(only), None) => only,
        _ => {
            let found = find_named(&items, query)?;
            items
                .iter()
                .position(|item| std::ptr::eq(item, found))
                .ok_or_else(|| Failure::msg(format!("no {} matches \"{query}\"", T::KIND)))?
        }
    };
    Ok(items.swap_remove(index))
}

/// The vault `wanted` names (by name, any case, or by id), else `preferred`,
/// else the only one. Never a guess between several.
pub fn choose_vault(
    vaults: Vec<VaultInfo>,
    wanted: Option<&str>,
    preferred: Option<&str>,
) -> Res<VaultInfo> {
    let names = |vaults: &[VaultInfo]| {
        vaults
            .iter()
            .map(|v| format!("\"{}\"", one_line(&v.name)))
            .collect::<Vec<_>>()
            .join(", ")
    };
    if let Some(wanted) = wanted {
        let w = wanted.trim();
        let by_id = vaults.iter().position(|v| v.vault_id == w);
        let by_name: Vec<usize> = vaults
            .iter()
            .enumerate()
            .filter(|(_, v)| v.name.eq_ignore_ascii_case(w))
            .map(|(i, _)| i)
            .collect();
        let index = match (by_id, by_name.as_slice()) {
            (Some(i), _) => i,
            (None, [i]) => *i,
            (None, []) => {
                return Err(Failure::msg(format!(
                    "no vault is called \"{wanted}\"; this account has {}",
                    names(&vaults)
                )))
            }
            (None, several) => {
                let ids: Vec<String> = several
                    .iter()
                    .filter_map(|&i| vaults.get(i))
                    .map(|v| format!("{} (\"{}\")", v.vault_id, one_line(&v.name)))
                    .collect();
                return Err(Failure::msg(format!(
                    "several vaults are called \"{wanted}\"; name one by its id: {}",
                    ids.join(", ")
                )));
            }
        };
        return vaults
            .into_iter()
            .nth(index)
            .ok_or_else(|| Failure::msg("the vault list changed while it was read"));
    }
    if let Some(p) = preferred {
        if let Some(i) = vaults.iter().position(|v| v.vault_id == p) {
            return vaults
                .into_iter()
                .nth(i)
                .ok_or_else(|| Failure::msg("the vault list changed while it was read"));
        }
    }
    match vaults.len() {
        0 => Err(Failure::msg(
            "this account has no vault yet: create one in the UniSSH app",
        )),
        1 => vaults
            .into_iter()
            .next()
            .ok_or_else(|| Failure::msg("the vault list changed while it was read")),
        _ => Err(Failure::msg(format!(
            "this account has several vaults; choose one with --vault: {}",
            names(&vaults)
        ))),
    }
}

/// `on` or `off`, for a yes/no field that `edit` may leave alone.
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Switch {
    /// Turn it on.
    On,
    /// Turn it off.
    Off,
}

impl Switch {
    /// Whether it says on.
    pub const fn on(self) -> bool {
        matches!(self, Self::On)
    }
}

/// `a,b,c` as a list: trimmed, without empty entries or repeats. An empty
/// value is the empty list, which is how a list flag clears a field.
pub fn list(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for part in text.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        if !out.iter().any(|seen| seen == part) {
            out.push(part.to_owned());
        }
    }
    out
}

/// A text flag that clears its field when given empty.
pub fn clearable(text: &str) -> Option<String> {
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

/// An item id for something new labelled `label`, made the way the app makes
/// one: a readable slug of the label and the time in milliseconds, so two
/// devices creating "web" at once do not collide.
pub fn mint_id(label: &str, fallback: &str) -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    format!("{}-{millis}", slug(label, fallback))
}

/// `label` lowercased, every run of other characters one dash, at most 40
/// characters; `fallback` when nothing is left.
pub fn slug(label: &str, fallback: &str) -> String {
    let mut out = String::new();
    let mut gap = false;
    for c in label.chars().flat_map(char::to_lowercase) {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            if gap && !out.is_empty() {
                out.push('-');
            }
            gap = false;
            out.push(c);
        } else {
            gap = true;
        }
    }
    // Only ASCII went in, so any length is a character boundary.
    out.truncate(40);
    let out = out.trim_end_matches('-');
    if out.is_empty() {
        fallback.to_owned()
    } else {
        out.to_owned()
    }
}

/// Where a secret that is being stored comes from: the terminal unless the
/// user says otherwise. Never an argument.
#[derive(Args, Clone, Default)]
pub struct SecretFrom {
    /// Read the secret from stdin instead of asking on the terminal.
    #[arg(long)]
    pub stdin: bool,
    /// Read the secret from FILE, which only you may be able to read.
    #[arg(long, value_name = "FILE", conflicts_with = "stdin")]
    pub from_file: Option<PathBuf>,
}

/// What kind of secret is read.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// One line that is being set: asked twice on the terminal.
    New,
    /// Any text (a note): pasted on the terminal, kept as given from a file
    /// or stdin.
    Block,
}

impl SecretFrom {
    /// Whether the secret comes from somewhere other than the terminal.
    pub const fn given(&self) -> bool {
        self.stdin || self.from_file.is_some()
    }

    /// Reads the secret `what` ("the password"): from the file, stdin, or the
    /// terminal with `prompt`. Empty is refused: nothing is stored then.
    pub fn read(&self, what: &str, prompt: &str, shape: Shape) -> Res<Zeroizing<String>> {
        let mut text = if let Some(path) = &self.from_file {
            read_private(path)?
                .ok_or_else(|| Failure::msg(format!("{} does not exist", path.display())))?
        } else if self.stdin {
            read_secret(tty::read_stdin)?
        } else {
            ask(what, prompt, shape)?
        };
        if shape != Shape::Block || !self.given() {
            // One trailing line ending is the file's (or the Enter's), not
            // the secret's — the rule `--password-file` follows.
            let keep = without_line_ending(&text).len();
            text.truncate(keep);
        }
        if text.is_empty() {
            return Err(Failure::msg(format!("{what} is empty; nothing was stored")));
        }
        Ok(text)
    }
}

fn ask(what: &str, prompt: &str, shape: Shape) -> Res<Zeroizing<String>> {
    let mut tty = Tty::open().map_err(|e| {
        Failure::msg(format!(
            "no terminal to ask for {what} ({e}); pass --stdin or --from-file"
        ))
    })?;
    Ok(match shape {
        Shape::New => tty.new_secret(prompt)?,
        Shape::Block => {
            tty.say(&format!(
                "{prompt}type or paste it; nothing is shown, a dot per line. \
                 An empty line or Ctrl-D ends it.\n"
            ))?;
            tty.pasted_secret(|_| false)?
        }
    })
}

/// The least room each read of stdin gets: the size of std's stdin buffer.
/// A read at least that large goes past std's buffer, which is never wiped,
/// so no part of a secret is left in it.
const STDIN_READ: usize = 8 * 1024;

/// All of stdin, for a secret, from `read` ([`tty::read_stdin`]). On Unix
/// that reads the descriptor itself; elsewhere it reads through std's stdin,
/// whose buffer a read of [`STDIN_READ`] or more skips, so each read is given
/// at least that much room, also after a short read.
///
/// The secret goes into a buffer that is wiped when it is dropped; when the
/// room left is less than [`STDIN_READ`], a buffer twice the size takes over
/// and the old one is wiped, so no copy of the secret is left behind in freed
/// memory. (`read_to_string` would grow its string by reallocating, leaving
/// each smaller copy unwiped.)
fn read_secret(mut read: impl FnMut(&mut [u8]) -> io::Result<usize>) -> Res<Zeroizing<String>> {
    let mut buf = Zeroizing::new(vec![0_u8; STDIN_READ]);
    let mut filled = 0_usize;
    loop {
        if buf.len().saturating_sub(filled) < STDIN_READ {
            let mut bigger = Zeroizing::new(vec![0_u8; buf.len().saturating_mul(2)]);
            if let (Some(to), Some(from)) = (bigger.get_mut(..filled), buf.get(..filled)) {
                to.copy_from_slice(from);
            }
            buf = bigger;
        }
        let Some(rest) = buf.get_mut(filled..) else {
            break;
        };
        match read(rest) {
            Ok(0) => break,
            Ok(n) => filled = filled.saturating_add(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    buf.truncate(filled);
    // `from_utf8` takes the bytes over without copying them.
    match String::from_utf8(std::mem::take(&mut *buf)) {
        Ok(text) => Ok(Zeroizing::new(text)),
        Err(e) => {
            drop(Zeroizing::new(e.into_bytes()));
            Err(Failure::msg("what came on stdin is not text (UTF-8)"))
        }
    }
}

/// Rows as aligned columns, each cell on one line without control characters
/// (they come from the vault) and at most 40 characters wide; the last
/// column is not padded.
pub fn columns(rows: &[Vec<String>]) -> String {
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|row| row.iter().map(String::as_str).map(one_line).collect())
        .collect();
    let count = cells.iter().map(Vec::len).max().unwrap_or(0);
    let widths: Vec<usize> = (0..count)
        .map(|i| {
            cells
                .iter()
                .filter_map(|row| row.get(i))
                .map(|c| c.chars().count())
                .max()
                .unwrap_or(0)
                .min(40)
        })
        .collect();
    let mut text = String::new();
    for row in &cells {
        let last = row.len().saturating_sub(1);
        for (i, cell) in row.iter().enumerate() {
            if i == last {
                text.push_str(cell);
            } else {
                let width = widths.get(i).copied().unwrap_or(0);
                let _ = write!(text, "{cell:<width$}  ");
            }
        }
        text.push('\n');
    }
    text
}

/// Prints `value` as JSON for scripts. Callers put names and ids in it, never
/// a secret.
pub fn print_json(value: &serde_json::Value) -> Res<()> {
    let text = serde_json::to_string_pretty(value).map_err(|e| Failure::msg(e.to_string()))?;
    println!("{text}");
    Ok(())
}

/// What a write to vault `vault_name` failed with, saying which vault: the
/// core's own words name no vault, and a command may write to several.
pub fn stored<T>(vault_name: &str, result: Result<T, FfiError>) -> Res<T> {
    result.map_err(|e| {
        let mut failure = Failure::from(e);
        failure.message = format!("vault \"{}\": {}", one_line(vault_name), failure.message);
        failure
    })
}

/// Whether vault `vault_id` syncs with a server. One this device no longer
/// lists is taken to: the sync then says what became of it.
pub fn syncs(core: &Core, vault_id: &str) -> Res<bool> {
    Ok(core
        .list_vaults()?
        .iter()
        .find(|v| v.vault_id == vault_id)
        .is_none_or(|v| v.sync_target == FfiSyncTarget::Cloud))
}

/// Sends a change just written to vault `vault_id` to the server, as the app
/// does after an edit, and says so with `done` ("Added host web"): see
/// [`server::push_after_write`] for where the change then stands.
pub fn commit(device: &Device, vault_id: &str, offline: bool, done: &str) -> Res<()> {
    let cloud = syncs(&device.core, vault_id)?;
    server::push_after_write(device, cloud, offline, done)
}

#[cfg(test)]
mod tests {
    use super::{choose_vault, list, read_secret, slug, take, STDIN_READ};
    use crate::hosts::Named;
    use std::io::Read as _;
    use unissh_ffi::{FfiSyncTarget, VaultInfo};

    struct Item(&'static str);

    impl Named for Item {
        const KIND: &'static str = "item";
        const KINDS: &'static str = "items";
        const LISTED_BY: Option<&'static str> = None;

        fn vault_name(&self) -> &str {
            "v"
        }

        fn label(&self) -> &str {
            self.0
        }
    }

    fn vault(id: &str, name: &str) -> VaultInfo {
        VaultInfo {
            vault_id: id.to_owned(),
            name: name.to_owned(),
            sync_target: FfiSyncTarget::Cloud,
            sync_tenant: None,
        }
    }

    /// The only vault, or the one named (by name in any case, or id), or the
    /// preferred one; several without a name are refused with their names.
    #[test]
    fn a_vault_is_chosen_by_name_id_preference_or_being_the_only_one() {
        let chosen = |vaults: Vec<VaultInfo>, wanted: Option<&str>, preferred: Option<&str>| {
            choose_vault(vaults, wanted, preferred)
                .map(|v| v.vault_id)
                .map_err(|e| e.message)
        };
        let two = || vec![vault("a1", "Team"), vault("b2", "Lab")];
        assert_eq!(chosen(vec![vault("a1", "Team")], None, None).unwrap(), "a1");
        assert_eq!(chosen(two(), Some("lab"), None).unwrap(), "b2");
        assert_eq!(chosen(two(), Some("a1"), None).unwrap(), "a1");
        assert_eq!(chosen(two(), None, Some("b2")).unwrap(), "b2");
        let several = chosen(two(), None, None).unwrap_err();
        assert!(several.contains("\"Team\", \"Lab\""), "{several}");
        assert!(chosen(two(), Some("prod"), None).is_err());
        let twins = vec![vault("a1", "Team"), vault("b2", "team")];
        assert!(chosen(twins, Some("TEAM"), None).is_err(), "never a guess");
    }

    /// A list flag trims, drops blanks and repeats; empty clears.
    #[test]
    fn a_list_flag_reads_as_a_clean_list_and_empty_clears() {
        assert_eq!(list(" prod, web ,,prod"), ["prod", "web"]);
        assert!(list("").is_empty());
    }

    /// Ids look like the app's: `web-server-<millis>`, and a label of only
    /// punctuation falls back.
    #[test]
    fn a_slug_keeps_letters_and_digits_with_single_dashes() {
        assert_eq!(slug("  Web Server #2 ", "host"), "web-server-2");
        assert_eq!(slug("!!!", "host"), "host");
        assert_eq!(slug(&"a".repeat(50), "host").len(), 40);
    }

    /// An item whose id is exactly what was typed is the one meant, though
    /// another one's name begins with it.
    #[test]
    fn an_exact_id_is_taken_before_a_name_it_begins() {
        let items = || vec![Item("web-2"), Item("web")];
        assert_eq!(take(items(), "web", |i| i.0).unwrap().0, "web");
        assert!(take(vec![Item("web-2"), Item("web-3")], "web", |i| i.0).is_err());
    }

    /// A secret longer than the first buffer is read whole.
    #[test]
    fn a_secret_on_stdin_is_read_whole_past_the_first_buffer() {
        let long = "k".repeat(20_000);
        let mut input = long.as_bytes();
        assert_eq!(read_secret(|b| input.read(b)).unwrap().as_str(), long);
        let mut input = &[0xff_u8, 0xfe][..];
        assert!(read_secret(|b| input.read(b)).is_err(), "not text");
    }

    /// Every read gets room for a whole stdin buffer, also after short
    /// reads, so std never buffers part of the secret on the way.
    #[test]
    fn each_read_of_a_secret_has_room_for_a_whole_stdin_buffer() {
        let mut input = "k".repeat(20_000).into_bytes();
        let mut smallest = usize::MAX;
        let read = read_secret(|b| {
            smallest = smallest.min(b.len());
            let n = input.len().min(b.len()).min(3_000);
            b[..n].copy_from_slice(&input[..n]);
            input.drain(..n);
            Ok(n)
        })
        .unwrap();
        assert_eq!(read.len(), 20_000);
        assert!(
            smallest >= STDIN_READ,
            "a read got {smallest} bytes of room"
        );
    }
}
