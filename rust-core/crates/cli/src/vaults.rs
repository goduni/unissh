//! `unissh vaults`: the vaults on this machine, and trusting the owner of a
//! vault a teammate shared.
//!
//! Sync verifies a teammate's vault against its owner's key, and this machine
//! learns that key only from the user: the server is never trusted to say who
//! owns a vault. Until then the vault waits on the server. `unissh vaults
//! trust` shows the owner's fingerprint, as the vault's signed membership
//! proves it, next to the name the server's directory claims for that key;
//! the user compares the fingerprint with the one the owner reads out from
//! their own device (`unissh status`, or the app) over a channel they trust,
//! types or pastes it, and only then is the owner pinned and the vault pulled.

use clap::Subcommand;
use serde_json::{json, Value};
use unissh_cloud::dto::DirectoryEntry;
use unissh_cloud::shared::{pending_shared_vaults, PendingVault};
use unissh_cloud::transport::HttpSyncTransport;
use unissh_ffi::{FfiMemberRole, FfiSyncTarget, FfiVaultTrust, SharedVaultInfo};

use crate::device::Device;
use crate::failure::{Failure, Res};
use crate::server;
use crate::tty::{one_line, Tty};

/// `unissh vaults`.
#[derive(Subcommand)]
pub enum VaultsAction {
    /// List the vaults on this machine, and the vaults shared with this
    /// account that wait for you to trust their owner.
    List {
        /// Print JSON (ids, names, owners' fingerprints; never a secret).
        #[arg(long)]
        json: bool,
    },
    /// Trust the owner of a vault a teammate shared, then fetch the vault.
    /// Compare the fingerprint shown with the one the owner reads out from
    /// their own device (`unissh status` there) before you accept it.
    Trust {
        /// The vault's id, or the start of it.
        vault: String,
        /// The owner's fingerprint, as they gave it to you; without it the
        /// fingerprint is asked on the terminal.
        #[arg(long, value_name = "FINGERPRINT")]
        fingerprint: Option<String>,
    },
}

/// Runs `action` on the unlocked device.
pub fn run(device: &Device, offline: bool, action: VaultsAction) -> Res<()> {
    match action {
        VaultsAction::List { json } => list(device, offline, json),
        VaultsAction::Trust { vault, fingerprint } => {
            if offline {
                return Err(Failure::msg(
                    "trusting a shared vault fetches it from the server: drop --offline",
                ));
            }
            trust(device, &vault, fingerprint.as_deref())
        }
    }
}

/// The vaults waiting for trust, read from the server.
fn pending(device: &Device) -> Res<Vec<PendingVault>> {
    let access = device.access()?;
    Ok(pending_shared_vaults(
        &device.core,
        &device.link.base_url,
        &access,
    )?)
}

/// `unissh vaults list`.
fn list(device: &Device, offline: bool, as_json: bool) -> Res<()> {
    let here = device.core.list_vaults()?;
    let waiting = if offline {
        Vec::new()
    } else {
        pending(device)?
    };
    if as_json {
        let mut rows: Vec<Value> = here
            .iter()
            .map(|v| {
                json!({
                    "vault_id": v.vault_id,
                    "name": v.name,
                    "kind": kind(v.sync_target),
                    "on_server": v.sync_tenant.is_some(),
                    "status": "here",
                })
            })
            .collect();
        rows.extend(waiting.iter().map(pending_json));
        let text = serde_json::to_string_pretty(&rows).map_err(|e| Failure::msg(e.to_string()))?;
        println!("{text}");
        return Ok(());
    }
    for v in &here {
        let place = match (v.sync_target, v.sync_tenant.is_some()) {
            (FfiSyncTarget::Local, _) => "local",
            (FfiSyncTarget::Cloud, true) => "synced",
            (FfiSyncTarget::Cloud, false) => "cloud, not on a server",
        };
        println!("{}  {}  ({place})", v.vault_id, one_line(&v.name));
    }
    if here.is_empty() && waiting.is_empty() {
        eprintln!("unissh: no vaults to show");
    }
    if !waiting.is_empty() {
        println!();
        println!("Shared with this account, waiting for you to trust the owner:");
        for p in &waiting {
            match &p.inspected {
                Ok(info) => println!(
                    "{}  {}, {}\n    owner fingerprint {}",
                    p.vault_id,
                    claimed(p.claimed_owner.as_ref()),
                    role(info.my_role),
                    grouped(&info.fingerprint)
                ),
                Err(e) => println!("{}  cannot be verified: {e}", p.vault_id),
            }
        }
        println!("Trust one with `unissh vaults trust <id>` after comparing the fingerprint with its owner.");
    }
    Ok(())
}

fn pending_json(p: &PendingVault) -> Value {
    match &p.inspected {
        Ok(info) => json!({
            "vault_id": p.vault_id,
            "status": "waiting_for_trust",
            "owner_ed25519": info.owner_ed25519_hex,
            "owner_fingerprint": info.fingerprint,
            "owner_claimed_handle": p.claimed_owner.as_ref().and_then(|d| d.handle.clone()),
            "owner_claimed_name": p.claimed_owner.as_ref().and_then(|d| d.display_name.clone()),
            "role": role(info.my_role),
            "pinned_to_another_owner": info.trust == FfiVaultTrust::PinnedToAnotherOwner,
        }),
        Err(e) => json!({
            "vault_id": p.vault_id,
            "status": "unverifiable",
            "error": e.to_string(),
        }),
    }
}

/// After `unissh sync`: names each vault that waits for trust, so the user
/// knows which one, whose, and what to do. Best effort: a failure is a
/// warning, the sync itself already went through.
pub fn name_pending(device: &Device) {
    let waiting = match pending(device) {
        Ok(waiting) => waiting,
        Err(e) => {
            eprintln!("unissh: could not check for vaults shared with this account: {e}");
            return;
        }
    };
    for p in &waiting {
        match &p.inspected {
            Ok(info) => eprintln!(
                "unissh: vault {} is shared with this account by {}; it is not fetched until \
                 you trust its owner. Owner fingerprint: {}. Compare it with the owner's, then \
                 `unissh vaults trust {}`",
                p.vault_id,
                claimed(p.claimed_owner.as_ref()),
                grouped(&info.fingerprint),
                p.vault_id
            ),
            Err(e) => eprintln!(
                "unissh: vault {} is shared with this account but cannot be verified: {e}",
                p.vault_id
            ),
        }
    }
}

/// `unissh vaults trust`.
fn trust(device: &Device, spec: &str, given: Option<&str>) -> Res<()> {
    // One sync at a time: the pull below writes the vault in.
    let _one_at_a_time = device.home.sync_lock()?;
    let waiting = pending(device)?;
    let vault = pick(&waiting, spec)?;
    let info = vault
        .inspected
        .as_ref()
        .map_err(|e| Failure::msg(format!("vault {}: {e}", vault.vault_id)))?;
    if info.trust == FfiVaultTrust::PinnedToAnotherOwner {
        return Err(Failure::msg(format!(
            "this machine already trusts another owner for vault {}, and the server now \
             presents a different one (fingerprint {}). Nothing changed: talk to the vault's \
             owner before going further",
            vault.vault_id,
            grouped(&info.fingerprint)
        )));
    }
    let shown = describe(vault, info);
    let reply = match given {
        Some(typed) => {
            println!("{shown}");
            answer(typed, &info.fingerprint)
        }
        None => {
            let mut tty = Tty::open().map_err(|e| {
                Failure::msg(format!(
                    "cannot ask on the terminal ({e}); pass --fingerprint with the fingerprint \
                     the owner gave you"
                ))
            })?;
            tty.say(&shown)?;
            tty.say("\n")?;
            let typed = tty.line(
                "Paste the fingerprint the owner gave you, or type yes if you compared it \
                 digit by digit [no]: ",
            )?;
            answer(&typed, &info.fingerprint)
        }
    };
    match reply {
        Answer::Matches | Answer::Confirmed => {}
        Answer::Mismatch => {
            return Err(Failure::msg(
                "that is not the fingerprint this vault's owner signed it with. Nothing was \
                 trusted: someone may be posing as the owner. Check with the owner again",
            ))
        }
        Answer::Declined => return Err(Failure::msg("not trusted; nothing changed")),
    }
    device
        .core
        .pin_vault_genesis_owner(vault.vault_id.clone(), info.owner_ed25519_hex.clone())?;
    let access = device.access()?;
    let space = server::space_of(device, &access);
    let transport = HttpSyncTransport::new(device.link.base_url.clone(), access);
    let report = transport.pull_vault(&device.core, &space, &vault.vault_id)?;
    println!(
        "Trusted. Vault {} fetched: {} received.",
        vault.vault_id, report.applied
    );
    server::warn_about(&report);
    Ok(())
}

/// What the user is shown before deciding.
fn describe(vault: &PendingVault, info: &SharedVaultInfo) -> String {
    format!(
        "Vault {} is shared with this account ({}).\n\
         Owner, as the server names them: {}.\n\
         Owner fingerprint, as the vault's signatures prove it:\n    {}\n\
         Ask the owner for their fingerprint (`unissh status`, or the app, on their device) \
         over a channel you trust, and compare.",
        vault.vault_id,
        role(info.my_role),
        claimed(vault.claimed_owner.as_ref()),
        grouped(&info.fingerprint)
    )
}

/// The vault `spec` names among `waiting`: its id or the start of it.
fn pick<'a>(waiting: &'a [PendingVault], spec: &str) -> Res<&'a PendingVault> {
    let spec = spec.trim().to_ascii_lowercase();
    if spec.is_empty() {
        return Err(Failure::msg("name the vault by its id"));
    }
    let found: Vec<&PendingVault> = waiting
        .iter()
        .filter(|p| p.vault_id.to_ascii_lowercase().starts_with(&spec))
        .collect();
    match found.as_slice() {
        [one] => Ok(*one),
        [] => Err(Failure::msg(format!(
            "no vault shared with this account waits for trust under \"{spec}\" \
             (`unissh vaults list` shows them)"
        ))),
        many => Err(Failure::msg(format!(
            "\"{spec}\" names several vaults: {}",
            many.iter()
                .map(|p| p.vault_id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

/// What the user answered when asked to confirm a fingerprint.
#[derive(Debug, PartialEq, Eq)]
enum Answer {
    /// They typed or pasted the fingerprint, and it is the owner's.
    Matches,
    /// They typed `yes`: they compared the fingerprint shown.
    Confirmed,
    /// They typed or pasted a fingerprint that is not the owner's.
    Mismatch,
    /// Anything else, an empty line included: no.
    Declined,
}

/// Reads an answer: a fingerprint (spaces, colons and dashes ignored, any
/// case), `y`/`yes`, or anything else for no. A fingerprint must be the whole
/// of it: a prefix does not match.
fn answer(typed: &str, fingerprint: &str) -> Answer {
    let word = typed.trim().to_ascii_lowercase();
    if matches!(word.as_str(), "y" | "yes") {
        return Answer::Confirmed;
    }
    let digits: String = word
        .chars()
        .filter(|c| !c.is_whitespace() && !matches!(*c, ':' | '-'))
        .collect();
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        return Answer::Declined;
    }
    if digits == fingerprint.to_ascii_lowercase() {
        Answer::Matches
    } else {
        Answer::Mismatch
    }
}

/// A fingerprint in groups of four, easier to read out and compare.
pub fn grouped(fingerprint: &str) -> String {
    let chars: Vec<char> = fingerprint.chars().collect();
    chars
        .chunks(4)
        .map(|group| group.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Who the server claims owns a key: handle and name as its directory lists
/// them, worded as a claim.
fn claimed(entry: Option<&DirectoryEntry>) -> String {
    let handle = entry.and_then(|d| d.handle.as_deref()).map(one_line);
    let name = entry.and_then(|d| d.display_name.as_deref()).map(one_line);
    match (handle, name) {
        (Some(h), Some(n)) => format!("{h} ({n}, unverified)"),
        (Some(one), None) | (None, Some(one)) => format!("{one} (unverified)"),
        (None, None) => "an owner the server does not name".to_owned(),
    }
}

const fn role(of: FfiMemberRole) -> &'static str {
    match of {
        FfiMemberRole::Viewer => "you can view it",
        FfiMemberRole::Editor => "you can edit it",
        FfiMemberRole::Admin => "you administer it",
    }
}

const fn kind(target: FfiSyncTarget) -> &'static str {
    match target {
        FfiSyncTarget::Local => "local",
        FfiSyncTarget::Cloud => "cloud",
    }
}

#[cfg(test)]
mod tests {
    use super::{answer, claimed, grouped, Answer};
    use unissh_cloud::dto::DirectoryEntry;

    const FP: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// The user trusts only by typing the owner's whole fingerprint (in any
    /// grouping or case) or an explicit yes; a wrong or partial fingerprint is
    /// a mismatch, and anything else — Enter included — is no.
    #[test]
    fn only_the_whole_fingerprint_or_an_explicit_yes_trusts() {
        assert_eq!(answer(&grouped(FP).to_uppercase(), FP), Answer::Matches);
        assert_eq!(answer("01:23:45-67 89ab", FP), Answer::Mismatch, "a prefix");
        assert_eq!(answer("yes", FP), Answer::Confirmed);
        for no in ["", "no", "ok", "trust me"] {
            assert_eq!(answer(no, FP), Answer::Declined, "{no:?}");
        }
    }

    /// The owner the server names is always worded as its unverified claim.
    #[test]
    fn the_owner_the_server_names_reads_as_an_unverified_claim() {
        let entry = DirectoryEntry {
            account_id: "id".to_owned(),
            handle: Some("alice".to_owned()),
            display_name: Some("Alice".to_owned()),
            ed25519_pub_hex: String::new(),
            x25519_pub_hex: String::new(),
            status: "active".to_owned(),
        };
        assert_eq!(claimed(Some(&entry)), "alice (Alice, unverified)");
        assert_eq!(claimed(None), "an owner the server does not name");
    }
}
