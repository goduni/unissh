//! `unissh vaults`: the vaults on this machine, and trusting the owner of a
//! vault a teammate shared.
//!
//! Sync verifies a teammate's vault against its owner's key, and this machine
//! learns that key only from the user: the server is never trusted to say who
//! owns a vault. Until then the vault waits on the server. `unissh vaults
//! trust` asks for the owner's fingerprint as the owner gave it (they read it
//! from their own device: `unissh status`, or the app), and the core pins the
//! owner only if it is the fingerprint of the key that created the vault.
//! Without one, the fingerprint is shown and an explicit `yes` after
//! comparing it is needed — weaker, and said so. Then the vault is pulled.
//!
//! `unissh vaults discard-unpushable` drops the changes made here that the
//! server will not take and puts back the server's copy (#166).

use clap::Subcommand;
use serde_json::{json, Value};
use unissh_cloud::dto::DirectoryEntry;
use unissh_cloud::shared::{
    inspect_pending, pending_shared_vaults, waiting_vaults, PendingList, PendingVault,
};
use unissh_cloud::transport::HttpSyncTransport;
use unissh_ffi::{
    grouped_fingerprint, normalize_fingerprint, FfiMemberRole, FfiSyncTarget, FfiTrustOutcome,
    FfiUnpushableItem, FfiVaultTrust, SharedVaultInfo,
};

use crate::device::Device;
use crate::edit::choose_vault;
use crate::failure::{Failure, Res};
use crate::server;
use crate::tty::{self, one_line, Tty};

/// How many characters of the owner's handle or name the server claims are
/// shown: enough to recognise someone, not a page of text.
const CLAIM_CHARS: usize = 64;

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
    /// Ask the owner for their fingerprint (`unissh status` on their device,
    /// or the app) over a channel you trust, and give it when asked.
    Trust {
        /// The vault's id, or the start of it.
        vault: String,
        /// The owner's fingerprint, as they gave it to you; without it the
        /// fingerprint is asked on the terminal.
        #[arg(long, value_name = "FINGERPRINT")]
        fingerprint: Option<String>,
    },
    /// Drop the changes made on this machine in a vault that the server will
    /// not take (an edit made while this account could only view the vault),
    /// after sending them once more, and put back the server's copy of those
    /// items. Other members' such changes are kept and no longer sent; other
    /// changes not sent yet are kept.
    #[command(name = "discard-unpushable")]
    DiscardUnpushable {
        /// The vault, by name or id.
        vault: String,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
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
        VaultsAction::DiscardUnpushable { vault, yes } => {
            discard_unpushable(device, offline, &vault, yes)
        }
    }
}

/// The vaults waiting for trust, each inspected, read from the server.
fn pending(device: &Device) -> Res<PendingList> {
    let access = device.access()?;
    Ok(pending_shared_vaults(
        &device.core,
        &device.link.base_url,
        &access,
    )?)
}

/// `unissh vaults list`. The server is asked only for the vaults that wait;
/// when it cannot be reached, this machine's vaults are still listed.
fn list(device: &Device, offline: bool, as_json: bool) -> Res<()> {
    let here = device.core.list_vaults()?;
    let waiting = if offline {
        None
    } else {
        match pending(device) {
            Ok(waiting) => Some(waiting),
            Err(e) => {
                eprintln!(
                    "unissh: could not ask the server for vaults shared with this account \
                     ({}); showing this machine's vaults only",
                    one_line(&e.to_string())
                );
                None
            }
        }
    };
    let waiting = waiting.unwrap_or_default();
    if waiting.malformed > 0 {
        eprintln!(
            "unissh: the server listed {} vault(s) under a malformed id; they were ignored",
            waiting.malformed
        );
    }
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
        rows.extend(waiting.vaults.iter().map(pending_json));
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
        println!(
            "{}  {}  ({place})",
            one_line(&v.vault_id),
            one_line(&v.name)
        );
    }
    if here.is_empty() && waiting.vaults.is_empty() {
        eprintln!("unissh: no vaults to show");
    }
    if !waiting.vaults.is_empty() {
        println!();
        println!("Shared with this account, not on this machine yet:");
        for p in &waiting.vaults {
            println!("{}", pending_line(p));
        }
        println!(
            "Trust one with `unissh vaults trust <id>`, with the fingerprint its owner gives you."
        );
    }
    Ok(())
}

/// One waiting vault, for `vaults list`.
fn pending_line(p: &PendingVault) -> String {
    let id = one_line(&p.vault_id);
    match &p.inspected {
        Ok(info) => match info.trust {
            FfiVaultTrust::NotPinned => format!(
                "{id}  {}, {}; waits for you to trust its owner",
                claimed(p.claimed_owner.as_ref()),
                role(info.my_role)
            ),
            FfiVaultTrust::Pinned => {
                format!("{id}  trusted, not fetched yet: `unissh vaults trust {id}` fetches it")
            }
            FfiVaultTrust::PinnedToAnotherOwner => format!("{id}  {}", another_owner(&id, info)),
        },
        Err(e) => format!("{id}  cannot be verified: {}", one_line(e)),
    }
}

/// The loud warning for a vault the server now says someone else created.
fn another_owner(id: &str, info: &SharedVaultInfo) -> String {
    format!(
        "WARNING: the server now names a DIFFERENT owner for vault {id} than the one you \
         trusted on this machine (it presents fingerprint {}). The vault is not fetched and \
         nothing changed. Check with the vault's owner over a channel you trust before doing \
         anything else: the server, or someone who controls it, may be posing as them",
        grouped_fingerprint(info.fingerprint.clone())
    )
}

fn pending_json(p: &PendingVault) -> Value {
    match &p.inspected {
        Ok(info) => json!({
            "vault_id": p.vault_id,
            "status": status(info.trust),
            "owner_ed25519": info.owner_ed25519_hex,
            "owner_fingerprint": info.fingerprint,
            "owner_claimed_handle": claim_of(p, |d| d.handle.as_deref()),
            "owner_claimed_name": claim_of(p, |d| d.display_name.as_deref()),
            "role": role(info.my_role),
            "pinned_to_another_owner": info.trust == FfiVaultTrust::PinnedToAnotherOwner,
        }),
        Err(e) => json!({
            "vault_id": p.vault_id,
            "status": "unverifiable",
            "error": e,
        }),
    }
}

/// A waiting vault's `status` in `vaults list --json`.
const fn status(trust: FfiVaultTrust) -> &'static str {
    match trust {
        FfiVaultTrust::NotPinned => "waiting_for_trust",
        FfiVaultTrust::Pinned => "trusted_not_fetched",
        FfiVaultTrust::PinnedToAnotherOwner => "owner_changed",
    }
}

/// One field of the owner's directory entry, as [`capped`] shows it.
fn claim_of(p: &PendingVault, field: impl Fn(&DirectoryEntry) -> Option<&str>) -> Option<String> {
    p.claimed_owner.as_ref().and_then(field).map(capped)
}

/// After `unissh sync`: says how many shared vaults wait, from the server's
/// catalog minus this machine, each inspected as `vaults list` does — so a
/// vault this account created is not counted, and a server naming a
/// DIFFERENT owner for a pinned vault is said loudly. Only vaults that are
/// not on this machine are read, which is usually none. Best effort: a
/// failure is a warning, the sync itself already went through.
pub fn name_pending(device: &Device) {
    if let Err(e) = report_pending(device) {
        eprintln!("unissh: could not check for vaults shared with this account: {e}");
    }
}

fn report_pending(device: &Device) -> Res<()> {
    let waiting = pending(device)?;
    if waiting.malformed > 0 {
        eprintln!(
            "unissh: the server listed {} vault(s) under a malformed id; they were ignored",
            waiting.malformed
        );
    }
    let (mut untrusted, mut unverifiable) = (0_usize, 0_usize);
    for p in &waiting.vaults {
        let id = one_line(&p.vault_id);
        match &p.inspected {
            Ok(info) => match info.trust {
                FfiVaultTrust::NotPinned => untrusted = untrusted.saturating_add(1),
                FfiVaultTrust::Pinned => eprintln!(
                    "unissh: vault {id} is trusted but not fetched yet: `unissh vaults trust \
                     {id}` fetches it"
                ),
                FfiVaultTrust::PinnedToAnotherOwner => {
                    eprintln!("unissh: {}", another_owner(&id, info));
                }
            },
            Err(_) => unverifiable = unverifiable.saturating_add(1),
        }
    }
    if untrusted > 0 {
        eprintln!(
            "unissh: {untrusted} shared vault(s) wait for you to trust their owner — \
             `unissh vaults list`"
        );
    }
    if unverifiable > 0 {
        eprintln!(
            "unissh: {unverifiable} shared vault(s) cannot be verified — `unissh vaults list`"
        );
    }
    Ok(())
}

/// `unissh vaults trust`.
fn trust(device: &Device, spec: &str, given: Option<&str>) -> Res<()> {
    // Checked before anything is fetched: `--fingerprint yes` is not a fingerprint.
    let given = given.map(fingerprint_arg).transpose()?;
    // One sync at a time: the pull below writes the vault in.
    let _one_at_a_time = device.home.sync_lock()?;
    let access = device.access()?;
    let transport = HttpSyncTransport::new(device.link.base_url.clone(), access.clone());
    let waiting = waiting_vaults(&device.core, &transport)?;
    let ids: Vec<String> = waiting.vaults.into_iter().map(|v| v.vault_id).collect();
    let id = pick(&ids, spec)?.to_owned();
    let Some(vault) = inspect_pending(&device.core, &device.link.base_url, &access, &id)? else {
        return Err(Failure::msg(format!(
            "vault {id} was created by this account: it needs no trust, and a sync brings it"
        )));
    };
    let info = vault
        .inspected
        .as_ref()
        .map_err(|e| Failure::msg(format!("vault {id}: {}", one_line(e))))?;
    match info.trust {
        FfiVaultTrust::PinnedToAnotherOwner => return Err(Failure::msg(another_owner(&id, info))),
        // Trusted earlier, the pull did not finish: straight to the pull.
        FfiVaultTrust::Pinned => {}
        FfiVaultTrust::NotPinned => confirm(device, &transport, &vault, info, given)?,
    }
    let space = server::space_of(device, &access);
    let report = transport.pull_vault(&device.core, &space, &id)?;
    let fetched = device
        .core
        .list_vaults()?
        .iter()
        .any(|v| v.vault_id.eq_ignore_ascii_case(&id));
    if fetched {
        println!("Trusted. Vault {id} fetched: {} received.", report.applied);
    } else {
        println!(
            "Trusted, not fetched yet: run `unissh vaults trust {id}` again ({} received).",
            report.applied
        );
    }
    server::warn_about(&report);
    Ok(())
}

/// Asks for the owner's fingerprint (or takes `given`) and has the core pin
/// the owner if it is the creator's.
fn confirm(
    device: &Device,
    transport: &HttpSyncTransport,
    vault: &PendingVault,
    info: &SharedVaultInfo,
    given: Option<String>,
) -> Res<()> {
    let shown = describe(vault, info);
    // The core pins only against a fingerprint given here: the one the owner
    // gave, or the one shown and confirmed — never whatever it finds.
    let expected = if let Some(fingerprint) = given {
        println!("{shown}");
        fingerprint
    } else {
        let mut tty = Tty::open().map_err(|e| {
            Failure::msg(format!(
                "cannot ask on the terminal ({e}); pass --fingerprint with the fingerprint \
                 the owner gave you"
            ))
        })?;
        tty.say(&shown)?;
        tty.say("\n")?;
        let typed = tty.line(
            "Type or paste the fingerprint the owner gave you (press Enter if you have none): ",
        )?;
        match answer(&typed) {
            Answer::Fingerprint(fingerprint) => fingerprint,
            Answer::Empty => {
                tty.say(&displayed(info))?;
                tty.say("\n")?;
                let typed = tty.line("Type yes if it is exactly theirs, digit by digit [no]: ")?;
                if answer(&typed) != Answer::Yes {
                    return Err(Failure::msg("not trusted; nothing changed"));
                }
                info.fingerprint.clone()
            }
            Answer::Yes | Answer::Other => {
                return Err(Failure::msg(
                    "that is not a fingerprint (64 hex digits); nothing was trusted",
                ))
            }
        }
    };
    let outcome = transport.trust_vault(&device.core, &vault.vault_id, &expected)?;
    match outcome {
        FfiTrustOutcome::Trusted | FfiTrustOutcome::AlreadyTrusted => Ok(()),
        FfiTrustOutcome::FingerprintMismatch => Err(Failure::msg(
            "that is not the fingerprint of the key that created this vault. Nothing was \
             trusted: someone may be posing as the owner. Check with the owner again",
        )),
        FfiTrustOutcome::PinnedToAnotherOwner => Err(Failure::msg(another_owner(
            &one_line(&vault.vault_id),
            info,
        ))),
    }
}

/// What the user is shown before being asked for the owner's fingerprint.
/// The fingerprint itself is not in it: the user gives theirs first.
fn describe(vault: &PendingVault, info: &SharedVaultInfo) -> String {
    format!(
        "Vault {} is shared with this account ({}).\n\
         Owner, as the server names them: {}.\n\
         Ask the owner for their fingerprint over a channel you trust (they find it with \
         `unissh status`, or in the app, on their own device).",
        one_line(&vault.vault_id),
        role(info.my_role),
        claimed(vault.claimed_owner.as_ref()),
    )
}

/// The fingerprint shown when the user has none from the owner, and why
/// confirming it is the weaker check.
fn displayed(info: &SharedVaultInfo) -> String {
    format!(
        "The key that created this vault has the fingerprint\n    {}\n\
         Whether it is your teammate's is what you are checking. Confirming a fingerprint \
         shown here is weaker than typing the one they gave you: compare it with theirs, \
         digit by digit, over a channel you trust.",
        grouped_fingerprint(info.fingerprint.clone())
    )
}

/// The vault `spec` names among the waiting `ids`: its id or the start of it.
fn pick<'a>(ids: &'a [String], spec: &str) -> Res<&'a str> {
    let spec = spec.trim().to_ascii_lowercase();
    if spec.is_empty() {
        return Err(Failure::msg("name the vault by its id"));
    }
    let found: Vec<&str> = ids
        .iter()
        .map(String::as_str)
        .filter(|id| id.starts_with(&spec))
        .collect();
    match found.as_slice() {
        [one] => Ok(one),
        [] => Err(Failure::msg(format!(
            "no vault shared with this account waits under \"{}\" (`unissh vaults list` \
             shows them)",
            one_line(&spec)
        ))),
        many => Err(Failure::msg(format!(
            "\"{}\" names several vaults: {}",
            one_line(&spec),
            many.join(", ")
        ))),
    }
}

/// What the user typed when asked for the owner's fingerprint.
#[derive(Debug, PartialEq, Eq)]
enum Answer {
    /// A whole fingerprint (normalised: spaces, `:`, `-` and case dropped).
    Fingerprint(String),
    /// Exactly `yes` (any case): only taken after the fingerprint was shown.
    Yes,
    /// Nothing: the user has no fingerprint from the owner.
    Empty,
    /// Anything else, a part of a fingerprint or `y` included.
    Other,
}

/// Reads an answer. Whether a fingerprint is the owner's is the core's call
/// ([`unissh_ffi::Core::trust_shared_vault_paged`]); here it is only told
/// apart from the rest.
fn answer(typed: &str) -> Answer {
    let word = typed.trim();
    if word.is_empty() {
        Answer::Empty
    } else if word.eq_ignore_ascii_case("yes") {
        Answer::Yes
    } else {
        normalize_fingerprint(word).map_or(Answer::Other, Answer::Fingerprint)
    }
}

/// `--fingerprint`: only an actual fingerprint, never `yes` — a flag cannot
/// have compared anything the user was shown.
fn fingerprint_arg(given: &str) -> Res<String> {
    match answer(given) {
        Answer::Fingerprint(fingerprint) => Ok(fingerprint),
        Answer::Yes | Answer::Empty | Answer::Other => Err(Failure::msg(
            "--fingerprint takes the owner's fingerprint itself (64 hex digits), as they gave \
             it to you",
        )),
    }
}

/// `text` from the server, on one line and at most [`CLAIM_CHARS`] long.
fn capped(text: &str) -> String {
    let clean = one_line(text);
    if clean.chars().count() <= CLAIM_CHARS {
        return clean;
    }
    let mut short: String = clean.chars().take(CLAIM_CHARS).collect();
    short.push('…');
    short
}

/// Who the server claims owns a key: handle and name as its directory lists
/// them, worded as a claim.
fn claimed(entry: Option<&DirectoryEntry>) -> String {
    let handle = entry.and_then(|d| d.handle.as_deref()).map(capped);
    let name = entry.and_then(|d| d.display_name.as_deref()).map(capped);
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

/// `vaults discard-unpushable`: a sync first, so what is listed is what the
/// push cannot send as of now; then the core pushes once more, drops this
/// account's edits that are still refused, stops sending other members' ones
/// and puts back the server's copy.
fn discard_unpushable(device: &Device, offline: bool, wanted: &str, yes: bool) -> Res<()> {
    if offline {
        return Err(Failure::msg(
            "the server's copy is needed to put back: drop --offline",
        ));
    }
    let vault = choose_vault(device.core.list_vaults()?, Some(wanted), None)?;
    let name = one_line(&vault.name);
    if vault.sync_target != FfiSyncTarget::Cloud || vault.sync_tenant.is_none() {
        return Err(Failure::msg(format!(
            "vault \"{name}\" does not sync with a server, so nothing in it is held back"
        )));
    }
    let report = server::sync(device)?;
    let here: Vec<&FfiUnpushableItem> = report
        .unpushable
        .iter()
        .filter(|item| item.vault_id == vault.vault_id)
        .collect();
    if here.is_empty() {
        println!("Nothing to discard in vault \"{name}\": the server refuses no change held here.");
        return Ok(());
    }
    let list = |mine: bool| -> String {
        here.iter()
            .filter(|item| item.mine == mine)
            .map(|item| format!("  {}\n", server::unpushable_entry(item)))
            .collect()
    };
    let (ours, theirs) = (list(true), list(false));
    let mut prompt = String::new();
    if !ours.is_empty() {
        prompt.push_str(&format!(
            "These changes made on this machine in vault \"{name}\" cannot be sent to the \
             server:\n{ours}They are sent once more; the ones still refused are dropped, and \
             the server's copy of each item is put back (an item the server never had is \
             gone).\n"
        ));
    }
    if !theirs.is_empty() {
        prompt.push_str(&format!(
            "These changes by other members of vault \"{name}\" cannot be sent from here \
             either:\n{theirs}They are kept as they are and no longer sent.\n"
        ));
    }
    tty::confirm(yes, &prompt)?;
    let done = server::discard_unpushable(device, &vault.vault_id)?;
    if done.dropped == 0 && done.released == 0 {
        println!("Nothing was dropped: the changes went through when sent again.");
        return Ok(());
    }
    if done.dropped > 0 {
        println!(
            "Dropped {} change(s) made here; vault \"{name}\" has the server's copy again.",
            done.dropped
        );
    }
    if done.released > 0 {
        println!(
            "{} change(s) by other members are kept and no longer sent.",
            done.released
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{answer, claimed, fingerprint_arg, pick, Answer, CLAIM_CHARS};
    use unissh_cloud::dto::DirectoryEntry;
    use unissh_ffi::grouped_fingerprint;

    const FP: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// A whole fingerprint in any grouping or case is told apart from `yes`,
    /// an empty line, and the rest — a part of one and `y` included.
    #[test]
    fn an_answer_is_a_whole_fingerprint_yes_nothing_or_no() {
        assert_eq!(
            answer(&grouped_fingerprint(FP.to_owned()).to_uppercase()),
            Answer::Fingerprint(FP.to_owned())
        );
        assert_eq!(answer(" YES "), Answer::Yes);
        assert_eq!(answer("  "), Answer::Empty);
        for other in ["y", "01:23:45-67 89ab", "no", "trust me"] {
            assert_eq!(answer(other), Answer::Other, "{other:?}");
        }
    }

    /// `--fingerprint` takes a fingerprint only: `yes` on the command line
    /// compared nothing.
    #[test]
    fn the_fingerprint_flag_refuses_yes() {
        assert_eq!(fingerprint_arg(FP).unwrap(), FP);
        assert!(fingerprint_arg("yes").is_err());
    }

    /// A vault is named by its id or a unique start of it, in any case;
    /// an empty, unknown or ambiguous name picks none.
    #[test]
    fn a_vault_is_picked_by_a_unique_start_of_its_id() {
        let ids = [
            "aa110000000000000000000000000000".to_owned(),
            "aa220000000000000000000000000000".to_owned(),
        ];
        assert_eq!(pick(&ids, " AA1 ").unwrap(), ids[0]);
        assert!(pick(&ids, "aa").is_err(), "ambiguous");
        assert!(pick(&ids, "bb").is_err(), "unknown");
        assert!(pick(&ids, "").is_err(), "empty");
    }

    /// The owner the server names is always worded as its unverified claim,
    /// cut to a readable length.
    #[test]
    fn the_owner_the_server_names_reads_as_a_short_unverified_claim() {
        let entry = DirectoryEntry {
            account_id: "id".to_owned(),
            handle: Some("alice".to_owned()),
            display_name: Some("A".repeat(500)),
            ed25519_pub_hex: String::new(),
            x25519_pub_hex: String::new(),
            status: "active".to_owned(),
        };
        let shown = claimed(Some(&entry));
        assert!(shown.starts_with("alice ("), "{shown}");
        assert!(shown.ends_with("…, unverified)"), "{shown}");
        assert!(shown.chars().count() < CLAIM_CHARS + 30, "{shown}");
        assert_eq!(claimed(None), "an owner the server does not name");
    }
}
