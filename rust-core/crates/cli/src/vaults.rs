//! `unissh vaults`: what concerns a vault as a whole.

use clap::Subcommand;
use unissh_ffi::{FfiSyncTarget, FfiUnpushableItem};

use crate::device::Device;
use crate::edit::choose_vault;
use crate::failure::{Failure, Res};
use crate::server;
use crate::tty::{self, one_line};

/// `unissh vaults …`.
#[derive(Subcommand)]
pub enum VaultsAction {
    /// Drop the changes made on this machine in a vault that the server will
    /// not take (an edit made while this account could only view the vault),
    /// and put back the server's copy of those items. Other changes not sent
    /// yet are kept.
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
        VaultsAction::DiscardUnpushable { vault, yes } => {
            discard_unpushable(device, offline, &vault, yes)
        }
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
