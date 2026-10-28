//! `unissh vaults`: what concerns a vault as a whole.

use clap::Subcommand;
use unissh_ffi::FfiSyncTarget;

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

/// `vaults discard-unpushable`: a sync first, so what is dropped is what the
/// push cannot send as of now; then the core drops this account's share of it
/// and the vault is pulled again.
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
    let held: Vec<String> = report
        .unpushable
        .iter()
        .filter(|item| item.mine && item.vault_id == vault.vault_id)
        .map(|item| format!("  {}\n", server::unpushable_entry(item)))
        .collect();
    if held.is_empty() {
        // Pulled all the same: a run whose pull failed after the drop is
        // finished by running it again.
        server::discard_unpushable(device, &vault.vault_id)?;
        println!("Nothing to discard in vault \"{name}\": the server has every change made here.");
        return Ok(());
    }
    tty::confirm(
        yes,
        &format!(
            "These changes made on this machine in vault \"{name}\" cannot be sent to the \
             server:\n{}They are dropped, and the server's copy of each item is put back \
             (an item the server never had is gone).\n",
            held.concat()
        ),
    )?;
    let (dropped, _pulled) = server::discard_unpushable(device, &vault.vault_id)?;
    println!("Dropped {dropped} change(s); vault \"{name}\" has the server's copy again.");
    Ok(())
}
