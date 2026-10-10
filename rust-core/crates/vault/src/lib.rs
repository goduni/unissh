//! # unissh-vault (local part)
//!
//! Local UniSSH vaults (spec 5.2–5.3). Builds on `crypto`, `keychain`,
//! `storage`.
//!
//! ## Model
//! - **Local vault** (`SyncTarget::Local`): create/open/delete.
//! - **Vault Key (VK)** — a random 256-bit per-vault key, wrapped under the
//!   owner's X25519 public key (HPKE). This is also the sharing format.
//! - **Per-item keys**, wrapped by the VK (not by the VK itself) → granular
//!   revocation, bounded blast radius.
//! - Item content is encrypted with the per-item key, bound via associated data
//!   `vault_id+item_id+version`; every record is signed with the owner's Ed25519
//!   and a monotonic version.
//! - **Membership and grants (P3):** an admin-signed membership manifest per
//!   `key_epoch` (member set + roles), per-member grants (VK wrapping with a
//!   `vk_wrap_info` binding), authority-chain verification (sigchain), and the
//!   access predicate `author ∈ members@epoch` AND `epoch >= floor` — see
//!   [`add_member`], [`build_manifest`]/[`verify_manifest`],
//!   [`build_grant`]/[`verify_grant`]/[`open_grant`],
//!   [`verify_record_authority`], [`pin_and_verify_member`].
//!   Applies only to vaults with a manifest; single-owner local vaults are
//!   unchanged (D2).
//!
//! ## Extension points (⏳ Milestone 2, not implemented)
//! - Cloud vault (`SyncTarget` is extensible).
//! - Person-to-person sharing: membership/grant/verification primitives added (P3);
//!   [`Vault::seal_vk_to_recipient`] — owner's VK wrapping. The full
//!   distribution/revocation flow comes later.
//!
//! ## VK rotation / epoch transitions (P4)
//! - [`Vault::rotate_vk`] — eager rotation for membership vaults (new `VK'`,
//!   manifest@`epoch+1`, per-member grants, re-wrap of live item keys, raising the
//!   epoch floor; atomic). [`Vault::purge_vault`] — cooperative hard-delete
//!   (best-effort, not remote-wipe). [`Vault::verify_chain`] — member-aware
//!   audit (D1 chain + epoch floor for membership vaults; single-owner
//!   check for local). Reading pre-rotation history (seed-chain) — ⏳ LATER.
//!
//! ## What is not here
//! Cloud sync, the full sharing flow, SSH.

#![forbid(unsafe_code)]
// Hostile input is parsed here: every +,-,*,<< must say what happens on overflow.
#![warn(clippy::arithmetic_side_effects)]
#![expect(
    clippy::map_err_ignore,
    reason = "error causes are erased on purpose: a decrypt or parse failure must not become an oracle"
)]

mod error;
mod membership;
mod vault;
mod vault_id;

pub use error::VaultError;
pub use membership::{
    add_member, build_grant, build_manifest, member_fingerprint, open_account_payload, open_grant,
    pin_and_verify_member, pin_and_verify_vault_anchor, seal_account_payload, sign_account_state,
    verify_account_state, verify_chain_to_epoch, verify_grant, verify_manifest, Member,
    VerifiedMembers,
};
pub use vault::{
    check_item_record, check_vault_record, verify_record_authority, DecryptedItem,
    IntegrityFailure, IntegrityIssue, IntegrityReport, ItemMeta, Vault,
};
pub use vault_id::new_vault_id;
