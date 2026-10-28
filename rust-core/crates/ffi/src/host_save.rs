//! Saving a host: one path for the app's host editor and `unissh hosts
//! add|edit` (issue #167).
//!
//! [`Core::save_host`] checks a host against the rules every saved host keeps
//! ([`HostRule`]), then writes it with what goes with it, all under one state
//! lock:
//!
//! - a password typed for the host, stored as a vault secret, together with
//!   the host in one storage transaction. When the host already logs in with
//!   a stored password that nothing else uses, the typed one is a new version
//!   of that same secret (the old one stays in its history); otherwise it is
//!   a new secret, and the one shared with something else is left alone. A
//!   save never deletes a password;
//! - the host's group: a host is in one group at most, so going into one
//!   takes it out of every other (a new group is created by the save), in
//!   the same transaction;
//! - for a personal host, the binding of the member's identity, pinned to
//!   where the host now points (the identity given, else the one already
//!   linked to it). The pin follows the save only when it still names where
//!   the host pointed before it: a pin someone else's change already left
//!   behind stays, so the connect keeps refusing the redirect.
//!
//! The password, the host and its groups are written all or nothing. The
//! binding lives in another vault, so its failing leaves the host saved, and
//! the result says what is missing ([`HostSaved::unfinished`]); it is never
//! left out silently.

use std::fmt;

use zeroize::Zeroizing;

use crate::item_ids::mint_item_id;
use crate::key_usage::usage_in;
use crate::{
    binding_in, binding_vault_in, groups_in, identities_in, personal_destination, profiles_in,
    put_binding, put_connection, put_group, put_password, resolve_vid, AuthMethod,
    ConnectionProfile, Core, CoreState, FfiError, IdentityBinding, JumpHost, ProfileAuth,
    ServerGroup, ITEM_TYPE_PASSWORD,
};

/// A rule a host save broke. Nothing is written when one is broken.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostRule {
    /// The host has no label.
    LabelRequired,
    /// The host has no address.
    AddressRequired,
    /// The host has no user to log in as, and does not log in with a personal
    /// identity (which names the user).
    UserRequired,
    /// A jump hop given by address has no address.
    HopAddressRequired,
    /// A jump hop references a saved host of another vault. The connect
    /// refuses such a hop too.
    HopOtherVault,
    /// A jump hop references a saved host the vault does not have.
    HopNotFound,
    /// A jump hop references the host itself.
    HopSelf,
    /// A jump hop references a saved host that asks for its password at every
    /// connection or logs in with a personal identity: a hop needs a key, a
    /// stored password or the system ssh-agent.
    HopNoCredential,
    /// A password typed for the host goes with a stored-password login only.
    NewPasswordNeedsPasswordLogin,
    /// The password typed for the host is empty.
    NewPasswordEmpty,
    /// The group named for the host is not a group of its vault.
    GroupNotFound,
    /// A new group for the host has no label.
    GroupLabelRequired,
    /// An identity is linked only to a host that logs in with a personal
    /// identity.
    IdentityNeedsPersonalLogin,
    /// The identity to link is not in the vault named for it.
    IdentityNotFound,
}
impl HostRule {
    /// A stable camelCase code for the rule, for a client to choose its own
    /// words by (the app's translations key on it).
    pub const fn code(self) -> &'static str {
        match self {
            Self::LabelRequired => "labelRequired",
            Self::AddressRequired => "addressRequired",
            Self::UserRequired => "userRequired",
            Self::HopAddressRequired => "hopAddressRequired",
            Self::HopOtherVault => "hopOtherVault",
            Self::HopNotFound => "hopNotFound",
            Self::HopSelf => "hopSelf",
            Self::HopNoCredential => "hopNoCredential",
            Self::NewPasswordNeedsPasswordLogin => "newPasswordNeedsPasswordLogin",
            Self::NewPasswordEmpty => "newPasswordEmpty",
            Self::GroupNotFound => "groupNotFound",
            Self::GroupLabelRequired => "groupLabelRequired",
            Self::IdentityNeedsPersonalLogin => "identityNeedsPersonalLogin",
            Self::IdentityNotFound => "identityNotFound",
        }
    }
}

impl fmt::Display for HostRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::LabelRequired => "a host needs a label",
            Self::AddressRequired => "a host needs an address",
            Self::UserRequired => {
                "a host needs a user to log in as, unless it logs in with a personal identity"
            }
            Self::HopAddressRequired => "a jump host needs an address",
            Self::HopOtherVault => "a jump host must be a saved host of the host's own vault",
            Self::HopNotFound => "the saved host a jump hop names is not in the vault",
            Self::HopSelf => "a host cannot be its own jump host",
            Self::HopNoCredential => {
                "a jump host must log in with a key, a stored password or the system ssh-agent"
            }
            Self::NewPasswordNeedsPasswordLogin => {
                "a password typed for the host goes with a stored-password login"
            }
            Self::NewPasswordEmpty => "the password typed for the host is empty",
            Self::GroupNotFound => "the group is not in the host's vault",
            Self::GroupLabelRequired => "a new group needs a label",
            Self::IdentityNeedsPersonalLogin => {
                "an identity is linked only to a host that logs in with a personal identity"
            }
            Self::IdentityNotFound => "the identity to link is not in its vault",
        })
    }
}

/// Which group a saved host is in. A host is in one group at most.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostGroup {
    /// Leave an existing host's groups as they are. A new host is in none.
    Unchanged,
    /// In no group: out of every group that lists it.
    Ungrouped,
    /// In this group of the host's vault, and out of every other.
    Existing {
        /// The group's id.
        group_id: String,
    },
    /// In a new group with this label, created by the save, and out of every
    /// other.
    New {
        /// The new group's label.
        label: String,
    },
}

/// The personal identity to link to a host that logs in with one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityLink {
    /// The vault holding the identity (where the binding is kept too).
    pub vault_id: String,
    /// The identity's item id.
    pub identity_id: String,
}

/// A host to save, with what goes with it.
pub struct HostSave {
    /// The host. An empty `profile_id` is a new host, whose id the core mints
    /// (`slug(label)-<millis>`). The uid is the core's: an existing host keeps
    /// its own whatever is sent, and a new host always gets a fresh one. Jump
    /// hops that reference a saved host are stored in the placeholder shape
    /// the connect expects (their inline fields are ignored, their vault is
    /// the host's). The username template is kept for a personal login only.
    pub profile: ConnectionProfile,
    /// A password typed for the host, which then logs in with it. The host's
    /// `auth` must be `VaultPassword`. When the host already logs in with a
    /// stored password nothing else uses, the typed one becomes that secret's
    /// new version (the previous one stays in its history); otherwise it is
    /// stored as a new secret and the host's `password_item_id` names it.
    pub new_password: Option<Zeroizing<String>>,
    /// The group the host is in.
    pub group: HostGroup,
    /// For a personal host: the identity to link. `None` re-pins the identity
    /// already linked to an existing host, if any, from a private vault.
    pub identity: Option<IdentityLink>,
}

/// What a save could not finish after the host itself was stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostSaveGap {
    /// The identity could not be linked to the host (or re-pinned to where it
    /// now points): connecting with it is refused until it is linked again.
    IdentityNotLinked {
        /// Why.
        message: String,
    },
    /// The identity is still pinned to an older address: the host was
    /// pointed elsewhere before this save (by another change, maybe someone
    /// else's), so the save did not move the pin, and connecting with the
    /// identity is refused as redirected until it is linked again.
    IdentityPinKept {
        /// Where the identity is still pinned.
        pinned: String,
        /// Plain words for the person saving.
        message: String,
    },
}

/// A saved host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostSaved {
    /// The host's id (minted for a new host).
    pub profile_id: String,
    /// The host's immutable uid (minted for a new host).
    pub uid: String,
    /// The secret a typed password was stored in: the host's own one (a new
    /// version of it) or a new one.
    pub password_item_id: Option<String>,
    /// The group the host is now in, when the save placed it in one (a new
    /// group's minted id included).
    pub group_id: Option<String>,
    /// Whether an identity is linked to the host and pinned to where it
    /// points now.
    pub identity_linked: bool,
    /// The vault an identity binding was written to (it changed too, so a
    /// client syncs it), when the save wrote one.
    pub binding_vault_id: Option<String>,
    /// What the save could not finish; empty when everything was saved.
    pub unfinished: Vec<HostSaveGap>,
}

/// What the storage transaction wrote.
struct Written {
    profile_id: String,
    uid: String,
    password_item_id: Option<String>,
    group_id: Option<String>,
}

/// The identity to link, with the binding it already has (if any).
struct Link {
    to: IdentityLink,
    existing: Option<IdentityBinding>,
}

impl Core {
    /// Saves a host the way the app's editor and `unissh hosts add|edit` do:
    /// checks it ([`HostRule`]; [`FfiError::InvalidHost`] and nothing written
    /// when one is broken), then stores it with its typed password and its
    /// group in one transaction, and links or re-pins a personal identity.
    /// See the module docs.
    pub fn save_host(&self, vault_id: &str, save: HostSave) -> Result<HostSaved, FfiError> {
        self.with_state(|state| save_locked(state, vault_id, save))
    }
}

const fn refused(rule: HostRule) -> FfiError {
    FfiError::InvalidHost { rule }
}

/// Whether a host logging in with `auth` can serve as a jump hop: the connect
/// resolves a referenced hop to that host's own credential.
const fn can_be_a_hop(auth: &ProfileAuth) -> bool {
    match auth {
        ProfileAuth::Key { .. }
        | ProfileAuth::VaultPassword { .. }
        | ProfileAuth::SystemAgent { .. } => true,
        ProfileAuth::PromptPassword | ProfileAuth::Personal => false,
    }
}

/// Where a host points, as an identity binding pins it: the connect renders
/// the same string from the stored host.
fn destination(p: &ConnectionProfile) -> String {
    personal_destination(
        &p.host,
        p.port,
        p.username_template.as_deref(),
        &p.jumps,
        p.proxy.as_ref(),
    )
}

fn save_locked(state: &CoreState, vault_id: &str, save: HostSave) -> Result<HostSaved, FfiError> {
    let HostSave {
        mut profile,
        new_password,
        group,
        identity,
    } = save;
    let hosts = profiles_in(state, vault_id)?;
    let before = hosts
        .iter()
        .find(|h| !profile.profile_id.is_empty() && h.profile_id == profile.profile_id)
        .cloned();
    // The uid is immutable: bindings and hops find the host by it. An edit
    // keeps the host's own; a new host gets a fresh one from the write.
    profile.uid = before.as_ref().map(|b| b.uid.clone()).unwrap_or_default();
    tidy(&mut profile);
    check_fields(&profile)?;
    check_new_password(&profile, new_password.as_deref().map(String::as_str))?;
    check_hops(state, vault_id, &mut profile, &hosts)?;
    let group = checked_group(state, vault_id, group, before.is_none())?;
    let link = link_to_pin(state, vault_id, &profile, before.is_some(), identity)?;
    let pin = destination(&profile);
    let pinned_before = before.as_ref().map(destination);
    let own_password = if new_password.is_some() {
        own_password_item(state, vault_id, before.as_ref(), &hosts)?
    } else {
        None
    };
    let written = state.storage.transaction(|| {
        write_host(
            state,
            vault_id,
            profile,
            new_password
                .as_deref()
                .map(|p| (p.as_str(), own_password.as_deref())),
            &group,
        )
    })?;

    let linked = link.map_or_else(Linked::default, |link| {
        pin_identity(
            state,
            vault_id,
            &written.uid,
            link,
            &pin,
            pinned_before.as_deref(),
        )
    });
    Ok(HostSaved {
        profile_id: written.profile_id,
        uid: written.uid,
        password_item_id: written.password_item_id,
        group_id: written.group_id,
        identity_linked: linked.linked,
        binding_vault_id: linked.binding_vault_id,
        unfinished: linked.gap.into_iter().collect(),
    })
}

/// What linking the identity did.
#[derive(Default)]
struct Linked {
    /// Linked and pinned to where the host points now.
    linked: bool,
    /// The vault the binding was written to, when it was.
    binding_vault_id: Option<String>,
    /// What it could not do.
    gap: Option<HostSaveGap>,
}

/// Links `link`'s identity to the saved host `uid`, pinned to `pin` (where
/// the host points now). Saving the host is the user's word on where it
/// points, so the pin follows it, but only from where the host pointed before
/// this save (`pinned_before`). A pin that already differs was left behind
/// by an earlier change of the host (a team member's, maybe): moving it here
/// would wave that redirect through, so it stays, and the gap says so.
fn pin_identity(
    state: &CoreState,
    vault_id: &str,
    uid: &str,
    link: Link,
    pin: &str,
    pinned_before: Option<&str>,
) -> Linked {
    let Link { to, existing } = link;
    let kept = existing
        .as_ref()
        .map(|b| b.destination_pin.clone())
        .filter(|was| pinned_before.is_some_and(|then| then != was.as_str()));
    let new_pin = kept.clone().unwrap_or_else(|| pin.to_owned());
    let unchanged = existing
        .as_ref()
        .is_some_and(|b| b.identity_item_id == to.identity_id && b.destination_pin == new_pin);
    let mut out = Linked::default();
    if !unchanged {
        let binding = IdentityBinding {
            team_vault_id: vault_id.to_owned(),
            profile_uid: uid.to_owned(),
            identity_item_id: to.identity_id,
            destination_pin: new_pin,
        };
        if let Err(e) = put_binding(state, &to.vault_id, binding, true) {
            out.gap = Some(HostSaveGap::IdentityNotLinked {
                message: e.to_string(),
            });
            return out;
        }
        out.binding_vault_id = Some(to.vault_id);
    }
    let still_pinned = kept.filter(|k| k != pin);
    out.linked = still_pinned.is_none();
    if let Some(pinned) = still_pinned {
        out.gap = Some(HostSaveGap::IdentityPinKept {
            message: format!(
                "your identity is still pinned to {pinned}, not to {pin}: the host had \
                 been pointed elsewhere before this save, so connecting with your \
                 identity is refused as redirected until you link it again"
            ),
            pinned,
        });
    }
    out
}

/// Trims what the editors trim, and keeps the username template for a
/// personal login only (it shapes the user an identity logs in as).
fn tidy(profile: &mut ConnectionProfile) {
    profile.label = profile.label.trim().to_owned();
    profile.host = profile.host.trim().to_owned();
    profile.user = profile.user.trim().to_owned();
    profile.username_template = match profile.auth {
        ProfileAuth::Personal => profile
            .username_template
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(str::to_owned),
        ProfileAuth::Key { .. }
        | ProfileAuth::VaultPassword { .. }
        | ProfileAuth::PromptPassword
        | ProfileAuth::SystemAgent { .. } => None,
    };
}

/// A label, an address, and a user unless the login is personal (the
/// identity names the user then).
fn check_fields(profile: &ConnectionProfile) -> Result<(), FfiError> {
    if profile.label.is_empty() {
        return Err(refused(HostRule::LabelRequired));
    }
    if profile.host.is_empty() {
        return Err(refused(HostRule::AddressRequired));
    }
    if profile.user.is_empty() && !matches!(profile.auth, ProfileAuth::Personal) {
        return Err(refused(HostRule::UserRequired));
    }
    Ok(())
}

fn check_new_password(
    profile: &ConnectionProfile,
    new_password: Option<&str>,
) -> Result<(), FfiError> {
    let Some(password) = new_password else {
        return Ok(());
    };
    if !matches!(profile.auth, ProfileAuth::VaultPassword { .. }) {
        return Err(refused(HostRule::NewPasswordNeedsPasswordLogin));
    }
    if password.trim().is_empty() {
        return Err(refused(HostRule::NewPasswordEmpty));
    }
    Ok(())
}

/// The hop rules. A hop given by address needs one (stored trimmed). A hop
/// referencing a saved host must name another host of the same vault, by its
/// uid, that logs in with a key, a stored password or the system ssh-agent;
/// it is stored in the placeholder shape (no inline fields, the host's own
/// vault id), as the connect resolves it from the referenced host.
fn check_hops(
    state: &CoreState,
    vault_id: &str,
    profile: &mut ConnectionProfile,
    hosts: &[ConnectionProfile],
) -> Result<(), FfiError> {
    let vid = resolve_vid(&state.storage, vault_id);
    for hop in &mut profile.jumps {
        let Some(mut hop_ref) = hop.hop_ref.clone() else {
            hop.host = hop.host.trim().to_owned();
            if hop.host.is_empty() {
                return Err(refused(HostRule::HopAddressRequired));
            }
            continue;
        };
        if resolve_vid(&state.storage, &hop_ref.vault_id) != vid {
            return Err(refused(HostRule::HopOtherVault));
        }
        let Some(target) = hosts.iter().find(|h| h.uid == hop_ref.profile_uid) else {
            return Err(refused(HostRule::HopNotFound));
        };
        let is_self = (!profile.profile_id.is_empty() && target.profile_id == profile.profile_id)
            || (!profile.uid.is_empty() && target.uid == profile.uid);
        if is_self {
            return Err(refused(HostRule::HopSelf));
        }
        if !can_be_a_hop(&target.auth) {
            return Err(refused(HostRule::HopNoCredential));
        }
        vault_id.clone_into(&mut hop_ref.vault_id);
        *hop = JumpHost {
            host: String::new(),
            port: 22,
            user: String::new(),
            auth: AuthMethod::Agent {
                vault_id: vault_id.to_owned(),
                key_item_id: String::new(),
            },
            hop_ref: Some(hop_ref),
        };
    }
    Ok(())
}

/// `group` checked against the vault's groups; a new host left "unchanged"
/// is in none.
fn checked_group(
    state: &CoreState,
    vault_id: &str,
    group: HostGroup,
    creating: bool,
) -> Result<HostGroup, FfiError> {
    match group {
        HostGroup::Unchanged if creating => Ok(HostGroup::Ungrouped),
        HostGroup::Unchanged => Ok(HostGroup::Unchanged),
        HostGroup::Ungrouped => Ok(HostGroup::Ungrouped),
        HostGroup::Existing { group_id } => {
            if groups_in(state, vault_id)?
                .iter()
                .any(|g| g.group_id == group_id)
            {
                Ok(HostGroup::Existing { group_id })
            } else {
                Err(refused(HostRule::GroupNotFound))
            }
        }
        HostGroup::New { label } => {
            let label = label.trim();
            if label.is_empty() {
                Err(refused(HostRule::GroupLabelRequired))
            } else {
                Ok(HostGroup::New {
                    label: label.to_owned(),
                })
            }
        }
    }
}

/// The identity to pin to a personal host, with the binding it already has:
/// the one given (which must exist and needs a personal login), else the one
/// already linked to an existing personal host from a private vault (only a
/// single-member vault holds a member's own identities).
fn link_to_pin(
    state: &CoreState,
    vault_id: &str,
    profile: &ConnectionProfile,
    editing: bool,
    given: Option<IdentityLink>,
) -> Result<Option<Link>, FfiError> {
    let personal = matches!(profile.auth, ProfileAuth::Personal);
    if let Some(to) = given {
        if !personal {
            return Err(refused(HostRule::IdentityNeedsPersonalLogin));
        }
        let found = identities_in(state, &to.vault_id)
            .is_ok_and(|ids| ids.iter().any(|i| i.identity_id == to.identity_id));
        if !found {
            return Err(refused(HostRule::IdentityNotFound));
        }
        let existing = if editing {
            binding_in(state, &to.vault_id, vault_id, &profile.uid)?
        } else {
            None
        };
        return Ok(Some(Link { to, existing }));
    }
    if !personal || !editing {
        return Ok(None);
    }
    let Some(binding_vault) = binding_vault_in(state, vault_id, &profile.uid, true)? else {
        return Ok(None);
    };
    Ok(
        binding_in(state, &binding_vault, vault_id, &profile.uid)?.map(|b| Link {
            to: IdentityLink {
                vault_id: binding_vault,
                identity_id: b.identity_item_id.clone(),
            },
            existing: Some(b),
        }),
    )
}

/// The stored password a typed one becomes the new version of: the one the
/// host logs in with, when it is a live password item nothing else in the
/// vault uses (no other host, hop, proxy or identity). `None` means a new
/// secret: a password shared with something else is left as it is.
fn own_password_item(
    state: &CoreState,
    vault_id: &str,
    before: Option<&ConnectionProfile>,
    hosts: &[ConnectionProfile],
) -> Result<Option<String>, FfiError> {
    let Some(ConnectionProfile {
        profile_id,
        auth: ProfileAuth::VaultPassword { password_item_id },
        ..
    }) = before
    else {
        return Ok(None);
    };
    if password_item_id.is_empty() {
        return Ok(None);
    }
    let vid = resolve_vid(&state.storage, vault_id);
    let live = state
        .storage
        .get_item(&vid, password_item_id.as_bytes())
        .map_err(FfiError::other)?
        .is_some_and(|i| i.item_type == ITEM_TYPE_PASSWORD && !i.tombstone);
    if !live {
        return Ok(None);
    }
    // The host itself is left out: its own login is what is being changed,
    // and a hop naming it follows its credential anyway.
    let others: Vec<ConnectionProfile> = hosts
        .iter()
        .filter(|h| h.profile_id != *profile_id)
        .cloned()
        .collect();
    let identities = identities_in(state, vault_id)?;
    let storage = &state.storage;
    let used = usage_in(
        password_item_id,
        |v| resolve_vid(storage, v) == vid,
        &others,
        &identities,
    )
    .count();
    Ok((used == 0).then(|| password_item_id.clone()))
}

/// The writes that go together, inside the storage transaction: the typed
/// password (with the host's own secret to write it into, if any), the host,
/// its groups.
fn write_host(
    state: &CoreState,
    vault_id: &str,
    mut profile: ConnectionProfile,
    new_password: Option<(&str, Option<&str>)>,
    group: &HostGroup,
) -> Result<Written, FfiError> {
    let password_item_id = match new_password {
        Some((password, own)) => {
            let id = match own {
                // A new version of the host's own secret: the one it replaces
                // stays in the item's history.
                Some(own) => own.to_owned(),
                // Written before the host, so the host's own minted id steps
                // past it.
                None => mint_item_id(
                    &state.storage,
                    vault_id,
                    &format!("{} pw", profile.label),
                    "item",
                )?,
            };
            put_password(state, vault_id, &id, password)?;
            profile.auth = ProfileAuth::VaultPassword {
                password_item_id: id.clone(),
            };
            Some(id)
        }
        None => None,
    };
    let (profile_id, uid) = put_connection(state, vault_id, profile)?;
    let group_id = place_in_group(state, vault_id, &profile_id, group)?;
    Ok(Written {
        profile_id,
        uid,
        password_item_id,
        group_id,
    })
}

/// Puts host `profile_id` into the group `group` says and out of every other
/// one. Returns the group it is now in, when the save placed it.
fn place_in_group(
    state: &CoreState,
    vault_id: &str,
    profile_id: &str,
    group: &HostGroup,
) -> Result<Option<String>, FfiError> {
    let target = match group {
        HostGroup::Unchanged => return Ok(None),
        HostGroup::Ungrouped => None,
        HostGroup::Existing { group_id } => Some(group_id.clone()),
        HostGroup::New { label } => Some(put_group(
            state,
            vault_id,
            ServerGroup {
                group_id: String::new(),
                label: label.clone(),
                member_ids: vec![profile_id.to_owned()],
                parent_id: None,
                color: None,
                icon: None,
            },
        )?),
    };
    for mut g in groups_in(state, vault_id)? {
        let wanted = target.as_deref() == Some(g.group_id.as_str());
        let listed = g.member_ids.iter().any(|m| m == profile_id);
        if wanted && !listed {
            g.member_ids.push(profile_id.to_owned());
            put_group(state, vault_id, g)?;
        } else if !wanted && listed {
            g.member_ids.retain(|m| m != profile_id);
            put_group(state, vault_id, g)?;
        }
    }
    Ok(target)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use zeroize::Zeroizing;

    use super::{HostGroup, HostRule, HostSave, HostSaveGap, IdentityLink};
    use crate::{
        binding_item_id, resolve_vid, AuthMethod, BindingResolution, ConnectionProfile, Core,
        FfiError, HopRef, Identity, JumpHost, ProfileAuth, ServerGroup, Vault, ITEM_TYPE_GROUP,
        ITEM_TYPE_PASSWORD,
    };

    /// A core with vault `v` (the hosts) and vault `p` (an identity `me`).
    fn core() -> (Arc<Core>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::new(
            dir.path().join("i.db").to_string_lossy().to_string(),
            dir.path().join("i.keyset").to_string_lossy().to_string(),
        );
        core.create_account(None).unwrap();
        core.create_vault("v".into(), "V".into()).unwrap();
        core.create_vault("p".into(), "P".into()).unwrap();
        core.create_identity(
            "p".into(),
            Identity {
                identity_id: "me".into(),
                label: "Me".into(),
                user: "alice".into(),
                key_item_id: None,
                password_item_id: None,
            },
        )
        .unwrap();
        (core, dir)
    }

    fn host(label: &str, auth: ProfileAuth) -> ConnectionProfile {
        ConnectionProfile {
            profile_id: String::new(),
            uid: String::new(),
            label: label.into(),
            host: format!("{label}.example"),
            port: 22,
            user: "root".into(),
            auth,
            username_template: None,
            jumps: Vec::new(),
            proxy: None,
            tags: Vec::new(),
            startup_snippet_ids: Vec::new(),
            record_sessions: false,
            agent_forward: false,
            color: None,
            icon: None,
        }
    }

    fn key() -> ProfileAuth {
        ProfileAuth::Key {
            key_item_id: "k".into(),
        }
    }

    const fn stored_password() -> ProfileAuth {
        ProfileAuth::VaultPassword {
            password_item_id: String::new(),
        }
    }

    const fn plain(profile: ConnectionProfile) -> HostSave {
        HostSave {
            profile,
            new_password: None,
            group: HostGroup::Unchanged,
            identity: None,
        }
    }

    fn typed(profile: ConnectionProfile, password: &str) -> HostSave {
        HostSave {
            new_password: Some(Zeroizing::new(password.to_owned())),
            ..plain(profile)
        }
    }

    fn me() -> Option<IdentityLink> {
        Some(IdentityLink {
            vault_id: "p".into(),
            identity_id: "me".into(),
        })
    }

    /// A hop referencing the saved host with uid `uid` of vault `vault`,
    /// with stale inline fields the save must drop.
    fn ref_hop(vault: &str, uid: &str) -> JumpHost {
        JumpHost {
            host: "stale.example".into(),
            port: 2222,
            user: "stale".into(),
            auth: AuthMethod::Agent {
                vault_id: vault.into(),
                key_item_id: "stale-key".into(),
            },
            hop_ref: Some(HopRef {
                vault_id: vault.into(),
                profile_uid: uid.into(),
            }),
        }
    }

    /// The rule `save` breaks; it must write nothing.
    fn refusal(core: &Core, save: HostSave) -> HostRule {
        let before = core.list_items("v".into()).unwrap().len();
        let rule = match core.save_host("v", save) {
            Err(FfiError::InvalidHost { rule }) => rule,
            Err(e) => panic!("refused with another error: {e}"),
            Ok(saved) => panic!("saved as {}", saved.profile_id),
        };
        assert_eq!(core.list_items("v".into()).unwrap().len(), before);
        rule
    }

    /// A host saved in vault `v`: its (profile id, uid).
    fn saved(core: &Core, label: &str, auth: ProfileAuth) -> (String, String) {
        let s = core.save_host("v", plain(host(label, auth))).unwrap();
        (s.profile_id, s.uid)
    }

    fn with_hop(hop: JumpHost) -> HostSave {
        let mut p = host("web", key());
        p.jumps = vec![hop];
        plain(p)
    }

    fn passwords(core: &Core) -> Vec<String> {
        core.list_items("v".into())
            .unwrap()
            .into_iter()
            .filter(|i| i.item_type == ITEM_TYPE_PASSWORD)
            .map(|i| i.item_id)
            .collect()
    }

    fn groups_of(core: &Core, profile_id: &str) -> Vec<String> {
        core.list_groups("v".into())
            .unwrap()
            .into_iter()
            .filter(|g| g.member_ids.iter().any(|m| m == profile_id))
            .map(|g| g.label)
            .collect()
    }

    fn group(core: &Core, label: &str, members: &[&str]) -> String {
        core.save_group(
            "v".into(),
            ServerGroup {
                group_id: String::new(),
                label: label.into(),
                member_ids: members.iter().map(|m| (*m).to_owned()).collect(),
                parent_id: None,
                color: None,
                icon: None,
            },
        )
        .unwrap()
    }

    /// The host `id` of vault `v`, as stored.
    fn stored(core: &Core, id: &str) -> ConnectionProfile {
        core.get_connection("v".into(), id.to_owned()).unwrap()
    }

    /// Edits host `id` with `group`.
    fn regroup(core: &Core, id: &str, group: HostGroup) -> super::HostSaved {
        let save = HostSave {
            group,
            ..plain(stored(core, id))
        };
        core.save_host("v", save).unwrap()
    }

    /// A personal host `web` linked to identity `me`: its (profile id, uid).
    fn linked(core: &Core) -> (String, String) {
        let save = HostSave {
            identity: me(),
            ..plain(host("web", ProfileAuth::Personal))
        };
        let s = core.save_host("v", save).unwrap();
        assert!(s.identity_linked, "not linked");
        (s.profile_id, s.uid)
    }

    /// What the binding of host `uid` resolves to at `address`.
    fn binding_at(core: &Core, uid: &str, address: &str) -> BindingResolution {
        let now = core.personal_destination(address.into(), 22, None, vec![], None);
        core.resolve_host_binding("p".into(), "v".into(), uid.into(), now)
            .unwrap()
    }

    #[test]
    fn a_host_without_a_label_is_refused() {
        let (core, _dir) = core();
        let rule = refusal(&core, plain(host(" ", key())));
        assert_eq!(rule, HostRule::LabelRequired);
    }

    #[test]
    fn a_host_without_an_address_is_refused() {
        let (core, _dir) = core();
        let mut p = host("web", key());
        p.host = "  ".into();
        assert_eq!(refusal(&core, plain(p)), HostRule::AddressRequired);
    }

    #[test]
    fn a_host_without_a_user_is_refused() {
        let (core, _dir) = core();
        let mut p = host("web", key());
        p.user = String::new();
        assert_eq!(refusal(&core, plain(p)), HostRule::UserRequired);
    }

    /// A personal login needs no user: the identity names it.
    #[test]
    fn a_personal_host_needs_no_user() {
        let (core, _dir) = core();
        let mut p = host("web", ProfileAuth::Personal);
        p.user = String::new();
        assert!(core.save_host("v", plain(p)).is_ok(), "personal refused");
    }

    #[test]
    fn a_hop_given_by_address_needs_one() {
        let (core, _dir) = core();
        let hop = JumpHost {
            host: " ".into(),
            port: 22,
            user: "ops".into(),
            auth: AuthMethod::Agent {
                vault_id: "v".into(),
                key_item_id: "k".into(),
            },
            hop_ref: None,
        };
        assert_eq!(refusal(&core, with_hop(hop)), HostRule::HopAddressRequired);
    }

    #[test]
    fn a_hop_given_by_address_is_stored_trimmed() {
        let (core, _dir) = core();
        let hop = JumpHost {
            host: " bastion.example ".into(),
            port: 22,
            user: "ops".into(),
            auth: AuthMethod::Agent {
                vault_id: "v".into(),
                key_item_id: "k".into(),
            },
            hop_ref: None,
        };
        let s = core.save_host("v", with_hop(hop)).unwrap();
        assert_eq!(
            stored(&core, &s.profile_id).jumps[0].host,
            "bastion.example"
        );
    }

    #[test]
    fn a_hop_must_be_a_host_of_the_same_vault() {
        let (core, _dir) = core();
        let other = core.save_host("p", plain(host("bastion", key()))).unwrap();
        let rule = refusal(&core, with_hop(ref_hop("p", &other.uid)));
        assert_eq!(rule, HostRule::HopOtherVault);
    }

    #[test]
    fn a_hop_must_name_a_host_the_vault_has() {
        let (core, _dir) = core();
        let rule = refusal(&core, with_hop(ref_hop("v", "no-such-uid")));
        assert_eq!(rule, HostRule::HopNotFound);
    }

    #[test]
    fn a_host_cannot_be_its_own_hop() {
        let (core, _dir) = core();
        let (id, uid) = saved(&core, "web", key());
        let mut p = stored(&core, &id);
        p.jumps = vec![ref_hop("v", &uid)];
        assert_eq!(refusal(&core, plain(p)), HostRule::HopSelf);
    }

    /// A host that asks for its password, or logs in personally, has no
    /// credential a hop could use.
    #[test]
    fn a_hop_must_log_in_with_a_credential() {
        let (core, _dir) = core();
        for auth in [ProfileAuth::PromptPassword, ProfileAuth::Personal] {
            let (_, uid) = saved(&core, "bastion", auth);
            let rule = refusal(&core, with_hop(ref_hop("v", &uid)));
            assert_eq!(rule, HostRule::HopNoCredential);
        }
    }

    /// Key, stored-password and system-agent hosts can all be hops; the hop
    /// is stored in the placeholder shape, its inline fields dropped.
    #[test]
    fn a_hop_may_log_in_with_a_key_a_stored_password_or_the_system_agent() {
        let (core, _dir) = core();
        let agent = ProfileAuth::SystemAgent {
            public_key: "ssh-ed25519 AAAA test".into(),
        };
        let password = ProfileAuth::VaultPassword {
            password_item_id: "pw".into(),
        };
        for auth in [key(), password, agent] {
            let (_, uid) = saved(&core, "bastion", auth);
            let s = core.save_host("v", with_hop(ref_hop("v", &uid))).unwrap();
            let hop = stored(&core, &s.profile_id).jumps[0].clone();
            assert_eq!(
                (hop.host.as_str(), hop.port, hop.user.as_str()),
                ("", 22, "")
            );
            assert!(
                matches!(&hop.auth, AuthMethod::Agent { key_item_id, .. } if key_item_id.is_empty()),
                "inline key kept"
            );
            assert_eq!(hop.hop_ref.unwrap().profile_uid, uid);
        }
    }

    /// A hop naming the host's vault by another spelling of its id is stored
    /// under the host's own vault id.
    #[test]
    fn a_hop_is_stored_under_the_hosts_vault_id() {
        let (core, _dir) = core();
        let cloud = core
            .create_cloud_vault("C".into(), "dGVuYW50".into())
            .unwrap();
        let bastion = core
            .save_host(&cloud, plain(host("bastion", key())))
            .unwrap();
        let mut p = host("web", key());
        p.jumps = vec![ref_hop(&cloud.to_uppercase(), &bastion.uid)];
        let s = core.save_host(&cloud, plain(p)).unwrap();
        let hop = core
            .get_connection(cloud.clone(), s.profile_id)
            .unwrap()
            .jumps[0]
            .clone();
        assert_eq!(hop.hop_ref.unwrap().vault_id, cloud);
    }

    #[test]
    fn a_typed_password_goes_with_a_stored_password_login() {
        let (core, _dir) = core();
        let rule = refusal(&core, typed(host("web", key()), "secret"));
        assert_eq!(rule, HostRule::NewPasswordNeedsPasswordLogin);
    }

    #[test]
    fn a_typed_password_cannot_be_empty() {
        let (core, _dir) = core();
        let rule = refusal(&core, typed(host("web", stored_password()), "  "));
        assert_eq!(rule, HostRule::NewPasswordEmpty);
    }

    #[test]
    fn the_group_named_must_be_in_the_vault() {
        let (core, _dir) = core();
        let save = HostSave {
            group: HostGroup::Existing {
                group_id: "nope".into(),
            },
            ..plain(host("web", key()))
        };
        assert_eq!(refusal(&core, save), HostRule::GroupNotFound);
    }

    #[test]
    fn a_new_group_needs_a_label() {
        let (core, _dir) = core();
        let save = HostSave {
            group: HostGroup::New { label: " ".into() },
            ..plain(host("web", key()))
        };
        assert_eq!(refusal(&core, save), HostRule::GroupLabelRequired);
    }

    #[test]
    fn an_identity_is_linked_only_to_a_personal_host() {
        let (core, _dir) = core();
        let save = HostSave {
            identity: me(),
            ..plain(host("web", key()))
        };
        assert_eq!(refusal(&core, save), HostRule::IdentityNeedsPersonalLogin);
    }

    #[test]
    fn the_identity_to_link_must_exist() {
        let (core, _dir) = core();
        let save = HostSave {
            identity: Some(IdentityLink {
                vault_id: "p".into(),
                identity_id: "nobody".into(),
            }),
            ..plain(host("web", ProfileAuth::Personal))
        };
        assert_eq!(refusal(&core, save), HostRule::IdentityNotFound);
    }

    #[test]
    fn a_new_host_gets_a_minted_id_and_uid() {
        let (core, _dir) = core();
        let s = core.save_host("v", plain(host("Web Box", key()))).unwrap();
        assert!(s.profile_id.starts_with("web-box-"), "id {}", s.profile_id);
        assert!(!s.uid.is_empty(), "no uid");
        assert!(s.unfinished.is_empty(), "unfinished");
        assert_eq!(stored(&core, &s.profile_id).uid, s.uid);
    }

    /// A uid sent with a new host is not taken: bindings and hops naming
    /// that uid belong to another host.
    #[test]
    fn a_new_host_never_takes_the_uid_it_was_sent_with() {
        let (core, _dir) = core();
        let mut p = host("web", key());
        p.uid = "someone-elses".into();
        assert_ne!(core.save_host("v", plain(p)).unwrap().uid, "someone-elses");
    }

    /// An edit keeps the host's uid whatever it sends, so its binding and the
    /// hops naming it still find it.
    #[test]
    fn an_edit_keeps_the_hosts_uid() {
        let (core, _dir) = core();
        let (id, uid) = saved(&core, "web", key());
        let mut p = stored(&core, &id);
        p.uid = "another".into();
        assert_eq!(core.save_host("v", plain(p)).unwrap().uid, uid);
        assert_eq!(stored(&core, &id).uid, uid);
    }

    #[test]
    fn the_username_template_is_dropped_for_a_non_personal_login() {
        let (core, _dir) = core();
        let mut p = host("web", key());
        p.username_template = Some("%u:web".into());
        let s = core.save_host("v", plain(p)).unwrap();
        assert!(stored(&core, &s.profile_id).username_template.is_none());
    }

    #[test]
    fn the_username_template_is_kept_for_a_personal_login() {
        let (core, _dir) = core();
        let mut p = host("web", ProfileAuth::Personal);
        p.username_template = Some("%u:web".into());
        let s = core.save_host("v", plain(p)).unwrap();
        let template = stored(&core, &s.profile_id).username_template;
        assert_eq!(template.as_deref(), Some("%u:web"));
    }

    /// A password typed for a new host is stored and logged in with.
    #[test]
    fn a_typed_password_is_stored_and_logged_in_with() {
        let (core, _dir) = core();
        let s = core
            .save_host("v", typed(host("web", stored_password()), "first"))
            .unwrap();
        let id = s.password_item_id.unwrap();
        assert_eq!(core.get_password("v".into(), id.clone()).unwrap(), "first");
        assert!(
            matches!(&stored(&core, &s.profile_id).auth, ProfileAuth::VaultPassword { password_item_id } if *password_item_id == id),
            "host does not log in with the typed password"
        );
    }

    /// A new password for a host whose stored one nothing else uses is a new
    /// version of that same secret: the old one stays in its history.
    #[test]
    fn a_typed_password_is_a_new_version_of_the_hosts_own_one() {
        let (core, _dir) = core();
        let s = core
            .save_host("v", typed(host("web", stored_password()), "first"))
            .unwrap();
        let first = s.password_item_id.unwrap();
        let s = core
            .save_host("v", typed(stored(&core, &s.profile_id), "second"))
            .unwrap();
        assert_eq!(s.password_item_id.as_deref(), Some(first.as_str()));
        assert_eq!(
            core.get_password("v".into(), first.clone()).unwrap(),
            "second"
        );
        let versions = core.list_item_versions("v".into(), first.clone()).unwrap();
        assert_eq!(versions.len(), 2, "versions {versions:?}");
        let oldest = versions.iter().copied().min().unwrap();
        let old = core
            .get_password_version("v".into(), first, oldest)
            .unwrap();
        assert_eq!(old, "first");
    }

    /// A password the host shares with something else is left alone; the
    /// typed one is a new secret for this host.
    #[test]
    fn a_shared_password_is_untouched_and_the_host_gets_a_new_one() {
        let (core, _dir) = core();
        core.save_password("v".into(), "shared".into(), "pw".into())
            .unwrap();
        let shared = || ProfileAuth::VaultPassword {
            password_item_id: "shared".into(),
        };
        saved(&core, "db", shared());
        let (id, _) = saved(&core, "web", shared());
        let s = core
            .save_host("v", typed(stored(&core, &id), "new"))
            .unwrap();
        let new = s.password_item_id.unwrap();
        assert_ne!(new, "shared");
        assert_eq!(
            core.get_password("v".into(), "shared".into()).unwrap(),
            "pw"
        );
        let versions = core
            .list_item_versions("v".into(), "shared".into())
            .unwrap();
        assert_eq!(versions.len(), 1, "shared password rewritten");
        assert!(
            matches!(&stored(&core, &id).auth, ProfileAuth::VaultPassword { password_item_id } if *password_item_id == new),
            "host does not log in with its new password"
        );
    }

    /// The typed password and the host are written together: a host that
    /// cannot be stored leaves no password behind.
    #[test]
    fn a_host_that_cannot_be_stored_leaves_no_typed_password() {
        let (core, _dir) = core();
        let mut p = host("web", stored_password());
        p.color = Some("#bad".into());
        assert!(core.save_host("v", typed(p, "secret")).is_err(), "saved");
        assert!(passwords(&core).is_empty(), "password left behind");
        let hosts = core.list_connections("v".into()).unwrap();
        assert!(hosts.is_empty(), "host saved");
    }

    /// The group write is part of the same transaction: when it fails, the
    /// host and its typed password are not stored either.
    #[test]
    fn a_failed_group_write_stores_neither_host_nor_password() {
        let (core, _dir) = core();
        // A group listing itself, as synced data could: writing it back is
        // refused, so placing a host in it fails.
        core.with_state_mut(|st| {
            let vault = Vault::open(&st.storage, &st.keyset, &resolve_vid(&st.storage, "v"))
                .map_err(FfiError::other)?;
            vault
                .put_item(
                    b"loop",
                    ITEM_TYPE_GROUP,
                    br#"{"label":"Loop","member_ids":["loop"],"color":null}"#,
                )
                .map_err(FfiError::other)?;
            Ok(())
        })
        .unwrap();
        let save = HostSave {
            group: HostGroup::Existing {
                group_id: "loop".into(),
            },
            ..typed(host("web", stored_password()), "secret")
        };
        assert!(core.save_host("v", save).is_err(), "saved");
        assert!(
            core.list_connections("v".into()).unwrap().is_empty(),
            "host saved"
        );
        assert!(passwords(&core).is_empty(), "password left behind");
    }

    #[test]
    fn going_into_a_group_takes_the_host_out_of_the_others() {
        let (core, _dir) = core();
        let (id, _) = saved(&core, "web", key());
        group(&core, "A", &[&id]);
        let b = group(&core, "B", &[]);
        let s = regroup(
            &core,
            &id,
            HostGroup::Existing {
                group_id: b.clone(),
            },
        );
        assert_eq!(s.group_id.as_deref(), Some(b.as_str()));
        assert_eq!(groups_of(&core, &id), vec!["B".to_owned()]);
    }

    #[test]
    fn an_unchanged_group_leaves_the_host_where_it_is() {
        let (core, _dir) = core();
        let (id, _) = saved(&core, "web", key());
        group(&core, "A", &[&id]);
        regroup(&core, &id, HostGroup::Unchanged);
        assert_eq!(groups_of(&core, &id), vec!["A".to_owned()]);
    }

    #[test]
    fn a_new_group_is_created_with_the_host_alone_in_it() {
        let (core, _dir) = core();
        let (id, _) = saved(&core, "web", key());
        let a = group(&core, "A", &[&id]);
        let s = regroup(&core, &id, HostGroup::New { label: "C".into() });
        assert!(s.group_id.is_some_and(|g| g != a), "no new group");
        assert_eq!(groups_of(&core, &id), vec!["C".to_owned()]);
    }

    #[test]
    fn ungrouped_takes_the_host_out_of_every_group() {
        let (core, _dir) = core();
        let (id, _) = saved(&core, "web", key());
        group(&core, "A", &[&id]);
        group(&core, "B", &[&id]);
        regroup(&core, &id, HostGroup::Ungrouped);
        assert!(groups_of(&core, &id).is_empty(), "still grouped");
    }

    /// A group still listing the id of a deleted host does not claim a new
    /// host saved under that id.
    #[test]
    fn a_new_host_drops_a_stale_group_membership() {
        let (core, _dir) = core();
        group(&core, "Old", &["web"]);
        let mut p = host("web", key());
        p.profile_id = "web".into();
        core.save_host("v", plain(p)).unwrap();
        assert!(groups_of(&core, "web").is_empty(), "stale membership kept");
    }

    /// Saving a personal host links the identity, pinned to where it points.
    #[test]
    fn a_personal_host_save_pins_its_identity() {
        let (core, _dir) = core();
        let (_, uid) = linked(&core);
        assert_eq!(
            binding_at(&core, &uid, "web.example"),
            BindingResolution::Matched {
                identity_item_id: "me".into()
            }
        );
    }

    /// An edit that moves the host from where its identity is pinned re-pins
    /// the identity to the new address.
    #[test]
    fn moving_a_personal_host_re_pins_its_identity() {
        let (core, _dir) = core();
        let (id, uid) = linked(&core);
        let mut p = stored(&core, &id);
        p.host = "moved.example".into();
        let s = core.save_host("v", plain(p)).unwrap();
        assert!(s.identity_linked, "not re-pinned");
        assert_eq!(s.binding_vault_id.as_deref(), Some("p"));
        assert_eq!(
            binding_at(&core, &uid, "moved.example"),
            BindingResolution::Matched {
                identity_item_id: "me".into()
            }
        );
    }

    /// A host someone else already pointed elsewhere keeps its identity's
    /// pin through the member's next save: the redirect stays refused, and
    /// the save says so.
    #[test]
    fn a_save_does_not_re_pin_an_identity_the_host_was_redirected_from() {
        let (core, _dir) = core();
        let (id, uid) = linked(&core);
        // Another change (synced from the team vault) points the host away.
        let mut p = stored(&core, &id);
        p.host = "evil.example".into();
        core.save_connection("v".into(), p).unwrap();
        let mut p = stored(&core, &id);
        p.label = "web box".into();
        let save = HostSave {
            identity: me(),
            ..plain(p)
        };
        let s = core.save_host("v", save).unwrap();
        assert!(!s.identity_linked, "linked to the redirected address");
        assert!(
            matches!(
                s.unfinished.as_slice(),
                [HostSaveGap::IdentityPinKept { pinned, .. }] if pinned == "web.example:22"
            ),
            "gap {:?}",
            s.unfinished
        );
        assert!(
            matches!(
                binding_at(&core, &uid, "evil.example"),
                BindingResolution::Redirected { .. }
            ),
            "redirect let through"
        );
    }

    /// A link that cannot be written leaves the host saved and says so.
    #[test]
    fn a_link_that_fails_is_reported_with_the_host_saved() {
        let (core, _dir) = core();
        let (id, uid) = saved(&core, "web", key());
        // Something else holds the binding's id in the identity's vault.
        core.save_note("p".into(), binding_item_id("v", &uid), "n".into())
            .unwrap();
        let mut p = stored(&core, &id);
        p.auth = ProfileAuth::Personal;
        let save = HostSave {
            identity: me(),
            ..plain(p)
        };
        let s = core.save_host("v", save).unwrap();
        assert!(!s.identity_linked, "linked");
        assert!(
            matches!(
                s.unfinished.as_slice(),
                [HostSaveGap::IdentityNotLinked { .. }]
            ),
            "gap not reported"
        );
        assert!(
            matches!(stored(&core, &id).auth, ProfileAuth::Personal),
            "not saved"
        );
    }

    /// The connect refuses a jump hop naming a saved host of another vault,
    /// as synced data could: a team vault's host must not borrow a member's
    /// personal-vault credential for its route.
    #[test]
    fn a_connect_refuses_a_hop_into_another_vault() {
        let (core, _dir) = core();
        let bastion = core.save_host("p", plain(host("bastion", key()))).unwrap();
        let mut p = host("web", key());
        p.jumps = vec![ref_hop("p", &bastion.uid)];
        // Written past the host rules, as a sync would.
        let id = core.save_connection("v".into(), p).unwrap();
        let p = stored(&core, &id);
        let result = core.ssh_exec(
            p.host,
            p.port,
            p.user,
            AuthMethod::Password {
                password: "x".into(),
            },
            "true".into(),
            p.jumps,
            None,
        );
        assert!(
            matches!(
                result,
                Err(FfiError::InvalidHost {
                    rule: HostRule::HopOtherVault
                })
            ),
            "connected through another vault's host"
        );
    }

    /// Resolving such a host for a connect is refused before any dial.
    #[test]
    fn resolving_a_host_with_a_hop_into_another_vault_is_refused() {
        let (core, _dir) = core();
        let bastion = core.save_host("p", plain(host("bastion", key()))).unwrap();
        let mut p = host("web", key());
        p.jumps = vec![ref_hop("p", &bastion.uid)];
        let id = core.save_connection("v".into(), p).unwrap();
        assert!(matches!(
            core.resolve_connection("v".into(), id),
            Err(FfiError::InvalidHost {
                rule: HostRule::HopOtherVault
            })
        ));
    }
}
