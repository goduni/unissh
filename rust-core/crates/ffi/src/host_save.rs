//! Saving a host: one path for the app's host editor and `unissh hosts
//! add|edit` (issue #167).
//!
//! [`Core::save_host`] checks a host against the rules every saved host keeps
//! ([`HostRule`]), then writes it with what goes with it, all under one state
//! lock:
//!
//! - a password typed for the host, stored as a vault secret under an id
//!   minted here, together with the host in one storage transaction;
//! - the host's group: a host is in one group at most, so going into one
//!   takes it out of every other (a new group is created by the save), in
//!   the same transaction;
//! - for a personal host, the binding of the member's identity, pinned to
//!   where the host now points (the identity given, else the one already
//!   linked to it);
//! - the password the host used before, removed when a typed one replaced it
//!   and nothing else in the vault uses it.
//!
//! The password, the host and its groups are written all or nothing. The
//! binding lives in another vault and the old password is only tidied away,
//! so either failing leaves the host saved, and the result says what is
//! missing ([`HostSaved::unfinished`]); it is never left out silently.

use std::fmt;

use zeroize::Zeroizing;

use crate::item_ids::mint_item_id;
use crate::key_usage::usage_in;
use crate::{
    binding_in, binding_vault_in, groups_in, identities_in, personal_destination, profiles_in,
    put_binding, put_connection, put_group, put_password, remove_item, resolve_vid, AuthMethod,
    ConnectionProfile, Core, CoreState, FfiError, IdentityBinding, JumpHost, ProfileAuth,
    ServerGroup,
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
    /// A jump hop references a saved host of another vault.
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
    /// (`slug(label)-<millis>`); an empty `uid` on an existing host keeps the
    /// one it has. Jump hops that reference a saved host are stored in the
    /// placeholder shape the connect expects (their inline fields are
    /// ignored). The username template is kept for a personal login only.
    pub profile: ConnectionProfile,
    /// A password typed for the host: stored as a new vault secret that the
    /// host then logs in with. The host's `auth` must be `VaultPassword`; its
    /// `password_item_id` is replaced by the new secret's id.
    pub new_password: Option<Zeroizing<String>>,
    /// The group the host is in.
    pub group: HostGroup,
    /// For a personal host: the identity to link. `None` re-pins the identity
    /// already linked to an existing host, if any.
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
    /// The password the host used before, replaced by the one typed, could
    /// not be removed: it is still in the vault, used by nothing.
    OldPasswordKept {
        /// The old password's item id.
        password_item_id: String,
        /// Why.
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
    /// The secret stored for a password typed for the host.
    pub password_item_id: Option<String>,
    /// The group the host is now in, when the save placed it in one (a new
    /// group's minted id included).
    pub group_id: Option<String>,
    /// Whether an identity is linked to the host and pinned to where it
    /// points now.
    pub identity_linked: bool,
    /// The password the host used before, removed because a typed one
    /// replaced it and nothing else used it.
    pub removed_password_item_id: Option<String>,
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

impl Core {
    /// Saves a host the way the app's editor and `unissh hosts add|edit` do:
    /// checks it ([`HostRule`]; [`FfiError::InvalidHost`] and nothing written
    /// when one is broken), then stores it with its new password and its
    /// group in one transaction, links or re-pins a personal identity, and
    /// removes the password a typed one replaced. See the module docs.
    pub fn save_host(&self, vault_id: &str, save: HostSave) -> Result<HostSaved, FfiError> {
        self.with_state_mut(|state| save_locked(state, vault_id, save))
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

fn save_locked(
    state: &mut CoreState,
    vault_id: &str,
    save: HostSave,
) -> Result<HostSaved, FfiError> {
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
    if profile.uid.is_empty() {
        profile.uid = before.as_ref().map(|b| b.uid.clone()).unwrap_or_default();
    }
    tidy(&mut profile);
    check_fields(&profile)?;
    check_new_password(&profile, new_password.as_deref().map(String::as_str))?;
    check_hops(state, vault_id, &mut profile, &hosts)?;
    let group = checked_group(state, vault_id, group, before.is_none())?;
    let link = link_to_pin(state, vault_id, &profile, identity)?;

    // Where a personal host points, for its binding's pin: the connect
    // renders the same string from the stored host.
    let pin = personal_destination(
        &profile.host,
        profile.port,
        profile.username_template.as_deref(),
        &profile.jumps,
        profile.proxy.as_ref(),
    );
    // The password a typed one replaces, to tidy away once the host is saved.
    let replaced = match &before {
        Some(ConnectionProfile {
            auth: ProfileAuth::VaultPassword { password_item_id },
            ..
        }) if new_password.is_some() && !password_item_id.is_empty() => {
            Some(password_item_id.clone())
        }
        Some(_) | None => None,
    };
    let written = {
        let shared = &*state;
        shared.storage.transaction(|| {
            write_host(
                shared,
                vault_id,
                profile,
                new_password.as_deref().map(String::as_str),
                &group,
            )
        })?
    };

    let mut unfinished = Vec::new();
    let mut identity_linked = false;
    if let Some(link) = link {
        let binding = IdentityBinding {
            team_vault_id: vault_id.to_owned(),
            profile_uid: written.uid.clone(),
            identity_item_id: link.identity_id,
            destination_pin: pin,
        };
        // Saving the host is the user's explicit word on where it points, so
        // the pin follows it (as the editors always did).
        match put_binding(state, &link.vault_id, binding, true) {
            Ok(()) => identity_linked = true,
            Err(e) => unfinished.push(HostSaveGap::IdentityNotLinked {
                message: e.to_string(),
            }),
        }
    }
    let removed_password_item_id = match replaced {
        Some(old) => match remove_if_unused(state, vault_id, &old) {
            Ok(true) => Some(old),
            Ok(false) => None,
            Err(e) => {
                unfinished.push(HostSaveGap::OldPasswordKept {
                    password_item_id: old,
                    message: e.to_string(),
                });
                None
            }
        },
        None => None,
    };
    Ok(HostSaved {
        profile_id: written.profile_id,
        uid: written.uid,
        password_item_id: written.password_item_id,
        group_id: written.group_id,
        identity_linked,
        removed_password_item_id,
        unfinished,
    })
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

/// The hop rules. A hop given by address needs one. A hop referencing a
/// saved host must name another host of the same vault, by its uid, that logs
/// in with a key, a stored password or the system ssh-agent; it is stored in
/// the placeholder shape (no inline fields), as the connect resolves it from
/// the referenced host.
fn check_hops(
    state: &CoreState,
    vault_id: &str,
    profile: &mut ConnectionProfile,
    hosts: &[ConnectionProfile],
) -> Result<(), FfiError> {
    let vid = resolve_vid(&state.storage, vault_id);
    for hop in &mut profile.jumps {
        let Some(hop_ref) = hop.hop_ref.clone() else {
            if hop.host.trim().is_empty() {
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

/// The identity to pin to a personal host: the one given (which must exist
/// and needs a personal login), else the one already linked to an existing
/// personal host.
fn link_to_pin(
    state: &CoreState,
    vault_id: &str,
    profile: &ConnectionProfile,
    given: Option<IdentityLink>,
) -> Result<Option<IdentityLink>, FfiError> {
    let personal = matches!(profile.auth, ProfileAuth::Personal);
    if let Some(link) = given {
        if !personal {
            return Err(refused(HostRule::IdentityNeedsPersonalLogin));
        }
        let found = identities_in(state, &link.vault_id)
            .is_ok_and(|ids| ids.iter().any(|i| i.identity_id == link.identity_id));
        if !found {
            return Err(refused(HostRule::IdentityNotFound));
        }
        return Ok(Some(link));
    }
    if !personal || profile.uid.is_empty() {
        return Ok(None);
    }
    let Some(binding_vault) = binding_vault_in(state, vault_id, &profile.uid)? else {
        return Ok(None);
    };
    Ok(
        binding_in(state, &binding_vault, vault_id, &profile.uid)?.map(|b| IdentityLink {
            vault_id: binding_vault,
            identity_id: b.identity_item_id,
        }),
    )
}

/// The writes that go together, inside the storage transaction: the typed
/// password, the host, its groups.
fn write_host(
    state: &CoreState,
    vault_id: &str,
    mut profile: ConnectionProfile,
    new_password: Option<&str>,
    group: &HostGroup,
) -> Result<Written, FfiError> {
    let password_item_id = match new_password {
        Some(password) => {
            // Written before the host, so the host's own minted id steps past it.
            let id = mint_item_id(
                &state.storage,
                vault_id,
                &format!("{} pw", profile.label),
                "item",
            )?;
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

/// Removes the password item `old` a typed password replaced, unless
/// something in the vault still uses it (another host, a hop, a proxy, an
/// identity). Whether it was removed.
fn remove_if_unused(state: &mut CoreState, vault_id: &str, old: &str) -> Result<bool, FfiError> {
    let hosts = profiles_in(state, vault_id)?;
    let identities = identities_in(state, vault_id)?;
    let vid = resolve_vid(&state.storage, vault_id);
    let storage = &state.storage;
    let used = usage_in(old, |v| resolve_vid(storage, v) == vid, &hosts, &identities).count();
    if used > 0 {
        return Ok(false);
    }
    remove_item(state, vault_id, old)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use zeroize::Zeroizing;

    use super::{HostGroup, HostRule, HostSave, HostSaveGap, IdentityLink};
    use crate::{
        binding_item_id, AuthMethod, BindingResolution, ConnectionProfile, Core, FfiError, HopRef,
        Identity, JumpHost, ProfileAuth, ServerGroup, ITEM_TYPE_PASSWORD,
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

    /// A user is needed unless the login is personal (the identity names it).
    #[test]
    fn a_host_without_a_user_is_refused_unless_it_logs_in_personally() {
        let (core, _dir) = core();
        let mut p = host("web", key());
        p.user = String::new();
        assert_eq!(refusal(&core, plain(p.clone())), HostRule::UserRequired);
        p.auth = ProfileAuth::Personal;
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
        let mut p = core.get_connection("v".into(), id).unwrap();
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
            let p = core.get_connection("v".into(), s.profile_id).unwrap();
            let hop = p.jumps[0].clone();
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
        let stored = core.get_connection("v".into(), s.profile_id).unwrap();
        assert_eq!(stored.uid, s.uid);
    }

    /// An edit that leaves the uid out keeps the one the host has, so its
    /// binding and the hops naming it still find it.
    #[test]
    fn an_edit_without_a_uid_keeps_the_hosts_uid() {
        let (core, _dir) = core();
        let (id, uid) = saved(&core, "web", key());
        let mut p = core.get_connection("v".into(), id).unwrap();
        p.uid = String::new();
        assert_eq!(core.save_host("v", plain(p)).unwrap().uid, uid);
    }

    #[test]
    fn the_username_template_is_kept_for_a_personal_login_only() {
        let (core, _dir) = core();
        let mut p = host("web", key());
        p.username_template = Some("%u:web".into());
        let s = core.save_host("v", plain(p.clone())).unwrap();
        let stored = core.get_connection("v".into(), s.profile_id).unwrap();
        assert!(stored.username_template.is_none(), "template kept");
        p.auth = ProfileAuth::Personal;
        let s = core.save_host("v", plain(p)).unwrap();
        let stored = core.get_connection("v".into(), s.profile_id).unwrap();
        assert_eq!(stored.username_template.as_deref(), Some("%u:web"));
    }

    /// The typed password is stored and logged in with; a later one replaces
    /// it, and the replaced one goes, as nothing else uses it.
    #[test]
    fn a_typed_password_is_stored_and_the_one_it_replaces_removed() {
        let (core, _dir) = core();
        let s = core
            .save_host("v", typed(host("web", stored_password()), "first"))
            .unwrap();
        let first = s.password_item_id.unwrap();
        let read = core.get_password("v".into(), first.clone()).unwrap();
        assert_eq!(read, "first");
        let edit = core.get_connection("v".into(), s.profile_id).unwrap();
        let s = core.save_host("v", typed(edit, "second")).unwrap();
        let second = s.password_item_id.unwrap();
        assert_eq!(s.removed_password_item_id.as_deref(), Some(first.as_str()));
        assert_eq!(passwords(&core), vec![second.clone()]);
        let stored = core.get_connection("v".into(), s.profile_id).unwrap();
        assert!(
            matches!(&stored.auth, ProfileAuth::VaultPassword { password_item_id } if *password_item_id == second),
            "host does not log in with the new password"
        );
    }

    #[test]
    fn a_replaced_password_still_used_elsewhere_is_kept() {
        let (core, _dir) = core();
        core.save_password("v".into(), "shared".into(), "pw".into())
            .unwrap();
        let shared = || ProfileAuth::VaultPassword {
            password_item_id: "shared".into(),
        };
        saved(&core, "db", shared());
        let (id, _) = saved(&core, "web", shared());
        let edit = core.get_connection("v".into(), id).unwrap();
        let s = core.save_host("v", typed(edit, "new")).unwrap();
        assert!(s.removed_password_item_id.is_none(), "removed");
        assert!(passwords(&core).contains(&"shared".to_owned()), "gone");
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

    /// A host is in one group: going into one takes it out of the others; a
    /// new group is created by the save; "ungrouped" takes it out of all;
    /// "unchanged" leaves them.
    #[test]
    fn a_host_is_in_one_group() {
        let (core, _dir) = core();
        let (id, _) = saved(&core, "web", key());
        let a = group(&core, "A", &[&id]);
        let b = group(&core, "B", &[]);
        let edit = |group: HostGroup| {
            let p = core.get_connection("v".into(), id.clone()).unwrap();
            core.save_host("v", HostSave { group, ..plain(p) }).unwrap()
        };
        let s = edit(HostGroup::Existing {
            group_id: b.clone(),
        });
        assert_eq!(s.group_id.as_deref(), Some(b.as_str()));
        assert_eq!(groups_of(&core, &id), vec!["B".to_owned()]);
        edit(HostGroup::Unchanged);
        assert_eq!(groups_of(&core, &id), vec!["B".to_owned()]);
        let s = edit(HostGroup::New { label: "C".into() });
        assert_eq!(groups_of(&core, &id), vec!["C".to_owned()]);
        assert!(s.group_id.is_some_and(|g| g != a && g != b), "no new group");
        edit(HostGroup::Ungrouped);
        assert!(groups_of(&core, &id).is_empty(), "still grouped");
    }

    /// Saving a personal host links the identity, pinned to where the host
    /// points; an edit that moves the host re-pins the identity linked.
    #[test]
    fn a_personal_host_save_pins_and_re_pins_its_identity() {
        let (core, _dir) = core();
        let save = HostSave {
            identity: me(),
            ..plain(host("web", ProfileAuth::Personal))
        };
        let s = core.save_host("v", save).unwrap();
        assert!(s.identity_linked, "not linked");
        let mut p = core.get_connection("v".into(), s.profile_id).unwrap();
        p.host = "moved.example".into();
        let s = core.save_host("v", plain(p)).unwrap();
        assert!(s.identity_linked, "not re-pinned");
        let now = core.personal_destination("moved.example".into(), 22, None, vec![], None);
        let resolved = core
            .resolve_host_binding("p".into(), "v".into(), s.uid, now)
            .unwrap();
        assert_eq!(
            resolved,
            BindingResolution::Matched {
                identity_item_id: "me".into()
            }
        );
    }

    /// A link that cannot be written leaves the host saved and says so.
    #[test]
    fn a_link_that_fails_is_reported_with_the_host_saved() {
        let (core, _dir) = core();
        let mut p = host("web", key());
        p.uid = "u1".into();
        let id = core.save_connection("v".into(), p.clone()).unwrap();
        // Something else holds the binding's id in the identity's vault.
        core.save_note("p".into(), binding_item_id("v", "u1"), "n".into())
            .unwrap();
        p.profile_id.clone_from(&id);
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
        let stored = core.get_connection("v".into(), id).unwrap();
        assert!(matches!(stored.auth, ProfileAuth::Personal), "not saved");
    }
}
