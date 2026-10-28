//! "Is this key or password still in use?" — one answer for the app (key
//! hygiene, delete warnings) and the CLI (`secrets rm`, issue #169).
//!
//! A key or password item of a vault is used by:
//! - a host of that vault that logs in with it (its own auth);
//! - a host whose inline jump hop authenticates with it;
//! - a host whose jump hop references a saved profile (`hop_ref`) in the SAME
//!   vault that logs in with it — the connect resolves the hop to that
//!   profile's auth, so the hop's own inline auth is a placeholder and ignored;
//! - a host whose proxy password is it;
//! - an identity of that vault that references it.
//!
//! Item ids are unique only per vault, so every vault-qualified reference
//! counts only when it names this vault. A `hop_ref` into another vault never
//! counts, even when that vault holds an item under the same id.
//!
//! Reads references only; no secret is decrypted or returned. The guided key
//! rotation's planner (`key_rotation_plan`) finds the machines to move with
//! these same predicates.

use std::collections::{BTreeSet, HashSet};

use super::{
    resolve_vid, AuthMethod, ConnectionProfile, Core, FfiError, Identity, ProfileAuth,
    ProxyPassword,
};

/// How a host uses the item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeyUseRole {
    /// The host logs in with it.
    Login,
    /// An inline jump hop of the host authenticates with it.
    InlineHop,
    /// A jump hop references a saved profile of this vault that logs in with it.
    ReferencedHop,
    /// The host's proxy authenticates with it (a password item).
    ProxyPassword,
}

/// A host using the item, with every way it does (each role once, in
/// [`KeyUseRole`] order).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKeyUse {
    /// The host's profile id.
    pub profile_id: String,
    /// The host's label.
    pub label: String,
    /// How it uses the item; never empty.
    pub roles: Vec<KeyUseRole>,
}

/// An identity referencing the item (as its key or its password).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityKeyUse {
    /// The identity's item id.
    pub identity_id: String,
    /// The identity's label.
    pub label: String,
}

/// Everything in a vault that uses one key or password item.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyUsage {
    /// Hosts using it, each once, in the vault's listing order.
    pub hosts: Vec<HostKeyUse>,
    /// Identities referencing it, in the vault's listing order.
    pub identities: Vec<IdentityKeyUse>,
}

impl KeyUsage {
    /// What "used by N" counts: distinct hosts plus identities.
    pub fn count(&self) -> usize {
        self.hosts.len().saturating_add(self.identities.len())
    }
}

/// Whether a host's own login is `item_id`.
pub(crate) fn logs_in_with(auth: &ProfileAuth, item_id: &str) -> bool {
    match auth {
        ProfileAuth::Key { key_item_id } => key_item_id == item_id,
        ProfileAuth::VaultPassword { password_item_id } => password_item_id == item_id,
        ProfileAuth::PromptPassword | ProfileAuth::SystemAgent { .. } | ProfileAuth::Personal => {
            false
        }
    }
}

/// Whether an inline hop's auth is item `item_id` of this vault; `same_vault`
/// says whether a vault id it names is this vault.
pub(crate) fn auth_uses(
    auth: &AuthMethod,
    item_id: &str,
    same_vault: &impl Fn(&str) -> bool,
) -> bool {
    match auth {
        AuthMethod::Agent {
            vault_id,
            key_item_id,
        } => key_item_id == item_id && same_vault(vault_id),
        AuthMethod::VaultPassword {
            vault_id,
            password_item_id,
        } => password_item_id == item_id && same_vault(vault_id),
        AuthMethod::Password { .. } | AuthMethod::SystemAgent { .. } => false,
    }
}

/// The usage of `item_id` among `hosts` and `identities` (one vault's own).
/// `same_vault` says whether a vault id named by a reference is this vault.
fn usage_in(
    item_id: &str,
    same_vault: impl Fn(&str) -> bool,
    hosts: &[ConnectionProfile],
    identities: &[Identity],
) -> KeyUsage {
    if item_id.is_empty() {
        return KeyUsage::default();
    }
    let inline = |auth: &AuthMethod| auth_uses(auth, item_id, &same_vault);
    // Profiles of this vault whose own login is the item, by uid: what a
    // referenced hop resolves to.
    let login_uids: HashSet<&str> = hosts
        .iter()
        .filter(|h| logs_in_with(&h.auth, item_id))
        .map(|h| h.uid.as_str())
        .collect();
    let mut out = KeyUsage::default();
    for h in hosts {
        let mut roles = BTreeSet::new();
        if logs_in_with(&h.auth, item_id) {
            roles.insert(KeyUseRole::Login);
        }
        for j in &h.jumps {
            let role = match &j.hop_ref {
                Some(r) => (same_vault(&r.vault_id) && login_uids.contains(r.profile_uid.as_str()))
                    .then_some(KeyUseRole::ReferencedHop),
                None => inline(&j.auth).then_some(KeyUseRole::InlineHop),
            };
            roles.extend(role);
        }
        let proxied = matches!(
            h.proxy.as_ref().and_then(|p| p.password.as_ref()),
            Some(ProxyPassword::Vault { vault_id, password_item_id })
                if password_item_id == item_id && same_vault(vault_id)
        );
        if proxied {
            roles.insert(KeyUseRole::ProxyPassword);
        }
        if !roles.is_empty() {
            out.hosts.push(HostKeyUse {
                profile_id: h.profile_id.clone(),
                label: h.label.clone(),
                roles: roles.into_iter().collect(),
            });
        }
    }
    out.identities = identities
        .iter()
        .filter(|i| {
            i.key_item_id.as_deref() == Some(item_id)
                || i.password_item_id.as_deref() == Some(item_id)
        })
        .map(|i| IdentityKeyUse {
            identity_id: i.identity_id.clone(),
            label: i.label.clone(),
        })
        .collect();
    out
}

/// Every vault id a host's references name (hops, hop refs, proxy).
fn named_vaults(hosts: &[ConnectionProfile]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for h in hosts {
        for j in &h.jumps {
            if let Some(r) = &j.hop_ref {
                out.insert(r.vault_id.clone());
            }
            match &j.auth {
                AuthMethod::Agent { vault_id, .. } | AuthMethod::VaultPassword { vault_id, .. } => {
                    out.insert(vault_id.clone());
                }
                AuthMethod::Password { .. } | AuthMethod::SystemAgent { .. } => {}
            }
        }
        if let Some(ProxyPassword::Vault { vault_id, .. }) =
            h.proxy.as_ref().and_then(|p| p.password.as_ref())
        {
            out.insert(vault_id.clone());
        }
    }
    out
}

impl Core {
    /// The vault ids `hosts`' references name that are vault `vault_id`. A
    /// reference may name the vault by any id `resolve_vid` accepts, so this
    /// compares what they resolve to, not the strings.
    pub(crate) fn names_of_vault(
        &self,
        vault_id: &str,
        hosts: &[ConnectionProfile],
    ) -> Result<BTreeSet<String>, FfiError> {
        let names = named_vaults(hosts);
        self.with_state(|state| {
            let vid = resolve_vid(&state.storage, vault_id);
            Ok(names
                .into_iter()
                .filter(|n| resolve_vid(&state.storage, n) == vid)
                .collect())
        })
    }

    /// What in vault `vault_id` uses the key or password item `item_id`: hosts
    /// (own login, inline hop, hop referencing a saved profile of this vault,
    /// proxy password) and identities. See the module docs for the rules. An
    /// id nothing references (or no item at all) is an empty usage.
    pub fn key_usage(&self, vault_id: String, item_id: String) -> Result<KeyUsage, FfiError> {
        let hosts = self.list_connections(vault_id.clone())?;
        let identities = self.list_identities(vault_id.clone())?;
        let same = self.names_of_vault(&vault_id, &hosts)?;
        Ok(usage_in(
            &item_id,
            |v| same.contains(v),
            &hosts,
            &identities,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HopRef, JumpHost, ProxyConfig, ProxyKind};

    fn host(profile_id: &str, auth: ProfileAuth, jumps: Vec<JumpHost>) -> ConnectionProfile {
        ConnectionProfile {
            profile_id: profile_id.to_owned(),
            uid: format!("uid-{profile_id}"),
            label: profile_id.to_owned(),
            host: format!("{profile_id}.example"),
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

    fn key(id: &str) -> ProfileAuth {
        ProfileAuth::Key {
            key_item_id: id.to_owned(),
        }
    }

    fn inline_hop(vault_id: &str, key_item_id: &str) -> JumpHost {
        JumpHost {
            host: "bastion.example".to_owned(),
            port: 22,
            user: "ops".to_owned(),
            auth: AuthMethod::Agent {
                vault_id: vault_id.to_owned(),
                key_item_id: key_item_id.to_owned(),
            },
            hop_ref: None,
        }
    }

    /// A hop referencing profile `target` of `vault_id`; its inline auth names
    /// the item, which must not count (a ref hop's inline auth is a placeholder).
    fn ref_hop(vault_id: &str, target: &str) -> JumpHost {
        JumpHost {
            hop_ref: Some(HopRef {
                vault_id: vault_id.to_owned(),
                profile_uid: format!("uid-{target}"),
            }),
            ..inline_hop(vault_id, "k")
        }
    }

    fn identity(id: &str, key_item_id: Option<&str>, password_item_id: Option<&str>) -> Identity {
        Identity {
            identity_id: id.to_owned(),
            label: id.to_owned(),
            user: "alice".to_owned(),
            key_item_id: key_item_id.map(str::to_owned),
            password_item_id: password_item_id.map(str::to_owned),
        }
    }

    /// `usage_in` for vault `v`.
    fn usage(item_id: &str, hosts: &[ConnectionProfile], identities: &[Identity]) -> KeyUsage {
        usage_in(item_id, |v| v == "v", hosts, identities)
    }

    fn roles(u: &KeyUsage) -> Vec<(&str, Vec<KeyUseRole>)> {
        u.hosts
            .iter()
            .map(|h| (h.profile_id.as_str(), h.roles.clone()))
            .collect()
    }

    #[test]
    fn a_host_logging_in_with_the_item_is_a_login_use() {
        let u = usage(
            "pw",
            &[host(
                "web",
                ProfileAuth::VaultPassword {
                    password_item_id: "pw".to_owned(),
                },
                vec![],
            )],
            &[],
        );
        assert_eq!(roles(&u), vec![("web", vec![KeyUseRole::Login])]);
    }

    #[test]
    fn an_inline_hop_counts_only_with_this_vaults_item() {
        let u = usage(
            "k",
            &[
                host(
                    "db",
                    ProfileAuth::PromptPassword,
                    vec![inline_hop("v", "k")],
                ),
                host(
                    "far",
                    ProfileAuth::PromptPassword,
                    vec![inline_hop("w", "k")],
                ),
            ],
            &[],
        );
        assert_eq!(roles(&u), vec![("db", vec![KeyUseRole::InlineHop])]);
    }

    #[test]
    fn a_hop_referencing_a_profile_that_logs_in_with_the_item_is_a_referenced_hop_use() {
        let u = usage(
            "k",
            &[
                host("bastion", key("k"), vec![]),
                host("other", ProfileAuth::PromptPassword, vec![]),
                host(
                    "db",
                    ProfileAuth::PromptPassword,
                    vec![ref_hop("v", "bastion")],
                ),
                host(
                    "cache",
                    ProfileAuth::PromptPassword,
                    vec![ref_hop("v", "other")],
                ),
            ],
            &[],
        );
        assert_eq!(
            roles(&u),
            vec![
                ("bastion", vec![KeyUseRole::Login]),
                ("db", vec![KeyUseRole::ReferencedHop]),
            ]
        );
    }

    #[test]
    fn a_proxy_password_is_a_proxy_use() {
        let mut h = host("web", ProfileAuth::PromptPassword, vec![]);
        h.proxy = Some(ProxyConfig {
            kind: ProxyKind::Socks5,
            host: "proxy.example".to_owned(),
            port: 1080,
            username: Some("p".to_owned()),
            password: Some(ProxyPassword::Vault {
                vault_id: "v".to_owned(),
                password_item_id: "pw".to_owned(),
            }),
        });
        assert_eq!(
            roles(&usage("pw", &[h], &[])),
            vec![("web", vec![KeyUseRole::ProxyPassword])]
        );
    }

    #[test]
    fn identities_referencing_the_item_as_key_or_password_are_listed() {
        let u = usage(
            "k",
            &[],
            &[
                identity("by-key", Some("k"), None),
                identity("by-password", None, Some("k")),
                identity("unrelated", Some("other"), None),
            ],
        );
        let ids: Vec<&str> = u
            .identities
            .iter()
            .map(|i| i.identity_id.as_str())
            .collect();
        assert_eq!(ids, vec!["by-key", "by-password"]);
    }

    #[test]
    fn a_host_using_the_item_several_ways_is_counted_once_with_each_role() {
        let u = usage(
            "k",
            &[
                host("bastion", key("k"), vec![]),
                host(
                    "api",
                    key("k"),
                    vec![
                        inline_hop("v", "k"),
                        inline_hop("v", "k"),
                        ref_hop("v", "bastion"),
                    ],
                ),
            ],
            &[identity("me", Some("k"), None)],
        );
        assert_eq!(
            roles(&u)[1],
            (
                "api",
                vec![
                    KeyUseRole::Login,
                    KeyUseRole::InlineHop,
                    KeyUseRole::ReferencedHop
                ]
            )
        );
        assert_eq!(u.count(), 3);
    }

    #[test]
    fn items_referencing_something_else_are_not_counted() {
        let u = usage(
            "k",
            &[host("web", key("other"), vec![inline_hop("v", "other")])],
            &[identity("me", Some("other"), Some("pw"))],
        );
        assert_eq!(u, KeyUsage::default());
    }

    /// Through the core: a `hop_ref` resolves within the vault only — a hop
    /// into another vault's profile that logs in with a same-id key there does
    /// not count here, one into this vault's profile does.
    #[test]
    fn a_referenced_hop_resolves_within_the_vault_only() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::new(
            dir.path().join("i.db").to_string_lossy().into_owned(),
            dir.path().join("i.keyset").to_string_lossy().into_owned(),
        );
        core.create_account(None).unwrap();
        for vault in ["v", "w"] {
            core.create_vault(vault.to_owned(), vault.to_uppercase())
                .unwrap();
        }
        let save = |vault: &str, h: ConnectionProfile| {
            core.save_connection(vault.to_owned(), h).unwrap();
        };
        save("v", host("bastion", key("k"), vec![]));
        save("w", host("bastion", key("k"), vec![]));
        save(
            "v",
            host(
                "db",
                ProfileAuth::PromptPassword,
                vec![ref_hop("v", "bastion")],
            ),
        );
        save(
            "v",
            host(
                "far",
                ProfileAuth::PromptPassword,
                vec![ref_hop("w", "bastion")],
            ),
        );
        let u = core.key_usage("v".to_owned(), "k".to_owned()).unwrap();
        assert_eq!(
            roles(&u),
            vec![
                ("bastion", vec![KeyUseRole::Login]),
                ("db", vec![KeyUseRole::ReferencedHop]),
            ]
        );
    }
}
