//! The hosts this device can reach: every connection profile in every vault,
//! found by the name people type, and resolved into a connection the way the
//! app resolves it.

use std::fmt::Write as _;

use serde_json::{json, Value};
use unissh_ffi::{AuthMethod, ConnectionProfile, Core, JumpHost, ProfileAuth, ProxyConfig};

use crate::failure::{Failure, Res};
use crate::tty::one_line;

/// A host and the vault it lives in.
#[derive(Clone)]
pub struct Host {
    /// The vault's id.
    pub vault_id: String,
    /// The vault's name.
    pub vault_name: String,
    /// The connection profile.
    pub profile: ConnectionProfile,
}

impl Host {
    /// `user@host:port`, or `host:port (personal)` when the user comes from a
    /// personal identity at connect time.
    pub fn target_text(&self) -> String {
        let p = &self.profile;
        let at = if p.port == 22 {
            p.host.clone()
        } else {
            format!("{}:{}", p.host, p.port)
        };
        match (&p.auth, p.user.trim()) {
            (ProfileAuth::Personal, _) => format!("{at} (personal)"),
            (_, "") => at,
            (_, user) => format!("{user}@{at}"),
        }
    }

    /// Whether `needle` (lowercase) occurs in the label, host, vault or a tag.
    fn mentions(&self, needle: &str) -> bool {
        let p = &self.profile;
        [p.label.as_str(), p.host.as_str(), self.vault_name.as_str()]
            .into_iter()
            .chain(p.tags.iter().map(String::as_str))
            .any(|text| text.to_lowercase().contains(needle))
    }
}

/// Every host of every vault, sorted by vault, then label.
///
/// A vault that cannot be read is reported and skipped rather than failing the
/// whole list: the other vaults' hosts are still reachable.
pub fn load(core: &Core) -> Res<Vec<Host>> {
    let mut hosts = Vec::new();
    for vault in core.list_vaults()? {
        match core.list_connections(vault.vault_id.clone()) {
            Ok(profiles) => hosts.extend(profiles.into_iter().map(|profile| Host {
                vault_id: vault.vault_id.clone(),
                vault_name: vault.name.clone(),
                profile,
            })),
            Err(e) => eprintln!("unissh: skipping vault \"{}\": {e}", one_line(&vault.name)),
        }
    }
    hosts.sort_by_cached_key(|h| (h.vault_name.to_lowercase(), h.profile.label.to_lowercase()));
    Ok(hosts)
}

/// The hosts that mention `filter` and carry `tag` (both optional, case-insensitive).
pub fn filter<'h>(hosts: &'h [Host], filter: Option<&str>, tag: Option<&str>) -> Vec<&'h Host> {
    let needle = filter.map(str::to_lowercase);
    hosts
        .iter()
        .filter(|h| needle.as_deref().is_none_or(|n| h.mentions(n)))
        .filter(|h| {
            tag.is_none_or(|t| h.profile.tags.iter().any(|own| own.eq_ignore_ascii_case(t)))
        })
        .collect()
}

/// The host `query` names: `vault/label`, else a label (any case), else the
/// one label it begins, else a host name. Several matches are an error that
/// lists them, never a guess.
pub fn find<'h>(hosts: &'h [Host], query: &str) -> Res<&'h Host> {
    let q = query.trim().to_lowercase();
    let by = |pred: &dyn Fn(&Host) -> bool| hosts.iter().filter(|&h| pred(h)).collect::<Vec<_>>();
    let qualified = q.split_once('/').map_or_else(Vec::new, |(vault, label)| {
        by(&|h| h.vault_name.to_lowercase() == vault && h.profile.label.to_lowercase() == label)
    });
    let rounds = [
        qualified,
        by(&|h| h.profile.label.to_lowercase() == q),
        by(&|h| h.profile.label.to_lowercase().starts_with(&q)),
        by(&|h| h.profile.host.to_lowercase() == q),
    ];
    for found in rounds {
        match found.as_slice() {
            [] => {}
            [one] => return Ok(*one),
            many => return Err(Failure::msg(ambiguous(query, many))),
        }
    }
    Err(Failure::msg(format!(
        "no host matches \"{query}\" (`unissh hosts` lists them)"
    )))
}

fn ambiguous(query: &str, many: &[&Host]) -> String {
    let mut text = format!("\"{query}\" matches several hosts; name one as vault/label:");
    for h in many {
        let _ = write!(
            text,
            "\n  {}/{}  {}",
            one_line(&h.vault_name),
            one_line(&h.profile.label),
            one_line(&h.target_text())
        );
    }
    text
}

/// The hosts as a table, numbered when `numbered` (for the picker).
pub fn table(hosts: &[&Host], numbered: bool) -> String {
    let width = |f: &dyn Fn(&Host) -> usize| hosts.iter().map(|&h| f(h)).max().unwrap_or(0);
    let label_w = width(&|h| h.profile.label.chars().count()).min(32);
    let target_w = width(&|h| h.target_text().chars().count()).min(48);
    let vault_w = width(&|h| h.vault_name.chars().count()).min(24);
    let mut text = String::new();
    for (i, h) in hosts.iter().enumerate() {
        if numbered {
            let _ = write!(text, "{:>3}  ", i.saturating_add(1));
        }
        let _ = writeln!(
            text,
            "{:<label_w$}  {:<target_w$}  {:<vault_w$}  {}",
            one_line(&h.profile.label),
            one_line(&h.target_text()),
            one_line(&h.vault_name),
            one_line(&h.profile.tags.join(","))
        );
    }
    text
}

/// The hosts as JSON, for scripts. Names and addresses only — no secret and
/// no reference to one.
pub fn json(hosts: &[&Host]) -> Value {
    Value::Array(
        hosts
            .iter()
            .map(|h| {
                let p = &h.profile;
                json!({
                    "vault": h.vault_name,
                    "label": p.label,
                    "host": p.host,
                    "port": p.port,
                    "user": p.user,
                    "auth": auth_kind(&p.auth),
                    "tags": p.tags,
                })
            })
            .collect(),
    )
}

const fn auth_kind(auth: &ProfileAuth) -> &'static str {
    match auth {
        ProfileAuth::Key { .. } => "key",
        ProfileAuth::VaultPassword { .. } => "password",
        ProfileAuth::PromptPassword => "ask",
        ProfileAuth::SystemAgent { .. } => "system-agent",
        ProfileAuth::Personal => "personal",
    }
}

/// Where and how to connect.
pub struct Target {
    /// Host to connect to.
    pub host: String,
    /// Port.
    pub port: u16,
    /// User name to log in as.
    pub user: String,
    /// The credential, by reference to the vault (an empty password when
    /// `ask_password` is set — the caller asks for it).
    pub auth: AuthMethod,
    /// ProxyJump chain.
    pub jumps: Vec<JumpHost>,
    /// Outbound proxy for the first hop.
    pub proxy: Option<ProxyConfig>,
    /// The profile wants the password typed at every connection.
    pub ask_password: bool,
}

/// Resolves `host` into a connection with the core's resolver — the one the
/// app and local automation use (see `Core::resolve_connection`). `user`
/// replaces the user name; a Personal host refuses that, because its identity
/// decides who logs in.
pub fn resolve(core: &Core, host: &Host, user: Option<&str>) -> Res<Target> {
    let p = &host.profile;
    let personal = matches!(p.auth, ProfileAuth::Personal);
    if personal && user.is_some() {
        return Err(Failure::msg(format!(
            "{} logs in with your personal identity, which decides the user name",
            one_line(&p.label)
        )));
    }
    let resolved = core
        .resolve_connection(host.vault_id.clone(), p.profile_id.clone())
        .map_err(|e| {
            if personal {
                Failure::msg(format!(
                    "{} needs your personal identity: {e}. Link one to this host in the UniSSH app",
                    one_line(&p.label)
                ))
            } else {
                e.into()
            }
        })?;
    let user = user.map_or(resolved.user, str::to_owned);
    if user.trim().is_empty() {
        return Err(Failure::msg(format!(
            "{} names no user: connect as user@{}",
            one_line(&p.label),
            one_line(&p.label)
        )));
    }
    Ok(Target {
        host: resolved.host,
        port: resolved.port,
        user,
        auth: resolved.auth,
        jumps: resolved.jumps,
        proxy: resolved.proxy,
        ask_password: resolved.ask_password,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(vault: &str, label: &str, address: &str) -> Host {
        Host {
            vault_id: vault.to_owned(),
            vault_name: vault.to_owned(),
            profile: ConnectionProfile {
                profile_id: label.to_owned(),
                uid: String::new(),
                label: label.to_owned(),
                host: address.to_owned(),
                port: 22,
                user: "deploy".to_owned(),
                auth: ProfileAuth::PromptPassword,
                username_template: None,
                jumps: Vec::new(),
                proxy: None,
                tags: vec!["prod".to_owned()],
                startup_snippet_ids: Vec::new(),
                record_sessions: false,
                agent_forward: false,
                color: None,
                icon: None,
            },
        }
    }

    fn found<'h>(hosts: &'h [Host], query: &str) -> Option<&'h str> {
        find(hosts, query)
            .ok()
            .map(|h| h.profile.profile_id.as_str())
    }

    /// The order people expect: an exact name beats the name it begins, a
    /// label beats a host name, and `vault/label` settles the rest.
    #[test]
    fn find_prefers_exact_then_prefix_then_host_and_qualifies_by_vault() {
        let hosts = [
            host("team", "web", "10.0.0.1"),
            host("team", "web-2", "10.0.0.2"),
            host("team", "db", "db.internal"),
            host("lab", "db", "10.9.0.5"),
        ];
        assert_eq!(found(&hosts, "WEB"), Some("web"), "exact label, any case");
        assert_eq!(
            found(&hosts, "web-"),
            Some("web-2"),
            "the one label it begins"
        );
        assert_eq!(found(&hosts, "10.0.0.1"), Some("web"), "a host name");
        assert_eq!(found(&hosts, "lab/db"), Some("db"), "vault/label");
        assert_eq!(found(&hosts, "nope"), None);
    }

    /// Two hosts with one name must not be a coin toss: the error names both.
    #[test]
    fn find_refuses_an_ambiguous_name_and_lists_the_candidates() {
        let hosts = [host("team", "db", "a"), host("lab", "db", "b")];
        let Err(err) = find(&hosts, "db") else {
            panic!("an ambiguous name must not pick a host");
        };
        assert!(
            err.message.contains("team/db") && err.message.contains("lab/db"),
            "{err}"
        );
    }

    #[test]
    fn filter_matches_label_host_vault_or_tag_and_narrows_by_tag() {
        let mut staging = host("team", "api", "api.staging");
        staging.profile.tags = vec!["staging".to_owned()];
        let hosts = [host("team", "web", "10.0.0.1"), staging];
        let labels = |v: Vec<&Host>| {
            v.iter()
                .map(|h| h.profile.label.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(labels(filter(&hosts, Some("STAG"), None)), ["api"]);
        assert_eq!(labels(filter(&hosts, None, Some("prod"))), ["web"]);
        assert_eq!(labels(filter(&hosts, Some("team"), None)).len(), 2);
    }
}
