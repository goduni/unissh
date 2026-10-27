//! The hosts this device can reach: every connection profile in every vault,
//! found by the name people type, and resolved into a connection the way the
//! app resolves it.

use std::fmt::{Display, Write as _};

use serde_json::{json, Value};
use unissh_ffi::{
    AuthMethod, ConnectionProfile, Core, JumpHost, ProfileAuth, ProxyConfig, ServerGroup,
};

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

/// What `list` gives for every vault, each item wrapped with its vault by
/// `wrap(vault_id, vault_name, item)`.
///
/// A vault that cannot be read is reported and skipped rather than failing the
/// whole list: the other vaults' items are still reachable.
pub fn per_vault<I, T, E: Display>(
    core: &Core,
    list: impl Fn(String) -> Result<Vec<I>, E>,
    wrap: impl Fn(&str, &str, I) -> T,
) -> Res<Vec<T>> {
    let mut items = Vec::new();
    for vault in core.list_vaults()? {
        match list(vault.vault_id.clone()) {
            Ok(found) => items.extend(
                found
                    .into_iter()
                    .map(|item| wrap(&vault.vault_id, &vault.name, item)),
            ),
            Err(e) => eprintln!("unissh: skipping vault \"{}\": {e}", one_line(&vault.name)),
        }
    }
    Ok(items)
}

/// Every host of every vault, sorted by vault, then label.
pub fn load(core: &Core) -> Res<Vec<Host>> {
    let mut hosts = per_vault(
        core,
        |vault_id| core.list_connections(vault_id),
        |vault_id, vault_name, profile| Host {
            vault_id: vault_id.to_owned(),
            vault_name: vault_name.to_owned(),
            profile,
        },
    )?;
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

/// A vault item people name on the command line: a host, a snippet, a group
/// (and an MCP integration, which is named the same way outside the vaults).
pub trait Named {
    /// What it is, for messages ("host").
    const KIND: &'static str;
    /// The plural of [`Self::KIND`] ("hosts", "identities"): spelled out,
    /// since English plurals are not all a trailing "s".
    const KINDS: &'static str;
    /// The command that lists them, for the "no match" hint.
    const LISTED_BY: Option<&'static str>;
    /// How a refusal of several matches says to name one.
    const NAME_ONE: &'static str = "name one as vault/label";
    /// The name of the vault it is in.
    fn vault_name(&self) -> &str;
    /// Its label.
    fn label(&self) -> &str;
    /// Another name it answers to after the labels (a host's address).
    fn address(&self) -> Option<&str> {
        None
    }
    /// What the list of candidates shows after `vault/label`.
    fn detail(&self) -> String {
        String::new()
    }
    /// How one of them is named in a refusal of several matches, before
    /// [`Self::detail`]: `vault/label` unless it lives outside the vaults.
    fn qualified(&self) -> String {
        format!("{}/{}", one_line(self.vault_name()), one_line(self.label()))
    }
}

impl Named for Host {
    const KIND: &'static str = "host";
    const KINDS: &'static str = "hosts";
    const LISTED_BY: Option<&'static str> = Some("unissh hosts");

    fn vault_name(&self) -> &str {
        &self.vault_name
    }

    fn label(&self) -> &str {
        &self.profile.label
    }

    fn address(&self) -> Option<&str> {
        Some(&self.profile.host)
    }

    fn detail(&self) -> String {
        self.target_text()
    }
}

/// A host group and the vault it lives in.
pub struct Group {
    /// The vault's id.
    pub vault_id: String,
    /// The vault's name.
    pub vault_name: String,
    /// The group.
    pub group: ServerGroup,
}

impl Named for Group {
    const KIND: &'static str = "group";
    const KINDS: &'static str = "groups";
    const LISTED_BY: Option<&'static str> = Some("unissh groups list");

    fn vault_name(&self) -> &str {
        &self.vault_name
    }

    fn label(&self) -> &str {
        &self.group.label
    }
}

/// Every group of every vault.
pub fn load_groups(core: &Core) -> Res<Vec<Group>> {
    per_vault(
        core,
        |vault_id| core.list_groups(vault_id),
        |vault_id, vault_name, group| Group {
            vault_id: vault_id.to_owned(),
            vault_name: vault_name.to_owned(),
            group,
        },
    )
}

/// A borrowed one answers to the same names, so a lookup can run over a
/// narrowed list (`--vault`) without copying it.
impl<T: Named> Named for &T {
    const KIND: &'static str = T::KIND;
    const KINDS: &'static str = T::KINDS;
    const LISTED_BY: Option<&'static str> = T::LISTED_BY;
    const NAME_ONE: &'static str = T::NAME_ONE;

    fn vault_name(&self) -> &str {
        (**self).vault_name()
    }

    fn label(&self) -> &str {
        (**self).label()
    }

    fn address(&self) -> Option<&str> {
        (**self).address()
    }

    fn detail(&self) -> String {
        (**self).detail()
    }

    fn qualified(&self) -> String {
        (**self).qualified()
    }
}

/// The host `query` names: `vault/label`, else a label (any case), else the
/// one label it begins, else a host name. Several matches are an error that
/// lists them, never a guess.
pub fn find<'h>(hosts: &'h [Host], query: &str) -> Res<&'h Host> {
    find_named(hosts, query)
}

/// The item `query` names, by the rules of [`find`]: `vault/label`, a label,
/// the one label it begins, an address.
pub fn find_named<'i, T: Named>(items: &'i [T], query: &str) -> Res<&'i T> {
    let q = query.trim().to_lowercase();
    let by = |pred: &dyn Fn(&T) -> bool| items.iter().filter(|&i| pred(i)).collect::<Vec<_>>();
    let qualified = q.split_once('/').map_or_else(Vec::new, |(vault, label)| {
        by(&|i| i.vault_name().to_lowercase() == vault && i.label().to_lowercase() == label)
    });
    let rounds = [
        qualified,
        by(&|i| i.label().to_lowercase() == q),
        by(&|i| i.label().to_lowercase().starts_with(&q)),
        by(&|i| i.address().is_some_and(|a| a.to_lowercase() == q)),
    ];
    for found in rounds {
        match found.as_slice() {
            [] => {}
            [one] => return Ok(*one),
            many => return Err(Failure::msg(ambiguous(query, many))),
        }
    }
    let hint = T::LISTED_BY.map_or_else(String::new, |cmd| format!(" (`{cmd}` lists them)"));
    Err(Failure::msg(format!(
        "no {} matches \"{query}\"{hint}",
        T::KIND
    )))
}

fn ambiguous<T: Named>(query: &str, many: &[&T]) -> String {
    let mut text = format!("\"{query}\" matches several {}; {}:", T::KINDS, T::NAME_ONE);
    for i in many {
        let _ = write!(text, "\n  {}", i.qualified());
        let detail = i.detail();
        if !detail.is_empty() {
            let _ = write!(text, "  {}", one_line(&detail));
        }
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
    resolve_with_hint(core, host, user, &|label| {
        format!("connect as user@{label}")
    })
}

/// [`resolve`], with `no_user(label)` saying what to do about a host that
/// names no user (the hint differs between connecting and running).
pub fn resolve_with_hint(
    core: &Core,
    host: &Host,
    user: Option<&str>,
    no_user: &dyn Fn(&str) -> String,
) -> Res<Target> {
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
                    "{} needs your personal identity: {e}. Link one with \
                     `unissh hosts edit \"{}\" --identity <name>`",
                    one_line(&p.label),
                    one_line(&p.label)
                ))
            } else {
                e.into()
            }
        })?;
    let user = user.map_or(resolved.user, str::to_owned);
    if user.trim().is_empty() {
        let label = one_line(&p.label);
        return Err(Failure::msg(format!(
            "{label} names no user: {}",
            no_user(&label)
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

    /// The refusal names the kind in its plural, as spelled, not KIND + "s".
    #[test]
    fn an_ambiguous_name_is_refused_with_the_kind_in_its_plural() {
        struct Identity(&'static str);
        impl Named for Identity {
            const KIND: &'static str = "identity";
            const KINDS: &'static str = "identities";
            const LISTED_BY: Option<&'static str> = None;
            fn vault_name(&self) -> &str {
                self.0
            }
            fn label(&self) -> &str {
                "me"
            }
        }
        let Err(err) = find_named(&[Identity("team"), Identity("lab")], "me") else {
            panic!("an ambiguous name must not pick one");
        };
        assert!(err.message.contains("several identities;"), "{err}");
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
