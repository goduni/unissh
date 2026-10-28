//! Editing hosts and their groups: `unissh hosts add|edit|rm` and
//! `unissh groups`, with the fields and rules of the app's host editor and
//! its Host groups.
//!
//! A host refers to its credentials, never holds them: a key or stored
//! password in its own vault, the system ssh-agent's key by its public half,
//! or the member's personal identity. A password typed for a new host is
//! stored as a vault secret first, as the app does.

use clap::{Args, Subcommand, ValueEnum};
use serde_json::{json, Value};
use unissh_ffi::{
    AuthMethod, ConnectionProfile, Core, FfiError, HopRef, HostGroup, HostRule, HostSave,
    HostSaveGap, IdentityLink, JumpHost, ProfileAuth, ProxyConfig, ProxyKind, ProxyPassword,
    ServerGroup,
};
use zeroize::Zeroizing;

use crate::device::Device;
use crate::edit::{
    self, clearable, columns, commit, list, print_json, stored, syncs, take, SecretFrom, Shape,
    Switch, VaultArg,
};
use crate::failure::{Failure, Res};
use crate::hosts::{self, find_named, Group, Host};
use crate::secrets::{self, IdentityEntry, Key, Password};
use crate::server;
use crate::snippet_edit;
use crate::tty::{confirm, one_line};

/// How a host logs in.
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AuthKind {
    /// An SSH key from the vault (--key).
    Key,
    /// A password stored in the vault (--password-item, or a new one).
    Password,
    /// A password typed at every connection.
    Ask,
    /// Each member's own personal identity (--identity).
    Personal,
    /// A key held by the system ssh-agent (--agent-key).
    SystemAgent,
}

impl AuthKind {
    const fn name(self) -> &'static str {
        match self {
            Self::Key => "key",
            Self::Password => "password",
            Self::Ask => "ask",
            Self::Personal => "personal",
            Self::SystemAgent => "system-agent",
        }
    }

    const fn flag(self) -> &'static str {
        match self {
            Self::Key => "--key",
            Self::Password => "--password-item",
            Self::Ask => "--auth ask",
            Self::Personal => "--identity",
            Self::SystemAgent => "--agent-key",
        }
    }
}

/// The colour tags the app offers (`TAG_COLORS` in client/src/theme/tokens.ts).
/// The core checks only that a colour is an id, so that one a newer app
/// offers survives an older one; what is offered is the app's list.
const COLORS: [&str; 9] = [
    "red", "orange", "amber", "green", "teal", "blue", "violet", "pink", "gray",
];

/// The icons the app offers for a host or a group (`APPEARANCE_ICONS` in
/// client/src/components/appearance.ts).
const ICONS: [&str; 19] = [
    "server", "database", "globe", "cloud", "shield", "terminal", "drive", "box", "layers",
    "branch", "zap", "home", "users", "lock", "activity", "radio", "grid", "star", "heart",
];

/// A colour tag and an icon, for a host or a group.
#[derive(Args)]
pub struct Look {
    /// Colour tag: red, orange, amber, green, teal, blue, violet, pink or
    /// gray; empty for none (a host then takes its group's).
    #[arg(long, value_name = "COLOUR")]
    color: Option<String>,
    /// Icon: server, database, globe, cloud, shield, terminal, drive, box,
    /// layers, branch, zap, home, users, lock, activity, radio, grid, star or
    /// heart; empty for the default.
    #[arg(long, value_name = "ICON")]
    icon: Option<String>,
}

impl Look {
    const fn given(&self) -> bool {
        self.color.is_some() || self.icon.is_some()
    }

    fn apply(&self, color: &mut Option<String>, icon: &mut Option<String>) -> Res<()> {
        if let Some(c) = &self.color {
            *color = appearance(c, &COLORS, "colour")?;
        }
        if let Some(i) = &self.icon {
            *icon = appearance(i, &ICONS, "icon")?;
        }
        Ok(())
    }
}

/// `given` as a colour or icon id from `offered`; empty is none.
fn appearance(given: &str, offered: &[&str], what: &str) -> Res<Option<String>> {
    let Some(id) = clearable(given).map(|id| id.to_ascii_lowercase()) else {
        return Ok(None);
    };
    if offered.contains(&id.as_str()) {
        Ok(Some(id))
    } else {
        Err(Failure::msg(format!(
            "\"{}\" is not a {what} the app offers: {}",
            one_line(given.trim()),
            offered.join(", ")
        )))
    }
}

/// The fields of the app's host editor. Each one left out is left as it is.
#[derive(Args)]
pub struct HostFields {
    /// The user to log in as.
    #[arg(long)]
    user: Option<String>,
    /// The SSH port.
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
    port: Option<u16>,
    /// How it logs in. The flags below imply it.
    #[arg(long, value_enum)]
    auth: Option<AuthKind>,
    /// Log in with this SSH key from the host's vault.
    #[arg(long, value_name = "KEY")]
    key: Option<String>,
    /// Log in with this stored password. `--auth password` without it stores
    /// a new password, asked on the terminal (or --stdin, --from-file).
    #[arg(long, value_name = "SECRET")]
    password_item: Option<String>,
    #[command(flatten)]
    new_password: SecretFrom,
    /// Log in with this key of the system ssh-agent: its public-key line, or
    /// the agent's comment for it.
    #[arg(long, value_name = "KEY")]
    agent_key: Option<String>,
    /// Log in with your personal identity: link this one ([vault/]name).
    #[arg(long, value_name = "IDENTITY")]
    identity: Option<String>,
    /// For a personal login: the user name to send, `%u` standing for the
    /// identity's (for gateways); empty for none.
    #[arg(long, value_name = "TEMPLATE")]
    username_template: Option<String>,
    /// A jump host: a saved host of the same vault that logs in with a key,
    /// a stored password or the system ssh-agent, or user@host[:port]. Repeat
    /// it for a chain, first hop first; on `edit` it replaces the chain.
    #[arg(long = "jump", value_name = "HOST")]
    jumps: Vec<String>,
    /// No jump host.
    #[arg(long, conflicts_with = "jumps")]
    no_jump: bool,
    /// The SSH key a jump host given as user@host logs in with. It goes with
    /// --jump (on `edit` too: give the chain again).
    #[arg(long, value_name = "KEY")]
    jump_key: Option<String>,
    /// The stored password a jump host given as user@host logs in with. It
    /// goes with --jump, like --jump-key.
    #[arg(long, value_name = "SECRET", conflicts_with = "jump_key")]
    jump_password_item: Option<String>,
    /// Outbound proxy for the first hop: http://, socks4:// or
    /// socks5://[user@]host[:port] (port 1080 if left out); empty for none.
    #[arg(long, value_name = "URL")]
    proxy: Option<String>,
    /// The stored password the proxy wants; empty for none.
    #[arg(long, value_name = "SECRET")]
    proxy_password_item: Option<String>,
    /// The group it is in (a host is in one); empty for none.
    #[arg(long)]
    group: Option<String>,
    #[command(flatten)]
    look: Look,
    /// Tags, comma-separated; empty for none.
    #[arg(long, value_name = "TAGS")]
    tags: Option<String>,
    /// Snippets typed into the shell right after connecting (in the app),
    /// comma-separated, in order; empty for none.
    #[arg(long, value_name = "SNIPPETS")]
    startup_snippets: Option<String>,
    /// Record interactive sessions with this host.
    #[arg(long, value_name = "on|off")]
    record: Option<Switch>,
    /// Forward the ssh-agent to this host (every signature is confirmed).
    #[arg(long, value_name = "on|off")]
    agent_forward: Option<Switch>,
}

impl HostFields {
    const fn given(&self) -> bool {
        self.user.is_some()
            || self.port.is_some()
            || self.auth.is_some()
            || self.key.is_some()
            || self.password_item.is_some()
            || self.new_password.given()
            || self.agent_key.is_some()
            || self.identity.is_some()
            || self.username_template.is_some()
            || !self.jumps.is_empty()
            || self.no_jump
            || self.jump_key.is_some()
            || self.jump_password_item.is_some()
            || self.proxy.is_some()
            || self.proxy_password_item.is_some()
            || self.group.is_some()
            || self.look.given()
            || self.tags.is_some()
            || self.startup_snippets.is_some()
            || self.record.is_some()
            || self.agent_forward.is_some()
    }

    /// The logins the credential flags imply.
    fn implied_auth(&self) -> Vec<AuthKind> {
        [
            (self.key.is_some(), AuthKind::Key),
            (self.password_item.is_some(), AuthKind::Password),
            (self.agent_key.is_some(), AuthKind::SystemAgent),
            (self.identity.is_some(), AuthKind::Personal),
        ]
        .into_iter()
        .filter_map(|(given, kind)| given.then_some(kind))
        .collect()
    }
}

/// `unissh hosts add|edit|rm`.
#[derive(Subcommand)]
pub enum HostsAction {
    /// Add a host. Say how it logs in: --key, --password-item, --agent-key,
    /// --identity, or --auth ask|password.
    Add {
        /// Its label in the list.
        label: String,
        /// Where it is: [user@]host[:port].
        address: String,
        #[command(flatten)]
        fields: HostFields,
        #[command(flatten)]
        vault: VaultArg,
    },
    /// Change a host: only what the flags say.
    Edit {
        /// The host (label, vault/label or address).
        host: String,
        /// A new label.
        #[arg(long)]
        label: Option<String>,
        /// A new address: [user@]host[:port] (the user and port when given).
        #[arg(long, value_name = "ADDRESS")]
        address: Option<String>,
        #[command(flatten)]
        fields: HostFields,
        #[command(flatten)]
        vault: VaultArg,
    },
    /// Delete a host.
    Rm {
        /// The host (label, vault/label or address).
        host: String,
        #[command(flatten)]
        vault: VaultArg,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
}

/// Runs `unissh hosts add|edit|rm`.
pub fn hosts(device: &Device, offline: bool, action: HostsAction) -> Res<()> {
    let core = &device.core;
    let all = hosts::load(core)?;
    match action {
        HostsAction::Add {
            label,
            address,
            fields,
            vault,
        } => {
            let target = vault.pick(core, None)?;
            let at = parse_address(&address)?;
            if at.user.is_some() && fields.user.is_some() {
                return Err(Failure::msg(
                    "the user is in the address and in --user: give it once",
                ));
            }
            if at.port.is_some() && fields.port.is_some() {
                return Err(Failure::msg(
                    "the port is in the address and in --port: give it once",
                ));
            }
            if fields.auth.is_none() && fields.implied_auth().is_empty() {
                return Err(Failure::msg(
                    "say how the host logs in: --key <key>, --password-item <secret>, \
                     --agent-key <key>, --identity <identity>, or --auth ask|password",
                ));
            }
            let label = label.trim().to_owned();
            let profile = ConnectionProfile {
                // The core mints the id when it saves the new host.
                profile_id: String::new(),
                uid: String::new(),
                label: label.clone(),
                host: at.host,
                port: at.port.unwrap_or(22),
                user: at.user.unwrap_or_default(),
                auth: ProfileAuth::PromptPassword,
                username_template: None,
                jumps: Vec::new(),
                proxy: None,
                tags: Vec::new(),
                startup_snippet_ids: Vec::new(),
                record_sessions: false,
                agent_forward: false,
                color: None,
                icon: None,
            };
            let place = Place {
                vault_id: &target.vault_id,
                vault_name: &target.name,
                all: &all,
                creating: true,
            };
            let done = format!(
                "Added host {} to vault \"{}\"",
                one_line(&label),
                one_line(&target.name)
            );
            save(device, offline, &place, profile, &fields, &done)
        }
        HostsAction::Edit {
            host,
            label,
            address,
            fields,
            vault,
        } => {
            if label.is_none() && address.is_none() && !fields.given() {
                return Err(Failure::msg(
                    "nothing to change: say what with flags (`unissh hosts edit --help`)",
                ));
            }
            let scope = vault.scope(core)?;
            let found = scoped_host(&all, scope.as_deref(), &host)?;
            let mut profile = found.profile.clone();
            if let Some(label) = label {
                profile.label = label.trim().to_owned();
            }
            if let Some(address) = address {
                let at = parse_address(&address)?;
                profile.host = at.host;
                if let Some(user) = at.user {
                    profile.user = user;
                }
                if let Some(port) = at.port {
                    profile.port = port;
                }
            }
            let done = format!("Changed host {}", one_line(&profile.label));
            let place = Place {
                vault_id: &found.vault_id,
                vault_name: &found.vault_name,
                all: &all,
                creating: false,
            };
            save(device, offline, &place, profile, &fields, &done)
        }
        HostsAction::Rm { host, vault, yes } => {
            let scope = vault.scope(core)?;
            let found = scoped_host(&all, scope.as_deref(), &host)?;
            confirm(
                yes,
                &format!(
                    "\"{}\" will be removed from vault \"{}\". Saved keys and passwords are kept.\n",
                    one_line(&found.profile.label),
                    one_line(&found.vault_name)
                ),
            )?;
            stored(
                &found.vault_name,
                core.delete_connection(found.vault_id.clone(), found.profile.profile_id.clone()),
            )?;
            commit(
                device,
                &found.vault_id,
                offline,
                &format!("Deleted host {}", one_line(&found.profile.label)),
            )
        }
    }
}

/// The host `query` names among those of the vault `scope` (all without one).
fn scoped_host<'h>(all: &'h [Host], scope: Option<&str>, query: &str) -> Res<&'h Host> {
    let within: Vec<&Host> = all
        .iter()
        .filter(|h| edit::in_scope(scope, &h.vault_id))
        .collect();
    find_named(&within, query).copied()
}

/// Where a host is saved: its vault, every host (for jump references), and
/// whether it is new.
struct Place<'a> {
    vault_id: &'a str,
    vault_name: &'a str,
    all: &'a [Host],
    creating: bool,
}

/// What a save writes besides the host itself.
#[derive(Default)]
struct Pending {
    /// A password typed for the host, stored with it as a vault secret.
    new_password: Option<Zeroizing<String>>,
    /// The personal identity to link.
    identity: Option<IdentityEntry>,
    /// The group to put it in (`Some(None)`: out of every group).
    group: Option<Option<String>>,
}

/// Applies `fields` to `profile` and saves it through the core's one
/// host-save path ([`Core::save_host`], the app's too): the rules every host
/// keeps, a new password, an identity link, its group. Then sends it all to
/// the server and says `done`.
///
/// Everything that is looked up or asked comes first, and the core writes
/// the password, the host and its group together, so a mistake stores
/// nothing. Once the host is saved, a link that fails (or an identity pin
/// the save had to keep) does not undo it: the command says what is missing,
/// still syncs, and fails.
fn save(
    device: &Device,
    offline: bool,
    place: &Place<'_>,
    mut profile: ConnectionProfile,
    fields: &HostFields,
    done: &str,
) -> Res<()> {
    let core = &device.core;
    let (vault_id, vault_name) = (place.vault_id, place.vault_name);
    let mut pending = Pending::default();
    apply_login(core, vault_id, &mut profile, fields, &mut pending)?;
    apply_route(core, vault_id, &mut profile, fields, place.all)?;
    apply_rest(core, vault_id, &mut profile, fields, &mut pending)?;
    let personal = matches!(profile.auth, ProfileAuth::Personal);
    let label = one_line(profile.label.trim());
    let group = match pending.group.take() {
        None => HostGroup::Unchanged,
        Some(None) => HostGroup::Ungrouped,
        Some(Some(group_id)) => HostGroup::Existing { group_id },
    };
    let request = HostSave {
        profile,
        new_password: pending.new_password.take(),
        group,
        identity: pending.identity.take().map(|entry| IdentityLink {
            vault_id: entry.vault_id,
            identity_id: entry.identity.identity_id,
        }),
    };
    let result = core.save_host(vault_id, request);
    if let Err(FfiError::InvalidHost { rule }) = &result {
        return Err(Failure::msg(refusal(*rule)));
    }
    let saved = stored(vault_name, result)?;

    // The identity's binding lives in its own vault, which changed too.
    let binding_syncs = saved
        .binding_vault_id
        .as_deref()
        .map(|binding_vault| syncs(core, binding_vault))
        .transpose()?;
    let cloud = syncs(core, vault_id)? || binding_syncs == Some(true);
    let pushed = server::push_after_write(device, cloud, offline, done);
    if !saved.unfinished.is_empty() {
        for gap in &saved.unfinished {
            eprintln!("unissh: saved host {label}, but {}", missing(gap, &label));
        }
        pushed?;
        let again = if place.creating {
            " (do not run `unissh hosts add` again: that adds a second host)"
        } else {
            ""
        };
        return Err(Failure::msg(format!(
            "host {label} is saved, but not all of it: see above{again}"
        )));
    }
    pushed?;
    if personal && !saved.identity_linked {
        eprintln!(
            "unissh: {label} logs in with each member's personal identity; link yours with \
             `unissh hosts edit \"{label}\" --identity <name>`"
        );
    }
    Ok(())
}

/// What a save left undone, and how to finish it.
fn missing(gap: &HostSaveGap, label: &str) -> String {
    match gap {
        HostSaveGap::IdentityNotLinked { message } => format!(
            "your identity is not linked to it ({}): link it with \
             `unissh hosts edit \"{label}\" --identity <name>`",
            one_line(message)
        ),
        HostSaveGap::IdentityPinKept { pinned, .. } => format!(
            "your identity is still pinned to {}, where the host pointed when it was \
             linked: it was pointed elsewhere before this save, so connecting with your \
             identity is refused as redirected. If the new address is right, link it again \
             with `unissh hosts edit \"{label}\" --identity <name>`",
            one_line(pinned)
        ),
    }
}

/// A host rule the core refused the save for, with the flag that fixes it
/// where there is one.
fn refusal(rule: HostRule) -> String {
    let hint = match rule {
        HostRule::UserRequired => ": user@host, or --user",
        HostRule::HopOtherVault => " (or give the jump host as user@host)",
        HostRule::HopNotFound => {
            " (remove the jump hosts with --no-jump, or name a saved host that works with --jump <host>)"
        }
        HostRule::HopNoCredential => {
            " (remove the jump hosts with --no-jump, name a saved host that logs in with a key, \
             a stored password or the ssh-agent with --jump <host>, or give the jump host as \
             user@host with --jump-key)"
        }
        HostRule::IdentityNeedsPersonalLogin => " (--identity goes with --auth personal)",
        HostRule::LabelRequired
        | HostRule::AddressRequired
        | HostRule::HopAddressRequired
        | HostRule::HopSelf
        | HostRule::NewPasswordNeedsPasswordLogin
        | HostRule::NewPasswordEmpty
        | HostRule::GroupNotFound
        | HostRule::GroupLabelRequired
        | HostRule::IdentityNotFound => "",
    };
    format!("{rule}{hint}")
}

/// The login a host's flags ask for: `--auth`, or what `--key`,
/// `--password-item`, `--agent-key` or `--identity` imply. `None` leaves it.
fn chosen_auth(explicit: Option<AuthKind>, implied: &[AuthKind]) -> Res<Option<AuthKind>> {
    match (explicit, implied) {
        (Some(kind), more) => match more.iter().find(|m| **m != kind) {
            Some(other) => Err(Failure::msg(format!(
                "{} is for --auth {}, not --auth {}",
                other.flag(),
                other.name(),
                kind.name()
            ))),
            None => Ok(Some(kind)),
        },
        (None, []) => Ok(None),
        (None, [one]) => Ok(Some(*one)),
        (None, many) => Err(Failure::msg(format!(
            "{} are different logins: give one",
            many.iter()
                .map(|k| k.flag())
                .collect::<Vec<_>>()
                .join(" and ")
        ))),
    }
}

fn apply_login(
    core: &Core,
    vault_id: &str,
    profile: &mut ConnectionProfile,
    f: &HostFields,
    pending: &mut Pending,
) -> Res<()> {
    let new_password = f.auth == Some(AuthKind::Password) && f.password_item.is_none();
    if f.new_password.given() && !new_password {
        return Err(Failure::msg(
            "--stdin and --from-file read a new password, for --auth password",
        ));
    }
    if let Some(kind) = chosen_auth(f.auth, &f.implied_auth())? {
        profile.auth = login(core, vault_id, profile, f, kind, pending)?;
    }
    let personal = matches!(profile.auth, ProfileAuth::Personal);
    if let Some(template) = &f.username_template {
        if !personal && !template.trim().is_empty() {
            return Err(Failure::msg(
                "--username-template is for a personal login (--auth personal)",
            ));
        }
        // The core keeps it for a personal login only.
        profile.username_template = clearable(template);
    }
    Ok(())
}

fn login(
    core: &Core,
    vault_id: &str,
    profile: &ConnectionProfile,
    f: &HostFields,
    kind: AuthKind,
    pending: &mut Pending,
) -> Res<ProfileAuth> {
    Ok(match kind {
        AuthKind::Key => {
            let key_item_id = match (&f.key, &profile.auth) {
                (Some(key), _) => secrets::find_in::<Key>(core, vault_id, key)?,
                (None, ProfileAuth::Key { key_item_id }) => key_item_id.clone(),
                (None, _) => return Err(Failure::msg("--auth key needs --key <key>")),
            };
            ProfileAuth::Key { key_item_id }
        }
        AuthKind::Password => match &f.password_item {
            Some(item) => ProfileAuth::VaultPassword {
                password_item_id: secrets::find_in::<Password>(core, vault_id, item)?,
            },
            None => {
                let password = f.new_password.read(
                    "the host's password",
                    "Password for the host: ",
                    Shape::New,
                )?;
                pending.new_password = Some(password);
                // The core stores the password and puts its id here.
                ProfileAuth::VaultPassword {
                    password_item_id: String::new(),
                }
            }
        },
        AuthKind::Ask => ProfileAuth::PromptPassword,
        AuthKind::Personal => {
            if let Some(query) = &f.identity {
                pending.identity = Some(secrets::find_identity(core, query)?);
            }
            ProfileAuth::Personal
        }
        AuthKind::SystemAgent => {
            let public_key = match (&f.agent_key, &profile.auth) {
                (Some(key), _) => agent_key(core, key)?,
                (None, ProfileAuth::SystemAgent { public_key }) => public_key.clone(),
                (None, _) => {
                    return Err(Failure::msg("--auth system-agent needs --agent-key <key>"))
                }
            };
            ProfileAuth::SystemAgent { public_key }
        }
    })
}

/// The system ssh-agent key `wanted` names: a public-key line as is, else the
/// one key whose comment (or key blob) it is.
fn agent_key(core: &Core, wanted: &str) -> Res<String> {
    let wanted = wanted.trim();
    if wanted.contains(char::is_whitespace) {
        return Ok(wanted.to_owned());
    }
    let keys = core.system_agent_keys()?;
    let matching: Vec<_> = keys
        .iter()
        .filter(|k| k.comment == wanted || k.public_key.split_whitespace().nth(1) == Some(wanted))
        .collect();
    match matching.as_slice() {
        [one] => Ok(one.public_key.clone()),
        [] if keys.is_empty() => Err(Failure::msg(
            "the system ssh-agent holds no key (is SSH_AUTH_SOCK set?)",
        )),
        [] => Err(Failure::msg(format!(
            "no key in the system ssh-agent is called \"{wanted}\"; it holds: {}",
            keys.iter()
                .map(|k| one_line(&k.comment))
                .collect::<Vec<_>>()
                .join(", ")
        ))),
        _ => Err(Failure::msg(format!(
            "several keys in the system ssh-agent are called \"{wanted}\": pass its \
             public-key line"
        ))),
    }
}

fn apply_route(
    core: &Core,
    vault_id: &str,
    profile: &mut ConnectionProfile,
    f: &HostFields,
    all: &[Host],
) -> Res<()> {
    let inline_auth = match (&f.jump_key, &f.jump_password_item) {
        (Some(key), _) => Some(AuthMethod::Agent {
            vault_id: vault_id.to_owned(),
            key_item_id: secrets::find_in::<Key>(core, vault_id, key)?,
        }),
        (None, Some(item)) => Some(AuthMethod::VaultPassword {
            vault_id: vault_id.to_owned(),
            password_item_id: secrets::find_in::<Password>(core, vault_id, item)?,
        }),
        (None, None) => None,
    };
    if inline_auth.is_some() && !f.jumps.iter().any(|spec| spec.contains('@')) {
        return Err(Failure::msg(
            "--jump-key and --jump-password-item are for a jump host given as user@host",
        ));
    }
    if f.no_jump {
        profile.jumps.clear();
    } else if !f.jumps.is_empty() {
        let chain = f
            .jumps
            .iter()
            .map(|spec| jump(spec, vault_id, all, inline_auth.as_ref()))
            .collect::<Res<Vec<_>>>()?;
        profile.jumps = chain;
    }
    if let Some(url) = &f.proxy {
        profile.proxy = if url.trim().is_empty() {
            None
        } else {
            let spec = parse_proxy(url)?;
            Some(ProxyConfig {
                kind: spec.kind,
                host: spec.host,
                port: spec.port,
                username: spec.user,
                password: None,
            })
        };
    }
    if let Some(item) = &f.proxy_password_item {
        let proxy = profile.proxy.as_mut().ok_or_else(|| {
            Failure::msg("--proxy-password-item is for a host with a proxy (--proxy)")
        })?;
        proxy.password = if item.trim().is_empty() {
            None
        } else if proxy.kind == ProxyKind::Socks4 {
            return Err(Failure::msg("a SOCKS4 proxy takes no password"));
        } else {
            Some(ProxyPassword::Vault {
                vault_id: vault_id.to_owned(),
                password_item_id: secrets::find_in::<Password>(core, vault_id, item)?,
            })
        };
    }
    Ok(())
}

/// One hop of a jump chain: `user@host[:port]` logs in with `inline_auth`;
/// anything else names a saved host, referenced so its own settings apply.
/// Which saved hosts may be hops (another host of the same vault that logs
/// in with a key, a stored password or the system ssh-agent) is the core's
/// rule, checked as it saves.
fn jump(
    spec: &str,
    vault_id: &str,
    all: &[Host],
    inline_auth: Option<&AuthMethod>,
) -> Res<JumpHost> {
    if spec.contains('@') {
        let at = parse_address(spec)?;
        let auth = inline_auth.cloned().ok_or_else(|| {
            Failure::msg(format!(
                "the jump host {spec} needs --jump-key or --jump-password-item"
            ))
        })?;
        return Ok(JumpHost {
            host: at.host,
            port: at.port.unwrap_or(22),
            user: at.user.unwrap_or_default(),
            auth,
            hop_ref: None,
        });
    }
    let bastion = match scoped_host(all, Some(vault_id), spec) {
        Ok(bastion) => bastion,
        // Named right but kept elsewhere: say so rather than "no host".
        Err(e) => match hosts::find(all, spec) {
            Ok(other) => other,
            Err(_) => return Err(e),
        },
    };
    // The core stores a reference hop in its placeholder shape.
    Ok(JumpHost {
        host: String::new(),
        port: 22,
        user: String::new(),
        auth: AuthMethod::Agent {
            vault_id: vault_id.to_owned(),
            key_item_id: String::new(),
        },
        hop_ref: Some(HopRef {
            vault_id: bastion.vault_id.clone(),
            profile_uid: bastion.profile.uid.clone(),
        }),
    })
}

fn apply_rest(
    core: &Core,
    vault_id: &str,
    profile: &mut ConnectionProfile,
    f: &HostFields,
    pending: &mut Pending,
) -> Res<()> {
    if let Some(user) = &f.user {
        profile.user = user.trim().to_owned();
    }
    if let Some(port) = f.port {
        profile.port = port;
    }
    if let Some(group) = &f.group {
        pending.group = Some(if group.trim().is_empty() {
            None
        } else {
            Some(find_group(core, vault_id, group)?)
        });
    }
    f.look.apply(&mut profile.color, &mut profile.icon)?;
    if let Some(tags) = &f.tags {
        profile.tags = list(tags)
            .into_iter()
            .map(|t| t.strip_prefix('#').unwrap_or(&t).to_owned())
            .filter(|t| !t.is_empty())
            .collect();
    }
    if let Some(names) = &f.startup_snippets {
        profile.startup_snippet_ids = list(names)
            .iter()
            .map(|name| snippet_edit::find_in(core, vault_id, name))
            .collect::<Res<_>>()?;
    }
    if let Some(record) = f.record {
        profile.record_sessions = record.on();
    }
    if let Some(forward) = f.agent_forward {
        profile.agent_forward = forward.on();
    }
    Ok(())
}

/// `[user@]host[:port]`.
#[derive(Debug, PartialEq, Eq)]
struct Address {
    user: Option<String>,
    host: String,
    port: Option<u16>,
}

/// Reads `[user@]host[:port]`; a host may be `[v6]` (with a port) or a bare
/// v6 address (without one).
fn parse_address(spec: &str) -> Res<Address> {
    let spec = spec.trim();
    let bad = |why: &str| Failure::msg(format!("\"{spec}\" is not [user@]host[:port]{why}"));
    let (user, rest) = match spec.rsplit_once('@') {
        Some(("", _)) => return Err(bad("")),
        Some((user, rest)) => (Some(user.to_owned()), rest),
        None => (None, spec),
    };
    let (host, port) = if let Some(inner) = rest.strip_prefix('[') {
        let (host, after) = inner.split_once(']').ok_or_else(|| bad(""))?;
        if after.is_empty() {
            (host, None)
        } else {
            (host, Some(after.strip_prefix(':').ok_or_else(|| bad(""))?))
        }
    } else if rest.matches(':').count() == 1 {
        rest.split_once(':')
            .map_or((rest, None), |(host, port)| (host, Some(port)))
    } else {
        (rest, None)
    };
    let port = port
        .map(|p| {
            p.parse::<u16>()
                .ok()
                .filter(|&n| n > 0)
                .ok_or_else(|| bad(" (a port is a number from 1 to 65535)"))
        })
        .transpose()?;
    if host.is_empty() || host.contains(|c: char| c.is_whitespace() || c.is_control()) {
        return Err(bad(""));
    }
    Ok(Address {
        user,
        host: host.to_owned(),
        port,
    })
}

/// An outbound proxy as `--proxy` gives it.
#[derive(Debug, PartialEq, Eq)]
struct ProxySpec {
    kind: ProxyKind,
    user: Option<String>,
    host: String,
    port: u16,
}

/// Reads `http|socks4|socks5://[user@]host[:port]`; the port is 1080 when
/// left out, as in the app. A password never goes in the URL.
fn parse_proxy(url: &str) -> Res<ProxySpec> {
    let url = url.trim();
    let bad = || {
        Failure::msg(format!(
            "\"{url}\" is not a proxy: http://, socks4:// or socks5://[user@]host[:port]"
        ))
    };
    let (scheme, rest) = url.split_once("://").ok_or_else(bad)?;
    let kind = match scheme.to_ascii_lowercase().as_str() {
        "http" => ProxyKind::Http,
        "socks4" | "socks4a" => ProxyKind::Socks4,
        "socks5" | "socks5h" => ProxyKind::Socks5,
        _ => return Err(bad()),
    };
    let at = parse_address(rest.trim_end_matches('/'))?;
    if at.user.as_deref().is_some_and(|u| u.contains(':')) {
        return Err(Failure::msg(
            "a password does not go in the proxy URL: store it with \
             `unissh secrets add-password` and pass --proxy-password-item",
        ));
    }
    Ok(ProxySpec {
        kind,
        user: at.user,
        host: at.host,
        port: at.port.unwrap_or(1080),
    })
}

// ---------- unissh groups ----------

/// The groups, of every vault or of the vault `scope` names.
fn load_groups(core: &Core, scope: Option<&str>) -> Res<Vec<Group>> {
    let mut groups = hosts::load_groups(core)?;
    groups.retain(|g| edit::in_scope(scope, &g.vault_id));
    groups.sort_by_cached_key(|g| (g.vault_name.to_lowercase(), g.group.label.to_lowercase()));
    Ok(groups)
}

/// The group `query` names (its label, vault/label, or id).
fn take_group(groups: Vec<Group>, query: &str) -> Res<Group> {
    take(groups, query, |g| &g.group.group_id)
}

/// The id of the group `query` names in vault `vault_id`.
fn find_group(core: &Core, vault_id: &str, query: &str) -> Res<String> {
    Ok(take_group(load_groups(core, Some(vault_id))?, query)?
        .group
        .group_id)
}

/// How many hosts group `group` of vault `vault_id` holds: the members that
/// still exist, as the app counts them.
fn live_members(group: &ServerGroup, vault_id: &str, hosts: &[Host]) -> usize {
    group
        .member_ids
        .iter()
        .filter(|id| {
            hosts
                .iter()
                .any(|h| h.vault_id == vault_id && &h.profile.profile_id == *id)
        })
        .count()
}

/// Whether making `parent` the parent of `group` would put `group` inside
/// itself (the core refuses only the group as its own parent).
fn nests_in_itself(groups: &[ServerGroup], group: &str, parent: &str) -> bool {
    let mut at = Some(parent);
    // A cycle already in the data must not spin forever.
    for _ in 0..=groups.len() {
        let Some(id) = at else {
            return false;
        };
        if id == group {
            return true;
        }
        at = groups
            .iter()
            .find(|g| g.group_id == id)
            .and_then(|g| g.parent_id.as_deref());
    }
    false
}

/// `unissh groups`.
#[derive(Subcommand)]
pub enum GroupsAction {
    /// List the host groups.
    List {
        #[command(flatten)]
        vault: VaultArg,
        /// Print JSON.
        #[arg(long)]
        json: bool,
    },
    /// Add a group.
    Add {
        /// Its label.
        label: String,
        /// The group it sits in.
        #[arg(long)]
        parent: Option<String>,
        #[command(flatten)]
        look: Look,
        #[command(flatten)]
        vault: VaultArg,
    },
    /// Change a group: its label, parent, look, or which hosts are in it.
    Edit {
        /// The group (label, vault/label or id).
        group: String,
        /// A new label.
        #[arg(long)]
        label: Option<String>,
        /// The group it sits in; empty for the top level.
        #[arg(long)]
        parent: Option<String>,
        #[command(flatten)]
        look: Look,
        /// Move a host into this group (out of any other). Repeatable.
        #[arg(long = "add-host", value_name = "HOST")]
        add_hosts: Vec<String>,
        /// Take a host out of this group. Repeatable.
        #[arg(long = "remove-host", value_name = "HOST")]
        remove_hosts: Vec<String>,
        #[command(flatten)]
        vault: VaultArg,
    },
    /// Delete a group; its hosts stay.
    Rm {
        /// The group (label, vault/label or id).
        group: String,
        #[command(flatten)]
        vault: VaultArg,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
}

/// Runs `unissh groups`.
pub fn groups(device: &Device, offline: bool, action: GroupsAction) -> Res<()> {
    let core = &device.core;
    match action {
        GroupsAction::List { vault, json } => list_groups(core, &vault, json),
        GroupsAction::Add {
            label,
            parent,
            look,
            vault,
        } => {
            let label = label.trim().to_owned();
            if label.is_empty() {
                return Err(Failure::msg("a group needs a label"));
            }
            let target = vault.pick(core, None)?;
            let parent_id = match parent.as_deref().map(str::trim) {
                Some(p) if !p.is_empty() => Some(find_group(core, &target.vault_id, p)?),
                Some(_) | None => None,
            };
            let mut group = ServerGroup {
                // The core mints the id when it saves the new group.
                group_id: String::new(),
                label: label.clone(),
                member_ids: Vec::new(),
                parent_id,
                color: None,
                icon: None,
            };
            look.apply(&mut group.color, &mut group.icon)?;
            stored(
                &target.name,
                core.save_group(target.vault_id.clone(), group),
            )?;
            commit(
                device,
                &target.vault_id,
                offline,
                &format!("Added group {}", one_line(&label)),
            )
        }
        GroupsAction::Edit {
            group,
            label,
            parent,
            look,
            add_hosts,
            remove_hosts,
            vault,
        } => {
            let change = GroupChange {
                label,
                parent,
                look,
                add_hosts,
                remove_hosts,
            };
            edit_group(device, offline, &vault, &group, change)
        }
        GroupsAction::Rm { group, vault, yes } => {
            let scope = vault.scope(core)?;
            let found = take_group(load_groups(core, scope.as_deref())?, &group)?;
            let members = live_members(&found.group, &found.vault_id, &hosts::load(core)?);
            confirm(
                yes,
                &format!(
                    "Group \"{}\" will be deleted. Its {members} host(s) remain.\n",
                    one_line(&found.group.label)
                ),
            )?;
            stored(
                &found.vault_name,
                core.delete_group(found.vault_id.clone(), found.group.group_id.clone()),
            )?;
            commit(
                device,
                &found.vault_id,
                offline,
                &format!("Deleted group {}", one_line(&found.group.label)),
            )
        }
    }
}

fn list_groups(core: &Core, vault: &VaultArg, json: bool) -> Res<()> {
    let scope = vault.scope(core)?;
    let all = load_groups(core, scope.as_deref())?;
    let hosts = hosts::load(core)?;
    let parent_label = |g: &Group| {
        g.group.parent_id.as_deref().map(|p| {
            all.iter()
                .find(|o| o.vault_id == g.vault_id && o.group.group_id == p)
                .map_or_else(|| p.to_owned(), |o| o.group.label.clone())
        })
    };
    if json {
        return print_json(&Value::Array(
            all.iter()
                .map(|g| {
                    json!({
                        "vault": g.vault_name,
                        "id": g.group.group_id,
                        "label": g.group.label,
                        "parent": parent_label(g),
                        "members": live_members(&g.group, &g.vault_id, &hosts),
                        "color": g.group.color,
                        "icon": g.group.icon,
                    })
                })
                .collect(),
        ));
    }
    if all.is_empty() {
        eprintln!("unissh: no groups to show");
        return Ok(());
    }
    let rows: Vec<Vec<String>> = all
        .iter()
        .map(|g| {
            vec![
                g.group.label.clone(),
                g.vault_name.clone(),
                parent_label(g).map_or_else(String::new, |p| format!("in {p}")),
                format!("{} host(s)", live_members(&g.group, &g.vault_id, &hosts)),
                g.group.color.clone().unwrap_or_default(),
            ]
        })
        .collect();
    print!("{}", columns(&rows));
    Ok(())
}

/// What `unissh groups edit` was asked to change.
struct GroupChange {
    label: Option<String>,
    parent: Option<String>,
    look: Look,
    add_hosts: Vec<String>,
    remove_hosts: Vec<String>,
}

fn edit_group(
    device: &Device,
    offline: bool,
    vault: &VaultArg,
    query: &str,
    change: GroupChange,
) -> Res<()> {
    let core = &device.core;
    if change.label.is_none()
        && change.parent.is_none()
        && !change.look.given()
        && change.add_hosts.is_empty()
        && change.remove_hosts.is_empty()
    {
        return Err(Failure::msg(
            "nothing to change: say what with flags (`unissh groups edit --help`)",
        ));
    }
    let scope = vault.scope(core)?;
    let all = load_groups(core, scope.as_deref())?;
    let found = take(all.iter().collect::<Vec<&Group>>(), query, |g| {
        &g.group.group_id
    })?;
    let (vault_id, vault_name) = (found.vault_id.clone(), found.vault_name.clone());
    let mut group = found.group.clone();
    if let Some(label) = &change.label {
        let label = label.trim();
        if label.is_empty() {
            return Err(Failure::msg("a group needs a label"));
        }
        label.clone_into(&mut group.label);
    }
    if let Some(parent) = &change.parent {
        group.parent_id = if parent.trim().is_empty() {
            None
        } else {
            let parent_id = find_group(core, &vault_id, parent)?;
            let siblings: Vec<ServerGroup> = all
                .iter()
                .filter(|g| g.vault_id == vault_id)
                .map(|g| g.group.clone())
                .collect();
            if nests_in_itself(&siblings, &group.group_id, &parent_id) {
                return Err(Failure::msg("a group cannot sit inside itself"));
            }
            Some(parent_id)
        };
    }
    change.look.apply(&mut group.color, &mut group.icon)?;
    let hosts = hosts::load(core)?;
    let moved = member_ids(&hosts, &vault_id, &change.add_hosts)?;
    let removed = member_ids(&hosts, &vault_id, &change.remove_hosts)?;
    for id in &moved {
        if !group.member_ids.contains(id) {
            group.member_ids.push(id.clone());
        }
    }
    group.member_ids.retain(|m| !removed.contains(m));
    let shown = one_line(&group.label);
    let group_id = group.group_id.clone();
    // This group first: a failure below leaves a moved host in two groups
    // rather than in none.
    stored(&vault_name, core.save_group(vault_id.clone(), group))?;
    // Moved in means out of the other groups: a host is in one.
    let mut missing = Vec::new();
    for other in all
        .iter()
        .filter(|g| g.vault_id == vault_id && g.group.group_id != group_id)
    {
        if other.group.member_ids.iter().any(|m| moved.contains(m)) {
            let mut other = other.group.clone();
            other.member_ids.retain(|m| !moved.contains(m));
            let label = one_line(&other.label);
            if let Err(e) = stored(&vault_name, core.save_group(vault_id.clone(), other)) {
                missing.push(format!("its hosts are still in group {label} too: {e}"));
            }
        }
    }
    let pushed = commit(
        device,
        &vault_id,
        offline,
        &format!("Changed group {shown}"),
    );
    if missing.is_empty() {
        return pushed;
    }
    for what in &missing {
        eprintln!("unissh: changed group {shown}, but {what}");
    }
    pushed?;
    Err(Failure::msg(format!(
        "group {shown} is changed, but a moved host is in another group too: \
         take it out with `unissh groups edit <group> --remove-host <host>`"
    )))
}

/// The profile ids of the hosts `names` names in vault `vault_id`.
fn member_ids(hosts: &[Host], vault_id: &str, names: &[String]) -> Res<Vec<String>> {
    names
        .iter()
        .map(|name| scoped_host(hosts, Some(vault_id), name).map(|h| h.profile.profile_id.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        appearance, chosen_auth, nests_in_itself, parse_address, parse_proxy, refusal, Address,
        AuthKind, COLORS,
    };
    use unissh_ffi::{HostRule, ProxyKind, ServerGroup};

    fn address(user: Option<&str>, host: &str, port: Option<u16>) -> Address {
        Address {
            user: user.map(str::to_owned),
            host: host.to_owned(),
            port,
        }
    }

    #[test]
    fn an_address_reads_user_host_port_and_v6() {
        assert_eq!(
            parse_address("deploy@web:2222").unwrap(),
            address(Some("deploy"), "web", Some(2222))
        );
        assert_eq!(parse_address("web").unwrap(), address(None, "web", None));
        assert_eq!(
            parse_address("root@[::1]:22").unwrap(),
            address(Some("root"), "::1", Some(22))
        );
        assert_eq!(parse_address("::1").unwrap(), address(None, "::1", None));
        for bad in ["@web", "web:0", "web:ssh", "", "we b"] {
            assert!(parse_address(bad).is_err(), "{bad:?}");
        }
    }

    /// The scheme picks the protocol, the port defaults as in the app, and a
    /// password in the URL is refused rather than stored in the clear.
    #[test]
    fn a_proxy_url_reads_its_kind_and_refuses_a_password() {
        let proxy = parse_proxy("socks5://me@proxy.lan").unwrap();
        assert_eq!(
            (
                proxy.kind,
                proxy.user.as_deref(),
                proxy.host.as_str(),
                proxy.port
            ),
            (ProxyKind::Socks5, Some("me"), "proxy.lan", 1080)
        );
        assert_eq!(parse_proxy("http://p:3128/").unwrap().port, 3128);
        assert!(parse_proxy("socks5://me:secret@proxy").is_err());
        assert!(parse_proxy("ftp://proxy").is_err());
    }

    /// `--key` implies key login; `--auth` must agree with what a flag
    /// implies, and two credentials are not one login.
    #[test]
    fn the_login_follows_auth_or_the_one_credential_flag() {
        assert!(chosen_auth(None, &[]).unwrap().is_none());
        assert!(chosen_auth(None, &[AuthKind::Key]).unwrap() == Some(AuthKind::Key));
        assert!(
            chosen_auth(Some(AuthKind::Password), &[AuthKind::Password]).unwrap()
                == Some(AuthKind::Password)
        );
        assert!(chosen_auth(Some(AuthKind::Ask), &[AuthKind::Key]).is_err());
        assert!(chosen_auth(None, &[AuthKind::Key, AuthKind::Personal]).is_err());
    }

    /// A group may not move under its own descendant.
    #[test]
    fn a_group_cannot_be_placed_inside_its_own_subtree() {
        let group = |id: &str, parent: Option<&str>| ServerGroup {
            group_id: id.to_owned(),
            label: id.to_owned(),
            member_ids: Vec::new(),
            parent_id: parent.map(str::to_owned),
            color: None,
            icon: None,
        };
        let tree = [
            group("a", None),
            group("b", Some("a")),
            group("c", Some("b")),
        ];
        assert!(nests_in_itself(&tree, "a", "c"));
        assert!(nests_in_itself(&tree, "a", "a"));
        assert!(!nests_in_itself(&tree, "c", "a"));
    }

    /// A jump host the core refuses (gone, or with nothing to log in with)
    /// says how to save the host anyway: without jump hosts, or through a
    /// saved host that works.
    #[test]
    fn a_refused_jump_host_names_the_flags_that_fix_it() {
        for rule in [HostRule::HopNotFound, HostRule::HopNoCredential] {
            let said = refusal(rule);
            assert!(said.starts_with(&rule.to_string()), "{said}");
            assert!(said.contains("--no-jump"), "{said}");
            assert!(said.contains("--jump <host>"), "{said}");
        }
    }

    /// A colour or icon is one the app offers, in any case; empty clears it.
    #[test]
    fn a_colour_must_be_one_the_app_offers() {
        assert_eq!(
            appearance(" Teal ", &COLORS, "colour").unwrap().as_deref(),
            Some("teal")
        );
        assert!(appearance("", &COLORS, "colour").unwrap().is_none());
        assert!(appearance("#ff0000", &COLORS, "colour").is_err());
    }
}
