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
    AuthMethod, ConnectionProfile, Core, HopRef, IdentityBinding, JumpHost, ProfileAuth,
    ProxyConfig, ProxyKind, ProxyPassword, ServerGroup,
};
use zeroize::Zeroizing;

use crate::device::Device;
use crate::edit::{
    self, clearable, columns, commit, list, mint_id, print_json, SecretFrom, Shape, Switch,
    VaultArg,
};
use crate::failure::{Failure, Res};
use crate::hosts::{self, find_named, Host, Kind, Named, HOSTS};
use crate::manage::confirm;
use crate::secrets::{self, IdentityEntry, KEYS, PASSWORD, PASSWORDS, SSH_KEY};
use crate::snippet_edit;
use crate::tty::one_line;

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

/// A colour tag and an icon, for a host or a group.
#[derive(Args)]
pub struct Look {
    /// Colour tag, a palette id such as red or teal; empty for none (a host
    /// then takes its group's).
    #[arg(long, value_name = "COLOUR")]
    color: Option<String>,
    /// Icon id; empty for the default.
    #[arg(long, value_name = "ICON")]
    icon: Option<String>,
}

impl Look {
    const fn given(&self) -> bool {
        self.color.is_some() || self.icon.is_some()
    }

    fn apply(&self, color: &mut Option<String>, icon: &mut Option<String>) {
        if let Some(c) = &self.color {
            *color = clearable(c);
        }
        if let Some(i) = &self.icon {
            *icon = clearable(i);
        }
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
    /// A jump host: a saved host, or user@host[:port]. Repeat it for a chain,
    /// first hop first.
    #[arg(long = "jump", value_name = "HOST")]
    jumps: Vec<String>,
    /// No jump host.
    #[arg(long, conflicts_with = "jumps")]
    no_jump: bool,
    /// The SSH key a jump host given as user@host logs in with.
    #[arg(long, value_name = "KEY")]
    jump_key: Option<String>,
    /// The stored password a jump host given as user@host logs in with.
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
                profile_id: mint_id(&label, "host"),
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
            core.delete_connection(found.vault_id.clone(), found.profile.profile_id.clone())?;
            commit(
                device,
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
    find_named(&within, query, &HOSTS).copied()
}

/// Where a host is saved: its vault, every host (for jump references), and
/// whether it is new.
struct Place<'a> {
    vault_id: &'a str,
    all: &'a [Host],
    creating: bool,
}

/// What a save writes besides the host itself.
#[derive(Default)]
struct Pending {
    /// A password typed for the host, to store under this id first.
    new_password: Option<(String, Zeroizing<String>)>,
    /// The personal identity to link.
    identity: Option<IdentityEntry>,
    /// The group to put it in (`Some(None)`: out of every group).
    group: Option<Option<String>>,
}

/// Applies `fields` to `profile`, checks it the way the app's editor does,
/// and writes it with what goes with it: a new password, an identity link,
/// its group. Then sends it all to the server and says `done`.
fn save(
    device: &Device,
    offline: bool,
    place: &Place<'_>,
    mut profile: ConnectionProfile,
    fields: &HostFields,
    done: &str,
) -> Res<()> {
    let core = &device.core;
    let vault_id = place.vault_id;
    let mut pending = Pending::default();
    apply_login(core, vault_id, &mut profile, fields, &mut pending)?;
    apply_route(core, vault_id, &mut profile, fields, place.all)?;
    apply_rest(core, vault_id, &mut profile, fields, &mut pending)?;
    validate(&profile)?;
    if let Some((id, password)) = pending.new_password.take() {
        core.save_password(vault_id.to_owned(), id, (*password).clone())?;
    }
    core.save_connection(vault_id.to_owned(), profile.clone())?;
    let personal = matches!(profile.auth, ProfileAuth::Personal);
    // As the app's editor: saving a personal host (re)pins the identity linked
    // to it — the one given, else the one already linked — to where it now
    // points.
    let link = match &pending.identity {
        Some(identity) => Some((
            identity.vault_id.clone(),
            identity.identity.identity_id.clone(),
        )),
        None if personal && !place.creating => linked_identity(core, vault_id, &profile)?,
        None => None,
    };
    if personal {
        if let Some((bind_vault, identity_id)) = &link {
            link_identity(core, vault_id, &profile, bind_vault, identity_id)?;
        }
    }
    let group = pending.group.take();
    if place.creating || group.is_some() {
        place_in_group(
            core,
            vault_id,
            &profile.profile_id,
            group.flatten().as_deref(),
        )?;
    }
    commit(device, offline, done)?;
    let label = one_line(&profile.label);
    if personal && link.is_none() {
        eprintln!(
            "unissh: {label} logs in with each member's personal identity; link yours with \
             `unissh hosts edit \"{label}\" --identity <name>`"
        );
    }
    Ok(())
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
        profile.username_template = clearable(template);
    }
    // As in the app: the template shapes a personal login only.
    if !personal {
        profile.username_template = None;
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
                (Some(key), _) => secrets::find_in(core, vault_id, key, &[SSH_KEY], &KEYS)?,
                (None, ProfileAuth::Key { key_item_id }) => key_item_id.clone(),
                (None, _) => return Err(Failure::msg("--auth key needs --key <key>")),
            };
            ProfileAuth::Key { key_item_id }
        }
        AuthKind::Password => match &f.password_item {
            Some(item) => ProfileAuth::VaultPassword {
                password_item_id: secrets::find_in(core, vault_id, item, &[PASSWORD], &PASSWORDS)?,
            },
            None => {
                let id = mint_id(&format!("{} pw", profile.label), "host-pw");
                let password = f.new_password.read(
                    "the host's password",
                    "Password for the host: ",
                    Shape::New,
                )?;
                pending.new_password = Some((id.clone(), password));
                ProfileAuth::VaultPassword {
                    password_item_id: id,
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
            key_item_id: secrets::find_in(core, vault_id, key, &[SSH_KEY], &KEYS)?,
        }),
        (None, Some(item)) => Some(AuthMethod::VaultPassword {
            vault_id: vault_id.to_owned(),
            password_item_id: secrets::find_in(core, vault_id, item, &[PASSWORD], &PASSWORDS)?,
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
            .map(|spec| jump(spec, vault_id, profile, all, inline_auth.as_ref()))
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
                password_item_id: secrets::find_in(core, vault_id, item, &[PASSWORD], &PASSWORDS)?,
            })
        };
    }
    Ok(())
}

/// One hop of a jump chain: `user@host[:port]` logs in with `inline_auth`;
/// anything else names a saved host, referenced so its own settings apply.
fn jump(
    spec: &str,
    vault_id: &str,
    profile: &ConnectionProfile,
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
    let bastion = hosts::find(all, spec)?;
    if bastion.profile.uid.is_empty() {
        return Err(Failure::msg(format!(
            "{} cannot be referenced as a jump host yet: save it in the app once",
            one_line(&bastion.profile.label)
        )));
    }
    if bastion.profile.uid == profile.uid {
        return Err(Failure::msg("a host cannot be its own jump host"));
    }
    // The app's shape for a reference hop: the inline fields are ignored.
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
    f.look.apply(&mut profile.color, &mut profile.icon);
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

/// The app editor's rules: a label, an address, and a user unless the login
/// is personal (the identity names the user then).
fn validate(p: &ConnectionProfile) -> Res<()> {
    if p.label.trim().is_empty() {
        return Err(Failure::msg("a host needs a label"));
    }
    if p.host.trim().is_empty() {
        return Err(Failure::msg("a host needs an address"));
    }
    if !matches!(p.auth, ProfileAuth::Personal) && p.user.trim().is_empty() {
        return Err(Failure::msg(format!(
            "{} needs a user to log in as: user@host, or --user",
            one_line(&p.label)
        )));
    }
    Ok(())
}

/// Links identity `identity_id` to the host as the app's editor does: a
/// binding in `bind_vault` (the identity's), pinned to where the host points
/// now.
fn link_identity(
    core: &Core,
    vault_id: &str,
    profile: &ConnectionProfile,
    bind_vault: &str,
    identity_id: &str,
) -> Res<()> {
    // A new host's uid is minted by the core when it is saved.
    let profile_uid = if profile.uid.is_empty() {
        core.get_connection(vault_id.to_owned(), profile.profile_id.clone())?
            .uid
    } else {
        profile.uid.clone()
    };
    let destination_pin = core.personal_destination(
        profile.host.clone(),
        profile.port,
        profile.username_template.clone(),
        profile.jumps.clone(),
        profile.proxy.clone(),
    );
    let existing = core
        .get_binding(
            bind_vault.to_owned(),
            vault_id.to_owned(),
            profile_uid.clone(),
        )
        .ok()
        .flatten();
    core.set_binding(
        bind_vault.to_owned(),
        IdentityBinding {
            team_vault_id: vault_id.to_owned(),
            profile_uid,
            identity_item_id: identity_id.to_owned(),
            destination_pin,
        },
        existing.is_some(),
    )?;
    Ok(())
}

/// The identity already linked to an existing host, and the vault holding
/// that link: the first vault with a binding for it, as the app finds it.
fn linked_identity(
    core: &Core,
    vault_id: &str,
    profile: &ConnectionProfile,
) -> Res<Option<(String, String)>> {
    if profile.uid.is_empty() {
        return Ok(None);
    }
    for vault in core.list_vaults()? {
        let binding = core
            .get_binding(
                vault.vault_id.clone(),
                vault_id.to_owned(),
                profile.uid.clone(),
            )
            .ok()
            .flatten();
        if let Some(binding) = binding {
            return Ok(Some((vault.vault_id, binding.identity_item_id)));
        }
    }
    Ok(None)
}

/// Puts host `profile_id` into group `target` and out of every other one: a
/// host is in one group, as in the app's editor. `None`: in none.
fn place_in_group(core: &Core, vault_id: &str, profile_id: &str, target: Option<&str>) -> Res<()> {
    for mut group in core.list_groups(vault_id.to_owned())? {
        let member = group.member_ids.iter().any(|m| m == profile_id);
        let wanted = target == Some(group.group_id.as_str());
        if wanted && !member {
            group.member_ids.push(profile_id.to_owned());
            core.save_group(vault_id.to_owned(), group)?;
        } else if !wanted && member {
            group.member_ids.retain(|m| m != profile_id);
            core.save_group(vault_id.to_owned(), group)?;
        }
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

/// Host groups, for lookups.
const GROUPS: Kind = Kind {
    one: "group",
    many: "groups",
    list: "unissh groups list",
};

/// A group and the vault it lives in.
struct GroupEntry {
    vault_id: String,
    vault_name: String,
    group: ServerGroup,
}

impl Named for GroupEntry {
    fn vault_name(&self) -> &str {
        &self.vault_name
    }

    fn label(&self) -> &str {
        &self.group.label
    }

    fn alias(&self) -> &str {
        &self.group.group_id
    }

    fn detail(&self) -> String {
        format!("{} member(s)", self.group.member_ids.len())
    }
}

fn load_groups(core: &Core, scope: Option<&str>) -> Res<Vec<GroupEntry>> {
    let mut out = Vec::new();
    for vault in core.list_vaults()? {
        if !edit::in_scope(scope, &vault.vault_id) {
            continue;
        }
        match core.list_groups(vault.vault_id.clone()) {
            Ok(groups) => out.extend(groups.into_iter().map(|group| GroupEntry {
                vault_id: vault.vault_id.clone(),
                vault_name: vault.name.clone(),
                group,
            })),
            Err(e) => eprintln!("unissh: skipping vault \"{}\": {e}", one_line(&vault.name)),
        }
    }
    out.sort_by_cached_key(|g| (g.vault_name.to_lowercase(), g.group.label.to_lowercase()));
    Ok(out)
}

/// The id of the group `query` names in vault `vault_id`.
fn find_group(core: &Core, vault_id: &str, query: &str) -> Res<String> {
    let groups = load_groups(core, Some(vault_id))?;
    Ok(find_named(&groups, query, &GROUPS)?.group.group_id.clone())
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
                group_id: mint_id(&label, "group"),
                label: label.clone(),
                member_ids: Vec::new(),
                parent_id,
                color: None,
                icon: None,
            };
            look.apply(&mut group.color, &mut group.icon);
            core.save_group(target.vault_id, group)?;
            commit(
                device,
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
            let all = load_groups(core, scope.as_deref())?;
            let found = find_named(&all, &group, &GROUPS)?;
            confirm(
                yes,
                &format!(
                    "Group \"{}\" will be deleted. Its {} member(s) remain.\n",
                    one_line(&found.group.label),
                    found.group.member_ids.len()
                ),
            )?;
            core.delete_group(found.vault_id.clone(), found.group.group_id.clone())?;
            commit(
                device,
                offline,
                &format!("Deleted group {}", one_line(&found.group.label)),
            )
        }
    }
}

fn list_groups(core: &Core, vault: &VaultArg, json: bool) -> Res<()> {
    let scope = vault.scope(core)?;
    let all = load_groups(core, scope.as_deref())?;
    let parent_label = |g: &GroupEntry| {
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
                        "members": g.group.member_ids,
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
                format!("{} member(s)", g.group.member_ids.len()),
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
    let found = find_named(&all, query, &GROUPS)?;
    let vault_id = found.vault_id.clone();
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
    change.look.apply(&mut group.color, &mut group.icon);
    let hosts = hosts::load(core)?;
    let moved = member_ids(&hosts, &vault_id, &change.add_hosts)?;
    let removed = member_ids(&hosts, &vault_id, &change.remove_hosts)?;
    for id in &moved {
        if !group.member_ids.contains(id) {
            group.member_ids.push(id.clone());
        }
    }
    group.member_ids.retain(|m| !removed.contains(m));
    // Moved in means out of the other groups: a host is in one.
    for other in all.iter().filter(|g| g.vault_id == vault_id) {
        if other.group.group_id == group.group_id {
            continue;
        }
        if other.group.member_ids.iter().any(|m| moved.contains(m)) {
            let mut other = other.group.clone();
            other.member_ids.retain(|m| !moved.contains(m));
            core.save_group(vault_id.clone(), other)?;
        }
    }
    let shown = one_line(&group.label);
    core.save_group(vault_id, group)?;
    commit(device, offline, &format!("Changed group {shown}"))
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
    use super::{chosen_auth, nests_in_itself, parse_address, parse_proxy, Address, AuthKind};
    use unissh_ffi::{ProxyKind, ServerGroup};

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
}
