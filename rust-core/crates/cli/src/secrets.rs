//! The secrets in a vault — SSH keys, passwords, notes and personal
//! identities — as the app's Secrets panel keeps them: `unissh secrets`,
//! `unissh keys` and `unissh identities`.
//!
//! A secret goes in from the terminal, stdin or an owner-only file, never an
//! argument. It comes back out only through `secrets show --reveal`, the
//! CLI's form of the app's gated reveal; a public key is printed freely.

use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use clap::{Args, Subcommand};
use serde_json::{json, Value};
use unissh_ffi::{
    AuthMethod, Core, FfiError, Identity, ItemInfo, ProfileAuth, ProxyPassword, VaultInfo,
    ITEM_TYPE_IDENTITY as IDENTITY, ITEM_TYPE_NOTE as NOTE, ITEM_TYPE_PASSWORD as PASSWORD,
    ITEM_TYPE_SSH_KEY as SSH_KEY,
};
use zeroize::Zeroizing;

use crate::device::{ask_secret, Device};
use crate::edit::{self, columns, commit, print_json, stored, take, SecretFrom, Shape, VaultArg};
use crate::failure::{Failure, Res};
use crate::home::read_private;
use crate::hosts::{self, Named};
use crate::manage::ago;
use crate::rotation::{self, RotationAction};
use crate::tty::{confirm, one_line};

/// Which secrets a lookup is after: the item types, and what one is called.
pub trait Sort {
    /// What one is called in messages ("SSH key").
    const KIND: &'static str;
    /// The plural of [`Self::KIND`] ("SSH keys").
    const KINDS: &'static str;
    /// The core's item types it covers.
    const TYPES: &'static [u32];
}

/// Any secret: what `unissh secrets` shows (certificates show on their key).
pub struct AnySecret;
impl Sort for AnySecret {
    const KIND: &'static str = "secret";
    const KINDS: &'static str = "secrets";
    const TYPES: &'static [u32] = &[SSH_KEY, PASSWORD, NOTE, IDENTITY];
}

/// An SSH key.
pub struct Key;
impl Sort for Key {
    const KIND: &'static str = "SSH key";
    const KINDS: &'static str = "SSH keys";
    const TYPES: &'static [u32] = &[SSH_KEY];
}

/// A stored password.
pub struct Password;
impl Sort for Password {
    const KIND: &'static str = "stored password";
    const KINDS: &'static str = "stored passwords";
    const TYPES: &'static [u32] = &[PASSWORD];
}

/// A personal identity, as a vault item.
pub struct IdentityItem;
impl Sort for IdentityItem {
    const KIND: &'static str = "identity";
    const KINDS: &'static str = "identities";
    const TYPES: &'static [u32] = &[IDENTITY];
}

/// A secret of sort `S` and the vault it lives in. Its name is its item id,
/// as in the app.
pub struct Entry<S> {
    /// The vault's id.
    pub vault_id: String,
    /// The vault's name.
    pub vault_name: String,
    /// The item, without its content.
    pub info: ItemInfo,
    sort: PhantomData<S>,
}

impl<S: Sort> Named for Entry<S> {
    const KIND: &'static str = S::KIND;
    const KINDS: &'static str = S::KINDS;
    const LISTED_BY: Option<&'static str> = Some("unissh secrets list");

    fn vault_name(&self) -> &str {
        &self.vault_name
    }

    fn label(&self) -> &str {
        &self.info.item_id
    }

    fn detail(&self) -> String {
        kind_name(self.info.item_type).to_owned()
    }
}

/// What an item type is called here.
const fn kind_name(item_type: u32) -> &'static str {
    match item_type {
        SSH_KEY => "key",
        PASSWORD => "password",
        NOTE => "note",
        IDENTITY => "identity",
        _ => "item",
    }
}

/// The secrets of sort `S` in every vault, or in the vault `scope` names.
pub fn load<S: Sort>(core: &Core, scope: Option<&str>) -> Res<Vec<Entry<S>>> {
    let mut out = hosts::per_vault(
        core,
        |vault_id| {
            if edit::in_scope(scope, &vault_id) {
                core.list_items(vault_id)
            } else {
                Ok(Vec::new())
            }
        },
        |vault_id, vault_name, info: ItemInfo| Entry {
            vault_id: vault_id.to_owned(),
            vault_name: vault_name.to_owned(),
            info,
            sort: PhantomData,
        },
    )?;
    out.retain(|e| S::TYPES.contains(&e.info.item_type));
    out.sort_by_cached_key(|e| {
        (
            e.vault_name.to_lowercase(),
            e.info.item_type,
            e.info.item_id.to_lowercase(),
        )
    });
    Ok(out)
}

/// The secret of sort `S` that `query` names in the vault `scope` names (in
/// any vault without one): its exact name first, else the usual lookup.
fn find<S: Sort>(core: &Core, scope: Option<&str>, query: &str) -> Res<Entry<S>> {
    take(load::<S>(core, scope)?, query, |e| &e.info.item_id)
}

/// The id of the secret of sort `S` that `query` names in vault `vault_id` —
/// for a host or identity field, which may only point into its own vault.
pub fn find_in<S: Sort>(core: &Core, vault_id: &str, query: &str) -> Res<String> {
    Ok(find::<S>(core, Some(vault_id), query)?.info.item_id)
}

/// The secret of sort `S` that `query` names, in the scope `vault` sets.
pub fn find_one<S: Sort>(core: &Core, vault: &VaultArg, query: &str) -> Res<Entry<S>> {
    find::<S>(core, vault.scope(core)?.as_deref(), query)
}

/// Refuses `name` when anything already has that id in the vault: the core
/// would overwrite a key's private material in place.
fn refuse_taken(core: &Core, vault_id: &str, vault_name: &str, name: &str) -> Res<()> {
    if core
        .list_items(vault_id.to_owned())?
        .iter()
        .any(|i| i.item_id == name)
    {
        return Err(Failure::msg(format!(
            "\"{name}\" already exists in vault \"{}\"",
            one_line(vault_name)
        )));
    }
    Ok(())
}

/// A name for a new item: not empty, one line.
fn new_name(name: &str) -> Res<String> {
    let name = name.trim();
    if name.is_empty() || name.chars().any(char::is_control) {
        return Err(Failure::msg("a name must be one line of text, not empty"));
    }
    Ok(name.to_owned())
}

// ---------- unissh secrets ----------

/// `unissh secrets`.
#[derive(Subcommand)]
pub enum SecretsAction {
    /// List the keys, passwords, notes and identities (names only).
    List {
        #[command(flatten)]
        vault: VaultArg,
        /// Print JSON (names and kinds; never a secret).
        #[arg(long)]
        json: bool,
    },
    /// Store a password, asked twice on the terminal. Storing one under an
    /// existing name makes a new version; the old one stays in its history.
    AddPassword {
        /// Its name.
        name: String,
        #[command(flatten)]
        vault: VaultArg,
        #[command(flatten)]
        from: SecretFrom,
        /// Replace an existing password without asking.
        #[arg(long)]
        yes: bool,
    },
    /// Store a note (recovery codes, IPMI credentials, ...). An existing one
    /// gets a new version; the old one stays in its history.
    AddNote {
        /// Its name.
        name: String,
        #[command(flatten)]
        vault: VaultArg,
        #[command(flatten)]
        from: SecretFrom,
        /// Replace an existing note without asking.
        #[arg(long)]
        yes: bool,
    },
    /// Show a secret: what it is and, with --reveal, what it holds (a
    /// password, a note's text, a key's private key) on stdout.
    Show {
        /// Its name (or vault/name).
        name: String,
        #[command(flatten)]
        vault: VaultArg,
        /// Print the secret itself, and nothing else. A private key is
        /// printed only after a confirmation on the terminal.
        #[arg(long)]
        reveal: bool,
        /// An earlier version of a password or note, from its history.
        #[arg(long, value_name = "N", requires = "reveal")]
        version: Option<u64>,
        /// Print a private key without asking (the warning is still shown).
        #[arg(long, requires = "reveal")]
        yes: bool,
    },
    /// Delete a key, password, note or identity.
    Rm {
        /// Its name (or vault/name).
        name: String,
        #[command(flatten)]
        vault: VaultArg,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
}

/// Runs `unissh secrets`.
pub fn secrets(device: &Device, offline: bool, action: SecretsAction) -> Res<()> {
    let core = &device.core;
    match action {
        SecretsAction::List { vault, json } => list(core, &vault, json),
        SecretsAction::AddPassword {
            name,
            vault,
            from,
            yes,
        } => {
            let (target, name) = prepare_text(core, &vault, &name, PASSWORD, yes)?;
            let secret = from.read("the password", "Password: ", Shape::New)?;
            stored(
                &target.name,
                core.save_password(target.vault_id.clone(), name.clone(), (*secret).clone()),
            )?;
            commit(
                device,
                &target.vault_id,
                offline,
                &format!("Stored password {}", one_line(&name)),
            )
        }
        SecretsAction::AddNote {
            name,
            vault,
            from,
            yes,
        } => {
            let (target, name) = prepare_text(core, &vault, &name, NOTE, yes)?;
            let text = from.read("the note", "Note: ", Shape::Block)?;
            stored(
                &target.name,
                core.save_note(target.vault_id.clone(), name.clone(), (*text).clone()),
            )?;
            commit(
                device,
                &target.vault_id,
                offline,
                &format!("Stored note {}", one_line(&name)),
            )
        }
        SecretsAction::Show {
            name,
            vault,
            reveal,
            version,
            yes,
        } => {
            let entry = find_one::<AnySecret>(core, &vault, &name)?;
            if reveal {
                self::reveal(core, &entry, version, yes)
            } else {
                describe(core, &entry)
            }
        }
        SecretsAction::Rm { name, vault, yes } => {
            let entry = find_one::<AnySecret>(core, &vault, &name)?;
            remove(device, offline, &entry, yes)
        }
    }
}

fn list(core: &Core, vault: &VaultArg, json: bool) -> Res<()> {
    let scope = vault.scope(core)?;
    let items = load::<AnySecret>(core, scope.as_deref())?;
    if json {
        return print_json(&Value::Array(
            items
                .iter()
                .map(|e| {
                    json!({
                        "vault": e.vault_name,
                        "name": e.info.item_id,
                        "kind": kind_name(e.info.item_type),
                        "version": e.info.version,
                        "updated_at": e.info.updated_at,
                        "certificate": e.info.has_certificate,
                    })
                })
                .collect(),
        ));
    }
    if items.is_empty() {
        eprintln!("unissh: no secrets to show");
        return Ok(());
    }
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|e| {
            let mut kind = kind_name(e.info.item_type).to_owned();
            if e.info.has_certificate {
                kind.push_str(" +cert");
            }
            vec![
                e.info.item_id.clone(),
                kind,
                e.vault_name.clone(),
                updated(e.info.updated_at),
            ]
        })
        .collect();
    print!("{}", columns(&rows));
    Ok(())
}

/// "3 days ago" for a unix time from the core.
fn updated(unix: i64) -> String {
    let secs = u64::try_from(unix).unwrap_or(0);
    if secs == 0 {
        return "—".to_owned();
    }
    ago(UNIX_EPOCH
        .checked_add(Duration::from_secs(secs))
        .unwrap_or(UNIX_EPOCH))
}

/// The vault and name a password or note is stored under. An existing item
/// of the same kind is replaced only after a yes (it keeps its history); one
/// of another kind is refused.
fn prepare_text(
    core: &Core,
    vault: &VaultArg,
    name: &str,
    item_type: u32,
    yes: bool,
) -> Res<(VaultInfo, String)> {
    let name = new_name(name)?;
    let target = vault.pick(core, None)?;
    let existing = core
        .list_items(target.vault_id.clone())?
        .into_iter()
        .find(|i| i.item_id == name);
    if let Some(item) = existing {
        if item.item_type != item_type {
            return Err(Failure::msg(format!(
                "\"{name}\" in vault \"{}\" is a {}, not a {}",
                one_line(&target.name),
                kind_name(item.item_type),
                kind_name(item_type)
            )));
        }
        confirm(
            yes,
            &format!(
                "\"{name}\" exists in vault \"{}\": this stores a new version of it \
                 (the current one stays in its history).\n",
                one_line(&target.name)
            ),
        )?;
    }
    Ok((target, name))
}

/// What a secret is, without what it holds.
fn describe<S>(core: &Core, entry: &Entry<S>) -> Res<()> {
    let info = &entry.info;
    let mut rows = vec![
        vec!["Name:".to_owned(), info.item_id.clone()],
        vec!["Kind:".to_owned(), kind_name(info.item_type).to_owned()],
        vec!["Vault:".to_owned(), entry.vault_name.clone()],
        vec!["Version:".to_owned(), info.version.to_string()],
        vec!["Updated:".to_owned(), updated(info.updated_at)],
    ];
    match info.item_type {
        SSH_KEY => {
            let public = core.get_public_key(entry.vault_id.clone(), info.item_id.clone())?;
            rows.push(vec!["Fingerprint:".to_owned(), public.fingerprint]);
            rows.push(vec![
                "Certificate:".to_owned(),
                if info.has_certificate {
                    "attached"
                } else {
                    "none"
                }
                .to_owned(),
            ]);
            rows.push(vec!["Public key:".to_owned(), public.openssh]);
        }
        IDENTITY => {
            let identity = core.get_identity(entry.vault_id.clone(), info.item_id.clone())?;
            rows.push(vec!["User:".to_owned(), identity.user.clone()]);
            rows.push(vec!["Logs in with:".to_owned(), credential(&identity)]);
        }
        _ => rows.push(vec![
            "Content:".to_owned(),
            "hidden; --reveal prints it".to_owned(),
        ]),
    }
    print!("{}", columns(&rows));
    Ok(())
}

/// Prints what a secret holds — the explicit reveal, on stdout only. A
/// private key is printed only after the app's export warning is confirmed
/// on the terminal (or `yes`): unlike a password, it is not meant to leave
/// the vault, and stdout may well be a file.
fn reveal<S>(core: &Core, entry: &Entry<S>, version: Option<u64>, yes: bool) -> Res<()> {
    let (vault_id, item_id) = (entry.vault_id.clone(), entry.info.item_id.clone());
    if entry.info.item_type == SSH_KEY && version.is_none() {
        confirm(
            yes,
            &format!(
                "The private key \"{}\" will be printed unencrypted. Keep it somewhere safe.\n",
                one_line(&item_id)
            ),
        )?;
    }
    let text = Zeroizing::new(match (entry.info.item_type, version) {
        (PASSWORD, None) => core.get_password(vault_id, item_id)?,
        (PASSWORD, Some(v)) => core.get_password_version(vault_id, item_id, v)?,
        (NOTE, None) => core.get_note(vault_id, item_id)?,
        (NOTE, Some(v)) => core.get_note_version(vault_id, item_id, v)?,
        (SSH_KEY, None) => core.export_ssh_key(vault_id, item_id)?,
        (SSH_KEY, Some(_)) => {
            return Err(Failure::msg(
                "earlier versions of a key are not revealed; only the current private key is",
            ))
        }
        _ => {
            return Err(Failure::msg(
                "an identity holds no secret of its own: `unissh secrets show` without \
                 --reveal shows what it logs in with",
            ))
        }
    });
    if text.ends_with('\n') {
        print!("{}", *text);
    } else {
        println!("{}", *text);
    }
    Ok(())
}

/// What an identity logs in with, by name.
fn credential(identity: &Identity) -> String {
    match (&identity.key_item_id, &identity.password_item_id) {
        (Some(key), _) => format!("key {key}"),
        (None, Some(password)) => format!("password {password}"),
        (None, None) => "the user name only".to_owned(),
    }
}

/// Deletes a secret after saying what still uses it.
fn remove<S>(device: &Device, offline: bool, entry: &Entry<S>, yes: bool) -> Res<()> {
    let core = &device.core;
    let id = &entry.info.item_id;
    let vault_id = &entry.vault_id;
    let mut warning = format!(
        "This deletes the {} \"{}\" from vault \"{}\".\n",
        kind_name(entry.info.item_type),
        one_line(id),
        one_line(&entry.vault_name)
    );
    if entry.info.item_type == IDENTITY {
        let bound = core
            .list_bindings(vault_id.clone())
            .map(|b| b.iter().filter(|b| &b.identity_item_id == id).count())
            .unwrap_or(0);
        if bound > 0 {
            warning.push_str(&format!(
                "{bound} host(s) log in with it; they will have no identity to log in with.\n"
            ));
        }
    } else {
        let uses = uses_of(core, vault_id, id)?;
        if uses > 0 {
            warning.push_str(&format!(
                "It is used by {uses} host(s) or identities. Deleting it will break their login.\n"
            ));
        }
    }
    confirm(yes, &warning)?;
    let deleted = if entry.info.item_type == IDENTITY {
        core.delete_identity(vault_id.clone(), id.clone())
    } else {
        core.delete_item(vault_id.clone(), id.clone())
    };
    stored(&entry.vault_name, deleted)?;
    commit(
        device,
        vault_id,
        offline,
        &format!(
            "Deleted {} {}",
            kind_name(entry.info.item_type),
            one_line(id)
        ),
    )
}

/// How many hosts (their login, a jump hop, a proxy) and identities in the
/// vault refer to the key or password `id`.
fn uses_of(core: &Core, vault_id: &str, id: &str) -> Res<usize> {
    let refers = |auth: &AuthMethod| match auth {
        AuthMethod::Agent { key_item_id, .. } => key_item_id == id,
        AuthMethod::VaultPassword {
            password_item_id, ..
        } => password_item_id == id,
        AuthMethod::Password { .. } | AuthMethod::SystemAgent { .. } => false,
    };
    let hosts = core
        .list_connections(vault_id.to_owned())?
        .into_iter()
        .filter(|p| {
            let own = match &p.auth {
                ProfileAuth::Key { key_item_id } => key_item_id == id,
                ProfileAuth::VaultPassword { password_item_id } => password_item_id == id,
                ProfileAuth::PromptPassword
                | ProfileAuth::SystemAgent { .. }
                | ProfileAuth::Personal => false,
            };
            let hop = p
                .jumps
                .iter()
                .any(|j| j.hop_ref.is_none() && refers(&j.auth));
            let proxy = p.proxy.as_ref().is_some_and(|x| {
                matches!(&x.password, Some(ProxyPassword::Vault { password_item_id, .. })
                    if password_item_id == id)
            });
            own || hop || proxy
        })
        .count();
    let identities = core
        .list_identities(vault_id.to_owned())?
        .into_iter()
        .filter(|i| {
            i.key_item_id.as_deref() == Some(id) || i.password_item_id.as_deref() == Some(id)
        })
        .count();
    Ok(hosts.saturating_add(identities))
}

// ---------- unissh keys ----------

/// `unissh keys`.
#[derive(Subcommand)]
pub enum KeysAction {
    /// Generate an Ed25519 key in the vault and print its public key. The
    /// private key never leaves the vault.
    Generate {
        /// Its name.
        name: String,
        #[command(flatten)]
        vault: VaultArg,
    },
    /// Import a private key (OpenSSH or PEM) from FILE, `-` for stdin. Its
    /// passphrase, when it has one, is asked on the terminal.
    Import {
        /// Its name in the vault.
        name: String,
        /// The private key file (only you may be able to read it), or `-`.
        file: PathBuf,
        #[command(flatten)]
        vault: VaultArg,
    },
    /// Print a key's public key, for authorized_keys.
    Public {
        /// The key's name (or vault/name).
        name: String,
        #[command(flatten)]
        vault: VaultArg,
        /// Print its SHA256 fingerprint instead.
        #[arg(long)]
        fingerprint: bool,
    },
    /// Attach an OpenSSH user certificate to a key: logins then present it.
    Certificate {
        /// The key's name (or vault/name).
        name: String,
        /// The certificate file (`*-cert.pub`), or `-` for stdin.
        file: PathBuf,
        #[command(flatten)]
        vault: VaultArg,
    },
    /// Replace a key with a new pair under the same name and print the new
    /// public key. Every host using it follows at once — and refuses logins
    /// until the new public key is installed there.
    Rotate {
        /// The key's name (or vault/name).
        name: String,
        #[command(flatten)]
        vault: VaultArg,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// A guided rotation, as the app's Start rotation: begin a new key beside
    /// this one, move each machine over to it, then finish (or abandon).
    #[command(subcommand)]
    Rotation(RotationAction),
    /// Delete a key.
    Rm {
        /// The key's name (or vault/name).
        name: String,
        #[command(flatten)]
        vault: VaultArg,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
}

/// Runs `unissh keys`.
pub fn keys(device: &Device, offline: bool, action: KeysAction) -> Res<()> {
    let core = &device.core;
    match action {
        KeysAction::Generate { name, vault } => {
            let name = new_name(&name)?;
            let target = vault.pick(core, None)?;
            refuse_taken(core, &target.vault_id, &target.name, &name)?;
            let public = stored(
                &target.name,
                core.generate_ssh_key(target.vault_id.clone(), name.clone()),
            )?;
            println!("{}", public.trim_end());
            commit(
                device,
                &target.vault_id,
                offline,
                &format!("Generated key {}", one_line(&name)),
            )
        }
        KeysAction::Import { name, file, vault } => {
            let name = new_name(&name)?;
            let target = vault.pick(core, None)?;
            refuse_taken(core, &target.vault_id, &target.name, &name)?;
            let private = read_input(&file, true)?;
            let public = import(core, &target, &name, &private)?;
            println!("{}", public.trim_end());
            commit(
                device,
                &target.vault_id,
                offline,
                &format!("Imported key {}", one_line(&name)),
            )
        }
        KeysAction::Public {
            name,
            vault,
            fingerprint,
        } => {
            let key = find_one::<Key>(core, &vault, &name)?;
            let public = core.get_public_key(key.vault_id, key.info.item_id)?;
            if fingerprint {
                println!("{}", public.fingerprint);
            } else {
                println!("{}", public.openssh.trim_end());
            }
            Ok(())
        }
        KeysAction::Certificate { name, file, vault } => {
            let key = find_one::<Key>(core, &vault, &name)?;
            let cert = read_input(&file, false)?;
            stored(
                &key.vault_name,
                core.import_ssh_certificate(
                    key.vault_id.clone(),
                    key.info.item_id.clone(),
                    cert.trim().to_owned(),
                ),
            )?;
            commit(
                device,
                &key.vault_id,
                offline,
                &format!("Attached the certificate to key {}", key.info.item_id),
            )
        }
        KeysAction::Rotate { name, vault, yes } => {
            let key = find_one::<Key>(core, &vault, &name)?;
            rotate(device, offline, &key, yes)
        }
        KeysAction::Rotation(action) => rotation::rotation(device, offline, action),
        KeysAction::Rm { name, vault, yes } => {
            let key = find_one::<Key>(core, &vault, &name)?;
            remove(device, offline, &key, yes)
        }
    }
}

/// The text of `file`, or of stdin for `-`. A private key file must be the
/// owner's alone, as `ssh` wants it; a certificate is public.
fn read_input(file: &Path, private: bool) -> Res<Zeroizing<String>> {
    if file == Path::new("-") {
        return SecretFrom {
            stdin: true,
            from_file: None,
        }
        .read("the input", "", Shape::Block);
    }
    let text = if private {
        read_private(file)?
    } else {
        match std::fs::read_to_string(file) {
            Ok(text) => Some(Zeroizing::new(text)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(Failure::msg(format!("cannot read {}: {e}", file.display()))),
        }
    };
    text.ok_or_else(|| Failure::msg(format!("{} does not exist", file.display())))
}

/// Imports `private` as key `name` into `target`, asking for its passphrase
/// when the core says it needs one — the app's flow, with the terminal as
/// its dialog.
fn import(core: &Core, target: &VaultInfo, name: &str, private: &str) -> Res<String> {
    let attempt = |passphrase: Option<String>| {
        stored(
            &target.name,
            core.import_ssh_key(
                target.vault_id.clone(),
                name.to_owned(),
                private.to_owned(),
                passphrase,
            ),
        )
    };
    match core.import_ssh_key(
        target.vault_id.clone(),
        name.to_owned(),
        private.to_owned(),
        None,
    ) {
        Ok(public) => Ok(public),
        Err(e) if needs_passphrase(&e) => {
            let passphrase = ask_secret(
                &format!("Passphrase for {}: ", one_line(name)),
                "the key's passphrase",
                "run interactively, or remove the passphrase from a copy of the key",
            )?;
            attempt(Some((*passphrase).clone()))
        }
        Err(e) => stored(&target.name, Err(e)),
    }
}

/// Whether the core refused a key for want of its passphrase (its messages
/// are stable English, which is what the app matches as well).
fn needs_passphrase(e: &FfiError) -> bool {
    let text = e.to_string().to_lowercase();
    text.contains("passphrase is required") || text.contains("passphrase-protected")
}

/// `unissh keys rotate`: the app's "Replace key", not its guided rotation.
fn rotate(device: &Device, offline: bool, key: &Entry<Key>, yes: bool) -> Res<()> {
    let core = &device.core;
    let id = &key.info.item_id;
    let staged = core
        .list_key_rotations(key.vault_id.clone())?
        .into_iter()
        .any(|l| &l.key_id == id || &l.candidate_id == id);
    if staged {
        return Err(Failure::msg(format!(
            "a staged rotation of \"{}\" is in progress: `unissh keys rotation finish \"{}\"`, \
             or `unissh keys rotation abandon \"{}\"`",
            one_line(id),
            one_line(id),
            one_line(id)
        )));
    }
    let mut warning = format!(
        "A new keypair replaces \"{}\" immediately and the old private key is discarded.\n\
         Every host that trusts only the old public key will refuse logins until you\n\
         install the new one. To switch without a lockout: `unissh keys rotation begin`.\n",
        one_line(id)
    );
    if key.info.has_certificate {
        warning.push_str("Its certificate certifies the old key and is removed.\n");
    }
    confirm(yes, &warning)?;
    let public = stored(
        &key.vault_name,
        core.rotate_ssh_key(key.vault_id.clone(), id.clone()),
    )?;
    println!("{}", public.trim_end());
    commit(
        device,
        &key.vault_id,
        offline,
        &format!("Replaced key {}", one_line(id)),
    )
}

// ---------- unissh identities ----------

/// A personal identity and the vault it lives in.
pub struct IdentityEntry {
    /// The vault's id.
    pub vault_id: String,
    /// The vault's name.
    pub vault_name: String,
    /// The identity.
    pub identity: Identity,
}

impl Named for IdentityEntry {
    const KIND: &'static str = "identity";
    const KINDS: &'static str = "identities";
    const LISTED_BY: Option<&'static str> = Some("unissh identities list");

    fn vault_name(&self) -> &str {
        &self.vault_name
    }

    fn label(&self) -> &str {
        &self.identity.label
    }

    fn detail(&self) -> String {
        self.identity.user.clone()
    }
}

/// Every personal identity, or those of the vault `scope` names.
pub fn load_identities(core: &Core, scope: Option<&str>) -> Res<Vec<IdentityEntry>> {
    let mut out = hosts::per_vault(
        core,
        |vault_id| {
            if edit::in_scope(scope, &vault_id) {
                core.list_identities(vault_id)
            } else {
                Ok(Vec::new())
            }
        },
        |vault_id, vault_name, identity| IdentityEntry {
            vault_id: vault_id.to_owned(),
            vault_name: vault_name.to_owned(),
            identity,
        },
    )?;
    out.sort_by_cached_key(|e| {
        (
            e.vault_name.to_lowercase(),
            e.identity.identity_id.to_lowercase(),
        )
    });
    Ok(out)
}

/// The identity `query` names (its name or vault/name) among `all`.
fn take_identity(all: Vec<IdentityEntry>, query: &str) -> Res<IdentityEntry> {
    take(all, query, |e| &e.identity.identity_id)
}

/// What an identity logs in with: `--key` or `--password-item`, both in the
/// identity's own vault.
#[derive(Args)]
pub struct IdentityCredential {
    /// Log in with this SSH key.
    #[arg(long, value_name = "KEY")]
    key: Option<String>,
    /// Log in with this stored password.
    #[arg(long, value_name = "SECRET", conflicts_with = "key")]
    password_item: Option<String>,
    /// Neither: the identity gives only the user name.
    #[arg(long, conflicts_with_all = ["key", "password_item"])]
    no_credential: bool,
}

impl IdentityCredential {
    const fn given(&self) -> bool {
        self.key.is_some() || self.password_item.is_some() || self.no_credential
    }

    /// Sets the credential on `identity`, checking the item it names.
    fn apply(&self, core: &Core, vault_id: &str, identity: &mut Identity) -> Res<()> {
        if let Some(key) = &self.key {
            identity.key_item_id = Some(find_in::<Key>(core, vault_id, key)?);
            identity.password_item_id = None;
        } else if let Some(password) = &self.password_item {
            identity.password_item_id = Some(find_in::<Password>(core, vault_id, password)?);
            identity.key_item_id = None;
        } else if self.no_credential {
            identity.key_item_id = None;
            identity.password_item_id = None;
        }
        Ok(())
    }
}

/// `unissh identities`.
#[derive(Subcommand)]
pub enum IdentitiesAction {
    /// List the personal identities.
    List {
        #[command(flatten)]
        vault: VaultArg,
        /// Print JSON (names, users and the names of what they log in with).
        #[arg(long)]
        json: bool,
    },
    /// Add a personal identity: a user name and the key or password it logs
    /// in with, kept in a private vault (your personal vault by default).
    /// Shared hosts that log in "personally" use it once linked with
    /// `unissh hosts edit <host> --identity <name>`.
    Add {
        /// Its name.
        name: String,
        /// The user name it logs in as.
        #[arg(long)]
        user: String,
        #[command(flatten)]
        credential: IdentityCredential,
        #[command(flatten)]
        vault: VaultArg,
    },
    /// Change an identity's user name or what it logs in with.
    Edit {
        /// Its name (or vault/name).
        name: String,
        /// The user name it logs in as.
        #[arg(long)]
        user: Option<String>,
        #[command(flatten)]
        credential: IdentityCredential,
        #[command(flatten)]
        vault: VaultArg,
    },
    /// Delete an identity.
    Rm {
        /// Its name (or vault/name).
        name: String,
        #[command(flatten)]
        vault: VaultArg,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
}

/// Runs `unissh identities`.
pub fn identities(device: &Device, offline: bool, action: IdentitiesAction) -> Res<()> {
    let core = &device.core;
    match action {
        IdentitiesAction::List { vault, json } => {
            let scope = vault.scope(core)?;
            let all = load_identities(core, scope.as_deref())?;
            if json {
                return print_json(&Value::Array(
                    all.iter()
                        .map(|e| {
                            json!({
                                "vault": e.vault_name,
                                "name": e.identity.identity_id,
                                "user": e.identity.user,
                                "key": e.identity.key_item_id,
                                "password_item": e.identity.password_item_id,
                            })
                        })
                        .collect(),
                ));
            }
            if all.is_empty() {
                eprintln!("unissh: no identities to show");
                return Ok(());
            }
            let rows: Vec<Vec<String>> = all
                .iter()
                .map(|e| {
                    vec![
                        e.identity.identity_id.clone(),
                        e.identity.user.clone(),
                        e.vault_name.clone(),
                        credential(&e.identity),
                    ]
                })
                .collect();
            print!("{}", columns(&rows));
            Ok(())
        }
        IdentitiesAction::Add {
            name,
            user,
            credential,
            vault,
        } => {
            let name = new_name(&name)?;
            let user = required_user(&user)?;
            let personal = core.get_personal_vault().ok().flatten();
            let target = vault.pick(core, personal.as_deref())?;
            refuse_taken(core, &target.vault_id, &target.name, &name)?;
            let mut identity = Identity {
                identity_id: name.clone(),
                label: name.clone(),
                user,
                key_item_id: None,
                password_item_id: None,
            };
            credential.apply(core, &target.vault_id, &mut identity)?;
            stored(
                &target.name,
                core.save_identity(target.vault_id.clone(), identity),
            )?;
            commit(
                device,
                &target.vault_id,
                offline,
                &format!("Added identity {}", one_line(&name)),
            )
        }
        IdentitiesAction::Edit {
            name,
            user,
            credential,
            vault,
        } => {
            if user.is_none() && !credential.given() {
                return Err(Failure::msg(
                    "nothing to change: give --user, --key, --password-item or --no-credential",
                ));
            }
            let scope = vault.scope(core)?;
            let found = take_identity(load_identities(core, scope.as_deref())?, &name)?;
            let mut identity = found.identity.clone();
            if let Some(user) = user {
                identity.user = required_user(&user)?;
            }
            credential.apply(core, &found.vault_id, &mut identity)?;
            let id = identity.identity_id.clone();
            stored(
                &found.vault_name,
                core.save_identity(found.vault_id.clone(), identity),
            )?;
            commit(
                device,
                &found.vault_id,
                offline,
                &format!("Changed identity {}", one_line(&id)),
            )
        }
        IdentitiesAction::Rm { name, vault, yes } => {
            let entry = find_one::<IdentityItem>(core, &vault, &name)?;
            remove(device, offline, &entry, yes)
        }
    }
}

fn required_user(user: &str) -> Res<String> {
    let user = user.trim();
    if user.is_empty() {
        return Err(Failure::msg("an identity needs a user name"));
    }
    Ok(user.to_owned())
}

/// The identity `query` names, in any vault — for linking one to a host.
pub fn find_identity(core: &Core, query: &str) -> Res<IdentityEntry> {
    take_identity(load_identities(core, None)?, query)
}

#[cfg(test)]
mod tests {
    use super::needs_passphrase;
    use unissh_ffi::FfiError;

    /// The core's wording for a key that needs its passphrase is what makes
    /// the import ask for one; any other failure is reported as it is.
    #[test]
    fn only_a_missing_passphrase_makes_the_import_ask_for_one() {
        let other = |msg: &str| FfiError::Other {
            msg: msg.to_owned(),
        };
        assert!(needs_passphrase(&other(
            "a passphrase is required to decrypt"
        )));
        assert!(needs_passphrase(&other("key is passphrase-protected")));
        assert!(!needs_passphrase(&other("incorrect passphrase")));
    }
}
