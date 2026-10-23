//! Signing this machine in, three ways:
//!
//! - **pair** with a signed-in app ("Add device") — the same account as that
//!   app, its keys delivered over the end-to-end encrypted pairing channel;
//! - **escrow** — the same account, recovered with the password and Secret Key;
//! - **join** an invite as a separate account — for a shared machine, which then
//!   holds only what the team grants that account.
//!
//! Each creates the local instance first and deletes it again if the sign-in
//! does not get far enough to keep.

use std::fmt::Write as _;
use std::io::ErrorKind;
use std::sync::Arc;

use unissh_cloud::client::{http, unb64, validate_base_url};
use unissh_cloud::dto::PairingPayload;
use unissh_cloud::{identity, onboard, recovery, CloudError};
use unissh_ffi::Core;
use zeroize::Zeroizing;

use crate::device::{format_secret_key, normalize_secret_key, open_core, Device};
use crate::failure::{best_effort, Failure, Res};
use crate::home::{Home, Link, Origin};
use crate::tty::Tty;
use crate::{hosts, server};

/// Choices common to every way of signing in.
pub struct SignIn {
    /// Keep the Secret Key on this machine (owner-only file), so unlocking
    /// needs only the master password.
    pub remember: bool,
    /// Leave this machine's copy without a master password: the Secret Key
    /// alone unlocks it.
    pub no_password: bool,
}

impl SignIn {
    /// Remembers the account Secret Key when asked to. A failure is reported
    /// and does not stop the sign-in: the key is then typed at each unlock.
    fn keep_secret_key(&self, home: &Home, key: &str) -> Res<()> {
        if !self.remember {
            return Ok(());
        }
        home.remember_secret_key(key).inspect_err(|e| {
            eprintln!("unissh: could not keep the Secret Key on this machine: {e}");
        })
    }

    /// The master password for this machine's copy: a new one, typed twice.
    fn new_password(&self, tty: &mut Tty, prompt: &str) -> Res<Option<Zeroizing<String>>> {
        if self.no_password {
            return Ok(None);
        }
        Ok(Some(tty.new_secret(prompt)?))
    }
}

/// The instance a sign-in is creating, deleted again on drop unless kept.
struct Fresh<'h> {
    home: &'h Home,
    keep: bool,
}

impl<'h> Fresh<'h> {
    fn start(home: &'h Home) -> Res<Self> {
        if home.has_instance() || home.link()?.is_some() {
            return Err(Failure::msg(format!(
                "this machine is already signed in (UniSSH data in {}). \
                 `unissh status` shows to what; `unissh logout` signs it out",
                home.dir().display()
            )));
        }
        home.create()?;
        Ok(Self { home, keep: false })
    }

    fn keep(mut self) {
        self.keep = true;
    }
}

impl Drop for Fresh<'_> {
    fn drop(&mut self) {
        if !self.keep {
            best_effort(self.home.wipe());
        }
    }
}

fn terminal() -> Res<Tty> {
    Tty::open().map_err(|e| Failure::msg(format!("signing in needs a terminal: {e}")))
}

/// `unissh login pair`: becomes another device of a signed-in app's account.
pub fn pair(home: &Home, choice: &SignIn) -> Res<()> {
    let fresh = Fresh::start(home)?;
    let mut tty = terminal()?;
    tty.say(
        "In a signed-in UniSSH app open Settings → Server → Add device, copy the\n\
         text it shows and paste it here. Keep that card open until this finishes.\n",
    )?;
    let payload = read_payload(&mut tty)?;
    validate_base_url(&payload.base_url)?;
    let password = choice.new_password(&mut tty, "Master password for this machine: ")?;
    let core = open_core(home);
    tty.say("Pairing…\n")?;
    onboard::responder_join(
        &core,
        http(),
        &payload.base_url,
        &payload.channel_id,
        unb64(&payload.oob_code)?,
        password.map(|mut p| std::mem::take(&mut *p)),
        |key| choice.keep_secret_key(home, key),
    )?;
    let link = Link {
        base_url: payload.base_url,
        instance_id: payload.instance_id,
        space_id: payload.space_id,
        account_id: payload.account_id,
        device_id: payload.device_id,
        handle: None,
        origin: Origin::Paired,
    };
    home.save_link(&link)?;
    fresh.keep();
    welcome(home, core, link)
}

/// Reads the pasted pairing text, up to its last field or an empty line.
fn read_payload(tty: &mut Tty) -> Res<PairingPayload> {
    let mut text = String::new();
    loop {
        let line = match tty.line("") {
            Ok(line) => line,
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        };
        if line.trim().is_empty() && !text.is_empty() {
            break;
        }
        text.push_str(&line);
        text.push('\n');
        if let Some(payload) = PairingPayload::parse_text(&text) {
            return Ok(payload);
        }
    }
    Err(Failure::msg(
        "that is not the whole pairing text: it has seven lines, from baseUrl to oobCode",
    ))
}

/// `unissh login escrow`: signs in to an account with its password and Secret
/// Key, through the server's escrow.
pub fn escrow(home: &Home, base_url: &str, handle: &str, choice: &SignIn) -> Res<()> {
    validate_base_url(base_url)?;
    let fresh = Fresh::start(home)?;
    let mut tty = terminal()?;
    let password = (!choice.no_password)
        .then(|| tty.secret("Account password: "))
        .transpose()?;
    let secret_key = normalize_secret_key(&tty.secret("Secret Key: ")?);
    let password = password.map(|mut p| std::mem::take(&mut *p));

    let instance = identity::instance_info(http(), base_url)?;
    let params = identity::escrow_params(http(), base_url, handle)?;
    let core = open_core(home);
    let k_auth = core.derive_escrow_auth_with_params(
        password.clone(),
        secret_key.clone(),
        params.argon_salt,
        params.argon_mem_kib,
        params.argon_iterations,
        params.argon_parallelism,
    )?;
    // The server answers every refusal alike (no oracle for which part was wrong).
    let (blob, account_id) =
        identity::escrow_fetch(http(), base_url, handle, &k_auth).map_err(|e| match e {
            CloudError::Server { code, .. } if code == "forbidden" => Failure::msg(
                "wrong handle, password or Secret Key (or escrow sign-in is off for this account)",
            ),
            e @ (CloudError::Server { .. } | CloudError::Core(_) | CloudError::Other { .. }) => {
                e.into()
            }
        })?;
    recovery::install_keyset(&core, blob, password, secret_key, |key| {
        choice.keep_secret_key(home, key)
    })?;
    let registration = core.build_registration_request()?;
    let (_, device_id) = identity::device_self_enroll_as(
        http(),
        base_url,
        &registration,
        &identity::device_label("CLI"),
    )?;
    let mut link = Link {
        base_url: base_url.to_owned(),
        instance_id: instance.instance_id,
        space_id: String::new(),
        account_id,
        device_id,
        handle: Some(handle.to_owned()),
        origin: Origin::Escrow,
    };
    link.space_id = first_space(&core, &link)?;
    home.save_link(&link)?;
    fresh.keep();
    welcome(home, core, link)
}

/// The account's first space — where its cloud vaults are bound, as the app
/// picks it after an escrow sign-in.
fn first_space(core: &Core, link: &Link) -> Res<String> {
    let session = server::ServerSession::open(core, link)?;
    let spaces = identity::list_spaces(http(), &link.base_url, session.access())?;
    Ok(spaces
        .into_iter()
        .next()
        .map(|s| s.space_id)
        .unwrap_or_default())
}

/// What `unissh login join` needs besides the server.
pub struct Joining<'a> {
    /// The invite: its token, or the join link that carries it.
    pub invite: &'a str,
    /// Display name for the new account.
    pub display_name: Option<String>,
    /// Handle for the new account.
    pub handle: Option<String>,
}

/// `unissh login join`: creates a separate account on this machine and joins
/// it to the server with an invite.
pub fn join(home: &Home, base_url: &str, joining: &Joining<'_>, choice: &SignIn) -> Res<()> {
    validate_base_url(base_url)?;
    let token = invite_token(joining.invite);
    let fresh = Fresh::start(home)?;
    let mut tty = terminal()?;
    let instance = identity::instance_info(http(), base_url)?;
    let preview = identity::join_preview(http(), base_url, &token)?;
    let mut about = format!(
        "This invite joins a new account to {}",
        preview
            .instance_name
            .or(instance.name)
            .unwrap_or_else(|| base_url.to_owned())
    );
    for space in &preview.spaces {
        let _ = write!(about, "\n  space {} as {}", space.name, space.role);
    }
    tty.say(&format!("{about}\n"))?;
    if !tty.confirm("Create the account and join? [y/N] ")? {
        return Err(Failure::msg("not joined"));
    }
    let password = choice.new_password(&mut tty, "Master password for the new account: ")?;
    let core = open_core(home);
    let secret_key =
        Zeroizing::new(core.create_account(password.map(|mut p| std::mem::take(&mut *p)))?);
    let registration = core.build_registration_request()?;
    let outcome = identity::join(
        http(),
        base_url,
        &token,
        registration,
        None,
        joining.display_name.clone(),
        joining.handle.clone(),
    )?;
    // The invite is spent now: whatever fails next, this account must survive.
    let link = Link {
        base_url: base_url.to_owned(),
        instance_id: instance.instance_id,
        space_id: outcome.spaces.first().cloned().unwrap_or_default(),
        account_id: outcome.account_id,
        device_id: outcome.device_id,
        handle: joining.handle.clone(),
        origin: Origin::Joined,
    };
    home.save_link(&link)?;
    fresh.keep();
    best_effort(choice.keep_secret_key(home, &secret_key));
    // Shown once, on the terminal only (never stdout, which may be a log).
    let kit = Zeroizing::new(format_secret_key(&secret_key));
    tty.say(&emergency_kit(&kit))?;
    best_effort(tty.line("Press Enter once it is saved. "));
    tty.say(
        "A vault admin now has to grant this account access to the vaults it needs;\n\
         after that, `unissh sync` brings them here.\n",
    )?;
    welcome(home, core, link)
}

/// The Emergency Kit text for a new account's Secret Key, as printed.
fn emergency_kit(kit: &str) -> Zeroizing<String> {
    Zeroizing::new(format!(
        "\nEMERGENCY KIT — the Secret Key of the new account:\n\n    {kit}\n\n\
         Write it down and keep it offline. With the master password it is the only\n\
         way back into this account; nobody, not even the server, can recover it.\n"
    ))
}

/// The invite token out of whatever was pasted: the token itself, or a join
/// link (`https://server/join#<token>`).
fn invite_token(invite: &str) -> String {
    let invite = invite.trim();
    invite
        .rsplit_once('#')
        .map_or(invite, |(_, token)| token)
        .to_owned()
}

/// The first sync after signing in, and what came of it.
fn welcome(home: &Home, core: Arc<Core>, link: Link) -> Res<()> {
    let base_url = link.base_url.clone();
    let device = Device {
        home: home.clone(),
        link,
        core,
    };
    match server::sync(&device) {
        Ok(report) => server::warn_about(&report),
        Err(e) => eprintln!(
            "unissh: signed in, but the first sync failed: {e}\nRun `unissh sync` to try again."
        ),
    }
    let vaults = device.core.list_vaults()?.len();
    let hosts = hosts::load(&device.core)?.len();
    println!(
        "Signed in to {base_url}: {hosts} host(s) in {vaults} vault(s). `unissh hosts` lists them."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::invite_token;

    #[test]
    fn an_invite_is_taken_as_a_token_or_out_of_its_join_link() {
        assert_eq!(invite_token(" abc123 \n"), "abc123");
        assert_eq!(invite_token("https://u.example/join#abc123"), "abc123");
    }
}
