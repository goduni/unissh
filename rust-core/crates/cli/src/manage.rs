//! Looking after the device itself: what it is signed in to, its pinned host
//! keys, and signing it out.

use std::time::SystemTime;

use unissh_cloud::client::http;
use unissh_cloud::identity;
use unissh_ffi::Core;

use crate::device::{open_core, Credentials, Device, NOT_SIGNED_IN};
use crate::failure::{Failure, Res};
use crate::home::{Home, Link, Origin};
use crate::server::ServerSession;
use crate::tty::Tty;

/// `unissh status`: what this machine is signed in to. Needs no unlock.
pub fn status(home: &Home) -> Res<()> {
    let Some(link) = home.link()? else {
        if home.has_instance() {
            return Err(Failure::msg(format!(
                "the UniSSH data in {} is incomplete; `unissh logout --local` removes it",
                home.dir().display()
            )));
        }
        println!("{NOT_SIGNED_IN}");
        return Ok(());
    };
    let core = open_core(home);
    let account = link.handle.as_deref().unwrap_or(&link.account_id);
    let origin = match link.origin {
        Origin::Paired => "paired with another device of the account",
        Origin::Escrow => "signed in with the account password",
        Origin::Joined => "an account of its own, joined by invite",
    };
    let password = match core.instance_requires_password() {
        Some(true) => "required",
        Some(false) => "none — the Secret Key alone unlocks it",
        None => "unknown (the keyset cannot be read)",
    };
    let key_storage = if home.remembers_secret_key() {
        "kept on this machine"
    } else {
        "asked at every unlock"
    };
    let synced = home.last_sync().map_or_else(|| "never".to_owned(), ago);
    println!("Server:          {}", link.base_url);
    println!("Account:         {account} ({origin})");
    println!("This device:     {}", link.device_id);
    println!("Master password: {password}");
    println!("Secret Key:      {key_storage}");
    println!("Last sync:       {synced}");
    println!("Data:            {}", home.dir().display());
    Ok(())
}

/// "3 minutes ago", for a time in the past.
fn ago(at: SystemTime) -> String {
    let Ok(age) = SystemTime::now().duration_since(at) else {
        return "just now".to_owned();
    };
    let (n, unit) = match age.as_secs() {
        s if s < 60 => return "just now".to_owned(),
        s if s < 3600 => (s / 60, "minute"),
        s if s < 86_400 => (s / 3600, "hour"),
        s => (s / 86_400, "day"),
    };
    let plural = if n == 1 { "" } else { "s" };
    format!("{n} {unit}{plural} ago")
}

/// What `unissh known-hosts` was asked to do.
pub enum KnownHostsAction {
    /// List the pinned keys.
    List,
    /// Accept a host's new key after a mismatch.
    Trust {
        /// `host` or `host:port`.
        host: String,
        /// The fingerprint the warning showed.
        fingerprint: String,
    },
    /// Drop a pinned key; the next connection pins whatever the host presents.
    Forget {
        /// `host` or `host:port`.
        host: String,
    },
}

/// `unissh known-hosts`.
pub fn known_hosts(core: &Core, action: KnownHostsAction) -> Res<()> {
    match action {
        KnownHostsAction::List => {
            for k in core.list_known_hosts()? {
                println!("{}:{}  {}", k.host, k.port, k.fingerprint);
            }
        }
        KnownHostsAction::Trust { host, fingerprint } => {
            let (host, port) = host_port(&host)?;
            let pinned = core.trust_host(host.clone(), port, fingerprint)?;
            println!("{host}:{port} is now trusted with {pinned}");
        }
        KnownHostsAction::Forget { host } => {
            let (host, port) = host_port(&host)?;
            if core.forget_host(host.clone(), port)? {
                println!("Forgot the key of {host}:{port}; the next connection pins the key it presents.");
            } else {
                println!("No key was pinned for {host}:{port}.");
            }
        }
    }
    Ok(())
}

/// `host`, `host:port` or `[v6]:port`; the port defaults to 22.
fn host_port(spec: &str) -> Res<(String, u16)> {
    let bad = |why: &str| Failure::msg(format!("\"{spec}\" is not host or host:port{why}"));
    let (host, port) = if let Some(rest) = spec.strip_prefix('[') {
        let (host, after) = rest.split_once(']').ok_or_else(|| bad(""))?;
        (host, after.strip_prefix(':'))
    } else if spec.matches(':').count() == 1 {
        spec.split_once(':')
            .map_or((spec, None), |(h, p)| (h, Some(p)))
    } else {
        (spec, None)
    };
    let port = port
        .map_or(Ok(22), str::parse::<u16>)
        .map_err(|e| bad(&format!(" ({e})")))?;
    if host.is_empty() {
        return Err(bad(""));
    }
    Ok((host.to_owned(), port))
}

/// `unissh logout`: revokes this device on the server, then deletes its data.
///
/// `local` skips the server — for a machine that can no longer reach it, or
/// whose master password is lost; the device must then be revoked from
/// another one. A joined account that has no other device is gone for good
/// once its data here is deleted, so that is said before asking.
pub fn logout(home: &Home, credentials: &Credentials, yes: bool, local: bool) -> Res<()> {
    let link = home.link()?;
    if link.is_none() && !home.has_instance() {
        println!("This machine is not signed in.");
        return Ok(());
    }
    if local {
        confirm(
            yes,
            "This deletes UniSSH's data from this machine. The device stays registered on the\n\
             server: revoke it from another device (Settings → Devices).\n",
        )?;
        home.wipe()?;
        println!("Signed out locally.");
        return Ok(());
    }
    let device = Device::open(home.clone())?;
    device.unlock(credentials)?;
    let session = ServerSession::open(&device.core, &device.link)?;
    let mut warning = format!(
        "This revokes this device on {} and deletes UniSSH's data from this machine.\n",
        device.link.base_url
    );
    if device.link.origin == Origin::Joined && is_only_device(&device.link, &session)? {
        warning.push_str(
            "THIS IS THE ACCOUNT'S ONLY DEVICE. Without another device, its vault contents\n\
             are lost for good unless you still have its Emergency Kit and escrow is on.\n",
        );
    }
    confirm(yes, &warning)?;
    identity::device_revoke(
        http(),
        &device.link.base_url,
        session.access(),
        &device.link.device_id,
    )?;
    drop(session);
    device.core.lock();
    home.wipe()?;
    println!("Signed out: the device is revoked and its data deleted.");
    Ok(())
}

fn is_only_device(link: &Link, session: &ServerSession<'_>) -> Res<bool> {
    let devices = identity::device_list(http(), &link.base_url, session.access())?;
    Ok(!devices
        .iter()
        .any(|d| d.device_id != link.device_id && d.status == "active"))
}

/// Shows `warning` and asks to go on, unless `yes`.
fn confirm(yes: bool, warning: &str) -> Res<()> {
    if yes {
        return Ok(());
    }
    let mut tty = Tty::open()
        .map_err(|e| Failure::msg(format!("cannot ask for confirmation ({e}); pass --yes")))?;
    tty.say(warning)?;
    if tty.confirm("Continue? [y/N] ")? {
        Ok(())
    } else {
        Err(Failure::msg("nothing changed"))
    }
}

#[cfg(test)]
mod tests {
    use super::{ago, host_port};
    use std::time::{Duration, SystemTime};

    fn ago_for(age: Duration) -> String {
        ago(SystemTime::now().checked_sub(age).unwrap())
    }

    #[test]
    fn host_port_reads_names_ports_and_bracketed_v6() {
        assert_eq!(host_port("web").unwrap(), ("web".to_owned(), 22));
        assert_eq!(host_port("web:2222").unwrap(), ("web".to_owned(), 2222));
        assert_eq!(host_port("[::1]:2222").unwrap(), ("::1".to_owned(), 2222));
        assert_eq!(
            host_port("::1").unwrap(),
            ("::1".to_owned(), 22),
            "a bare v6 address"
        );
        assert!(host_port("web:ssh").is_err());
        assert!(host_port(":22").is_err());
    }

    #[test]
    fn ages_read_as_people_say_them() {
        assert_eq!(ago_for(Duration::from_secs(5)), "just now");
        assert_eq!(ago_for(Duration::from_secs(60)), "1 minute ago");
        assert_eq!(ago_for(Duration::from_secs(3 * 3600 + 10)), "3 hours ago");
    }
}
