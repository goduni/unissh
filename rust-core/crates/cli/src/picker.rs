//! `unissh` with no command: unlock once, then pick hosts from a list until
//! done, coming back to the list after each session.
//!
//! Left alone at the list for [`IDLE_LOCK`], the instance locks: the keys
//! leave memory, and the next pick asks for the master password again.

use std::io::{self, ErrorKind, IsTerminal};
use std::time::Duration;

use crate::connect;
use crate::device::{Credentials, Device};
use crate::failure::{Failure, Res};
use crate::home::Home;
use crate::hosts::{self, Host};
use crate::server;
use crate::tty::{one_line, Tty};

/// How long the list may sit unanswered before the instance locks.
pub const IDLE_LOCK: Duration = Duration::from_secs(15 * 60);

const HINT: &str =
    "Number or name to connect · text to filter · Enter to clear · s to sync · q to quit\n";

/// Runs the picker.
pub fn run(home: Home, credentials: &Credentials, offline: bool) -> Res<u8> {
    if !io::stdin().is_terminal() {
        return Err(Failure::msg(
            "no command given, and stdin is not a terminal for picking a host (`unissh --help`)",
        ));
    }
    let device = Device::open(home)?;
    device.unlock(credentials)?;
    if !offline {
        server::sync_if_stale(&device);
    }
    let mut tty = Tty::open()?;
    let mut filter: Option<String> = None;
    loop {
        let all = hosts::load(&device.core)?;
        let shown = hosts::filter(&all, filter.as_deref(), None);
        if let (true, Some(text)) = (shown.is_empty(), &filter) {
            tty.say(&format!("Nothing matches \"{}\".\n", one_line(text)))?;
        } else if shown.is_empty() {
            tty.say("No hosts here yet — add them in the UniSSH app, then sync.\n")?;
        } else {
            tty.say(&hosts::table(&shown, true))?;
        }
        tty.say(HINT)?;
        let Some(answer) = ask(&mut tty, &device, credentials)? else {
            return Ok(0);
        };
        match answer.trim() {
            "q" | "quit" | "exit" => return Ok(0),
            "" => filter = None,
            "s" | "sync" if offline => tty.say("Not syncing: --offline.\n")?,
            "s" | "sync" => match server::sync(&device) {
                Ok(report) => {
                    tty.say(&format!("{}\n", server::summary(&report)))?;
                    server::warn_about(&report);
                }
                Err(e) => eprintln!("unissh: {e}"),
            },
            text => {
                let chosen = pick(&shown, &all, text);
                match chosen {
                    Some(host) => {
                        if let Err(e) = session(&device, host, offline) {
                            eprintln!("unissh: {e}");
                        }
                    }
                    None => filter = Some(text.to_owned()),
                }
            }
        }
    }
}

/// The host an answer picks: a number from the list shown, a host name, or
/// the one host a filter leaves. `None` means "filter by it".
fn pick<'h>(shown: &[&'h Host], all: &'h [Host], answer: &str) -> Option<&'h Host> {
    if let Ok(number) = answer.parse::<usize>() {
        return number.checked_sub(1).and_then(|i| shown.get(i)).copied();
    }
    if let Ok(host) = hosts::find(all, answer) {
        return Some(host);
    }
    match hosts::filter(all, Some(answer), None).as_slice() {
        [one] => Some(*one),
        _ => None,
    }
}

/// Waits for an answer, locking the instance if none comes for [`IDLE_LOCK`].
/// `None` when the user ends input (Ctrl-D).
fn ask(tty: &mut Tty, device: &Device, credentials: &Credentials) -> Res<Option<String>> {
    tty.say("> ")?;
    if !tty.wait(IDLE_LOCK)? {
        device.core.lock();
        tty.say("\nLocked after 15 minutes without input.\n")?;
        unlock_again(device, credentials)?;
        tty.say("> ")?;
    }
    match tty.line("") {
        Ok(line) => Ok(Some(line)),
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Unlocks after an idle lock, allowing a mistyped password or two.
fn unlock_again(device: &Device, credentials: &Credentials) -> Res<()> {
    const TRIES: u32 = 3;
    let mut tried = 0;
    loop {
        tried += 1;
        match device.unlock(credentials) {
            Ok(()) => return Ok(()),
            Err(e) if tried < TRIES => eprintln!("unissh: {e}"),
            Err(e) => return Err(e),
        }
    }
}

/// One session from the picker; a recording it made goes to the server after.
fn session(device: &Device, host: &Host, offline: bool) -> Res<()> {
    let target = hosts::resolve(&device.core, host, None)?;
    connect::shell(&device.core, host, target)?;
    if host.profile.record_sessions && !offline {
        server::push_recording(device);
    }
    Ok(())
}
