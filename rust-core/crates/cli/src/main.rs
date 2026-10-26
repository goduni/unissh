//! `unissh` — UniSSH in a terminal.
//!
//! Signs a machine without a GUI (a server reached over plain SSH, say) in as a
//! device of a UniSSH account, keeps a synced, encrypted copy of the account's
//! vaults, and connects to their hosts: an interactive terminal, a one-off
//! command, a file copy. It is the same core as the app — the same vault
//! format, host-key pinning and verify-before-apply sync — and it never takes a
//! secret on the command line.

#![expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a CLI writes its output and errors to the terminal by design"
)]

mod connect;
mod device;
mod escape;
mod failure;
mod home;
mod hosts;
mod login;
mod manage;
mod mcp;
mod mcp_tty;
mod picker;
mod server;
mod tty;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

use crate::connect::{exit_code, Direction, Endpoint};
use crate::device::{Credentials, Device};
use crate::failure::{Failure, Res};
use crate::home::Home;
use crate::login::{Joining, SignIn};
use crate::manage::KnownHostsAction;

#[derive(Parser)]
#[command(
    name = "unissh",
    version,
    about = "UniSSH in a terminal: sign this machine in, then reach the hosts in your vaults",
    long_about = "UniSSH in a terminal: sign this machine in as a device of your UniSSH account, \
                  then reach the hosts in your vaults.\n\n\
                  Without a command, `unissh` lists the hosts to pick from.",
    after_help = "Secrets are never taken as arguments: they are asked on the terminal, or read \
                  from an owner-only file (--password-file)."
)]
struct Cli {
    /// Where this device keeps its data [default: $XDG_DATA_HOME/unissh or ~/.local/share/unissh].
    #[arg(long, global = true, env = "UNISSH_HOME", value_name = "DIR")]
    home: Option<PathBuf>,
    /// Read the master password from FILE (owner-only) instead of asking for it.
    #[arg(long, global = true, env = "UNISSH_PASSWORD_FILE", value_name = "FILE")]
    password_file: Option<PathBuf>,
    /// Do not contact the server: use the vaults as last synced.
    #[arg(long, global = true)]
    offline: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Sign this machine in.
    #[command(subcommand)]
    Login(Login),
    /// Sign this machine out: revoke it on the server and delete its data.
    Logout {
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
        /// Delete the data without contacting the server (revoke the device
        /// from another one afterwards).
        #[arg(long)]
        local: bool,
    },
    /// What this machine is signed in to.
    Status,
    /// Sync the vaults with the server now.
    Sync,
    /// List the hosts.
    Hosts {
        /// Only hosts whose label, address, vault or tags contain this.
        filter: Option<String>,
        /// Only hosts with this tag.
        #[arg(long)]
        tag: Option<String>,
        /// Print JSON (names and addresses; never a secret).
        #[arg(long)]
        json: bool,
    },
    /// Open a terminal on a host, or run a command there.
    Ssh {
        /// Do not send stdin to the command.
        #[arg(short = 'n')]
        no_stdin: bool,
        /// Host label (or vault/label, or address); `user@host` picks the user.
        host: String,
        /// Command to run instead of a terminal.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Copy one file to or from a host: `host:path` on one side.
    Cp {
        /// Replace the destination if it exists.
        #[arg(long)]
        force: bool,
        /// Source: a local path or host:path.
        source: String,
        /// Destination: a local path or host:path.
        destination: String,
    },
    /// The host keys this machine has pinned.
    #[command(subcommand, name = "known-hosts")]
    KnownHosts(KnownHosts),
    /// Serve the hosts you grant to a local AI agent over MCP (stdio; --http
    /// for loopback HTTP), and manage its integrations, grants and limits.
    Mcp(mcp::Mcp),
}

#[derive(Subcommand)]
enum Login {
    /// Pair with a signed-in UniSSH app ("Add device"): the same account.
    Pair {
        #[command(flatten)]
        options: SignInArgs,
    },
    /// The same account, with its handle, password and Secret Key (server escrow).
    Escrow {
        /// Server URL, e.g. https://unissh.example.com.
        server: String,
        /// The account's handle.
        handle: String,
        /// Do not keep the Secret Key on this machine; ask for it at every unlock.
        #[arg(long)]
        no_remember: bool,
    },
    /// A separate account for this machine, joined with an invite: it holds only
    /// what the team grants it. The invite is asked on the terminal.
    Join {
        /// Server URL, e.g. https://unissh.example.com.
        server: String,
        /// Display name for the new account.
        #[arg(long)]
        name: Option<String>,
        /// Handle for the new account.
        #[arg(long)]
        handle: Option<String>,
        #[command(flatten)]
        options: SignInArgs,
    },
}

#[derive(Args)]
struct SignInArgs {
    /// Do not keep the Secret Key on this machine; ask for it at every unlock.
    #[arg(long)]
    no_remember: bool,
    /// No master password on this machine's copy: the Secret Key alone unlocks it.
    #[arg(long)]
    no_password: bool,
}

impl SignInArgs {
    const fn choice(&self) -> SignIn {
        SignIn {
            remember: !self.no_remember,
            no_password: self.no_password,
        }
    }
}

#[derive(Subcommand)]
enum KnownHosts {
    /// List the pinned host keys.
    List,
    /// Trust a host's new key after a "host key has changed" warning
    /// (direct hosts; behind a jump host use `forget` and connect again).
    Trust {
        /// host or host:port.
        host: String,
        /// The SHA256 fingerprint the warning showed.
        fingerprint: String,
    },
    /// Forget a host's key: the next connection pins the key it presents.
    Forget {
        /// host or host:port.
        host: String,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(failure) => {
            eprintln!("unissh: {failure}");
            ExitCode::from(failure.exit)
        }
    }
}

fn run(cli: Cli) -> Res<u8> {
    let home = Home::locate(cli.home)?;
    let credentials = Credentials {
        password_file: cli.password_file,
    };
    let offline = cli.offline;
    let Some(command) = cli.command else {
        return picker::run(home, &credentials, offline);
    };
    match command {
        Command::Login(how) => {
            log_in(&home, how)?;
            Ok(0)
        }
        Command::Logout { yes, local } => {
            manage::logout(&home, &credentials, yes, local)?;
            Ok(0)
        }
        Command::Status => {
            manage::status(&home)?;
            Ok(0)
        }
        Command::Sync => {
            if offline {
                return Err(Failure::msg("`sync` and --offline contradict each other"));
            }
            let device = unlocked(home, &credentials)?;
            let report = server::sync(&device)?;
            println!("{}", server::summary(&report));
            server::warn_about(&report);
            Ok(0)
        }
        Command::Hosts { filter, tag, json } => {
            let device = ready(home, &credentials, offline)?;
            let all = hosts::load(&device.core)?;
            let shown = hosts::filter(&all, filter.as_deref(), tag.as_deref());
            if json {
                let text = serde_json::to_string_pretty(&hosts::json(&shown))
                    .map_err(|e| Failure::msg(e.to_string()))?;
                println!("{text}");
            } else if shown.is_empty() {
                eprintln!("unissh: no hosts to show");
            } else {
                print!("{}", hosts::table(&shown, false));
            }
            Ok(0)
        }
        Command::Ssh {
            no_stdin,
            host,
            command,
        } => ssh(home, &credentials, offline, &host, &command, no_stdin),
        Command::Cp {
            force,
            source,
            destination,
        } => {
            copy(home, &credentials, offline, &source, &destination, force)?;
            Ok(0)
        }
        Command::KnownHosts(action) => {
            let device = unlocked(home, &credentials)?;
            let action = match action {
                KnownHosts::List => KnownHostsAction::List,
                KnownHosts::Trust { host, fingerprint } => {
                    KnownHostsAction::Trust { host, fingerprint }
                }
                KnownHosts::Forget { host } => KnownHostsAction::Forget { host },
            };
            manage::known_hosts(&device.core, action)?;
            Ok(0)
        }
        Command::Mcp(args) => mcp::run(home, &credentials, offline, args),
    }
}

fn log_in(home: &Home, how: Login) -> Res<()> {
    match how {
        Login::Pair { options } => login::pair(home, &options.choice()),
        Login::Escrow {
            server,
            handle,
            no_remember,
        } => login::escrow(
            home,
            &server,
            &handle,
            &SignIn {
                remember: !no_remember,
                // The copy here is wrapped with the account password.
                no_password: false,
            },
        ),
        Login::Join {
            server,
            name,
            handle,
            options,
        } => login::join(
            home,
            &server,
            &Joining {
                display_name: name,
                handle,
            },
            &options.choice(),
        ),
    }
}

/// The signed-in device, unlocked.
fn unlocked(home: Home, credentials: &Credentials) -> Res<Device> {
    let device = Device::open(home)?;
    device.unlock(credentials)?;
    Ok(device)
}

/// The signed-in device, unlocked, with its vaults synced unless they are
/// fresh or the user said `--offline`.
fn ready(home: Home, credentials: &Credentials, offline: bool) -> Res<Device> {
    let device = unlocked(home, credentials)?;
    if !offline {
        server::sync_if_stale(&device);
    }
    Ok(device)
}

/// `user@host` → the user and the host; anything else is just the host.
fn split_user(spec: &str) -> (Option<&str>, &str) {
    match spec.split_once('@') {
        Some((user, host)) if !user.is_empty() && !host.is_empty() => (Some(user), host),
        Some(_) | None => (None, spec),
    }
}

fn ssh(
    home: Home,
    credentials: &Credentials,
    offline: bool,
    spec: &str,
    command: &[String],
    no_stdin: bool,
) -> Res<u8> {
    let device = ready(home, credentials, offline)?;
    let all = hosts::load(&device.core)?;
    let (user, name) = split_user(spec);
    let host = hosts::find(&all, name)?;
    let target = hosts::resolve(&device.core, host, user)?;
    if !command.is_empty() {
        let status = connect::run(&device.core, target, command.join(" "), no_stdin)?;
        return Ok(exit_code(status));
    }
    let status = connect::shell(&device.core, host, target)?;
    if host.profile.record_sessions && !offline {
        server::push_recording(&device);
    }
    Ok(exit_code(status))
}

fn copy(
    home: Home,
    credentials: &Credentials,
    offline: bool,
    source: &str,
    destination: &str,
    force: bool,
) -> Res<()> {
    let (spec, direction) = match (Endpoint::parse(source), Endpoint::parse(destination)) {
        (Endpoint::Remote { host, path }, Endpoint::Local(local)) => (
            host,
            Direction::Download {
                remote: path,
                local,
            },
        ),
        (Endpoint::Local(local), Endpoint::Remote { host, path }) => {
            if !local.is_file() {
                return Err(Failure::msg(format!(
                    "{} is not a file (one file at a time)",
                    local.display()
                )));
            }
            (
                host,
                Direction::Upload {
                    local,
                    remote: path,
                },
            )
        }
        (Endpoint::Remote { .. }, Endpoint::Remote { .. }) => {
            return Err(Failure::msg(
                "both sides are hosts: copy through this machine in two steps",
            ))
        }
        (Endpoint::Local(_), Endpoint::Local(_)) => {
            return Err(Failure::msg("one side must be a host, as host:path"))
        }
    };
    let device = ready(home, credentials, offline)?;
    let all = hosts::load(&device.core)?;
    let (user, name) = split_user(&spec);
    let host = hosts::find(&all, name)?;
    let target = hosts::resolve(&device.core, host, user)?;
    connect::copy(&device.core, target, direction, force)
}

#[cfg(test)]
mod tests {
    use super::{split_user, Cli};
    use clap::CommandFactory;

    #[test]
    fn the_command_line_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn user_at_host_splits_only_with_both_sides() {
        assert_eq!(split_user("root@web"), (Some("root"), "web"));
        assert_eq!(split_user("web"), (None, "web"));
        assert_eq!(split_user("@web"), (None, "@web"));
    }
}
