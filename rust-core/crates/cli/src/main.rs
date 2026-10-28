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
mod edit;
mod escape;
mod failure;
mod fleet;
mod home;
mod host_edit;
mod hosts;
mod login;
mod manage;
mod mcp;
mod mcp_tty;
mod picker;
mod pool;
mod recordings;
mod replay;
mod secrets;
mod server;
mod signals;
mod snippet_edit;
mod snippets;
mod system_lock;
mod tree;
mod tty;
mod tunnel;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::error::{ContextKind, ContextValue, ErrorKind};
use clap::{ArgGroup, Args, CommandFactory, Parser, Subcommand};
use unissh_ffi::snippet_params::{builtins_from_profile, resolve_command};
use unissh_ffi::Core;

use crate::connect::{exit_code, Direction, Endpoint};
use crate::device::{Credentials, Device};
use crate::failure::{Failure, Res};
use crate::home::Home;
use crate::host_edit::{GroupsAction, HostsAction};
use crate::login::{Joining, SignIn};
use crate::manage::KnownHostsAction;
use crate::replay::Timing;
use crate::secrets::{IdentitiesAction, KeysAction, SecretsAction};
use crate::snippet_edit::SnippetWrite;
use crate::tty::Tty;
use crate::tunnel::Forward;

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
    /// List the hosts, or add, change or delete one.
    #[command(args_conflicts_with_subcommands = true)]
    Hosts {
        #[command(subcommand)]
        action: Option<Box<HostsAction>>,
        /// Only hosts whose label, address, vault or tags contain this (after
        /// `--` when it is add, edit or rm: `unissh hosts -- add`).
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
    /// Copy a file, or a directory with -r, to or from a host: `host:path` on one side.
    Cp {
        /// Replace destination files that exist.
        #[arg(long)]
        force: bool,
        /// Copy a directory and everything in it; links inside are not followed.
        #[arg(short = 'r', long)]
        recursive: bool,
        /// With -r: how many files to copy at once (1 to 16).
        #[arg(long, default_value_t = tree::PARALLEL, value_parser = clap::value_parser!(u32).range(1..=16))]
        parallel: u32,
        /// Source: a local path or host:path.
        source: String,
        /// Destination: a local path or host:path.
        destination: String,
    },
    /// Forward ports through a host until Ctrl-C, as `ssh -N` does.
    #[command(group(
        ArgGroup::new("forwards")
            .args(["local", "remote", "dynamic"])
            .required(true)
            .multiple(true)
    ))]
    Tunnel {
        /// Host label (or vault/label, or address); `user@host` picks the user.
        host: String,
        /// Listen on PORT here and connect to HOST:HOSTPORT from the host
        /// (BIND defaults to 127.0.0.1).
        #[arg(short = 'L', value_name = "[BIND:]PORT:HOST:HOSTPORT", value_parser = tunnel::local)]
        local: Vec<Forward>,
        /// The host listens on PORT and sends connections to HOST:HOSTPORT
        /// from here (BIND, on the host, defaults to 127.0.0.1).
        #[arg(short = 'R', value_name = "[BIND:]PORT:HOST:HOSTPORT", value_parser = tunnel::remote)]
        remote: Vec<Forward>,
        /// A SOCKS5 proxy on PORT here, connecting from the host (BIND must be
        /// loopback; defaults to 127.0.0.1).
        #[arg(short = 'D', value_name = "[BIND:]PORT", value_parser = tunnel::dynamic)]
        dynamic: Vec<Forward>,
    },
    /// The host keys this machine has pinned.
    #[command(subcommand, name = "known-hosts")]
    KnownHosts(KnownHosts),
    /// Host groups: list, add, change or delete them.
    #[command(subcommand)]
    Groups(GroupsAction),
    /// Keys, passwords, notes and identities in the vaults; a secret is shown
    /// only with `show --reveal`.
    #[command(subcommand)]
    Secrets(SecretsAction),
    /// SSH keys: generate, import, print the public key, rotate.
    #[command(subcommand)]
    Keys(KeysAction),
    /// Personal identities: a user name and the key or password it logs in
    /// with, for hosts that log in personally.
    #[command(subcommand)]
    Identities(IdentitiesAction),
    /// Recorded sessions: list, replay, export, delete.
    #[command(subcommand)]
    Recordings(Recordings),
    /// Run a command on several hosts at once, as the app's Fleet does.
    /// `{{name}}` in it is filled as in a snippet; `\{{` is a literal `{{`.
    Run {
        #[command(flatten)]
        hosts: HostSelection,
        #[command(flatten)]
        options: RunArgs,
        /// The command to run, after `--`.
        #[arg(last = true, required = true, value_name = "COMMAND")]
        command: Vec<String>,
    },
    /// The vaults' snippets: list, run, add, edit, delete.
    #[command(subcommand)]
    Snippets(Snippets),
    /// Serve the hosts you grant to a local AI agent over MCP (stdio; --http
    /// for loopback HTTP), and manage its integrations, grants and limits.
    Mcp(mcp::Mcp),
}

/// `unissh snippets`.
#[derive(Subcommand)]
enum Snippets {
    /// List the snippets.
    List {
        /// Print JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run a snippet on hosts, as `unissh run` runs a command. Parameters
    /// without a --set are asked on the terminal, where Enter takes the default.
    Run {
        /// Snippet label (or vault/label).
        snippet: String,
        #[command(flatten)]
        hosts: HostSelection,
        #[command(flatten)]
        options: RunArgs,
    },
    #[command(flatten)]
    Write(SnippetWrite),
}

/// Which hosts a run goes to: one way of naming them.
#[derive(Args)]
#[group(required = true, multiple = false)]
struct HostSelection {
    /// The hosts with this tag; repeat for hosts with every one of them.
    #[arg(long, value_name = "TAG")]
    tag: Vec<String>,
    /// The hosts of this group (label or vault/label), and of groups listed as
    /// its members; not those of its subgroups (groups whose parent it is).
    #[arg(long, value_name = "GROUP")]
    group: Option<String>,
    /// Hosts by label (or vault/label, or address).
    #[arg(value_name = "HOST")]
    hosts: Vec<String>,
}

impl HostSelection {
    fn selection(self) -> fleet::Selection {
        if let Some(group) = self.group {
            fleet::Selection::Group(group)
        } else if self.tag.is_empty() {
            fleet::Selection::Hosts(self.hosts)
        } else {
            fleet::Selection::Tags(self.tag)
        }
    }
}

#[derive(Args)]
struct RunArgs {
    /// Show which hosts would run what, without connecting.
    #[arg(long)]
    dry_run: bool,
    /// How many hosts run at once.
    #[arg(long, value_name = "N", default_value_t = fleet::DEFAULT_PARALLEL,
          value_parser = clap::value_parser!(u32).range(1..))]
    parallel: u32,
    /// Seconds for the command to finish on each host (the connect is not
    /// counted); 0 for no limit.
    #[arg(long, value_name = "SECS", default_value_t = fleet::DEFAULT_TIMEOUT_SECS)]
    timeout: u32,
    /// A parameter's value (`{{NAME}}` in the command); repeat for several.
    /// `--set NAME=` gives it an empty value, not its default.
    #[arg(long = "set", value_name = "NAME=VALUE", value_parser = snippets::parse_set)]
    set: Vec<(String, String)>,
    /// Print JSON: per host, the command, its output and exit status.
    #[arg(long)]
    json: bool,
}

impl RunArgs {
    const fn options(&self) -> fleet::Options {
        fleet::Options {
            parallel: self.parallel,
            timeout_secs: self.timeout,
            dry_run: self.dry_run,
            json: self.json,
        }
    }
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

#[derive(Subcommand)]
enum Recordings {
    /// List the recordings, newest first.
    List {
        /// Only recordings whose label, host or vault contain this.
        filter: Option<String>,
        /// Print JSON (what was recorded is not in it).
        #[arg(long)]
        json: bool,
    },
    /// Replay a recording in this terminal; Ctrl-C stops it.
    Play {
        /// The recording's id, or a part of it only that id contains.
        id: String,
        /// Play this many times as fast.
        #[arg(long, default_value_t = 1.0, value_parser = replay::positive)]
        speed: f64,
        /// Cut every pause longer than this many seconds to that.
        #[arg(long, value_name = "SECONDS", value_parser = replay::positive)]
        idle_limit: Option<f64>,
    },
    /// Save a recording as an asciicast v2 file, as `asciinema` plays it.
    Export {
        /// The recording's id, or a part of it only that id contains.
        id: String,
        /// Where to write it; `-` is stdout.
        file: PathBuf,
        /// Replace the file if it exists.
        #[arg(long)]
        force: bool,
    },
    /// Delete a recording, here and, once synced, everywhere.
    Rm {
        /// The recording's id, or a part of it only that id contains.
        id: String,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::try_parse().unwrap_or_else(|e| plain_usage(e, std::env::args_os()).exit());
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(failure) => {
            eprintln!("unissh: {failure}");
            ExitCode::from(failure.exit)
        }
    }
}

/// A missing-argument error with the command's own usage line. clap's echoes
/// every option that was given, on the command line or from the environment,
/// so `--home` and `--password-file` (from `UNISSH_HOME`, say) read as if the
/// command required them.
fn plain_usage(mut err: clap::Error, args: impl IntoIterator<Item = OsString>) -> clap::Error {
    if err.kind() != ErrorKind::MissingRequiredArgument {
        return err;
    }
    let Ok(matches) = Cli::command()
        .ignore_errors(true)
        .try_get_matches_from(args)
    else {
        return err;
    };
    let mut path = Vec::new();
    let mut at = &matches;
    while let Some((name, sub)) = at.subcommand() {
        path.push(name.to_owned());
        at = sub;
    }
    let mut root = Cli::command();
    root.build();
    let mut command = &mut root;
    for name in &path {
        match command.find_subcommand_mut(name) {
            Some(sub) => command = sub,
            None => return err,
        }
    }
    err.insert(
        ContextKind::Usage,
        ContextValue::StyledStr(command.render_usage()),
    );
    err
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
        Command::Hosts {
            action: Some(action),
            ..
        } => edit(home, &credentials, offline, |d| {
            host_edit::hosts(d, offline, *action)
        }),
        Command::Hosts {
            action: None,
            filter,
            tag,
            json,
        } => {
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
            recursive,
            parallel,
            source,
            destination,
        } => {
            let how = CopyHow {
                force,
                recursive,
                parallel,
            };
            copy(home, &credentials, offline, &source, &destination, how)?;
            Ok(0)
        }
        Command::Tunnel {
            host,
            local,
            remote,
            dynamic,
        } => {
            // Grouped by kind, as clap collects them: -L, then -R, then -D.
            let forwards: Vec<Forward> = local.into_iter().chain(remote).chain(dynamic).collect();
            let named = named_host(home, &credentials, offline, &host)?;
            tunnel::run(
                &named.device.core,
                named.target,
                &named.host.profile.label,
                &forwards,
            )
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
        Command::Groups(action) => edit(home, &credentials, offline, |d| {
            host_edit::groups(d, offline, action)
        }),
        Command::Secrets(action) => edit(home, &credentials, offline, |d| {
            secrets::secrets(d, offline, action)
        }),
        Command::Keys(action) => edit(home, &credentials, offline, |d| {
            secrets::keys(d, offline, action)
        }),
        Command::Identities(action) => edit(home, &credentials, offline, |d| {
            secrets::identities(d, offline, action)
        }),
        Command::Recordings(what) => recording(home, &credentials, offline, what),
        Command::Run {
            hosts: selection,
            options,
            command,
        } => {
            let device = ready(home, &credentials, offline)?;
            fleet_run(
                &device.core,
                &selection.selection(),
                &command.join(" "),
                &options,
            )
        }
        Command::Snippets(action) => snippet(home, &credentials, offline, action),
        Command::Mcp(args) => mcp::run(home, &credentials, offline, args),
    }
}

/// A command that writes to the vaults: `write` runs on the unlocked device.
fn edit(
    home: Home,
    credentials: &Credentials,
    offline: bool,
    write: impl FnOnce(&Device) -> Res<()>,
) -> Res<u8> {
    let device = ready(home, credentials, offline)?;
    write(&device)?;
    Ok(0)
}

/// `unissh recordings`.
fn recording(home: Home, credentials: &Credentials, offline: bool, what: Recordings) -> Res<u8> {
    let device = ready(home, credentials, offline)?;
    match what {
        Recordings::List { filter, json } => {
            recordings::list(&device, filter.as_deref(), json)?;
        }
        Recordings::Play {
            id,
            speed,
            idle_limit,
        } => return recordings::play(&device, &id, Timing { speed, idle_limit }),
        Recordings::Export { id, file, force } => {
            recordings::export(&device, &id, &file, force)?;
        }
        Recordings::Rm { id, yes } => recordings::remove(&device, &id, yes, offline)?,
    }
    Ok(0)
}

fn snippet(home: Home, credentials: &Credentials, offline: bool, action: Snippets) -> Res<u8> {
    let device = ready(home, credentials, offline)?;
    match action {
        Snippets::List { json } => {
            let saved = snippets::load(&device.core)?;
            if json {
                let text = serde_json::to_string_pretty(&snippets::json(&saved))
                    .map_err(|e| Failure::msg(e.to_string()))?;
                println!("{text}");
            } else if saved.is_empty() {
                eprintln!("unissh: no snippets to show");
            } else {
                print!("{}", snippets::table(&saved));
            }
            Ok(0)
        }
        Snippets::Run {
            snippet,
            hosts: selection,
            options,
        } => {
            let saved = snippets::load(&device.core)?;
            let command = &hosts::find_named(&saved, &snippet)?.snippet.command;
            fleet_run(&device.core, &selection.selection(), command, &options)
        }
        Snippets::Write(action) => {
            snippet_edit::run(&device, offline, action)?;
            Ok(0)
        }
    }
}

/// Runs `template` on the hosts `selection` picks, as Fleet runs a command:
/// the hosts resolve first; the parameters the hosts that will run cannot
/// answer come from `--set` or are asked once; each host then runs the
/// command filled with those and its own built-ins.
fn fleet_run(
    core: &Core,
    selection: &fleet::Selection,
    template: &str,
    options: &RunArgs,
) -> Res<u8> {
    let all = hosts::load(core)?;
    let picked = fleet::select(core, &all, selection)?;
    let plan = fleet::plan(core, &picked)?;
    let values = if plan.nothing_runs() {
        BTreeMap::new()
    } else {
        let split = plan.params(template);
        // Opened only when a value has to be asked.
        let mut tty: Option<Option<Tty>> = None;
        snippets::answers(&split.ask, &split.from_host, &options.set, &mut |param| {
            let tty = tty.get_or_insert_with(|| Tty::open().ok());
            snippets::ask_on_tty(tty.as_mut(), param)
        })?
    };
    fleet::run(
        core,
        plan,
        &|h| resolve_command(template, &values, &builtins_from_profile(&h.profile)),
        &options.options(),
    )
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

/// A host named on the command line, ready to connect to.
struct NamedHost {
    /// The device, unlocked (and synced unless fresh or `--offline`).
    device: Device,
    /// The host the name matched; its label is `host.profile.label`.
    host: hosts::Host,
    /// How to connect to it, with the user `user@host` named, if any.
    target: hosts::Target,
}

/// Unlocks the device and finds and resolves the host `spec` names (a label,
/// `vault/label`, a prefix or an address; `user@host` picks the user), as
/// `unissh ssh` names hosts.
fn named_host(home: Home, credentials: &Credentials, offline: bool, spec: &str) -> Res<NamedHost> {
    let device = ready(home, credentials, offline)?;
    let all = hosts::load(&device.core)?;
    let (user, name) = split_user(spec);
    let host = hosts::find(&all, name)?.clone();
    let target = hosts::resolve(&device.core, &host, user)?;
    Ok(NamedHost {
        device,
        host,
        target,
    })
}

fn ssh(
    home: Home,
    credentials: &Credentials,
    offline: bool,
    spec: &str,
    command: &[String],
    no_stdin: bool,
) -> Res<u8> {
    let NamedHost {
        device,
        host,
        target,
    } = named_host(home, credentials, offline, spec)?;
    if !command.is_empty() {
        let status = connect::run(&device.core, target, command.join(" "), no_stdin)?;
        return Ok(exit_code(status));
    }
    let status = connect::shell(&device.core, &host, target)?;
    if host.profile.record_sessions && !offline {
        server::push_recording(&device);
    }
    Ok(exit_code(status))
}

/// The options of `unissh cp`.
struct CopyHow {
    force: bool,
    recursive: bool,
    parallel: u32,
}

fn copy(
    home: Home,
    credentials: &Credentials,
    offline: bool,
    source: &str,
    destination: &str,
    how: CopyHow,
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
            if local.is_dir() {
                if !how.recursive {
                    return Err(Failure::msg(format!(
                        "{} is a directory; pass -r to copy it",
                        local.display()
                    )));
                }
            } else if !local.is_file() {
                return Err(Failure::msg(format!(
                    "{} is not a file or a directory",
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
    let named = named_host(home, credentials, offline, &spec)?;
    connect::copy(
        &named.device.core,
        named.target,
        direction,
        how.force,
        how.recursive,
        how.parallel,
    )
}

#[cfg(test)]
mod tests {
    use super::{plain_usage, split_user, Cli};
    use clap::{CommandFactory, Parser};
    use std::ffi::OsString;

    #[test]
    fn the_command_line_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn a_tunnel_needs_at_least_one_forward() {
        let Err(err) = Cli::try_parse_from(["unissh", "tunnel", "web"]) else {
            panic!("a tunnel without -L, -R or -D must be refused");
        };
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    /// The usage line of a missing-argument error is the command's own: the
    /// global options given do not appear in it as if they were required.
    #[test]
    fn a_missing_argument_shows_the_plain_usage() {
        let args = [
            "unissh",
            "--home",
            "/h",
            "--password-file",
            "/p",
            "tunnel",
            "web",
        ];
        let Err(err) = Cli::try_parse_from(args) else {
            panic!("a tunnel without -L, -R or -D must be refused");
        };
        let text = plain_usage(err, args.map(OsString::from))
            .render()
            .to_string();
        let usage = text
            .lines()
            .find(|line| line.starts_with("Usage:"))
            .unwrap_or_default();
        assert!(usage.starts_with("Usage: unissh tunnel "), "{text}");
        assert!(!usage.contains("--home"), "{usage}");
        assert!(!usage.contains("--password-file"), "{usage}");
    }

    #[test]
    fn user_at_host_splits_only_with_both_sides() {
        assert_eq!(split_user("root@web"), (Some("root"), "web"));
        assert_eq!(split_user("web"), (None, "web"));
        assert_eq!(split_user("@web"), (None, "@web"));
    }
}
