//! `unissh mcp`: the desktop app's MCP server, in a terminal.
//!
//! The same tools, the same broker (`unissh-automation`) and the same transport
//! (`unissh-mcp`) as the desktop, over this device's core. What the desktop's MCP
//! screen does natively — integrations, the hosts each may reach and how its
//! commands are approved, the application-wide limits — are subcommands here,
//! stored in this device's data directory in the desktop's own formats. Nothing
//! an agent sends can grant, approve or widen anything, and the commands that
//! widen access show what they will do and then want the master password typed,
//! as its confirmation, in the foreground of a terminal ([`unlock_confirmed`]).
//!
//! What this cannot do: an agent with a shell as the same OS user, on a device
//! that unlocks without a typed password (a password file), has whatever the
//! vaults hold, whatever the grants say. Grants and approvals constrain what an
//! agent does through MCP, not what it can do as you.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Args, Subcommand};
use serde_json::{json, Value};
use unissh_automation::{
    core::{CoreExecutor, PromptFactory},
    load_limits, save_limits, ApprovalMode, Broker, BrokerLimits, Cancel, GrantLimits, TargetInfo,
};
use unissh_ffi::{AuthPromptRequest, AuthPrompter};
use unissh_mcp::contract::ToolError;
use unissh_mcp::credentials::{Credentials as Integrations, Integration};
use unissh_mcp::{serve_stdio, Backend, CancellationToken, IntegrationId, LocalServer};

use crate::connect::RECORDING_GRACE_MS;
use crate::device::{Credentials, Device};
use crate::failure::{best_effort, Failure, Res};
use crate::home::Home;
use crate::hosts::{find_named, Named};
use crate::mcp_tty::{self, Prompts, Terminal};
use crate::tty::{confirm, one_line, stdin_is_foreground, Tty};
use crate::{hosts, server, signals, system_lock};

// `unissh mcp`: serve, or manage what it serves. (Plain comments on clap
// structs here: a doc comment would replace the subcommand's own help.) The
// serving flags are refused next to a subcommand by hand, not by clap's
// `args_conflicts_with_subcommands`, which would also refuse the global flags
// (`--offline`, `--home`) there.
#[derive(Args)]
pub struct Mcp {
    #[command(subcommand)]
    action: Option<Action>,
    #[command(flatten)]
    serve: Serve,
}

// How to serve.
#[derive(Args)]
struct Serve {
    /// The integration this stdio server acts for (label or id); the only one
    /// when omitted.
    #[arg(long, value_name = "NAME", conflicts_with = "http")]
    integration: Option<String>,
    /// Serve loopback HTTP, where each integration's bearer token identifies it,
    /// instead of stdio.
    #[arg(long)]
    http: bool,
    /// HTTP port [default: the last one used, or a free one the first time].
    #[arg(long, requires = "http")]
    port: Option<u16>,
    /// Also log grants and authorized commands (by id) to stderr.
    #[arg(long, short)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Action {
    /// The applications that may connect: each has a name and a token.
    #[command(subcommand)]
    Integrations(IntegrationsAction),
    /// Which hosts each integration may reach, and how its commands are approved.
    #[command(subcommand)]
    Grants(GrantsAction),
    /// Show or change the limits shared by every integration.
    Limits(LimitArgs),
}

#[derive(Subcommand)]
enum IntegrationsAction {
    /// List them.
    List {
        /// Print JSON.
        #[arg(long)]
        json: bool,
    },
    /// Add one; prints its token (for --http) once. Asks for the master
    /// password on the terminal.
    Add {
        /// A name you will recognise, e.g. "Claude Code".
        label: String,
    },
    /// Give one a new token; its access is revoked and has to be granted again.
    /// Shows what changes, then asks for the master password on the terminal.
    Rotate {
        /// Label or id.
        integration: String,
    },
    /// Remove one, with its access.
    Rm {
        /// Label or id.
        integration: String,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum GrantsAction {
    /// List the saved grants.
    List {
        /// Print JSON (names and addresses; never a secret).
        #[arg(long)]
        json: bool,
    },
    /// Grant an integration access to hosts, replacing what it had: its open
    /// sessions and commands end. Asks for the master password on the terminal.
    Set(GrantArgs),
    /// Revoke an integration's access (or everyone's), ending its sessions.
    Rm {
        /// Label or id.
        #[arg(required_unless_present = "all", conflicts_with = "all")]
        integration: Option<String>,
        /// Revoke every integration's access.
        #[arg(long)]
        all: bool,
    },
}

#[derive(Args)]
struct GrantArgs {
    /// The integration (label or id).
    integration: String,
    /// Hosts, named as for `unissh ssh`.
    #[arg(required = true)]
    hosts: Vec<String>,
    /// Access ends after this long: 30m, 8h, 7d [default: no expiry].
    #[arg(long = "for", value_name = "DURATION", value_parser = grant_seconds)]
    expires: Option<u32>,
    /// Run commands without asking (default: confirm each one on the terminal
    /// of `unissh mcp --http`; over stdio they are refused). The agent then acts
    /// with the SSH user's authority.
    #[arg(long)]
    trusted: bool,
    /// Longest a command may run: 1m to 24h.
    #[arg(long, value_name = "DURATION", default_value = "10m", value_parser = command_ceiling_ms)]
    command_limit: u32,
    /// SSH connections at once, sessions and one-off commands together (1–64).
    #[arg(long, value_name = "N")]
    max_connections: Option<u32>,
    /// Commands waiting, queued or running at once (1–256).
    #[arg(long, value_name = "N")]
    max_active_commands: Option<u32>,
    /// Command records kept for status and output (up to 10000).
    #[arg(long, value_name = "N")]
    command_history: Option<u32>,
    /// Session records kept (up to 1000).
    #[arg(long, value_name = "N")]
    session_history: Option<u32>,
    /// Output kept per command, in MiB (1–64).
    #[arg(long, value_name = "MIB")]
    output_per_command: Option<u32>,
}

#[derive(Args)]
struct LimitArgs {
    /// SSH connections at once, across integrations (1–256).
    #[arg(long, value_name = "N")]
    max_connections: Option<u32>,
    /// Command records kept, across integrations (16–100000).
    #[arg(long, value_name = "N")]
    command_history: Option<u32>,
    /// Output kept in total, in MiB (1–1024).
    #[arg(long, value_name = "MIB")]
    output_total: Option<u64>,
}

const NO_INTEGRATION: &str = "no MCP integration yet. Add one, then grant it hosts:\n  \
     unissh mcp integrations add \"Claude Code\"\n  \
     unissh mcp grants set \"Claude Code\" <host>...";

/// Serving with nobody to ask needs an unlock that asks nothing.
const UNATTENDED_UNLOCK: &str = "unissh mcp asks nothing on a terminal here (over stdio the \
     terminal belongs to the client that started it), so the vaults must open without a typed \
     password: pass --password-file FILE (or set UNISSH_PASSWORD_FILE), or use a copy without a \
     master password. Whatever can read that file can open the vaults, an agent with a shell as \
     you included. To be asked instead, run `unissh mcp --http` in a terminal of your own";

/// Widening access with nobody at a terminal.
const WIDENING_NEEDS_A_TERMINAL: &str = "this widens what an agent may do, so it asks for the \
     master password on a terminal (a password file does not count), and it runs only in the \
     foreground of a terminal of its own: not with its input piped, not in the background. \
     Run it in a terminal";

const MIB: u32 = 1024 * 1024;

impl Serve {
    /// Whether any serving flag was given.
    const fn given(&self) -> bool {
        self.integration.is_some() || self.http || self.port.is_some() || self.verbose
    }
}

/// Runs `unissh mcp ...`.
pub fn run(home: Home, credentials: &Credentials, offline: bool, mcp: Mcp) -> Res<u8> {
    if mcp.action.is_some() && mcp.serve.given() {
        return Err(Failure::msg(
            "--integration, --http, --port and --verbose are for serving (`unissh mcp` without \
             a subcommand)",
        ));
    }
    match mcp.action {
        None => serve(home, credentials, offline, &mcp.serve),
        Some(Action::Integrations(action)) => {
            integrations(home, credentials, action)?;
            Ok(0)
        }
        Some(Action::Grants(action)) => {
            grants(home, credentials, offline, action)?;
            Ok(0)
        }
        Some(Action::Limits(args)) => {
            limits(&Device::open(home)?.home, &args)?;
            Ok(0)
        }
    }
}

fn serve(home: Home, credentials: &Credentials, offline: bool, args: &Serve) -> Res<u8> {
    let attended = mcp_tty::attended(args.http);
    let device = if attended {
        crate::ready(home, credentials, offline)?
    } else {
        unattended(home, credentials, offline)?
    };
    mcp_tty::log_to_stderr(args.verbose);
    let store = Arc::new(open_integrations(&device.home)?);
    let identity = if args.http {
        if store.list().is_empty() {
            return Err(Failure::msg(NO_INTEGRATION));
        }
        None
    } else {
        Some(find_integration(
            &store.list(),
            args.integration.as_deref(),
        )?)
    };
    let terminal = Arc::new(Terminal::default());
    let prompts: Arc<dyn PromptFactory> = if attended {
        Arc::new(Prompts(terminal.clone()))
    } else {
        Arc::new(NoPrompts)
    };
    let broker = broker(&device, prompts);
    if let Some(limits) = load_limits(&device.home.mcp_limits()) {
        if broker.set_limits(limits).is_err() {
            eprintln!("unissh mcp: the saved limits are out of range; using the defaults");
        }
    }
    broker.set_manual_approval_available(attended);
    if !attended {
        eprintln!(
            "unissh mcp: nobody is asked anything here, so only grants made with --trusted \
             run; other commands, and hosts that ask for a password or a code, are refused \
             (approval_unavailable)"
        );
    }
    let stop = Arc::new(AtomicBool::new(false));
    let approver = attended.then(|| {
        let (broker, terminal, stop) = (broker.clone(), terminal.clone(), stop.clone());
        std::thread::spawn(move || mcp_tty::approve_until_stopped(&broker, &terminal, &stop))
    });
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let served = runtime.block_on(transport(
        &broker,
        &store,
        identity.map(|i| (i.id, i.label)),
        args.port,
    ));
    // Revoked first, so nothing runs while the rest shuts down.
    broker.suspend();
    stop.store(true, Ordering::SeqCst);
    // A read of stdin may still be blocked in the runtime's pool: do not wait for it.
    runtime.shutdown_background();
    if let Some(approver) = approver {
        best_effort(approver.join());
    }
    if !device.core.wait_for_recordings(RECORDING_GRACE_MS) {
        eprintln!(
            "unissh mcp: a command recording is still being written; it is kept as interrupted"
        );
    }
    // Asked of the broker, not of its review: the suspend above dropped the runs.
    if broker.made_recordings() && !offline {
        server::push_recording(&device);
    }
    device.core.lock();
    served.map(|()| 0)
}

/// Serves until the client goes (stdio: stdin closes), the listener fails, or
/// a signal; on a signal, access is revoked before the transport stops.
async fn transport(
    broker: &Arc<Broker>,
    store: &Arc<Integrations>,
    identity: Option<(String, String)>,
    port: Option<u16>,
) -> Res<()> {
    let cancel = CancellationToken::new();
    let backend: Arc<dyn Backend> = broker.clone();
    let served = async {
        if let Some((id, label)) = identity {
            eprintln!(
                "unissh mcp: serving \"{}\" on stdin/stdout",
                one_line(&label)
            );
            return serve_stdio(IntegrationId(id), backend, cancel.clone())
                .await
                .map_err(Failure::from);
        }
        let port = port.unwrap_or_else(|| store.settings().1);
        let server = LocalServer::bind(port, store.clone(), backend)
            .await
            .map_err(|e| Failure::msg(format!("cannot listen on 127.0.0.1:{port}: {e}")))?;
        let port = server.local_addr()?.port();
        // Remembered, so that client configurations keep working next time.
        if let Err(e) = store.set_enabled(false, port) {
            eprintln!("unissh mcp: cannot remember the port: {e}");
        }
        eprintln!(
            "unissh mcp: serving http://127.0.0.1:{port}/mcp \
             (clients send \"Authorization: Bearer <token>\")"
        );
        server.serve(cancel.clone()).await.map_err(Failure::from)
    };
    tokio::pin!(served);
    // The lock watcher runs in this task, so it is gone (and cannot resume
    // anything) once the select ends, before the caller's final suspend.
    let ended = tokio::select! {
        result = &mut served => Some(result),
        // Ctrl-C, SIGTERM or SIGHUP (Ctrl-C alone off Unix). Handlers that
        // cannot be installed end the server: it would not stop cleanly.
        caught = signals::first(signals::STOP_OR_HANG_UP) => match caught {
            Ok(_) => None,
            Err(e) => Some(Err(Failure::msg(format!(
                "cannot catch Ctrl-C, SIGTERM or SIGHUP: {e}"
            )))),
        },
        () = system_lock::pause_on_lock(broker) => None,
    };
    if let Some(result) = ended {
        return result;
    }
    broker.suspend();
    cancel.cancel();
    best_effort(tokio::time::timeout(Duration::from_secs(2), served).await);
    Ok(())
}

/// The vaults, unlocked for a server nobody attends: with a password file or no
/// master password, and a remembered Secret Key. Nothing is asked on a terminal,
/// not even a server's second factor (the sync then fails and says so).
fn unattended(home: Home, credentials: &Credentials, offline: bool) -> Res<Device> {
    let device = Device::open(home)?;
    device.core.set_auth_prompter(None);
    let needs_password = device.core.instance_requires_password().ok_or_else(|| {
        Failure::msg(format!(
            "cannot read {} — the UniSSH data here is damaged",
            device.home.keyset().display()
        ))
    })?;
    if needs_password && credentials.password_file.is_none() {
        return Err(Failure::msg(UNATTENDED_UNLOCK));
    }
    if device.home.secret_key()?.is_none() {
        return Err(Failure::msg(
            "this machine does not keep the Secret Key, and unissh mcp asks nothing on a \
             terminal here. Run `unissh mcp --http` in a terminal of your own",
        ));
    }
    device.unlock(credentials)?;
    if !offline {
        server::sync_if_stale(&device);
    }
    Ok(device)
}

/// This device, still locked, for a command that widens what an agent may do.
/// It runs only in the foreground of a terminal of its own (stdin is the
/// controlling terminal, as for attended serving): a child process with its
/// input piped, or one sent to the background, is refused.
fn widening(home: Home) -> Res<Device> {
    if !stdin_is_foreground() || Tty::open().is_err() {
        return Err(Failure::msg(WIDENING_NEEDS_A_TERMINAL));
    }
    Device::open(home)
}

/// Unlocks `device` for a widening command. With a master password, `summary`
/// (everything the command will do) is shown first and typing the password
/// confirms it; a password file does not count (an agent that can read it
/// could run the command too). Returns `true` then. A copy without a master
/// password has nothing to type: it unlocks, returns `false`, and the caller
/// confirms on the terminal. An agent that controls a terminal of its own and
/// knows the password gets past this: see the module docs.
fn unlock_confirmed(device: &Device, summary: &str) -> Res<bool> {
    let typed = device.core.instance_requires_password() == Some(true);
    if typed {
        let mut tty =
            Tty::open().map_err(|_no_terminal| Failure::msg(WIDENING_NEEDS_A_TERMINAL))?;
        tty.say(summary)?;
        tty.say(
            "This widens what an agent may do. Type the master password to confirm it \
             (Ctrl-C changes nothing).\n",
        )?;
    }
    device.unlock(&Credentials {
        password_file: None,
    })?;
    Ok(typed)
}

/// The broker over this device's core, as the desktop builds it.
fn broker(device: &Device, prompts: Arc<dyn PromptFactory>) -> Arc<Broker> {
    Broker::new(Arc::new(CoreExecutor {
        core: device.core.clone(),
        prompts,
    }))
}

/// Nobody to answer a host's sign-in prompts: a server nobody attends (its
/// connections that ask fail with `approval_unavailable`), and management,
/// which never connects anywhere.
struct NoPrompts;

impl PromptFactory for NoPrompts {
    fn for_connection(&self, _: &str, _: Cancel, _: Instant) -> Arc<dyn AuthPrompter> {
        Arc::new(Self)
    }

    fn can_ask(&self) -> bool {
        false
    }
}

impl AuthPrompter for NoPrompts {
    fn prompt(&self, _: AuthPromptRequest) -> Option<Vec<String>> {
        eprintln!(
            "unissh mcp: a host asked for a password or a code; nobody can answer here, so \
             that connection fails"
        );
        None
    }
}

fn open_integrations(home: &Home) -> Res<Integrations> {
    let path = home.mcp_config();
    Integrations::load(path.clone()).map_err(|e| Failure::msg(format!("{}: {e}", path.display())))
}

/// An integration is named as a vault item is ([`find_named`]): its
/// label in any case, or the one label a name begins. It lives outside the
/// vaults, so several that share a label are told apart by their ids.
impl Named for Integration {
    const KIND: &'static str = "MCP integration";
    const KINDS: &'static str = "MCP integrations";
    const LISTED_BY: Option<&'static str> = Some("unissh mcp integrations list");
    const NAME_ONE: &'static str = "name one by its id";

    fn vault_name(&self) -> &str {
        ""
    }

    fn label(&self) -> &str {
        &self.label
    }

    fn detail(&self) -> String {
        self.label.clone()
    }

    fn qualified(&self) -> String {
        one_line(&self.id)
    }
}

/// The integration `name` means — its id, else its label as [`Named`] reads
/// it — or, without a name, the only one there is. Never a guess between
/// several.
fn find_integration(all: &[Integration], name: Option<&str>) -> Res<Integration> {
    let found = match (name, all) {
        (Some(name), _) => match all.iter().find(|i| i.id == name) {
            Some(by_id) => by_id,
            None => find_named(all, name)?,
        },
        (None, [one]) => one,
        (None, []) => return Err(Failure::msg(NO_INTEGRATION)),
        (None, many) => {
            let names: Vec<_> = many
                .iter()
                .map(|i| format!("\n  {}  ({})", one_line(&i.label), one_line(&i.id)))
                .collect();
            return Err(Failure::msg(format!(
                "there are several MCP integrations; choose one with --integration:{}",
                names.concat()
            )));
        }
    };
    Ok(Integration {
        id: found.id.clone(),
        label: found.label.clone(),
    })
}

fn integrations(home: Home, credentials: &Credentials, action: IntegrationsAction) -> Res<()> {
    match action {
        IntegrationsAction::List { json } => {
            let device = Device::open(home)?;
            let all = open_integrations(&device.home)?.list();
            if json {
                let text =
                    serde_json::to_string_pretty(&all).map_err(|e| Failure::msg(e.to_string()))?;
                println!("{text}");
            } else if all.is_empty() {
                eprintln!("unissh: {NO_INTEGRATION}");
            } else {
                for i in all {
                    println!("{}  {}", one_line(&i.label), i.id);
                }
            }
        }
        IntegrationsAction::Add { label } => {
            let device = widening(home)?;
            let summary = format!(
                "\"{}\" will be able to connect to unissh mcp.\n",
                one_line(&label)
            );
            if !unlock_confirmed(&device, &summary)? {
                confirm(false, &summary)?;
            }
            let (id, token) = open_integrations(&device.home)?
                .create(label.clone())
                .map_err(|e| Failure::msg(format!("cannot add the integration: {e}")))?;
            println!("Added \"{}\" ({id}).", one_line(&label));
            println!("Its token, shown only now (needed only with --http): {token}");
            println!(
                "Next: unissh mcp grants set \"{}\" <host>...",
                one_line(&label)
            );
        }
        IntegrationsAction::Rotate { integration } => {
            let device = widening(home)?;
            let store = open_integrations(&device.home)?;
            let found = find_integration(&store.list(), Some(&integration))?;
            let summary = format!(
                "A new token for \"{}\" revokes its access; grant it hosts again afterwards.\n",
                one_line(&found.label)
            );
            if !unlock_confirmed(&device, &summary)? {
                confirm(false, &summary)?;
            }
            forget(&device, Some(&found.id))?;
            let (_, token) = store
                .rotate(&found.id)
                .map_err(|e| Failure::msg(format!("cannot rotate the token: {e}")))?;
            println!("New token for \"{}\": {token}", one_line(&found.label));
            println!("{RESTART_HTTP}");
        }
        IntegrationsAction::Rm { integration, yes } => {
            let device = crate::unlocked(home, credentials)?;
            let store = open_integrations(&device.home)?;
            let found = find_integration(&store.list(), Some(&integration))?;
            confirm(
                yes,
                &format!(
                    "Removing \"{}\" disables its token and revokes its access.\n",
                    one_line(&found.label)
                ),
            )?;
            forget(&device, Some(&found.id))?;
            store
                .delete(&found.id)
                .map_err(|e| Failure::msg(format!("cannot remove the integration: {e}")))?;
            println!("Removed \"{}\".", one_line(&found.label));
            println!("{RESTART_HTTP}");
        }
    }
    Ok(())
}

/// What a token change means for an HTTP server already running: its tokens
/// were read at start. (The integration's access is revoked at once, but a grant
/// made later would work with the old token again until the restart.)
const RESTART_HTTP: &str = "Restart a running `unissh mcp --http`: it accepts the old token \
     until then.";

/// Revokes saved access (one integration's, or everyone's) on this device. A
/// running `unissh mcp` notices the write and stops that work at once.
fn forget(device: &Device, integration: Option<&str>) -> Res<()> {
    broker(device, Arc::new(NoPrompts))
        .forget_access(integration)
        .map_err(broker_failure)
}

fn grants(home: Home, credentials: &Credentials, offline: bool, action: GrantsAction) -> Res<()> {
    match action {
        GrantsAction::List { json } => {
            let device = crate::unlocked(home, credentials)?;
            let labels = open_integrations(&device.home)?.list();
            let rows = grant_rows(&broker(&device, Arc::new(NoPrompts)).review(), &labels);
            if json {
                let text =
                    serde_json::to_string_pretty(&rows).map_err(|e| Failure::msg(e.to_string()))?;
                println!("{text}");
            } else if rows.is_empty() {
                eprintln!(
                    "unissh: no MCP grants (`unissh mcp grants set <integration> <host>...`)"
                );
            } else {
                print!("{}", grant_table(&rows));
            }
        }
        GrantsAction::Set(args) => grant(home, offline, &args)?,
        GrantsAction::Rm { integration, all } => {
            let device = crate::unlocked(home, credentials)?;
            // clap refuses a name together with --all.
            let id = match (integration, all) {
                (Some(name), _) => {
                    let store = open_integrations(&device.home)?;
                    Some(find_integration(&store.list(), Some(&name))?.id)
                }
                (None, true) => None,
                (None, false) => return Err(Failure::msg("name an integration, or pass --all")),
            };
            forget(&device, id.as_deref())?;
            println!("Revoked.");
        }
    }
    Ok(())
}

fn grant(home: Home, offline: bool, args: &GrantArgs) -> Res<()> {
    let limits = args.limits()?;
    let device = widening(home)?;
    let integration = find_integration(
        &open_integrations(&device.home)?.list(),
        Some(&args.integration),
    )?;
    // Before the password: the hosts as named (resolving them needs the
    // vaults open), with everything else the grant will say.
    let named: String = args
        .hosts
        .iter()
        .map(|h| format!("  {}\n", one_line(h)))
        .collect();
    let typed = unlock_confirmed(
        &device,
        &grant_summary(&integration.label, &named, args, &limits),
    )?;
    if !offline {
        server::sync_if_stale(&device);
    }
    let broker = broker(&device, Arc::new(NoPrompts));
    // The ticket comes first, as in the desktop's host picker: a vault change
    // from here on (while the hosts load, while the summary waits for an
    // answer) fails the grant rather than granting what was not shown.
    let ticket = broker.grant_ticket().map_err(broker_failure)?;
    let all = hosts::load(&device.core)?;
    let mut targets = Vec::new();
    let mut shown = String::new();
    let mut seen = BTreeSet::new();
    for name in &args.hosts {
        let host = hosts::find(&all, name)?;
        if seen.insert((host.vault_id.clone(), host.profile.profile_id.clone())) {
            targets.push((host.vault_id.clone(), host.profile.profile_id.clone()));
            shown.push_str(&format!(
                "  {}/{}  {}\n",
                one_line(&host.vault_name),
                one_line(&host.profile.label),
                one_line(&host.target_text())
            ));
        }
    }
    if broker.grant_ticket().map_err(broker_failure)? != ticket {
        return Err(broker_failure(ToolError::GrantExpired));
    }
    if !typed {
        confirm(
            false,
            &grant_summary(&integration.label, &shown, args, &limits),
        )?;
    }
    let mode = if args.trusted {
        ApprovalMode::Trusted
    } else {
        ApprovalMode::Manual
    };
    broker
        .grant_with_limits(
            &integration.id,
            integration.label.clone(),
            targets,
            args.expires,
            &ticket,
            mode,
            args.command_limit,
            limits,
        )
        .map_err(broker_failure)?;
    println!("Granted \"{}\":\n{shown}", one_line(&integration.label));
    Ok(())
}

/// Everything a grant will do, for its confirmation: the integration, the
/// `hosts` (one per line), the expiry, whether commands are confirmed, and the
/// ceilings.
fn grant_summary(label: &str, hosts: &str, args: &GrantArgs, limits: &GrantLimits) -> String {
    format!(
        "\"{}\" may reach, {}:\n{hosts}{}\
         Each command runs for up to {}; at most {} connections and {} commands at once, \
         {} MiB of output kept per command.\n\
         Command output can reach the AI provider. This replaces its previous access.\n",
        one_line(label),
        args.expires.map_or_else(
            || "with no expiry".to_owned(),
            |s| format!("for {}", span(s.into()))
        ),
        if args.trusted {
            "Commands run WITHOUT confirmation, with the SSH user's permissions; only the \
             agent's own settings stand between a prompt and a command.\n"
        } else {
            "Each command is confirmed on the terminal of `unissh mcp --http`; over stdio, \
             or without a terminal, commands are refused.\n"
        },
        span(u64::from(args.command_limit / 1000)),
        limits.max_connections,
        limits.max_active_commands,
        limits.output_per_run_bytes / MIB,
    )
}

impl LimitArgs {
    /// `current` with the values given, or `None` when none was: errors when
    /// one is out of range.
    fn applied_to(&self, current: BrokerLimits) -> Res<Option<BrokerLimits>> {
        if self.max_connections.is_none()
            && self.command_history.is_none()
            && self.output_total.is_none()
        {
            return Ok(None);
        }
        let limits = BrokerLimits {
            max_connections: self.max_connections.unwrap_or(current.max_connections),
            retained_commands: self.command_history.unwrap_or(current.retained_commands),
            output_total_bytes: match self.output_total {
                Some(mib) => mib.checked_mul(MIB.into()).unwrap_or(0),
                None => current.output_total_bytes,
            },
        };
        if limits.is_valid() {
            Ok(Some(limits))
        } else {
            Err(Failure::msg(
                "limits out of range: --max-connections 1–256, --command-history 16–100000, \
                 --output-total 1–1024 (MiB)",
            ))
        }
    }
}

impl GrantArgs {
    /// The per-grant limits: the defaults, with what was given.
    fn limits(&self) -> Res<GrantLimits> {
        let d = GrantLimits::default();
        let limits = GrantLimits {
            max_connections: self.max_connections.unwrap_or(d.max_connections),
            max_active_commands: self.max_active_commands.unwrap_or(d.max_active_commands),
            // A history left unset follows a raised concurrency limit up, as
            // its floor is that limit; one given explicitly is checked as is.
            retained_commands: self.command_history.unwrap_or_else(|| {
                d.retained_commands
                    .max(self.max_active_commands.unwrap_or(d.max_active_commands))
            }),
            retained_sessions: self.session_history.unwrap_or_else(|| {
                d.retained_sessions
                    .max(self.max_connections.unwrap_or(d.max_connections))
            }),
            output_per_run_bytes: match self.output_per_command {
                Some(mib) => mib.checked_mul(MIB).unwrap_or(0),
                None => d.output_per_run_bytes,
            },
        };
        if limits.is_valid() {
            Ok(limits)
        } else {
            Err(Failure::msg(
                "limits out of range: --max-connections 1–64, --max-active-commands 1–256, \
                 --command-history from --max-active-commands to 10000, --session-history \
                 from --max-connections to 1000, --output-per-command 1–64 (MiB)",
            ))
        }
    }
}

fn limits(home: &Home, args: &LimitArgs) -> Res<()> {
    let path = home.mcp_limits();
    let current = load_limits(&path).unwrap_or_default();
    let changed = args.applied_to(current)?;
    if let Some(limits) = &changed {
        save_limits(&path, limits)
            .map_err(|e| Failure::msg(format!("cannot save {}: {e}", path.display())))?;
    }
    let limits = changed.unwrap_or(current);
    println!("SSH connections at once:  {}", limits.max_connections);
    println!("Command records kept:     {}", limits.retained_commands);
    println!(
        "Output kept in total:     {} MiB",
        limits.output_total_bytes / u64::from(MIB)
    );
    if changed.is_some() {
        println!("A running `unissh mcp` uses them from its next start.");
    }
    Ok(())
}

/// The saved grants, for the table and for `--json`: whether each would be in
/// force now (a host or security record changed since, or it expired, and it
/// needs granting again), its policy, and its hosts.
fn grant_rows(review: &Value, integrations: &[Integration]) -> Vec<Value> {
    let empty = Vec::new();
    let list = |key: &str| review.get(key).and_then(Value::as_array).unwrap_or(&empty);
    let active: BTreeSet<&str> = list("grants")
        .iter()
        .filter_map(|g| g.get("integration_id").and_then(Value::as_str))
        .collect();
    list("saved_access")
        .iter()
        .map(|saved| {
            let id = saved
                .get("integration_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let label = integrations
                .iter()
                .find(|i| i.id == id)
                .map(|i| i.label.as_str());
            let hosts: Vec<TargetInfo> = saved
                .get("targets")
                .and_then(|t| serde_json::from_value(t.clone()).ok())
                .unwrap_or_default();
            json!({
                "integration": label,
                "integration_id": id,
                "active": active.contains(id),
                "approval_mode": saved.get("approval_mode"),
                "remaining_seconds": saved.get("remaining_seconds"),
                "max_timeout_ms": saved.get("max_timeout_ms"),
                "limits": saved.get("limits"),
                "hosts": hosts.iter().map(|h| json!({
                    "vault": h.vault, "label": h.label, "host": h.host, "port": h.port, "user": h.user,
                })).collect::<Vec<_>>(),
            })
        })
        .collect()
}

fn grant_table(rows: &[Value]) -> String {
    let text =
        |row: &Value, key: &str| one_line(row.get(key).and_then(Value::as_str).unwrap_or_default());
    let mut out = String::new();
    for row in rows {
        let name = row
            .get("integration")
            .and_then(Value::as_str)
            .map_or_else(|| "(removed integration)".to_owned(), one_line);
        let mode = if text(row, "approval_mode") == "trusted" {
            "trusted: no confirmation"
        } else {
            "confirm each command"
        };
        let expiry = row
            .get("remaining_seconds")
            .and_then(Value::as_u64)
            .map_or_else(|| "no expiry".to_owned(), |s| format!("{} left", span(s)));
        let ceiling = row
            .get("max_timeout_ms")
            .and_then(Value::as_u64)
            .map_or_else(String::new, |ms| {
                format!(", commands up to {}", span(ms / 1000))
            });
        let state = if row.get("active").and_then(Value::as_bool) == Some(true) {
            "in force"
        } else {
            "needs granting again (it expired, or a host or security record changed)"
        };
        out.push_str(&format!("{name}: {mode}, {expiry}{ceiling} — {state}\n"));
        for host in row
            .get("hosts")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            out.push_str(&format!(
                "  {}/{}  {}@{}:{}\n",
                text(host, "vault"),
                text(host, "label"),
                text(host, "user"),
                text(host, "host"),
                host.get("port").and_then(Value::as_u64).unwrap_or(22)
            ));
        }
    }
    out
}

/// A span of seconds in the largest unit that divides it: "7d", "8h", "90m", "45s".
fn span(seconds: u64) -> String {
    match seconds {
        0 => "0s".to_owned(),
        s if s % 86_400 == 0 => format!("{}d", s / 86_400),
        s if s % 3600 == 0 => format!("{}h", s / 3600),
        s if s % 60 == 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

/// `30m`, `8h`, `7d` in seconds: a positive whole number and a unit, as the
/// desktop's access editor offers them.
fn duration_seconds(text: &str) -> Result<u64, String> {
    let text = text.trim();
    let unit = match text.chars().next_back() {
        Some('m') => 60,
        Some('h') => 3600,
        Some('d') => 86_400,
        Some(_) | None => return Err("give a number and m, h or d, e.g. 30m, 8h, 7d".to_owned()),
    };
    let number = text
        .get(..text.len().saturating_sub(1))
        .and_then(|n| n.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .ok_or_else(|| "give a positive whole number, e.g. 30m, 8h, 7d".to_owned())?;
    number
        .checked_mul(unit)
        .ok_or_else(|| "too long".to_owned())
}

/// A grant's lifetime, in seconds as the broker takes it.
fn grant_seconds(text: &str) -> Result<u32, String> {
    u32::try_from(duration_seconds(text)?).map_err(|_out_of_range| "too long".to_owned())
}

/// A command's longest runtime, 1 minute to 24 hours, in milliseconds.
fn command_ceiling_ms(text: &str) -> Result<u32, String> {
    let seconds = duration_seconds(text)?;
    if (60..=86_400).contains(&seconds) && seconds % 60 == 0 {
        u32::try_from(seconds * 1000).map_err(|_out_of_range| "too long".to_owned())
    } else {
        Err("from 1m to 24h".to_owned())
    }
}

/// A broker refusal in words for this command line (the wire messages speak
/// to an agent).
fn broker_failure(error: ToolError) -> Failure {
    Failure::msg(match error {
        ToolError::GrantExpired => {
            "the vaults changed while granting; run the command again".to_owned()
        }
        ToolError::Busy => {
            "too many saved grants (32 at most); revoke one with `unissh mcp grants rm`".to_owned()
        }
        ToolError::TargetUnavailable => {
            "a host cannot be granted: check that it connects with `unissh ssh`".to_owned()
        }
        ToolError::Locked => "the vaults are locked".to_owned(),
        ToolError::TimeoutLimit
        | ToolError::RequestConflict
        | ToolError::GrantRequired
        | ToolError::HostUntrusted
        | ToolError::HostChanged
        | ToolError::SessionNotReady
        | ToolError::SessionClosed
        | ToolError::ConnectionLost
        | ToolError::ApprovalDenied
        | ToolError::ApprovalExpired
        | ToolError::ApprovalUnavailable
        | ToolError::OutputExpired
        | ToolError::OutcomeUnknown => error.message().to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        command_ceiling_ms, duration_seconds, find_integration, grant_rows, grant_summary,
        GrantArgs, LimitArgs,
    };
    use crate::failure::Res;
    use serde_json::json;
    use unissh_automation::{BrokerLimits, GrantLimits};
    use unissh_mcp::credentials::Integration;

    /// The message of a refusal (`Integration` has no `Debug` for `unwrap_err`).
    fn refused(found: Res<Integration>) -> String {
        match found {
            Ok(i) => panic!("unexpectedly found {}", i.id),
            Err(e) => e.message,
        }
    }

    fn integration(id: &str, label: &str) -> Integration {
        Integration {
            id: id.into(),
            label: label.into(),
        }
    }

    #[test]
    fn durations_are_a_whole_number_and_a_unit() {
        assert_eq!(duration_seconds("30m"), Ok(1800));
        assert_eq!(duration_seconds("8h"), Ok(28_800));
        assert_eq!(duration_seconds("7d"), Ok(604_800));
        for bad in ["", "m", "0m", "5", "1w", "1.5h", "-1h", "h1"] {
            assert!(duration_seconds(bad).is_err(), "{bad:?} is refused");
        }
    }

    /// The command ceiling is the desktop's range: whole minutes, 1m to 24h.
    #[test]
    fn a_command_limit_runs_from_a_minute_to_a_day() {
        assert_eq!(command_ceiling_ms("1m"), Ok(60_000));
        assert_eq!(command_ceiling_ms("24h"), Ok(86_400_000));
        for bad in ["2d", "25h"] {
            assert!(command_ceiling_ms(bad).is_err(), "{bad:?} is past 24 h");
        }
    }

    fn grant_args(edit: impl FnOnce(&mut GrantArgs)) -> GrantArgs {
        let mut args = GrantArgs {
            integration: "Claude Code".into(),
            hosts: vec!["web".into()],
            expires: None,
            trusted: false,
            command_limit: 600_000,
            max_connections: None,
            max_active_commands: None,
            command_history: None,
            session_history: None,
            output_per_command: None,
        };
        edit(&mut args);
        args
    }

    /// What a grant is confirmed on (before the master password is typed) says
    /// all it will do: the integration, the hosts, the expiry, whether commands
    /// run unconfirmed, and the ceilings.
    #[test]
    fn a_grant_summary_says_everything_it_will_do() {
        let args = grant_args(|a| {
            a.trusted = true;
            a.expires = Some(8 * 3600);
            a.command_limit = 30 * 60 * 1000;
            a.max_connections = Some(2);
            a.max_active_commands = Some(3);
            a.output_per_command = Some(5);
        });
        let limits = args.limits().unwrap();
        let summary = grant_summary("Claude\u{1b}[2J Code", "  web\n  db\n", &args, &limits);
        for part in [
            "\"Claude[2J Code\" may reach, for 8h:\n  web\n  db\n",
            "WITHOUT confirmation",
            "up to 30m",
            "at most 2 connections and 3 commands at once",
            "5 MiB of output",
            "replaces its previous access",
        ] {
            assert!(summary.contains(part), "{part:?} in {summary:?}");
        }
        let manual = grant_args(|_| {});
        let summary = grant_summary("a", "  web\n", &manual, &manual.limits().unwrap());
        assert!(summary.contains("with no expiry"), "{summary:?}");
        assert!(summary.contains("Each command is confirmed"), "{summary:?}");
        assert!(!summary.contains("WITHOUT"), "{summary:?}");
    }

    /// A grant's limits are the defaults with what was given, in the desktop
    /// editor's ranges; an out-of-range one refuses the grant instead of being
    /// clamped.
    #[test]
    fn grant_limits_outside_the_editor_ranges_are_refused() {
        assert_eq!(
            grant_args(|_| ()).limits().ok(),
            Some(GrantLimits::default())
        );
        let given = grant_args(|a| {
            a.max_connections = Some(64);
            a.output_per_command = Some(64);
        })
        .limits()
        .ok();
        assert_eq!(given.map(|l| l.max_connections), Some(64));
        assert_eq!(
            given.map(|l| l.retained_sessions),
            Some(64),
            "history follows up"
        );
        assert_eq!(
            given.map(|l| l.output_per_run_bytes),
            Some(64 * 1024 * 1024)
        );
        let out_of_range: [fn(&mut GrantArgs); 5] = [
            |a| a.max_connections = Some(65),
            |a| a.max_active_commands = Some(0),
            |a| a.command_history = Some(10_001),
            |a| a.session_history = Some(1_001),
            |a| a.output_per_command = Some(65),
        ];
        for (i, edit) in out_of_range.into_iter().enumerate() {
            assert!(grant_args(edit).limits().is_err(), "case {i} is refused");
        }
    }

    /// `unissh mcp limits` changes only what is given, within the settings'
    /// ranges; with nothing given it changes nothing.
    #[test]
    fn app_limits_change_only_what_is_given_within_range() {
        let none = LimitArgs {
            max_connections: None,
            command_history: None,
            output_total: None,
        };
        let current = BrokerLimits::default();
        assert_eq!(none.applied_to(current).ok(), Some(None));
        let more = LimitArgs {
            max_connections: Some(256),
            ..none
        };
        let applied = more.applied_to(current).ok().flatten();
        assert_eq!(applied.map(|l| l.max_connections), Some(256));
        assert_eq!(
            applied.map(|l| l.retained_commands),
            Some(current.retained_commands)
        );
        for bad in [
            LimitArgs {
                max_connections: Some(257),
                ..none
            },
            LimitArgs {
                command_history: Some(15),
                ..none
            },
            LimitArgs {
                output_total: Some(1025),
                ..none
            },
        ] {
            assert!(bad.applied_to(current).is_err(), "out of range is refused");
        }
    }

    /// By id, or by label as hosts are named (any case, or the one label a
    /// name begins); a label two integrations share is refused rather than
    /// guessed, and the refusal names them by id.
    #[test]
    fn an_integration_is_named_by_id_or_label_never_guessed() {
        let all = [
            integration("id1", "Claude Code"),
            integration("id2", "Codex"),
            integration("id3", "codex"),
        ];
        assert_eq!(
            find_integration(&all, Some("claude code")).unwrap().id,
            "id1"
        );
        assert_eq!(find_integration(&all, Some("id3")).unwrap().id, "id3");
        assert_eq!(find_integration(&all, Some("clau")).unwrap().id, "id1");
        let begun = refused(find_integration(&all, Some("cod")));
        assert!(begun.contains("name one by its id"), "{begun}");
        let err = refused(find_integration(&all, Some("CODEX")));
        assert!(err.contains("id2") && err.contains("id3"), "{err}");
        assert!(refused(find_integration(&all, Some("cursor"))).contains("no MCP integration"));
    }

    /// Without --integration the stdio server serves the only one; with none,
    /// it says how to add one; with several, it asks which.
    #[test]
    fn without_a_name_only_a_single_integration_is_served() {
        let one = [integration("id1", "Claude Code")];
        assert_eq!(find_integration(&one, None).unwrap().id, "id1");
        let none = refused(find_integration(&[], None));
        assert!(none.contains("integrations add"), "{none}");
        let two = [integration("id1", "a"), integration("id2", "b")];
        assert!(refused(find_integration(&two, None)).contains("--integration"));
    }

    /// A saved grant that no longer restores (expired, or a host or security
    /// record changed) is listed as such, under its integration's name.
    #[test]
    fn saved_grants_say_whether_they_are_in_force() {
        let review = json!({
            "grants": [{"integration_id": "id1"}],
            "saved_access": [
                {"integration_id": "id1", "approval_mode": "manual", "targets": [{
                    "vault_id": "v", "profile_id": "p", "vault": "Prod", "groups": [], "tags": [],
                    "label": "web", "host": "web.example.com", "port": 22, "user": "deploy"
                }]},
                {"integration_id": "gone", "approval_mode": "trusted", "targets": []}
            ]
        });
        let rows = grant_rows(&review, &[integration("id1", "Claude Code")]);
        assert_eq!(rows[0]["integration"], "Claude Code");
        assert_eq!(rows[0]["active"], true);
        assert_eq!(rows[0]["hosts"][0]["host"], "web.example.com");
        assert!(rows[1]["integration"].is_null());
        assert_eq!(rows[1]["active"], false);
    }
}
