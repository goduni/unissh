//! Temporary UniSSH CLI harness — "poke" at the core from a terminal through the
//! [`unissh_ffi::Core`] FFI facade until a native UI exists.
//!
//! ⚠️ This is a **debug harness**, not a production interface. Secrets (`--secret-key`,
//! `--password`, `--ssh-password`) are passed as command-line arguments and are
//! therefore visible in `ps`/`/proc/<pid>/cmdline` and shell history. For real
//! use, secrets must be entered interactively/via env. Do not use it
//! on multi-user hosts with real keys.
//!
//! End-to-end scenario (Milestone 1):
//! ```text
//! unissh init                                   # prints the Secret Key (Emergency Kit)
//! unissh create-vault --secret-key <hex> --id default --name Default
//! unissh gen-key      --secret-key <hex> --vault default --item id_ed25519   # -> public key
//! unissh exec         --secret-key <hex> --vault default --item id_ed25519 \
//!                     --host 10.0.0.5 --user deploy --command "uname -a" \
//!                     --jump bastion:22:admin:id_ed25519                      # ProxyJump (repeatable)
//! ```

use std::error::Error;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use unissh_ffi::{AuthMethod, Core, JumpHost, MultiExecTarget, SessionObserver};

/// Authentication method from flags: `--password` takes precedence over `--item`.
/// `--item <id>` — a key from the vault; `--item pw:<id>` — a password item from the vault.
fn build_auth(
    vault: &str,
    item: Option<String>,
    password: Option<String>,
) -> Result<AuthMethod, Box<dyn Error>> {
    match (password, item) {
        (Some(password), _) => Ok(AuthMethod::Password { password }),
        (None, Some(item)) => Ok(item_auth(vault, &item)),
        (None, None) => Err("specify --item <key | pw:password-item> or --password".into()),
    }
}

/// Prints multi/group/tags-exec results: successes to stdout, errors/timeouts
/// to stderr (with duration).
fn print_multi(results: Vec<unissh_ffi::MultiExecResult>) {
    for r in results {
        match r.error {
            Some(e) if r.timed_out => eprintln!("[{}:TIMEOUT {}ms] {e}", r.host, r.duration_ms),
            Some(e) => eprintln!("[{}:ERROR] {e}", r.host),
            None => print!(
                "[{} exit={} {}ms]\n{}",
                r.host, r.exit_status, r.duration_ms, r.stdout
            ),
        }
    }
}

/// `pw:<id>` → the vault's password item, otherwise a key item.
fn item_auth(vault: &str, item: &str) -> AuthMethod {
    match item.strip_prefix("pw:") {
        Some(id) => AuthMethod::VaultPassword {
            vault_id: vault.to_string(),
            password_item_id: id.to_string(),
        },
        None => AuthMethod::Agent {
            vault_id: vault.to_string(),
            key_item_id: item.to_string(),
        },
    }
}

#[derive(Parser)]
#[command(name = "unissh", about = "UniSSH core CLI harness (Milestone 1)")]
struct Cli {
    /// Path to the instance's encrypted DB file.
    #[arg(long, global = true, default_value = "unissh.db")]
    db: String,
    /// Path to the sidecar holding the encrypted keyset.
    #[arg(long, global = true, default_value = "unissh-keyset.bin")]
    keyset: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create an account (first device). Prints the Secret Key for the Emergency Kit.
    Init {
        /// Master password (optional; without it — SecretKeyOnly mode).
        #[arg(long)]
        password: Option<String>,
    },
    /// Create a local vault.
    CreateVault {
        #[command(flatten)]
        unlock: UnlockArgs,
        #[arg(long)]
        id: String,
        #[arg(long)]
        name: String,
    },
    /// Generate an SSH key in the vault (prints the public key).
    GenKey {
        #[command(flatten)]
        unlock: UnlockArgs,
        #[arg(long)]
        vault: String,
        #[arg(long)]
        item: String,
    },
    /// List vaults.
    ListVaults {
        #[command(flatten)]
        unlock: UnlockArgs,
    },
    /// List a vault's items.
    ListItems {
        #[command(flatten)]
        unlock: UnlockArgs,
        #[arg(long)]
        vault: String,
    },
    /// Save a server password into the vault (a "password" item).
    SavePassword {
        #[command(flatten)]
        unlock: UnlockArgs,
        #[arg(long)]
        vault: String,
        #[arg(long)]
        item: String,
        #[arg(long)]
        password: String,
    },
    /// Show a password from the vault (reveal).
    ShowPassword {
        #[command(flatten)]
        unlock: UnlockArgs,
        #[arg(long)]
        vault: String,
        #[arg(long)]
        item: String,
    },
    /// Connect over SSH and run a command (optionally via ProxyJump).
    Exec {
        #[command(flatten)]
        unlock: UnlockArgs,
        #[arg(long)]
        vault: String,
        /// Key item for agent authentication (or use --ssh-password).
        #[arg(long)]
        item: Option<String>,
        /// Password for authenticating to the host (instead of a key).
        #[arg(long = "ssh-password")]
        ssh_password: Option<String>,
        #[arg(long)]
        host: String,
        #[arg(long, default_value = "22")]
        port: u16,
        #[arg(long)]
        user: String,
        #[arg(long)]
        command: String,
        /// Jump host `host:port:user:keyitem` (repeatable, in order).
        #[arg(long = "jump")]
        jumps: Vec<String>,
    },
    /// Import a user certificate (OpenSSH) and bind it to a key.
    ImportCert {
        #[command(flatten)]
        unlock: UnlockArgs,
        #[arg(long)]
        vault: String,
        #[arg(long)]
        item: String,
        /// Path to the certificate file (`*-cert.pub`).
        #[arg(long)]
        cert_file: String,
    },
    /// Run a command on several hosts (concurrently).
    MultiExec {
        #[command(flatten)]
        unlock: UnlockArgs,
        #[arg(long)]
        vault: String,
        #[arg(long)]
        item: Option<String>,
        #[arg(long = "ssh-password")]
        ssh_password: Option<String>,
        #[arg(long)]
        command: String,
        /// Host `host:port:user` (repeatable).
        #[arg(long = "host")]
        hosts: Vec<String>,
        /// Maximum concurrent commands (0 = no limit).
        #[arg(long, default_value = "0")]
        max_concurrency: u32,
        /// Per-host command timeout in seconds (0 = no timeout).
        #[arg(long, default_value = "0")]
        timeout: u32,
    },
    /// Save an encrypted note into the vault (a "note" item).
    SaveNote {
        #[command(flatten)]
        unlock: UnlockArgs,
        #[arg(long)]
        vault: String,
        #[arg(long)]
        item: String,
        #[arg(long)]
        text: String,
    },
    /// Show a note from the vault (reveal).
    ShowNote {
        #[command(flatten)]
        unlock: UnlockArgs,
        #[arg(long)]
        vault: String,
        #[arg(long)]
        item: String,
    },
    /// Save/update a host group.
    SaveGroup {
        #[command(flatten)]
        unlock: UnlockArgs,
        #[arg(long)]
        vault: String,
        #[arg(long)]
        group: String,
        #[arg(long)]
        label: String,
        /// Members: comma-separated profile/group ids.
        #[arg(long, value_delimiter = ',')]
        members: Vec<String>,
        /// Parent group (for the folder tree).
        #[arg(long)]
        parent: Option<String>,
    },
    /// List a vault's groups.
    ListGroups {
        #[command(flatten)]
        unlock: UnlockArgs,
        #[arg(long)]
        vault: String,
    },
    /// Delete a group.
    DeleteGroup {
        #[command(flatten)]
        unlock: UnlockArgs,
        #[arg(long)]
        vault: String,
        #[arg(long)]
        group: String,
    },
    /// Dry run of a group: show the expanded targets and their status (without connecting).
    DryRunGroup {
        #[command(flatten)]
        unlock: UnlockArgs,
        #[arg(long)]
        vault: String,
        #[arg(long)]
        group: String,
    },
    /// Run a command on all hosts in a group (nested groups are expanded).
    ExecGroup {
        #[command(flatten)]
        unlock: UnlockArgs,
        #[arg(long)]
        vault: String,
        #[arg(long)]
        group: String,
        #[arg(long)]
        command: String,
        #[arg(long, default_value = "0")]
        max_concurrency: u32,
        #[arg(long, default_value = "0")]
        timeout: u32,
    },
    /// Run a command on profiles with matching tags.
    ExecByTags {
        #[command(flatten)]
        unlock: UnlockArgs,
        #[arg(long)]
        vault: String,
        /// Comma-separated tags.
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
        /// Require all tags (AND); otherwise any (OR).
        #[arg(long)]
        all: bool,
        #[arg(long)]
        command: String,
        #[arg(long, default_value = "0")]
        max_concurrency: u32,
        #[arg(long, default_value = "0")]
        timeout: u32,
    },
    /// Interactive shell session (PTY): input from stdin, output to stdout.
    Shell {
        #[command(flatten)]
        unlock: UnlockArgs,
        #[arg(long)]
        vault: String,
        #[arg(long)]
        item: Option<String>,
        #[arg(long = "ssh-password")]
        ssh_password: Option<String>,
        #[arg(long)]
        host: String,
        #[arg(long, default_value = "22")]
        port: u16,
        #[arg(long)]
        user: String,
        /// Jump host `host:port:user:keyitem` (repeatable).
        #[arg(long = "jump")]
        jumps: Vec<String>,
    },
    /// Rename a vault.
    RenameVault {
        #[command(flatten)]
        unlock: UnlockArgs,
        #[arg(long)]
        vault: String,
        #[arg(long)]
        name: String,
    },
    /// Delete a vault.
    DeleteVault {
        #[command(flatten)]
        unlock: UnlockArgs,
        #[arg(long)]
        vault: String,
    },
    /// Delete an item from the vault.
    DeleteItem {
        #[command(flatten)]
        unlock: UnlockArgs,
        #[arg(long)]
        vault: String,
        #[arg(long)]
        item: String,
    },
    /// List pinned host keys (TOFU).
    KnownHosts {
        #[command(flatten)]
        unlock: UnlockArgs,
    },
    /// "Forget" a pinned host key.
    ForgetHost {
        #[command(flatten)]
        unlock: UnlockArgs,
        #[arg(long)]
        host: String,
        #[arg(long, default_value = "22")]
        port: u16,
    },
    /// Show the public key and fingerprint of an existing key item.
    PubKey {
        #[command(flatten)]
        unlock: UnlockArgs,
        #[arg(long)]
        vault: String,
        #[arg(long)]
        item: String,
    },
    /// Change the master password (re-wrap the keyset). Does not require unlock.
    ChangePassword {
        /// Secret Key (hex from the Emergency Kit).
        #[arg(long)]
        secret_key: String,
        /// Current password (if any).
        #[arg(long)]
        old_password: Option<String>,
        /// New password (without it — passwordless mode).
        #[arg(long)]
        new_password: Option<String>,
    },
    /// Rename (move) an item to a new id.
    RenameItem {
        #[command(flatten)]
        unlock: UnlockArgs,
        #[arg(long)]
        vault: String,
        #[arg(long)]
        item: String,
        #[arg(long)]
        new: String,
    },
    /// Trust a new host key after a mismatch (re-pin). Prints the fingerprint.
    TrustHost {
        #[command(flatten)]
        unlock: UnlockArgs,
        #[arg(long)]
        host: String,
        #[arg(long, default_value = "22")]
        port: u16,
        /// Confirmed fingerprint (SHA256:...) from the mismatch warning.
        #[arg(long)]
        fingerprint: String,
    },
    /// Import an ssh-config into the vault's connection profiles.
    ImportSshConfig {
        #[command(flatten)]
        unlock: UnlockArgs,
        #[arg(long)]
        vault: String,
        /// Path to the config file (default ~/.ssh/config).
        #[arg(long)]
        file: String,
    },
    /// List saved connection profiles.
    ListConnections {
        #[command(flatten)]
        unlock: UnlockArgs,
        #[arg(long)]
        vault: String,
    },
    /// SFTP: list a directory.
    SftpLs {
        #[command(flatten)]
        target: SftpTarget,
        /// Remote path.
        #[arg(long, default_value = ".")]
        path: String,
    },
    /// SFTP: download a file.
    SftpGet {
        #[command(flatten)]
        target: SftpTarget,
        /// Remote path.
        #[arg(long)]
        remote: String,
        /// Local path.
        #[arg(long)]
        local: String,
    },
    /// SFTP: upload a file.
    SftpPut {
        #[command(flatten)]
        target: SftpTarget,
        /// Local path.
        #[arg(long)]
        local: String,
        /// Remote path.
        #[arg(long)]
        remote: String,
    },
    /// Local port forward (blocks until Ctrl-C).
    LocalForward {
        #[command(flatten)]
        target: SftpTarget,
        /// Local bind (`127.0.0.1:8080`).
        #[arg(long)]
        local_bind: String,
        /// Target host on the server side.
        #[arg(long)]
        remote_host: String,
        /// Target port.
        #[arg(long)]
        remote_port: u16,
    },
}

/// Common connection parameters for a single host (for SFTP/forwards).
#[derive(clap::Args)]
struct SftpTarget {
    #[command(flatten)]
    unlock: UnlockArgs,
    #[arg(long)]
    vault: String,
    /// Key item for agent authentication (or --ssh-password).
    #[arg(long)]
    item: Option<String>,
    #[arg(long = "ssh-password")]
    ssh_password: Option<String>,
    #[arg(long)]
    host: String,
    #[arg(long, default_value = "22")]
    port: u16,
    #[arg(long)]
    user: String,
    #[arg(long = "jump")]
    jumps: Vec<String>,
}

/// Session observer: prints PTY output to stdout, signals on close.
struct StdoutObserver {
    done: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl SessionObserver for StdoutObserver {
    fn on_data(&self, data: Vec<u8>) {
        use std::io::Write;
        let mut out = std::io::stdout();
        let _ = out.write_all(&data);
        let _ = out.flush();
    }
    fn on_close(&self, exit_status: i32) {
        self.done.store(true, std::sync::atomic::Ordering::SeqCst);
        eprintln!("\n[session closed, code {exit_status}]");
    }
}

#[derive(clap::Args)]
struct UnlockArgs {
    /// Secret Key (hex from the Emergency Kit).
    #[arg(long)]
    secret_key: String,
    /// Master password (if one was used).
    #[arg(long)]
    password: Option<String>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let core = Core::new(cli.db.clone(), cli.keyset.clone());

    match cli.cmd {
        Cmd::Init { password } => {
            let secret = core.create_account(password)?;
            println!("Secret Key (SAVE THIS — Emergency Kit, shown once):");
            println!("{secret}");
        }
        Cmd::CreateVault { unlock, id, name } => {
            do_unlock(&core, &unlock)?;
            core.create_vault(id, name)?;
            println!("ok");
        }
        Cmd::GenKey {
            unlock,
            vault,
            item,
        } => {
            do_unlock(&core, &unlock)?;
            let public = core.generate_ssh_key(vault, item)?;
            println!("{public}");
        }
        Cmd::ListVaults { unlock } => {
            do_unlock(&core, &unlock)?;
            for v in core.list_vaults()? {
                println!("{}\t{}", v.vault_id, v.name);
            }
        }
        Cmd::ListItems { unlock, vault } => {
            do_unlock(&core, &unlock)?;
            for i in core.list_items(vault)? {
                let cert = if i.has_certificate { " +cert" } else { "" };
                println!(
                    "{}\ttype={}\tv{}\tupdated={}{}",
                    i.item_id, i.item_type, i.version, i.updated_at, cert
                );
            }
        }
        Cmd::Exec {
            unlock,
            vault,
            item,
            ssh_password,
            host,
            port,
            user,
            command,
            jumps,
        } => {
            do_unlock(&core, &unlock)?;
            let auth = build_auth(&vault, item, ssh_password)?;
            let jumps = parse_jumps(&vault, &jumps)?;
            let res = core.ssh_exec(host, port, user, auth, command, jumps)?;
            print!("{}", res.stdout);
            eprint!("{}", res.stderr);
            std::process::exit(res.exit_status);
        }
        Cmd::ImportCert {
            unlock,
            vault,
            item,
            cert_file,
        } => {
            do_unlock(&core, &unlock)?;
            let cert = std::fs::read_to_string(&cert_file)?;
            core.import_ssh_certificate(vault, item, cert)?;
            println!("ok");
        }
        Cmd::MultiExec {
            unlock,
            vault,
            item,
            ssh_password,
            command,
            hosts,
            max_concurrency,
            timeout,
        } => {
            do_unlock(&core, &unlock)?;
            let mut targets = Vec::new();
            for h in &hosts {
                let parts: Vec<&str> = h.split(':').collect();
                if parts.len() != 3 {
                    return Err(format!("bad --host '{h}', expected host:port:user").into());
                }
                targets.push(MultiExecTarget {
                    host: parts[0].to_string(),
                    port: parts[1].parse()?,
                    user: parts[2].to_string(),
                    auth: build_auth(&vault, item.clone(), ssh_password.clone())?,
                    jumps: vec![],
                });
            }
            print_multi(core.ssh_exec_multi(targets, command, max_concurrency, timeout)?);
        }
        Cmd::SaveNote {
            unlock,
            vault,
            item,
            text,
        } => {
            do_unlock(&core, &unlock)?;
            core.save_note(vault, item, text)?;
            println!("ok");
        }
        Cmd::ShowNote {
            unlock,
            vault,
            item,
        } => {
            do_unlock(&core, &unlock)?;
            println!("{}", core.get_note(vault, item)?);
        }
        Cmd::SaveGroup {
            unlock,
            vault,
            group,
            label,
            members,
            parent,
        } => {
            do_unlock(&core, &unlock)?;
            core.save_group(
                vault,
                unissh_ffi::ServerGroup {
                    group_id: group,
                    label,
                    member_ids: members,
                    parent_id: parent,
                },
            )?;
            println!("ok");
        }
        Cmd::ListGroups { unlock, vault } => {
            do_unlock(&core, &unlock)?;
            for g in core.list_groups(vault)? {
                println!(
                    "{}\t{}\tparent={}\tmembers={}",
                    g.group_id,
                    g.label,
                    g.parent_id.as_deref().unwrap_or("-"),
                    g.member_ids.join(",")
                );
            }
        }
        Cmd::DeleteGroup {
            unlock,
            vault,
            group,
        } => {
            do_unlock(&core, &unlock)?;
            core.delete_group(vault, group)?;
            println!("ok");
        }
        Cmd::DryRunGroup {
            unlock,
            vault,
            group,
        } => {
            do_unlock(&core, &unlock)?;
            for p in core.dry_run_group(vault, group)? {
                println!(
                    "{}\t{}:{}@{}\t{:?}",
                    p.member_id, p.user, p.host, p.port, p.status
                );
            }
        }
        Cmd::ExecGroup {
            unlock,
            vault,
            group,
            command,
            max_concurrency,
            timeout,
        } => {
            do_unlock(&core, &unlock)?;
            print_multi(core.ssh_exec_group(vault, group, command, max_concurrency, timeout)?);
        }
        Cmd::ExecByTags {
            unlock,
            vault,
            tags,
            all,
            command,
            max_concurrency,
            timeout,
        } => {
            do_unlock(&core, &unlock)?;
            print_multi(core.ssh_exec_by_tags(
                vault,
                tags,
                all,
                command,
                max_concurrency,
                timeout,
            )?);
        }
        Cmd::Shell {
            unlock,
            vault,
            item,
            ssh_password,
            host,
            port,
            user,
            jumps,
        } => {
            do_unlock(&core, &unlock)?;
            let auth = build_auth(&vault, item, ssh_password)?;
            let jumps = parse_jumps(&vault, &jumps)?;
            let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let observer: Arc<dyn SessionObserver> =
                Arc::new(StdoutObserver { done: done.clone() });
            let session = core.open_session(
                host,
                port,
                user,
                auth,
                jumps,
                "xterm-256color".to_string(),
                80,
                24,
                observer,
                // The harness does not record: a recording needs a vault to write
                // into and a decision about whether the user wanted one, and this
                // is a debugging shell, not the product.
                None,
                // Nor does it forward the agent: that needs an approver to confirm
                // each signature, and there is nobody at a harness to ask.
                false,
            )?;
            // line-by-line input from stdin (no raw mode — this is a harness)
            use std::io::BufRead;
            for line in std::io::stdin().lock().lines() {
                if done.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
                let mut line = line?;
                line.push('\n');
                session.write(line.into_bytes())?;
            }
            // let the remote shell finish and the output drain
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while !done.load(std::sync::atomic::Ordering::SeqCst)
                && std::time::Instant::now() < deadline
            {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
            let _ = session.close();
        }
        Cmd::RenameVault {
            unlock,
            vault,
            name,
        } => {
            do_unlock(&core, &unlock)?;
            core.rename_vault(vault, name)?;
            println!("ok");
        }
        Cmd::DeleteVault { unlock, vault } => {
            do_unlock(&core, &unlock)?;
            core.delete_vault(vault)?;
            println!("ok");
        }
        Cmd::SavePassword {
            unlock,
            vault,
            item,
            password,
        } => {
            do_unlock(&core, &unlock)?;
            core.save_password(vault, item, password)?;
            println!("ok");
        }
        Cmd::ShowPassword {
            unlock,
            vault,
            item,
        } => {
            do_unlock(&core, &unlock)?;
            println!("{}", core.get_password(vault, item)?);
        }
        Cmd::DeleteItem {
            unlock,
            vault,
            item,
        } => {
            do_unlock(&core, &unlock)?;
            core.delete_item(vault, item)?;
            println!("ok");
        }
        Cmd::KnownHosts { unlock } => {
            do_unlock(&core, &unlock)?;
            for h in core.list_known_hosts()? {
                println!("{}:{}\t{}", h.host, h.port, h.key);
            }
        }
        Cmd::ForgetHost { unlock, host, port } => {
            do_unlock(&core, &unlock)?;
            let removed = core.forget_host(host, port)?;
            println!("{}", if removed { "ok" } else { "not found" });
        }
        Cmd::PubKey {
            unlock,
            vault,
            item,
        } => {
            do_unlock(&core, &unlock)?;
            let pk = core.get_public_key(vault, item)?;
            println!("{}", pk.openssh);
            eprintln!("{}", pk.fingerprint);
        }
        Cmd::ChangePassword {
            secret_key,
            old_password,
            new_password,
        } => {
            core.change_password(old_password, new_password, secret_key)?;
            println!("ok");
        }
        Cmd::RenameItem {
            unlock,
            vault,
            item,
            new,
        } => {
            do_unlock(&core, &unlock)?;
            core.rename_item(vault, item, new)?;
            println!("ok");
        }
        Cmd::TrustHost {
            unlock,
            host,
            port,
            fingerprint,
        } => {
            do_unlock(&core, &unlock)?;
            let fp = core.trust_host(host, port, fingerprint)?;
            println!("{fp}");
        }
        Cmd::ImportSshConfig {
            unlock,
            vault,
            file,
        } => {
            do_unlock(&core, &unlock)?;
            let text = std::fs::read_to_string(&file)?;
            let created = core.import_ssh_config(vault, text)?;
            for id in &created {
                println!("{id}");
            }
            eprintln!("imported {} profile(s)", created.len());
        }
        Cmd::ListConnections { unlock, vault } => {
            do_unlock(&core, &unlock)?;
            for c in core.list_connections(vault)? {
                let auth = match &c.auth {
                    unissh_ffi::ProfileAuth::Key { key_item_id } => key_item_id.clone(),
                    unissh_ffi::ProfileAuth::VaultPassword { password_item_id } => {
                        format!("pw:{password_item_id}")
                    }
                    unissh_ffi::ProfileAuth::PromptPassword => "(password)".to_string(),
                    unissh_ffi::ProfileAuth::Personal => "(personal)".to_string(),
                    unissh_ffi::ProfileAuth::SystemAgent { public_key } => {
                        // Just the comment/type, not the whole blob: a listing
                        // wants to be readable, and the key is not a secret but
                        // it is long.
                        let short = public_key.split_whitespace().next().unwrap_or("key");
                        format!("(system agent: {short})")
                    }
                };
                println!(
                    "{}\t{}@{}:{}\tauth={}\tjumps={}",
                    c.profile_id,
                    c.user,
                    c.host,
                    c.port,
                    auth,
                    c.jumps.len()
                );
            }
        }
        Cmd::SftpLs { target, path } => {
            let sftp = open_sftp(&core, target)?;
            for e in sftp.list_dir(path)? {
                let kind = if e.is_dir { "d" } else { "-" };
                println!("{kind}\t{}\t{}", e.size, e.filename);
            }
            sftp.close();
        }
        Cmd::SftpGet {
            target,
            remote,
            local,
        } => {
            let sftp = open_sftp(&core, target)?;
            let data = sftp.read_file(remote)?;
            std::fs::write(&local, &data)?;
            sftp.close();
            eprintln!("wrote {} bytes -> {local}", data.len());
        }
        Cmd::SftpPut {
            target,
            local,
            remote,
        } => {
            let sftp = open_sftp(&core, target)?;
            let data = std::fs::read(&local)?;
            let n = data.len();
            sftp.write_file(remote, data)?;
            sftp.close();
            eprintln!("uploaded {n} bytes");
        }
        Cmd::LocalForward {
            target,
            local_bind,
            remote_host,
            remote_port,
        } => {
            do_unlock(&core, &target.unlock)?;
            let auth = build_auth(&target.vault, target.item, target.ssh_password)?;
            let jumps = parse_jumps(&target.vault, &target.jumps)?;
            let tunnel = core.open_local_forward(
                target.host,
                target.port,
                target.user,
                auth,
                jumps,
                local_bind,
                remote_host,
                remote_port,
            )?;
            println!("listening on {} (Ctrl-C to stop)", tunnel.bind_address());
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
    }
    Ok(())
}

/// Opens an SFTP session from the target parameters (unlocking the core).
fn open_sftp(core: &Core, target: SftpTarget) -> Result<Arc<unissh_ffi::SftpFfi>, Box<dyn Error>> {
    do_unlock(core, &target.unlock)?;
    let auth = build_auth(&target.vault, target.item, target.ssh_password)?;
    let jumps = parse_jumps(&target.vault, &target.jumps)?;
    Ok(core.open_sftp(
        target.host,
        target.port,
        target.user,
        auth,
        jumps,
        4, // parallelism: a reasonable default for CLI folder transfers
    )?)
}

fn do_unlock(core: &Core, args: &UnlockArgs) -> Result<(), Box<dyn Error>> {
    core.unlock(args.password.clone(), args.secret_key.clone())?;
    Ok(())
}

fn parse_jumps(vault: &str, specs: &[String]) -> Result<Vec<JumpHost>, Box<dyn Error>> {
    let mut out = Vec::new();
    for s in specs {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 4 {
            return Err(format!(
                "bad --jump '{s}', expected host:port:user:<keyitem|pw:passworditem>"
            )
            .into());
        }
        out.push(JumpHost {
            host: parts[0].to_string(),
            port: parts[1].parse()?,
            user: parts[2].to_string(),
            auth: item_auth(vault, parts[3]),
            hop_ref: None,
        });
    }
    Ok(out)
}
