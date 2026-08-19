//! `unissh-server` binary: load config → init obs → connect the DB + migrations
//! → bring up axum (rustls TLS 1.3 or plain behind a reverse-proxy).

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use unissh_server::{Config, app, build_state, obs, time};

/// UniSSH self-hosted server.
#[derive(Parser)]
#[command(name = "unissh-server", version, about)]
struct Cli {
    /// Path to the TOML config (default: config.toml).
    #[arg(short, long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run migrations then serve the API (also the default when no subcommand is given).
    Serve,
    /// Apply pending database migrations and exit.
    Migrate,
    /// Raise next_seq after restoring an old backup (anti-rollback runbook §14.3); never lowers it.
    SeqBump {
        /// Raise next_seq to at least this floor N.
        #[arg(long, value_name = "N")]
        to: Option<i64>,
        /// Raise next_seq by this delta.
        #[arg(long, value_name = "DELTA")]
        by: Option<i64>,
    },
    /// Report where the first-run setup code stands. Read-only without --rotate.
    SetupCode {
        /// Issue a NEW code and print it. Invalidates the previous one; no restart needed.
        #[arg(long)]
        rotate: bool,
    },
    /// Unclaim the instance so a new owner can claim it (owner lost everything — spec §8).
    /// Prints a fresh code, unless one is pinned in the config — that one is applied, not echoed.
    Reclaim,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let Cli {
        config: config_path,
        command,
    } = Cli::parse();

    let cfg_path = config_path.unwrap_or_else(|| PathBuf::from("config.toml"));
    let config =
        Config::load(Some(cfg_path.as_path())).map_err(|e| anyhow::anyhow!("config load: {e}"))?;

    obs::init_tracing(&config.obs);

    if matches!(command, Some(Command::Migrate)) {
        let store = unissh_server::Store::connect(&config.db).await?;
        store.migrate().await?;
        tracing::info!("migrations applied");
        return Ok(());
    }

    // Anti-rollback runbook (§14.3): after a restore from an old backup, raise
    // next_seq so report_version doesn't fall below client cursors (otherwise
    // a fatal TransportRollback). NEVER lowers it. Instance-wide.
    //   seq-bump --by <delta>   (next_seq += delta)
    //   seq-bump --to <N>       (raise to floor N)
    if let Some(Command::SeqBump { to, by }) = command {
        let store = unissh_server::Store::connect(&config.db).await?;
        store.migrate().await?;
        let now = time::system_clock().now_unix();
        store.ensure_instance(now).await?;
        let (old, new) = if let Some(to) = to {
            store.bump_instance_seq_to(to).await?
        } else if let Some(by) = by {
            store.bump_instance_seq_by(by).await?
        } else {
            return Err(anyhow::anyhow!(
                "seq-bump requires --by <delta> or --to <N>"
            ));
        };
        println!("instance next_seq {old} -> {new}");
        return Ok(());
    }

    // The generated setup code is printed exactly once, to the boot log. One restart
    // plus a lost scrollback used to leave an unclaimed instance reachable only by
    // someone who already knew about UNISSH__SETUP__CODE or `reclaim` — one report
    // ended with the operator dropping the volumes and starting over. `setup-code`
    // says where the code stands; `--rotate` issues a new one, data untouched.
    if let Some(Command::SetupCode { rotate }) = command {
        use unissh_server::{
            SetupCodeState, apply_pinned_setup_code, ids, rotate_setup_code, setup_code_state,
        };
        let store = unissh_server::Store::connect(&config.db).await?;
        store.migrate().await?;
        let now = time::system_clock().now_unix();
        store.ensure_instance(now).await?;
        // Which database this actually opened, on stderr so it never pollutes the
        // `SETUP CODE:` line operators grep for. The default db url is RELATIVE, so
        // a wrong working directory silently creates an empty database and this
        // command would hand out a confident code for the wrong instance.
        eprintln!("using {} database at {}", config.db.backend, config.db.url);
        let pinned = config.setup.code.trim().to_string();
        let pinned_hash = (!pinned.is_empty()).then(|| ids::sha256(pinned.as_bytes()));
        // `[u8; 32]` is not `Deref`, so `as_deref()` does not apply here.
        let state = setup_code_state(&store, pinned_hash.as_ref().map(|h| h.as_slice())).await?;
        match (state, rotate) {
            (SetupCodeState::Claimed, false) => println!(
                "This instance is already claimed — no setup code is live (claiming clears \
                 it). To hand the instance to a new owner, run `unissh-server reclaim`: it \
                 unclaims and prints a code to claim with, leaving accounts, vaults and \
                 objects intact."
            ),
            (SetupCodeState::Claimed, true) => {
                return Err(anyhow::anyhow!(
                    "refusing to rotate: the instance is already claimed, so a setup code \
                     would not let anyone in. Use `unissh-server reclaim` to unclaim it and \
                     mint a code for a new owner."
                ));
            }
            (SetupCodeState::Pinned, false) => println!(
                "The setup code pinned in your configuration ([setup].code / \
                 UNISSH__SETUP__CODE) is the live one — use that value. It is deliberately \
                 never printed here or to the log: it came from you, and echoing it would \
                 only copy a live credential somewhere new."
            ),
            (SetupCodeState::Pinned, true) => {
                return Err(anyhow::anyhow!(
                    "refusing to rotate: [setup].code / UNISSH__SETUP__CODE pins the code and \
                     every boot re-applies it, so a rotated code would be overwritten on the \
                     next restart. Change the pinned value instead (or unset it to fall back \
                     to a generated code)."
                ));
            }
            // The pinned value is only applied by a boot, and this command reads the
            // config fresh — so an edited code, or one pinned before the first boot,
            // is NOT what the server accepts yet. Saying "use your pinned value" here
            // would hand the operator a code the claim endpoint rejects.
            (SetupCodeState::PinnedStale, false) => println!(
                "A setup code is pinned in your configuration, but this instance is not \
                 using it yet — the pinned value is applied at boot. Restart the server, or \
                 run `unissh-server setup-code --rotate` to apply it right now."
            ),
            (SetupCodeState::PinnedStale, true) => {
                apply_pinned_setup_code(&store, &pinned).await?;
                println!(
                    "The pinned setup code is now live (not printed — you already hold it). \
                     Any code issued earlier no longer works."
                );
            }
            (SetupCodeState::NotIssued, false) => println!(
                "No setup code has ever been issued on this database. The server mints one \
                 on its first boot and prints it to the log — start it, or run \
                 `unissh-server setup-code --rotate` to mint one now."
            ),
            (SetupCodeState::NotIssued, true) => {
                let code = rotate_setup_code(&store).await?;
                println!("SETUP CODE: {code}");
            }
            (SetupCodeState::Issued, true) => {
                let code = rotate_setup_code(&store).await?;
                println!("SETUP CODE: {code}");
                println!("(the previous code is now invalid; this one works immediately)");
            }
            (SetupCodeState::Issued, false) => println!(
                "A setup code was issued on an earlier boot and is still valid, but only its \
                 sha256 is stored — the plaintext existed solely in that boot's log, so it \
                 cannot be shown again.\nRun `unissh-server setup-code --rotate` to issue a \
                 new one. It invalidates the old code, takes effect immediately (no restart), \
                 and touches no data."
            ),
        }
        return Ok(());
    }

    // Reclaim (§8): the owner lost every device/keyset. Unclaim the instance and mint
    // a fresh setup code so a new owner can claim it. Data (accounts/vaults/objects)
    // is left intact — only the claim/owner binding + a fresh code.
    if matches!(command, Some(Command::Reclaim)) {
        let store = unissh_server::Store::connect(&config.db).await?;
        store.migrate().await?;
        let now = time::system_clock().now_unix();
        store.ensure_instance(now).await?;
        store
            .exec(
                "UPDATE instance SET claimed = 0, owner_account_id = NULL WHERE id = 1",
                vec![],
            )
            .await?;
        // Also strip the owner ROLE from the prior owner(s): reclaim nulls
        // instance.owner_account_id, but a stale accounts.is_owner=1 would leave a
        // ghost owner that still passes `require_owner` after a new owner claims.
        store
            .exec(
                "UPDATE accounts SET is_owner = 0 WHERE is_owner = 1",
                vec![],
            )
            .await?;
        // A pinned code is applied, not printed — the same rule the boot log and
        // `setup-code` follow. It came from the operator; echoing it here would
        // only copy a live credential into another scrollback.
        if config.setup.code.trim().is_empty() {
            let code = unissh_server::rotate_setup_code(&store).await?;
            println!("SETUP CODE: {code}");
        } else {
            unissh_server::apply_pinned_setup_code(&store, config.setup.code.trim()).await?;
            println!(
                "Instance unclaimed. Claim it with the setup code pinned in your \
                 configuration ([setup].code / UNISSH__SETUP__CODE) — not printed here, \
                 you already hold it."
            );
        }
        return Ok(());
    }

    // Whole-DB-snapshot anti-rollback (§16) is now enforced inside
    // `build_state` (below), so that in-process deployments are protected too.

    let metrics = obs::init_metrics();
    let bind: SocketAddr = config
        .server
        .bind
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid server.bind {}: {e}", config.server.bind))?;

    // TLS plan (fail-fast on acme=true; previously it silently served plain HTTP).
    let tls = unissh_server::tls_plan(&config.server).map_err(|e| anyhow::anyhow!(e))?;
    let trust_proxy = config.server.trust_proxy;
    // Fail-closed: do not serve plain HTTP on a non-loopback address without a declared
    // TLS-terminating reverse-proxy (trust_proxy). This combination puts
    // bearer/ops tokens and ciphertext on an open channel. The documented Caddy
    // stack sets trust_proxy=true; a bare open bind is almost always a misconfig —
    // we refuse to come up rather than silently downgrade to cleartext.
    if matches!(tls, unissh_server::TlsPlan::Plain) && !bind.ip().is_loopback() && !trust_proxy {
        return Err(anyhow::anyhow!(
            "refusing to serve plain HTTP on non-loopback {bind} without TLS: set \
             server.tls_cert+tls_key, or server.trust_proxy=true if a reverse proxy \
             terminates TLS in front, or bind to 127.0.0.1"
        ));
    }
    let janitor_interval = config.session.janitor_interval_seconds.max(1);
    let idem_ttl = config.session.idempotency_ttl_seconds.max(0);
    let metrics_bind = config.obs.metrics_bind.clone();
    let has_metrics = metrics.is_some();

    let state = build_state(config, time::system_clock(), metrics).await?;

    // Prometheus /metrics — on a separate internal listener (§5.7/§13), NOT on
    // the public API port.
    if has_metrics {
        if let Ok(maddr) = metrics_bind.parse::<SocketAddr>() {
            let mstate = state.clone();
            tokio::spawn(async move {
                match tokio::net::TcpListener::bind(maddr).await {
                    Ok(l) => {
                        tracing::info!(%maddr, "metrics listening");
                        let _ = axum::serve(
                            l,
                            unissh_server::http::build_metrics_router(mstate).into_make_service(),
                        )
                        .await;
                    }
                    Err(e) => tracing::warn!(error = %e, "metrics listener bind failed"),
                }
            });
        }
    }

    // Background TTL-janitor (§13).
    {
        let st = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(janitor_interval));
            loop {
                tick.tick().await;
                let now = st.now();
                match st.store.cleanup_expired(now, now - idem_ttl).await {
                    Ok(()) => st
                        .last_janitor_run
                        .store(now, std::sync::atomic::Ordering::Relaxed),
                    Err(e) => tracing::warn!(error = %e, "janitor cleanup failed"),
                }
            }
        });
    }

    let make = app(state).into_make_service_with_connect_info::<SocketAddr>();

    match tls {
        unissh_server::TlsPlan::Rustls { cert, key } => {
            // Install the process-level crypto provider for rustls 0.23 (idempotent).
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
            let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, &key)
                .await
                .map_err(|e| anyhow::anyhow!("load TLS cert/key: {e}"))?;
            tracing::info!(%bind, "unissh-server listening (rustls TLS 1.3)");
            axum_server::bind_rustls(bind, tls).serve(make).await?;
        }
        unissh_server::TlsPlan::Plain => {
            tracing::warn!(
                %bind, trust_proxy,
                "unissh-server listening (plain HTTP — terminate TLS at a reverse proxy and set trust_proxy=true)"
            );
            axum_server::bind(bind).serve(make).await?;
        }
    }
    Ok(())
}
