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
        return seq_bump(&config, to, by).await;
    }

    // The generated setup code is printed exactly once, to the boot log. One restart
    // plus a lost scrollback used to leave an unclaimed instance reachable only by
    // someone who already knew about UNISSH__SETUP__CODE or `reclaim` — one report
    // ended with the operator dropping the volumes and starting over. `setup-code`
    // says where the code stands; `--rotate` issues a new one, data untouched.
    if let Some(Command::SetupCode { rotate }) = command {
        return setup_code(&config, rotate).await;
    }

    // Reclaim (§8): the owner lost every device/keyset. Unclaim the instance and mint
    // a fresh setup code so a new owner can claim it. Data (accounts/vaults/objects)
    // is left intact — only the claim/owner binding + a fresh code.
    if matches!(command, Some(Command::Reclaim)) {
        return reclaim(&config).await;
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
        spawn_metrics_listener(&state, &metrics_bind);
    }

    // Background TTL-janitor (§13).
    spawn_janitor(&state, janitor_interval, idem_ttl);

    // Audit export sinks (`[audit.*]`): one delivery task each. They and the
    // listener stop together on SIGTERM/Ctrl-C; an in-flight batch is simply
    // re-sent after the restart (at-least-once).
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let sinks = unissh_server::audit_sinks::spawn_configured(&state, stop_rx)
        .map_err(|e| anyhow::anyhow!(e))?;
    let handle = axum_server::Handle::<SocketAddr>::new();
    {
        let handle = handle.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            tracing::info!("shutdown requested");
            let _ = stop_tx.send(true);
            // 8 s drain + 1 s sink join stays inside Docker's default 10 s stop grace.
            handle.graceful_shutdown(Some(std::time::Duration::from_secs(8)));
        });
    }

    let make = app(state).into_make_service_with_connect_info::<SocketAddr>();

    match tls {
        unissh_server::TlsPlan::Rustls { cert, key } => {
            // Install the process-level crypto provider for rustls 0.23 (idempotent).
            // `Err` only means a provider is already installed, which is fine.
            drop(rustls::crypto::aws_lc_rs::default_provider().install_default());
            let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, &key)
                .await
                .map_err(|e| anyhow::anyhow!("load TLS cert/key: {e}"))?;
            tracing::info!(%bind, "unissh-server listening (rustls TLS 1.3)");
            axum_server::bind_rustls(bind, tls)
                .handle(handle)
                .serve(make)
                .await?;
        }
        unissh_server::TlsPlan::Plain => {
            tracing::warn!(
                %bind, trust_proxy,
                "unissh-server listening (plain HTTP — terminate TLS at a reverse proxy and set trust_proxy=true)"
            );
            axum_server::bind(bind).handle(handle).serve(make).await?;
        }
    }
    // The sinks were told to stop with the listener; give them one shared second.
    // A sink still busy after that second is abandoned with the process.
    drop(
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            futures_util::future::join_all(sinks),
        )
        .await,
    );
    Ok(())
}

/// Serve Prometheus `/metrics` on its own internal listener; an unparsable
/// `metrics_bind` leaves metrics unexposed.
fn spawn_metrics_listener(state: &unissh_server::AppState, metrics_bind: &str) {
    let Ok(maddr) = metrics_bind.parse::<SocketAddr>() else {
        return;
    };
    let mstate = state.clone();
    tokio::spawn(async move {
        match tokio::net::TcpListener::bind(maddr).await {
            Ok(l) => {
                tracing::info!(%maddr, "metrics listening");
                if let Err(e) = axum::serve(
                    l,
                    unissh_server::http::build_metrics_router(mstate).into_make_service(),
                )
                .await
                {
                    tracing::warn!(error = %e, "metrics listener stopped");
                }
            }
            Err(e) => tracing::warn!(error = %e, "metrics listener bind failed"),
        }
    });
}

/// Run the TTL janitor every `janitor_interval` seconds for the life of the process.
fn spawn_janitor(state: &unissh_server::AppState, janitor_interval: u64, idem_ttl: i64) {
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

/// `seq-bump`: raise next_seq after restoring an old backup; never lowers it.
#[expect(
    clippy::print_stdout,
    reason = "operator-facing CLI result of the seq-bump subcommand"
)]
async fn seq_bump(config: &Config, to: Option<i64>, by: Option<i64>) -> anyhow::Result<()> {
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
    Ok(())
}

/// `setup-code [--rotate]`: report where the first-run setup code stands, or issue a new one.
#[expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "operator-facing setup output; the setup code is handed to the operator on stdout, never through the log pipeline"
)]
async fn setup_code(config: &Config, rotate: bool) -> anyhow::Result<()> {
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
    // The url is redacted: a Postgres url may carry `user:password@`.
    eprintln!(
        "using {} database at {}",
        config.db.backend,
        redact_db_url(&config.db.url)
    );
    let pinned = config.setup.code.trim().to_owned();
    let pinned_hash = (!pinned.is_empty()).then(|| ids::sha256(pinned.as_bytes()));
    // `[u8; 32]` is not `Deref`, so `as_deref()` does not apply here.
    let state = setup_code_state(&store, pinned_hash.as_ref().map(<[u8; 32]>::as_slice)).await?;
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
    Ok(())
}

/// `reclaim`: unclaim the instance and issue (or apply the pinned) setup code.
#[expect(
    clippy::print_stdout,
    reason = "operator-facing setup output; the setup code is handed to the operator on stdout, never through the log pipeline"
)]
async fn reclaim(config: &Config) -> anyhow::Result<()> {
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
    Ok(())
}

/// `url` with every password it carries replaced by `***`, for operator-facing
/// output: the one in the `scheme://user:password@host` userinfo and the value of a
/// `password=` query parameter (sqlx accepts both). Keys, other parameters and
/// anything without a password (a sqlite path, `scheme://user@host`,
/// `scheme://host/db?x=a@b`) come back as is.
///
/// The authority is cut at the first `/`, `?` or `#` after `://`, so an `@` in the
/// path or query is never taken for the userinfo separator. Inside the authority
/// the LAST `@` ends the userinfo, so a password with a stray unencoded `@` is
/// still masked whole rather than partially echoed.
fn redact_db_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_owned();
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    let authority = authority
        .rsplit_once('@')
        .and_then(|(userinfo, host)| {
            let (user, _password) = userinfo.split_once(':')?;
            Some(format!("{user}:***@{host}"))
        })
        .unwrap_or_else(|| authority.to_owned());
    format!("{scheme}://{authority}{}", redact_query_password(tail))
}

/// `tail` (path, query and fragment of a URL) with the value of every `password=`
/// query pair replaced by `***`; the path and the fragment are left untouched.
fn redact_query_password(tail: &str) -> String {
    let Some((path, after)) = tail.split_once('?') else {
        return tail.to_owned();
    };
    let (query, fragment) = after.find('#').map_or((after, ""), |i| after.split_at(i));
    let query = query
        .split('&')
        .map(|pair| {
            if pair
                .split_once('=')
                .is_some_and(|(key, _value)| key == "password")
            {
                "password=***"
            } else {
                pair
            }
        })
        .collect::<Vec<_>>()
        .join("&");
    format!("{path}?{query}{fragment}")
}

/// Resolves on Ctrl-C or (unix) SIGTERM, which is what `docker stop` sends.
async fn shutdown_signal() {
    let ctrl_c = async {
        // No signal handler (rare) → never resolve, rather than shut down at once.
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {}
        _ = term => {}
    }
}

#[cfg(test)]
mod tests {
    use super::redact_db_url;

    #[test]
    fn redact_db_url_masks_userinfo_and_query_passwords() {
        assert_eq!(
            redact_db_url("postgres://unissh:s3cret@db:5432/unissh?sslmode=require"),
            "postgres://unissh:***@db:5432/unissh?sslmode=require",
            "a password in the userinfo is masked"
        );
        assert_eq!(
            redact_db_url("postgres://unissh@db:5432/unissh"),
            "postgres://unissh@db:5432/unissh",
            "a user without a password is left alone"
        );
        assert_eq!(
            redact_db_url("sqlite://data/unissh.db"),
            "sqlite://data/unissh.db",
            "a sqlite path is left alone"
        );
        assert_eq!(
            redact_db_url("postgres://db:5432/unissh?application_name=a:b@c"),
            "postgres://db:5432/unissh?application_name=a:b@c",
            "an @ in the query is not userinfo"
        );
        assert_eq!(
            redact_db_url("postgres://u:p@ss@h/db"),
            "postgres://u:***@h/db",
            "the LAST @ ends the userinfo, so a raw @ in the password is masked whole"
        );
        assert_eq!(
            redact_db_url("postgres://unissh@db:5432/unissh?sslmode=require&password=s3cret#f"),
            "postgres://unissh@db:5432/unissh?sslmode=require&password=***#f",
            "a password query parameter is masked, other parameters are kept"
        );
        assert_eq!(
            redact_db_url("data/unissh.db"),
            "data/unissh.db",
            "the default sqlite path is left alone"
        );
        assert_eq!(
            redact_db_url("/app/data/unissh.db"),
            "/app/data/unissh.db",
            "the compose sqlite path is left alone"
        );
    }
}
