//! UniSSH Tauri backend — wires the `unissh_ffi::Core` into Tauri commands.

mod cloud;
mod commands;
mod dto;
mod error;
mod keychain;
mod observers;
mod state;

use tauri::Manager;
use unissh_ffi::Core;

use crate::state::AppState;

/// Parse the log level directive from `UNISSH_LOG` (preferred) or `RUST_LOG`.
/// Format: a global level optionally followed by `module=level` overrides, e.g.
/// `info,unissh_sync=debug,russh=info`. Unparseable parts are ignored; the global
/// level defaults to Info. Lets an operator raise verbosity without a rebuild.
fn log_filter_from_env() -> (log::LevelFilter, Vec<(String, log::LevelFilter)>) {
    let directive = std::env::var("UNISSH_LOG")
        .or_else(|_| std::env::var("RUST_LOG"))
        .unwrap_or_default();
    let mut global = log::LevelFilter::Info;
    let mut overrides = Vec::new();
    for part in directive
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if let Some((module, level)) = part.split_once('=') {
            let module = module.trim();
            if let (false, Ok(lf)) = (module.is_empty(), level.trim().parse::<log::LevelFilter>()) {
                overrides.push((module.to_string(), lf));
            }
        } else if let Ok(lf) = part.parse::<log::LevelFilter>() {
            global = lf;
        }
    }
    (global, overrides)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Logging first, so every later plugin/command is captured. Sinks: stdout,
    // a rotating file in the per-OS app log dir, and the webview console.
    // Redaction rule (mirrors the server, spec §13): NEVER log private keys,
    // passphrases, the master password, the Secret Key, tokens, vault plaintext
    // or full pubkeys/blobs — only metadata (host/port/user, fingerprints, ids,
    // error kinds, counters). See SECURITY.md.
    let (log_level, log_overrides) = log_filter_from_env();
    let mut log_builder = tauri_plugin_log::Builder::new()
        .level(log_level)
        // Bounded retention: rotate at ~5 MB and keep the current + one rotated
        // file (~10 MB cap) — enough history to diagnose, but it never grows
        // forever (the plugin default is a tiny 40 KB).
        .max_file_size(5_000_000)
        .rotation_strategy(tauri_plugin_log::RotationStrategy::KeepOne)
        .targets([
            tauri_plugin_log::Target::new(tauri_plugin_log::TargetKind::Stdout),
            tauri_plugin_log::Target::new(tauri_plugin_log::TargetKind::LogDir { file_name: None }),
            tauri_plugin_log::Target::new(tauri_plugin_log::TargetKind::Webview),
        ]);
    // russh is chatty and may carry sensitive context — default it to warn unless
    // the operator explicitly set a russh level via the env directive.
    if !log_overrides.iter().any(|(m, _)| m == "russh") {
        log_builder = log_builder.level_for("russh", log::LevelFilter::Warn);
    }
    for (module, level) in log_overrides {
        log_builder = log_builder.level_for(module, level);
    }

    #[cfg_attr(not(mobile), allow(unused_mut))]
    let mut builder = tauri::Builder::default()
        .plugin(log_builder.build())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_store::Builder::default().build())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_opener::init());

    // Biometric unlock is mobile-only (no desktop support in the official plugin).
    #[cfg(mobile)]
    {
        builder = builder.plugin(tauri_plugin_biometric::init());
    }

    builder
        .setup(|app| {
            // One local instance = two files in the app-data dir: the SQLCipher DB
            // and the encrypted keyset sidecar. The DB key is derived from the
            // unlocked keyset, so neither opens without unlocking.
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir).ok();
            let db_path = dir.join("instance.db");
            let keyset_path = dir.join("instance.keyset.bin");
            let core: std::sync::Arc<Core> = Core::new(
                db_path.to_string_lossy().to_string(),
                keyset_path.to_string_lossy().to_string(),
            );
            app.manage(AppState::new(core, db_path, keyset_path));

            // iOS: by default WKWebView adjusts its scroll-view content insets for
            // the safe area, which confines the web layout to (screen − safe
            // insets) — e.g. 839 of a 932px screen — and leaves a dead band below
            // the bottom tab bar that CSS can't paint into (the layout viewport,
            // and even position:fixed, stop at the inset edge). Setting the inset
            // adjustment to `.never` makes the webview lay out edge-to-edge; the
            // notch/home-indicator are then handled purely by CSS
            // env(safe-area-inset-*) padding on the shell and tab bar.
            #[cfg(target_os = "ios")]
            {
                use objc2::msg_send;
                use objc2::runtime::AnyObject;
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.with_webview(|wv| {
                        let wk = wv.inner() as *mut AnyObject; // the WKWebView
                        if wk.is_null() {
                            return;
                        }
                        // UIScrollViewContentInsetAdjustmentBehavior::Never == 2
                        unsafe {
                            let scroll: *mut AnyObject = msg_send![wk, scrollView];
                            if !scroll.is_null() {
                                let _: () =
                                    msg_send![scroll, setContentInsetAdjustmentBehavior: 2isize];
                            }
                        }
                    });
                }
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // account / instance
            commands::instance_status,
            commands::reset_partial_instance,
            commands::reset_instance,
            commands::log_dir,
            commands::reveal_log_dir,
            commands::create_account,
            commands::unlock,
            commands::lock,
            commands::is_unlocked,
            commands::set_keepalive_secs,
            commands::change_password,
            commands::account_id,
            // vaults
            commands::list_vaults,
            commands::create_vault,
            commands::rename_vault,
            commands::delete_vault,
            commands::purge_vault,
            commands::verify_vault_integrity,
            commands::check_consistency,
            // items / keys / certs
            commands::list_items,
            commands::generate_ssh_key,
            commands::import_ssh_key,
            commands::import_ssh_certificate,
            commands::get_public_key,
            commands::export_ssh_key,
            commands::rotate_ssh_key,
            commands::rename_item,
            commands::delete_item,
            commands::list_item_versions,
            // passwords
            commands::save_password,
            commands::get_password,
            commands::get_password_version,
            // notes
            commands::save_note,
            commands::get_note,
            commands::get_note_version,
            // known hosts
            commands::list_known_hosts,
            commands::forget_host,
            commands::trust_host,
            commands::import_known_hosts,
            // connection profiles
            commands::save_connection,
            commands::list_connections,
            commands::get_connection,
            commands::delete_connection,
            // identities (personal SSH creds)
            commands::save_identity,
            commands::list_identities,
            commands::get_identity,
            commands::delete_identity,
            // identity bindings (personal vault ↔ shared host)
            commands::set_binding,
            commands::get_binding,
            commands::list_bindings,
            commands::delete_binding,
            commands::resolve_host_binding,
            commands::resolve_personal_auth,
            commands::personal_destination,
            commands::apply_username_template,
            commands::import_ssh_config,
            commands::export_ssh_config,
            commands::import_putty_sessions,
            // groups
            commands::save_group,
            commands::list_groups,
            commands::get_group,
            commands::delete_group,
            commands::dry_run_group,
            // exec / fleet
            commands::ssh_exec,
            commands::ssh_exec_multi,
            commands::ssh_exec_by_tags,
            commands::ssh_exec_group,
            // streaming exec
            commands::exec_stream_open,
            commands::exec_stream_write,
            commands::exec_stream_close,
            // PTY sessions
            commands::session_open,
            commands::session_open_reconnecting,
            commands::session_write,
            commands::session_resize,
            commands::session_close,
            // broadcast
            commands::broadcast_open,
            commands::broadcast_write_all,
            commands::broadcast_resize_all,
            commands::broadcast_close,
            // tunnels
            commands::tunnel_open_local,
            commands::tunnel_open_dynamic,
            commands::tunnel_open_remote,
            commands::tunnel_close,
            // sftp
            commands::sftp_open,
            commands::local_list_dir,
            commands::sftp_list_dir,
            commands::sftp_stat,
            commands::sftp_realpath,
            commands::sftp_reopen,
            commands::sftp_chmod,
            commands::sftp_mkdir,
            commands::sftp_rmdir,
            commands::sftp_rmdir_recursive,
            commands::sftp_remove,
            commands::sftp_rename,
            commands::sftp_read_file,
            commands::sftp_write_file,
            commands::sftp_download,
            commands::sftp_upload,
            commands::sftp_close,
            // cancel tokens
            commands::cancel_new,
            commands::cancel_trigger,
            commands::cancel_dispose,
            // keychain (Secret Key on trusted device)
            keychain::keychain_available,
            keychain::keychain_save_secret_key,
            keychain::keychain_get_secret_key,
            keychain::keychain_unlock,
            keychain::keychain_delete_secret_key,
            // cloud server — identity / session / devices
            cloud::commands::server_status,
            cloud::commands::server_instance_info,
            cloud::commands::server_list,
            cloud::commands::server_set_active,
            cloud::commands::server_remove,
            cloud::commands::server_join,
            cloud::commands::server_claim,
            cloud::commands::server_login,
            cloud::commands::server_refresh_session,
            cloud::commands::server_logout,
            cloud::commands::server_disconnect,
            cloud::commands::server_join_preview,
            cloud::commands::server_device_add,
            cloud::commands::server_list_devices,
            cloud::commands::server_device_revoke,
            cloud::commands::server_account_profile,
            // cloud vaults + sync
            cloud::commands::server_create_cloud_vault,
            cloud::commands::server_bind_unbound_cloud_vaults,
            cloud::commands::server_bind_cloud_vault,
            cloud::commands::server_sync_now,
            cloud::commands::server_repull,
            cloud::commands::server_restore_deleted_vaults,
            // cloud membership / sharing
            cloud::commands::server_list_accounts,
            cloud::commands::server_add_member,
            cloud::commands::server_list_members,
            cloud::commands::server_member_fingerprint,
            cloud::commands::server_confirm_member_pin,
            cloud::commands::server_pin_vault_genesis_owner,
            cloud::commands::set_personal_vault,
            cloud::commands::set_account_default_username,
            cloud::commands::get_personal_vault,
            cloud::commands::get_account_default_username,
            cloud::commands::server_rotate_vk,
            // cloud spaces / directory / pending / attestations / invites (server-v2)
            cloud::commands::server_invite,
            cloud::commands::server_list_spaces,
            cloud::commands::server_create_space,
            cloud::commands::server_add_space_member,
            cloud::commands::server_directory,
            cloud::commands::server_pending,
            cloud::commands::server_attestations_put,
            cloud::commands::server_attestations_list,
            // cloud devices / onboarding (Path A keyset escrow, Path B PAKE relay)
            cloud::commands::server_keyset_push,
            cloud::commands::server_keyset_pull_and_unlock,
            cloud::commands::server_escrow_params,
            cloud::commands::server_escrow_fetch_and_unlock,
            cloud::commands::server_onboard_initiate,
            cloud::commands::server_onboard_complete,
            cloud::commands::server_onboard_join,
            // cloud audit (read-only)
            cloud::commands::server_audit_query,
        ])
        .run(tauri::generate_context!())
        .expect("error while running UniSSH");
}
