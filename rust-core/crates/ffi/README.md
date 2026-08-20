# unissh-ffi

The UniSSH core's FFI boundary (SPEC 4) on **UniFFI**. The `Core` facade ties
`keychain`, `storage`, `vault`, `ssh-agent`, and `ssh-transport` into a stable
contract for the UI (Swift/Kotlin/…).

## Hard constraint

**The UI/FFI never receives plaintext keys.** Private SSH keys are
generated and live inside the core; only the **public** key is handed out. There is not
a single method that returns a private key or a keyset secret. This is verified by the
test `tests/e2e.rs::private_key_never_stored_in_plaintext` (only ciphertext on
disk; the private key never leaks).

Secrets that cross the boundary on an explicit request are the **server password**
(`get_password`) and the **note text** (`get_note`), revealed for display/copy
in the UI. These are user secrets at the level of a password manager, not key
material; each reveal is strictly type-gated — for an item of another type (including
a private key) the call refuses (tests `get_password_refuses_non_password_items`,
`get_note_is_type_gated`).

## Contract (the essentials)

```text
Core::new(db_path, keyset_path)
create_account(password?) -> SecretKeyHex      // Emergency Kit (once)
unlock(password?, secret_key_hex)
lock() / is_unlocked()
change_password(old_password?, new_password?, secret_key_hex)  // re-wrap keyset; no unlock required

// vaults
create_vault(vault_id, name) / list_vaults()
rename_vault(vault_id, new_name) / delete_vault(vault_id)

// keys/items
generate_ssh_key(vault_id, item_id) -> public  // private key into the vault, public key out
import_ssh_key(vault_id, item_id, openssh_private) -> public   // Ed25519/ECDSA/RSA
import_ssh_certificate(vault_id, key_item_id, cert_openssh)    // cert-auth (CA)
get_public_key(vault_id, item_id) -> {openssh, fingerprint}    // re-read the public key
rename_item(vault_id, item_id, new_item_id) / delete_item(vault_id, item_id)
list_items(vault_id) -> [{item_id, item_type, version, created_at, updated_at, has_certificate}]

// server passwords (type-4 items; content is the UTF-8 bytes of the password)
save_password(vault_id, item_id, password)
get_password(vault_id, item_id) -> password    // reveal; only for a "password" item

// encrypted notes (type-6 items; arbitrary UTF-8)
save_note(vault_id, item_id, text)
get_note(vault_id, item_id) -> text            // reveal; only for a "note" item

// known_hosts (TOFU)
list_known_hosts() / forget_host(host, port)
trust_host(host, port, expected_fingerprint) -> fingerprint  // trust a new key (with verification)

// auth: AuthMethod::Agent{key_item_id} | Password{password} | VaultPassword{password_item_id}
//   VaultPassword: the core itself decrypts the password item on connect (plaintext never crosses the FFI)
//   jumps[]: JumpHost{host, port, user, auth} — each hop has its own method
ssh_exec(host, port, user, vault_id, auth, command, jumps[]) -> {stdout, stderr, exit}
// multi-exec: max_concurrency (0=unlimited), timeout_secs (0=no timeout, per-host)
ssh_exec_multi(targets[], command, max_concurrency, timeout_secs)
    -> [{host, stdout, stderr, exit, error?, duration_ms, timed_out}]  // concurrently
open_session(host, port, user, vault_id, auth, jumps[], term, cols, rows, observer)
    -> SshSession            // interactive PTY; output to observer (callback). cols,rows > 0
SshSession::{write(data), resize(cols, rows), close()}  // resize is best-effort (no server ack)
SessionObserver::{on_data(bytes), on_close(exit)}   // implemented by the UI

// host groups (type-5 items; only references to profiles/nested groups)
// ServerGroup{group_id, label, member_ids[], parent_id?} — parent_id for the folder tree in the UI
save_group(vault_id, group) / list_groups(vault_id) / get_group(vault_id, group_id)
delete_group(vault_id, group_id)
ssh_exec_group(vault_id, group_id, command, max_concurrency, timeout_secs) -> [MultiExecResult]
    // expands nested groups (visited-set + depth limit); dangling/cycle/prompt → error marker
dry_run_group(vault_id, group_id) -> [{member_id, host, port, user, status}]
    // resolve WITHOUT connect/keys/passwords; status: Ok|Dangling|PromptPassword|CycleSkipped

// profile tags (ConnectionProfile.tags[]; inside the encrypted profile) — selection, not RBAC
select_targets_by_tags(vault_id, tags[], match_all) -> [MultiExecTarget]
ssh_exec_by_tags(vault_id, tags[], match_all, command, max_concurrency, timeout_secs) -> [MultiExecResult]

// tunnels (live until close)
open_local_forward(.., local_bind, remote_host, remote_port) -> SshTunnel
open_dynamic_forward(.., local_bind) -> SshTunnel       // SOCKS5 (loopback only!)
open_remote_forward(.., remote_bind, remote_port, local_host, local_port) -> SshTunnel
SshTunnel::{bind_address(), close()}

// SFTP (lives until close)
open_sftp(host, port, user, vault_id, auth, jumps[]) -> SftpFfi
SftpFfi::{list_dir, read_file, write_file, remove, mkdir, rmdir, rename, stat, realpath, close}
// resumable transfers with progress/cancellation (CancelToken, SftpProgressObserver)
SftpFfi::sftp_download(remote, local, offset, progress?, cancel?) -> completed: bool
SftpFfi::sftp_upload(local, remote, offset, progress?, cancel?) -> completed: bool   // no TRUNC when resuming
sftp_put_multi(targets[], remote_path, data, make_parent_dirs, max_concurrency, timeout_secs)
    -> [{host, error?}]   // fleet push: one blob to many hosts

// streaming exec (separate stdout/stderr) and broadcast (cluster-ssh)
ssh_exec_stream(host, port, user, vault_id, auth, command, jumps[], ExecObserver) -> ExecHandleFfi
ExecHandleFfi::{write_stdin, wait_exit(timeout_ms), close}   // ExecObserver: on_stdout/on_stderr/on_exit
open_broadcast(targets[], term, cols, rows, BroadcastObserver) -> BroadcastSession
BroadcastSession::{write_all, resize_all, close, statuses}   // one input → N PTYs; output tagged by index
open_reconnecting_session(.., max_retries, backoff_ms, observer) -> ReconnectingSession
ReconnectingSession::{write, resize, reconnect, close, is_connected}  // auto-reconnect; HostKeyMismatch does not reconnect

// secret version history (password/note): stored in item_history (V3), retention 20, purged on deletion
list_item_versions(vault_id, item_id) -> [version]   // numbers only, no secrets
get_password_version(vault_id, item_id, version) -> password   // type-gated reveal of a version
get_note_version(vault_id, item_id, version) -> text

// audit and interop
verify_vault_integrity(vault_id) -> {ok, checked, issues[{item_id, version, tombstone, failure}]}  // signatures of all items
check_consistency() -> {ok, integrity_ok, issues[]}   // integrity_check + orphans + invariants, no secrets
export_ssh_config(vault_id) -> text                   // inverse of import_ssh_config
import_known_hosts(text) -> {imported, skipped_hashed, skipped_invalid}   // key canonicalization as in pinning
import_putty_sessions(vault_id, reg_text) -> {created_ids[], skipped}     // .reg → profiles

// encrypted vault backup (portable file, NOT sync; passphrase+Argon2id)
export_vault(vault_id, passphrase) -> bytes
import_vault(bytes, passphrase, new_vault_id)   // items are re-encrypted under the new VK; wrong passphrase → error

// connection profiles ("hosts"; stored as encrypted type-3 items)
// ConnectionProfile.auth: ProfileAuth::Key{key_item_id} | VaultPassword{password_item_id}
//   | PromptPassword (ask on connect); ConnectionProfile.tags[] — selection labels.
//   The profile JSON holds references only; a jump host with an inline password cannot be saved
//   (error). The legacy format (without tags/password_item_id) is read without migration.
save_connection(vault_id, profile) / list_connections(vault_id)
get_connection(vault_id, profile_id) / delete_connection(vault_id, profile_id)
import_ssh_config(vault_id, config_text) -> [created_profile_ids]        // pasted text; Include is reported, not followed
import_ssh_config_at_path(vault_id, path, only?) -> [{alias, origin_file}] // a FILE: Include followed as ssh follows it,
                                                                          // `only` = the aliases the preview left ticked
ssh_config_report(config_text) / ssh_config_report_at_path(path)
  -> {hosts[{alias, origin_file, hostname, port, user, identity_file}], skipped[{line, keyword, inside_match, origin_file}],
      pending_includes[], files_read[]}   // shown BEFORE importing: files_read is every file an Include pulled in

// errors: HostKeyMismatch{host, port, fingerprint} is singled out for a UI MITM warning
```

### Milestone 2 (cloud vaults, membership, identity, sync)

These methods expose the Milestone 2 operations (server-tz §2–§9, §13). **The
private-key boundary does not change:** only public keys + fingerprints,
opaque signed/encrypted blobs (`Vec<u8>`), and typed reports go out;
VK, per-item keys, and keyset private keys never cross the boundary. **A cloud
`vault_id` is hex** (UUIDv4 — non-UTF8 bytes; local methods keep UTF-8 ids).

```text
// === Milestone 2 (cloud vaults, membership, identity, sync) ===
// cloud vaults (vault_id — hex UUIDv4)
create_cloud_vault(name) -> vault_id_hex                 // SyncTarget::Cloud
get_cache_policy(vault_id) / set_cache_policy(vault_id, policy)   // server-tz §6.6

// membership/grants (member keys — hex, PUBLIC; VK does not go out)
add_member(vault_id, member_ed25519_pub, member_x25519_pub, role)
list_members(vault_id) -> [{ed25519_pub_hex, role, fingerprint}]
member_fingerprint(ed25519_pub) -> hex(SHA-256)          // OOB confirm
confirm_member_pin(account_id, ed25519_pub)              // TOFU pinning
rotate_vk(vault_id, [remaining]) -> new_epoch            // eager VK rotation (revocation)
purge_vault(vault_id)                                    // cooperative hard-delete
verify_chain(vault_id) -> {ok, checked, issues}          // member-aware audit

// identity/auth (out — public keys/signatures/blobs, NOT secrets)
account_id() -> hex                                      // server-tz §2.1
build_registration() -> bytes                            // self-attested blob
sign_server_challenge(host, account_id, device_id, key_id, nonce, expiry) -> sig

// device onboarding
unlock_from_server_blob(keyset_blob, password?, secret_key_hex)   // Path A
OnboardInitiatorHandle::start(code) -> handle; handle.msg() -> msg1   // Path B (initiator)
Core::onboard_confirm_and_seal(handle, msg2) -> msg3
OnboardResponderHandle::respond(code, msg1) -> handle; handle.msg() -> msg2   // Path B (responder)
Core::onboard_finish_install(handle, msg3, password?)

// audit (server-tz §8) — blobs are opaque, the signing is done by the layer above
audit_append(vault_id, entry_blob, signature, author_pubkey) -> seq
audit_query(since_seq) -> [{seq, entry_blob, signature, author_pubkey_hex, recorded_at}]

// sync (server-tz §3) — callback interface (the app relays opaque blobs)
trait FfiSyncTransport { push_objects(objects)->[seq]; delta_since(cursor)->[item]; report_version()->u64 }
sync_now(transport) -> {applied, skipped_stale, conflicts, rejected, pushed}
```

#### Sync: callback interface (decision)

`FfiSyncTransport` is a UniFFI **callback interface** (foreign-implemented by the
application, which is the one that goes to the network). Sync objects cross the
boundary as opaque bytes (a serialized `SyncObject`); the core holds an adapter to
`unissh_sync::SyncTransport` and **verifies every object before applying it**
(the transport is untrusted — its ordering, its `server_seq`, and its contents are
not to be trusted). The "bare blob operations without a trait" variant is not used —
a callback more precisely reflects the "server relays blobs" model and reuses the
foreign-callback mechanism already adopted in the crate (like `SessionObserver`).

#### Onboarding Path B: shape of the handles (uniffi 0.31)

`#[uniffi::constructor]` in uniffi 0.31 returns only `Self`/`Arc<Self>`, not an
arbitrary Record. So `OnboardInitiatorHandle::start`/
`OnboardResponderHandle::respond` perform the PAKE step immediately and place the outgoing
relay blob (`msg1`/`msg2`) **inside the handle**; the blob is fetched by a separate getter,
`handle.msg()`. The semantics of the planned "handle + bytes" pair are preserved; the state
is one-shot (a repeated consume → typed error).

**Authentication:** the private key never leaves the built-in agent — the signature is done by the
agent (`russh::auth::Signer`); only the public key comes out of the agent.

**Locks:** Core holds an internal lock only for the duration of the connect; `exec` and the
lifetime of an interactive session run without it. Session streaming is fully asynchronous
(a background task → `SessionObserver`).

## Model

A local instance = an encrypted DB file (`storage`, SQLCipher) + a sidecar with
the encrypted keyset. The SQLCipher key is derived from the secrets of the **unlocked**
keyset (HKDF) — the DB cannot be opened without unlocking. SSH sessions go through
the built-in agent (the key is in the agent, not in the UI). russh's async operations run on
an internal tokio runtime (the methods are synchronous/blocking — convenient for FFI).

## Generating bindings

The UniFFI facade (`uniffi::setup_scaffolding!`) generates bindings for
Swift/Kotlin/Python on the fly; prebuilt artifacts are not kept in the repository:

```bash
cargo build -p unissh-ffi                      # builds the cdylib
cargo run -p unissh-ffi --bin uniffi-bindgen -- \
    generate --library target/debug/libunissh_ffi.so --language swift --out-dir <out-dir>
```

The contract includes `Core`, `sshExec`, `generateSshKey`, `JumpHost`,
`SshExecResult` … UniFFI also supports Kotlin/Python.

## CLI harness

The [`unissh-cli`](../cli) crate (the `unissh` binary) uses this facade for an end-to-end
scenario from the terminal: `init → create-vault → gen-key → exec` (with `--jump` for
ProxyJump).
