// Typed bridge over the Tauri command surface (src-tauri/src/commands.rs).
// Tauri converts camelCase JS arg keys to the snake_case Rust params automatically.

import { Channel, invoke } from "@tauri-apps/api/core";
import { vaultMutated } from "./sync-hook";
import type {
  AccountInfo,
  AuditEntry,
  AuthMethod,
  BroadcastEvent,
  ConnectionProfile,
  Identity,
  IdentityBinding,
  BindingResolution,
  PersonalAuth,
  DbConsistencyReport,
  DeviceInfo,
  ExecEvent,
  GroupTargetPlan,
  HostImportReport,
  InstanceInfo,
  InstanceStatus,
  InviteInfo,
  JoinPreview,
  SpaceInfo,
  DirectoryEntry,
  PendingAction,
  AttestationInfo,
  EscrowParamsInfo,
  ItemInfo,
  JumpHost,
  KnownHostInfo,
  KnownHostsImport,
  MemberInfo,
  MemberRole,
  MultiExecResult,
  MultiExecTarget,
  OpenedBroadcast,
  OpenedTunnel,
  PairingPayload,
  ProgressEvent,
  PublicKeyInfo,
  RemainingMember,
  ServerGroup,
  ServerList,
  ServerStatus,
  SftpEntry,
  SftpFileStat,
  LocalEntry,
  SshExecResult,
  SyncReport,
  TermEvent,
  VaultInfo,
  VaultIntegrityReport,
} from "./types";
import { profileToAuth } from "./types";

// After a vault-content mutation succeeds, notify the auto-sync hook so cloud
// vaults push to their server immediately (no manual "Sync now"). The original
// result is passed through unchanged.
function afterMut<T>(vaultId: string, p: Promise<T>): Promise<T> {
  return p.then((r) => {
    vaultMutated(vaultId);
    return r;
  });
}

// ── account / instance ─────────────────────────────────────────
export const instanceStatus = () => invoke<InstanceStatus>("instance_status");
/** Clear a half-written (partial) instance so onboarding can start clean.
 *  Backend hard-guards this to never touch a complete or unlocked instance. */
export const resetPartialInstance = () => invoke<void>("reset_partial_instance");
/** Destructive full reset of this device's instance (db + keyset + cloud links +
 *  keychain Secret Key) → back to onboarding. Backend refuses while unlocked.
 *  The "can't unlock → start over" escape on the lock screen. */
export const resetInstance = () => invoke<void>("reset_instance");
/** Absolute path to the per-OS application log directory. */
export const logDir = () => invoke<string>("log_dir");
/** Open the log directory in the OS file manager. */
export const revealLogDir = () => invoke<void>("reveal_log_dir");
export const createAccount = (password: string | null) =>
  invoke<string>("create_account", { password });
export const unlock = (password: string | null, secretKeyHex: string) =>
  invoke<void>("unlock", { password, secretKeyHex });
export const lock = () => invoke<void>("lock");
export const isUnlocked = () => invoke<boolean>("is_unlocked");
export const changePassword = (
  oldPassword: string | null,
  newPassword: string | null,
  secretKeyHex: string,
) => invoke<void>("change_password", { oldPassword, newPassword, secretKeyHex });
export const accountId = () => invoke<string>("account_id");

// ── vaults ─────────────────────────────────────────────────────
export const listVaults = () => invoke<VaultInfo[]>("list_vaults");
export const createVault = (vaultId: string, name: string) =>
  afterMut(vaultId, invoke<void>("create_vault", { vaultId, name }));
export const renameVault = (vaultId: string, newName: string) =>
  afterMut(vaultId, invoke<void>("rename_vault", { vaultId, newName }));
export const deleteVault = (vaultId: string) =>
  afterMut(vaultId, invoke<void>("delete_vault", { vaultId }));
export const verifyVaultIntegrity = (vaultId: string) =>
  invoke<VaultIntegrityReport>("verify_vault_integrity", { vaultId });
export const checkConsistency = () => invoke<DbConsistencyReport>("check_consistency");
export const purgeVault = (vaultId: string) => invoke<void>("purge_vault", { vaultId });

// ── items / keys / certs ───────────────────────────────────────
export const listItems = (vaultId: string) => invoke<ItemInfo[]>("list_items", { vaultId });
export const generateSshKey = (vaultId: string, itemId: string) =>
  afterMut(vaultId, invoke<string>("generate_ssh_key", { vaultId, itemId }));
export const importSshKey = (
  vaultId: string,
  itemId: string,
  opensshPrivate: string,
  passphrase?: string,
) =>
  afterMut(
    vaultId,
    invoke<string>("import_ssh_key", {
      vaultId,
      itemId,
      opensshPrivate,
      passphrase: passphrase ?? null,
    }),
  );
export const importSshCertificate = (vaultId: string, keyItemId: string, certOpenssh: string) =>
  afterMut(vaultId, invoke<void>("import_ssh_certificate", { vaultId, keyItemId, certOpenssh }));
export const getPublicKey = (vaultId: string, itemId: string) =>
  invoke<PublicKeyInfo>("get_public_key", { vaultId, itemId });
/** Export the private OpenSSH key (backup/migration). Gate behind explicit user intent. */
export const exportSshKey = (vaultId: string, itemId: string) =>
  invoke<string>("export_ssh_key", { vaultId, itemId });
/** Rotate an SSH key in place (same item id). Returns the new public key to install. */
export const rotateSshKey = (vaultId: string, itemId: string) =>
  afterMut(vaultId, invoke<string>("rotate_ssh_key", { vaultId, itemId }));
export const renameItem = (vaultId: string, itemId: string, newItemId: string) =>
  afterMut(vaultId, invoke<void>("rename_item", { vaultId, itemId, newItemId }));
export const deleteItem = (vaultId: string, itemId: string) =>
  afterMut(vaultId, invoke<void>("delete_item", { vaultId, itemId }));
export const listItemVersions = (vaultId: string, itemId: string) =>
  invoke<number[]>("list_item_versions", { vaultId, itemId });

// ── passwords ──────────────────────────────────────────────────
export const savePassword = (vaultId: string, itemId: string, password: string) =>
  afterMut(vaultId, invoke<void>("save_password", { vaultId, itemId, password }));
export const getPassword = (vaultId: string, itemId: string) =>
  invoke<string>("get_password", { vaultId, itemId });
export const getPasswordVersion = (vaultId: string, itemId: string, version: number) =>
  invoke<string>("get_password_version", { vaultId, itemId, version });

// ── notes ──────────────────────────────────────────────────────
export const saveNote = (vaultId: string, itemId: string, text: string) =>
  afterMut(vaultId, invoke<void>("save_note", { vaultId, itemId, text }));
export const getNote = (vaultId: string, itemId: string) =>
  invoke<string>("get_note", { vaultId, itemId });
export const getNoteVersion = (vaultId: string, itemId: string, version: number) =>
  invoke<string>("get_note_version", { vaultId, itemId, version });

// ── known hosts / TOFU ─────────────────────────────────────────
export const listKnownHosts = () => invoke<KnownHostInfo[]>("list_known_hosts");
export const forgetHost = (host: string, port: number) =>
  invoke<boolean>("forget_host", { host, port });
export const trustHost = (host: string, port: number, expectedFingerprint: string) =>
  invoke<string>("trust_host", { host, port, expectedFingerprint });
export const importKnownHosts = (text: string) =>
  invoke<KnownHostsImport>("import_known_hosts", { text });

// ── connection profiles (hosts) ────────────────────────────────
export const saveConnection = (vaultId: string, profile: ConnectionProfile) =>
  afterMut(vaultId, invoke<void>("save_connection", { vaultId, profile }));
export const listConnections = (vaultId: string) =>
  invoke<ConnectionProfile[]>("list_connections", { vaultId });
export const getConnection = (vaultId: string, profileId: string) =>
  invoke<ConnectionProfile>("get_connection", { vaultId, profileId });
export const deleteConnection = (vaultId: string, profileId: string) =>
  afterMut(vaultId, invoke<void>("delete_connection", { vaultId, profileId }));

// ── identities (personal SSH creds) ────────────────────────────
export const saveIdentity = (vaultId: string, identity: Identity) =>
  afterMut(vaultId, invoke<void>("save_identity", { vaultId, identity }));
export const listIdentities = (vaultId: string) =>
  invoke<Identity[]>("list_identities", { vaultId });
export const getIdentity = (vaultId: string, identityId: string) =>
  invoke<Identity>("get_identity", { vaultId, identityId });
export const deleteIdentity = (vaultId: string, identityId: string) =>
  afterMut(vaultId, invoke<void>("delete_identity", { vaultId, identityId }));

// ── identity bindings (personal vault ↔ shared host) ───────────
export const setBinding = (
  personalVaultId: string,
  binding: IdentityBinding,
  allowRebind = false,
) => afterMut(personalVaultId, invoke<void>("set_binding", { personalVaultId, binding, allowRebind }));
export const getBinding = (personalVaultId: string, teamVaultId: string, profileUid: string) =>
  invoke<IdentityBinding | null>("get_binding", { personalVaultId, teamVaultId, profileUid });
export const listBindings = (personalVaultId: string) =>
  invoke<IdentityBinding[]>("list_bindings", { personalVaultId });
export const deleteBinding = (personalVaultId: string, teamVaultId: string, profileUid: string) =>
  afterMut(
    personalVaultId,
    invoke<void>("delete_binding", { personalVaultId, teamVaultId, profileUid }),
  );
export const resolveHostBinding = (
  personalVaultId: string,
  teamVaultId: string,
  profileUid: string,
  currentDestination: string,
) =>
  invoke<BindingResolution>("resolve_host_binding", {
    personalVaultId,
    teamVaultId,
    profileUid,
    currentDestination,
  });
/** Resolve a Personal profile's connect auth in-core (binding → identity +
 *  anti-redirect). Rejects if unbound or the destination changed since binding. */
export const resolvePersonalAuth = (
  teamVaultId: string,
  profileUid: string,
  currentDestination: string,
  profileUserFallback: string,
) =>
  invoke<PersonalAuth>("resolve_personal_auth", {
    teamVaultId,
    profileUid,
    currentDestination,
    profileUserFallback,
  });
/** Canonical anti-redirect destination string (includes the username template).
 *  Use for BOTH the bind pin and the connect `currentDestination` so they match. */
export const personalDestination = (
  host: string,
  port: number,
  usernameTemplate: string | null | undefined,
  jumps: JumpHost[],
) =>
  invoke<string>("personal_destination", {
    host,
    port,
    usernameTemplate: usernameTemplate ?? null,
    // Anti-redirect pins the ProxyJump chain too — a mutated chain must change
    // the destination so a bound personal credential isn't routed via a MITM hop.
    jumps,
  });
/** Final connect username: applies the username template (`%u`→baseUser), else `baseUser`. */
export const applyUsernameTemplate = (baseUser: string, usernameTemplate?: string | null) =>
  invoke<string>("apply_username_template", { baseUser, usernameTemplate: usernameTemplate ?? null });

/** Resolve a profile's connect {user, auth} for an INTERACTIVE connection.
 *  Personal profiles are resolved in-core (binding → identity + anti-redirect,
 *  rejecting on Unbound/Redirected) and get the resolved connect username;
 *  everything else uses the stored ProfileAuth. `vaultId` is the profile's vault
 *  (the team vault for a Personal host). Throws on a Personal resolution error —
 *  callers surface it. Not for fan-out (Personal is excluded there — B6). */
export async function resolveConnectAuth(
  profile: ConnectionProfile,
  vaultId: string,
  promptedPassword?: string,
): Promise<{ user: string; auth: AuthMethod }> {
  if (profile.auth.type === "personal") {
    const dest = await personalDestination(
      profile.host,
      profile.port,
      profile.usernameTemplate,
      profile.jumps,
    );
    const pa = await resolvePersonalAuth(vaultId, profile.uid, dest, profile.user);
    const user = await applyUsernameTemplate(pa.user, profile.usernameTemplate);
    return { user, auth: pa.auth };
  }
  return { user: profile.user, auth: profileToAuth(profile.auth, vaultId, promptedPassword) };
}
export const importSshConfig = (vaultId: string, configText: string) =>
  afterMut(vaultId, invoke<string[]>("import_ssh_config", { vaultId, configText }));
export const exportSshConfig = (vaultId: string) =>
  invoke<string>("export_ssh_config", { vaultId });
export const importPuttySessions = (vaultId: string, regText: string) =>
  afterMut(vaultId, invoke<HostImportReport>("import_putty_sessions", { vaultId, regText }));

// ── groups ─────────────────────────────────────────────────────
export const saveGroup = (vaultId: string, group: ServerGroup) =>
  afterMut(vaultId, invoke<void>("save_group", { vaultId, group }));
export const listGroups = (vaultId: string) => invoke<ServerGroup[]>("list_groups", { vaultId });
export const getGroup = (vaultId: string, groupId: string) =>
  invoke<ServerGroup>("get_group", { vaultId, groupId });
export const deleteGroup = (vaultId: string, groupId: string) =>
  afterMut(vaultId, invoke<void>("delete_group", { vaultId, groupId }));
export const dryRunGroup = (vaultId: string, groupId: string) =>
  invoke<GroupTargetPlan[]>("dry_run_group", { vaultId, groupId });

// ── exec / fleet ───────────────────────────────────────────────
// The vault a credential lives in now rides inside `auth` (and each jump's auth),
// so there is no standalone `vaultId` here — target and hops may span vaults.
export interface ConnectArgs {
  host: string;
  port: number;
  user: string;
  auth: AuthMethod;
  jumps: JumpHost[];
}
export const sshExec = (a: ConnectArgs, command: string) =>
  invoke<SshExecResult>("ssh_exec", { ...a, command });
export const sshExecMulti = (
  targets: MultiExecTarget[],
  command: string,
  maxConcurrency: number,
  timeoutSecs: number,
) => invoke<MultiExecResult[]>("ssh_exec_multi", { targets, command, maxConcurrency, timeoutSecs });
export const sshExecByTags = (
  vaultId: string,
  tags: string[],
  matchAll: boolean,
  command: string,
  maxConcurrency: number,
  timeoutSecs: number,
) =>
  invoke<MultiExecResult[]>("ssh_exec_by_tags", {
    vaultId,
    tags,
    matchAll,
    command,
    maxConcurrency,
    timeoutSecs,
  });
export const sshExecGroup = (
  vaultId: string,
  groupId: string,
  command: string,
  maxConcurrency: number,
  timeoutSecs: number,
) =>
  invoke<MultiExecResult[]>("ssh_exec_group", {
    vaultId,
    groupId,
    command,
    maxConcurrency,
    timeoutSecs,
  });

// ── streaming exec ─────────────────────────────────────────────
export async function execStreamOpen(
  a: ConnectArgs,
  command: string,
  onEvent: (e: ExecEvent) => void,
): Promise<string> {
  const ch = new Channel<ExecEvent>();
  ch.onmessage = onEvent;
  return invoke<string>("exec_stream_open", { ...a, command, onEvent: ch });
}
export const execStreamWrite = (id: string, data: number[]) =>
  invoke<void>("exec_stream_write", { id, data });
export const execStreamClose = (id: string) => invoke<void>("exec_stream_close", { id });

// ── interactive PTY sessions ───────────────────────────────────
export interface OpenSessionArgs extends ConnectArgs {
  term: string;
  cols: number;
  rows: number;
}
export async function sessionOpen(
  a: OpenSessionArgs,
  onEvent: (e: TermEvent) => void,
): Promise<string> {
  const ch = new Channel<TermEvent>();
  ch.onmessage = onEvent;
  return invoke<string>("session_open", { ...a, onEvent: ch });
}
export async function sessionOpenReconnecting(
  a: OpenSessionArgs & { maxRetries: number; backoffMs: number },
  onEvent: (e: TermEvent) => void,
): Promise<string> {
  const ch = new Channel<TermEvent>();
  ch.onmessage = onEvent;
  return invoke<string>("session_open_reconnecting", { ...a, onEvent: ch });
}
export const sessionWrite = (id: string, data: number[]) =>
  invoke<void>("session_write", { id, data });
export const sessionResize = (id: string, cols: number, rows: number) =>
  invoke<void>("session_resize", { id, cols, rows });
export const sessionClose = (id: string) => invoke<void>("session_close", { id });

/** Set the SSH keepalive interval (seconds) for subsequent connections; 0 = off. */
export const setKeepaliveSecs = (secs: number) =>
  invoke<void>("set_keepalive_secs", { secs });

// ── broadcast ──────────────────────────────────────────────────
export async function broadcastOpen(
  targets: MultiExecTarget[],
  term: string,
  cols: number,
  rows: number,
  onEvent: (e: BroadcastEvent) => void,
): Promise<OpenedBroadcast> {
  const ch = new Channel<BroadcastEvent>();
  ch.onmessage = onEvent;
  return invoke<OpenedBroadcast>("broadcast_open", { targets, term, cols, rows, onEvent: ch });
}
export const broadcastWriteAll = (id: string, data: number[]) =>
  invoke<void>("broadcast_write_all", { id, data });
export const broadcastResizeAll = (id: string, cols: number, rows: number) =>
  invoke<void>("broadcast_resize_all", { id, cols, rows });
export const broadcastClose = (id: string) => invoke<void>("broadcast_close", { id });

// ── tunnels ────────────────────────────────────────────────────
export const tunnelOpenLocal = (
  a: ConnectArgs,
  localBind: string,
  remoteHost: string,
  remotePort: number,
) => invoke<OpenedTunnel>("tunnel_open_local", { ...a, localBind, remoteHost, remotePort });
export const tunnelOpenDynamic = (a: ConnectArgs, localBind: string) =>
  invoke<OpenedTunnel>("tunnel_open_dynamic", { ...a, localBind });
export const tunnelOpenRemote = (
  a: ConnectArgs,
  remoteBind: string,
  remotePort: number,
  localHost: string,
  localPort: number,
) =>
  invoke<OpenedTunnel>("tunnel_open_remote", {
    ...a,
    remoteBind,
    remotePort,
    localHost,
    localPort,
  });
export const tunnelClose = (id: string) => invoke<void>("tunnel_close", { id });

// ── SFTP ───────────────────────────────────────────────────────
export const sftpOpen = (a: ConnectArgs, parallelism: number) =>
  invoke<string>("sftp_open", { ...a, parallelism });
export const sftpListDir = (id: string, path: string) =>
  invoke<SftpEntry[]>("sftp_list_dir", { id, path });
export const localListDir = (path: string) => invoke<LocalEntry[]>("local_list_dir", { path });
export const sftpStat = (id: string, path: string) =>
  invoke<SftpFileStat>("sftp_stat", { id, path });
export const sftpRealpath = (id: string, path: string) =>
  invoke<string>("sftp_realpath", { id, path });
export const sftpReopen = (id: string) => invoke<void>("sftp_reopen", { id });
export const sftpMkdir = (id: string, path: string) => invoke<void>("sftp_mkdir", { id, path });
export const sftpRmdir = (id: string, path: string) => invoke<void>("sftp_rmdir", { id, path });
export const sftpRmdirRecursive = (id: string, path: string) =>
  invoke<void>("sftp_rmdir_recursive", { id, path });
export const sftpRemove = (id: string, path: string) => invoke<void>("sftp_remove", { id, path });
export const sftpRename = (id: string, from: string, to: string) =>
  invoke<void>("sftp_rename", { id, from, to });
export const sftpChmod = (id: string, path: string, mode: number) =>
  invoke<void>("sftp_chmod", { id, path, mode });
export const sftpReadFile = (id: string, path: string) =>
  invoke<ArrayBuffer>("sftp_read_file", { id, path });
export const sftpWriteFile = (id: string, path: string, data: number[]) =>
  invoke<void>("sftp_write_file", { id, path, data });
export async function sftpDownload(
  id: string,
  remotePath: string,
  localPath: string,
  offset: number,
  knownSize: number | null,
  onProgress: (p: ProgressEvent) => void,
  cancelId?: string,
): Promise<boolean> {
  const ch = new Channel<ProgressEvent>();
  ch.onmessage = onProgress;
  return invoke<boolean>("sftp_download", {
    id,
    remotePath,
    localPath,
    offset,
    knownSize,
    onProgress: ch,
    cancelId,
  });
}
export async function sftpUpload(
  id: string,
  localPath: string,
  remotePath: string,
  offset: number,
  onProgress: (p: ProgressEvent) => void,
  cancelId?: string,
): Promise<boolean> {
  const ch = new Channel<ProgressEvent>();
  ch.onmessage = onProgress;
  return invoke<boolean>("sftp_upload", {
    id,
    localPath,
    remotePath,
    offset,
    onProgress: ch,
    cancelId,
  });
}
export const sftpClose = (id: string) => invoke<void>("sftp_close", { id });

// ── cancel tokens ──────────────────────────────────────────────
export const cancelNew = () => invoke<string>("cancel_new");
export const cancelTrigger = (id: string) => invoke<void>("cancel_trigger", { id });
export const cancelDispose = (id: string) => invoke<void>("cancel_dispose", { id });

// ── OS keychain (Secret Key on a trusted device) ───────────────
export const keychainAvailable = () => invoke<boolean>("keychain_available");
export const keychainSaveSecretKey = (secretKey: string) =>
  invoke<void>("keychain_save_secret_key", { secretKey });
export const keychainGetSecretKey = () => invoke<string | null>("keychain_get_secret_key");
/** Trusted-device auto-unlock done in Rust: the Secret Key never enters JS. */
export const keychainUnlock = (password: string | null) =>
  invoke<void>("keychain_unlock", { password });
export const keychainDeleteSecretKey = () => invoke<void>("keychain_delete_secret_key");

// ── cloud server: identity / session ───────────────────────────
// The cloud integration is additive: a local-only instance never touches it.
// An instance may be linked to MULTIPLE servers; per-server commands take an
// optional `serverId` and default to the active server when it's omitted.
export const serverStatus = (serverId?: string) =>
  invoke<ServerStatus>("server_status", { serverId: serverId ?? null });
/** Session-less probe of a server instance at `baseUrl`: its name, whether it has
 *  been claimed, its instance id, and advertised sign-in methods. Drives the
 *  Add-server flow's branch (setup-code vs invite/sign-in). PUBLIC — no session. */
export const instanceInfo = (baseUrl: string) =>
  invoke<InstanceInfo>("server_instance_info", { baseUrl });
export const serverList = () => invoke<ServerList>("server_list");
export const serverSetActive = (serverId: string) =>
  invoke<ServerList>("server_set_active", { serverId });
export const serverRemove = (serverId: string) =>
  invoke<ServerList>("server_remove", { serverId });
/** Join an instance via a single-link invite `inviteToken`. The instance is
 *  addressed by `baseUrl` (no tenant id on the wire any more); the granted spaces
 *  come back inside the resulting ServerStatus' link. Joiners are never owners. */
export const serverJoin = (
  baseUrl: string,
  inviteToken: string,
  opts: { displayName?: string; handle?: string } = {},
) =>
  invoke<ServerStatus>("server_join", {
    baseUrl,
    inviteToken,
    displayName: opts.displayName ?? null,
    handle: opts.handle ?? null,
  });
/** Claim an UNCLAIMED instance and become its owner. The `setupCode` (printed by
 *  the server on first boot) authorizes the single-winner claim; the server creates
 *  the owner account + device + a first Space and returns their ids. A claimed
 *  instance returns 409. */
export const serverClaim = (
  baseUrl: string,
  opts: { setupCode: string; displayName?: string; handle?: string; spaceName?: string },
) =>
  invoke<ServerStatus>("server_claim", {
    baseUrl,
    setupCode: opts.setupCode,
    spaceName: opts.spaceName ?? null,
    handle: opts.handle ?? null,
    displayName: opts.displayName ?? null,
  });
export const serverLogin = (serverId?: string) =>
  invoke<ServerStatus>("server_login", { serverId: serverId ?? null });
/** Sign in with SSO (OIDC browser flow). Opens the system browser to the instance's
 *  IdP, catches the loopback redirect, exchanges the code for an id_token, and runs
 *  `POST /v1/oidc/callback` (nonce-bound to the local keyset). Gated on the probed
 *  `instanceInfo().auth.includes("oidc")`. Requires the local keyset to be unlocked.
 *  NOTE: the browser↔IdP round-trip needs a real IdP + browser (manual test). */
export const serverOidcLogin = (baseUrl: string) =>
  invoke<ServerStatus>("server_oidc_login", { baseUrl });
export const serverRefreshSession = (serverId?: string) =>
  invoke<ServerStatus>("server_refresh_session", { serverId: serverId ?? null });
export const serverLogout = (serverId?: string) =>
  invoke<ServerStatus>("server_logout", { serverId: serverId ?? null });
export const serverDisconnect = (serverId?: string) =>
  invoke<ServerList>("server_disconnect", { serverId: serverId ?? null });
/** Preview an invite before joining (does not consume it): the instance name and
 *  the spaces (with roles) it grants. Stateless — no session. */
export const serverJoinPreview = (baseUrl: string, token: string) =>
  invoke<JoinPreview>("server_join_preview", { baseUrl, token });
export const serverDeviceAdd = (serverId?: string) =>
  invoke<string>("server_device_add", { serverId: serverId ?? null });
export const serverListDevices = (serverId?: string) =>
  invoke<DeviceInfo[]>("server_list_devices", { serverId: serverId ?? null });
export const serverDeviceRevoke = (deviceId: string, serverId?: string) =>
  invoke<void>("server_device_revoke", { deviceId, serverId: serverId ?? null });
export const serverAccountProfile = (
  displayName: string | null,
  handle: string | null,
  serverId?: string,
) =>
  invoke<ServerStatus>("server_account_profile", {
    displayName,
    handle,
    serverId: serverId ?? null,
  });

// ── cloud vaults + sync ────────────────────────────────────────
// Bound 1:1 to a server (defaults to the active one) by a space id. `spaceId` picks
// the bound space (an existing space you admin, or one just created); omit it to bind
// to the link's primary space.
export const serverCreateCloudVault = (name: string, serverId?: string, spaceId?: string) =>
  invoke<string>("server_create_cloud_vault", {
    serverId: serverId ?? null,
    name,
    spaceId: spaceId ?? null,
  });
// One-time migration: bind legacy unbound cloud vaults to a server (default active).
export const serverBindUnboundCloudVaults = (serverId?: string) =>
  invoke<number>("server_bind_unbound_cloud_vaults", { serverId: serverId ?? null });
// Bind ONE unbound cloud vault (hex id) to a server (default active) — reclaim an
// orphaned/never-bound vault manually.
export const serverBindCloudVault = (vaultId: string, serverId?: string) =>
  invoke<void>("server_bind_cloud_vault", { vaultId, serverId: serverId ?? null });
export const serverSyncNow = (serverId?: string) =>
  invoke<SyncReport>("server_sync_now", { serverId: serverId ?? null });
/** Full re-pull: reset the pull cursor then sync — recovers vaults that an
 *  incremental sync can't (rejected under a prior identity, cursor already past them). */
export const serverRepull = (serverId?: string) =>
  invoke<SyncReport>("server_repull", { serverId: serverId ?? null });
/** Restore cloud vaults deleted LOCALLY but still live on the server (purge the
 *  local tombstone that shadows the server copy, then re-pull). Returns the count. */
export const serverRestoreDeletedVaults = (serverId?: string) =>
  invoke<number>("server_restore_deleted_vaults", { serverId: serverId ?? null });

// ── cloud membership / sharing ─────────────────────────────────
export const serverListAccounts = (serverId?: string) =>
  invoke<AccountInfo[]>("server_list_accounts", { serverId: serverId ?? null });
export const serverAddMember = (
  vaultId: string,
  memberEd25519Hex: string,
  memberX25519Hex: string,
  role: MemberRole,
) => invoke<void>("server_add_member", { vaultId, memberEd25519Hex, memberX25519Hex, role });
export const serverListMembers = (vaultId: string) =>
  invoke<MemberInfo[]>("server_list_members", { vaultId });
export const serverMemberFingerprint = (ed25519PubHex: string) =>
  invoke<string>("server_member_fingerprint", { ed25519PubHex });
export const serverConfirmMemberPin = (accountId: string, ed25519PubHex: string) =>
  invoke<void>("server_confirm_member_pin", { accountId, ed25519PubHex });
export const serverPinVaultGenesisOwner = (vaultId: string, ed25519PubHex: string) =>
  invoke<void>("server_pin_vault_genesis_owner", { vaultId, ed25519PubHex });
export const setPersonalVault = (vaultId: string) =>
  invoke<void>("set_personal_vault", { vaultId });
export const setAccountDefaultUsername = (username: string) =>
  invoke<void>("set_account_default_username", { username });
export const getPersonalVault = () => invoke<string | null>("get_personal_vault");
export const getAccountDefaultUsername = () =>
  invoke<string | null>("get_account_default_username");
export const serverRotateVk = (vaultId: string, remaining: RemainingMember[]) =>
  invoke<number>("server_rotate_vk", { vaultId, remaining });

// ── cloud spaces / directory / pending / attestations (server-v2) ──
// Each command resolves its Bearer from the server link (defaults to the active
// server), like the sibling identity commands — so they take an optional serverId.
/** Mint a one-link invite for a SINGLE space intent (`spaceId` at `role`) on a
 *  server (defaults to active). Caller must be an admin of that space. `ttlSeconds`
 *  optionally bounds the invite lifetime. The token is shown once (only its hash is
 *  stored server-side). */
export const serverInvite = (
  spaceId: string,
  role: string,
  ttlSeconds?: number,
  serverId?: string,
) =>
  invoke<InviteInfo>("server_invite", {
    spaceId,
    role,
    ttlSeconds: ttlSeconds ?? null,
    serverId: serverId ?? null,
  });
/** The caller's own spaces (with roles) on a server (defaults to active). */
export const serverListSpaces = (serverId?: string) =>
  invoke<SpaceInfo[]>("server_list_spaces", { serverId: serverId ?? null });
/** Create a Space (instance owner) on a server (defaults to active); the creator
 *  becomes its admin. Returns the new space id (base64). */
export const serverCreateSpace = (name: string, serverId?: string) =>
  invoke<string>("server_create_space", { name, serverId: serverId ?? null });
/** Add (idempotent) an account to a space at a role (space-admin) on a server
 *  (defaults to active). */
export const serverAddSpaceMember = (
  spaceId: string,
  accountId: string,
  role: string,
  serverId?: string,
) =>
  invoke<void>("server_add_space_member", {
    spaceId,
    accountId,
    role,
    serverId: serverId ?? null,
  });
/** The shared people directory on a server (defaults to active): handles + hex
 *  canonical keys, ready to feed serverAddMember / serverAddSpaceMember. */
export const serverDirectory = (serverId?: string) =>
  invoke<DirectoryEntry[]>("server_directory", { serverId: serverId ?? null });
/** The caller's outstanding vault-admin crypto actions (grant/revoke) on a server
 *  (defaults to active). Fulfil each via serverAddMember / serverRotateVk. */
export const serverPending = (serverId?: string) =>
  invoke<PendingAction[]>("server_pending", { serverId: serverId ?? null });
/** Publish an OPAQUE key-binding attestation about an account (space-admin) on a
 *  server (defaults to active). `blob`/`signature` are base64, produced+verified by
 *  clients (the server stores them verbatim). */
export const serverAttestationsPut = (
  accountId: string,
  blob: string,
  signature: string,
  serverId?: string,
) =>
  invoke<void>("server_attestations_put", {
    accountId,
    blob,
    signature,
    serverId: serverId ?? null,
  });
/** Every attestation about an account on a server (defaults to active). Opaque
 *  blob+signature (base64); the caller verifies signatures. */
export const serverAttestationsList = (accountId: string, serverId?: string) =>
  invoke<AttestationInfo[]>("server_attestations_list", {
    accountId,
    serverId: serverId ?? null,
  });

// ── cloud devices / onboarding ─────────────────────────────────
/** Escrow this device's (already-encrypted) keyset to a server (defaults to active)
 *  AND arm keyless-escrow sign-in: the escrow K_auth is derived ONCE from the SAME
 *  `password` + `secretKeyHex` that wraps the uploaded blob, so a later
 *  serverEscrowFetchAndUnlock re-derives an identical K_auth. `password` is null for
 *  passwordless/SSO accounts. Returns the stored generation. */
export const serverKeysetPush = (
  password: string | null,
  secretKeyHex: string,
  serverId?: string,
) =>
  invoke<number>("server_keyset_push", {
    password,
    secretKeyHex,
    serverId: serverId ?? null,
  });
export const serverKeysetPullAndUnlock = (
  password: string | null,
  secretKeyHex: string,
  serverId?: string,
) =>
  invoke<void>("server_keyset_pull_and_unlock", {
    password,
    secretKeyHex,
    serverId: serverId ?? null,
  });
/** Fetch the escrow Argon2id params for a `handle` from a server (PUBLIC — no
 *  session). NOTE: a 200 is NOT proof the handle exists (shaped decoy for unknown
 *  handles), so callers must not treat this as an existence oracle. */
export const serverEscrowParams = (baseUrl: string, handle: string) =>
  invoke<EscrowParamsInfo>("server_escrow_params", { baseUrl, handle });
/** Recover this device's keyset from a server's ESCROW by handle and unlock it
 *  (PUBLIC — no session). `password` is null for passwordless/SSO accounts;
 *  `secretKeyHex` is the account Secret Key (Emergency Kit). A wrong password/key
 *  surfaces as the server's 403. */
export const serverEscrowFetchAndUnlock = (
  baseUrl: string,
  handle: string,
  password: string | null,
  secretKeyHex: string,
) =>
  invoke<void>("server_escrow_fetch_and_unlock", {
    baseUrl,
    handle,
    password,
    secretKeyHex,
  });
export const serverOnboardInitiate = (serverId?: string) =>
  invoke<PairingPayload>("server_onboard_initiate", { serverId: serverId ?? null });
export const serverOnboardComplete = (channelId: string, oobCode: string, serverId?: string) =>
  invoke<void>("server_onboard_complete", { channelId, oobCode, serverId: serverId ?? null });
export const serverOnboardJoin = (payload: PairingPayload, password: string | null) =>
  invoke<ServerStatus>("server_onboard_join", {
    baseUrl: payload.baseUrl,
    instanceId: payload.instanceId,
    spaceId: payload.spaceId,
    accountId: payload.accountId,
    deviceId: payload.deviceId,
    channelId: payload.channelId,
    oobCode: payload.oobCode,
    password,
  });

// ── cloud audit (read-only) ────────────────────────────────────
export const serverAuditQuery = (sinceSeq?: number, serverId?: string) =>
  invoke<AuditEntry[]>("server_audit_query", {
    sinceSeq: sinceSeq ?? null,
    serverId: serverId ?? null,
  });
