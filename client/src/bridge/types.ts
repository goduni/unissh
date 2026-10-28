// TypeScript mirrors of the backend DTOs (src-tauri/src/dto.rs). camelCase JSON.

import { i18n } from "@/i18n";

// Vault-qualified credential refs: `vaultId` names the vault holding the
// key/password, so the target and each jump hop can draw from different vaults.
export type AuthMethod =
  | { type: "agent"; vaultId: string; keyItemId: string }
  | { type: "password"; password: string }
  | { type: "vaultPassword"; vaultId: string; passwordItemId: string }
  /** A key held by the OS ssh-agent, named by its public key. The route to
   *  hardware: FIDO tokens, PKCS#11 smart cards, Secure Enclave, 1Password,
   *  gpg-agent. For these hosts the key lives outside the vault. */
  | { type: "systemAgent"; publicKey: string };

export type ProfileAuth =
  | { type: "key"; keyItemId: string }
  | { type: "vaultPassword"; passwordItemId: string }
  | { type: "promptPassword" }
  // Shared host with no stored creds — log in with a personal identity via a
  // binding (B4). Resolved at connect in the core (`api.resolveConnection`:
  // binding lookup + anti-redirect check).
  | { type: "personal" }
  /** A key in the OS ssh-agent. The public key is a handle, not a secret. */
  | { type: "systemAgent"; publicKey: string };

/** Host-chain reference (B2.2): a jump hop that points at another saved profile
 *  by its immutable uid (possibly in another vault), resolved to that profile's
 *  host/port/user/auth at connect. When set, the inline JumpHost fields are ignored. */
export interface HopRef {
  vaultId: string;
  profileUid: string;
}

export interface JumpHost {
  host: string;
  port: number;
  user: string;
  auth: AuthMethod;
  hopRef?: HopRef | null;
}

/** Outbound proxy protocol (issue #27). */
export type ProxyKind = "http" | "socks4" | "socks5";

/** Proxy password: a vault reference (storable) or an inline value
 *  (connect-time only — the core refuses to save it into a profile). */
export type ProxyPassword =
  | { type: "vault"; vaultId: string; passwordItemId: string }
  | { type: "inline"; password: string };

/** How to reach a host through an http/socks4/socks5 proxy. Applies to the
 *  FIRST TCP hop only: the target, or hop #1 of the jump chain — later hops
 *  ride direct-tcpip channels inside SSH and cannot be proxied. */
export interface ProxyConfig {
  kind: ProxyKind;
  host: string;
  port: number;
  username?: string | null;
  password?: ProxyPassword | null;
}

export interface ConnectionProfile {
  profileId: string;
  /** Immutable profile uid (minted by core on create; preserved on edit).
   *  Empty string when creating a new host — the core mints it on save. */
  uid: string;
  label: string;
  host: string;
  port: number;
  user: string;
  auth: ProfileAuth;
  /** Username template (gateway-agnostic): `%u` expands to the identity's username.
   *  For gateways that route by encoding the target in the login (e.g. `%u:prod-db`,
   *  `%u@edge`). Empty → plain username. Usually with Personal auth; editing it is
   *  covered by the anti-redirect destination pin. */
  usernameTemplate?: string | null;
  jumps: JumpHost[];
  /** Outbound proxy for the first TCP hop; composes with `jumps`. */
  proxy?: ProxyConfig | null;
  tags: string[];
  /** Snippet ids typed into the shell right after connecting, in order.
   *  Kept on the profile rather than as a flag on the snippet: "run on connect"
   *  has to say where, and a global flag would fire on every host. */
  startupSnippetIds: string[];
  /** Record interactive sessions with this host. Per host, not global:
   *  recording production is a requirement and recording a homelab is noise. */
  recordSessions: boolean;
  /** Serve a forwarded ssh-agent to this host. Off by default: while the
   *  session lives, anything running as you on that machine can ask to sign. */
  agentForward: boolean;
  /** Colour tag palette id (#134) — tells production from staging in the
   *  sidebar and on terminal tabs. Absent → inherited from containing groups. */
  color?: string | null;
  /** Icon id replacing the default host glyph (#134). */
  icon?: string | null;
}

export interface ServerGroup {
  groupId: string;
  label: string;
  memberIds: string[];
  parentId?: string | null;
  /** Colour tag palette id (#134), inherited by the hosts the group contains.
   *  An id resolved per theme in `components/appearance`, never a colour value. */
  color?: string | null;
  /** Icon id for the folder row (#134). Not inherited by member hosts. */
  icon?: string | null;
}

/** Personal identity: SSH creds under one name (username + optional refs to a
 *  key/password item in the SAME vault). Lives in a personal vault and links to
 *  a shared host via a binding (Phase B3), keeping personal creds out of the
 *  shared vault. `identityId` is the item id. */
export interface Identity {
  identityId: string;
  label: string;
  user: string;
  keyItemId?: string | null;
  passwordItemId?: string | null;
}

/** Binds a personal identity to a shared host. Lives in the personal vault
 *  (syncs only across the account's devices), keyed on (teamVaultId, profileUid).
 *  `destinationPin` is the rendered host:port at bind time — the anti-redirect
 *  anchor checked at connect. */
export interface IdentityBinding {
  teamVaultId: string;
  profileUid: string;
  identityItemId: string;
  destinationPin: string;
}

/** Anti-redirect binding-resolution result. `redirected` = the shared host was
 *  re-pointed since binding → show re-bind, do NOT send the personal credential. */
export type BindingResolution =
  | { type: "unbound" }
  | { type: "matched"; identityItemId: string }
  | { type: "redirected"; pinned: string; current: string };

/** Personal auth resolved by the core (after the anti-redirect check) — the
 *  concrete AuthMethod (key/password ref in the personal vault) + the username
 *  to use. Returned by `api.resolvePersonalAuth`. */
export interface PersonalAuth {
  user: string;
  auth: AuthMethod;
}

/** A saved host resolved for a connect by the core (`resolve_connection`): the
 *  destination read from the vault, which a Personal host's anti-redirect check
 *  was made against — connect to this, not to a cached profile. */
export interface ResolvedConnect {
  host: string;
  port: number;
  user: string;
  /** An empty password when `askPassword`: the caller fills in what was typed. */
  auth: AuthMethod;
  jumps: JumpHost[];
  proxy: ProxyConfig | null;
  askPassword: boolean;
}

export type SyncTarget = "local" | "cloud";

export interface VaultInfo {
  vaultId: string;
  name: string;
  /** Local vault (offline only) or Cloud vault (syncs with a server). */
  syncTarget: SyncTarget;
  /** For a cloud vault, the base64 SPACE id it is bound 1:1 to (the server link's
   *  primary Space — see ServerConfig.space_id in Rust; sync scopes to it). null for
   *  local vaults and not-yet-bound legacy cloud vaults.
   *  NOTE: the Rust FFI + client DTO field is still literally `sync_tenant`
   *  (serialized camelCase → `syncTenant`), so this TS name is UNCHANGED under the
   *  instance+space model — only its meaning moved from tenant → space. */
  syncTenant: string | null;
}

/** One vault the caller can access on a server (`GET /v1/vaults`), enriched with this
 *  device's local state so the picker can offer Pull / Push / in-sync per vault. */
export interface ServerVault {
  /** hex vault_id. */
  vaultId: string;
  latestVersion: number;
  tombstone: boolean;
  /** Already present locally on this device. */
  isLocal: boolean;
  /** The local copy is bound to a server. */
  bound: boolean;
  /** The local vault's name if present locally, else null (pull to load it). */
  localName: string | null;
}

// ── vault integrity / maintenance ──────────────────────────────
export type IntegrityFailureKind = "signatureInvalid" | "authorMismatch" | "malformed";

export interface IntegrityIssue {
  itemId: string;
  version: number;
  tombstone: boolean;
  failure: IntegrityFailureKind;
}

export interface VaultIntegrityReport {
  ok: boolean;
  checked: number;
  issues: IntegrityIssue[];
}

/** Biometric unlock on this device (Touch ID on macOS, Windows Hello on
 *  Windows). `supported` is false on every platform without an adapter, on a
 *  Mac that cannot do Touch ID or whose build may not use the protected
 *  Keychain, and on Windows without Windows Hello set up. */
export interface BiometricStatus {
  /** A sealed password is on disk, usable or not: there is something Settings
   *  can forget, whatever the vault's password state is now. */
  stored: boolean;
  supported: boolean;
  /** The sealed password is stored and its biometric-gated device secret
   *  still exists (as far as the platform says without a prompt). */
  enabled: boolean;
  /** The sealed password is stored but its device secret is gone
   *  (fingerprints changed, Windows Hello reset): biometric unlock must be
   *  enabled again. */
  invalidated: boolean;
  /** The sealed password is stored but the platform cannot use biometrics
   *  here now (Windows Hello turned off or its PIN removed, Touch ID gone or
   *  its lid closed): shown as off, with the reason and a way to forget it. */
  stranded: boolean;
  /** The platform's presence prompt can be shown — the Secret-Key-only
   *  startup gate, which stores nothing. */
  presenceSupported: boolean;
  /** The Secret Key is remembered in the OS keychain. Biometric unlock stores
   *  only the password, and the presence gate guards that remembered key, so
   *  without it neither has anything to offer. Without `withSecretKey` it is
   *  asked (and can be true) only when a sealed password is stored. */
  secretKeyRemembered: boolean;
}

/** How the one-off presence prompt before turning the startup gate on ended.
 *  The gate is stored only on "confirmed". */
export type PresenceCheck = "confirmed" | "cancelled" | "unavailable";

/** How `biometric_unlock` ended. "unlocked": the vault is open. "superseded":
 *  nobody is waiting for that prompt any more (the password was chosen, a
 *  newer prompt was asked for, the vault was locked) — the unlock screen
 *  ignores it. Anything else shows the password. */
export type BiometricUnlockOutcome = "unlocked" | "cancelled" | "invalidated" | "noSecretKey" | "superseded";

export type DbConsistencyKind =
  | "orphanItem"
  | "badVersion"
  | "badAuthorLen"
  | "badSignatureLen"
  | "tombstoneNotEmpty"
  | "staleHistory";

export interface DbConsistencyIssue {
  kind: DbConsistencyKind;
  vaultIdHex: string;
  itemIdHex: string;
  detail: string;
}

export interface DbConsistencyReport {
  ok: boolean;
  integrityOk: boolean;
  issues: DbConsistencyIssue[];
}

/** item_type values from the core. */
export enum ItemType {
  SshKey = 1,
  SshCert = 2,
  Connection = 3,
  Password = 4,
  Group = 5,
  Note = 6,
  Identity = 7,
  Binding = 8,
  Snippet = 9,
  Recording = 10,
}

export interface ItemInfo {
  itemId: string;
  itemType: number;
  version: number;
  createdAt: number;
  updatedAt: number;
  hasCertificate: boolean;
}

export interface PublicKeyInfo {
  openssh: string;
  fingerprint: string;
}

export interface KnownHostInfo {
  host: string;
  port: number;
  key: string;
  /** Core-computed SHA256 fingerprint ("SHA256:…") — the same format the
   *  HostKeyMismatch error emits, so stored vs presented are directly comparable. */
  fingerprint: string;
  addedAt: number;
}

export interface KnownHostsImport {
  imported: number;
  skippedHashed: number;
  skippedInvalid: number;
}

export interface HostImportReport {
  createdIds: string[];
  skipped: number;
}

export interface SshExecResult {
  stdout: string;
  stderr: string;
  exitStatus: number;
}

export interface MultiExecTarget {
  host: string;
  port: number;
  user: string;
  auth: AuthMethod;
  jumps: JumpHost[];
  proxy?: ProxyConfig | null;
  /** Log in to the target with its key only: no keyboard-interactive, so no
   *  password prompt can stand in for the key (proving a key works). */
  publickeyOnly?: boolean;
}

export interface MultiExecResult {
  host: string;
  stdout: string;
  stderr: string;
  exitStatus: number;
  error?: string | null;
  durationMs: number;
  timedOut: boolean;
  /** Set when the target was a key-only login (`publickeyOnly`) that failed
   *  with an answer about the key itself: the server refused it, or accepted it
   *  and asked for a second factor. Absent for every other result. */
  keyLogin?: KeyLoginFailure | null;
}

export type KeyLoginFailure = "refused" | "acceptedNeedsMore";

export type ResolveStatus =
  | "ok"
  | "dangling"
  | "promptPassword"
  | "cycleSkipped"
  | "personal";

export interface GroupTargetPlan {
  memberId: string;
  host: string;
  port: number;
  user: string;
  status: ResolveStatus;
}

export interface SftpEntry {
  sizeKnown?: boolean;
  filename: string;
  isDir: boolean;
  size: number;
  /** Full unix st_mode; 0 when the server didn't report it. */
  mode: number;
  /** Modified time, epoch seconds; 0 when the server didn't report it. */
  mtime: number;
  /** Owner uid / gid (numeric); 0 when the server didn't report it. */
  uid: number;
  gid: number;
}

export interface SftpFileStat {
  sizeKnown?: boolean;
  size: number;
  isDir: boolean;
  mode: number;
  mtime: number;
}

export interface LocalEntry {
  mode?: number;
  name: string;
  isSymlink: boolean;
  isDir: boolean;
  size: number;
  mtime: number;
}

/** A mounted volume the SFTP local pane can jump to. `label` is the OS's name
 *  for it where there is one (Windows volume label, a USB stick's name) and ""
 *  where there isn't — show `path` then. */
export interface LocalVolume {
  label: string;
  path: string;
  totalBytes: number;
  freeBytes: number;
  removable: boolean;
}

export interface BroadcastHostStatus {
  host: string;
  index: number;
  connected: boolean;
  error?: string | null;
}

export interface OpenedTunnel {
  id: string;
  bindAddress: string;
}

export interface OpenedBroadcast {
  id: string;
  statuses: BroadcastHostStatus[];
}

/** The shell a local terminal would start by default, plus who and where this
 *  machine is. Feeds the Settings placeholder and the actual open. */
export interface LocalShellInfo {
  program: string;
  args: string[];
  /** OS account this app runs as — half of the local pane's status line. */
  user: string;
  /** This machine's hostname — the other half, and what tells a local pane apart
   *  from a remote one at a glance. */
  hostname: string;
}

/** What a local pane runs, resolved once when the pane is created.
 *
 *  A snapshot, not a live read of the settings: Restart brings up the same shell
 *  the pane was opened with, and editing the settings does not rewrite what is
 *  already running. */
export interface LocalPaneSpec {
  /** Absolute path — the empty "auto" setting is resolved before this exists. */
  shell: string;
  args: string[];
  cwd?: string;
  /** Bare program name ("zsh", "pwsh") — the tab's title until the shell sets one. */
  label: string;
}

export interface InstanceStatus {
  exists: boolean;
  /** Exactly one of the instance's two files (DB / keyset) is present on disk —
   *  a half-written instance that can't be unlocked or recreated. UI shows repair. */
  partial: boolean;
  unlocked: boolean;
  /** Whether the instance needs a master password to unlock; null when there's no
   *  readable keyset. `false` → passwordless, so "start unlocked" auto-unlock works. */
  requiresPassword: boolean | null;
}

// ── streaming channel payloads ─────────────────────────────────
/** Which recognised password prompt the core is offering the login password at. */
export type FillPromptKind = "sudo" | "doas" | "generic";
/** A change in a session's saved-password offer. Carries no secret and no
 *  output — the core decides what is a prompt and types the password itself. */
export type FillEvent =
  | {
      type: "offered";
      kind: FillPromptKind;
      /** Names this offer to `sessionFillPassword`; increases per session. */
      offerId: number;
      /** The account a sudo/doas prompt names; null for a bare prompt. */
      user: string | null;
      /** A saved password was rejected on this session already. */
      rejectedBefore: boolean;
    }
  | { type: "withdrawn"; offerId: number }
  | { type: "rejected" }
  /** The core masked the echoed password and killed the line (Ctrl-U). */
  | { type: "echoed" };
/** At which password prompts a session may offer its saved login password. */
export type PasswordFillMode = "off" | "sudoOnly" | "sudoAndGeneric";
export type TermEvent =
  | { type: "data"; bytes: number[] }
  | { type: "close"; exit: number }
  | { type: "fill"; event: FillEvent };
export type ExecEvent =
  | { type: "stdout"; bytes: number[] }
  | { type: "stderr"; bytes: number[] }
  | { type: "exit"; exit: number };
export type BroadcastEvent =
  | { type: "data"; index: number; bytes: number[] }
  | { type: "close"; index: number; exit: number };
export interface ProgressEvent {
  transferred: number;
  total: number;
}

// ── error ──────────────────────────────────────────────────────
export type ApiErrorKind =
  | "locked"
  | "invalidCredentials"
  | "notFound"
  | "alreadyExists"
  | "alreadyCloud"
  | "readOnlyVault"
  | "noServer"
  | "hostKeyMismatch"
  | "rotationInProgress"
  | "rotationPartlyFinished"
  | "ssh"
  | "server"
  | "other";

export interface ApiError {
  kind: ApiErrorKind;
  msg?: string;
  host?: string;
  port?: number;
  fingerprint?: string;
  /** `rotationInProgress` variant: the live candidate's item id. */
  candidateId?: string;
  /** `rotationPartlyFinished` variant: the original key's item id. */
  keyId?: string;
  /** `server` variant: the server's snake_case code + message. */
  code?: string;
  message?: string;
}

/** True if `e` is a cloud-server ApiError with the given code (e.g. "unauthenticated"). */
export function isServerErrorCode(e: unknown, code: string): boolean {
  return isApiError(e) && e.kind === "server" && e.code === code;
}

export function isApiError(e: unknown): e is ApiError {
  return typeof e === "object" && e !== null && "kind" in e;
}

/** Detect a host-key mismatch in a per-host error STRING and recover the FAILING
 *  HOP's host/port/fingerprint. Batched APIs (ssh_exec_multi, broadcast_open)
 *  flatten per-host connect errors to strings, so the structured ApiError is
 *  unavailable there; the only signal left is `HostKeyMismatch`'s Display text.
 *  Two core variants exist and both are matched:
 *    - ffi/src/lib.rs:105          "host key mismatch for {host}:{port}; presented {fp}"
 *    - ssh-transport/src/error.rs  "host key mismatch for {host}:{port} (possible MITM); presented {fp}"
 *  The host:port belongs to the hop that actually failed — for a jump-host chain
 *  that's the *jump* host, not the profile — so callers must trust the PARSED
 *  host/port over the profile's. Returns null for any other error. trust_host
 *  re-verifies the fingerprint against the live host before pinning, so a
 *  stale/garbled parse can never pin a wrong key. */
export function mismatchFromError(
  err: string | null | undefined,
): { host: string; port: number; fingerprint: string } | null {
  const m = err?.match(/host key mismatch for (.+?):(\d+)(?: \(possible MITM\))?; presented (\S+)/);
  return m ? { host: m[1], port: Number(m[2]), fingerprint: m[3] } : null;
}

/** UI auth-kind from a stored ProfileAuth (matches AuthBadge's AuthKind). */
export function profileAuthKind(
  a: ProfileAuth,
): "key" | "password" | "ask" | "personal" | "systemAgent" {
  if (a.type === "key") return "key";
  if (a.type === "vaultPassword") return "password";
  if (a.type === "personal") return "personal";
  if (a.type === "systemAgent") return "systemAgent";
  return "ask";
}

/** Localized message for an ApiError. Raw backend `e.msg` stays untranslated
 *  (out of i18n scope) with a localized generic fallback. */
export function apiErrorMessage(e: unknown): string {
  if (isApiError(e)) {
    switch (e.kind) {
      case "locked":
        return i18n.t("error.locked");
      case "invalidCredentials":
        return i18n.t("error.invalidCredentials");
      case "notFound":
        return i18n.t("error.notFound");
      case "alreadyExists":
        return i18n.t("error.alreadyExists");
      case "alreadyCloud":
        return i18n.t("error.alreadyCloud");
      case "readOnlyVault":
        return i18n.t("error.readOnlyVault");
      case "noServer":
        return i18n.t("error.noServer");
      case "hostKeyMismatch":
        return i18n.t("error.hostKeyMismatch", { host: e.host ?? "", port: e.port ?? 0 });
      case "rotationInProgress":
        return i18n.t("error.rotationInProgress", { item: e.candidateId ?? "" });
      case "rotationPartlyFinished":
        return i18n.t("error.rotationPartlyFinished", { item: e.keyId ?? "" });
      case "ssh":
        return e.msg || i18n.t("error.sshGeneric");
      case "server":
        return e.message || i18n.t("error.serverGeneric");
      default:
        return e.msg || i18n.t("error.generic");
    }
  }
  return String((e as Error)?.message ?? e);
}

// ── cloud server ───────────────────────────────────────────────

/** A staged key rotation in progress on this device (ids only). */
export interface KeyRotationLink {
  keyId: string;
  candidateId: string;
  /** Started on another device: only abandon is possible here, not finish. */
  startedElsewhere: boolean;
}

/** How a host uses a key or password item. */
export type KeyUseRole = "login" | "inlineHop" | "referencedHop" | "proxyPassword";

/** What in a vault uses one key or password item — the core's single answer
 *  (`key_usage`, #169), shared with the CLI. Ids and labels only. */
export interface KeyUsage {
  /** Hosts using it, each once, with every way it does. */
  hosts: { profileId: string; label: string; roles: KeyUseRole[] }[];
  /** Identities referencing it as their key or password. */
  identities: { identityId: string; label: string }[];
}

export interface ServerStatus {
  /** Local, stable id of this server link (null when nothing is linked). */
  serverId: string | null;
  /** A server is linked (config persisted). */
  connected: boolean;
  /** This is the active server (argument-less commands resolve to it). */
  active: boolean;
  /** A live access token is held (this process can make authenticated calls). */
  hasSession: boolean;
  baseUrl: string | null;
  /** base64 opaque server-instance id (from claim/join) — the link identity. */
  instanceId: string | null;
  accountId: string | null;
  deviceId: string | null;
  handle: string | null;
  /** This account owns (claimed) the instance's first Space — eligible to hold the
   *  personal vault. */
  owned: boolean;
  /** base64 space id — this link's cloud-vault binding label. A cloud vault whose
   *  `syncTenant` equals this is bound to THIS server; unlike `spaces` it needs no
   *  live session, so the vault→server attribution resolves even when signed out.
   *  null when the link has no space yet. */
  spaceId: string | null;
  /** The caller's spaces on this server link (name + role), so the UI can name a
   *  vault's bound space (vault.syncTenant = space id) and show spaces in the vault
   *  list/sidebar without a separate round-trip. The Rust ServerStatus always
   *  serializes this as an array (empty until a session fetches /v1/spaces); callers
   *  still guard with `?? []` defensively. */
  spaces: SpaceInfo[];
}

/** Public, session-less probe of a server instance (`instanceInfo`): its display
 *  name, whether it has been claimed yet, its opaque instance id, and the sign-in
 *  auth methods it advertises. Drives the Add-server flow's branch: `!claimed` →
 *  setup-code (claim); claimed → invite-link (join) or sign-in.
 *  TODO(gate): backed by the Rust `server_instance_info` command (added at the gate). */
export interface InstanceInfo {
  claimed: boolean;
  name: string;
  version: string;
  instanceId: string;
  /** Advertised sign-in methods, e.g. `["password", "oidc"]`. */
  auth: string[];
  /** IdP hints for "Sign in with SSO" — present iff `auth` includes `"oidc"`. */
  oidc?: { issuer: string; clientId: string };
}

/** The full set of linked cloud servers plus the active selection. */
export interface ServerList {
  servers: ServerStatus[];
  active: string | null;
}

export interface SyncReport {
  applied: number;
  skippedStale: number;
  conflicts: number;
  rejected: number;
  pushed: number;
  /** Items the server refuses as too large: NOT uploaded (everything else was).
   *  Reported by every sync until the item changes or a manual sync gets it through. */
  tooLarge: TooLargeItem[];
}

/** An item the sync server refuses as too large: over its `limits.max_object_bytes`,
 *  or over the body limit of a reverse proxy in front of it. */
export interface TooLargeItem {
  vaultId: string;
  vaultName: string;
  itemId: string;
  /** The core's item type ({@link ItemType}), to name the item by kind. */
  itemType: number;
  /** Size of the refused sync object, in bytes. */
  bytes: number;
}

/** Result of moving a local vault to a server: the new cloud vault id (hex) and the
 *  first push — `push` on success (it may still name items the server refused as
 *  too large), `pushError` when it failed (the move stands; the vault stays bound
 *  and a later sync of its space uploads it). */
export interface MovedVault {
  vaultId: string;
  push: SyncReport | null;
  pushError: ApiError | null;
}

export type MemberRole = "viewer" | "editor" | "admin";

export interface MemberInfo {
  ed25519PubHex: string;
  role: MemberRole;
  fingerprint: string;
}

export interface RemainingMember {
  ed25519PubHex: string;
  x25519PubHex: string;
  role: MemberRole;
}

export interface AccountInfo {
  accountId: string;
  displayName: string | null;
  handle: string | null;
  isAdmin: boolean;
  ed25519PubHex: string | null;
  x25519PubHex: string | null;
  status: string;
  deviceCount: number;
}

export interface DeviceInfo {
  deviceId: string;
  /** The name the device gave itself (e.g. `CLI · Linux`), if any. */
  label?: string | null;
  status: string;
  registeredAt: number;
  activeSessions: number;
}

/** Produced by the existing device; carried to the new device over a trusted
 *  side channel (QR / read-aloud). `oobCode` is the PAKE secret. */
export interface PairingPayload {
  baseUrl: string;
  /** Opaque server-instance id (base64) — keys the new device's link. */
  instanceId: string;
  /** Cloud-vault binding label (space id, base64) the new device inherits. */
  spaceId: string;
  accountId: string;
  deviceId: string;
  channelId: string;
  oobCode: string;
}

/** One space an invite grants, in a `serverJoinPreview` (read-only; does not
 *  consume the invite). */
export interface JoinPreviewSpace {
  spaceId: string;
  name: string;
  role: string;
}

/** Read-only preview of an invite: the instance name + the spaces it grants. */
export interface JoinPreview {
  instanceName: string | null;
  spaces: JoinPreviewSpace[];
}

// ── cloud spaces / directory / pending / attestations (server-v2) ──

/** One space the caller is a member of (`serverListSpaces`). `role` is the
 *  caller's server-trusted role in that space (`admin` | `member`). */
export interface SpaceInfo {
  spaceId: string;
  name: string;
  role: string;
}

/** A freshly-minted invite (`serverInvite`). `token` is returned exactly once
 *  (only its hash is stored server-side); `url` is the shareable join link when
 *  the server has a public URL configured, else null. */
export interface InviteInfo {
  inviteId: string;
  token: string;
  url: string | null;
  expiresAt: number;
}

/** One person in the shared directory (`serverDirectory`). Pubkeys are hex, ready
 *  to feed serverAddMember / serverAddSpaceMember directly. */
export interface DirectoryEntry {
  accountId: string;
  handle: string | null;
  displayName: string | null;
  ed25519PubHex: string;
  x25519PubHex: string;
  status: string;
}

/** One outstanding vault-admin crypto action (`serverPending`): a `grant` or
 *  `revoke` for `accountId` on the vault. Hex ids/pubkeys feed serverAddMember /
 *  serverRotateVk; opaque server ids + binding `proof` stay base64. */
export interface PendingAction {
  actionId: string;
  kind: string;
  vaultIdHex: string;
  accountId: string;
  ed25519PubHex: string | null;
  x25519PubHex: string | null;
  cryptoRole: number | null;
  source: string;
  proof: string | null;
  createdAt: number;
}

/** One opaque key-binding attestation about an account (`serverAttestationsList`).
 *  `blob` + `signature` are base64 the CLIENT verifies (the server never interprets
 *  them); `attestorPubkey` is the attesting device's Ed25519 (base64). */
export interface AttestationInfo {
  attestorPubkey: string;
  blob: string;
  signature: string;
  createdAt: number;
}

/** Argon2id params for keyless-escrow K_auth re-derivation (`serverEscrowParams`).
 *  `argonSalt` is base64. NOT an existence oracle (the server returns a shaped
 *  decoy of the same form for unknown/unenrolled handles). */
export interface EscrowParamsInfo {
  argonSalt: string;
  argonMemKib: number;
  argonIterations: number;
  argonParallelism: number;
}

export interface AuditEntry {
  seq: number;
  source: string;
  recordedAt: number;
  authorPubkey: string | null;
}
