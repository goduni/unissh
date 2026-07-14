// TypeScript mirrors of the backend DTOs (src-tauri/src/dto.rs). camelCase JSON.

import { i18n } from "@/i18n";

// Vault-qualified credential refs: `vaultId` names the vault holding the
// key/password, so the target and each jump hop can draw from different vaults.
export type AuthMethod =
  | { type: "agent"; vaultId: string; keyItemId: string }
  | { type: "password"; password: string }
  | { type: "vaultPassword"; vaultId: string; passwordItemId: string };

export type ProfileAuth =
  | { type: "key"; keyItemId: string }
  | { type: "vaultPassword"; passwordItemId: string }
  | { type: "promptPassword" }
  // Shared host with no stored creds — log in with a personal identity via a
  // binding (B4). Resolved at connect via `api.resolvePersonalAuth`, not
  // `profileToAuth` (needs an in-core binding lookup + anti-redirect check).
  | { type: "personal" };

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
  tags: string[];
}

export interface ServerGroup {
  groupId: string;
  label: string;
  memberIds: string[];
  parentId?: string | null;
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
}

export interface MultiExecResult {
  host: string;
  stdout: string;
  stderr: string;
  exitStatus: number;
  error?: string | null;
  durationMs: number;
  timedOut: boolean;
}

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
  filename: string;
  isDir: boolean;
  size: number;
  /** Full unix st_mode; 0 when the server didn't report it. */
  mode: number;
  /** Modified time, epoch seconds; 0 when the server didn't report it. */
  mtime: number;
}

export interface SftpFileStat {
  size: number;
  isDir: boolean;
  mode: number;
  mtime: number;
}

export interface LocalEntry {
  name: string;
  isDir: boolean;
  size: number;
  mtime: number;
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
export type TermEvent = { type: "data"; bytes: number[] } | { type: "close"; exit: number };
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
  | "hostKeyMismatch"
  | "ssh"
  | "server"
  | "other";

export interface ApiError {
  kind: ApiErrorKind;
  msg?: string;
  host?: string;
  port?: number;
  fingerprint?: string;
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

/** Resolve a stored ProfileAuth into a connect-time AuthMethod. `vaultId` is the
 *  vault the profile lives in (where its key/password items are). PromptPassword
 *  becomes an inline password the UI must have collected first. */
export function profileToAuth(
  a: ProfileAuth,
  vaultId: string,
  promptedPassword?: string,
): AuthMethod {
  switch (a.type) {
    case "key":
      return { type: "agent", vaultId, keyItemId: a.keyItemId };
    case "vaultPassword":
      return { type: "vaultPassword", vaultId, passwordItemId: a.passwordItemId };
    case "promptPassword":
      return { type: "password", password: promptedPassword ?? "" };
    case "personal":
      // Personal has no cred in this vault — resolve via api.resolvePersonalAuth
      // (binding → identity + anti-redirect). Callers must branch on this before
      // calling profileToAuth.
      throw new Error("personal profiles must be resolved via resolvePersonalAuth");
  }
}

/** UI auth-kind from a stored ProfileAuth (matches AuthBadge's AuthKind). */
export function profileAuthKind(a: ProfileAuth): "key" | "password" | "ask" | "personal" {
  if (a.type === "key") return "key";
  if (a.type === "vaultPassword") return "password";
  if (a.type === "personal") return "personal";
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
      case "hostKeyMismatch":
        return i18n.t("error.hostKeyMismatch", { host: e.host ?? "", port: e.port ?? 0 });
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
  /** The caller's spaces on this server link (name + role), so the UI can name a
   *  vault's bound space (vault.syncTenant = space id) and show spaces in the vault
   *  list/sidebar without a separate round-trip.
   *  TODO(gate): the Rust ServerStatus must serialize this `spaces` array (server-v2
   *  snapshot). Until then it may arrive undefined — callers use `?.`/`?? []`. */
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
