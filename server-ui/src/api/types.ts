// Wire types — mirror the server's JSON response shapes (architecture spec §2.2).
// Verified against server/src/modules/{admin,ops,identity,instance,escrow,spaces,
// pending}.rs. Instance-scoped (v2): no tenant_id anywhere. All crypto blobs are
// base64 strings; *_seq / *_expires / *_at are integers.

// ── Enums (open metadata) ──────────────────────────────────────
export enum ObjectTag {
  Vault = 1,
  Item = 2,
  Manifest = 3,
  Grant = 4,
  Audit = 5,
  Keyset = 6,
}
export const OBJECT_TAG_LABEL: Record<number, string> = {
  1: "Vault",
  2: "Item",
  3: "Manifest",
  4: "Grant",
  5: "Audit",
  6: "Keyset",
};

export type VaultRole = "viewer" | "editor" | "admin";
export const ROLE_BY_CODE: Record<number, VaultRole> = {
  0: "viewer",
  1: "editor",
  2: "admin",
};
export const CODE_BY_ROLE: Record<VaultRole, number> = {
  viewer: 0,
  editor: 1,
  admin: 2,
};

export const SYNC_TARGET_LABEL: Record<number, string> = {
  0: "Local",
  1: "Cloud",
};
export const CACHE_POLICY_LABEL: Record<number, string> = {
  0: "OfflineAllowed",
  1: "OnlineOnly",
};

export type InviteState = "pending" | "redeemed" | "expired" | "revoked";
export type AccountStatus = "active" | "disabled";
export type DeviceStatus = "active" | "revoked";
export type AuditSource = "client-signed" | "server-observed";

// ── Service ────────────────────────────────────────────────────
export interface VersionInfo {
  api: number;
  server: string;
}

// ── Instance identity (GET /v1/instance) + claim (POST /v1/claim) ──
export interface InstanceInfo {
  claimed: boolean;
  name: string | null;
  version: string;
  instance_id: string;
  /** Enabled sign-in mechanisms, e.g. ["password"] or ["password", "oidc"]. */
  auth: string[];
}
export interface ClaimReq {
  setup_code: string;
  registration_payload: string;
  registration_signature: string;
  display_name?: string;
  handle?: string;
  space_name?: string;
}
export interface ClaimResp {
  account_id: string;
  device_id: string;
  space_id: string;
  instance_id: string;
}

// ── Anti-rollback generation ───────────────────────────────────
/** Anti-rollback generation + floor (GET /v1/admin/instance). */
export interface InstanceGeneration {
  generation: number;
  min_floor: number;
}

// ── Admin overview (instance-scoped) ───────────────────────────
export interface AdminOverview {
  instance_id: string;
  name: string | null;
  claimed: boolean;
  next_seq: number;
  accounts: number;
  owners: number;
  devices: number;
  active_sessions: number;
  vaults: number;
  objects: number;
  pending_invites: number;
  instance_generation: number;
}

export interface DeviceRow {
  device_id: string;
  status: DeviceStatus;
  registered_at: number;
  active_sessions: number;
}
export interface DevicesResp {
  devices: DeviceRow[];
}

export interface SessionRow {
  session_id: string;
  account_id: string;
  device_id: string;
  access_expires: number;
  refresh_expires: number;
  created_at: number;
}
export interface SessionsResp {
  sessions: SessionRow[];
}

// v2 invites carry per-space intents, not a single role/scope. The admin listing
// (GET /v1/admin/invites) is read-only metadata: id, lifecycle state, timestamps.
export interface InviteRow {
  invite_id: string;
  state: InviteState;
  expires_at: number;
  created_at: number;
  redeemed_at: number | null;
}
export interface InvitesResp {
  invites: InviteRow[];
}

export interface VaultRow {
  vault_id: string;
  owner_pubkey: string;
  latest_version: number;
  latest_epoch: number;
  sync_target: number;
  cache_policy: number;
  tombstone: boolean;
}
export interface VaultsResp {
  vaults: VaultRow[];
}

export interface ObjectMeta {
  server_seq: number;
  object_tag: number;
  vault_id: string | null;
  item_id: string | null;
  obj_version: number | null;
  key_epoch: number | null;
  tombstone: boolean | null;
  author_pubkey: string | null;
  received_at: number;
  blob_len: number;
}
export interface ObjectsResp {
  items: ObjectMeta[];
  has_more: boolean;
  next_cursor: number;
}

export interface RelayChannel {
  channel_id: string;
  state: string;
  expires_at: number;
  created_at: number;
}
export interface RelayResp {
  channels: RelayChannel[];
}

export interface KeysetGen {
  generation: number;
  uploaded_at: number;
}
export interface KeysetsResp {
  keysets: KeysetGen[];
}

/** Raw Prometheus render (GET /v1/admin/metrics). */
export interface MetricsRaw {
  enabled: boolean;
  prometheus: string | null;
}

/** Ring-buffer time series (GET /v1/admin/metrics/summary, P1.3). */
export interface MetricsPoint {
  t: number; // unix seconds
  v: number; // cumulative counter
}
export interface MetricsSummary {
  enabled: boolean;
  // Omitted by the server when metrics are disabled ({enabled:false, series:null}).
  sample_interval_seconds?: number;
  retained_samples?: number;
  series: Record<string, MetricsPoint[]> | null;
}

/** Detailed diagnostics (GET /v1/admin/health, P1.2). */
export interface HealthInfo {
  status: "ok" | "degraded";
  version: string;
  uptime_seconds: number;
  db: {
    backend: string;
    reachable: boolean;
    pool: { in_use: number; idle: number; size: number; max: number };
  };
  janitor: {
    interval_seconds: number;
    last_run: number | null;
    last_run_age_seconds: number | null;
  };
  tls: string;
  trust_proxy: boolean;
}

/** Hot-reloadable config keys (PUT /v1/admin/config, P2.8). */
export interface ConfigPutReq {
  validate_signatures?: boolean;
  max_object_bytes?: number;
  max_objects_per_push?: number;
}
export interface ConfigPutResp {
  validate_signatures: boolean;
  max_object_bytes: number;
  max_objects_per_push: number;
  note: string;
}

export interface SeqBumpResp {
  old: number;
  new: number;
}

export interface Migration {
  version: number;
  description: string;
}
export interface MigrationsResp {
  migrations: Migration[];
}

export interface AuditVerify {
  ok: boolean;
  count: number;
  broken_at: number | null;
  head_hash: string | null;
}

// Config: effective config with masked secrets ("***"). Source-of-value isn't
// surfaced by the server, so we render the value + a derived "secret" marker.
export interface ConfigResp {
  server: Record<string, unknown>;
  db: Record<string, unknown>;
  limits: Record<string, unknown>;
  sync: Record<string, unknown>;
  session: Record<string, unknown>;
  obs: Record<string, unknown>;
  setup: Record<string, unknown>;
  oidc: Record<string, unknown>;
  ops: Record<string, unknown>;
}

// ── Identity ───────────────────────────────────────────────────
export interface AccountRow {
  account_id: string;
  display_name: string | null;
  handle: string | null;
  is_owner: boolean;
  member_pubkey: string | null;
  /** X25519 encryption key (P0) — needed for HPKE-wrapping the VK on rotation. */
  x25519_pub: string | null;
  status: AccountStatus;
  device_count: number;
  /** Self-attested registration (M14): canonical payload + signature (base64).
   *  The panel verifies x25519<->ed25519 binding with the signature before
   *  wrapping the VK. NULL for pre-M14 accounts (legacy/unverifiable). */
  reg_payload: string | null;
  reg_signature: string | null;
}
export interface AccountsResp {
  accounts: AccountRow[];
}

export interface AuthChallenge {
  host: string;
  account_id: string;
  device_id: string;
  key_id: string;
  nonce: string;
  expiry: number;
}
export interface VerifyResp {
  access_token: string;
  refresh_token: string;
  access_expires: number;
  refresh_expires: number;
  session_id: string;
}
// v2 invite intents (POST /v1/invite). A space intent joins `space_id` at server-
// trusted `role` ("member" | "admin"); a vault intent enqueues a `grant` for
// `vault_id` at crypto role (0|1|2). See server identity.rs invite_issue_v2.
export interface SpaceIntent {
  space_id: string;
  role: string;
}
export interface VaultIntent {
  vault_id: string;
  role: number;
}
export interface InviteIssueReq {
  space_intents: SpaceIntent[];
  vault_intents?: VaultIntent[];
  ttl_seconds?: number;
}
export interface InviteIssueResp {
  invite_id: string;
  token: string;
  /** `{public_url}/join#<token>` when the server has a public_url configured, else null. */
  url: string | null;
  expires_at: number;
}

export interface AuditEntry {
  seq: number;
  entry_blob: string;
  signature: string | null;
  author_pubkey: string | null;
  recorded_at: number;
  source: AuditSource;
}
export interface AuditResp {
  entries: AuditEntry[];
  has_more: boolean;
  next_since: number;
}

/**
 * `/v1/grants` returns the manifest + grants as base64 of their SyncObject wire
 * envelopes (NOT decoded JSON). Decode the manifest with util/grant-codec to get
 * the member set; the grant blobs carry the per-member HPKE-wrapped VK.
 */
export interface GrantsResp {
  manifest: string; // base64 SyncObject manifest envelope (tag 3)
  grants: string[]; // base64 SyncObject grant envelopes (tag 4)
  key_epoch: number;
}

// ── Escrow sign-in (Phase 2, public) ───────────────────────────
/** Argon2id params to re-derive K_auth (GET /v1/escrow/params?handle=). */
export interface EscrowParams {
  argon_salt: string;
  argon_mem_kib: number;
  argon_iterations: number;
  argon_parallelism: number;
}
/** Encrypted keyset recovered by handle (POST /v1/escrow/fetch). */
export interface EscrowFetchResp {
  keyset_blob: string;
  generation: number;
  account_id: string;
}

// ── Keyset upload (PUT /v1/keyset) ─────────────────────────────
/** Optional escrow enrollment carried with a keyset upload. The client sends the
 *  RAW `k_auth`; the server persists only sha256(k_auth), never the raw credential. */
export interface KeysetEscrowIn {
  k_auth: string;
  argon_salt: string;
  argon_mem_kib: number;
  argon_iterations: number;
  argon_parallelism: number;
}
export interface KeysetPutReq {
  keyset_blob: string;
  escrow?: KeysetEscrowIn;
}
export interface KeysetPutResp {
  generation: number;
}

// ── Spaces (server-trusted groupings) ──────────────────────────
export interface SpaceInfo {
  space_id: string;
  name: string;
  /** The caller's role in this space ("admin" | "member"). */
  role: string;
}
export interface SpacesResp {
  spaces: SpaceInfo[];
}
export interface CreateSpaceResp {
  space_id: string;
}

// ── Directory (shared people address book) ─────────────────────
export interface DirEntry {
  account_id: string;
  handle: string | null;
  display_name: string | null;
  /** Canonical member-id (Ed25519 keyset, base64). */
  member_pubkey: string;
  x25519_pub: string;
  status: string;
}
export interface DirectoryResp {
  accounts: DirEntry[];
}

// ── Pending crypto queue (vault-admin to-do list) ──────────────
export interface PendingAction {
  action_id: string;
  kind: string;
  vault_id: string;
  account_id: string;
  /** Target account's canonical Ed25519 keyset (base64); null if keyless. */
  member_pubkey: string | null;
  /** Target account's X25519 key (base64) — recipient of the HPKE-wrapped VK. */
  x25519_pub: string | null;
  crypto_role: number | null;
  source: string;
  /** Opaque binding MAC (base64) or null. */
  proof: string | null;
  created_at: number;
}
export interface PendingResp {
  actions: PendingAction[];
}

// ── Key-binding attestations ───────────────────────────────────
export interface AttestationInfo {
  attestor_pubkey: string;
  blob: string;
  signature: string;
  created_at: number;
}
export interface AttestationsResp {
  attestations: AttestationInfo[];
}
