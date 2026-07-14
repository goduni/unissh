// CryptoProvider — the seam between the SPA and the real rust-core crypto
// (compiled to wasm in crypto-wasm/, registered at startup). The foundation and
// every non-crypto screen compile and run against the interface; the keyset
// unlock + grant rotation call through to the registered provider.
//
// Byte-compatibility note: the real implementation wraps the verified
// crypto/keychain/vault functions (sign domains unissh-server-auth-v1 /
// unissh-registration-v1 / unissh-manifest-v1 / unissh-grant-v1 / unissh-sig-v1)
// so the server accepts signatures under `validate_signatures`.

export interface KeysetIdentity {
  ed25519_pub: Uint8Array;
  x25519_pub: Uint8Array;
  generation: number;
}

export interface ChallengeInput {
  host: Uint8Array;
  account_id: Uint8Array;
  device_id: Uint8Array;
  key_id: Uint8Array;
  nonce: Uint8Array;
  expiry: number;
}

export interface MemberSpec {
  ed25519_pub: Uint8Array;
  x25519_pub: Uint8Array;
  role: number; // 0 viewer · 1 editor · 2 admin
}

export interface ManifestOut {
  manifest: Uint8Array;
  signature: Uint8Array;
  author_pubkey: Uint8Array;
}

export interface GrantOut {
  wrapped_vk: Uint8Array;
  signature: Uint8Array;
  author_pubkey: Uint8Array;
}

export interface NewAccount {
  /** EncryptedKeyset bytes to persist / download as the .keyset file. */
  enc: Uint8Array;
  /** Secret Key (Emergency Kit) — show once. */
  secretKey: Uint8Array;
  ed25519_pub: Uint8Array;
  x25519_pub: Uint8Array;
}

export interface RegistrationOut {
  /** Canonical registration_payload bytes. */
  payload: Uint8Array;
  /** Ed25519 signature over the domain-separated payload. */
  signature: Uint8Array;
}

export interface CryptoProvider {
  /** Whether a real implementation is loaded (false → the wasm stub). */
  readonly available: boolean;
  /** Generate a fresh keyset identity (for bootstrap). */
  createAccount(password: string | null): Promise<NewAccount>;
  /** Decrypt an EncryptedKeyset → keeps the UnlockedKeyset in memory only. */
  unlock(
    enc: Uint8Array,
    password: string | null,
    secretKey: Uint8Array,
  ): Promise<KeysetIdentity>;
  /** Sign a server auth challenge (domain unissh-server-auth-v1). */
  signChallenge(c: ChallengeInput): Promise<Uint8Array>;
  /** Build a signed registration payload + signature (domain unissh-registration-v1). */
  buildRegistration(accountId: Uint8Array): Promise<RegistrationOut>;
  /** Build a signed membership manifest for an epoch. */
  buildManifest(
    vaultId: Uint8Array,
    keyEpoch: number,
    members: MemberSpec[],
  ): Promise<ManifestOut>;
  /** Build a per-member grant (VK HPKE-sealed to the recipient x25519). */
  buildGrant(
    vaultId: Uint8Array,
    recipientX25519: Uint8Array,
    memberEd25519: Uint8Array,
    role: number,
    keyEpoch: number,
    vk: Uint8Array,
  ): Promise<GrantOut>;
  /**
   * High-level epoch rotation: unwrap the current VK from the caller's grant,
   * build a new-epoch signed manifest + per-member grants for `members`, and
   * return base64 blobs ready for POST /v1/grants/publish.
   */
  rotateGrants(input: RotateInput): Promise<RotateOutput>;
  /**
   * Verify a `/v1/grants` manifest envelope against the PINNED genesis owner
   * before its member set is trusted for rotation. Throws if the envelope is
   * malformed, the Ed25519 signature is invalid, or the author is not the pinned
   * genesis owner, or the envelope is for a different vault than `vaultIdB64`.
   * Returns the verified member set. (Closes the gap where the panel rotated to an
   * unverified, server-supplied member set.)
   */
  verifyManifest(
    manifestB64: string,
    genesisOwnerB64: string,
    vaultIdB64: string,
  ): Promise<VerifiedManifest>;
  /**
   * Verify the FULL manifest authority chain (epoch 1..N envelopes, in order)
   * from the pinned genesis owner — multi-admin: each later manifest must be
   * signed by an admin of the previous verified epoch, and EVERY link must belong
   * to `vaultIdB64` (cross-vault splice guard). Returns the latest verified member
   * set; throws on any signature/authority/epoch-gap/vault-id failure.
   */
  verifyManifestChain(
    genesisOwnerB64: string,
    manifestsB64: string,
    vaultIdB64: string,
  ): Promise<VerifiedManifest>;
  /**
   * Verify a member's x25519<->ed25519 binding via its self-attested registration
   * signature (M14), against the EXACT stored `reg_payload` bytes and under the
   * manifest-verified `expectedEd25519B64`. Returns the ATTESTED x25519 (base64) —
   * the caller MUST wrap the VK to this, not to a server-supplied account row.
   * Throws if the signature does not attest the keys (server x25519 substitution).
   */
  verifyMemberBinding(
    regPayloadB64: string,
    regSigB64: string,
    expectedEd25519B64: string,
  ): Promise<string>;
  /**
   * Derive the escrow retrieval credential K_auth (base64) for escrow login.
   * Reproduces the server's K_auth from the account password (null for
   * SecretKeyOnly / SSO accounts), the 16-byte Secret Key, and the account's
   * SERVER-STORED Argon2id params (mem/iter/parallelism + salt). The params must
   * be the server's stored values — not freshly minted — or the derived K_auth
   * will not match `sha256(K_auth)` and login fails. Synchronous.
   */
  deriveEscrowAuth(
    password: string | null,
    secretKeyB64: string,
    saltB64: string,
    mem: number,
    iter: number,
    par: number,
  ): string;
  /**
   * The OIDC nonce key-binding for the unlocked keyset:
   * `base64(sha256(ed25519_pub ‖ x25519_pub))` (Ed25519 first, then X25519). The
   * id_token requested from the IdP MUST carry this exact string as its `nonce`, so
   * the server's `/v1/oidc/callback` binds the IdP-signed token to THIS keyset. Byte-
   * matches the server's `expected_nonce`. Requires an unlocked keyset. Synchronous.
   */
  oidcNonce(): string;
  /** Wipe the UnlockedKeyset from memory. */
  lock(): void;
}

export interface VerifiedManifest {
  epoch: number;
  members: { ed25519_pub: string; role: number }[];
}

export interface RotateInput {
  vaultId: Uint8Array;
  currentEpoch: number;
  /** Current manifest blob (base64) and grants from GET /v1/grants. */
  currentManifestB64: string;
  currentGrants: { member_pubkey: string; wrapped_vk: string; role: number }[];
  /** Desired member set for the new epoch. `not_after` (unix seconds; omitted or
   *  <=0 = no expiry) is an authenticated per-grant access expiry the server
   *  enforces on read. */
  members: {
    ed25519_pub: Uint8Array;
    x25519_pub: Uint8Array;
    role: number;
    not_after?: number;
  }[];
}
export interface RotateOutput {
  manifest: string;
  grants: unknown[];
  new_epoch: number;
}

export class CryptoUnavailableError extends Error {
  constructor() {
    super("crypto provider not loaded — keyset operations need the wasm module");
    this.name = "CryptoUnavailableError";
  }
}

const unavailable: CryptoProvider = {
  available: false,
  async createAccount() {
    throw new CryptoUnavailableError();
  },
  async unlock() {
    throw new CryptoUnavailableError();
  },
  async signChallenge() {
    throw new CryptoUnavailableError();
  },
  async buildRegistration() {
    throw new CryptoUnavailableError();
  },
  async buildManifest() {
    throw new CryptoUnavailableError();
  },
  async buildGrant() {
    throw new CryptoUnavailableError();
  },
  async rotateGrants() {
    throw new CryptoUnavailableError();
  },
  async verifyManifest() {
    throw new CryptoUnavailableError();
  },
  async verifyManifestChain() {
    throw new CryptoUnavailableError();
  },
  async verifyMemberBinding() {
    throw new CryptoUnavailableError();
  },
  deriveEscrowAuth(): string {
    throw new CryptoUnavailableError();
  },
  oidcNonce(): string {
    throw new CryptoUnavailableError();
  },
  lock() {},
};

let active: CryptoProvider = unavailable;

export function setCryptoProvider(p: CryptoProvider): void {
  active = p;
}
export function getCrypto(): CryptoProvider {
  return active;
}
