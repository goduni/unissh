import { b64ToBytes, bytesToB64 } from "../util/bytes";
import {
  setCryptoProvider,
  type ChallengeInput,
  type CryptoProvider,
  type KeysetIdentity,
  type NewAccount,
  type RegistrationOut,
  type VerifiedManifest,
} from "./provider";

interface WasmModule {
  default: (input?: unknown) => Promise<unknown>;
  create_account: (password?: string | null) => string;
  unlock: (enc_b64: string, password: string | null | undefined, secret_key_b64: string) => string;
  sign_challenge: (
    host_b64: string,
    account_id_b64: string,
    device_id_b64: string,
    key_id_b64: string,
    nonce_b64: string,
    expiry: number,
  ) => string;
  build_registration: (account_id_b64: string) => string;
  rotate_grants: (vault_id_b64: string, new_epoch: number, members_csv: string) => string;
  verify_manifest_authorized: (
    manifest_b64: string,
    genesis_owner_b64: string,
    vault_id_b64: string,
  ) => string;
  verify_manifest_chain: (
    genesis_owner_b64: string,
    manifests_b64: string,
    vault_id_b64: string,
  ) => string;
  verify_member_binding: (
    reg_payload_b64: string,
    reg_sig_b64: string,
    expected_ed25519_b64: string,
  ) => string;
  derive_escrow_auth: (
    password: string | null | undefined,
    secret_key_b64: string,
    argon_salt_b64: string,
    argon_mem_kib: number,
    argon_iterations: number,
    argon_parallelism: number,
  ) => string;
  oidc_nonce: () => string;
  lock: () => void;
}

function makeProvider(m: WasmModule): CryptoProvider {
  return {
    available: true,

    async createAccount(password): Promise<NewAccount> {
      const r = JSON.parse(m.create_account(password ?? undefined)) as {
        enc: string;
        secret_key: string;
        ed25519_pub: string;
        x25519_pub: string;
      };
      return {
        enc: b64ToBytes(r.enc),
        secretKey: b64ToBytes(r.secret_key),
        ed25519_pub: b64ToBytes(r.ed25519_pub),
        x25519_pub: b64ToBytes(r.x25519_pub),
      };
    },

    async unlock(enc, password, secretKey): Promise<KeysetIdentity> {
      const r = JSON.parse(m.unlock(bytesToB64(enc), password ?? null, bytesToB64(secretKey))) as {
        ed25519_pub: string;
        x25519_pub: string;
        generation: number;
      };
      return {
        ed25519_pub: b64ToBytes(r.ed25519_pub),
        x25519_pub: b64ToBytes(r.x25519_pub),
        generation: r.generation,
      };
    },

    async signChallenge(c: ChallengeInput): Promise<Uint8Array> {
      const sig = m.sign_challenge(
        bytesToB64(c.host),
        bytesToB64(c.account_id),
        bytesToB64(c.device_id),
        bytesToB64(c.key_id),
        bytesToB64(c.nonce),
        c.expiry,
      );
      return b64ToBytes(sig);
    },

    async buildRegistration(accountId): Promise<RegistrationOut> {
      const r = JSON.parse(m.build_registration(bytesToB64(accountId))) as {
        payload: string;
        signature: string;
      };
      return { payload: b64ToBytes(r.payload), signature: b64ToBytes(r.signature) };
    },

    async buildManifest() {
      throw new Error("use rotateGrants (high-level) instead of buildManifest");
    },
    async buildGrant() {
      throw new Error("use rotateGrants (high-level) instead of buildGrant");
    },

    async rotateGrants(input) {
      const newEpoch = input.currentEpoch + 1;
      const csv = input.members
        .map(
          (mem) =>
            `${bytesToB64(mem.ed25519_pub)}|${bytesToB64(mem.x25519_pub)}|${mem.role}|${mem.not_after ?? 0}`,
        )
        .join("\n");
      const r = JSON.parse(m.rotate_grants(bytesToB64(input.vaultId), newEpoch, csv)) as {
        manifest: string;
        grants: string[];
        new_epoch: number;
      };
      return { manifest: r.manifest, grants: r.grants, new_epoch: r.new_epoch };
    },

    async verifyManifest(manifestB64, genesisOwnerB64, vaultIdB64): Promise<VerifiedManifest> {
      // Throws (rejects) if the manifest is unsigned-by-genesis / tampered / for a
      // different vault than vaultIdB64.
      return JSON.parse(
        m.verify_manifest_authorized(manifestB64, genesisOwnerB64, vaultIdB64),
      ) as VerifiedManifest;
    },

    async verifyManifestChain(genesisOwnerB64, manifestsB64, vaultIdB64): Promise<VerifiedManifest> {
      return JSON.parse(
        m.verify_manifest_chain(genesisOwnerB64, manifestsB64, vaultIdB64),
      ) as VerifiedManifest;
    },

    async verifyMemberBinding(regPayloadB64, regSigB64, expectedEd25519B64) {
      // Throws if the registration signature does not attest the claimed keys.
      // Returns the ATTESTED x25519 (base64) — caller wraps the VK to this.
      return m.verify_member_binding(regPayloadB64, regSigB64, expectedEd25519B64);
    },

    deriveEscrowAuth(password, secretKeyB64, saltB64, mem, iter, par): string {
      // Reproduces the server's K_auth (base64) from the account password
      // (null → SecretKeyOnly / SSO) + Secret Key + the server's stored Argon2id
      // params. Synchronous — no keyset state is touched.
      return m.derive_escrow_auth(password ?? undefined, secretKeyB64, saltB64, mem, iter, par);
    },

    oidcNonce(): string {
      // base64(sha256(ed25519_pub ‖ x25519_pub)) over the unlocked keyset — the
      // id_token `nonce` the server's /v1/oidc/callback binds to this keyset.
      // Synchronous; reads the in-memory unlocked keyset only.
      return m.oidc_nonce();
    },

    lock() {
      m.lock();
    },
  };
}

/** Load the wasm crypto module and register it as the active CryptoProvider. */
export async function loadWasmProvider(): Promise<boolean> {
  try {
    const mod = (await import("../../crypto-wasm/pkg/unissh_crypto_wasm.js")) as unknown as WasmModule;
    const urlMod = (await import("../../crypto-wasm/pkg/unissh_crypto_wasm_bg.wasm?url")) as {
      default: string;
    };
    await mod.default(urlMod.default);
    setCryptoProvider(makeProvider(mod));
    return true;
  } catch (e) {
    console.warn("[crypto-wasm] failed to load:", e);
    return false;
  }
}
