import { getCrypto } from "../crypto/provider";
import { useSession, type KeysetSession } from "../store/session";
import { b64ToBytes, bytesToB64, bytesToHex, hexToBytes, truncId } from "../util/bytes";
import { api } from "./index";

// ── Device-link persistence ────────────────────────────────────
// The panel's browser device_id is NOT a secret (it merely addresses the auth
// challenge — the account keyset is the secret). We persist it, keyed by
// (instanceUrl, account_id), so a returning owner's escrow sign-in can re-use the
// device that was registered at claim time. `auth/challenge` requires an existing,
// active device row and device registration is session-gated (POST /v1/devices/add
// needs a Bearer), so a browser that never claimed here has no device to sign in
// with — see `DeviceNotLinkedError`. (Fresh-device onboarding = QR-approve / signed
// device-add is a server-side follow-up; the desktop client carries the same gap.)
const LINK_KEY = "unissh-admin-device-links";
interface DeviceLink {
  accountId: string;
  deviceId: string;
  handle: string | null;
}
function linkKey(instanceUrl: string, accountId: string): string {
  return `${instanceUrl}::${accountId}`;
}
function readLinks(): Record<string, DeviceLink> {
  try {
    const raw = localStorage.getItem(LINK_KEY);
    return raw ? (JSON.parse(raw) as Record<string, DeviceLink>) : {};
  } catch {
    return {};
  }
}
function saveDeviceLink(instanceUrl: string, link: DeviceLink): void {
  try {
    const all = readLinks();
    all[linkKey(instanceUrl, link.accountId)] = link;
    localStorage.setItem(LINK_KEY, JSON.stringify(all));
  } catch {
    /* storage may be unavailable (private mode) — escrow re-login just won't persist */
  }
}
function findDeviceLink(instanceUrl: string, accountId: string): DeviceLink | null {
  return readLinks()[linkKey(instanceUrl, accountId)] ?? null;
}

// Recommended Argon2id params for escrow enrollment — match the server's
// KdfParams::recommended() (64 MiB · t=3 · p=1). GET /v1/escrow/params returns the
// stored values verbatim, so a later deriveEscrowAuth re-derives an identical
// K_auth only if we enroll with exactly these (self-consistent) params.
const ESCROW_ARGON = { mem_kib: 65536, iterations: 3, parallelism: 1 } as const;

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

/** No account linked a device in this browser for the target instance. */
export class DeviceNotLinkedError extends Error {
  constructor() {
    super("no linked device for this account in this browser");
    this.name = "DeviceNotLinkedError";
  }
}

// challenge → sign (unissh-server-auth-v1) → verify → session tokens. Does NOT
// commit to the store; the caller decides when (claim shows the one-time Secret Key
// before flipping the app into the Shell).
async function buildSession(
  accountId: string,
  deviceId: string,
  keyIdB64: string,
  label: string,
): Promise<KeysetSession> {
  const crypto_ = getCrypto();
  const challenge = await api.identity.challenge(accountId, deviceId, keyIdB64);
  const sig = await crypto_.signChallenge({
    host: challenge.host ? b64ToBytes(challenge.host) : new Uint8Array(0),
    account_id: b64ToBytes(challenge.account_id),
    device_id: b64ToBytes(challenge.device_id),
    key_id: b64ToBytes(challenge.key_id),
    nonce: b64ToBytes(challenge.nonce),
    expiry: challenge.expiry,
  });
  const verify = await api.identity.verify(challenge, bytesToB64(sig));
  return {
    bearer: verify.access_token,
    refreshToken: verify.refresh_token,
    accessExpires: verify.access_expires,
    accountId,
    deviceId,
    label,
  };
}

// ── Escrow sign-in ─────────────────────────────────────────────
export interface EscrowLoginParams {
  instanceUrl: string;
  handle: string;
  password: string | null;
  /** Secret Key from the Emergency Kit (hex, as shown at claim). */
  secretKeyHex: string;
}

/**
 * Escrow sign-in: re-derive K_auth from handle+password+Secret Key, fetch and
 * unlock the account keyset in wasm, then challenge→sign→verify for the admin
 * Bearer. Re-uses the device this browser registered at claim time (see
 * `DeviceNotLinkedError`).
 */
export async function loginWithEscrow(p: EscrowLoginParams): Promise<void> {
  const crypto_ = getCrypto();
  const handle = p.handle.trim();
  const secretKeyBytes = hexToBytes(p.secretKeyHex.trim());
  const secretKeyB64 = bytesToB64(secretKeyBytes);

  const params = await api.escrowParams(handle);
  const kAuth = crypto_.deriveEscrowAuth(
    p.password,
    secretKeyB64,
    params.argon_salt,
    params.argon_mem_kib,
    params.argon_iterations,
    params.argon_parallelism,
  );
  const fetched = await api.escrowFetch(handle, kAuth);
  const id = await crypto_.unlock(b64ToBytes(fetched.keyset_blob), p.password, secretKeyBytes);
  const keyId = bytesToB64(id.ed25519_pub);

  const link = findDeviceLink(p.instanceUrl, fetched.account_id);
  if (!link) {
    crypto_.lock();
    throw new DeviceNotLinkedError();
  }

  const session = await buildSession(
    fetched.account_id,
    link.deviceId,
    keyId,
    handle || truncId(fetched.account_id),
  );
  useSession.getState().setKeysetSession(session);
  saveDeviceLink(p.instanceUrl, {
    accountId: fetched.account_id,
    deviceId: link.deviceId,
    handle: handle || link.handle,
  });
}

// ── Claim (first-run owner setup) ──────────────────────────────
export interface ClaimParams {
  instanceUrl: string;
  setupCode: string;
  password: string | null;
  displayName?: string;
  handle?: string;
  spaceName?: string;
}
export interface ClaimOutcome {
  /** One-time Secret Key (hex) — the operator MUST save this. */
  secretKeyHex: string;
  /** EncryptedKeyset bytes to download as the genesis key file. */
  enc: Uint8Array;
  accountId: string;
  /** Commit the admin session — flips the app into the Shell. Call after the
   *  Secret Key has been saved. */
  commit: () => void;
  /** Arm escrow sign-in so future logins work by handle+password+Secret Key. Must
   *  run AFTER {@link commit} (needs the Bearer). Resolves true when armed; never
   *  throws — claim already succeeded, so a failure just means the owner re-signs-in
   *  from this browser (device link persisted) or via the saved key file. */
  armEscrow: () => Promise<boolean>;
}

/**
 * Claim an unclaimed instance with a setup code: mint a genesis keyset (in wasm),
 * self-attest the owner registration, POST /v1/claim (the server mints account +
 * device + first space), and prepare the auto-sign-in. Returns the one-time
 * credentials plus deferred `commit`/`armEscrow` steps so the caller can show the
 * "save your Secret Key" gate before entering the Shell.
 */
export async function claimInstance(p: ClaimParams): Promise<ClaimOutcome> {
  const crypto_ = getCrypto();
  const handle = p.handle?.trim() || undefined;
  const acc = await crypto_.createAccount(p.password); // installs the keyset in wasm
  // The server mints the real account_id; the registration payload's id is a
  // client-side placeholder (the signature binds x25519<->ed25519, not the id).
  const reg = await crypto_.buildRegistration(randomBytes(16));

  const claimed = await api.claim({
    setup_code: p.setupCode.trim(),
    registration_payload: bytesToB64(reg.payload),
    registration_signature: bytesToB64(reg.signature),
    display_name: p.displayName?.trim() || undefined,
    handle,
    space_name: p.spaceName?.trim() || undefined,
  });

  const keyId = bytesToB64(acc.ed25519_pub);
  const session = await buildSession(
    claimed.account_id,
    claimed.device_id,
    keyId,
    handle || truncId(claimed.account_id),
  );

  const commit = (): void => {
    useSession.getState().setKeysetSession(session);
    saveDeviceLink(p.instanceUrl, {
      accountId: claimed.account_id,
      deviceId: claimed.device_id,
      handle: handle ?? null,
    });
  };

  const armEscrow = async (): Promise<boolean> => {
    try {
      const salt = randomBytes(16);
      const kAuth = crypto_.deriveEscrowAuth(
        p.password,
        bytesToB64(acc.secretKey),
        bytesToB64(salt),
        ESCROW_ARGON.mem_kib,
        ESCROW_ARGON.iterations,
        ESCROW_ARGON.parallelism,
      );
      await api.identity.keysetPut({
        keyset_blob: bytesToB64(acc.enc),
        escrow: {
          k_auth: kAuth,
          argon_salt: bytesToB64(salt),
          argon_mem_kib: ESCROW_ARGON.mem_kib,
          argon_iterations: ESCROW_ARGON.iterations,
          argon_parallelism: ESCROW_ARGON.parallelism,
        },
      });
      return true;
    } catch {
      return false;
    }
  };

  return {
    secretKeyHex: bytesToHex(acc.secretKey),
    enc: acc.enc,
    accountId: claimed.account_id,
    commit,
    armEscrow,
  };
}

/** Wipe the unlocked keyset + Bearer from memory. */
export function lockKeyset(): void {
  getCrypto().lock();
  useSession.getState().lock();
}
