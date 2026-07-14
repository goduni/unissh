import { getCrypto, type KeysetIdentity } from "../crypto/provider";
import { usePrefs } from "../store/prefs";
import { useSession, type KeysetSession } from "../store/session";
import { b64ToBytes, bytesToB64, bytesToHex, hexToBytes, truncId } from "../util/bytes";
import { api } from "./index";

// ── Device-link persistence ────────────────────────────────────
// The panel's browser device_id is NOT a secret (it merely addresses the auth
// challenge — the account keyset is the secret). We persist it, keyed by
// (instanceUrl, account_id), so a returning owner's escrow sign-in re-uses the
// device this browser already registered (at claim time, or on a prior escrow
// sign-in) instead of enrolling a fresh one each visit. `auth/challenge` requires an
// existing, active device row; a browser that never registered here self-enrolls one
// during escrow sign-in via the public POST /v1/devices/self-enroll (the unlocked
// keyset's self-signed registration is the credential — no Bearer needed).
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
 * Shared sign-in tail for BOTH keyset paths (escrow fetch + offline Emergency-Kit
 * restore). Precondition: the account keyset is ALREADY unlocked in wasm — `id` is
 * its identity. Reuses the device this browser already registered for the account
 * (only possible when the account_id is known up front — escrow's fetch supplies it);
 * otherwise, on a fresh browser, self-enrolls one against the unlocked keyset via the
 * public POST /v1/devices/self-enroll (the self-signed registration IS the credential
 * — no Bearer; the placeholder id is inert, the server keys off the registration's
 * Ed25519 pubkey). Then challenge→sign→verify mints the admin session and the device
 * link is persisted (non-secret ids only). `knownAccountId` is escrow's fetched
 * account_id; the restore path passes null (no pre-known id) and always self-enrolls,
 * taking the account_id from the enroll response.
 */
/**
 * A short, non-fingerprinty label for a browser (panel) device — the browser family
 * only, never a version string — so the Devices list can tell one panel from another
 * without leaking a full user-agent. E.g. "Admin panel · Chrome".
 */
function panelDeviceLabel(): string {
  const ua = typeof navigator !== "undefined" ? navigator.userAgent : "";
  const family = /Edg\//.test(ua)
    ? "Edge"
    : /Firefox\//.test(ua)
      ? "Firefox"
      : /Chrome\//.test(ua)
        ? "Chrome"
        : /Safari\//.test(ua)
          ? "Safari"
          : "Browser";
  return `Admin panel · ${family}`;
}

async function enrollAndCommit(
  instanceUrl: string,
  id: KeysetIdentity,
  knownAccountId: string | null,
  handle: string,
): Promise<void> {
  const crypto_ = getCrypto();
  const keyId = bytesToB64(id.ed25519_pub);

  const link = knownAccountId ? findDeviceLink(instanceUrl, knownAccountId) : null;
  let accountId: string;
  let deviceId: string;
  let priorHandle: string | null;
  if (link && knownAccountId) {
    accountId = knownAccountId;
    deviceId = link.deviceId;
    priorHandle = link.handle;
  } else {
    const reg = await crypto_.buildRegistration(randomBytes(16));
    const enrolled = await api.deviceSelfEnroll({
      registration_payload: bytesToB64(reg.payload),
      registration_signature: bytesToB64(reg.signature),
      kind: "web",
      label: panelDeviceLabel(),
    });
    accountId = enrolled.account_id;
    deviceId = enrolled.device_id;
    priorHandle = null;
  }

  const session = await buildSession(accountId, deviceId, keyId, handle || truncId(accountId));
  useSession.getState().setKeysetSession(session);
  saveDeviceLink(instanceUrl, {
    accountId,
    deviceId,
    handle: handle || priorHandle,
  });
}

/**
 * Escrow sign-in: re-derive K_auth from handle+password+Secret Key, fetch and
 * unlock the account keyset in wasm, then run the shared self-enroll → session tail
 * ({@link enrollAndCommit}). Re-uses the device this browser already registered
 * (claim / prior escrow sign-in) when a link exists; on a fresh browser it
 * self-enrolls one against the now-unlocked keyset so sign-in still completes.
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

  await enrollAndCommit(p.instanceUrl, id, fetched.account_id, handle);
}

// ── Offline restore from the Emergency Kit ─────────────────────
/**
 * Thrown by {@link restoreFromKit} when the chosen file isn't a recovery keyset at
 * all — it fails to parse as an EncryptedKeyset (wrong length / version / framing) —
 * as opposed to a valid keyset that merely failed to unlock (wrong password / Secret
 * Key). Lets the Login UI show a precise "not a valid recovery file" message.
 */
export class NotAKeysetFileError extends Error {
  constructor() {
    super("not a valid recovery file");
    this.name = "NotAKeysetFileError";
  }
}

// Structural-parse failures from the wasm EncryptedKeyset decoder — i.e. the bytes
// are not a keyset at all. Everything else unlock throws (AEAD "invalid credentials",
// bad Secret Key length, post-decrypt checks) is a WRONG-CREDENTIAL failure, which
// the caller maps to the same "wrong password or Secret Key" message escrow uses.
const KEYSET_STRUCTURE_MARKERS = [
  "keyset too short",
  "bad keyset version",
  "bad keyset mode",
  "keyset truncated",
  "mode/params mismatch",
] as const;

export interface RestoreKitParams {
  instanceUrl: string;
  /** Raw bytes of the identity.kit / .keyset recovery file (File.arrayBuffer()). */
  fileBytes: Uint8Array;
  password: string | null;
  /** Secret Key from the Emergency Kit (hex, as shown at claim). */
  secretKeyHex: string;
}

/**
 * Offline twin of {@link loginWithEscrow}: unlock the account keyset from the
 * Emergency-Kit FILE (never the server's escrow copy), then run the SAME self-enroll
 * → session tail ({@link enrollAndCommit}). Belt-and-suspenders recovery for when the
 * server's escrow copy is unreachable. The file bytes, password and Secret Key stay
 * in wasm/JS memory — only the registration payload/signature and the derived session
 * cross the wire.
 */
export async function restoreFromKit(p: RestoreKitParams): Promise<void> {
  const crypto_ = getCrypto();
  const secretKeyBytes = hexToBytes(p.secretKeyHex.trim());

  let id: KeysetIdentity;
  try {
    id = await crypto_.unlock(p.fileBytes, p.password, secretKeyBytes);
  } catch (e) {
    const msg = e instanceof Error ? e.message : "";
    if (KEYSET_STRUCTURE_MARKERS.some((m) => msg.includes(m))) throw new NotAKeysetFileError();
    throw e; // wrong-credential (or CryptoUnavailable) — surfaced/mapped by the caller
  }

  await enrollAndCommit(p.instanceUrl, id, null, "");
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
  /** Mint + commit the admin session (challenge→sign→verify), then persist the
   *  device link — flips the app into the Shell. Call AFTER the Secret Key has been
   *  saved. RETRYABLE: the (irreversible) owner is already minted and the Secret Key
   *  is already on screen, so a transient failure here just rejects — the caller
   *  keeps the saved key visible and can retry, never losing it. */
  commit: () => Promise<void>;
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

  // Session-mint is DEFERRED into commit() — never a precondition for revealing the
  // Secret Key. api.claim() above already minted the (irreversible) owner, so the
  // caller surfaces secretKeyHex/enc immediately; challenge→sign→verify then runs as
  // a retryable step behind the save-gate. A transient 5xx here rejects commit()
  // (caller keeps the saved key + a retry) instead of losing the one-time key. The
  // wasm keyset stays installed from createAccount(), so buildSession can re-run.
  const commit = async (): Promise<void> => {
    const session = await buildSession(
      claimed.account_id,
      claimed.device_id,
      keyId,
      handle || truncId(claimed.account_id),
    );
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

// ── SSO (OIDC Authorization Code + PKCE, browser redirect) ─────
//
// Two legs around a full-page redirect to the IdP:
//   · oidcLogin(): mint an ephemeral SSO keyset, compute the key-binding nonce,
//     stash the PKCE verifier + keyset material in sessionStorage, and redirect the
//     browser to the IdP authorize URL.
//   · resumeOidcLogin(): on the callback load (?code=…), restore the exact keyset,
//     exchange the code for an id_token at the IdP token endpoint (public client),
//     and POST /v1/oidc/callback — the server verifies the nonce key-binding and
//     mints the session, which we commit directly (no separate challenge→verify).
//
// The keyset is a throwaway per-login device keyset (passwordless), mirroring the
// desktop client. It is persisted in sessionStorage ONLY across the redirect and
// cleared immediately on resume.
//
// MANUAL-TEST NOTE: the browser↔IdP round-trip needs a real IdP + browser and cannot
// be exercised in CI. The server side is proven by the `oidc_http` test (Task 4).

const OIDC_FLOW_KEY = "unissh-admin-oidc-flow";
interface OidcFlowState {
  instanceUrl: string;
  codeVerifier: string;
  state: string;
  /** Ephemeral SSO EncryptedKeyset + Secret Key (base64) — to restore the SAME keyset
   *  the nonce was bound to, after the redirect reload. */
  encB64: string;
  secretKeyB64: string;
  tokenEndpoint: string;
  clientId: string;
}

/** URL-safe base64 without padding (PKCE + `state`). */
function b64url(bytes: Uint8Array): string {
  return bytesToB64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return b64url(new Uint8Array(digest));
}

/** The redirect target = this SPA's own origin + path (registered at the IdP). */
function oidcRedirectUri(): string {
  return window.location.origin + window.location.pathname;
}

/** Resolve the IdP authorize/token endpoints from the issuer's discovery document
 *  (`{issuer}/.well-known/openid-configuration`). The REAL OIDC discovery endpoint —
 *  handles any standards-compliant IdP regardless of its endpoint paths. */
async function discoverOidc(
  issuer: string,
): Promise<{ authorization_endpoint: string; token_endpoint: string }> {
  const url = issuer.replace(/\/+$/, "") + "/.well-known/openid-configuration";
  const r = await fetch(url, { headers: { Accept: "application/json" } });
  if (!r.ok) throw new Error(`OIDC discovery failed (HTTP ${r.status})`);
  const d = (await r.json()) as { authorization_endpoint?: string; token_endpoint?: string };
  if (!d.authorization_endpoint || !d.token_endpoint) {
    throw new Error("OIDC discovery is missing authorization/token endpoints");
  }
  return { authorization_endpoint: d.authorization_endpoint, token_endpoint: d.token_endpoint };
}

/** True when this page load is an OIDC redirect callback with a pending flow. */
export function pendingOidcRedirect(): boolean {
  const params = new URLSearchParams(window.location.search);
  return (params.has("code") || params.has("error")) && sessionStorage.getItem(OIDC_FLOW_KEY) !== null;
}

/**
 * Begin SSO sign-in: mint an ephemeral keyset, compute the key-binding nonce, and
 * redirect the browser to the IdP. Does not return normally — it navigates away.
 */
export async function oidcLogin(instanceUrl: string): Promise<void> {
  const crypto_ = getCrypto();
  const info = await api.instance();
  if (!info.oidc) throw new Error("this server does not offer SSO sign-in");
  const { authorization_endpoint, token_endpoint } = await discoverOidc(info.oidc.issuer);

  // Fresh throwaway SSO keyset (passwordless). Its pubkeys bind the id_token nonce.
  const acc = await crypto_.createAccount(null);
  const nonce = crypto_.oidcNonce();

  const codeVerifier = b64url(randomBytes(32));
  const state = b64url(randomBytes(16));
  const codeChallenge = await pkceChallenge(codeVerifier);

  const flow: OidcFlowState = {
    instanceUrl,
    codeVerifier,
    state,
    encB64: bytesToB64(acc.enc),
    secretKeyB64: bytesToB64(acc.secretKey),
    tokenEndpoint: token_endpoint,
    clientId: info.oidc.client_id,
  };
  sessionStorage.setItem(OIDC_FLOW_KEY, JSON.stringify(flow));

  const authUrl = new URL(authorization_endpoint);
  authUrl.search = new URLSearchParams({
    response_type: "code",
    client_id: info.oidc.client_id,
    redirect_uri: oidcRedirectUri(),
    scope: "openid profile groups",
    state,
    nonce,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  }).toString();
  window.location.assign(authUrl.toString());
}

/**
 * Resume SSO sign-in on the callback load: validate `state`, restore the ephemeral
 * keyset, exchange the code for an id_token, run POST /v1/oidc/callback, and commit
 * the returned session. Clears the pending flow + the `?code` from the URL first so a
 * reload can't replay it.
 */
export async function resumeOidcLogin(): Promise<void> {
  const raw = sessionStorage.getItem(OIDC_FLOW_KEY);
  const params = new URLSearchParams(window.location.search);
  // Scrub the code from the address bar and drop the pending flow up front.
  const redirectUri = oidcRedirectUri();
  window.history.replaceState({}, "", redirectUri);
  sessionStorage.removeItem(OIDC_FLOW_KEY);
  if (!raw) throw new Error("no pending SSO sign-in");
  const flow = JSON.parse(raw) as OidcFlowState;

  const err = params.get("error");
  if (err) throw new Error(`the identity provider returned an error: ${err}`);
  const code = params.get("code");
  if (!code) throw new Error("SSO redirect carried no authorization code");
  if (params.get("state") !== flow.state) {
    throw new Error("SSO redirect state mismatch (possible CSRF)");
  }

  // Keep subsequent api calls pointed at the same instance across the reload.
  usePrefs.getState().setInstanceUrl(flow.instanceUrl);

  const crypto_ = getCrypto();
  // Restore the exact keyset the nonce was bound to (passwordless).
  await crypto_.unlock(b64ToBytes(flow.encB64), null, b64ToBytes(flow.secretKeyB64));
  const reg = await crypto_.buildRegistration(randomBytes(16));

  // PKCE token exchange straight to the IdP (public client — no secret).
  const tokenRes = await fetch(flow.tokenEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: flow.clientId,
      code_verifier: flow.codeVerifier,
    }).toString(),
  });
  if (!tokenRes.ok) {
    let detail = `HTTP ${tokenRes.status}`;
    try {
      const j = (await tokenRes.json()) as { error?: string; error_description?: string };
      detail = j.error_description || j.error || detail;
    } catch {
      /* non-JSON error body */
    }
    crypto_.lock();
    throw new Error(`OIDC token exchange failed: ${detail}`);
  }
  const tokens = (await tokenRes.json()) as { id_token?: string };
  if (!tokens.id_token) {
    crypto_.lock();
    throw new Error("OIDC token response is missing id_token");
  }

  const resp = await api.oidcCallback({
    id_token: tokens.id_token,
    registration_payload: bytesToB64(reg.payload),
    registration_signature: bytesToB64(reg.signature),
  });

  // The callback already minted the session; the keyset is already unlocked → commit
  // both together (App shows the Shell only when bearer && keysetUnlocked).
  useSession.getState().setKeysetSession({
    bearer: resp.access_token,
    refreshToken: resp.refresh_token,
    accessExpires: resp.access_expires,
    accountId: resp.account_id,
    deviceId: resp.device_id,
    label: truncId(resp.account_id),
  });
  saveDeviceLink(flow.instanceUrl, {
    accountId: resp.account_id,
    deviceId: resp.device_id,
    handle: null,
  });
}

/** Wipe the unlocked keyset + Bearer from memory. */
export function lockKeyset(): void {
  getCrypto().lock();
  useSession.getState().lock();
}
