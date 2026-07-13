//! wasm-bindgen surface for the UniSSH admin panel.
//!
//! Vendors the *storage-free* keychain crypto logic (keyset (de)serialize, unlock
//! key derivation, create/unlock) VERBATIM from rust-core `keychain` so it is
//! byte-compatible with real clients, while depending only on `unissh_crypto`
//! (the `keychain`/`vault` crates pull `unissh-storage` → rusqlite/sqlcipher,
//! which does not compile to wasm). Signing domains:
//! `unissh-server-auth-v1` (challenge) and `unissh-registration-v1`.

use std::cell::RefCell;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use hkdf::Hkdf;
use sha2::Sha256;
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

use unissh_crypto::{
    aead_decrypt, aead_encrypt, derive_key, seal_key_to_public, sign_registration,
    sign_server_auth, sign_version, verify_registration, verify_version, vk_wrap_info,
    AssociatedData, Ed25519Keypair, Ed25519SigningKey, Ed25519VerifyingKey, KdfParams,
    RegistrationPayload, ServerAuthChallenge, SymmetricKey, VersionedObject, X25519Keypair,
    X25519PublicKey, X25519SecretKey,
};

/// Current on-disk keyset format version (written by `to_bytes`). Matches
/// rust-core `keychain::keyset::KEYSET_FORMAT_VERSION`.
const KEYSET_FORMAT_VERSION: u8 = 3;
/// Legacy keyset version still accepted for READ. The wire byte layout is
/// identical to v3 and this vendored copy already uses the current Scheme-B
/// unlock recipe, so a v2 blob opens with no AEAD/derivation change. Mirrors
/// rust-core `keychain::keyset::KEYSET_FORMAT_LEGACY`.
const KEYSET_FORMAT_LEGACY: u8 = 2;
const SK_LEN: usize = 32;
const SECRET_KEY_LEN: usize = 16;
const UNLOCK_HKDF_SALT: &[u8] = b"unissh-unlock-salt-v1";
const UNLOCK_HKDF_INFO: &[u8] = b"unissh-unlock-key-v1";
/// HKDF `info` for the escrow retrieval credential K_auth. A distinct label →
/// an independent key: K_auth cannot recover the Unlock Key. Byte-matches
/// rust-core `keychain::unlock::ESCROW_AUTH_HKDF_INFO`.
const ESCROW_AUTH_HKDF_INFO: &[u8] = b"unissh-escrow-auth-v1";

thread_local! {
    /// The single in-memory unlocked keyset for this tab. Cleared on `lock()`.
    static UNLOCKED: RefCell<Option<UnlockedKeyset>> = const { RefCell::new(None) };
}

struct UnlockedKeyset {
    encryption: X25519Keypair,
    signing: Ed25519Keypair,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum UnlockMode {
    Password,
    SecretKeyOnly,
}
impl UnlockMode {
    fn to_u8(self) -> u8 {
        match self {
            UnlockMode::Password => 1,
            UnlockMode::SecretKeyOnly => 2,
        }
    }
    fn from_u8(v: u8) -> Result<Self, JsError> {
        match v {
            1 => Ok(UnlockMode::Password),
            2 => Ok(UnlockMode::SecretKeyOnly),
            _ => Err(JsError::new("bad keyset mode")),
        }
    }
}

struct EncryptedKeyset {
    mode: UnlockMode,
    kdf_params: Option<KdfParams>,
    x25519_public: [u8; 32],
    ed25519_public: [u8; 32],
    generation: u32,
    wrapped_keyset: Vec<u8>,
}

fn keyset_aad(x25519_public: &[u8; 32], generation: u32) -> AssociatedData {
    AssociatedData::new(
        b"unissh-keyset".to_vec(),
        x25519_public.to_vec(),
        generation as u64,
    )
}

fn derive_unlock_key(argon_key: Option<&SymmetricKey>, secret_key: &[u8; SECRET_KEY_LEN]) -> SymmetricKey {
    // Length-framed IKM — MUST stay byte-identical to rust-core
    // `keychain::unlock::derive_unlock_key`: `present:u8 || len:u32be || data` per
    // field (argon_key, secret_key, device_secret). The panel has no device_secret,
    // so its field is always absent (present=0, len=0) — matching the native
    // client's None branch, keeping admin-panel and client keysets compatible.
    fn push_field(ikm: &mut Vec<u8>, present: bool, data: &[u8]) {
        ikm.push(present as u8);
        ikm.extend_from_slice(&(data.len() as u32).to_be_bytes());
        ikm.extend_from_slice(data);
    }
    let mut ikm = Zeroizing::new(Vec::new());
    match argon_key {
        Some(ak) => push_field(&mut ikm, true, ak.expose_bytes()),
        None => push_field(&mut ikm, false, &[]),
    }
    push_field(&mut ikm, true, secret_key);
    push_field(&mut ikm, false, &[]); // device_secret: always absent in the panel
    let hk = Hkdf::<Sha256>::new(Some(UNLOCK_HKDF_SALT), ikm.as_ref());
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(UNLOCK_HKDF_INFO, okm.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    SymmetricKey::from_bytes(*okm)
}

/// Derives the escrow **auth** credential `K_auth`. Same length-framed IKM and
/// salt as [`derive_unlock_key`] but a distinct HKDF `info`, so K_auth is
/// domain-separated from K_unlock. MUST stay byte-identical to rust-core
/// `keychain::unlock::derive_escrow_auth_key`: field framing
/// `present:u8 || len:u32be || data` for [argon_key (present iff Some),
/// secret_key (present), device_secret (always absent in the panel)], then
/// HKDF-SHA256 with salt `UNLOCK_HKDF_SALT` and info `ESCROW_AUTH_HKDF_INFO`.
/// The framing deliberately duplicates `derive_unlock_key`'s (rather than
/// factoring it out) to keep that format-frozen function byte-untouched.
fn derive_escrow_auth_key(argon_key: Option<&SymmetricKey>, secret_key: &[u8; SECRET_KEY_LEN]) -> SymmetricKey {
    fn push_field(ikm: &mut Vec<u8>, present: bool, data: &[u8]) {
        ikm.push(present as u8);
        ikm.extend_from_slice(&(data.len() as u32).to_be_bytes());
        ikm.extend_from_slice(data);
    }
    let mut ikm = Zeroizing::new(Vec::new());
    match argon_key {
        Some(ak) => push_field(&mut ikm, true, ak.expose_bytes()),
        None => push_field(&mut ikm, false, &[]),
    }
    push_field(&mut ikm, true, secret_key);
    push_field(&mut ikm, false, &[]); // device_secret: always absent in the panel
    let hk = Hkdf::<Sha256>::new(Some(UNLOCK_HKDF_SALT), ikm.as_ref());
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(ESCROW_AUTH_HKDF_INFO, okm.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    SymmetricKey::from_bytes(*okm)
}

fn wrap_keyset(
    unlock_key: &SymmetricKey,
    encryption: &X25519Keypair,
    signing: &Ed25519Keypair,
    x25519_public: &[u8; 32],
    generation: u32,
) -> Result<Vec<u8>, JsError> {
    let x_secret = Zeroizing::new(encryption.secret.expose_to_bytes());
    let e_secret = Zeroizing::new(signing.signing.expose_to_bytes());
    let mut plaintext = Zeroizing::new(Vec::with_capacity(SK_LEN * 2));
    plaintext.extend_from_slice(x_secret.as_ref());
    plaintext.extend_from_slice(e_secret.as_ref());
    aead_encrypt(unlock_key, &plaintext, &keyset_aad(x25519_public, generation))
        .map_err(|e| JsError::new(&format!("wrap: {e:?}")))
}

impl EncryptedKeyset {
    fn to_bytes(&self) -> Result<Vec<u8>, JsError> {
        let kdf_blob = match &self.kdf_params {
            Some(p) => p.to_blob().map_err(|e| JsError::new(&format!("{e:?}")))?,
            None => Vec::new(),
        };
        if kdf_blob.len() > u16::MAX as usize {
            return Err(JsError::new("kdf blob too large"));
        }
        let mut out = Vec::with_capacity(8 + kdf_blob.len() + 64 + self.wrapped_keyset.len());
        out.push(KEYSET_FORMAT_VERSION);
        out.push(self.mode.to_u8());
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&(kdf_blob.len() as u16).to_be_bytes());
        out.extend_from_slice(&kdf_blob);
        out.extend_from_slice(&self.x25519_public);
        out.extend_from_slice(&self.ed25519_public);
        out.extend_from_slice(&self.wrapped_keyset);
        Ok(out)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, JsError> {
        if bytes.len() < 8 + 64 {
            return Err(JsError::new("keyset too short"));
        }
        // Accept the current (v3) and legacy (v2) versions — the wire layout is
        // identical and this copy already uses the current unlock recipe, so a v2
        // blob opens unchanged. A record from the future (> current) is a loud
        // rejection (unknown recipe). Mirrors rust-core `keyset::from_bytes`.
        if bytes[0] != KEYSET_FORMAT_VERSION && bytes[0] != KEYSET_FORMAT_LEGACY {
            return Err(JsError::new("bad keyset version"));
        }
        let mode = UnlockMode::from_u8(bytes[1])?;
        let generation = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        let kdf_len = u16::from_be_bytes([bytes[6], bytes[7]]) as usize;

        let mut pos: usize = 8;
        let kdf_params = if kdf_len > 0 {
            let end = pos.checked_add(kdf_len).ok_or_else(|| JsError::new("overflow"))?;
            if bytes.len() < end + 64 {
                return Err(JsError::new("keyset truncated"));
            }
            let p = KdfParams::from_blob(&bytes[pos..end]).map_err(|e| JsError::new(&format!("{e:?}")))?;
            pos = end;
            Some(p)
        } else {
            None
        };
        match (mode, &kdf_params) {
            (UnlockMode::Password, Some(_)) | (UnlockMode::SecretKeyOnly, None) => {}
            _ => return Err(JsError::new("mode/params mismatch")),
        }
        if bytes.len() < pos + 64 {
            return Err(JsError::new("keyset truncated"));
        }
        let mut x25519_public = [0u8; 32];
        x25519_public.copy_from_slice(&bytes[pos..pos + 32]);
        let mut ed25519_public = [0u8; 32];
        ed25519_public.copy_from_slice(&bytes[pos + 32..pos + 64]);
        pos += 64;
        let wrapped_keyset = bytes[pos..].to_vec();
        if wrapped_keyset.is_empty() {
            return Err(JsError::new("empty wrapped keyset"));
        }
        Ok(Self {
            mode,
            kdf_params,
            x25519_public,
            ed25519_public,
            generation,
            wrapped_keyset,
        })
    }
}

fn create_account_logic(
    password: Option<&[u8]>,
) -> Result<([u8; SECRET_KEY_LEN], EncryptedKeyset, UnlockedKeyset), JsError> {
    use rand_core::{OsRng, RngCore};
    let mut secret_key = [0u8; SECRET_KEY_LEN];
    OsRng.fill_bytes(&mut secret_key);

    let (mode, kdf_params, argon_key) = match password {
        Some(pw) => {
            let params = KdfParams::recommended();
            let ak = derive_key(pw, &params).map_err(|e| JsError::new(&format!("{e:?}")))?;
            (UnlockMode::Password, Some(params), Some(ak))
        }
        None => (UnlockMode::SecretKeyOnly, None, None),
    };

    let unlock_key = derive_unlock_key(argon_key.as_ref(), &secret_key);
    let encryption = X25519Keypair::generate();
    let signing = Ed25519Keypair::generate();
    let x25519_public = encryption.public.to_bytes();
    let ed25519_public = signing.verifying.to_bytes();
    let generation: u32 = 1;
    let wrapped_keyset = wrap_keyset(&unlock_key, &encryption, &signing, &x25519_public, generation)?;

    let record = EncryptedKeyset {
        mode,
        kdf_params,
        x25519_public,
        ed25519_public,
        generation,
        wrapped_keyset,
    };
    Ok((secret_key, record, UnlockedKeyset { encryption, signing }))
}

fn unlock_logic(
    record: &EncryptedKeyset,
    password: Option<&[u8]>,
    secret_key: &[u8; SECRET_KEY_LEN],
) -> Result<UnlockedKeyset, JsError> {
    let argon_key = match record.mode {
        UnlockMode::Password => {
            let pw = password.ok_or_else(|| JsError::new("password required"))?;
            let params = record.kdf_params.as_ref().ok_or_else(|| JsError::new("missing kdf params"))?;
            Some(derive_key(pw, params).map_err(|e| JsError::new(&format!("{e:?}")))?)
        }
        UnlockMode::SecretKeyOnly => None,
    };
    let unlock_key = derive_unlock_key(argon_key.as_ref(), secret_key);

    let mut plaintext = aead_decrypt(
        &unlock_key,
        &record.wrapped_keyset,
        &keyset_aad(&record.x25519_public, record.generation),
    )
    .map_err(|_| JsError::new("invalid credentials"))?;

    if plaintext.len() != SK_LEN * 2 {
        plaintext.zeroize();
        return Err(JsError::new("bad keyset plaintext"));
    }
    let x_secret = X25519SecretKey::from_bytes(&plaintext[..SK_LEN]);
    let e_secret = Ed25519SigningKey::from_bytes(&plaintext[SK_LEN..]);
    plaintext.zeroize();
    let x_secret = x_secret.map_err(|_| JsError::new("bad x25519 secret"))?;
    let e_secret = e_secret.map_err(|_| JsError::new("bad ed25519 secret"))?;

    let encryption = X25519Keypair {
        public: x_secret.public_key(),
        secret: x_secret,
    };
    let signing = Ed25519Keypair {
        verifying: e_secret.verifying_key(),
        signing: e_secret,
    };
    if encryption.public.to_bytes() != record.x25519_public {
        return Err(JsError::new("keyset pubkey mismatch"));
    }
    Ok(UnlockedKeyset { encryption, signing })
}

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}
fn unb64(s: &str) -> Result<Vec<u8>, JsError> {
    STANDARD.decode(s).map_err(|_| JsError::new("bad base64"))
}

// ── wasm-bindgen exports ───────────────────────────────────────

#[wasm_bindgen]
pub fn create_account(password: Option<String>) -> Result<String, JsError> {
    let (mut sk, enc, unlocked) = create_account_logic(password.as_deref().map(str::as_bytes))?;
    let json = format!(
        "{{\"enc\":\"{}\",\"secret_key\":\"{}\",\"ed25519_pub\":\"{}\",\"x25519_pub\":\"{}\"}}",
        b64(&enc.to_bytes()?),
        b64(&sk),
        b64(&unlocked.signing.verifying.to_bytes()),
        b64(&unlocked.encryption.public.to_bytes()),
    );
    sk.zeroize(); // drop the raw Secret Key copy once it's encoded into the response
    UNLOCKED.with(|c| *c.borrow_mut() = Some(unlocked));
    Ok(json)
}

#[wasm_bindgen]
pub fn unlock(enc_b64: String, password: Option<String>, secret_key_b64: String) -> Result<String, JsError> {
    let record = EncryptedKeyset::from_bytes(&unb64(&enc_b64)?)?;
    let skv = unb64(&secret_key_b64)?;
    let sk: [u8; SECRET_KEY_LEN] = skv
        .as_slice()
        .try_into()
        .map_err(|_| JsError::new("secret key must be 16 bytes"))?;
    let unlocked = unlock_logic(&record, password.as_deref().map(str::as_bytes), &sk)?;
    let json = format!(
        "{{\"ed25519_pub\":\"{}\",\"x25519_pub\":\"{}\",\"generation\":{}}}",
        b64(&unlocked.signing.verifying.to_bytes()),
        b64(&unlocked.encryption.public.to_bytes()),
        record.generation,
    );
    UNLOCKED.with(|c| *c.borrow_mut() = Some(unlocked));
    Ok(json)
}

/// Derive the escrow retrieval credential `K_auth` (base64) for escrow login.
///
/// Reproduces the server's K_auth from the account's password (None for
/// SecretKeyOnly / SSO accounts), the 16-byte Secret Key, and the account's
/// SERVER-STORED Argon2id parameters (mem/iterations/parallelism/salt). The
/// server-stored params are passed in DIRECTLY (not `KdfParams::recommended()`,
/// which would mint fresh params) so `argon_key = Argon2id(password, params)`
/// reproduces exactly; the escrow HKDF then byte-matches rust-core
/// `keychain::unlock::derive_escrow_auth_key`. The server compares
/// `sha256(K_auth)`, so any byte drift here makes login always fail.
#[wasm_bindgen]
pub fn derive_escrow_auth(
    password: Option<String>,
    secret_key_b64: String,
    argon_salt_b64: String,
    argon_mem_kib: u32,
    argon_iterations: u32,
    argon_parallelism: u32,
) -> Result<String, JsValue> {
    let skv = unb64(&secret_key_b64)?;
    let secret_key: [u8; SECRET_KEY_LEN] = skv
        .as_slice()
        .try_into()
        .map_err(|_| JsError::new("secret key must be 16 bytes"))?;
    let salt = unb64(&argon_salt_b64)?;

    // Rebuild the account's exact Argon2id params from the server's stored values
    // (fields are all public) so the derived argon_key reproduces the server's.
    let params = KdfParams {
        mem_kib: argon_mem_kib,
        iterations: argon_iterations,
        parallelism: argon_parallelism,
        salt,
    };
    let argon_key = match password {
        Some(pw) => Some(derive_key(pw.as_bytes(), &params).map_err(|e| JsError::new(&format!("{e:?}")))?),
        None => None,
    };
    let k_auth = derive_escrow_auth_key(argon_key.as_ref(), &secret_key);
    Ok(b64(k_auth.expose_bytes()))
}

#[wasm_bindgen]
pub fn sign_challenge(
    host_b64: String,
    account_id_b64: String,
    device_id_b64: String,
    key_id_b64: String,
    nonce_b64: String,
    expiry: f64,
) -> Result<String, JsError> {
    let challenge = ServerAuthChallenge {
        host: unb64(&host_b64)?,
        account_id: unb64(&account_id_b64)?,
        device_id: unb64(&device_id_b64)?,
        key_id: unb64(&key_id_b64)?,
        nonce: unb64(&nonce_b64)?,
        expiry: expiry as u64,
    };
    UNLOCKED.with(|c| {
        let g = c.borrow();
        let u = g.as_ref().ok_or_else(|| JsError::new("keyset locked"))?;
        let sig = sign_server_auth(&u.signing.signing, &challenge).map_err(|e| JsError::new(&format!("{e:?}")))?;
        Ok(b64(&sig))
    })
}

#[wasm_bindgen]
pub fn build_registration(account_id_b64: String) -> Result<String, JsError> {
    let account_id = unb64(&account_id_b64)?;
    UNLOCKED.with(|c| {
        let g = c.borrow();
        let u = g.as_ref().ok_or_else(|| JsError::new("keyset locked"))?;
        let x25519_pub = u.encryption.public.to_bytes();
        let ed25519_pub = u.signing.verifying.to_bytes();
        // Canonical payload: u16(len) || account_id || x25519(32) || ed25519(32)
        let mut payload = Vec::with_capacity(2 + account_id.len() + 64);
        payload.extend_from_slice(&(account_id.len() as u16).to_be_bytes());
        payload.extend_from_slice(&account_id);
        payload.extend_from_slice(&x25519_pub);
        payload.extend_from_slice(&ed25519_pub);
        let rp = RegistrationPayload {
            account_id: account_id.clone(),
            x25519_pub,
            ed25519_pub,
        };
        let sig = sign_registration(&u.signing.signing, &rp).map_err(|e| JsError::new(&format!("{e:?}")))?;
        Ok(format!(
            "{{\"payload\":\"{}\",\"signature\":\"{}\"}}",
            b64(&payload),
            b64(&sig)
        ))
    })
}

/// Verify that a member's x25519 encryption key is cryptographically BOUND to its
/// ed25519 identity (finding M14), and return the ATTESTED x25519 (base64) so the
/// caller wraps the fresh VK to THAT key rather than to a server-supplied account
/// row. Verifies the member's `reg_signature` over the EXACT stored registration
/// payload bytes (`account_id_len:u16be || account_id || x25519:32 || ed25519:32`),
/// under the manifest-verified `expected_ed25519`. We verify the stored bytes — not
/// a payload reconstructed from a claimed account_id — because the server mints its
/// own account_id while the signature was made over the client's; reconstructing
/// from the server id would fail for every honest account. A valid signature proves
/// the member itself bound this x25519 (the server cannot forge it without the
/// member's signing key) → safe to wrap to. Throws on any mismatch.
#[wasm_bindgen]
pub fn verify_member_binding(
    reg_payload_b64: String,
    reg_sig_b64: String,
    expected_ed25519_b64: String,
) -> Result<String, JsError> {
    let payload_bytes = unb64(&reg_payload_b64)?;
    let sig = unb64(&reg_sig_b64)?;
    let expected_ed: [u8; 32] = unb64(&expected_ed25519_b64)?
        .as_slice()
        .try_into()
        .map_err(|_| JsError::new("bad ed25519 length"))?;

    // Parse the canonical RegistrationPayload the member signed (server stores it
    // verbatim): account_id_len:u16be || account_id || x25519:32 || ed25519:32.
    if payload_bytes.len() < 2 {
        return Err(JsError::new("reg payload: truncated"));
    }
    let alen = u16::from_be_bytes([payload_bytes[0], payload_bytes[1]]) as usize;
    if payload_bytes.len() != 2 + alen + 32 + 32 {
        return Err(JsError::new("reg payload: bad length"));
    }
    let account_id = payload_bytes[2..2 + alen].to_vec();
    let x: [u8; 32] = payload_bytes[2 + alen..2 + alen + 32].try_into().unwrap();
    let ed: [u8; 32] = payload_bytes[2 + alen + 32..].try_into().unwrap();

    // The payload's ed25519 MUST be the manifest-verified member identity, else a
    // server could hand us a valid self-signed payload for an UNRELATED keyset whose
    // x25519 it controls and pass the signature check.
    if ed != expected_ed {
        return Err(JsError::new(
            "reg payload ed25519 does not match the manifest-verified member identity",
        ));
    }
    let payload = RegistrationPayload {
        account_id,
        x25519_pub: x,
        ed25519_pub: ed,
    };
    let vk = Ed25519VerifyingKey::from_bytes(&ed).map_err(|_| JsError::new("bad ed25519 key"))?;
    verify_registration(&vk, &payload, &sig).map_err(|_| {
        JsError::new("member x25519<->ed25519 binding is not attested by a valid registration signature")
    })?;
    Ok(b64(&x))
}

/// u32-BE length-prefix + bytes (the server's SyncObject `put` helper).
fn put(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

struct RotMember {
    ed: Vec<u8>,
    x: Vec<u8>,
    role: u8,
    not_after: i64,
}

/// Verify a `/v1/grants` manifest envelope (tag 3) against the PINNED genesis
/// owner before its member set is trusted for rotation. Closes the gap where the
/// panel rendered an unverified, server-supplied member set: a malicious server
/// can no longer inject a member (it cannot forge the genesis owner's Ed25519
/// signature). Returns the verified member set JSON `{epoch, members:[{ed,role}]}`
/// on success; errors if the envelope is malformed, the signature is invalid, or
/// the author is not the pinned genesis owner.
///
/// Trust model: single genesis-admin (the panel operator). `genesis_owner_b64` is
/// pinned client-side (TOFU) by the caller, NOT taken on faith each call. Vaults
/// with a multi-admin manifest chain need full chain verification (the author may
/// be a later admin) — out of scope here; this covers the operator-managed case.
#[wasm_bindgen]
pub fn verify_manifest_authorized(
    manifest_b64: String,
    genesis_owner_b64: String,
    vault_id_b64: String,
) -> Result<String, JsError> {
    let buf = unb64(&manifest_b64)?;
    let genesis = unb64(&genesis_owner_b64)?;
    let target_vault = unb64(&vault_id_b64)?;

    // Parse the tag-3 envelope (shared with the chain verifier).
    let (vault_id, epoch, blob, sig, author) = parse_manifest_envelope(&buf)?;

    // (0) the envelope MUST be for the vault we are rotating. Without this, an
    // untrusted server can return a valid, genesis-signed manifest from a DIFFERENT
    // vault of the same operator (cross-vault splice) and pass every check below.
    // Mirrors rust-core `verify_manifest` (membership.rs) which pins vault_id.
    if vault_id != target_vault {
        return Err(JsError::new(
            "manifest vault_id does not match the target vault — possible cross-vault splice",
        ));
    }
    // (1) author must be the pinned genesis owner.
    if author != genesis {
        return Err(JsError::new("manifest author is not the pinned genesis owner"));
    }
    // (2) verify the Ed25519 signature and (3) parse the authenticated member set
    // (both shared with the chain verifier — same AAD, domain, and strictness).
    let members = verify_and_parse_manifest(&vault_id, epoch, &blob, &sig, &author)?;
    let members_json: Vec<String> = members
        .iter()
        .map(|(ed, role)| format!("{{\"ed25519_pub\":\"{}\",\"role\":{}}}", b64(ed), role))
        .collect();
    Ok(format!(
        "{{\"epoch\":{},\"members\":[{}]}}",
        epoch,
        members_json.join(",")
    ))
}

/// Parse a tag-3 manifest envelope → (vault_id, epoch, manifest_blob, sig, author).
fn parse_manifest_envelope(buf: &[u8]) -> Result<(Vec<u8>, u64, Vec<u8>, Vec<u8>, Vec<u8>), JsError> {
    let trunc = || JsError::new("manifest: truncated envelope");
    let mut p = 0usize;
    if buf.is_empty() || buf[0] != 3 {
        return Err(JsError::new("not a manifest envelope (tag 3)"));
    }
    p += 1;
    let take = |p: &mut usize| -> Result<Vec<u8>, JsError> {
        if *p + 4 > buf.len() {
            return Err(trunc());
        }
        let n = u32::from_be_bytes([buf[*p], buf[*p + 1], buf[*p + 2], buf[*p + 3]]) as usize;
        *p += 4;
        if *p + n > buf.len() {
            return Err(trunc());
        }
        let b = buf[*p..*p + n].to_vec();
        *p += n;
        Ok(b)
    };
    let vault_id = take(&mut p)?;
    if p + 8 > buf.len() {
        return Err(trunc());
    }
    let epoch = u64::from_be_bytes(buf[p..p + 8].try_into().unwrap());
    p += 8;
    let blob = take(&mut p)?;
    let sig = take(&mut p)?;
    let author = take(&mut p)?;
    Ok((vault_id, epoch, blob, sig, author))
}

/// Verify a manifest envelope's Ed25519 signature and parse its member set
/// (`[(ed, role)]`), checking the blob's embedded epoch matches.
fn verify_and_parse_manifest(
    vault_id: &[u8],
    epoch: u64,
    blob: &[u8],
    sig: &[u8],
    author: &[u8],
) -> Result<Vec<(Vec<u8>, u8)>, JsError> {
    let vk = Ed25519VerifyingKey::from_bytes(author).map_err(|_| JsError::new("bad author key"))?;
    let vo = VersionedObject::from_content(
        AssociatedData::new(vault_id.to_vec(), b"__manifest__".to_vec(), epoch),
        blob,
    );
    verify_version(&vk, &vo, sig).map_err(|_| JsError::new("manifest signature invalid"))?;
    const DOM: &[u8] = b"unissh-manifest-v1";
    if blob.len() < DOM.len() + 8 + 4 || &blob[..DOM.len()] != DOM {
        return Err(JsError::new("manifest blob: bad format"));
    }
    let mut q = DOM.len();
    let blob_epoch = u64::from_be_bytes(blob[q..q + 8].try_into().unwrap());
    if blob_epoch != epoch {
        return Err(JsError::new("manifest blob epoch mismatch"));
    }
    q += 8;
    let count = u32::from_be_bytes(blob[q..q + 4].try_into().unwrap()) as usize;
    q += 4;
    let mut members = Vec::with_capacity(count.min(4096));
    for _ in 0..count {
        if q + 1 + 2 > blob.len() {
            return Err(JsError::new("manifest blob: truncated member"));
        }
        let role = blob[q];
        q += 1;
        // Match native strictness (server codec.rs rejects role > 2): a manifest
        // carrying an out-of-range role is malformed, not silently coerced.
        if role > 2 {
            return Err(JsError::new("manifest member role out of range (>2)"));
        }
        let edlen = u16::from_be_bytes([blob[q], blob[q + 1]]) as usize;
        q += 2;
        if q + edlen > blob.len() {
            return Err(JsError::new("manifest blob: truncated member ed"));
        }
        members.push((blob[q..q + edlen].to_vec(), role));
        q += edlen;
    }
    if q != blob.len() {
        return Err(JsError::new("manifest blob: trailing bytes"));
    }
    Ok(members)
}

/// Verify the FULL membership-manifest authority CHAIN from the pinned genesis
/// owner to the latest epoch (multi-admin, mirrors rust-core `verify_chain_to_epoch`):
/// the genesis manifest (epoch 1) must be signed by the pinned genesis owner, and
/// each later manifest by an ADMIN of the immediately-previous verified set, with
/// contiguous epochs. `manifests_b64` is a newline-separated list of tag-3 manifest
/// envelopes in epoch order (1..N). Returns the verified member set at the LATEST
/// epoch `{epoch, members:[{ed,role}]}`; errors on any signature / authority / gap.
/// This supersedes `verify_manifest_authorized` for orgs where a non-genesis admin
/// signed a later manifest (which the single-manifest check would wrongly reject).
#[wasm_bindgen]
pub fn verify_manifest_chain(
    genesis_owner_b64: String,
    manifests_b64: String,
    vault_id_b64: String,
) -> Result<String, JsError> {
    let genesis = unb64(&genesis_owner_b64)?;
    let target_vault = unb64(&vault_id_b64)?;
    let mut prev: Option<Vec<(Vec<u8>, u8)>> = None;
    let mut prev_epoch = 0u64;
    let mut last_json = String::new();
    let mut seen = 0u32;
    for line in manifests_b64.split('\n') {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let buf = unb64(line)?;
        let (vault_id, epoch, blob, sig, author) = parse_manifest_envelope(&buf)?;
        // Every link MUST belong to the target vault (cross-vault splice guard).
        if vault_id != target_vault {
            return Err(JsError::new(
                "manifest vault_id does not match the target vault — possible cross-vault splice",
            ));
        }
        match &prev {
            None => {
                if epoch != 1 {
                    return Err(JsError::new("manifest chain must start at epoch 1"));
                }
                if author != genesis {
                    return Err(JsError::new("genesis manifest not signed by the pinned genesis owner"));
                }
            }
            Some(pm) => {
                if epoch != prev_epoch + 1 {
                    return Err(JsError::new("non-contiguous manifest chain (epoch gap)"));
                }
                let is_admin = pm
                    .iter()
                    .any(|(ed, role)| ed.as_slice() == author.as_slice() && *role == 2);
                if !is_admin {
                    return Err(JsError::new("manifest author is not an admin of the previous epoch"));
                }
            }
        }
        let members = verify_and_parse_manifest(&vault_id, epoch, &blob, &sig, &author)?;
        let mj: Vec<String> = members
            .iter()
            .map(|(ed, role)| format!("{{\"ed25519_pub\":\"{}\",\"role\":{}}}", b64(ed), role))
            .collect();
        last_json = format!("{{\"epoch\":{},\"members\":[{}]}}", epoch, mj.join(","));
        prev_epoch = epoch;
        prev = Some(members);
        seen += 1;
    }
    if seen == 0 {
        return Err(JsError::new("empty manifest chain"));
    }
    Ok(last_json)
}

/// Epoch rotation: fresh VK → signed manifest (tag 3) + per-member grants (tag 4),
/// HPKE-wrapped to each member's x25519. Byte-exact with rust-core vault::build_*
/// (domains unissh-manifest-v1 / unissh-grant-v1 / unissh-vkwrap-v1 / unissh-sig-v1)
/// and the server's SyncObject wire envelope (policy.rs). `members_csv` lines:
/// `ed25519_b64|x25519_b64|role`. Returns {manifest, grants[], new_epoch} (base64).
#[wasm_bindgen]
pub fn rotate_grants(
    vault_id_b64: String,
    new_epoch: f64,
    members_csv: String,
) -> Result<String, JsError> {
    let vault_id = unb64(&vault_id_b64)?;
    let epoch = new_epoch as u64;

    let mut members: Vec<RotMember> = Vec::new();
    for line in members_csv.split('\n') {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // ed|x|role  or  ed|x|role|not_after (unix-sec; empty/<=0 = no expiry).
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() != 3 && parts.len() != 4 {
            return Err(JsError::new("bad member line"));
        }
        let ed = unb64(parts[0])?;
        let x = unb64(parts[1])?;
        let role: u8 = parts[2].trim().parse().map_err(|_| JsError::new("bad role"))?;
        let not_after: i64 = match parts.get(3).map(|s| s.trim()) {
            Some(s) if !s.is_empty() => s.parse().map_err(|_| JsError::new("bad not_after"))?,
            _ => 0,
        };
        members.push(RotMember {
            ed,
            x,
            role: role.min(2),
            not_after,
        });
    }
    if members.is_empty() {
        return Err(JsError::new("no members"));
    }

    UNLOCKED.with(|c| {
        let g = c.borrow();
        let u = g.as_ref().ok_or_else(|| JsError::new("keyset locked"))?;
        let author = u.signing.verifying.to_bytes().to_vec();
        let vk = SymmetricKey::generate();

        // canonical_member_payload: domain || epoch || count || [role||len||ed]*, sorted asc.
        let mut sorted: Vec<&RotMember> = members.iter().collect();
        sorted.sort_by(|a, b| a.ed.cmp(&b.ed));
        for w in sorted.windows(2) {
            if w[0].ed == w[1].ed {
                return Err(JsError::new("duplicate member"));
            }
        }
        let mut payload = Vec::new();
        payload.extend_from_slice(b"unissh-manifest-v1");
        payload.extend_from_slice(&epoch.to_be_bytes());
        payload.extend_from_slice(&(sorted.len() as u32).to_be_bytes());
        for m in &sorted {
            // Reject (don't silently truncate via `as u16`) an over-long ed key —
            // matches the native builder's explicit error.
            if m.ed.len() > u16::MAX as usize {
                return Err(JsError::new("member ed25519 key too long"));
            }
            payload.push(m.role);
            payload.extend_from_slice(&(m.ed.len() as u16).to_be_bytes());
            payload.extend_from_slice(&m.ed);
        }
        let m_vo = VersionedObject::from_content(
            AssociatedData::new(vault_id.clone(), b"__manifest__".to_vec(), epoch),
            &payload,
        );
        let m_sig = sign_version(&u.signing.signing, &m_vo).map_err(|e| JsError::new(&format!("{e:?}")))?;
        let mut m_obj = vec![3u8];
        put(&mut m_obj, &vault_id);
        m_obj.extend_from_slice(&epoch.to_be_bytes());
        put(&mut m_obj, &payload);
        put(&mut m_obj, &m_sig);
        put(&mut m_obj, &author);

        // per-member grants
        let mut grants: Vec<String> = Vec::with_capacity(members.len());
        for m in &members {
            let recipient = X25519PublicKey::from_bytes(&m.x).map_err(|_| JsError::new("bad x25519 pub"))?;
            let info = vk_wrap_info(&vault_id, &m.ed, epoch).map_err(|e| JsError::new(&format!("{e:?}")))?;
            let wrapped_vk = seal_key_to_public(&recipient, &vk, &info).map_err(|e| JsError::new(&format!("{e:?}")))?;
            // not_after:i64be(8), per-member (sentinel <=0 = no expiry). In BOTH
            // the signed content and the wire object, after role — byte-exact with
            // rust-core membership.rs / server crypto.rs tag 4.
            let not_after: i64 = m.not_after;
            let mut content = Vec::new();
            content.extend_from_slice(b"unissh-grant-v1");
            content.push(m.role);
            content.extend_from_slice(&not_after.to_be_bytes());
            content.extend_from_slice(&wrapped_vk);
            let g_vo = VersionedObject::from_content(
                AssociatedData::new(vault_id.clone(), m.ed.clone(), epoch),
                &content,
            );
            let g_sig = sign_version(&u.signing.signing, &g_vo).map_err(|e| JsError::new(&format!("{e:?}")))?;
            let mut g_obj = vec![4u8];
            put(&mut g_obj, &vault_id);
            put(&mut g_obj, &m.ed);
            g_obj.extend_from_slice(&epoch.to_be_bytes());
            g_obj.push(m.role);
            g_obj.extend_from_slice(&not_after.to_be_bytes());
            put(&mut g_obj, &wrapped_vk);
            put(&mut g_obj, &g_sig);
            put(&mut g_obj, &author);
            grants.push(b64(&g_obj));
        }

        let grants_json = grants.iter().map(|s| format!("\"{s}\"")).collect::<Vec<_>>().join(",");
        Ok(format!(
            "{{\"manifest\":\"{}\",\"grants\":[{}],\"new_epoch\":{}}}",
            b64(&m_obj),
            grants_json,
            epoch
        ))
    })
}

#[wasm_bindgen]
pub fn lock() {
    UNLOCKED.with(|c| *c.borrow_mut() = None);
}

#[wasm_bindgen]
pub fn is_unlocked() -> bool {
    UNLOCKED.with(|c| c.borrow().is_some())
}
