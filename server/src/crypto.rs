//! Server-side crypto (minimal by design): `verify_strict` Ed25519 for
//! registration / server-auth (always) and optional record signatures (§2.4), plus parsing
//! the `EncryptedKeyset` header. The formats mirror `crates/crypto/src/*` and
//! `crates/keychain/src/keyset.rs` → byte compatibility. The server does NOT
//! decrypt the payload and holds no private keys.

use crate::error::AppError;
use ed25519_dalek::{Signature, VerifyingKey};

/// Blob version header (mirror of `crypto/src/version.rs`).
const FORMAT_VERSION: u8 = 0x01;
/// `AlgId::Ed25519` (u16 BE) — signature header = `[0x01, 0x00, 0x20]`.
const ALG_ED25519: u16 = 0x0020;
const SIG_BLOB_LEN: usize = 3 + 64; // header(3) + raw sig(64) = 67

/// Domains for domain-separated signatures (`crypto/src/domain_sig.rs`).
pub const REGISTRATION_SIG_DOMAIN: &[u8] = b"unissh-registration-v1";
pub const SERVER_AUTH_SIG_DOMAIN: &[u8] = b"unissh-server-auth-v1";
pub const AUDIT_SIG_DOMAIN: &[u8] = b"unissh-audit-v1";
/// Signature domain for versioned records (`crypto/src/signature.rs`).
const RECORD_SIG_DOMAIN: &[u8] = b"unissh-sig-v1";
/// Grant content domain (`vault/src/membership.rs`).
const GRANT_CONTENT_DOMAIN: &[u8] = b"unissh-grant-v1";
/// Record AAD markers (`vault/src/vault.rs`, `membership.rs`).
const VAULT_MARKER: &[u8] = b"__vault__";
const MANIFEST_MARKER: &[u8] = b"__manifest__";
/// DEDICATED signature domain for per-account state (A3). MUST match
/// `unissh_crypto::ACCOUNT_STATE_SIG_DOMAIN` (rust-core) byte-for-byte.
const ACCOUNT_STATE_SIG_DOMAIN: &[u8] = b"unissh-account-state-v1";

/// Canonical domain message: `len(domain):u16BE || domain || payload`.
fn domain_message(domain: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + domain.len() + payload.len());
    out.extend_from_slice(&(domain.len() as u16).to_be_bytes());
    out.extend_from_slice(domain);
    out.extend_from_slice(payload);
    out
}

/// Extract the 64-byte Ed25519 signature from the 67-byte `header || sig` blob.
fn parse_sig_blob(blob: &[u8]) -> Result<[u8; 64], AppError> {
    if blob.len() != SIG_BLOB_LEN {
        return Err(AppError::malformed("signature blob: wrong length"));
    }
    if blob[0] != FORMAT_VERSION {
        return Err(AppError::malformed("signature blob: bad format version"));
    }
    let alg = u16::from_be_bytes([blob[1], blob[2]]);
    if alg != ALG_ED25519 {
        return Err(AppError::malformed("signature blob: not Ed25519"));
    }
    let mut sig = [0_u8; 64];
    sig.copy_from_slice(&blob[3..]);
    Ok(sig)
}

fn verifying_key(vk_bytes: &[u8]) -> Result<VerifyingKey, AppError> {
    let arr: [u8; 32] = vk_bytes
        .try_into()
        .map_err(|_| AppError::malformed("pubkey: expected 32 bytes"))?;
    VerifyingKey::from_bytes(&arr).map_err(|_| AppError::malformed("pubkey: invalid Ed25519 point"))
}

/// Basic domain verification (`verify_strict`). Failure → `unauthenticated`.
pub fn domain_verify(
    vk_bytes: &[u8],
    domain: &[u8],
    payload: &[u8],
    sig_blob: &[u8],
) -> Result<(), AppError> {
    let vk = verifying_key(vk_bytes)?;
    let sig_bytes = parse_sig_blob(sig_blob)?;
    let sig = Signature::from_bytes(&sig_bytes);
    let msg = domain_message(domain, payload);
    vk.verify_strict(&msg, &sig)
        .map_err(|_| AppError::unauthenticated("signature verification failed"))
}

/// Open registration payload (mirror of `crypto/src/registration.rs`).
#[derive(Debug, Clone)]
pub struct RegistrationPayload {
    pub account_id: Vec<u8>,
    pub x25519_pub: [u8; 32],
    pub ed25519_pub: [u8; 32],
}

impl RegistrationPayload {
    /// Parse the canonical payload (as sent by the client) into the triple.
    pub fn parse_canonical(bytes: &[u8]) -> Result<Self, AppError> {
        if bytes.len() < 2 {
            return Err(AppError::malformed("registration payload too short"));
        }
        let alen = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        let need = 2 + alen + 64;
        if bytes.len() != need {
            return Err(AppError::malformed("registration payload length mismatch"));
        }
        let account_id = bytes[2..2 + alen].to_vec();
        let mut x25519_pub = [0_u8; 32];
        x25519_pub.copy_from_slice(&bytes[2 + alen..2 + alen + 32]);
        let mut ed25519_pub = [0_u8; 32];
        ed25519_pub.copy_from_slice(&bytes[2 + alen + 32..2 + alen + 64]);
        Ok(Self {
            account_id,
            x25519_pub,
            ed25519_pub,
        })
    }

    /// `len(account_id):u16BE || account_id || x25519_pub(32) || ed25519_pub(32)`.
    pub fn canonical(&self) -> Result<Vec<u8>, AppError> {
        if self.account_id.len() > u16::MAX as usize {
            return Err(AppError::malformed("registration: account_id too long"));
        }
        let mut out = Vec::with_capacity(2 + self.account_id.len() + 64);
        out.extend_from_slice(&(self.account_id.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.account_id);
        out.extend_from_slice(&self.x25519_pub);
        out.extend_from_slice(&self.ed25519_pub);
        Ok(out)
    }
}

/// Verify the self-attested registration signature (vk = ed25519_pub FROM the payload).
/// Binds exactly the triple `(account_id, x25519_pub, ed25519_pub)`.
pub fn verify_registration(payload: &RegistrationPayload, sig_blob: &[u8]) -> Result<(), AppError> {
    domain_verify(
        &payload.ed25519_pub,
        REGISTRATION_SIG_DOMAIN,
        &payload.canonical()?,
        sig_blob,
    )
}

/// Server-auth challenge (mirror of `crypto/src/server_auth.rs`).
#[derive(Debug, Clone)]
pub struct ServerAuthChallenge {
    pub host: Vec<u8>,
    pub account_id: Vec<u8>,
    pub device_id: Vec<u8>,
    pub key_id: Vec<u8>,
    pub nonce: Vec<u8>,
    pub expiry: u64,
}

impl ServerAuthChallenge {
    /// `for each (host,account_id,device_id,key_id,nonce): len:u16BE || field`,
    /// then `expiry:u64BE`.
    pub fn canonical(&self) -> Result<Vec<u8>, AppError> {
        fn put(out: &mut Vec<u8>, f: &[u8]) -> Result<(), AppError> {
            if f.len() > u16::MAX as usize {
                return Err(AppError::malformed("server-auth: field too long"));
            }
            out.extend_from_slice(&(f.len() as u16).to_be_bytes());
            out.extend_from_slice(f);
            Ok(())
        }
        let mut out = Vec::new();
        put(&mut out, &self.host)?;
        put(&mut out, &self.account_id)?;
        put(&mut out, &self.device_id)?;
        put(&mut out, &self.key_id)?;
        put(&mut out, &self.nonce)?;
        out.extend_from_slice(&self.expiry.to_be_bytes());
        Ok(out)
    }
}

/// Verify the server-auth challenge signature under the device ed25519_pub.
pub fn verify_server_auth(
    device_ed25519_pub: &[u8],
    challenge: &ServerAuthChallenge,
    sig_blob: &[u8],
) -> Result<(), AppError> {
    domain_verify(
        device_ed25519_pub,
        SERVER_AUTH_SIG_DOMAIN,
        &challenge.canonical()?,
        sig_blob,
    )
}

/// Parsed `EncryptedKeyset` header (open metadata for the index; §6.4).
#[derive(Debug, Clone)]
pub struct KeysetHeader {
    pub mode: u8,
    pub generation: u32,
    pub x25519_pub: [u8; 32],
    pub ed25519_pub: [u8; 32],
}

/// Parse the keyset-blob header (mirror of `keychain/src/keyset.rs::from_bytes`).
/// The server parses ONLY generation + mode + the two pubkeys; it stores everything verbatim
/// and does NOT alter generation.
pub fn parse_keyset_header(blob: &[u8]) -> Result<KeysetHeader, AppError> {
    // version(1)+mode(1)+generation(4)+kdf_len(2) = 8, then pubkeys(64) minimum.
    if blob.len() < 8 + 64 {
        return Err(AppError::malformed("keyset: too short"));
    }
    // Keyset format: v3 current, v2 legacy — both have the SAME header layout
    // (the version marks the key-derivation "recipe", not the offsets of the open fields
    // the server reads: mode/generation/pubkeys). Mirror of keychain
    // `KEYSET_FORMAT_VERSION=3` / `KEYSET_FORMAT_LEGACY=2`; other versions — reject.
    if blob[0] != 2 && blob[0] != 3 {
        return Err(AppError::malformed(
            "keyset: bad format version (expected 2 or 3)",
        ));
    }
    let mode = blob[1];
    if mode != 1 && mode != 2 {
        return Err(AppError::malformed("keyset: bad mode"));
    }
    let generation = u32::from_be_bytes([blob[2], blob[3], blob[4], blob[5]]);
    let kdf_len = u16::from_be_bytes([blob[6], blob[7]]) as usize;
    let mut pos = 8_usize;
    if kdf_len > 0 {
        let end = pos
            .checked_add(kdf_len)
            .ok_or_else(|| AppError::malformed("keyset: kdf overflow"))?;
        if blob.len() < end + 64 {
            return Err(AppError::malformed("keyset: truncated after kdf"));
        }
        pos = end;
    }
    // mode↔kdf consistency (mirror of the core): Password⇒kdf, SecretKeyOnly⇒none.
    match (mode, kdf_len > 0) {
        (1, true) | (2, false) => {}
        _ => return Err(AppError::malformed("keyset: mode/kdf mismatch")),
    }
    if blob.len() < pos + 64 + 1 {
        return Err(AppError::malformed("keyset: missing pubkeys/wrapped"));
    }
    let mut x25519_pub = [0_u8; 32];
    x25519_pub.copy_from_slice(&blob[pos..pos + 32]);
    let mut ed25519_pub = [0_u8; 32];
    ed25519_pub.copy_from_slice(&blob[pos + 32..pos + 64]);
    // wrapped_keyset = the remainder, must be non-empty.
    if blob.len() <= pos + 64 {
        return Err(AppError::malformed("keyset: empty wrapped_keyset"));
    }
    Ok(KeysetHeader {
        mode,
        generation,
        x25519_pub,
        ed25519_pub,
    })
}

// ---- Optional server-side record-signature verification (§2.4 defense-in-depth) ----
//
// Mirror of `crypto/src/signature.rs` + per-record AAD/content from `vault/src/*`.
// Signed message = `"unissh-sig-v1" || AAD.canonical || SHA-256(content)`,
// verify_strict under the record's author_pubkey. With `validate_signatures` the server
// discards garbage/forged objects early; the client re-verifies on read anyway.

/// Cursor parser (does not panic), mirror of the codec.
struct Cursor<'a> {
    b: &'a [u8],
}
impl<'a> Cursor<'a> {
    fn new(b: &'a [u8]) -> Self {
        Cursor { b }
    }
    fn u8(&mut self) -> Result<u8, AppError> {
        let (h, t) = self.b.split_first().ok_or_else(rec_fmt)?;
        self.b = t;
        Ok(*h)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], AppError> {
        if self.b.len() < n {
            return Err(rec_fmt());
        }
        let (h, t) = self.b.split_at(n);
        self.b = t;
        Ok(h)
    }
    fn u32(&mut self) -> Result<u32, AppError> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64(&mut self) -> Result<u64, AppError> {
        let s = self.take(8)?;
        let mut a = [0_u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_be_bytes(a))
    }
    fn bytes(&mut self) -> Result<&'a [u8], AppError> {
        let n = self.u32()? as usize;
        self.take(n)
    }
}

fn rec_fmt() -> AppError {
    AppError::malformed("record signature: format error")
}

/// AAD.canonical: `len(vault_id):u16BE || vault_id || len(item_id):u16BE || item_id || version:u64BE`.
fn aad_canonical(vault_id: &[u8], item_id: &[u8], version: u64) -> Result<Vec<u8>, AppError> {
    if vault_id.len() > u16::MAX as usize || item_id.len() > u16::MAX as usize {
        return Err(rec_fmt());
    }
    let mut out = Vec::with_capacity(2 + vault_id.len() + 2 + item_id.len() + 8);
    out.extend_from_slice(&(vault_id.len() as u16).to_be_bytes());
    out.extend_from_slice(vault_id);
    out.extend_from_slice(&(item_id.len() as u16).to_be_bytes());
    out.extend_from_slice(item_id);
    out.extend_from_slice(&version.to_be_bytes());
    Ok(out)
}

/// Verify the signature of a versioned record (`verify_strict`).
fn verify_versioned(
    author: &[u8],
    vault_id: &[u8],
    item_id: &[u8],
    version: u64,
    content: &[u8],
    sig_blob: &[u8],
) -> Result<(), AppError> {
    let vk = verifying_key(author)?;
    let sig_bytes = parse_sig_blob(sig_blob)?;
    let sig = Signature::from_bytes(&sig_bytes);
    let aad = aad_canonical(vault_id, item_id, version)?;
    let digest = crate::ids::sha256(content);
    let mut msg = Vec::with_capacity(RECORD_SIG_DOMAIN.len() + aad.len() + 32);
    msg.extend_from_slice(RECORD_SIG_DOMAIN);
    msg.extend_from_slice(&aad);
    msg.extend_from_slice(&digest);
    vk.verify_strict(&msg, &sig)
        .map_err(|_| AppError::malformed("record signature verification failed"))
}

/// Verify a record's Ed25519 signature (§2.4). Vault/Item/Manifest/Grant — full
/// verification; Audit (design-time payload, §11) and Keyset (AEAD-authenticated)
/// — sig is NOT checked here (audit is gated by author==genesis separately).
/// `bytes` — verbatim `SyncObject::to_bytes()`.
pub fn verify_record_sig(bytes: &[u8]) -> Result<(), AppError> {
    let mut r = Cursor::new(bytes);
    let tag = r.u8()?;
    match tag {
        1 => {
            // Vault: put(vault_id) [sync_target] put(name_blob) put(wrapped_vk)
            // [version:u64] [tombstone] put(sig) put(author) [key_epoch] [cache_policy]
            let vault_id = r.bytes()?;
            let _sync_target = r.u8()?;
            let name_blob = r.bytes()?;
            let wrapped_vk = r.bytes()?;
            let version = r.u64()?;
            let _tombstone = r.u8()?;
            let sig = r.bytes()?;
            let author = r.bytes()?;
            let mut content = Vec::with_capacity(wrapped_vk.len() + name_blob.len());
            content.extend_from_slice(wrapped_vk);
            content.extend_from_slice(name_blob);
            verify_versioned(author, vault_id, VAULT_MARKER, version, &content, sig)
        }
        2 => {
            // Item: put(vault_id) put(item_id) [item_type:u32] put(content_blob)
            // put(wrapped_item_key) [version:u64] [tombstone] put(sig) put(author) [key_epoch]
            let vault_id = r.bytes()?;
            let item_id = r.bytes()?;
            let _item_type = r.u32()?;
            let content_blob = r.bytes()?;
            let _wrapped_item_key = r.bytes()?;
            let version = r.u64()?;
            let _tombstone = r.u8()?;
            let sig = r.bytes()?;
            let author = r.bytes()?;
            verify_versioned(author, vault_id, item_id, version, content_blob, sig)
        }
        3 => {
            // Manifest: put(vault_id) [key_epoch:u64] put(manifest_blob) put(sig) put(author)
            let vault_id = r.bytes()?;
            let key_epoch = r.u64()?;
            let manifest_blob = r.bytes()?;
            let sig = r.bytes()?;
            let author = r.bytes()?;
            verify_versioned(
                author,
                vault_id,
                MANIFEST_MARKER,
                key_epoch,
                manifest_blob,
                sig,
            )
        }
        4 => {
            // Grant: put(vault_id) put(member_pubkey) [key_epoch:u64] [role:u8]
            // put(wrapped_vk) put(sig) put(author)
            let vault_id = r.bytes()?;
            let member = r.bytes()?;
            let key_epoch = r.u64()?;
            let role = r.u8()?;
            // not_after:i64be(8) — in the signed content AND the wire (after role).
            let not_after = r.u64()? as i64;
            let wrapped_vk = r.bytes()?;
            let sig = r.bytes()?;
            let author = r.bytes()?;
            let mut content =
                Vec::with_capacity(GRANT_CONTENT_DOMAIN.len() + 1 + 8 + wrapped_vk.len());
            content.extend_from_slice(GRANT_CONTENT_DOMAIN);
            content.push(role);
            content.extend_from_slice(&not_after.to_be_bytes());
            content.extend_from_slice(wrapped_vk);
            verify_versioned(author, vault_id, member, key_epoch, &content, sig)
        }
        5 | 6 => Ok(()), // Audit (design-time payload) / Keyset (AEAD) — not an Ed25519 record-sig
        7 => {
            // AccountState: [version:u64] put(payload) put(sig) put(author).
            // Dedicated domain: message = ACCOUNT_STATE_SIG_DOMAIN || version_be ||
            // sha256(payload) (mirror unissh_crypto::sign_account_state).
            let version = r.u64()?;
            let payload = r.bytes()?;
            let sig_blob = r.bytes()?;
            let author = r.bytes()?;
            let vk = verifying_key(author)?;
            let sig_bytes = parse_sig_blob(sig_blob)?;
            let sig = Signature::from_bytes(&sig_bytes);
            let digest = crate::ids::sha256(payload);
            let mut msg = Vec::with_capacity(ACCOUNT_STATE_SIG_DOMAIN.len() + 8 + 32);
            msg.extend_from_slice(ACCOUNT_STATE_SIG_DOMAIN);
            msg.extend_from_slice(&version.to_be_bytes());
            msg.extend_from_slice(&digest);
            vk.verify_strict(&msg, &sig)
                .map_err(|_| AppError::malformed("account state signature verification failed"))
        }
        _ => Err(AppError::malformed("unknown object tag")),
    }
}
