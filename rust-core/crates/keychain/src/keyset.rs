//! Personal keyset: X25519 (encryption) + Ed25519 (signing) pair, encrypted
//! under the Unlock Key.
//!
//! ## `EncryptedKeyset` record format
//! ```text
//! [0]      keyset_format_version : u8 (=3 current; =2 legacy, read with migration)
//! [1]      mode                  : u8 (1=Password, 2=SecretKeyOnly)
//! [2..6]   generation            : u32 be (record generation, part of the AAD)
//! [6..8]   kdf_params_len        : u16 be (0 if there is no password)
//! [..]     kdf_params            : crypto::KdfParams blob (if present)
//! [..+32]  x25519_public         : 32
//! [..+32]  ed25519_public        : 32
//! [..]     wrapped_keyset        : crypto AEAD blob over the keyset secrets
//! ```
//! Plaintext under the AEAD = `x25519_secret(32) || ed25519_secret(32)`. The AEAD
//! is bound (associated data) to the public X25519 key AND the generation — an
//! identity swap or a rollback to an old blob breaks the unwrap.
//!
//! ## Schema versions and migration (see `SECURITY.md` → "On-disk format changes")
//! The `keyset_format_version` byte is the version of the ENTIRE record recipe
//! (layout + Unlock Key derivation + AAD recipe), not just the algorithm:
//! - **v3 (current, "explicit"):** length-framing IKM ([`derive_unlock_key`]) +
//!   AEAD with header binding in the AAD ([`aead_decrypt`]). Always written.
//! - **v2 (legacy, ambiguous):** on disk it may have been written before round 2
//!   (Scheme A: raw IKM + AAD without the header) OR during round 2..7 (Scheme B,
//!   crypto-identical to v3 but tagged with the old byte). The byte cannot tell
//!   them apart — round 2 changed the crypto without bumping the version. So v2 is
//!   read by **trial** (current → legacy), and on success [`unlock_account_migrating`]
//!   re-wraps the record to v3 (`generation+1`), removing the ambiguity for good.

use zeroize::{Zeroize, Zeroizing};

use unissh_crypto::{
    aead_decrypt, aead_decrypt_pre_agility, aead_encrypt, derive_key, AssociatedData,
    Ed25519Keypair, Ed25519SigningKey, KdfParams, SymmetricKey, X25519Keypair, X25519SecretKey,
};

use crate::error::KeychainError;
use crate::secret_key::SecretKey;
use crate::unlock::{derive_unlock_key, derive_unlock_key_legacy_v1};

/// Current keyset record format version (the full recipe: layout + derivation +
/// AAD recipe). Always written; v2 is read with migration (see the module docstring).
const KEYSET_FORMAT_VERSION: u8 = 3;
/// Legacy on-disk record version (round 1..7): read by trial of the schemes and
/// migrated to [`KEYSET_FORMAT_VERSION`] on the first successful unlock.
const KEYSET_FORMAT_LEGACY: u8 = 2;
/// Length of a serialized X25519/Ed25519 private key.
const SK_LEN: usize = 32;

/// Keyset unlock mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockMode {
    /// Root — `combine(Argon2id(password), Secret Key)`.
    Password,
    /// Root — Secret Key only (+ a device secret in the future). SSO/trusted
    /// devices. Extension point: biometrics are not implemented here.
    SecretKeyOnly,
}

impl UnlockMode {
    fn to_u8(self) -> u8 {
        match self {
            Self::Password => 1,
            Self::SecretKeyOnly => 2,
        }
    }
    fn from_u8(v: u8) -> Result<Self, KeychainError> {
        match v {
            1 => Ok(Self::Password),
            2 => Ok(Self::SecretKeyOnly),
            _ => Err(KeychainError::Format),
        }
    }
}

/// Encrypted keyset record — what gets persisted (via `storage`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedKeyset {
    /// On-disk record recipe version: [`KEYSET_FORMAT_VERSION`] (current) or
    /// [`KEYSET_FORMAT_LEGACY`] (read from an old disk — will be migrated).
    /// Reflects the actual `wrapped_keyset` wrapping scheme, so
    /// [`to_bytes`](Self::to_bytes) writes exactly this value, not the constant.
    pub format_version: u8,
    /// Unlock mode.
    pub mode: UnlockMode,
    /// Argon2id parameters (Password mode only).
    pub kdf_params: Option<KdfParams>,
    /// Keyset public X25519 key (public).
    pub x25519_public: [u8; 32],
    /// Keyset public Ed25519 key (public).
    pub ed25519_public: [u8; 32],
    /// Monotonic record generation: part of the wrapped_keyset associated data.
    /// Grows on keyset re-encryption (e.g. a password change) — protection against
    /// swapping in an old blob under the same public key.
    pub generation: u32,
    /// AEAD blob over the keyset secrets.
    pub wrapped_keyset: Vec<u8>,
}

/// Unwrapped keyset — secrets in memory. Zeroized on Drop (types from crypto).
pub struct UnlockedKeyset {
    /// X25519 pair (encryption/HPKE).
    pub encryption: X25519Keypair,
    /// Ed25519 pair (signing).
    pub signing: Ed25519Keypair,
}

impl core::fmt::Debug for UnlockedKeyset {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UnlockedKeyset")
            .field("x25519_public", &self.encryption.public.to_bytes())
            .field("ed25519_public", &self.signing.verifying.to_bytes())
            .field("secrets", &"<redacted>")
            .finish()
    }
}

/// Associated data binding wrapped_keyset to the public identity key and the
/// record generation.
fn keyset_aad(x25519_public: &[u8; 32], generation: u32) -> AssociatedData {
    AssociatedData::new(
        b"unissh-keyset".to_vec(),
        x25519_public.to_vec(),
        u64::from(generation),
    )
}

/// Creates a new account: generates a Secret Key and keyset, encrypts the keyset
/// under the Unlock Key.
///
/// Returns `(secret_key, encrypted_keyset, unlocked)`:
/// - `secret_key` — show it in the Emergency Kit and never store it in the clear anywhere else;
/// - `encrypted_keyset` — persist it;
/// - `unlocked` — a ready-to-use keyset (secrets in memory).
///
/// `password = None` → `SecretKeyOnly` mode (SSO), `params` are ignored.
pub fn create_account(
    password: Option<&[u8]>,
    params: KdfParams,
) -> Result<(SecretKey, EncryptedKeyset, UnlockedKeyset), KeychainError> {
    let secret_key = SecretKey::generate();

    let (mode, kdf_params, argon_key) = match password {
        Some(pw) => {
            let ak = derive_key(pw, &params)?;
            (UnlockMode::Password, Some(params), Some(ak))
        }
        None => (UnlockMode::SecretKeyOnly, None, None),
    };

    let unlock_key = derive_unlock_key(argon_key.as_ref(), &secret_key, None);

    let encryption = X25519Keypair::generate();
    let signing = Ed25519Keypair::generate();

    let x25519_public = encryption.public.to_bytes();
    let ed25519_public = signing.verifying.to_bytes();
    let generation: u32 = 1;

    let wrapped_keyset = wrap_keyset(
        &unlock_key,
        &encryption,
        &signing,
        &x25519_public,
        generation,
    )?;

    let record = EncryptedKeyset {
        format_version: KEYSET_FORMAT_VERSION,
        mode,
        kdf_params,
        x25519_public,
        ed25519_public,
        generation,
        wrapped_keyset,
    };
    let unlocked = UnlockedKeyset {
        encryption,
        signing,
    };
    Ok((secret_key, record, unlocked))
}

/// Unlocks the keyset from a record, using the password (if needed) and the Secret Key.
///
/// Version-resilient: a v3 record is opened with the current scheme; a legacy v2
/// record — by trial (current → pre-round-2). It does **not** migrate the on-disk
/// record itself (no I/O); for `migrate-on-open` use [`unlock_account_migrating`].
pub fn unlock_account(
    record: &EncryptedKeyset,
    password: Option<&[u8]>,
    secret_key: &SecretKey,
) -> Result<UnlockedKeyset, KeychainError> {
    let argon_key = derive_argon(record, password)?;
    open_dispatch(record, argon_key.as_ref(), secret_key)
}

/// Like [`unlock_account`], but implements **migrate-on-open**: if the record was
/// read in the legacy format ([`KEYSET_FORMAT_LEGACY`]), returns `Some(EncryptedKeyset)` —
/// the same identity, re-wrapped under the current scheme ([`KEYSET_FORMAT_VERSION`])
/// with `generation+1`. The caller **persists it atomically and raises the
/// generation floor** to the new generation (this closes off a rollback to an
/// old/weak blob). For a record already in the current format, returns `None`.
///
/// Argon2id is computed once and reused for both opening and re-wrapping.
pub fn unlock_account_migrating(
    record: &EncryptedKeyset,
    password: Option<&[u8]>,
    secret_key: &SecretKey,
) -> Result<(UnlockedKeyset, Option<EncryptedKeyset>), KeychainError> {
    let argon_key = derive_argon(record, password)?;
    let unlocked = open_dispatch(record, argon_key.as_ref(), secret_key)?;
    let migrated = if record.format_version < KEYSET_FORMAT_VERSION {
        Some(rewrap_to_current(
            record,
            &unlocked,
            argon_key.as_ref(),
            secret_key,
        )?)
    } else {
        None
    };
    Ok((unlocked, migrated))
}

/// Derives the Argon2id key from the password using the record's parameters (or
/// `None` in SSO mode). Argon2id itself did not change between schemes — so it is
/// computed once and shared by the current/legacy trial and by the re-wrap.
fn derive_argon(
    record: &EncryptedKeyset,
    password: Option<&[u8]>,
) -> Result<Option<SymmetricKey>, KeychainError> {
    match record.mode {
        UnlockMode::Password => {
            let pw = password.ok_or(KeychainError::PasswordRequired)?;
            let params = record.kdf_params.as_ref().ok_or(KeychainError::Format)?;
            Ok(Some(derive_key(pw, params)?))
        }
        UnlockMode::SecretKeyOnly => Ok(None),
    }
}

/// Dispatch by the record's recipe version. v3 → current scheme only (no trial);
/// v2 → try current, then legacy (round 2 changed the crypto without bumping the
/// version, so the v2 byte is ambiguous — see the module docstring).
fn open_dispatch(
    record: &EncryptedKeyset,
    argon_key: Option<&SymmetricKey>,
    secret_key: &SecretKey,
) -> Result<UnlockedKeyset, KeychainError> {
    if record.format_version >= KEYSET_FORMAT_VERSION {
        return open_current(record, argon_key, secret_key);
    }
    match open_current(record, argon_key, secret_key) {
        Ok(unlocked) => Ok(unlocked),
        // Only an authentication failure means "possibly an older scheme".
        // Format/anything else is not "a different scheme" but corruption; propagate as is.
        Err(KeychainError::InvalidCredentials) => open_legacy_v1(record, argon_key, secret_key),
        Err(other) => Err(other),
    }
}

/// Current scheme (v3 / Scheme B): length-framing IKM + AEAD with header binding.
fn open_current(
    record: &EncryptedKeyset,
    argon_key: Option<&SymmetricKey>,
    secret_key: &SecretKey,
) -> Result<UnlockedKeyset, KeychainError> {
    let unlock_key = derive_unlock_key(argon_key, secret_key, None);
    let plaintext = aead_decrypt(
        &unlock_key,
        &record.wrapped_keyset,
        &keyset_aad(&record.x25519_public, record.generation),
    )
    .map_err(|_| KeychainError::InvalidCredentials)?;
    finish_unlock(record, plaintext)
}

/// Legacy scheme (pre-round-2 / Scheme A): raw IKM + AEAD without header binding.
/// **FROZEN** — must not change; pinned by a golden vector (`tests/migration.rs`).
fn open_legacy_v1(
    record: &EncryptedKeyset,
    argon_key: Option<&SymmetricKey>,
    secret_key: &SecretKey,
) -> Result<UnlockedKeyset, KeychainError> {
    let unlock_key = derive_unlock_key_legacy_v1(argon_key, secret_key, None);
    let plaintext = aead_decrypt_pre_agility(
        &unlock_key,
        &record.wrapped_keyset,
        &keyset_aad(&record.x25519_public, record.generation),
    )
    .map_err(|_| KeychainError::InvalidCredentials)?;
    finish_unlock(record, plaintext)
}

/// The shared "tail" of unlocking: parse the secrets from the decrypted plaintext
/// and sanity-check that the public X25519 derived from the secret matches the recorded one.
fn finish_unlock(
    record: &EncryptedKeyset,
    mut plaintext: Vec<u8>,
) -> Result<UnlockedKeyset, KeychainError> {
    if plaintext.len() != SK_LEN * 2 {
        plaintext.zeroize();
        return Err(KeychainError::Format);
    }

    let x_secret = X25519SecretKey::from_bytes(&plaintext[..SK_LEN]);
    let e_secret = Ed25519SigningKey::from_bytes(&plaintext[SK_LEN..]);
    plaintext.zeroize();

    let x_secret = x_secret.map_err(|_| KeychainError::Format)?;
    let e_secret = e_secret.map_err(|_| KeychainError::Format)?;

    let encryption = X25519Keypair {
        public: x_secret.public_key(),
        secret: x_secret,
    };
    let signing = Ed25519Keypair {
        verifying: e_secret.verifying_key(),
        signing: e_secret,
    };

    // Sanity: the public key derived from the unwrapped secret matches the recorded one.
    if encryption.public.to_bytes() != record.x25519_public {
        return Err(KeychainError::Format);
    }

    Ok(UnlockedKeyset {
        encryption,
        signing,
    })
}

/// Re-wraps an already-unwrapped keyset under the current scheme (same contents and
/// same Secret Key — only the wrapping), `generation+1`, version [`KEYSET_FORMAT_VERSION`].
/// Argon2id is passed in ready-made (see [`derive_argon`]) and not recomputed.
fn rewrap_to_current(
    record: &EncryptedKeyset,
    unlocked: &UnlockedKeyset,
    argon_key: Option<&SymmetricKey>,
    secret_key: &SecretKey,
) -> Result<EncryptedKeyset, KeychainError> {
    let generation = record
        .generation
        .checked_add(1)
        .ok_or(KeychainError::Format)?;
    let unlock_key = derive_unlock_key(argon_key, secret_key, None);
    let wrapped_keyset = wrap_keyset(
        &unlock_key,
        &unlocked.encryption,
        &unlocked.signing,
        &record.x25519_public,
        generation,
    )?;
    Ok(EncryptedKeyset {
        format_version: KEYSET_FORMAT_VERSION,
        mode: record.mode,
        kdf_params: record.kdf_params.clone(),
        x25519_public: record.x25519_public,
        ed25519_public: record.ed25519_public,
        generation,
        wrapped_keyset,
    })
}

/// Re-encrypts the keyset under a **new** Unlock Key (changing/removing/setting the
/// master password). The Secret Key and the keyset secrets themselves do not change —
/// only the wrapping and `generation` (grows by 1, protection against swapping in an old blob).
///
/// The old `(old_password, secret_key)` are verified by unlocking the record: on
/// wrong credentials it returns `InvalidCredentials` and there is no re-wrap — this
/// rules out "bricking" (you cannot accidentally overwrite the keyset such that it
/// can no longer be opened). `new_password = None` → switch to `SecretKeyOnly` mode.
///
/// Returns a new `EncryptedKeyset` — the caller persists it (atomically).
pub fn change_password(
    record: &EncryptedKeyset,
    old_password: Option<&[u8]>,
    new_password: Option<&[u8]>,
    secret_key: &SecretKey,
    new_params: KdfParams,
) -> Result<EncryptedKeyset, KeychainError> {
    // Verify the old credentials and extract the keyset secrets (brick protection).
    let unlocked = unlock_account(record, old_password, secret_key)?;
    let generation = record
        .generation
        .checked_add(1)
        .ok_or(KeychainError::Format)?;

    let (mode, kdf_params, argon_key) = match new_password {
        Some(pw) => {
            let ak = derive_key(pw, &new_params)?;
            (UnlockMode::Password, Some(new_params), Some(ak))
        }
        None => (UnlockMode::SecretKeyOnly, None, None),
    };

    let unlock_key = derive_unlock_key(argon_key.as_ref(), secret_key, None);
    let wrapped_keyset = wrap_keyset(
        &unlock_key,
        &unlocked.encryption,
        &unlocked.signing,
        &record.x25519_public,
        generation,
    )?;

    Ok(EncryptedKeyset {
        format_version: KEYSET_FORMAT_VERSION,
        mode,
        kdf_params,
        x25519_public: record.x25519_public,
        ed25519_public: record.ed25519_public,
        generation,
        wrapped_keyset,
    })
}

/// Encrypts the keyset secrets under the Unlock Key.
pub(crate) fn wrap_keyset(
    unlock_key: &SymmetricKey,
    encryption: &X25519Keypair,
    signing: &Ed25519Keypair,
    x25519_public: &[u8; 32],
    generation: u32,
) -> Result<Vec<u8>, KeychainError> {
    // Keep temporary copies of the private bytes in Zeroizing — zeroized on exit.
    let x_secret = Zeroizing::new(encryption.secret.expose_to_bytes());
    let e_secret = Zeroizing::new(signing.signing.expose_to_bytes());
    let mut plaintext = Zeroizing::new(Vec::with_capacity(SK_LEN * 2));
    plaintext.extend_from_slice(x_secret.as_ref());
    plaintext.extend_from_slice(e_secret.as_ref());

    let blob = aead_encrypt(
        unlock_key,
        &plaintext,
        &keyset_aad(x25519_public, generation),
    );
    Ok(blob?)
}

// --- EncryptedKeyset serialization ---

impl EncryptedKeyset {
    /// Serializes the record into bytes for persistence.
    pub fn to_bytes(&self) -> Result<Vec<u8>, KeychainError> {
        let kdf_blob = match &self.kdf_params {
            Some(p) => p.to_blob()?,
            None => Vec::new(),
        };
        if kdf_blob.len() > u16::MAX as usize {
            return Err(KeychainError::Format);
        }

        let mut out = Vec::with_capacity(8 + kdf_blob.len() + 64 + self.wrapped_keyset.len());
        // Write the record's actual recipe version, not the constant: a legacy record
        // re-serialized without re-wrapping stays legacy (the version byte must match
        // the real `wrapped_keyset` scheme). A record is raised to
        // KEYSET_FORMAT_VERSION only by re-wrapping (`rewrap_to_current`/`change_password`).
        out.push(self.format_version);
        out.push(self.mode.to_u8());
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&(kdf_blob.len() as u16).to_be_bytes());
        out.extend_from_slice(&kdf_blob);
        out.extend_from_slice(&self.x25519_public);
        out.extend_from_slice(&self.ed25519_public);
        out.extend_from_slice(&self.wrapped_keyset);
        Ok(out)
    }

    /// Parses a record from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeychainError> {
        // version(1)+mode(1)+generation(4)+kdf_len(2) = 8, then pubkeys(64) at minimum
        if bytes.len() < 8 + 64 {
            return Err(KeychainError::Format);
        }
        // Accept the current (v3) and legacy (v2) versions; v2 will be opened by
        // trial of the schemes and migrated on the first unlock. A record from the
        // future (> current) is a loud rejection (you cannot "decrypt" an unknown
        // recipe), not a misparse.
        let format_version = bytes[0];
        if format_version != KEYSET_FORMAT_VERSION && format_version != KEYSET_FORMAT_LEGACY {
            return Err(KeychainError::Format);
        }
        let mode = UnlockMode::from_u8(bytes[1])?;
        let generation = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        let kdf_len = u16::from_be_bytes([bytes[6], bytes[7]]) as usize;

        let mut pos: usize = 8;
        let kdf_params = if kdf_len > 0 {
            let end = pos.checked_add(kdf_len).ok_or(KeychainError::Format)?;
            if bytes.len() < end + 64 {
                return Err(KeychainError::Format);
            }
            let p = KdfParams::from_blob(&bytes[pos..end])?;
            pos = end;
            Some(p)
        } else {
            None
        };

        // consistency between the mode and the presence of parameters
        match (mode, &kdf_params) {
            (UnlockMode::Password, Some(_)) | (UnlockMode::SecretKeyOnly, None) => {}
            _ => return Err(KeychainError::Format),
        }

        if bytes.len() < pos + 64 {
            return Err(KeychainError::Format);
        }
        let mut x25519_public = [0_u8; 32];
        x25519_public.copy_from_slice(&bytes[pos..pos + 32]);
        let mut ed25519_public = [0_u8; 32];
        ed25519_public.copy_from_slice(&bytes[pos + 32..pos + 64]);
        pos += 64;

        let wrapped_keyset = bytes[pos..].to_vec();
        if wrapped_keyset.is_empty() {
            return Err(KeychainError::Format);
        }

        Ok(Self {
            format_version,
            mode,
            kdf_params,
            x25519_public,
            ed25519_public,
            generation,
            wrapped_keyset,
        })
    }
}

/// Length of the transferred keyset secrets (x25519_secret(32) || ed25519_secret(32)).
pub(crate) const TRANSFERRED_SECRETS_LEN: usize = SK_LEN * 2;

/// Version of the Path B transfer payload. v2 = added the shared account-wide Secret
/// Key (the "one key for all devices" model, like 1Password).
pub(crate) const TRANSFER_PAYLOAD_VERSION: u8 = 2;
/// v2 payload length: version(1) || keypairs(64) || secret_key(16).
pub(crate) const TRANSFERRED_PAYLOAD_V2_LEN: usize =
    1 + TRANSFERRED_SECRETS_LEN + crate::secret_key::SECRET_KEY_LEN;

/// Installs a keyset from **transferred secrets** (device-to-device onboarding,
/// server-tz §9 Path B): builds the X25519/Ed25519 pairs from `secrets` and encrypts
/// the keyset under the **shared account-wide** `secret_key` (passed from the
/// initiating device over the PAKE channel) and the local Unlock Key, generation = 1.
///
/// This is "the new device making its own device record": the keyset identity is the
/// same (same public keys), and the Secret Key is also the shared account-wide one
/// (the 1Password model — one Emergency Kit for all devices). Returns this shared
/// Secret Key so the caller can store it in the device keychain.
///
/// `secrets` is zeroized by the caller (passed as a slice from `Zeroizing`).
pub(crate) fn install_transferred_keyset(
    secrets: &[u8; TRANSFERRED_SECRETS_LEN],
    secret_key: SecretKey,
    password: Option<&[u8]>,
    params: KdfParams,
) -> Result<(SecretKey, EncryptedKeyset, UnlockedKeyset), KeychainError> {
    let x_secret =
        X25519SecretKey::from_bytes(&secrets[..SK_LEN]).map_err(|_| KeychainError::Format)?;
    let e_secret =
        Ed25519SigningKey::from_bytes(&secrets[SK_LEN..]).map_err(|_| KeychainError::Format)?;

    let encryption = X25519Keypair {
        public: x_secret.public_key(),
        secret: x_secret,
    };
    let signing = Ed25519Keypair {
        verifying: e_secret.verifying_key(),
        signing: e_secret,
    };

    let (mode, kdf_params, argon_key) = match password {
        Some(pw) => {
            let ak = derive_key(pw, &params)?;
            (UnlockMode::Password, Some(params), Some(ak))
        }
        None => (UnlockMode::SecretKeyOnly, None, None),
    };
    let unlock_key = derive_unlock_key(argon_key.as_ref(), &secret_key, None);

    let x25519_public = encryption.public.to_bytes();
    let ed25519_public = signing.verifying.to_bytes();
    let generation: u32 = 1;
    let wrapped_keyset = wrap_keyset(
        &unlock_key,
        &encryption,
        &signing,
        &x25519_public,
        generation,
    )?;

    let record = EncryptedKeyset {
        format_version: KEYSET_FORMAT_VERSION,
        mode,
        kdf_params,
        x25519_public,
        ed25519_public,
        generation,
        wrapped_keyset,
    };
    Ok((
        secret_key,
        record,
        UnlockedKeyset {
            encryption,
            signing,
        },
    ))
}

#[cfg(test)]
mod migration_tests {
    use super::*;
    use unissh_crypto::aead_encrypt_pre_agility;

    const PW: &[u8] = b"correct horse battery staple";

    /// Low cost + a FIXED salt → a deterministic argon_key (for frozen vectors).
    fn fixed_params() -> KdfParams {
        KdfParams {
            mem_kib: 8 * 1024,
            iterations: 1,
            parallelism: 1,
            salt: vec![0x44; 16],
        }
    }
    fn fixed_secret_key() -> SecretKey {
        SecretKey::from_bytes([0x11_u8; crate::secret_key::SECRET_KEY_LEN])
    }
    fn fixed_keypairs() -> (X25519Keypair, Ed25519Keypair) {
        let x = X25519SecretKey::from_bytes(&[0x22_u8; 32]).unwrap();
        let e = Ed25519SigningKey::from_bytes(&[0x33_u8; 32]).unwrap();
        (
            X25519Keypair {
                public: x.public_key(),
                secret: x,
            },
            Ed25519Keypair {
                verifying: e.verifying_key(),
                signing: e,
            },
        )
    }

    /// Forges a legacy record (Scheme A: raw IKM + AEAD without header binding) —
    /// reproduces what builds before round 2 used to write.
    fn forge_legacy_record(password: Option<&[u8]>) -> (SecretKey, EncryptedKeyset) {
        let secret_key = fixed_secret_key();
        let params = fixed_params();
        let argon = password.map(|pw| derive_key(pw, &params).unwrap());
        let legacy_unlock = derive_unlock_key_legacy_v1(argon.as_ref(), &secret_key, None);
        let (encryption, signing) = fixed_keypairs();
        let x_pub = encryption.public.to_bytes();
        let ed_pub = signing.verifying.to_bytes();
        let generation = 1_u32;
        let x_secret = Zeroizing::new(encryption.secret.expose_to_bytes());
        let e_secret = Zeroizing::new(signing.signing.expose_to_bytes());
        let mut pt = Zeroizing::new(Vec::new());
        pt.extend_from_slice(x_secret.as_ref());
        pt.extend_from_slice(e_secret.as_ref());
        let wrapped =
            aead_encrypt_pre_agility(&legacy_unlock, &pt, &keyset_aad(&x_pub, generation)).unwrap();
        let (mode, kdf_params) = match password {
            Some(_) => (UnlockMode::Password, Some(params)),
            None => (UnlockMode::SecretKeyOnly, None),
        };
        let record = EncryptedKeyset {
            format_version: KEYSET_FORMAT_LEGACY,
            mode,
            kdf_params,
            x25519_public: x_pub,
            ed25519_public: ed_pub,
            generation,
            wrapped_keyset: wrapped,
        };
        (secret_key, record)
    }

    /// FROZEN: round-1 Unlock Key derivation for a fixed input (argon=[0x42;32],
    /// sk=[0x11;16]). If this vector breaks — `derive_unlock_key_legacy_v1` was
    /// changed; that is a format break, requiring a NEW schema version, not an edit to the old one.
    const FROZEN_LEGACY_UNLOCK_KEY: [u8; 32] = [
        0xb2, 0x3a, 0x0e, 0x38, 0xb6, 0x35, 0xa0, 0xb0, 0x0b, 0x77, 0x0f, 0xd2, 0x1e, 0xd8, 0x27,
        0x0d, 0xe9, 0x9b, 0xc1, 0xbd, 0xc6, 0xfd, 0xe4, 0x09, 0xae, 0xa7, 0x10, 0xf6, 0x81, 0x17,
        0x6d, 0x36,
    ];

    /// FROZEN: a whole legacy keyset record (Scheme A), captured once. An anti-drift
    /// gate — it must keep opening under the current code (forge+open in a single run
    /// is self-consistent and does NOT catch drift, hence the bytes are frozen).
    /// Captured by the generator with fixed material (`fixed_*`, password `PW`); record version 0x02.
    const FROZEN_LEGACY_RECORD: &[u8] = &[
        0x02, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x21, 0x01, 0x00, 0x30, 0x01, 0x00, 0x00, 0x20,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x10, 0x44, 0x44, 0x44, 0x44, 0x44,
        0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x0f, 0xaa, 0x68, 0x4e,
        0xd2, 0x88, 0x67, 0xb9, 0x7f, 0x4a, 0x6a, 0x2d, 0xee, 0x5d, 0xf8, 0xce, 0x97, 0x4e, 0x76,
        0xb7, 0x01, 0x8e, 0x3f, 0x22, 0xa1, 0xc4, 0xcf, 0x26, 0x78, 0x57, 0x0f, 0x20, 0x17, 0xcb,
        0x79, 0xfb, 0x2b, 0x41, 0x20, 0xf2, 0xb1, 0xec, 0x65, 0xe4, 0x19, 0x8d, 0x6e, 0x08, 0xb2,
        0x8e, 0x81, 0x3f, 0xeb, 0x01, 0xe4, 0xa4, 0x00, 0x83, 0x9b, 0x85, 0xe1, 0x80, 0x80, 0xce,
        0x01, 0x00, 0x01, 0x5c, 0xdd, 0x8b, 0x8c, 0xc9, 0x78, 0x67, 0x5c, 0x0c, 0x17, 0x64, 0x24,
        0x0a, 0xa2, 0x0f, 0xe3, 0xda, 0xcb, 0xc1, 0xeb, 0xde, 0x70, 0x37, 0x26, 0x43, 0x43, 0x99,
        0xa3, 0xbd, 0xd6, 0xc9, 0x80, 0x9d, 0x86, 0x8b, 0x42, 0x6c, 0xfc, 0x56, 0x86, 0x76, 0x28,
        0x9f, 0x14, 0x17, 0x41, 0xd9, 0xa0, 0x22, 0x36, 0xec, 0x52, 0xee, 0x19, 0xd1, 0xbc, 0x94,
        0xc5, 0x36, 0x3c, 0x30, 0xc0, 0x5a, 0x39, 0xfc, 0xf9, 0xc9, 0x0c, 0xdf, 0xfc, 0x66, 0xf2,
        0x84, 0x24, 0xf0, 0xd2, 0x0b, 0x4a, 0x0d, 0x34, 0x2d, 0x0f, 0x74, 0x50, 0x62, 0x7d, 0xf6,
        0x95, 0x93, 0xfd, 0x74, 0xda, 0x1c, 0xaa, 0x9f, 0x40, 0x7b, 0xee, 0x04, 0x08, 0xd4, 0x70,
        0xc5, 0x49,
    ];

    #[test]
    fn legacy_v1_unlock_key_is_frozen() {
        let argon = SymmetricKey::from_bytes([0x42_u8; 32]);
        let key = derive_unlock_key_legacy_v1(Some(&argon), &fixed_secret_key(), None);
        assert_eq!(key.expose_bytes(), &FROZEN_LEGACY_UNLOCK_KEY);
    }

    #[test]
    fn frozen_legacy_keyset_blob_still_opens_and_migrates() {
        let record = EncryptedKeyset::from_bytes(FROZEN_LEGACY_RECORD).unwrap();
        assert_eq!(record.format_version, KEYSET_FORMAT_LEGACY);
        let sk = fixed_secret_key();
        let (unlocked, migrated) = unlock_account_migrating(&record, Some(PW), &sk).unwrap();
        let (_, signing) = fixed_keypairs();
        assert_eq!(
            unlocked.signing.verifying.to_bytes(),
            signing.verifying.to_bytes()
        );
        assert_eq!(migrated.unwrap().format_version, KEYSET_FORMAT_VERSION);
    }

    #[test]
    fn legacy_record_opens_under_current_unlock() {
        let (sk, record) = forge_legacy_record(Some(PW));
        let unlocked = unlock_account(&record, Some(PW), &sk).unwrap();
        let (_, signing) = fixed_keypairs();
        assert_eq!(
            unlocked.signing.verifying.to_bytes(),
            signing.verifying.to_bytes()
        );
    }

    #[test]
    fn migrating_upgrades_legacy_to_current_v3() {
        let (sk, record) = forge_legacy_record(Some(PW));
        let (unlocked, migrated) = unlock_account_migrating(&record, Some(PW), &sk).unwrap();
        let migrated = migrated.expect("legacy record must yield a migrated v3 record");

        assert_eq!(migrated.format_version, KEYSET_FORMAT_VERSION);
        assert_eq!(migrated.generation, record.generation + 1);
        // Same keyset identity.
        assert_eq!(migrated.x25519_public, record.x25519_public);
        assert_eq!(migrated.ed25519_public, record.ed25519_public);
        // migrated opens with the CURRENT scheme (format_version=3 → open_current, no trial).
        let reopened = unlock_account(&migrated, Some(PW), &sk).unwrap();
        assert_eq!(
            reopened.signing.verifying.to_bytes(),
            unlocked.signing.verifying.to_bytes()
        );
        // And it serializes as v3 now; the roundtrip preserves the version.
        let bytes = migrated.to_bytes().unwrap();
        assert_eq!(bytes[0], KEYSET_FORMAT_VERSION);
        let parsed = EncryptedKeyset::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, migrated);
    }

    #[test]
    fn current_record_does_not_migrate() {
        let (sk, record, _unlocked) = create_account(Some(PW), fixed_params()).unwrap();
        assert_eq!(record.format_version, KEYSET_FORMAT_VERSION);
        let (_u, migrated) = unlock_account_migrating(&record, Some(PW), &sk).unwrap();
        assert!(migrated.is_none());
    }

    #[test]
    fn legacy_wrong_password_is_invalid_credentials() {
        let (sk, record) = forge_legacy_record(Some(PW));
        let err = unlock_account(&record, Some(b"wrong"), &sk).unwrap_err();
        assert_eq!(err, KeychainError::InvalidCredentials);
    }

    #[test]
    fn legacy_sso_record_opens_and_migrates() {
        // A passwordless (SecretKeyOnly) legacy keyset also opens and migrates.
        let (sk, record) = forge_legacy_record(None);
        let (_u, migrated) = unlock_account_migrating(&record, None, &sk).unwrap();
        assert_eq!(migrated.unwrap().format_version, KEYSET_FORMAT_VERSION);
    }
}
