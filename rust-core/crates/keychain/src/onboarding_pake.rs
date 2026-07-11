//! Device-to-device onboarding (server-tz §9 Path B / §13.14) via the VETTED PAKE
//! `spake2` (SPAKE2, Ed25519Group).
//!
//! Flow: short OOB code → SPAKE2 exchange (initiator start_a / responder start_b)
//! → channel-key derivation → **mutual confirmation** (an HMAC tag over the
//! transcript — mandatory, because SPAKE2 `finish` returns a key even for a wrong
//! code, the parties just end up with different keys) → the initiator E2E-encrypts
//! the keyset secrets under the channel key (`crypto::aead`) → the responder
//! decrypts and installs its own device record.
//!
//! The server only relays opaque blobs — there is no server in this repo, so the
//! relay is modeled as in-memory message passing.
//!
//! ## We do NOT roll our own crypto
//! PAKE — `spake2`; confirmation — `hmac`+`sha2`; encryption — `crypto::aead`;
//! key derivation — `hkdf`. The channel key and the transferred secrets live in
//! `Zeroizing`.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use spake2::{Ed25519Group, Identity, Password, Spake2};

use unissh_crypto::{aead_decrypt, aead_encrypt, AssociatedData, KdfParams, SymmetricKey};

use crate::error::KeychainError;
use crate::keyset::{
    install_transferred_keyset, EncryptedKeyset, UnlockedKeyset, TRANSFERRED_PAYLOAD_V2_LEN,
    TRANSFERRED_SECRETS_LEN, TRANSFER_PAYLOAD_VERSION,
};
use crate::secret_key::SecretKey;

/// Domain label of the confirmation transcript.
const CONFIRM_TRANSCRIPT_LABEL: &[u8] = b"unissh-onboard-confirm-v1";
/// HKDF-info for the channel AEAD key.
const INFO_CHANNEL_KEY: &[u8] = b"unissh-onboard-channel-key";
/// HKDF-info for the responder side's confirm key.
const INFO_CONFIRM_RESPONDER: &[u8] = b"unissh-onboard-confirm-key-responder";
/// HKDF-info for the initiator side's confirm key.
const INFO_CONFIRM_INITIATOR: &[u8] = b"unissh-onboard-confirm-key-initiator";
/// Initiator identity (role-binding SPAKE2 start_a).
pub(crate) const ID_INITIATOR: &[u8] = b"unissh-onboard-initiator";
/// Responder identity (role-binding SPAKE2 start_b).
pub(crate) const ID_RESPONDER: &[u8] = b"unissh-onboard-responder";
/// Length of the confirm tag (HMAC-SHA256).
const CONFIRM_TAG_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// Derives a 32-byte subkey from the shared SPAKE2 key using `info` (HKDF-SHA256).
fn derive_subkey(spake_key: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, spake_key);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(info, okm.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

/// Channel AEAD key (raw 32 bytes) from the shared SPAKE2 key.
fn channel_key_bytes(spake_key: &[u8]) -> Zeroizing<[u8; 32]> {
    derive_subkey(spake_key, INFO_CHANNEL_KEY)
}

/// Confirmation transcript: label ‖ msg1 ‖ msg2_pake.
fn confirm_transcript(msg1: &[u8], msg2_pake: &[u8]) -> Vec<u8> {
    let mut t = Vec::with_capacity(CONFIRM_TRANSCRIPT_LABEL.len() + msg1.len() + msg2_pake.len());
    t.extend_from_slice(CONFIRM_TRANSCRIPT_LABEL);
    t.extend_from_slice(msg1);
    t.extend_from_slice(msg2_pake);
    t
}

/// HMAC tag of the transcript under the directional confirm key.
fn confirm_tag(spake_key: &[u8], info: &[u8], transcript: &[u8]) -> [u8; CONFIRM_TAG_LEN] {
    let key = derive_subkey(spake_key, info);
    let mut mac = HmacSha256::new_from_slice(key.as_ref()).expect("HMAC accepts any key length");
    mac.update(transcript);
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; CONFIRM_TAG_LEN];
    tag.copy_from_slice(&out);
    tag
}

/// Verifies the confirm tag in constant time. A mismatch → `ConfirmationFailed`.
fn verify_confirm_tag(
    spake_key: &[u8],
    info: &[u8],
    transcript: &[u8],
    presented: &[u8],
) -> Result<(), KeychainError> {
    if presented.len() != CONFIRM_TAG_LEN {
        return Err(KeychainError::ConfirmationFailed);
    }
    let expected = confirm_tag(spake_key, info, transcript);
    if expected.ct_eq(presented).into() {
        Ok(())
    } else {
        Err(KeychainError::ConfirmationFailed)
    }
}

/// AEAD context for the sealed keyset (onboarding is not a vault/item, hence fixed labels).
fn transfer_aad() -> AssociatedData {
    AssociatedData::new(b"unissh-onboard".to_vec(), b"keyset-transfer".to_vec(), 1)
}

/// Initiator state after `start` (holds the SPAKE2 state and msg1 for the transcript).
pub struct OnboardInitiator {
    spake: Spake2<Ed25519Group>,
    msg1: Vec<u8>,
}

impl OnboardInitiator {
    /// Starts onboarding on the existing device: SPAKE2 start_a from the code.
    /// Returns the state and `msg1` to relay to the responder.
    pub fn start(code: &[u8]) -> (Self, Vec<u8>) {
        let (spake, msg1) = Spake2::<Ed25519Group>::start_a(
            &Password::new(code),
            &Identity::new(ID_INITIATOR),
            &Identity::new(ID_RESPONDER),
        );
        (
            Self {
                spake,
                msg1: msg1.clone(),
            },
            msg1,
        )
    }

    /// Receives `msg2` (responder PAKE msg ‖ responder confirm tag), finishes the PAKE,
    /// verifies the responder confirm tag and, on success, E2E-encrypts the keyset secrets.
    /// Returns `msg3` = initiator confirm tag ‖ sealed keyset.
    ///
    /// A wrong code / forgery → [`KeychainError::ConfirmationFailed`] (the secrets are
    /// NOT encrypted and NOT transmitted).
    pub fn confirm_and_seal(
        self,
        msg2: &[u8],
        unlocked: &UnlockedKeyset,
        secret_key: &SecretKey,
    ) -> Result<Vec<u8>, KeychainError> {
        if msg2.len() < CONFIRM_TAG_LEN {
            return Err(KeychainError::ConfirmationFailed);
        }
        let (msg2_pake, responder_tag) = msg2.split_at(msg2.len() - CONFIRM_TAG_LEN);

        let spake_key = Zeroizing::new(
            self.spake
                .finish(msg2_pake)
                .map_err(|_| KeychainError::ConfirmationFailed)?,
        );

        let transcript = confirm_transcript(&self.msg1, msg2_pake);
        // 1) verify the responder confirm tag
        verify_confirm_tag(
            &spake_key,
            INFO_CONFIRM_RESPONDER,
            &transcript,
            responder_tag,
        )?;

        // 2) our own confirm tag
        let initiator_tag = confirm_tag(&spake_key, INFO_CONFIRM_INITIATOR, &transcript);

        // 3) E2E-encrypt the keyset secrets + the shared account Secret Key under
        //    the channel key (payload v2: version || keypairs(64) || secret_key(16)).
        let mut secrets = Zeroizing::new(Vec::with_capacity(TRANSFERRED_PAYLOAD_V2_LEN));
        secrets.push(TRANSFER_PAYLOAD_VERSION);
        secrets.extend_from_slice(&unlocked.encryption.secret.expose_to_bytes());
        secrets.extend_from_slice(&unlocked.signing.signing.expose_to_bytes());
        secrets.extend_from_slice(secret_key.expose_bytes());

        let ckey = SymmetricKey::from_bytes(*channel_key_bytes(&spake_key));
        let sealed = aead_encrypt(&ckey, &secrets, &transfer_aad())?;

        let mut msg3 = Vec::with_capacity(CONFIRM_TAG_LEN + sealed.len());
        msg3.extend_from_slice(&initiator_tag);
        msg3.extend_from_slice(&sealed);
        Ok(msg3)
    }
}

/// Responder state after `respond`.
pub struct OnboardResponder {
    spake_key: Zeroizing<Vec<u8>>,
    transcript: Vec<u8>,
}

impl OnboardResponder {
    /// The new device receives `msg1`, does SPAKE2 start_b + finish, derives the
    /// channel key and sends `msg2` = PAKE outbound ‖ responder confirm tag.
    pub fn respond(code: &[u8], msg1: &[u8]) -> Result<(Self, Vec<u8>), KeychainError> {
        let (spake, msg2_pake) = Spake2::<Ed25519Group>::start_b(
            &Password::new(code),
            &Identity::new(ID_INITIATOR),
            &Identity::new(ID_RESPONDER),
        );
        let spake_key = Zeroizing::new(
            spake
                .finish(msg1)
                .map_err(|_| KeychainError::ConfirmationFailed)?,
        );
        let transcript = confirm_transcript(msg1, &msg2_pake);
        let responder_tag = confirm_tag(&spake_key, INFO_CONFIRM_RESPONDER, &transcript);

        let mut msg2 = Vec::with_capacity(msg2_pake.len() + CONFIRM_TAG_LEN);
        msg2.extend_from_slice(&msg2_pake);
        msg2.extend_from_slice(&responder_tag);
        Ok((
            Self {
                spake_key,
                transcript,
            },
            msg2,
        ))
    }

    /// Receives `msg3` (initiator confirm tag ‖ sealed keyset), verifies the
    /// initiator tag, decrypts payload v2 (keypairs + the **shared account
    /// Secret Key**) and installs its own device record under this shared key and
    /// a local password. Returns the shared Secret Key (the caller persists it).
    ///
    /// A forged tag → [`KeychainError::ConfirmationFailed`]; a corrupted sealed blob →
    /// [`KeychainError::Crypto`] (AEAD does not authenticate); a foreign version/length
    /// of the payload → [`KeychainError::Format`].
    pub fn finish_install(
        self,
        msg3: &[u8],
        password: Option<&[u8]>,
        params: KdfParams,
    ) -> Result<(SecretKey, EncryptedKeyset, UnlockedKeyset), KeychainError> {
        if msg3.len() < CONFIRM_TAG_LEN {
            return Err(KeychainError::ConfirmationFailed);
        }
        let (initiator_tag, sealed) = msg3.split_at(CONFIRM_TAG_LEN);
        verify_confirm_tag(
            &self.spake_key,
            INFO_CONFIRM_INITIATOR,
            &self.transcript,
            initiator_tag,
        )?;

        let ckey = SymmetricKey::from_bytes(*channel_key_bytes(&self.spake_key));
        let mut plaintext = Zeroizing::new(aead_decrypt(&ckey, sealed, &transfer_aad())?);
        // payload v2: version(1) || keypairs(64) || secret_key(16). Length check is
        // first so the `[0]` version read can't index an empty buffer.
        if plaintext.len() != TRANSFERRED_PAYLOAD_V2_LEN || plaintext[0] != TRANSFER_PAYLOAD_VERSION
        {
            return Err(KeychainError::Format);
        }
        let mut secrets = Zeroizing::new([0u8; TRANSFERRED_SECRETS_LEN]);
        secrets.copy_from_slice(&plaintext[1..1 + TRANSFERRED_SECRETS_LEN]);
        let secret_key = SecretKey::from_slice(&plaintext[1 + TRANSFERRED_SECRETS_LEN..])
            .map_err(|_| KeychainError::Format)?;
        plaintext.zeroize();

        install_transferred_keyset(&secrets, secret_key, password, params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_keys_confirm_tag_verifies() {
        let spake_key = [9u8; 32];
        let t = confirm_transcript(b"m1", b"m2");
        let tag = confirm_tag(&spake_key, INFO_CONFIRM_RESPONDER, &t);
        verify_confirm_tag(&spake_key, INFO_CONFIRM_RESPONDER, &t, &tag).unwrap();
    }

    #[test]
    fn different_spake_key_confirm_tag_fails() {
        let t = confirm_transcript(b"m1", b"m2");
        let tag = confirm_tag(&[9u8; 32], INFO_CONFIRM_RESPONDER, &t);
        assert_eq!(
            verify_confirm_tag(&[8u8; 32], INFO_CONFIRM_RESPONDER, &t, &tag).unwrap_err(),
            KeychainError::ConfirmationFailed
        );
    }

    #[test]
    fn directional_subkeys_differ() {
        let k = [3u8; 32];
        let r = derive_subkey(&k, INFO_CONFIRM_RESPONDER);
        let i = derive_subkey(&k, INFO_CONFIRM_INITIATOR);
        assert_ne!(r.as_ref(), i.as_ref());
    }
}
