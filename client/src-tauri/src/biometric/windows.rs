//! Windows: the device secret is a Windows Hello signature.
//!
//! A consent prompt alone protects nothing — `UserConsentVerifier` answers
//! yes/no and any process can skip asking — so it is not used. Instead:
//!
//! * `KeyCredentialManager` creates a Hello-protected key credential for this
//!   app (`me.goduni.unissh.biometric-unlock`). Its private key never leaves
//!   the Hello container (TPM-backed where the machine has one), and every use
//!   of it shows the Hello prompt — face, fingerprint or PIN.
//! * A fixed **challenge** (32 random bytes, made at enable time) is signed with
//!   that key. The signature is the device secret: `device_wrap` derives the
//!   sealing key from it by HKDF, so the stored password opens only after a
//!   successful Hello verification produces that same signature again. Hello
//!   keys are RSA and signed with PKCS#1 v1.5, which is deterministic, so the
//!   same challenge always yields the same signature.
//! * The challenge is not secret and sits in Credential Manager
//!   (`me.goduni.unissh` / `biometric-hello-challenge`, through `keyring`). The
//!   sealed password stays in the shared blob file beside the keyset (see
//!   `biometric.rs`). Neither is useful without the Hello key; the signature
//!   and the key derived from it are never stored anywhere.
//!
//! Removing the Hello PIN (or resetting Hello) destroys the credential, which
//! `OpenAsync` then reports as `NotFound`: the stored material is invalidated.
//! Unlike Touch ID's `biometryCurrentSet`, *adding* a fingerprint or a face does
//! not — Hello keys are bound to the Hello container, not to one biometric set,
//! and the PIN is always one of its ways in.
//!
//! The WinRT prompt takes no message, so `read`'s `reason` is ignored; Windows
//! shows the app's own name. Every `IAsyncOperation` is waited on with `join()`,
//! which blocks: the shared code only calls this from the blocking pool, never
//! from the main thread that serves the window.
//!
//! None of this is unit-testable — every path ends in a Hello prompt or a
//! Credential Manager the test runner does not have. It is checked by hand on
//! Windows.

use windows::core::{Array, HSTRING};
use windows::Security::Credentials::{
    KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
};
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Storage::Streams::IBuffer;
use zeroize::{Zeroize, Zeroizing};

use super::{DeviceSecretStore, SecretError, SecretState};

/// The Hello key credential's name. One per Windows user and app.
const CREDENTIAL_NAME: &str = "me.goduni.unissh.biometric-unlock";
/// Credential Manager entry for the challenge (not secret).
const SERVICE: &str = "me.goduni.unissh";
const CHALLENGE_ACCOUNT: &str = "biometric-hello-challenge";
const CHALLENGE_LEN: u32 = 32;

pub(super) struct WindowsHello;

fn name() -> HSTRING {
    HSTRING::from(CREDENTIAL_NAME)
}

/// A diagnostic for `SecretError::Failed`: an HRESULT or a status number,
/// never secret material.
fn failed(what: &str, e: impl std::fmt::Display) -> SecretError {
    SecretError::Failed(format!("Windows Hello: {what}: {e}"))
}

fn status_failed(what: &str, s: KeyCredentialStatus) -> SecretError {
    SecretError::Failed(format!("Windows Hello: {what}: status {}", s.0))
}

/// The user said no (dismissed the prompt or chose "use password" instead).
fn declined(s: KeyCredentialStatus) -> bool {
    s == KeyCredentialStatus::UserCanceled || s == KeyCredentialStatus::UserPrefersPassword
}

/// Hello is set up for this user (a PIN at least) and usable by this app.
/// An error counts as "no": nothing is offered, nothing is wiped.
fn hello_supported() -> bool {
    KeyCredentialManager::IsSupportedAsync()
        .and_then(|op| op.join())
        .unwrap_or(false)
}

/// Open the credential without prompting. `Err(status)` is a status other than
/// success (`NotFound` when it does not exist).
fn open() -> windows::core::Result<Result<KeyCredential, KeyCredentialStatus>> {
    let found = KeyCredentialManager::OpenAsync(&name())?.join()?;
    let status = found.Status()?;
    if status == KeyCredentialStatus::Success {
        found.Credential().map(Ok)
    } else {
        Ok(Err(status))
    }
}

/// Copy a WinRT buffer out. The intermediate array is wiped; the buffer itself
/// is WinRT memory this code cannot wipe (released when it drops).
fn bytes(buf: &IBuffer) -> windows::core::Result<Zeroizing<Vec<u8>>> {
    let mut array = Array::<u8>::new();
    CryptographicBuffer::CopyToByteArray(buf, &mut array)?;
    let out = Zeroizing::new(array.to_vec());
    let raw: &mut [u8] = &mut array;
    raw.zeroize();
    Ok(out)
}

fn challenge_entry() -> Result<keyring::Entry, SecretError> {
    keyring::Entry::new(SERVICE, CHALLENGE_ACCOUNT).map_err(|e| failed("challenge entry", e))
}

/// Sign `challenge` — this is the Hello prompt — and return the signature.
fn sign(credential: &KeyCredential, challenge: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecretError> {
    let data =
        CryptographicBuffer::CreateFromByteArray(challenge).map_err(|e| failed("sign", e))?;
    let signed = credential
        .RequestSignAsync(&data)
        .and_then(|op| op.join())
        .map_err(|e| failed("sign", e))?;
    let status = signed.Status().map_err(|e| failed("sign", e))?;
    if declined(status) {
        return Err(SecretError::Cancelled);
    }
    if status == KeyCredentialStatus::NotFound {
        return Err(SecretError::Invalidated);
    }
    if status != KeyCredentialStatus::Success {
        // `SecurityDeviceLocked` (too many wrong PINs) lands here: not a wipe.
        return Err(status_failed("sign", status));
    }
    signed
        .Result()
        .and_then(|buf| bytes(&buf))
        .map_err(|e| failed("sign", e))
}

impl DeviceSecretStore for WindowsHello {
    fn state(&self) -> SecretState {
        if !hello_supported() {
            return SecretState::Unsupported;
        }
        match open() {
            Ok(Ok(_)) => {}
            Ok(Err(KeyCredentialStatus::NotFound)) => return SecretState::Absent,
            _ => return SecretState::Unknown,
        }
        // The key alone cannot reproduce the secret: the challenge must be there too.
        match challenge_entry().map(|e| e.get_secret()) {
            Ok(Ok(mut challenge)) => {
                challenge.zeroize();
                SecretState::Present
            }
            Ok(Err(keyring::Error::NoEntry)) => SecretState::Absent,
            _ => SecretState::Unknown,
        }
    }

    fn create(&self) -> Result<Zeroizing<Vec<u8>>, SecretError> {
        if !hello_supported() {
            return Err(SecretError::Unsupported);
        }
        // Shows the Hello prompt; replaces an earlier credential of the same name.
        let created = KeyCredentialManager::RequestCreateAsync(
            &name(),
            KeyCredentialCreationOption::ReplaceExisting,
        )
        .and_then(|op| op.join())
        .map_err(|e| failed("create", e))?;
        let status = created.Status().map_err(|e| failed("create", e))?;
        if declined(status) {
            return Err(SecretError::Cancelled);
        }
        if status != KeyCredentialStatus::Success {
            return Err(status_failed("create", status));
        }
        let credential = created.Credential().map_err(|e| failed("create", e))?;
        let challenge = CryptographicBuffer::GenerateRandom(CHALLENGE_LEN)
            .and_then(|buf| bytes(&buf))
            .map_err(|e| failed("challenge", e))?;
        challenge_entry()?
            .set_secret(&challenge)
            .map_err(|e| failed("store challenge", e))?;
        // Signing prompts again: Hello verifies every use of the key.
        sign(&credential, &challenge)
    }

    fn read(&self, _reason: &str) -> Result<Zeroizing<Vec<u8>>, SecretError> {
        // Hello turned off by policy or not reachable right now: not a wipe.
        if !hello_supported() {
            return Err(SecretError::Unsupported);
        }
        let credential = match open() {
            Ok(Ok(credential)) => credential,
            Ok(Err(KeyCredentialStatus::NotFound)) => return Err(SecretError::Invalidated),
            Ok(Err(status)) => return Err(status_failed("open", status)),
            Err(e) => return Err(failed("open", e)),
        };
        let challenge = match challenge_entry()?.get_secret() {
            Ok(challenge) => Zeroizing::new(challenge),
            Err(keyring::Error::NoEntry) => return Err(SecretError::Invalidated),
            Err(e) => return Err(failed("read challenge", e)),
        };
        sign(&credential, &challenge)
    }

    fn delete(&self) -> Result<(), SecretError> {
        // Where Hello is not usable the credential cannot be reached (and a
        // Hello reset has already destroyed it); the challenge alone is useless.
        let credential = if !hello_supported() {
            Ok(())
        } else {
            match open() {
                Ok(Err(KeyCredentialStatus::NotFound)) => Ok(()),
                _ => KeyCredentialManager::DeleteAsync(&name())
                    .and_then(|op| op.join())
                    .map_err(|e| failed("delete", e)),
            }
        };
        let challenge = match challenge_entry().map(|e| e.delete_credential()) {
            Ok(Ok(()) | Err(keyring::Error::NoEntry)) => Ok(()),
            Ok(Err(e)) => Err(failed("delete challenge", e)),
            Err(e) => Err(e),
        };
        credential.and(challenge)
    }
}
