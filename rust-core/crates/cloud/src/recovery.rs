//! Shared installation for escrow and Emergency-Kit recovery.
//!
//! Call on a blocking thread. The desktop app calls it inside its
//! `biometric::installing_keyset`: a recovered keyset may be wrapped under
//! another password, and nothing sealed for the one it replaced may stay behind.

use crate::{CloudError, CloudResult};
use unissh_ffi::Core;

/// Installs and unlocks a recovered keyset `blob`, then hands its Secret Key to
/// `save_secret_key` so the device can unlock again after a restart.
///
/// The keyset is authenticated and the storage opened before anything is
/// remembered: a wrong credential or another identity's keyset never replaces
/// the Secret Key this device already keeps. A failing `save_secret_key` is
/// logged and does not undo the install — the user then types the key at the
/// next unlock.
pub fn install_keyset<E: std::fmt::Debug>(
    core: &Core,
    blob: Vec<u8>,
    password: Option<String>,
    secret_key_hex: String,
    save_secret_key: impl FnOnce(&str) -> Result<(), E>,
) -> CloudResult<()> {
    // Authenticate and open storage FIRST. A wrong credential or another
    // identity's DB must not replace this device's remembered Secret Key.
    core.unlock_from_server_blob(blob, password, secret_key_hex.clone())
        .map_err(CloudError::from)?;
    // Save before device enrollment/login: a network failure after installation
    // must still leave an instance that can unlock after a restart. As with
    // pairing, an unavailable key store requires manual entry, not a DB rollback.
    if let Err(e) = save_secret_key(&secret_key_hex) {
        log::warn!("recovery: failed to remember the Secret Key: {e:?}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn core(dir: &std::path::Path) -> std::sync::Arc<Core> {
        Core::new(
            dir.join("instance.db").to_string_lossy().into_owned(),
            dir.join("instance.keyset.bin")
                .to_string_lossy()
                .into_owned(),
        )
    }

    #[test]
    fn recovery_remembers_only_an_installed_identity_and_reopens_offline() {
        let source = tempfile::tempdir().unwrap();
        let original = core(source.path());
        let secret = original.create_account(Some("password".into())).unwrap();
        let blob = std::fs::read(source.path().join("instance.keyset.bin")).unwrap();
        let target = tempfile::tempdir().unwrap();
        let recovered = core(target.path());
        let mut saved = None;
        install_keyset(
            &recovered,
            blob.clone(),
            Some("password".into()),
            secret.clone(),
            |key| {
                assert!(recovered.is_unlocked());
                saved = Some(key.to_owned());
                Ok::<(), CloudError>(())
            },
        )
        .unwrap();
        assert_eq!(saved.as_deref(), Some(secret.as_str()));
        recovered.lock();
        drop(recovered);
        core(target.path())
            .unlock(Some("password".into()), saved.unwrap())
            .unwrap();

        let clean = tempfile::tempdir().unwrap();
        assert!(install_keyset(
            &core(clean.path()),
            blob,
            Some("wrong".into()),
            secret,
            |_| -> Result<(), CloudError> {
                panic!("must not overwrite keychain on failed authentication")
            },
        )
        .is_err());
        assert!(!clean.path().join("instance.db").exists());
    }

    #[test]
    fn unavailable_keychain_keeps_manual_unlock_working() {
        let source = tempfile::tempdir().unwrap();
        let secret = core(source.path()).create_account(None).unwrap();
        let blob = std::fs::read(source.path().join("instance.keyset.bin")).unwrap();
        let target = tempfile::tempdir().unwrap();
        let recovered = core(target.path());
        install_keyset(&recovered, blob, None, secret.clone(), |_| {
            Err(CloudError::other("unavailable"))
        })
        .unwrap();
        recovered.lock();
        drop(recovered);
        core(target.path()).unlock(None, secret).unwrap();
    }
}
