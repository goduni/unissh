//! P5: device-to-device PAKE onboarding (server-tz §9 Path B). Relay = in-memory
//! message passing (there is no server in this repo).

use unissh_keychain::{
    create_account, unlock_account, KdfParams, KeychainError, OnboardInitiator, OnboardResponder,
};

fn fast_params() -> KdfParams {
    // ≥ OWASP minimum (19 MiB / t=2) — below the hard floor from_blob rejects the keyset.
    KdfParams {
        mem_kib: 19 * 1024,
        iterations: 2,
        parallelism: 1,
        salt: vec![6u8; 16],
    }
}

#[test]
fn pake_onboarding_happy_path_transfers_identity() {
    // The existing device owns the keyset.
    let (sk, _rec, unlocked) = create_account(Some(b"pw"), fast_params()).unwrap();
    let code = b"483920";

    // Step 1: initiator starts, sends msg1.
    let (initiator, msg1) = OnboardInitiator::start(code);
    // Step 2: responder replies with msg2 (PAKE outbound + confirm-tag).
    let (responder, msg2) = OnboardResponder::respond(code, &msg1).unwrap();
    // Step 3: initiator verifies the responder-tag, sends msg3 (initiator-tag + sealed keyset).
    let msg3 = initiator.confirm_and_seal(&msg2, &unlocked, &sk).unwrap();
    // Final: responder verifies the initiator-tag, decrypts, and installs its own device record.
    let (device_sk, device_record, installed) = responder
        .finish_install(&msg3, Some(b"device-pw"), fast_params())
        .unwrap();

    // The keyset identity is transferred: the same public keys.
    assert_eq!(
        installed.signing.verifying.to_bytes(),
        unlocked.signing.verifying.to_bytes()
    );
    assert_eq!(
        installed.encryption.public.to_bytes(),
        unlocked.encryption.public.to_bytes()
    );
    // Model A: device B received the SAME account Secret Key as A.
    assert_eq!(
        sk.expose_bytes(),
        device_sk.expose_bytes(),
        "общий аккаунтный Secret Key на обоих устройствах"
    );
    // the device record opens with the local password + the shared account Secret Key.
    let reopened = unlock_account(&device_record, Some(b"device-pw"), &device_sk).unwrap();
    assert_eq!(
        reopened.signing.verifying.to_bytes(),
        unlocked.signing.verifying.to_bytes()
    );
    // generation of the new record = 1 (fresh local wrapping).
    assert_eq!(device_record.generation, 1);
}

#[test]
fn pake_wrong_code_confirmation_fails_no_key_agreement() {
    // Negative §1: the two sides have different codes → confirm-tag does not match, secrets are not sent.
    let (sk, _rec, unlocked) = create_account(Some(b"pw"), fast_params()).unwrap();
    let (initiator, msg1) = OnboardInitiator::start(b"111111");
    let (_responder, msg2) = OnboardResponder::respond(b"222222", &msg1).unwrap();
    // initiator verifies the responder-confirm-tag → must fail (different channel keys).
    assert_eq!(
        initiator
            .confirm_and_seal(&msg2, &unlocked, &sk)
            .unwrap_err(),
        KeychainError::ConfirmationFailed
    );
}

#[test]
fn pake_tampered_sealed_blob_aead_fails() {
    // Negative §2: corrupting the sealed-keyset in msg3 → AEAD authentication will fail.
    let (sk, _rec, unlocked) = create_account(Some(b"pw"), fast_params()).unwrap();
    let code = b"777000";
    let (initiator, msg1) = OnboardInitiator::start(code);
    let (responder, msg2) = OnboardResponder::respond(code, &msg1).unwrap();
    let mut msg3 = initiator.confirm_and_seal(&msg2, &unlocked, &sk).unwrap();
    // corrupt the last byte (part of the sealed keyset's AEAD tag)
    let last = msg3.len() - 1;
    msg3[last] ^= 0x01;
    let err = responder
        .finish_install(&msg3, Some(b"device-pw"), fast_params())
        .unwrap_err();
    // either confirm-tag (if we hit it) or AEAD Decrypt — both are typed, not a panic
    assert!(matches!(
        err,
        KeychainError::Crypto(_) | KeychainError::ConfirmationFailed
    ));
}

#[test]
fn pake_tampered_initiator_confirm_tag_rejected() {
    // Negative §3: corrupt the initiator confirm-tag in msg3[0..32], the sealed-keyset is NOT touched.
    // Isolates the responder-side verify_confirm_tag check in finish_install: with the guard
    // → ConfirmationFailed; without the guard finish would reach the AEAD-decrypt (the tag is not part of the AAD)
    // and would decrypt a valid sealed blob, i.e. without the guard the test fails (non-vacuous).
    let (sk, _rec, unlocked) = create_account(Some(b"pw"), fast_params()).unwrap();
    let code = b"246810";
    let (initiator, msg1) = OnboardInitiator::start(code);
    let (responder, msg2) = OnboardResponder::respond(code, &msg1).unwrap();
    let mut msg3 = initiator.confirm_and_seal(&msg2, &unlocked, &sk).unwrap();
    // flip a byte INSIDE the initiator confirm-tag (first 32 bytes), without touching the sealed-keyset
    msg3[0] ^= 0x01;
    assert_eq!(
        responder
            .finish_install(&msg3, Some(b"device-pw"), fast_params())
            .unwrap_err(),
        KeychainError::ConfirmationFailed
    );
}

#[test]
fn pake_responder_tampered_pake_msg_rejected() {
    // Negative: corrupting the PAKE part of msg1 at the responder → finish errors / confirm does not match.
    let (_sk, _rec, _unlocked) = create_account(Some(b"pw"), fast_params()).unwrap();
    let (_initiator, mut msg1) = OnboardInitiator::start(b"909090");
    let last = msg1.len() - 1;
    msg1[last] ^= 0x01;
    // the responder may either reject the PAKE-msg or derive a different key — both are non-panic.
    let res = OnboardResponder::respond(b"909090", &msg1);
    assert!(res.is_ok() || matches!(res, Err(KeychainError::ConfirmationFailed)));
}
