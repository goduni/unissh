//! Тесты P3: членство, гранты, верификация доступа, пиннинг member-pubkey.

use unissh_crypto::{Ed25519Keypair, X25519Keypair};
use unissh_keychain::{create_account, KdfParams, UnlockedKeyset};
use unissh_storage::{MemberRole, Storage};
use unissh_vault::{
    add_member, build_grant, build_manifest, member_fingerprint, new_vault_id,
    open_account_payload, open_grant, pin_and_verify_member, pin_and_verify_vault_anchor,
    seal_account_payload, verify_grant, verify_manifest, Member, Vault, VaultError,
};

#[allow(dead_code)]
fn keyset() -> UnlockedKeyset {
    let (_sk, _rec, unlocked) = create_account(None, KdfParams::recommended()).unwrap();
    unlocked
}
#[allow(dead_code)]
fn storage() -> Storage {
    Storage::open_in_memory(&[7u8; 32]).unwrap()
}

#[test]
fn new_vault_id_is_uuid_v4_16_bytes() {
    let a = new_vault_id();
    let b = new_vault_id();
    assert_eq!(a.len(), 16);
    assert_ne!(a, b, "две генерации различны");
    // версия 4: старший ниббл байта 6 == 0x4
    assert_eq!(a[6] >> 4, 0x4);
    // вариант RFC 4122: два старших бита байта 8 == 0b10
    assert_eq!(a[8] >> 6, 0b10);
}

// --- Task 2: membership manifest + sigchain authority ---

#[test]
fn genesis_manifest_anchored_on_creator_verifies() {
    let creator = keyset();
    let vid = new_vault_id();
    let creator_ed = creator.signing.verifying.to_bytes().to_vec();
    let alice_ed = Ed25519Keypair::generate().verifying.to_bytes().to_vec();
    let members = vec![
        Member {
            ed25519_pub: creator_ed.clone(),
            role: MemberRole::Admin,
        },
        Member {
            ed25519_pub: alice_ed.clone(),
            role: MemberRole::Editor,
        },
    ];
    // genesis (epoch 1) подписан создателем (он же admin в наборе)
    let m = build_manifest(&creator, &vid, 1, &members).unwrap();
    // verify против genesis-owner = pubkey создателя
    let verified = verify_manifest(&m, &vid, None, &creator_ed).unwrap();
    assert_eq!(verified.epoch(), 1);
    assert!(verified.contains(&alice_ed));
    assert!(verified.is_admin(&creator_ed));
}

#[test]
fn forged_manifest_signature_rejected() {
    let creator = keyset();
    let vid = new_vault_id();
    let creator_ed = creator.signing.verifying.to_bytes().to_vec();
    let members = vec![Member {
        ed25519_pub: creator_ed.clone(),
        role: MemberRole::Admin,
    }];
    let mut m = build_manifest(&creator, &vid, 1, &members).unwrap();
    // порча подписи
    *m.signature.last_mut().unwrap() ^= 0xff;
    assert!(matches!(
        verify_manifest(&m, &vid, None, &creator_ed).unwrap_err(),
        VaultError::SignatureInvalid
    ));
}

#[test]
fn genesis_manifest_not_signed_by_creator_rejected() {
    let creator = keyset();
    let attacker = keyset();
    let vid = new_vault_id();
    let creator_ed = creator.signing.verifying.to_bytes().to_vec();
    let attacker_ed = attacker.signing.verifying.to_bytes().to_vec();
    // атакующий подписывает genesis, ставя себя admin
    let members = vec![Member {
        ed25519_pub: attacker_ed,
        role: MemberRole::Admin,
    }];
    let m = build_manifest(&attacker, &vid, 1, &members).unwrap();
    // verify против правильного genesis-owner (создателя) → отказ авторитета
    assert!(matches!(
        verify_manifest(&m, &vid, None, &creator_ed).unwrap_err(),
        VaultError::AuthorityInvalid
    ));
}

#[test]
fn next_epoch_manifest_signed_by_prior_admin_verifies() {
    let creator = keyset(); // admin@epoch1
    let bob = keyset(); // станет admin@epoch1 тоже
    let vid = new_vault_id();
    let creator_ed = creator.signing.verifying.to_bytes().to_vec();
    let bob_ed = bob.signing.verifying.to_bytes().to_vec();
    let m1 = build_manifest(
        &creator,
        &vid,
        1,
        &[
            Member {
                ed25519_pub: creator_ed.clone(),
                role: MemberRole::Admin,
            },
            Member {
                ed25519_pub: bob_ed.clone(),
                role: MemberRole::Admin,
            },
        ],
    )
    .unwrap();
    let v1 = verify_manifest(&m1, &vid, None, &creator_ed).unwrap();
    // epoch 2 подписан bob (admin в epoch1) — авторитет ок
    let m2 = build_manifest(
        &bob,
        &vid,
        2,
        &[Member {
            ed25519_pub: bob_ed.clone(),
            role: MemberRole::Admin,
        }],
    )
    .unwrap();
    let v2 = verify_manifest(&m2, &vid, Some(&v1), &creator_ed).unwrap();
    assert_eq!(v2.epoch(), 2);
}

#[test]
fn next_epoch_manifest_signed_by_non_admin_rejected() {
    let creator = keyset();
    let viewer = keyset();
    let vid = new_vault_id();
    let creator_ed = creator.signing.verifying.to_bytes().to_vec();
    let viewer_ed = viewer.signing.verifying.to_bytes().to_vec();
    let m1 = build_manifest(
        &creator,
        &vid,
        1,
        &[
            Member {
                ed25519_pub: creator_ed.clone(),
                role: MemberRole::Admin,
            },
            Member {
                ed25519_pub: viewer_ed,
                role: MemberRole::Viewer,
            },
        ],
    )
    .unwrap();
    let v1 = verify_manifest(&m1, &vid, None, &creator_ed).unwrap();
    // epoch2 подписан viewer (не admin@epoch1) → отказ
    let m2 = build_manifest(&viewer, &vid, 2, &[]).unwrap();
    assert!(matches!(
        verify_manifest(&m2, &vid, Some(&v1), &creator_ed).unwrap_err(),
        VaultError::AuthorityInvalid
    ));
}

#[test]
fn next_epoch_must_be_prev_plus_one() {
    let creator = keyset();
    let vid = new_vault_id();
    let creator_ed = creator.signing.verifying.to_bytes().to_vec();
    let m1 = build_manifest(
        &creator,
        &vid,
        1,
        &[Member {
            ed25519_pub: creator_ed.clone(),
            role: MemberRole::Admin,
        }],
    )
    .unwrap();
    let v1 = verify_manifest(&m1, &vid, None, &creator_ed).unwrap();
    // epoch 3 поверх epoch1 (пропуск 2) → монотонность нарушена
    let m3 = build_manifest(
        &creator,
        &vid,
        3,
        &[Member {
            ed25519_pub: creator_ed.clone(),
            role: MemberRole::Admin,
        }],
    )
    .unwrap();
    assert!(matches!(
        verify_manifest(&m3, &vid, Some(&v1), &creator_ed).unwrap_err(),
        VaultError::EpochInvalid
    ));
}

// --- Task 3: per-member grants ---

#[test]
fn grant_roundtrip_open_with_correct_recipient() {
    let admin = keyset();
    let vid = new_vault_id();
    let admin_ed = admin.signing.verifying.to_bytes().to_vec();
    // получатель
    let recipient = X25519Keypair::generate();
    let recip_x = recipient.public.to_bytes().to_vec();
    let member_ed = Ed25519Keypair::generate().verifying.to_bytes().to_vec();
    let vk = unissh_crypto::SymmetricKey::generate();

    // Получатель должен быть членом набора (новый инвариант verify_grant) с
    // ролью, совпадающей с ролью гранта.
    let members = vec![
        Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        },
        Member {
            ed25519_pub: member_ed.clone(),
            role: MemberRole::Editor,
        },
    ];
    let m = build_manifest(&admin, &vid, 1, &members).unwrap();
    let v = verify_manifest(&m, &vid, None, &admin_ed).unwrap();

    let grant = build_grant(
        &admin,
        &vid,
        &recip_x,
        &member_ed,
        MemberRole::Editor,
        1,
        &vk,
    )
    .unwrap();
    verify_grant(&grant, &vid, &v).unwrap();
    let opened = open_grant(&grant, &vid, &recipient.secret, &member_ed, 1, 0).unwrap();
    assert_eq!(opened.expose_bytes(), vk.expose_bytes());
}

#[test]
fn grant_open_wrong_epoch_fails() {
    let admin = keyset();
    let vid = new_vault_id();
    let recipient = X25519Keypair::generate();
    let recip_x = recipient.public.to_bytes().to_vec();
    let member_ed = Ed25519Keypair::generate().verifying.to_bytes().to_vec();
    let vk = unissh_crypto::SymmetricKey::generate();
    let grant = build_grant(
        &admin,
        &vid,
        &recip_x,
        &member_ed,
        MemberRole::Editor,
        1,
        &vk,
    )
    .unwrap();
    // открытие с эпохой 2 → info не сходится
    assert!(matches!(
        open_grant(&grant, &vid, &recipient.secret, &member_ed, 2, 0).unwrap_err(),
        VaultError::Decrypt
    ));
}

#[test]
fn grant_open_wrong_member_binding_fails() {
    let admin = keyset();
    let vid = new_vault_id();
    let recipient = X25519Keypair::generate();
    let recip_x = recipient.public.to_bytes().to_vec();
    let member_ed = Ed25519Keypair::generate().verifying.to_bytes().to_vec();
    let other_ed = Ed25519Keypair::generate().verifying.to_bytes().to_vec();
    let vk = unissh_crypto::SymmetricKey::generate();
    let grant = build_grant(
        &admin,
        &vid,
        &recip_x,
        &member_ed,
        MemberRole::Editor,
        1,
        &vk,
    )
    .unwrap();
    assert!(matches!(
        open_grant(&grant, &vid, &recipient.secret, &other_ed, 1, 0).unwrap_err(),
        VaultError::Decrypt
    ));
}

#[test]
fn grant_open_wrong_vault_fails() {
    let admin = keyset();
    let vid = new_vault_id();
    let other_vid = new_vault_id();
    let recipient = X25519Keypair::generate();
    let recip_x = recipient.public.to_bytes().to_vec();
    let member_ed = Ed25519Keypair::generate().verifying.to_bytes().to_vec();
    let vk = unissh_crypto::SymmetricKey::generate();
    let grant = build_grant(
        &admin,
        &vid,
        &recip_x,
        &member_ed,
        MemberRole::Editor,
        1,
        &vk,
    )
    .unwrap();
    assert!(matches!(
        open_grant(&grant, &other_vid, &recipient.secret, &member_ed, 1, 0).unwrap_err(),
        VaultError::Decrypt
    ));
}

#[test]
fn grant_open_expired_not_after_rejected_client_side() {
    // F16: even if the untrusted server hands back an expired grant, the client must
    // refuse to open it (read-deny by time, independent of server enforcement).
    let admin = keyset();
    let vid = new_vault_id();
    let recipient = X25519Keypair::generate();
    let recip_x = recipient.public.to_bytes().to_vec();
    let member_ed = Ed25519Keypair::generate().verifying.to_bytes().to_vec();
    let vk = unissh_crypto::SymmetricKey::generate();
    let mut grant = build_grant(
        &admin,
        &vid,
        &recip_x,
        &member_ed,
        MemberRole::Editor,
        1,
        &vk,
    )
    .unwrap();
    // Stamp an expiry in the past (the signature isn't re-checked by open_grant; the
    // expiry gate runs BEFORE the unwrap).
    grant.not_after = 1_000;
    assert!(matches!(
        open_grant(&grant, &vid, &recipient.secret, &member_ed, 1, 2_000).unwrap_err(),
        VaultError::GrantExpired
    ));
    // A `now` before not_after still opens (no expiry yet).
    let opened = open_grant(&grant, &vid, &recipient.secret, &member_ed, 1, 999).unwrap();
    assert_eq!(opened.expose_bytes(), vk.expose_bytes());
    // Sentinel not_after = 0 ⇒ never expires.
    grant.not_after = 0;
    assert!(open_grant(&grant, &vid, &recipient.secret, &member_ed, 1, i64::MAX).is_ok());
}

#[test]
fn grant_forged_signature_rejected() {
    let admin = keyset();
    let vid = new_vault_id();
    let admin_ed = admin.signing.verifying.to_bytes().to_vec();
    let recipient = X25519Keypair::generate();
    let recip_x = recipient.public.to_bytes().to_vec();
    let member_ed = Ed25519Keypair::generate().verifying.to_bytes().to_vec();
    let vk = unissh_crypto::SymmetricKey::generate();
    let m = build_manifest(
        &admin,
        &vid,
        1,
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
    )
    .unwrap();
    let v = verify_manifest(&m, &vid, None, &admin_ed).unwrap();
    let mut grant = build_grant(
        &admin,
        &vid,
        &recip_x,
        &member_ed,
        MemberRole::Editor,
        1,
        &vk,
    )
    .unwrap();
    *grant.signature.last_mut().unwrap() ^= 0xff;
    assert!(matches!(
        verify_grant(&grant, &vid, &v).unwrap_err(),
        VaultError::SignatureInvalid
    ));
}

#[test]
fn grant_signed_by_non_admin_rejected() {
    let admin = keyset();
    let editor = keyset();
    let vid = new_vault_id();
    let admin_ed = admin.signing.verifying.to_bytes().to_vec();
    let editor_ed = editor.signing.verifying.to_bytes().to_vec();
    let recipient = X25519Keypair::generate();
    let recip_x = recipient.public.to_bytes().to_vec();
    let member_ed = Ed25519Keypair::generate().verifying.to_bytes().to_vec();
    let vk = unissh_crypto::SymmetricKey::generate();
    let m = build_manifest(
        &admin,
        &vid,
        1,
        &[
            Member {
                ed25519_pub: admin_ed.clone(),
                role: MemberRole::Admin,
            },
            Member {
                ed25519_pub: editor_ed.clone(),
                role: MemberRole::Editor,
            },
        ],
    )
    .unwrap();
    let v = verify_manifest(&m, &vid, None, &admin_ed).unwrap();
    // грант подписан editor (не admin) → verify_grant отказ авторитета
    let grant = build_grant(
        &editor,
        &vid,
        &recip_x,
        &member_ed,
        MemberRole::Viewer,
        1,
        &vk,
    )
    .unwrap();
    assert!(matches!(
        verify_grant(&grant, &vid, &v).unwrap_err(),
        VaultError::AuthorityInvalid
    ));
}

// --- Task 4: author-in-members@epoch authority predicate ---

use unissh_storage::MembershipManifest;

// Хелпер: положить проверяемый manifest в storage (как это сделает add_member).
fn put_manifest(st: &Storage, m: &MembershipManifest) {
    st.put_membership_manifest(m).unwrap();
}

#[test]
fn authority_accepts_member_at_epoch() {
    let st = storage();
    let admin = keyset();
    let vid = new_vault_id();
    let admin_ed = admin.signing.verifying.to_bytes().to_vec();
    let author_ed = Ed25519Keypair::generate().verifying.to_bytes().to_vec();
    let m = build_manifest(
        &admin,
        &vid,
        1,
        &[
            Member {
                ed25519_pub: admin_ed.clone(),
                role: MemberRole::Admin,
            },
            Member {
                ed25519_pub: author_ed.clone(),
                role: MemberRole::Editor,
            },
        ],
    )
    .unwrap();
    put_manifest(&st, &m);
    // genesis_owner = admin (создатель). author_ed — член@1, пол=0.
    unissh_vault::verify_record_authority(&st, &vid, &author_ed, 1, &admin_ed).unwrap();
}

#[test]
fn authority_rejects_viewer_authoring_content() {
    // RBAC write-integrity: Viewer (read-only) ЧИСЛИТСЯ членом, но не вправе
    // авторить item/vault-записи. verify_record_authority обязан отказать
    // (иначе read-only член мог бы создавать/перезаписывать/томбстонить записи,
    // а verify-before-apply у других членов принял бы их как аутентичные).
    let st = storage();
    let admin = keyset();
    let vid = new_vault_id();
    let admin_ed = admin.signing.verifying.to_bytes().to_vec();
    let viewer_ed = Ed25519Keypair::generate().verifying.to_bytes().to_vec();
    let m = build_manifest(
        &admin,
        &vid,
        1,
        &[
            Member {
                ed25519_pub: admin_ed.clone(),
                role: MemberRole::Admin,
            },
            Member {
                ed25519_pub: viewer_ed.clone(),
                role: MemberRole::Viewer,
            },
        ],
    )
    .unwrap();
    put_manifest(&st, &m);
    // Viewer — член@1, но не writer → AuthorityInvalid.
    assert!(matches!(
        unissh_vault::verify_record_authority(&st, &vid, &viewer_ed, 1, &admin_ed).unwrap_err(),
        VaultError::AuthorityInvalid
    ));
    // Admin из того же набора — пишет нормально (контроль).
    unissh_vault::verify_record_authority(&st, &vid, &admin_ed, 1, &admin_ed).unwrap();
}

#[test]
fn authority_rejects_non_member() {
    let st = storage();
    let admin = keyset();
    let vid = new_vault_id();
    let admin_ed = admin.signing.verifying.to_bytes().to_vec();
    let stranger = Ed25519Keypair::generate().verifying.to_bytes().to_vec();
    let m = build_manifest(
        &admin,
        &vid,
        1,
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
    )
    .unwrap();
    put_manifest(&st, &m);
    assert!(matches!(
        unissh_vault::verify_record_authority(&st, &vid, &stranger, 1, &admin_ed).unwrap_err(),
        VaultError::NotAMember
    ));
}

#[test]
fn authority_rejects_rolled_back_epoch() {
    let st = storage();
    let admin = keyset();
    let vid = new_vault_id();
    let admin_ed = admin.signing.verifying.to_bytes().to_vec();
    let m = build_manifest(
        &admin,
        &vid,
        1,
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
    )
    .unwrap();
    put_manifest(&st, &m);
    // пол эпохи = 5; запись на эпохе 1 (< пол) → откат
    st.set_vault_epoch_floor(&vid, 5).unwrap();
    assert!(matches!(
        unissh_vault::verify_record_authority(&st, &vid, &admin_ed, 1, &admin_ed).unwrap_err(),
        VaultError::EpochInvalid
    ));
}

#[test]
fn authority_falls_back_to_owner_when_no_manifest() {
    let st = storage();
    let owner = keyset();
    let vid = new_vault_id();
    let owner_ed = owner.signing.verifying.to_bytes().to_vec();
    let other = Ed25519Keypair::generate().verifying.to_bytes().to_vec();
    // нет manifest → genesis_owner играет роль доверенного владельца
    unissh_vault::verify_record_authority(&st, &vid, &owner_ed, 0, &owner_ed).unwrap();
    assert!(matches!(
        unissh_vault::verify_record_authority(&st, &vid, &other, 0, &owner_ed).unwrap_err(),
        VaultError::NotAMember
    ));
}

#[test]
fn authority_rejects_epoch_without_manifest_in_membership_mode() {
    // АНТИ-ROLLBACK BYPASS (high): волт В membership-режиме (есть manifest@1 + пол),
    // но запись предъявляет key_epoch=0 (эпоха БЕЗ manifest). Режим НЕ должен
    // вычисляться по-записно: даунгрейд на owner==author запрещён. Даже валидный
    // owner-автор на эпохе без manifest в membership-режиме → отказ.
    let st = storage();
    let admin = keyset();
    let vid = new_vault_id();
    let admin_ed = admin.signing.verifying.to_bytes().to_vec();
    let m = build_manifest(
        &admin,
        &vid,
        1,
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
    )
    .unwrap();
    put_manifest(&st, &m);
    // volt-level сигнал membership-режима: пол эпохи установлен.
    st.set_vault_epoch_floor(&vid, 1).unwrap();
    // admin — genesis_owner И член@1, НО предъявляет key_epoch=0 (без manifest).
    assert!(matches!(
        unissh_vault::verify_record_authority(&st, &vid, &admin_ed, 0, &admin_ed).unwrap_err(),
        VaultError::EpochInvalid
    ));
}

// --- Task 5: member-pubkey pinning (TOFU) + OOB fingerprint ---

#[test]
fn fingerprint_is_stable_sha256_hex() {
    let ed = Ed25519Keypair::generate().verifying.to_bytes().to_vec();
    let f1 = member_fingerprint(&ed);
    let f2 = member_fingerprint(&ed);
    assert_eq!(f1, f2);
    assert_eq!(f1.len(), 64); // hex SHA-256
    assert!(f1.chars().all(|c| c.is_ascii_hexdigit()));
    let other = Ed25519Keypair::generate().verifying.to_bytes().to_vec();
    assert_ne!(member_fingerprint(&other), f1);
}

#[test]
fn pin_tofu_then_match_ok() {
    let st = storage();
    let acct = b"alice-account".to_vec();
    let ed = Ed25519Keypair::generate().verifying.to_bytes().to_vec();
    // TOFU: первый раз пиннится
    pin_and_verify_member(&st, &acct, &ed).unwrap();
    // второй раз — совпадает с пином → ок
    pin_and_verify_member(&st, &acct, &ed).unwrap();
    let pinned = st.get_pinned_member_key(&acct).unwrap().unwrap();
    assert_eq!(pinned.member_pubkey, ed);
    assert_eq!(pinned.fingerprint, member_fingerprint(&ed));
}

#[test]
fn pin_mismatch_rejected() {
    let st = storage();
    let acct = b"alice-account".to_vec();
    let ed = Ed25519Keypair::generate().verifying.to_bytes().to_vec();
    let imposter = Ed25519Keypair::generate().verifying.to_bytes().to_vec();
    pin_and_verify_member(&st, &acct, &ed).unwrap();
    // другой ключ под тем же account → mismatch (НЕ перезапись)
    assert!(matches!(
        pin_and_verify_member(&st, &acct, &imposter).unwrap_err(),
        VaultError::PinMismatch
    ));
    // пин не изменился
    assert_eq!(
        st.get_pinned_member_key(&acct)
            .unwrap()
            .unwrap()
            .member_pubkey,
        ed
    );
}

#[test]
fn vault_anchor_tofu_then_match_ok() {
    let st = storage();
    let vid = b"vault-x".to_vec();
    let creator = Ed25519Keypair::generate().verifying.to_bytes().to_vec();
    // TOFU: первый раз пиннится
    pin_and_verify_vault_anchor(&st, &vid, &creator).unwrap();
    // второй раз тем же creator-pubkey → ок (идемпотентно)
    pin_and_verify_vault_anchor(&st, &vid, &creator).unwrap();
    let anchor = st.get_vault_trust_anchor(&vid).unwrap().unwrap();
    assert_eq!(anchor.genesis_owner_pubkey, creator);
}

#[test]
fn vault_anchor_rebind_rejected() {
    let st = storage();
    let vid = b"vault-x".to_vec();
    let creator = Ed25519Keypair::generate().verifying.to_bytes().to_vec();
    let imposter = Ed25519Keypair::generate().verifying.to_bytes().to_vec();
    pin_and_verify_vault_anchor(&st, &vid, &creator).unwrap();
    // сервер пытается ре-биндить volt→owner на другой ключ → PinMismatch, без перезаписи
    assert!(matches!(
        pin_and_verify_vault_anchor(&st, &vid, &imposter).unwrap_err(),
        VaultError::PinMismatch
    ));
    assert_eq!(
        st.get_vault_trust_anchor(&vid)
            .unwrap()
            .unwrap()
            .genesis_owner_pubkey,
        creator
    );
}

// --- Task 6: add_member flow + integration into decrypt_record ---

#[test]
fn add_member_persists_verified_manifest_and_grants() {
    let st = storage();
    let admin = keyset();
    let vid = new_vault_id();
    let admin_ed = admin.signing.verifying.to_bytes().to_vec();
    // получатель (новый член)
    let recip_kc = keyset();
    let recip_ed = recip_kc.signing.verifying.to_bytes().to_vec();
    let recip_x = recip_kc.encryption.public.to_bytes().to_vec();
    let vk = unissh_crypto::SymmetricKey::generate();

    let members = vec![
        Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        },
        Member {
            ed25519_pub: recip_ed.clone(),
            role: MemberRole::Editor,
        },
    ];
    let grants = vec![(recip_x.clone(), recip_ed.clone(), MemberRole::Editor)];
    add_member(
        &st, &admin, &vid, 1, None, &admin_ed, &members, &grants, &vk,
    )
    .unwrap();

    // manifest и грант в storage
    let m = st.get_membership_manifest(&vid, 1).unwrap().unwrap();
    assert_eq!(m.key_epoch, 1);
    let gs = st.list_membership_grants(&vid, 1).unwrap();
    assert_eq!(gs.len(), 1);
    // получатель открывает свой грант → VK
    let opened = open_grant(&gs[0], &vid, &recip_kc.encryption.secret, &recip_ed, 1, 0).unwrap();
    assert_eq!(opened.expose_bytes(), vk.expose_bytes());
}

#[test]
fn add_member_rejects_unauthorized_admin() {
    let st = storage();
    let creator = keyset();
    let attacker = keyset();
    let vid = new_vault_id();
    let creator_ed = creator.signing.verifying.to_bytes().to_vec();
    let attacker_ed = attacker.signing.verifying.to_bytes().to_vec();
    let vk = unissh_crypto::SymmetricKey::generate();
    // attacker пытается выпустить genesis, ставя себя admin, но genesis_owner=creator
    let members = vec![Member {
        ed25519_pub: attacker_ed.clone(),
        role: MemberRole::Admin,
    }];
    let err = add_member(
        &st,
        &attacker,
        &vid,
        1,
        None,
        &creator_ed,
        &members,
        &[],
        &vk,
    )
    .unwrap_err();
    assert!(matches!(err, VaultError::AuthorityInvalid));
    // ничего не записано
    assert!(st.get_membership_manifest(&vid, 1).unwrap().is_none());
}

#[test]
fn local_vault_flow_unchanged_with_no_manifest() {
    // D2: волт без manifest ведёт себя как раньше (owner==author).
    let st = storage();
    let ks = keyset();
    let v = Vault::create(&st, &ks, b"local-v".to_vec(), b"name").unwrap();
    v.put_item(b"i", 1, b"secret").unwrap();
    let got = v.get_item(b"i").unwrap().unwrap();
    assert_eq!(got.content.as_slice(), b"secret");
    let report = v.verify_chain().unwrap();
    assert!(report.ok);
}

// --- Регресс P3-ревью: read-path авторитет САМОДОСТАТОЧЕН (D1 от genesis) ---

#[test]
fn authority_rejects_self_consistent_injected_manifest_at_later_epoch() {
    // Угроза (untrusted-DB / sync-ready): оператор инъектирует в storage
    // самосогласованный manifest эпохи 2 (author=attacker, members=[attacker]),
    // НЕ через add_member (т.е. без D1-цепочки от genesis). До фикса read-путь
    // верил storage и принимал его. Теперь verify_record_authority обязан
    // перепроверить цепочку от genesis_owner и отказать.
    let st = storage();
    let creator = keyset();
    let attacker = keyset();
    let vid = new_vault_id();
    let creator_ed = creator.signing.verifying.to_bytes().to_vec();
    let attacker_ed = attacker.signing.verifying.to_bytes().to_vec();

    // Легитимный genesis (epoch 1): только creator-admin.
    let m1 = build_manifest(
        &creator,
        &vid,
        1,
        &[Member {
            ed25519_pub: creator_ed.clone(),
            role: MemberRole::Admin,
        }],
    )
    .unwrap();
    put_manifest(&st, &m1);

    // Инъекция: самосогласованный manifest эпохи 2, подписанный attacker,
    // ставящий attacker admin-членом. Подпись валидна ПОД attacker, но цепочка
    // от genesis (creator) к нему не ведёт.
    let m2_forged = build_manifest(
        &attacker,
        &vid,
        2,
        &[Member {
            ed25519_pub: attacker_ed.clone(),
            role: MemberRole::Admin,
        }],
    )
    .unwrap();
    put_manifest(&st, &m2_forged);

    // Запись attacker на эпохе 2 должна быть отклонена (нет авторитета от genesis).
    assert!(matches!(
        unissh_vault::verify_record_authority(&st, &vid, &attacker_ed, 2, &creator_ed).unwrap_err(),
        VaultError::AuthorityInvalid
    ));
}

#[test]
fn authority_accepts_legitimately_chained_later_epoch() {
    // Контроль к предыдущему: если эпоха 2 ЗАКОННО связана с genesis (подписана
    // admin из эпохи 1), запись её члена принимается.
    let st = storage();
    let creator = keyset();
    let bob = keyset();
    let vid = new_vault_id();
    let creator_ed = creator.signing.verifying.to_bytes().to_vec();
    let bob_ed = bob.signing.verifying.to_bytes().to_vec();

    // genesis: creator+bob admin.
    let m1 = build_manifest(
        &creator,
        &vid,
        1,
        &[
            Member {
                ed25519_pub: creator_ed.clone(),
                role: MemberRole::Admin,
            },
            Member {
                ed25519_pub: bob_ed.clone(),
                role: MemberRole::Admin,
            },
        ],
    )
    .unwrap();
    put_manifest(&st, &m1);
    // epoch 2 подписан bob (admin@1) — законная цепочка.
    let m2 = build_manifest(
        &bob,
        &vid,
        2,
        &[Member {
            ed25519_pub: bob_ed.clone(),
            role: MemberRole::Admin,
        }],
    )
    .unwrap();
    put_manifest(&st, &m2);

    unissh_vault::verify_record_authority(&st, &vid, &bob_ed, 2, &creator_ed).unwrap();
}

#[test]
fn authority_rejects_when_intermediate_manifest_missing() {
    // Цепочка с дырой: есть genesis (epoch1) и manifest эпохи 3, но эпоха 2
    // отсутствует в storage. Перепроверка цепочки невозможна → отказ
    // (нельзя доказать авторитет автора на эпохе 3).
    let st = storage();
    let creator = keyset();
    let vid = new_vault_id();
    let creator_ed = creator.signing.verifying.to_bytes().to_vec();

    let m1 = build_manifest(
        &creator,
        &vid,
        1,
        &[Member {
            ed25519_pub: creator_ed.clone(),
            role: MemberRole::Admin,
        }],
    )
    .unwrap();
    put_manifest(&st, &m1);
    // самосогласованный manifest эпохи 3 (без эпохи 2 в storage).
    let m3 = build_manifest(
        &creator,
        &vid,
        3,
        &[Member {
            ed25519_pub: creator_ed.clone(),
            role: MemberRole::Admin,
        }],
    )
    .unwrap();
    put_manifest(&st, &m3);

    assert!(matches!(
        unissh_vault::verify_record_authority(&st, &vid, &creator_ed, 3, &creator_ed).unwrap_err(),
        VaultError::AuthorityInvalid
    ));
}

#[test]
fn authority_rejects_tampered_genesis_under_pinned_owner() {
    // Genesis в storage подменён на подписанный attacker (анти-anchor): даже
    // single-epoch read-путь обязан сверять genesis с пиннингованным
    // genesis_owner, а не доверять storage.
    let st = storage();
    let creator = keyset();
    let attacker = keyset();
    let vid = new_vault_id();
    let creator_ed = creator.signing.verifying.to_bytes().to_vec();
    let attacker_ed = attacker.signing.verifying.to_bytes().to_vec();

    let m1_forged = build_manifest(
        &attacker,
        &vid,
        1,
        &[Member {
            ed25519_pub: attacker_ed.clone(),
            role: MemberRole::Admin,
        }],
    )
    .unwrap();
    put_manifest(&st, &m1_forged);

    // genesis_owner пиннингован = creator; injected genesis подписан attacker.
    assert!(matches!(
        unissh_vault::verify_record_authority(&st, &vid, &attacker_ed, 1, &creator_ed).unwrap_err(),
        VaultError::AuthorityInvalid
    ));
}

// --- Регресс P3-ревью: verify_grant сверяет членство/роль получателя ---

#[test]
fn grant_to_non_member_rejected() {
    // Defense-in-depth: admin не должен иметь возможности выдать VK-обёртку
    // ключу, которого нет в manifest (иначе не-член получает VK-конверт).
    let admin = keyset();
    let vid = new_vault_id();
    let admin_ed = admin.signing.verifying.to_bytes().to_vec();
    let recipient = X25519Keypair::generate();
    let recip_x = recipient.public.to_bytes().to_vec();
    // member_ed НЕ входит в manifest.
    let non_member_ed = Ed25519Keypair::generate().verifying.to_bytes().to_vec();
    let vk = unissh_crypto::SymmetricKey::generate();

    let m = build_manifest(
        &admin,
        &vid,
        1,
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
    )
    .unwrap();
    let v = verify_manifest(&m, &vid, None, &admin_ed).unwrap();

    let grant = build_grant(
        &admin,
        &vid,
        &recip_x,
        &non_member_ed,
        MemberRole::Editor,
        1,
        &vk,
    )
    .unwrap();
    assert!(matches!(
        verify_grant(&grant, &vid, &v).unwrap_err(),
        VaultError::NotAMember
    ));
}

#[test]
fn grant_role_mismatch_with_manifest_rejected() {
    // Роль в гранте должна совпадать с ролью получателя в manifest.
    let admin = keyset();
    let vid = new_vault_id();
    let admin_ed = admin.signing.verifying.to_bytes().to_vec();
    let recipient = X25519Keypair::generate();
    let recip_x = recipient.public.to_bytes().to_vec();
    let member_ed = Ed25519Keypair::generate().verifying.to_bytes().to_vec();
    let vk = unissh_crypto::SymmetricKey::generate();

    // member числится Viewer в manifest.
    let m = build_manifest(
        &admin,
        &vid,
        1,
        &[
            Member {
                ed25519_pub: admin_ed.clone(),
                role: MemberRole::Admin,
            },
            Member {
                ed25519_pub: member_ed.clone(),
                role: MemberRole::Viewer,
            },
        ],
    )
    .unwrap();
    let v = verify_manifest(&m, &vid, None, &admin_ed).unwrap();

    // грант выписан с ролью Editor (≠ Viewer) → отказ консистентности.
    let grant = build_grant(
        &admin,
        &vid,
        &recip_x,
        &member_ed,
        MemberRole::Editor,
        1,
        &vk,
    )
    .unwrap();
    assert!(matches!(
        verify_grant(&grant, &vid, &v).unwrap_err(),
        VaultError::AuthorityInvalid
    ));
}

#[test]
fn grant_to_member_with_matching_role_ok() {
    // Контроль: грант члену с совпадающей ролью проходит (не регрессируем
    // легитимный путь).
    let admin = keyset();
    let vid = new_vault_id();
    let admin_ed = admin.signing.verifying.to_bytes().to_vec();
    let recipient = X25519Keypair::generate();
    let recip_x = recipient.public.to_bytes().to_vec();
    let member_ed = Ed25519Keypair::generate().verifying.to_bytes().to_vec();
    let vk = unissh_crypto::SymmetricKey::generate();

    let m = build_manifest(
        &admin,
        &vid,
        1,
        &[
            Member {
                ed25519_pub: admin_ed.clone(),
                role: MemberRole::Admin,
            },
            Member {
                ed25519_pub: member_ed.clone(),
                role: MemberRole::Editor,
            },
        ],
    )
    .unwrap();
    let v = verify_manifest(&m, &vid, None, &admin_ed).unwrap();

    let grant = build_grant(
        &admin,
        &vid,
        &recip_x,
        &member_ed,
        MemberRole::Editor,
        1,
        &vk,
    )
    .unwrap();
    verify_grant(&grant, &vid, &v).unwrap();
}

// --- P7: Vault::establish_or_extend_membership (VK остаётся в ядре) ---

#[test]
fn establish_membership_via_vault_method_and_extend() {
    use unissh_vault::verify_chain_to_epoch;
    let st = storage();
    let owner = keyset();
    let bob = keyset();
    let owner_ed = owner.signing.verifying.to_bytes().to_vec();
    let owner_x = owner.encryption.public.to_bytes().to_vec();
    let bob_ed = bob.signing.verifying.to_bytes().to_vec();
    let bob_x = bob.encryption.public.to_bytes().to_vec();

    let v = Vault::create(&st, &owner, b"mv".to_vec(), b"shared").unwrap();

    // genesis: owner(Admin) + bob(Editor).
    let members = vec![
        Member {
            ed25519_pub: owner_ed.clone(),
            role: MemberRole::Admin,
        },
        Member {
            ed25519_pub: bob_ed.clone(),
            role: MemberRole::Editor,
        },
    ];
    let xkeys = vec![
        (owner_ed.clone(), owner_x.clone()),
        (bob_ed.clone(), bob_x.clone()),
    ];
    let epoch = v
        .establish_or_extend_membership(&owner, &members, &xkeys)
        .unwrap();
    assert_eq!(epoch, 1);

    // цепочка до epoch 1 верифицируется, оба члена присутствуют
    let verified = verify_chain_to_epoch(&st, v.vault_id(), 1, &owner_ed).unwrap();
    assert!(verified.contains(&owner_ed) && verified.contains(&bob_ed));

    // расширение: добавляем carol → новый manifest на epoch 2
    let carol = keyset();
    let carol_ed = carol.signing.verifying.to_bytes().to_vec();
    let carol_x = carol.encryption.public.to_bytes().to_vec();
    let members2 = vec![
        Member {
            ed25519_pub: owner_ed.clone(),
            role: MemberRole::Admin,
        },
        Member {
            ed25519_pub: bob_ed.clone(),
            role: MemberRole::Editor,
        },
        Member {
            ed25519_pub: carol_ed.clone(),
            role: MemberRole::Viewer,
        },
    ];
    let xkeys2 = vec![
        (owner_ed.clone(), owner_x.clone()),
        (bob_ed.clone(), bob_x.clone()),
        (carol_ed.clone(), carol_x.clone()),
    ];
    let epoch2 = v
        .establish_or_extend_membership(&owner, &members2, &xkeys2)
        .unwrap();
    assert_eq!(epoch2, 2);
    let verified2 = verify_chain_to_epoch(&st, v.vault_id(), 2, &owner_ed).unwrap();
    assert!(verified2.contains(&carol_ed));
}

#[test]
fn set_cache_policy_bumps_version_and_persists() {
    use unissh_storage::CachePolicy;
    let st = storage();
    let owner = keyset();
    let mut v = Vault::create_with_target(
        &st,
        &owner,
        new_vault_id(),
        b"cp",
        unissh_storage::SyncTarget::Cloud,
    )
    .unwrap();
    let vid = v.vault_id().to_vec();
    // дефолт — OfflineAllowed
    let rec0 = st.get_vault(&vid).unwrap().unwrap();
    assert!(matches!(rec0.cache_policy, CachePolicy::OfflineAllowed));
    v.set_cache_policy(CachePolicy::OnlineOnly).unwrap();
    let rec1 = st.get_vault(&vid).unwrap().unwrap();
    assert!(matches!(rec1.cache_policy, CachePolicy::OnlineOnly));
    assert_eq!(rec1.version, rec0.version + 1);
    // волт всё ещё открывается (переподпись валидна)
    let reopened = Vault::open(&st, &owner, &vid).unwrap();
    assert_eq!(reopened.name(), b"cp");
}

#[test]
fn account_payload_seal_open_roundtrip() {
    let ks = keyset();
    let plaintext = b"personal-vault-ptr + default username".to_vec();
    let sealed = seal_account_payload(&ks, &plaintext).unwrap();
    assert_ne!(sealed, plaintext, "payload должен быть зашифрован");
    let opened = open_account_payload(&ks, &sealed).unwrap();
    assert_eq!(opened, plaintext, "self-seal round-trip");
    // Чужой keyset НЕ открывает.
    let other = keyset();
    assert!(open_account_payload(&other, &sealed).is_err());
}
