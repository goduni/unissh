//! P3 tests: membership, grants, access verification, member-pubkey pinning.

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
    assert_ne!(a, b, "two generations differ");
    // version 4: high nibble of byte 6 == 0x4
    assert_eq!(a[6] >> 4, 0x4);
    // RFC 4122 variant: the two high bits of byte 8 == 0b10
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
    // genesis (epoch 1) is signed by the creator (who is also admin in the set)
    let m = build_manifest(&creator, &vid, 1, &members).unwrap();
    // verify against genesis-owner = the creator's pubkey
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
    // corrupt the signature
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
    // the attacker signs genesis, making themselves admin
    let members = vec![Member {
        ed25519_pub: attacker_ed,
        role: MemberRole::Admin,
    }];
    let m = build_manifest(&attacker, &vid, 1, &members).unwrap();
    // verify against the correct genesis-owner (the creator) → authority denied
    assert!(matches!(
        verify_manifest(&m, &vid, None, &creator_ed).unwrap_err(),
        VaultError::AuthorityInvalid
    ));
}

#[test]
fn next_epoch_manifest_signed_by_prior_admin_verifies() {
    let creator = keyset(); // admin@epoch1
    let bob = keyset(); // will also become admin@epoch1
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
    // epoch 2 is signed by bob (admin in epoch1) — authority ok
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
    // epoch2 is signed by viewer (not admin@epoch1) → rejected
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
    // epoch 3 on top of epoch1 (skipping 2) → monotonicity violated
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
    // recipient
    let recipient = X25519Keypair::generate();
    let recip_x = recipient.public.to_bytes().to_vec();
    let member_ed = Ed25519Keypair::generate().verifying.to_bytes().to_vec();
    let vk = unissh_crypto::SymmetricKey::generate();

    // The recipient must be a member of the set (a new verify_grant invariant)
    // with a role matching the grant's role.
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
    // opening with epoch 2 → the info doesn't match
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
    // grant is signed by editor (not admin) → verify_grant denies authority
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

// Helper: put a verified manifest into storage (as add_member would).
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
    // genesis_owner = admin (creator). author_ed is a member@1, floor=0.
    unissh_vault::verify_record_authority(&st, &vid, &author_ed, 1, &admin_ed).unwrap();
}

#[test]
fn authority_rejects_viewer_authoring_content() {
    // RBAC write-integrity: a Viewer (read-only) IS listed as a member but is not
    // allowed to author item/vault records. verify_record_authority must deny it
    // (otherwise a read-only member could create/overwrite/tombstone records, and
    // other members' verify-before-apply would accept them as authentic).
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
    // Viewer is a member@1 but not a writer → AuthorityInvalid.
    assert!(matches!(
        unissh_vault::verify_record_authority(&st, &vid, &viewer_ed, 1, &admin_ed).unwrap_err(),
        VaultError::AuthorityInvalid
    ));
    // Admin from the same set writes fine (control).
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
    // epoch floor = 5; a record at epoch 1 (< floor) → rollback
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
    // no manifest → genesis_owner acts as the trusted owner
    unissh_vault::verify_record_authority(&st, &vid, &owner_ed, 0, &owner_ed).unwrap();
    assert!(matches!(
        unissh_vault::verify_record_authority(&st, &vid, &other, 0, &owner_ed).unwrap_err(),
        VaultError::NotAMember
    ));
}

#[test]
fn authority_rejects_epoch_without_manifest_in_membership_mode() {
    // ANTI-ROLLBACK BYPASS (high): the vault is IN membership mode (manifest@1 +
    // floor present), but a record presents key_epoch=0 (an epoch WITHOUT a
    // manifest). The mode must NOT be computed per-record: a downgrade to
    // owner==author is forbidden. Even a valid owner-author at an epoch without a
    // manifest, in membership mode → rejected.
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
    // vault-level signal of membership mode: the epoch floor is set.
    st.set_vault_epoch_floor(&vid, 1).unwrap();
    // admin is genesis_owner AND a member@1, BUT presents key_epoch=0 (no manifest).
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
    // TOFU: pinned on the first encounter
    pin_and_verify_member(&st, &acct, &ed).unwrap();
    // second time — matches the pin → ok
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
    // a different key under the same account → mismatch (NOT overwritten)
    assert!(matches!(
        pin_and_verify_member(&st, &acct, &imposter).unwrap_err(),
        VaultError::PinMismatch
    ));
    // the pin is unchanged
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
    // TOFU: pinned on the first encounter
    pin_and_verify_vault_anchor(&st, &vid, &creator).unwrap();
    // second time with the same creator-pubkey → ok (idempotent)
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
    // the server tries to re-bind vault→owner to a different key → PinMismatch, no overwrite
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
    // recipient (new member)
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

    // manifest and grant in storage
    let m = st.get_membership_manifest(&vid, 1).unwrap().unwrap();
    assert_eq!(m.key_epoch, 1);
    let gs = st.list_membership_grants(&vid, 1).unwrap();
    assert_eq!(gs.len(), 1);
    // the recipient opens their grant → VK
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
    // the attacker tries to issue genesis, making themselves admin, but genesis_owner=creator
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
    // nothing written
    assert!(st.get_membership_manifest(&vid, 1).unwrap().is_none());
}

#[test]
fn local_vault_flow_unchanged_with_no_manifest() {
    // D2: a vault with no manifest behaves as before (owner==author).
    let st = storage();
    let ks = keyset();
    let v = Vault::create(&st, &ks, b"local-v".to_vec(), b"name").unwrap();
    v.put_item(b"i", 1, b"secret").unwrap();
    let got = v.get_item(b"i").unwrap().unwrap();
    assert_eq!(got.content.as_slice(), b"secret");
    let report = v.verify_chain().unwrap();
    assert!(report.ok);
}

// --- P3-review regression: read-path authority is SELF-SUFFICIENT (D1 from genesis) ---

#[test]
fn authority_rejects_self_consistent_injected_manifest_at_later_epoch() {
    // Threat (untrusted-DB / sync-ready): the operator injects into storage a
    // self-consistent epoch-2 manifest (author=attacker, members=[attacker]),
    // NOT via add_member (i.e. without a D1 chain from genesis). Before the fix the
    // read path trusted storage and accepted it. Now verify_record_authority must
    // re-verify the chain from genesis_owner and reject it.
    let st = storage();
    let creator = keyset();
    let attacker = keyset();
    let vid = new_vault_id();
    let creator_ed = creator.signing.verifying.to_bytes().to_vec();
    let attacker_ed = attacker.signing.verifying.to_bytes().to_vec();

    // Legitimate genesis (epoch 1): creator-admin only.
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

    // Injection: a self-consistent epoch-2 manifest signed by attacker, making
    // attacker an admin member. The signature is valid UNDER attacker, but no chain
    // from genesis (creator) leads to it.
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

    // An attacker record at epoch 2 must be rejected (no authority from genesis).
    assert!(matches!(
        unissh_vault::verify_record_authority(&st, &vid, &attacker_ed, 2, &creator_ed).unwrap_err(),
        VaultError::AuthorityInvalid
    ));
}

#[test]
fn authority_accepts_legitimately_chained_later_epoch() {
    // Control for the previous test: if epoch 2 is LEGITIMATELY chained to genesis
    // (signed by an admin from epoch 1), a record from its member is accepted.
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
    // epoch 2 is signed by bob (admin@1) — a legitimate chain.
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
    // Chain with a hole: genesis (epoch1) and an epoch-3 manifest exist, but epoch 2
    // is missing from storage. Re-verifying the chain is impossible → rejected
    // (the author's authority at epoch 3 cannot be proven).
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
    // self-consistent epoch-3 manifest (with no epoch 2 in storage).
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
    // The genesis in storage is swapped for one signed by attacker (anti-anchor):
    // even the single-epoch read path must check genesis against the pinned
    // genesis_owner rather than trust storage.
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

    // genesis_owner is pinned = creator; the injected genesis is signed by attacker.
    assert!(matches!(
        unissh_vault::verify_record_authority(&st, &vid, &attacker_ed, 1, &creator_ed).unwrap_err(),
        VaultError::AuthorityInvalid
    ));
}

// --- P3-review regression: verify_grant checks the recipient's membership/role ---

#[test]
fn grant_to_non_member_rejected() {
    // Defense-in-depth: an admin must not be able to hand a VK wrap to a key that
    // is not in the manifest (otherwise a non-member receives a VK envelope).
    let admin = keyset();
    let vid = new_vault_id();
    let admin_ed = admin.signing.verifying.to_bytes().to_vec();
    let recipient = X25519Keypair::generate();
    let recip_x = recipient.public.to_bytes().to_vec();
    // member_ed is NOT in the manifest.
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
    // The role in the grant must match the recipient's role in the manifest.
    let admin = keyset();
    let vid = new_vault_id();
    let admin_ed = admin.signing.verifying.to_bytes().to_vec();
    let recipient = X25519Keypair::generate();
    let recip_x = recipient.public.to_bytes().to_vec();
    let member_ed = Ed25519Keypair::generate().verifying.to_bytes().to_vec();
    let vk = unissh_crypto::SymmetricKey::generate();

    // member is listed as Viewer in the manifest.
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

    // the grant is issued with role Editor (≠ Viewer) → consistency rejected.
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
    // Control: a grant to a member with a matching role passes (don't regress
    // the legitimate path).
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

// --- P7: Vault::establish_or_extend_membership (the VK stays in the core) ---

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

    // the chain up to epoch 1 verifies, both members are present
    let verified = verify_chain_to_epoch(&st, v.vault_id(), 1, &owner_ed).unwrap();
    assert!(verified.contains(&owner_ed) && verified.contains(&bob_ed));

    // extension: add carol → a new manifest at epoch 2
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
    // default — OfflineAllowed
    let rec0 = st.get_vault(&vid).unwrap().unwrap();
    assert!(matches!(rec0.cache_policy, CachePolicy::OfflineAllowed));
    v.set_cache_policy(CachePolicy::OnlineOnly).unwrap();
    let rec1 = st.get_vault(&vid).unwrap().unwrap();
    assert!(matches!(rec1.cache_policy, CachePolicy::OnlineOnly));
    assert_eq!(rec1.version, rec0.version + 1);
    // the vault still opens (re-signing is valid)
    let reopened = Vault::open(&st, &owner, &vid).unwrap();
    assert_eq!(reopened.name(), b"cp");
}

#[test]
fn account_payload_seal_open_roundtrip() {
    let ks = keyset();
    let plaintext = b"personal-vault-ptr + default username".to_vec();
    let sealed = seal_account_payload(&ks, &plaintext).unwrap();
    assert_ne!(sealed, plaintext, "payload must be encrypted");
    let opened = open_account_payload(&ks, &sealed).unwrap();
    assert_eq!(opened, plaintext, "self-seal round-trip");
    // A foreign keyset does NOT open it.
    let other = keyset();
    assert!(open_account_payload(&other, &sealed).is_err());
}

// --- P4 member-decrypt: a distinct-account member reads a shared vault via open_grant ---

/// A distinct-account member opens a teammate's shared VAULT through the same
/// `Vault::open` the FFI read surface uses, and decrypts a real item via their own
/// membership grant (owner-wrap is bound to the owner, so the member MUST go through
/// `open_grant`). This is the read path that unblocks `get_password`/`get_note`.
#[test]
fn member_opens_shared_vault_and_decrypts_item() {
    let st = storage();
    let owner = keyset();
    let member_kc = keyset(); // a DISTINCT account (own keyset)
    let owner_ed = owner.signing.verifying.to_bytes().to_vec();
    let member_ed = member_kc.signing.verifying.to_bytes().to_vec();
    let member_x = member_kc.encryption.public.to_bytes().to_vec();

    // Owner creates the vault, establishes membership (owner Admin + member Editor; the
    // grant wraps the VK under the member's X25519 key), and stores a secret AFTER
    // membership so the item is stamped at the epoch the grant unlocks.
    let v = Vault::create(&st, &owner, new_vault_id(), b"Shared").unwrap();
    let vid = v.vault_id().to_vec();
    let members = vec![
        Member {
            ed25519_pub: owner_ed.clone(),
            role: MemberRole::Admin,
        },
        Member {
            ed25519_pub: member_ed.clone(),
            role: MemberRole::Editor,
        },
    ];
    let x_by_ed = vec![(member_ed.clone(), member_x.clone())];
    v.establish_or_extend_membership(&owner, &members, &x_by_ed)
        .unwrap();
    v.put_item(b"db-pw", 1, b"s3cr3t").unwrap();

    // The member pins the owner as the vault's genesis anchor (TOFU share-accept), then
    // opens the vault WITH THEIR OWN KEYSET and reads the item byte-for-byte.
    pin_and_verify_vault_anchor(&st, &vid, &owner_ed).unwrap();
    let vm = Vault::open(&st, &member_kc, &vid).unwrap();
    assert_eq!(vm.name(), b"Shared");
    let got = vm.get_item(b"db-pw").unwrap().unwrap();
    assert_eq!(got.content.as_slice(), b"s3cr3t");
}

/// After a VK rotation that REVOKES the member (no grant at the latest epoch), the
/// member can no longer open the vault — and it fails cleanly (a typed error, no panic).
#[test]
fn revoked_member_cannot_open_after_rotation() {
    let st = storage();
    let owner = keyset();
    let member_kc = keyset();
    let owner_ed = owner.signing.verifying.to_bytes().to_vec();
    let member_ed = member_kc.signing.verifying.to_bytes().to_vec();
    let member_x = member_kc.encryption.public.to_bytes().to_vec();

    let v = Vault::create(&st, &owner, new_vault_id(), b"Shared").unwrap();
    let vid = v.vault_id().to_vec();
    let members = vec![
        Member {
            ed25519_pub: owner_ed.clone(),
            role: MemberRole::Admin,
        },
        Member {
            ed25519_pub: member_ed.clone(),
            role: MemberRole::Editor,
        },
    ];
    let x_by_ed = vec![(member_ed.clone(), member_x.clone())];
    v.establish_or_extend_membership(&owner, &members, &x_by_ed)
        .unwrap();
    v.put_item(b"db-pw", 1, b"s3cr3t").unwrap();
    pin_and_verify_vault_anchor(&st, &vid, &owner_ed).unwrap();

    // Sanity: before revocation the member CAN open.
    assert!(Vault::open(&st, &member_kc, &vid).is_ok());

    // Owner rotates the VK, keeping ONLY themselves (member revoked → no grant@latest).
    let remaining = vec![Member {
        ed25519_pub: owner_ed.clone(),
        role: MemberRole::Admin,
    }];
    v.rotate_vk(&owner, &remaining, &[]).unwrap();

    // The revoked member cannot open: no grant at the latest epoch → a typed error, not a panic.
    let err = Vault::open(&st, &member_kc, &vid).unwrap_err();
    assert!(
        matches!(err, VaultError::NotAMember),
        "revoked member open must fail cleanly, got {err:?}"
    );
}

/// Enabling member-open makes the owner-only whole-record re-seal methods reachable by a
/// member. They MUST stay owner-only: a member running `set_name`/`delete` would re-seal
/// the owner-bound `wrapped_vk` under its own keyset and lock the true owner out. Each is
/// refused with `AuthorityInvalid`; the genuine owner can still perform them.
#[test]
fn member_cannot_rewrite_owner_record() {
    let st = storage();
    let owner = keyset();
    let member_kc = keyset();
    let owner_ed = owner.signing.verifying.to_bytes().to_vec();
    let member_ed = member_kc.signing.verifying.to_bytes().to_vec();
    let member_x = member_kc.encryption.public.to_bytes().to_vec();

    let v = Vault::create(&st, &owner, new_vault_id(), b"Shared").unwrap();
    let vid = v.vault_id().to_vec();
    let members = vec![
        Member {
            ed25519_pub: owner_ed.clone(),
            role: MemberRole::Admin,
        },
        Member {
            ed25519_pub: member_ed.clone(),
            role: MemberRole::Editor,
        },
    ];
    let x_by_ed = vec![(member_ed.clone(), member_x.clone())];
    v.establish_or_extend_membership(&owner, &members, &x_by_ed)
        .unwrap();
    pin_and_verify_vault_anchor(&st, &vid, &owner_ed).unwrap();

    // The member opens via its grant, but whole-record re-seal ops are refused (they would
    // re-seal the owner-wrap under the member → owner lockout).
    let mut vm = Vault::open(&st, &member_kc, &vid).unwrap();
    assert!(matches!(
        vm.set_name(b"Hijacked"),
        Err(VaultError::AuthorityInvalid)
    ));
    assert!(matches!(
        Vault::open(&st, &member_kc, &vid).unwrap().delete(),
        Err(VaultError::AuthorityInvalid)
    ));

    // The genuine owner can still rename and re-open their own vault.
    let mut vo = Vault::open(&st, &owner, &vid).unwrap();
    vo.set_name(b"Renamed").unwrap();
    assert_eq!(Vault::open(&st, &owner, &vid).unwrap().name(), b"Renamed");
}
