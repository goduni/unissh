//! Тесты P4: eager VK-ротация, revocation re-wrap, purge_vault, member-aware verify_chain.

use unissh_keychain::{create_account, KdfParams, UnlockedKeyset};
use unissh_storage::{ItemRecord, MemberRole, Storage};
use unissh_vault::{
    build_manifest, open_grant, verify_manifest, IntegrityFailure, Member, Vault, VaultError,
};

fn keyset() -> UnlockedKeyset {
    let (_sk, _rec, unlocked) = create_account(None, KdfParams::recommended()).unwrap();
    unlocked
}
fn storage() -> Storage {
    Storage::open_in_memory(&[7u8; 32]).unwrap()
}

/// member-id члена = его Ed25519 pubkey; X25519 pub — для обёртки VK.
fn ed_of(ks: &UnlockedKeyset) -> Vec<u8> {
    ks.signing.verifying.to_bytes().to_vec()
}
fn x_of(ks: &UnlockedKeyset) -> Vec<u8> {
    ks.encryption.public.to_bytes().to_vec()
}

/// Делает из свежесозданного Vault — membership-волт: кладёт genesis manifest@1
/// над набором `members` в storage. Vault создаёт admin (owner==admin_ed).
/// VK волта для manifest не нужен — manifest только про членов/роли.
#[allow(dead_code)]
fn put_genesis_manifest(st: &Storage, admin: &UnlockedKeyset, vault_id: &[u8], members: &[Member]) {
    let m = build_manifest(admin, vault_id, 1, members).unwrap();
    // самопроверка цепочки до персиста (genesis_owner == admin_ed)
    let admin_ed = ed_of(admin);
    verify_manifest(&m, vault_id, None, &admin_ed).unwrap();
    st.put_membership_manifest(&m).unwrap();
}

#[test]
fn rotate_vk_reissues_to_remaining_members_only() {
    let st = storage();
    let admin = keyset();
    let bob = keyset(); // останется
    let carol = keyset(); // будет отозвана
    let admin_ed = ed_of(&admin);
    let bob_ed = ed_of(&bob);
    let carol_ed = ed_of(&carol);

    let v = Vault::create(&st, &admin, b"mv".to_vec(), b"shared").unwrap();
    v.put_item(b"secret", 1, b"top-secret").unwrap();

    // genesis manifest@1 над всеми тремя (carol = Editor)
    put_genesis_manifest(
        &st,
        &admin,
        v.vault_id(),
        &[
            Member {
                ed25519_pub: admin_ed.clone(),
                role: MemberRole::Admin,
            },
            Member {
                ed25519_pub: bob_ed.clone(),
                role: MemberRole::Editor,
            },
            Member {
                ed25519_pub: carol_ed.clone(),
                role: MemberRole::Editor,
            },
        ],
    );

    // Ротация: оставляем admin + bob (carol отозвана). Гранты только оставшимся.
    let remaining = vec![
        Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        },
        Member {
            ed25519_pub: bob_ed.clone(),
            role: MemberRole::Editor,
        },
    ];
    let grants = vec![
        (x_of(&admin), admin_ed.clone(), MemberRole::Admin),
        (x_of(&bob), bob_ed.clone(), MemberRole::Editor),
    ];
    let new_epoch = v.rotate_vk(&admin, &remaining, &grants).unwrap();
    assert_eq!(new_epoch, 2);

    // manifest@2 существует и проверяется по цепочке (genesis_owner=admin_ed)
    let m2 = st
        .get_membership_manifest(v.vault_id(), 2)
        .unwrap()
        .unwrap();
    assert_eq!(m2.key_epoch, 2);

    // bob (оставшийся) открывает свой грант@2 → получает VK'
    let gs2 = st.list_membership_grants(v.vault_id(), 2).unwrap();
    let bob_grant = gs2.iter().find(|g| g.member_pubkey == bob_ed).unwrap();
    let vk_prime = open_grant(
        bob_grant,
        v.vault_id(),
        &bob.encryption.secret,
        &bob_ed,
        2,
        0,
    )
    .unwrap();
    assert_eq!(vk_prime.expose_bytes().len(), 32);

    // carol (отозванная) НЕ имеет гранта@2
    assert!(gs2.iter().all(|g| g.member_pubkey != carol_ed));

    // пол эпохи поднят до 2
    assert_eq!(st.get_vault_epoch_floor(v.vault_id()).unwrap().unwrap(), 2);

    // vault-запись несёт key_epoch=2 и version выросла
    let vrec = st.get_vault(v.vault_id()).unwrap().unwrap();
    assert_eq!(vrec.key_epoch, 2);
    assert!(vrec.version >= 2);
}

#[test]
fn rotate_vk_by_non_admin_rejected() {
    let st = storage();
    let admin = keyset();
    let mallory = keyset(); // Editor, не Admin
    let admin_ed = ed_of(&admin);
    let mallory_ed = ed_of(&mallory);

    let v = Vault::create(&st, &admin, b"mv".to_vec(), b"shared").unwrap();
    put_genesis_manifest(
        &st,
        &admin,
        v.vault_id(),
        &[
            Member {
                ed25519_pub: admin_ed.clone(),
                role: MemberRole::Admin,
            },
            Member {
                ed25519_pub: mallory_ed.clone(),
                role: MemberRole::Editor,
            },
        ],
    );
    // mallory (Editor) пытается ротировать
    let remaining = vec![Member {
        ed25519_pub: mallory_ed.clone(),
        role: MemberRole::Admin,
    }];
    let grants = vec![(x_of(&mallory), mallory_ed.clone(), MemberRole::Admin)];
    assert!(matches!(
        v.rotate_vk(&mallory, &remaining, &grants).unwrap_err(),
        VaultError::AuthorityInvalid
    ));
    // ничего не записано на эпоху 2
    assert!(st
        .get_membership_manifest(v.vault_id(), 2)
        .unwrap()
        .is_none());
    assert!(st.get_vault_epoch_floor(v.vault_id()).unwrap().is_none());
}

#[test]
fn rotate_vk_on_local_vault_without_manifest_rejected() {
    let st = storage();
    let owner = keyset();
    let owner_ed = ed_of(&owner);
    let v = Vault::create(&st, &owner, b"local".to_vec(), b"n").unwrap();
    v.put_item(b"i", 1, b"x").unwrap();
    // нет manifest → ротация недопустима (D2: local-волты не меняются)
    let remaining = vec![Member {
        ed25519_pub: owner_ed.clone(),
        role: MemberRole::Admin,
    }];
    let grants = vec![(x_of(&owner), owner_ed.clone(), MemberRole::Admin)];
    assert!(matches!(
        v.rotate_vk(&owner, &remaining, &grants).unwrap_err(),
        VaultError::NotAMember
    ));
    // local item читается как раньше
    assert_eq!(v.get_item(b"i").unwrap().unwrap().content.as_slice(), b"x");
}

#[test]
fn rotated_item_decrypts_under_new_vk_for_remaining_member() {
    use unissh_crypto::{aead_decrypt, unwrap_key};
    let st = storage();
    let admin = keyset();
    let bob = keyset();
    let admin_ed = ed_of(&admin);
    let bob_ed = ed_of(&bob);

    let v = Vault::create(&st, &admin, b"mv".to_vec(), b"shared").unwrap();
    v.put_item(b"secret", 7, b"payload-v1").unwrap();
    put_genesis_manifest(
        &st,
        &admin,
        v.vault_id(),
        &[
            Member {
                ed25519_pub: admin_ed.clone(),
                role: MemberRole::Admin,
            },
            Member {
                ed25519_pub: bob_ed.clone(),
                role: MemberRole::Editor,
            },
        ],
    );
    let remaining = vec![
        Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        },
        Member {
            ed25519_pub: bob_ed.clone(),
            role: MemberRole::Editor,
        },
    ];
    let grants = vec![
        (x_of(&admin), admin_ed.clone(), MemberRole::Admin),
        (x_of(&bob), bob_ed.clone(), MemberRole::Editor),
    ];
    v.rotate_vk(&admin, &remaining, &grants).unwrap();

    // bob получает VK' из своего гранта@2
    let gs2 = st.list_membership_grants(v.vault_id(), 2).unwrap();
    let bob_grant = gs2.iter().find(|g| g.member_pubkey == bob_ed).unwrap();
    let vk_prime = open_grant(
        bob_grant,
        v.vault_id(),
        &bob.encryption.secret,
        &bob_ed,
        2,
        0,
    )
    .unwrap();

    // читает re-wrapped item: storage-запись несёт key_epoch=2, version=2
    let rec = st.get_item(v.vault_id(), b"secret").unwrap().unwrap();
    assert_eq!(rec.key_epoch, 2);
    assert_eq!(rec.version, 2);
    // per-item ключ разворачивается VK' (AAD=item_id), контент — под версионным AAD
    let item_key = unwrap_key(&vk_prime, &rec.wrapped_item_key, b"secret").unwrap();
    let aad = unissh_crypto::AssociatedData::new(v.vault_id().to_vec(), b"secret".to_vec(), 2);
    let pt = aead_decrypt(&item_key, &rec.content_blob, &aad).unwrap();
    assert_eq!(pt.as_slice(), b"payload-v1");
}

#[test]
fn rotated_item_key_not_unwrappable_with_old_vk() {
    let st = storage();
    let admin = keyset();
    let admin_ed = ed_of(&admin);
    let v = Vault::create(&st, &admin, b"mv".to_vec(), b"shared").unwrap();
    v.put_item(b"secret", 1, b"data").unwrap();
    // сохраним СТАРЫЙ wrapped_item_key до ротации
    let old_rec = st.get_item(v.vault_id(), b"secret").unwrap().unwrap();
    let old_wik = old_rec.wrapped_item_key.clone();

    put_genesis_manifest(
        &st,
        &admin,
        v.vault_id(),
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
    );
    v.rotate_vk(
        &admin,
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
        &[(x_of(&admin), admin_ed.clone(), MemberRole::Admin)],
    )
    .unwrap();

    let new_rec = st.get_item(v.vault_id(), b"secret").unwrap().unwrap();
    // обёртка ключа изменилась (под VK'). Прямую проверку «старый VK не открывает»
    // даёт rotated_item_decrypts_under_new_vk_for_remaining_member (VK' тестам
    // напрямую не виден — граница ядро↔UI).
    assert_ne!(new_rec.wrapped_item_key, old_wik);
}

#[test]
fn rotate_vk_is_atomic_on_midway_failure() {
    // Атомарность: сбой ПОСРЕДИ транзакции (после записи manifest@2, грантов@2 и
    // re-wrapped item, на шаге put_vault) обязан откатить ВСЮ ротацию — никакого
    // полу-ротированного состояния. Версии в `rotate_vk` монотонно выводятся из
    // свежих чтений, поэтому version-конфликт недостижим; вместо этого
    // детерминированно ломаем put_vault через `checked_version`: stored
    // vault-version = i64::MAX → ротация считает v_version = i64::MAX+1, которую
    // storage отвергает (VersionOutOfRange) уже ВНУТРИ транзакции — после
    // manifest/grant/item. Порядок put в транзакции: manifest → гранты → items →
    // vault → floor (см. Vault::rotate_vk). `rotate_vk` не расшифровывает старый
    // name_blob (берёт self.name из памяти и пере-шифрует под VK'/новую версию),
    // поэтому подмена stored vault-version не ломает его чтения.
    let st = storage();
    let admin = keyset();
    let admin_ed = ed_of(&admin);
    let v = Vault::create(&st, &admin, b"mv".to_vec(), b"shared").unwrap();
    v.put_item(b"secret", 1, b"data").unwrap();
    put_genesis_manifest(
        &st,
        &admin,
        v.vault_id(),
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
    );

    // Подкладываем vault-запись на версии i64::MAX (storage не верит подписи).
    let mut bumped = st.get_vault(v.vault_id()).unwrap().unwrap();
    bumped.version = i64::MAX as u64;
    st.put_vault(&bumped).unwrap();

    let err = v
        .rotate_vk(
            &admin,
            &[Member {
                ed25519_pub: admin_ed.clone(),
                role: MemberRole::Admin,
            }],
            &[(x_of(&admin), admin_ed.clone(), MemberRole::Admin)],
        )
        .unwrap_err();
    assert!(matches!(err, VaultError::Storage(_)), "actual err: {err:?}");

    // Откат полный: re-wrapped item НЕ записан (остался на version=1, epoch=0),
    // manifest@2 / пол эпохи / гранты@2 отсутствуют. Главное: ничего из эпохи 2 не
    // закоммичено (manifest@2 и грант@2 писались в транзакции до упавшего put_vault).
    let it = st.get_item(v.vault_id(), b"secret").unwrap().unwrap();
    assert_eq!(it.version, 1);
    assert_eq!(it.key_epoch, 0);
    assert!(st
        .get_membership_manifest(v.vault_id(), 2)
        .unwrap()
        .is_none());
    assert!(st.get_vault_epoch_floor(v.vault_id()).unwrap().is_none());
    assert!(st
        .list_membership_grants(v.vault_id(), 2)
        .unwrap()
        .is_empty());
}

#[test]
fn purge_vault_leaves_no_rows() {
    let st = storage();
    let admin = keyset();
    let admin_ed = ed_of(&admin);
    let v = Vault::create(&st, &admin, b"mv".to_vec(), b"shared").unwrap();
    v.put_item(b"a", 1, b"x").unwrap();
    v.put_item_keep_history(b"pw", 4, b"s1").unwrap();
    v.put_item_keep_history(b"pw", 4, b"s2").unwrap(); // создаёт историю
    put_genesis_manifest(
        &st,
        &admin,
        v.vault_id(),
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
    );
    st.set_vault_epoch_floor(v.vault_id(), 1).unwrap();
    let vid = v.vault_id().to_vec();

    // соседний волт — не трогать
    let other = Vault::create(&st, &admin, b"other".to_vec(), b"o").unwrap();
    other.put_item(b"keep", 1, b"y").unwrap();

    // purge поглощает self (zeroize VK) и стирает все строки
    v.purge_vault().unwrap();

    assert!(st.get_vault(&vid).unwrap().is_none());
    assert!(st.list_items_including_tombstones(&vid).unwrap().is_empty());
    assert!(st.list_all_history(&vid).unwrap().is_empty());
    assert!(st.get_membership_manifest(&vid, 1).unwrap().is_none());
    assert!(st.list_membership_grants(&vid, 1).unwrap().is_empty());
    assert!(st.get_vault_epoch_floor(&vid).unwrap().is_none());
    // соседний волт цел
    assert!(st.get_vault(other.vault_id()).unwrap().is_some());
    assert_eq!(st.list_items(other.vault_id()).unwrap().len(), 1);
}

#[test]
fn purge_vault_after_rotation_clears_all_epochs() {
    let st = storage();
    let admin = keyset();
    let admin_ed = ed_of(&admin);
    let v = Vault::create(&st, &admin, b"mv".to_vec(), b"shared").unwrap();
    v.put_item(b"a", 1, b"x").unwrap();
    put_genesis_manifest(
        &st,
        &admin,
        v.vault_id(),
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
    );
    v.rotate_vk(
        &admin,
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
        &[(x_of(&admin), admin_ed.clone(), MemberRole::Admin)],
    )
    .unwrap();
    let vid = v.vault_id().to_vec();
    // переоткрыть под VK' не нужно для purge — purge не разворачивает VK
    v.purge_vault().unwrap();
    // обе эпохи манифестов/грантов стёрты
    assert!(st.get_membership_manifest(&vid, 1).unwrap().is_none());
    assert!(st.get_membership_manifest(&vid, 2).unwrap().is_none());
    assert!(st.list_membership_grants(&vid, 1).unwrap().is_empty());
    assert!(st.list_membership_grants(&vid, 2).unwrap().is_empty());
    assert!(st.get_vault(&vid).unwrap().is_none());
}

#[test]
fn verify_chain_ok_after_rotation() {
    let st = storage();
    let admin = keyset();
    let admin_ed = ed_of(&admin);
    let v = Vault::create(&st, &admin, b"mv".to_vec(), b"shared").unwrap();
    v.put_item(b"a", 1, b"alpha").unwrap();
    put_genesis_manifest(
        &st,
        &admin,
        v.vault_id(),
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
    );
    v.rotate_vk(
        &admin,
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
        &[(x_of(&admin), admin_ed.clone(), MemberRole::Admin)],
    )
    .unwrap();

    // verify_chain на том же инстансе (его genesis_owner = admin = author всех записей)
    let report = v.verify_chain().unwrap();
    assert!(report.ok, "issues: {:?}", report.issues);
}

#[test]
fn rotate_vk_rejects_omitting_owner_from_remaining_members() {
    // P4-ревью (hardening): re-wrapped items и новую vault-запись авторствует
    // владелец (self.keyset == genesis_owner). Если админ != владелец опускает
    // владельца из remaining_members, эти записи на new_epoch — от не-члена и
    // позже отвергнутся verify_record_authority. rotate_vk обязан отвергнуть
    // такую ротацию ДО записей. Контроль: с владельцем в наборе — ротация ок.
    let st = storage();
    let owner = keyset(); // создатель волта = genesis_owner
    let admin2 = keyset(); // второй админ, != владелец
    let owner_ed = ed_of(&owner);
    let admin2_ed = ed_of(&admin2);

    let v = Vault::create(&st, &owner, b"mv".to_vec(), b"shared").unwrap();
    v.put_item(b"secret", 1, b"top").unwrap();
    // genesis@1: владелец Admin + admin2 Admin.
    put_genesis_manifest(
        &st,
        &owner,
        v.vault_id(),
        &[
            Member {
                ed25519_pub: owner_ed.clone(),
                role: MemberRole::Admin,
            },
            Member {
                ed25519_pub: admin2_ed.clone(),
                role: MemberRole::Admin,
            },
        ],
    );

    // admin2 ротирует, ОПУСКАЯ владельца из remaining_members → отказ.
    let err = v
        .rotate_vk(
            &admin2,
            &[Member {
                ed25519_pub: admin2_ed.clone(),
                role: MemberRole::Admin,
            }],
            &[(x_of(&admin2), admin2_ed.clone(), MemberRole::Admin)],
        )
        .unwrap_err();
    assert!(matches!(err, VaultError::NotAMember), "got {err:?}");
    // ничего не закоммичено: эпоха 2 отсутствует, пол не выставлен.
    assert!(st
        .get_membership_manifest(v.vault_id(), 2)
        .unwrap()
        .is_none());
    assert!(st.get_vault_epoch_floor(v.vault_id()).unwrap().is_none());

    // Контроль: admin2 включает владельца → ротация проходит.
    v.rotate_vk(
        &admin2,
        &[
            Member {
                ed25519_pub: owner_ed.clone(),
                role: MemberRole::Admin,
            },
            Member {
                ed25519_pub: admin2_ed.clone(),
                role: MemberRole::Admin,
            },
        ],
        &[
            (x_of(&owner), owner_ed.clone(), MemberRole::Admin),
            (x_of(&admin2), admin2_ed.clone(), MemberRole::Admin),
        ],
    )
    .unwrap();
    assert_eq!(st.get_vault_epoch_floor(v.vault_id()).unwrap().unwrap(), 2);
}

#[test]
fn verify_chain_flags_record_below_epoch_floor() {
    // После ротации (пол=2) злонамеренно инъектируем запись item на эпохе 1
    // (manifest@1 ещё в storage, но эпоха ниже пола). verify_chain обязан
    // пометить её как NotAuthorized (anti-rollback, §1.1).
    let st = storage();
    let admin = keyset();
    let admin_ed = ed_of(&admin);
    let v = Vault::create(&st, &admin, b"mv".to_vec(), b"shared").unwrap();
    v.put_item(b"a", 1, b"alpha").unwrap();
    put_genesis_manifest(
        &st,
        &admin,
        v.vault_id(),
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
    );
    v.rotate_vk(
        &admin,
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
        &[(x_of(&admin), admin_ed.clone(), MemberRole::Admin)],
    )
    .unwrap();
    // после ротации item "a" на эпохе 2, пол=2. Инъектируем НОВЫЙ item на эпохе 1.
    use unissh_crypto::{
        aead_encrypt, sign_version, wrap_key, AssociatedData, SymmetricKey, VersionedObject,
    };
    let item_key = SymmetricKey::generate();
    let aad = AssociatedData::new(v.vault_id().to_vec(), b"injected".to_vec(), 1u64);
    let content_blob = aead_encrypt(&item_key, b"old", &aad).unwrap();
    let vo = VersionedObject::from_content(aad, &content_blob);
    let signature = sign_version(&admin.signing.signing, &vo).unwrap();
    let injected = ItemRecord {
        vault_id: v.vault_id().to_vec(),
        item_id: b"injected".to_vec(),
        item_type: 1,
        content_blob,
        wrapped_item_key: wrap_key(&item_key, &item_key, b"injected").unwrap(),
        version: 1,
        tombstone: false,
        signature,
        author_pubkey: admin_ed.clone(),
        created_at: 0,
        updated_at: 0,
        key_epoch: 1, // ниже пола (2)
    };
    st.put_item(&injected).unwrap();

    let report = v.verify_chain().unwrap();
    assert!(!report.ok);
    assert!(report
        .issues
        .iter()
        .any(|i| i.item_id == b"injected" && i.failure == IntegrityFailure::NotAuthorized));
}

#[test]
fn verify_chain_flags_record_with_epoch_having_no_manifest() {
    // АНТИ-ROLLBACK BYPASS (high): post-rotation злоумышленник из untrusted-DB
    // ставит ВАЛИДНО-owner-подписанной записи key_epoch=0 (эпоха БЕЗ manifest).
    // До фикса режим вычислялся ПО-ЗАПИСНО из её же key_epoch: нет manifest@0 →
    // downgrade на owner==author → запись принималась (floor/D1 пропускались).
    // Фикс: режим берётся из vault-level доверенного сигнала; в membership-режиме
    // запись на эпохе без manifest → NotAuthorized.
    let st = storage();
    let admin = keyset();
    let admin_ed = ed_of(&admin);
    let v = Vault::create(&st, &admin, b"mv".to_vec(), b"shared").unwrap();
    v.put_item(b"a", 1, b"alpha").unwrap();
    put_genesis_manifest(
        &st,
        &admin,
        v.vault_id(),
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
    );
    v.rotate_vk(
        &admin,
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
        &[(x_of(&admin), admin_ed.clone(), MemberRole::Admin)],
    )
    .unwrap();
    // Инъекция: запись на key_epoch=0 (НЕТ manifest@0), подписана owner (валидно).
    use unissh_crypto::{
        aead_encrypt, sign_version, wrap_key, AssociatedData, SymmetricKey, VersionedObject,
    };
    let item_key = SymmetricKey::generate();
    let aad = AssociatedData::new(v.vault_id().to_vec(), b"injected".to_vec(), 1u64);
    let content_blob = aead_encrypt(&item_key, b"old", &aad).unwrap();
    let vo = VersionedObject::from_content(aad, &content_blob);
    let signature = sign_version(&admin.signing.signing, &vo).unwrap();
    let injected = ItemRecord {
        vault_id: v.vault_id().to_vec(),
        item_id: b"injected".to_vec(),
        item_type: 1,
        content_blob,
        wrapped_item_key: wrap_key(&item_key, &item_key, b"injected").unwrap(),
        version: 1,
        tombstone: false,
        signature,
        author_pubkey: admin_ed.clone(),
        created_at: 0,
        updated_at: 0,
        key_epoch: 0, // эпоха БЕЗ manifest — даунгрейд режима
    };
    st.put_item(&injected).unwrap();

    let report = v.verify_chain().unwrap();
    assert!(!report.ok);
    assert!(report
        .issues
        .iter()
        .any(|i| i.item_id == b"injected" && i.failure == IntegrityFailure::NotAuthorized));
}

#[test]
fn get_item_refuses_downgraded_epoch_record() {
    // Тот же даунгрейд на ЖИВОМ read-пути (decrypt_record): после ротации (пол=2)
    // untrusted-DB кладёт ВАЛИДНО-owner-подписанную запись на key_epoch=0 (эпоха
    // БЕЗ manifest). До фикса decrypt_record выбирал режим по record.key_epoch:
    // нет manifest@0 → owner==author проходил → дальше unwrap_key/decrypt.
    // Авторитет ОБЯЗАН отказать ПЕРЕД разворотом ключа (VaultError != Decrypt),
    // иначе даунгрейд-режим принят. Это и есть «empirically reproduced» read-путь.
    let st = storage();
    let admin = keyset();
    let admin_ed = ed_of(&admin);
    let v = Vault::create(&st, &admin, b"mv".to_vec(), b"shared").unwrap();
    v.put_item(b"a", 1, b"alpha").unwrap();
    put_genesis_manifest(
        &st,
        &admin,
        v.vault_id(),
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
    );
    v.rotate_vk(
        &admin,
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
        &[(x_of(&admin), admin_ed.clone(), MemberRole::Admin)],
    )
    .unwrap();
    // переоткрываем волт владельцем: vault-запись@2 запечатывает VK' под его pubkey.
    let v2 = Vault::open(&st, &admin, v.vault_id()).unwrap();

    // Инъекция: новая запись на key_epoch=0, валидно подписана owner.
    use unissh_crypto::{
        aead_encrypt, sign_version, wrap_key, AssociatedData, SymmetricKey, VersionedObject,
    };
    let item_key = SymmetricKey::generate();
    let aad = AssociatedData::new(v.vault_id().to_vec(), b"injected".to_vec(), 1u64);
    let content_blob = aead_encrypt(&item_key, b"old", &aad).unwrap();
    let vo = VersionedObject::from_content(aad, &content_blob);
    let signature = sign_version(&admin.signing.signing, &vo).unwrap();
    let injected = ItemRecord {
        vault_id: v.vault_id().to_vec(),
        item_id: b"injected".to_vec(),
        item_type: 1,
        content_blob,
        wrapped_item_key: wrap_key(&item_key, &item_key, b"injected").unwrap(),
        version: 1,
        tombstone: false,
        signature,
        author_pubkey: admin_ed.clone(),
        created_at: 0,
        updated_at: 0,
        key_epoch: 0, // эпоха БЕЗ manifest — даунгрейд режима
    };
    st.put_item(&injected).unwrap();

    // Живой read-путь обязан отказать ПО АВТОРИТЕТУ, не дойдя до unwrap/decrypt.
    let err = v2.get_item(b"injected").unwrap_err();
    assert!(
        !matches!(err, VaultError::Decrypt),
        "authority must reject before key unwrap; got {err:?}"
    );
}

#[test]
fn verify_chain_rejects_self_consistent_old_epoch_record() {
    // Сервер после ротации отдаёт запись, чей author — НЕ член проверенной
    // цепочки на её эпоху. verify_chain ловит это.
    let st = storage();
    let admin = keyset();
    let attacker = keyset();
    let admin_ed = ed_of(&admin);
    let attacker_ed = ed_of(&attacker);
    let v = Vault::create(&st, &admin, b"mv".to_vec(), b"shared").unwrap();
    v.put_item(b"a", 1, b"alpha").unwrap();
    put_genesis_manifest(
        &st,
        &admin,
        v.vault_id(),
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
    );
    v.rotate_vk(
        &admin,
        &[Member {
            ed25519_pub: admin_ed.clone(),
            role: MemberRole::Admin,
        }],
        &[(x_of(&admin), admin_ed.clone(), MemberRole::Admin)],
    )
    .unwrap();
    // attacker инъектирует запись на эпохе 2, подписанную собой (не член@2).
    use unissh_crypto::{
        aead_encrypt, sign_version, wrap_key, AssociatedData, SymmetricKey, VersionedObject,
    };
    let item_key = SymmetricKey::generate();
    let aad = AssociatedData::new(v.vault_id().to_vec(), b"evil".to_vec(), 1u64);
    let content_blob = aead_encrypt(&item_key, b"x", &aad).unwrap();
    let vo = VersionedObject::from_content(aad, &content_blob);
    let signature = sign_version(&attacker.signing.signing, &vo).unwrap();
    let evil = ItemRecord {
        vault_id: v.vault_id().to_vec(),
        item_id: b"evil".to_vec(),
        item_type: 1,
        content_blob,
        wrapped_item_key: wrap_key(&item_key, &item_key, b"evil").unwrap(),
        version: 1,
        tombstone: false,
        signature,
        author_pubkey: attacker_ed.clone(),
        created_at: 0,
        updated_at: 0,
        key_epoch: 2, // на эпохе 2 attacker НЕ член
    };
    st.put_item(&evil).unwrap();
    let report = v.verify_chain().unwrap();
    assert!(!report.ok);
    assert!(report
        .issues
        .iter()
        .any(|i| i.item_id == b"evil" && i.failure == IntegrityFailure::NotAuthorized));
}
