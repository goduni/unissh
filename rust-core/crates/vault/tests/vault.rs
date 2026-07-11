//! Тесты локального волта: round-trip item через VK, изоляция, неверный keyset,
//! подпись, tombstone.

use unissh_crypto::X25519Keypair;
use unissh_keychain::{create_account, KdfParams, UnlockedKeyset};
use unissh_storage::{ItemRecord, Storage};
use unissh_vault::{Vault, VaultError};

fn keyset() -> UnlockedKeyset {
    // SecretKeyOnly режим → без Argon2id, быстро
    let (_sk, _rec, unlocked) = create_account(None, KdfParams::recommended()).unwrap();
    unlocked
}

fn storage() -> Storage {
    Storage::open_in_memory(&[7u8; 32]).unwrap()
}

#[test]
fn item_roundtrip_through_vk() {
    let st = storage();
    let ks = keyset();
    let v = Vault::create(&st, &ks, b"vault-1".to_vec(), b"My Vault").unwrap();
    assert_eq!(v.name(), b"My Vault");

    let ssh_key = b"-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END-----";
    let ver = v.put_item(b"ssh-prod", 1, ssh_key).unwrap();
    assert_eq!(ver, 1);

    let got = v.get_item(b"ssh-prod").unwrap().unwrap();
    assert_eq!(got.content.as_slice(), ssh_key);
    assert_eq!(got.item_type, 1);
    assert_eq!(got.version, 1);
}

#[test]
fn reopen_vault_and_read_item() {
    let st = storage();
    let ks = keyset();
    {
        let v = Vault::create(&st, &ks, b"v".to_vec(), b"name").unwrap();
        v.put_item(b"i", 2, b"secret-content").unwrap();
    }
    // повторное открытие тем же keyset
    let v = Vault::open(&st, &ks, b"v").unwrap();
    assert_eq!(v.name(), b"name");
    let got = v.get_item(b"i").unwrap().unwrap();
    assert_eq!(got.content.as_slice(), b"secret-content");
}

#[test]
fn wrong_keyset_cannot_open() {
    let st = storage();
    let ks = keyset();
    {
        let _v = Vault::create(&st, &ks, b"v".to_vec(), b"name").unwrap();
    }
    // другой keyset — VK не развернётся
    let other = keyset();
    let err = Vault::open(&st, &other, b"v").unwrap_err();
    assert!(matches!(err, VaultError::Decrypt));
}

#[test]
fn item_update_increments_version() {
    let st = storage();
    let ks = keyset();
    let v = Vault::create(&st, &ks, b"v".to_vec(), b"n").unwrap();
    assert_eq!(v.put_item(b"i", 1, b"v1").unwrap(), 1);
    assert_eq!(v.put_item(b"i", 1, b"v2").unwrap(), 2);
    let got = v.get_item(b"i").unwrap().unwrap();
    assert_eq!(got.version, 2);
    assert_eq!(got.content.as_slice(), b"v2");
}

#[test]
fn list_and_delete_item() {
    let st = storage();
    let ks = keyset();
    let v = Vault::create(&st, &ks, b"v".to_vec(), b"n").unwrap();
    v.put_item(b"a", 1, b"x").unwrap();
    v.put_item(b"b", 1, b"y").unwrap();
    assert_eq!(v.list_items().unwrap().len(), 2);

    v.delete_item(b"a").unwrap();
    assert_eq!(v.list_items().unwrap().len(), 1);
    assert!(v.get_item(b"a").unwrap().is_none());
    assert!(v.get_item(b"b").unwrap().is_some());
}

#[test]
fn delete_vault_tombstones() {
    let st = storage();
    let ks = keyset();
    let v = Vault::create(&st, &ks, b"v".to_vec(), b"n").unwrap();
    v.delete().unwrap();
    // больше не открывается
    assert!(matches!(
        Vault::open(&st, &ks, b"v").unwrap_err(),
        VaultError::NotFound
    ));
}

#[test]
fn vault_isolation_independent_vks() {
    let st = storage();
    let ks = keyset();
    let v1 = Vault::create(&st, &ks, b"v1".to_vec(), b"one").unwrap();
    let v2 = Vault::create(&st, &ks, b"v2".to_vec(), b"two").unwrap();
    v1.put_item(b"i", 1, b"in-v1").unwrap();

    // item из v1 не виден в v2
    assert!(v2.get_item(b"i").unwrap().is_none());
    assert_eq!(
        v1.get_item(b"i").unwrap().unwrap().content.as_slice(),
        b"in-v1"
    );
}

#[test]
fn tampered_item_fails_signature() {
    let st = storage();
    let ks = keyset();
    let v = Vault::create(&st, &ks, b"v".to_vec(), b"n").unwrap();
    v.put_item(b"i", 1, b"content").unwrap();

    // подкладываем запись с большей версией, но мусорной подписью
    let mut rec = st.get_item(b"v", b"i").unwrap().unwrap();
    rec.version = 99;
    rec.content_blob[5] ^= 0x01; // меняем шифротекст
                                 // signature осталась старой → не совпадёт
    st.put_item(&rec).unwrap();

    assert!(matches!(
        v.get_item(b"i").unwrap_err(),
        VaultError::SignatureInvalid
    ));
}

#[test]
fn manual_record_bad_signature_rejected() {
    let st = storage();
    let ks = keyset();
    let v = Vault::create(&st, &ks, b"v".to_vec(), b"n").unwrap();

    let bogus = ItemRecord {
        vault_id: b"v".to_vec(),
        item_id: b"x".to_vec(),
        item_type: 0,
        content_blob: b"not-really-encrypted".to_vec(),
        wrapped_item_key: b"junk".to_vec(),
        version: 1,
        tombstone: false,
        signature: vec![0u8; 67],
        author_pubkey: vec![0u8; 32],
        created_at: 0,
        updated_at: 0,
        // TODO(P3/P4): эпоха ключа волта при ротации VK; пока единственная (0).
        key_epoch: 0,
    };
    st.put_item(&bogus).unwrap();
    assert!(v.get_item(b"x").is_err());
}

#[test]
fn rename_item_moves_content_and_tombstones_old() {
    let st = storage();
    let ks = keyset();
    let v = Vault::create(&st, &ks, b"v".to_vec(), b"n").unwrap();
    v.put_item(b"old", 1, b"secret-content").unwrap();

    v.rename_item(b"old", b"new").unwrap();

    // старого нет, новый несёт тот же контент и тип
    assert!(v.get_item(b"old").unwrap().is_none());
    let moved = v.get_item(b"new").unwrap().unwrap();
    assert_eq!(moved.item_type, 1);
    assert_eq!(moved.content.as_slice(), b"secret-content");

    // в списке ровно один живой item
    let live = v.list_items().unwrap();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].item_id, b"new");
}

#[test]
fn rename_item_rejects_existing_target() {
    let st = storage();
    let ks = keyset();
    let v = Vault::create(&st, &ks, b"v".to_vec(), b"n").unwrap();
    v.put_item(b"a", 1, b"aa").unwrap();
    v.put_item(b"b", 1, b"bb").unwrap();
    assert!(matches!(
        v.rename_item(b"a", b"b"),
        Err(unissh_vault::VaultError::AlreadyExists)
    ));
    // переименование отсутствующего — NotFound
    assert!(matches!(
        v.rename_item(b"missing", b"z"),
        Err(unissh_vault::VaultError::NotFound)
    ));
}

#[test]
fn seal_vk_to_recipient_extension_point() {
    let st = storage();
    let ks = keyset();
    let v = Vault::create(&st, &ks, b"v".to_vec(), b"n").unwrap();

    let recipient = X25519Keypair::generate();
    let recipient_ed = [9u8; 32];
    let wrapped = v
        .seal_vk_to_recipient(&recipient.public.to_bytes(), &recipient_ed)
        .unwrap();
    assert!(!wrapped.is_empty());

    // некорректный публичный ключ — ошибка
    assert!(v.seal_vk_to_recipient(b"too-short", &recipient_ed).is_err());
}

#[test]
fn verify_chain_ok_for_valid_vault() {
    let st = storage();
    let ks = keyset();
    let v = Vault::create(&st, &ks, b"v".to_vec(), b"n").unwrap();
    v.put_item(b"a", 1, b"alpha").unwrap();
    v.put_item(b"b", 4, b"bravo").unwrap();
    v.delete_item(b"b").unwrap(); // tombstone — тоже должен пройти аудит

    let report = v.verify_chain().unwrap();
    assert!(report.ok, "issues: {:?}", report.issues);
    assert!(report.issues.is_empty());
    // vault-запись + item a + item b(tombstone) = 3
    assert!(report.checked >= 3);
}

#[test]
fn verify_chain_flags_tampered_content() {
    let st = storage();
    let ks = keyset();
    let v = Vault::create(&st, &ks, b"v".to_vec(), b"n").unwrap();
    v.put_item(b"i", 1, b"content").unwrap();

    // версия выше (проходит anti-rollback), контент изменён, подпись старая
    let mut rec = st.get_item(b"v", b"i").unwrap().unwrap();
    rec.version = 99;
    rec.content_blob[3] ^= 0x01;
    st.put_item(&rec).unwrap();

    let report = v.verify_chain().unwrap();
    assert!(!report.ok);
    assert!(report.issues.iter().any(
        |i| i.item_id == b"i" && i.failure == unissh_vault::IntegrityFailure::SignatureInvalid
    ));
}

#[test]
fn check_item_record_detects_author_mismatch() {
    // Запись, валидно подписанная ДРУГИМ владельцем, но сверяемая с нашим
    // доверенным ключом → AuthorMismatch (главный кейс: подмена author_pubkey).
    let st = storage();
    let owner = keyset();
    let attacker = keyset();
    let va = Vault::create(&st, &attacker, b"va".to_vec(), b"n").unwrap();
    va.put_item(b"x", 1, b"data").unwrap();
    let rec = st.get_item(b"va", b"x").unwrap().unwrap();

    let trusted = owner.signing.verifying.to_bytes();
    assert_eq!(
        unissh_vault::check_item_record(&rec, &trusted),
        Some(unissh_vault::IntegrityFailure::AuthorMismatch)
    );
    // тот же ключ-владелец → ок
    let attacker_trusted = attacker.signing.verifying.to_bytes();
    assert_eq!(
        unissh_vault::check_item_record(&rec, &attacker_trusted),
        None
    );
}

#[test]
fn check_item_record_detects_malformed_author() {
    let st = storage();
    let ks = keyset();
    let _v = Vault::create(&st, &ks, b"v".to_vec(), b"n").unwrap();
    let bad = ItemRecord {
        vault_id: b"v".to_vec(),
        item_id: b"x".to_vec(),
        item_type: 0,
        content_blob: vec![1, 2, 3],
        wrapped_item_key: vec![],
        version: 1,
        tombstone: false,
        signature: vec![0u8; 67],
        author_pubkey: vec![0u8; 5], // не 32 байта
        created_at: 0,
        updated_at: 0,
        // TODO(P3/P4): эпоха ключа волта при ротации VK; пока единственная (0).
        key_epoch: 0,
    };
    assert_eq!(
        unissh_vault::check_item_record(&bad, &ks.signing.verifying.to_bytes()),
        Some(unissh_vault::IntegrityFailure::Malformed)
    );
}

#[test]
fn item_history_reveal_through_vault() {
    let st = storage();
    let ks = keyset();
    let v = Vault::create(&st, &ks, b"v".to_vec(), b"n").unwrap();
    v.put_item_keep_history(b"pw", 4, b"secret1").unwrap();
    v.put_item_keep_history(b"pw", 4, b"secret2").unwrap();
    v.put_item_keep_history(b"pw", 4, b"secret3").unwrap();

    // версии: текущая 3 + архив 2,1
    let mut versions = v.list_item_versions(b"pw").unwrap();
    versions.sort();
    assert_eq!(versions, vec![1, 2, 3]);

    // reveal каждой версии (подпись проверяется, контент расшифровывается)
    assert_eq!(
        v.get_item_version(b"pw", 1)
            .unwrap()
            .unwrap()
            .content
            .as_slice(),
        b"secret1"
    );
    assert_eq!(
        v.get_item_version(b"pw", 2)
            .unwrap()
            .unwrap()
            .content
            .as_slice(),
        b"secret2"
    );
    assert_eq!(
        v.get_item_version(b"pw", 3)
            .unwrap()
            .unwrap()
            .content
            .as_slice(),
        b"secret3"
    );
    // несуществующая версия → None
    assert!(v.get_item_version(b"pw", 9).unwrap().is_none());
}

#[test]
fn delete_clears_item_history() {
    let st = storage();
    let ks = keyset();
    let v = Vault::create(&st, &ks, b"v".to_vec(), b"n").unwrap();
    v.put_item_keep_history(b"pw", 4, b"s1").unwrap();
    v.put_item_keep_history(b"pw", 4, b"s2").unwrap();
    assert!(!v.list_item_versions(b"pw").unwrap().is_empty());

    v.delete_item(b"pw").unwrap();
    // удалённый секрет: история стёрта, старый plaintext не достаётся
    assert!(v.list_item_versions(b"pw").unwrap().is_empty());
    assert!(v.get_item_version(b"pw", 1).unwrap().is_none());
}

#[test]
fn verify_chain_audits_history_records() {
    let st = storage();
    let ks = keyset();
    let v = Vault::create(&st, &ks, b"v".to_vec(), b"n").unwrap();
    v.put_item_keep_history(b"pw", 4, b"v1").unwrap();
    v.put_item_keep_history(b"pw", 4, b"v2").unwrap();
    v.put_item_keep_history(b"pw", 4, b"v3").unwrap(); // 2 архивные версии

    let report = v.verify_chain().unwrap();
    assert!(report.ok, "issues: {:?}", report.issues);
    // vault(1) + текущий pw(1) + 2 истории = минимум 4 проверенных записи
    assert!(report.checked >= 4, "checked={}", report.checked);
}
