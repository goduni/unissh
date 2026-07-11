//! P7 — FFI-экспозиция операций Веха-2: cloud-волт, членство, ротация/purge,
//! identity/auth, cache-policy, аудит, онбординг Path A/B, синк через коллбэк.
//!
//! Жёсткое ограничение: новые методы НЕ отдают plaintext приватные
//! ключи — только публичные ключи/fingerprints/подписи/непрозрачные блобы.

use std::sync::Arc;
use unissh_ffi::{Core, FfiMemberRole};

/// base64-`tenant_id` тестового сервера, к которому привязываются cloud-волты
/// (1:1-binding). `sync_now`/`sync_push` фильтруют push по нему.
const TENANT: &str = "dGVuYW50LXRlc3Q="; // base64("tenant-test")

fn new_core(dir: &std::path::Path) -> Arc<Core> {
    Core::new(
        dir.join("inst.db").to_str().unwrap().to_string(),
        dir.join("keyset.bin").to_str().unwrap().to_string(),
    )
}

#[test]
fn create_cloud_vault_returns_uuid_hex_and_lists() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();

    let vid = core
        .create_cloud_vault("Shared".to_string(), TENANT.to_string())
        .unwrap();
    // vault_id = UUIDv4 (16 байт) в hex = 32 hex-символа
    assert_eq!(vid.len(), 32);
    assert!(hex::decode(&vid).is_ok());

    // волт виден в списке (имя расшифровано)
    let vaults = core.list_vaults().unwrap();
    assert!(vaults.iter().any(|v| v.name == "Shared"));

    // на заблокированном ядре — Locked
    core.lock();
    assert!(matches!(
        core.create_cloud_vault("X".to_string(), TENANT.to_string()),
        Err(unissh_ffi::FfiError::Locked)
    ));
}

#[test]
fn membership_add_list_fingerprint_pin() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    let vid = core
        .create_cloud_vault("Team".to_string(), TENANT.to_string())
        .unwrap();

    // фиксированные публичные ключи "члена" (32 байта каждый) — публичный материал
    let member_ed = "11".repeat(32);
    let member_x = "22".repeat(32);

    core.add_member(
        vid.clone(),
        member_ed.clone(),
        member_x.clone(),
        FfiMemberRole::Editor,
    )
    .unwrap();

    let members = core.list_members(vid.clone()).unwrap();
    // owner (Admin) + новый член (Editor)
    assert_eq!(members.len(), 2);
    assert!(members
        .iter()
        .any(|m| m.ed25519_pub_hex == member_ed && matches!(m.role, FfiMemberRole::Editor)));
    let me = members
        .iter()
        .find(|m| m.ed25519_pub_hex == member_ed)
        .unwrap();
    assert_eq!(me.fingerprint.len(), 64); // hex(SHA-256)

    // standalone fingerprint совпадает с тем, что в списке
    let fp = core.member_fingerprint(member_ed.clone()).unwrap();
    assert_eq!(fp, me.fingerprint);

    // OOB-pin: первый раз ок (TOFU), повторный с тем же ключом — ок
    core.confirm_member_pin("acct-bob".to_string(), member_ed.clone())
        .unwrap();
    core.confirm_member_pin("acct-bob".to_string(), member_ed.clone())
        .unwrap();
    // другой ключ под тем же account_id → ошибка (PinMismatch)
    assert!(core
        .confirm_member_pin("acct-bob".to_string(), "33".repeat(32))
        .is_err());
}

#[test]
fn set_personal_vault_rejects_shared_vault() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    let vid = core
        .create_cloud_vault("Team".to_string(), TENANT.to_string())
        .unwrap();
    // Solo волт (ещё нет members) → можно сделать личным.
    core.set_personal_vault(vid.clone()).unwrap();
    // Добавляем члена → волт становится shared (2 члена) → set_personal_vault
    // отказывает (иначе личные идентичности/привязки утекли бы команде, B5.3).
    core.add_member(
        vid.clone(),
        "11".repeat(32),
        "22".repeat(32),
        FfiMemberRole::Editor,
    )
    .unwrap();
    assert_eq!(core.list_members(vid.clone()).unwrap().len(), 2);
    assert!(core.set_personal_vault(vid.clone()).is_err());
}

#[test]
fn local_vault_can_be_personal() {
    // A purely-local (offline) vault is a valid personal vault — the most private
    // option (identities never leave the device). set/get must accept its arbitrary
    // UTF-8 id, not just a hex cloud id, and get must echo it in list_vaults form so
    // the UI's "is this the personal vault?" match succeeds.
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    core.create_vault("personal-local".to_string(), "Personal".to_string())
        .unwrap();
    core.set_personal_vault("personal-local".to_string())
        .unwrap();
    assert_eq!(
        core.get_personal_vault().unwrap().as_deref(),
        Some("personal-local"),
        "local personal-vault id round-trips (UTF-8, matching list_vaults)"
    );
}

#[test]
fn rotate_vk_and_purge_cloud_vault() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    let vid = core
        .create_cloud_vault("R".to_string(), TENANT.to_string())
        .unwrap();

    // владелец (Admin) + bob (Editor)
    let bob_ed = "44".repeat(32);
    let bob_x = "55".repeat(32);
    core.add_member(
        vid.clone(),
        bob_ed.clone(),
        bob_x.clone(),
        FfiMemberRole::Editor,
    )
    .unwrap();

    // ротация: оставить ТОЛЬКО владельца (отзыв bob). Владелец всегда сохраняется
    // ядром как Admin → передаём пустой список «дополнительных оставшихся».
    let new_epoch = core.rotate_vk(vid.clone(), vec![]).unwrap();
    assert!(new_epoch >= 2);

    // verify_chain ok
    let report = core.verify_chain(vid.clone()).unwrap();
    assert!(report.ok, "verify_chain должен быть ok: {report:?}");

    // bob больше не член на новой эпохе
    let members = core.list_members(vid.clone()).unwrap();
    assert!(members.iter().all(|m| m.ed25519_pub_hex != bob_ed));

    // purge → волт исчезает из списка
    core.purge_vault(vid.clone()).unwrap();
    let vaults = core.list_vaults().unwrap();
    assert!(vaults.iter().all(|v| v.name != "R"));
}

#[test]
fn identity_account_id_registration_and_server_auth() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();

    // account-id стабилен между вызовами (генерится один раз и персистится)
    let aid1 = core.account_id().unwrap();
    let aid2 = core.account_id().unwrap();
    assert_eq!(aid1, aid2);
    assert_eq!(aid1.len(), 32); // 16 байт hex

    // registration-блоб непустой
    let reg = core.build_registration().unwrap();
    assert!(!reg.is_empty());

    // server-auth подпись непустая (домен unissh-server-auth-v1)
    let sig = core
        .sign_server_challenge(
            "vault.example.com".to_string(),
            aid1.clone(),
            "device-1".to_string(),
            "key-1".to_string(),
            b"server-nonce".to_vec(),
            9999999999,
        )
        .unwrap();
    assert!(!sig.is_empty());

    // на заблокированном ядре — Locked
    core.lock();
    assert!(matches!(
        core.account_id(),
        Err(unissh_ffi::FfiError::Locked)
    ));
    assert!(matches!(
        core.build_registration(),
        Err(unissh_ffi::FfiError::Locked)
    ));
}

#[test]
fn cache_policy_get_set_and_audit() {
    use unissh_ffi::FfiCachePolicy;
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    let vid = core
        .create_cloud_vault("C".to_string(), TENANT.to_string())
        .unwrap();

    // дефолт — OfflineAllowed
    assert!(matches!(
        core.get_cache_policy(vid.clone()).unwrap(),
        FfiCachePolicy::OfflineAllowed
    ));
    core.set_cache_policy(vid.clone(), FfiCachePolicy::OnlineOnly)
        .unwrap();
    assert!(matches!(
        core.get_cache_policy(vid.clone()).unwrap(),
        FfiCachePolicy::OnlineOnly
    ));

    // аудит: append непрозрачную подписанную тройку → query видит её
    let entry = b"signed-audit-event".to_vec();
    let sig = vec![7u8; 67];
    let author = "66".repeat(32);
    core.audit_append(vid.clone(), entry.clone(), sig.clone(), author.clone())
        .unwrap();
    let entries = core.audit_query(0).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].entry_blob, entry);
    assert_eq!(entries[0].author_pubkey_hex, author);
    assert!(entries[0].seq >= 1);

    // since_seq фильтрует
    let after = core.audit_query(entries[0].seq).unwrap();
    assert!(after.is_empty());
}

#[test]
fn onboarding_path_a_unlock_from_server_blob() {
    // Устройство A: создаём аккаунт с паролем, забираем Secret Key + keyset-блоб.
    let dir_a = tempfile::tempdir().unwrap();
    let core_a = new_core(dir_a.path());
    let secret = core_a.create_account(Some("pw".to_string())).unwrap();
    core_a
        .create_vault("v".to_string(), "V".to_string())
        .unwrap();
    // keyset-блоб A = содержимое сайдкара keyset (уже зашифрован под Unlock Key).
    let keyset_blob = std::fs::read(dir_a.path().join("keyset.bin")).unwrap();

    // Устройство B: пустой инстанс, принимает keyset-блоб «с сервера» (Path A).
    let dir_b = tempfile::tempdir().unwrap();
    let core_b = new_core(dir_b.path());
    core_b
        .unlock_from_server_blob(keyset_blob.clone(), Some("pw".to_string()), secret.clone())
        .unwrap();
    assert!(core_b.is_unlocked());

    // битый keyset-блоб → типизированная ошибка, не паника
    let dir_c = tempfile::tempdir().unwrap();
    let core_c = new_core(dir_c.path());
    assert!(core_c
        .unlock_from_server_blob(vec![1, 2, 3], Some("pw".to_string()), secret.clone())
        .is_err());

    // неверный пароль → InvalidCredentials
    let dir_d = tempfile::tempdir().unwrap();
    let core_d = new_core(dir_d.path());
    assert!(matches!(
        core_d.unlock_from_server_blob(keyset_blob, Some("wrong".to_string()), secret),
        Err(unissh_ffi::FfiError::InvalidCredentials)
    ));
}

/// NEGATIVE (anti-rollback, server-tz §13.13b): `unlock_from_server_blob` обязан
/// ОТВЕРГНУТЬ устаревший keyset-блоб (generation ниже доверенного пола) ДО приёма,
/// а не только поднимать пол после. Прежняя версия принимала такой блоб.
#[test]
fn unlock_from_server_blob_rejects_stale_generation() {
    // Устройство A: аккаунт (gen 1) → захватываем СТАРЫЙ блоб → смена пароля (gen 2).
    let dir_a = tempfile::tempdir().unwrap();
    let core_a = new_core(dir_a.path());
    let secret = core_a.create_account(Some("pw1".to_string())).unwrap();
    let stale_blob = std::fs::read(dir_a.path().join("keyset.bin")).unwrap(); // gen 1
    core_a
        .change_password(
            Some("pw1".to_string()),
            Some("pw2".to_string()),
            secret.clone(),
        )
        .unwrap();
    let fresh_blob = std::fs::read(dir_a.path().join("keyset.bin")).unwrap(); // gen 2

    // Устройство B: принимает СВЕЖИЙ блоб (gen 2) — пол поднимается до 2.
    let dir_b = tempfile::tempdir().unwrap();
    let core_b = new_core(dir_b.path());
    core_b
        .unlock_from_server_blob(fresh_blob, Some("pw2".to_string()), secret.clone())
        .unwrap();
    core_b.lock();

    // Малициозный сервер подсовывает СТАРЫЙ блоб (gen 1 < пол 2) с верным старым
    // паролем — должен быть отвергнут как rollback (не InvalidCredentials).
    let err = core_b
        .unlock_from_server_blob(stale_blob, Some("pw1".to_string()), secret)
        .unwrap_err();
    assert!(
        matches!(err, unissh_ffi::FfiError::Other { .. }),
        "stale generation должен быть отвергнут (rollback), got {err:?}"
    );
    assert!(
        !core_b.is_unlocked(),
        "состояние не должно быть установлено"
    );
}

/// NEGATIVE (anti-rollback, server-tz §13.13b): после `change_password` старый
/// (понижённой generation) keyset-блоб больше не должен приниматься на этом
/// устройстве — `change_password` обязан поднять доверенный пол. Прежняя версия
/// пол не поднимала, старый блоб проходил.
#[test]
fn change_password_raises_floor_rejecting_old_blob() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    let secret = core.create_account(Some("old".to_string())).unwrap();
    // gen 1 блоб ДО смены пароля.
    let old_blob = std::fs::read(dir.path().join("keyset.bin")).unwrap();

    // Смена пароля (в разблокированном состоянии): gen → 2, пол → 2.
    core.change_password(
        Some("old".to_string()),
        Some("new".to_string()),
        secret.clone(),
    )
    .unwrap();

    // Старый блоб (gen 1 < пол 2), даже с верным старым паролем, отвергается
    // через тот же inst.db (anti-rollback пол в storage-meta).
    core.lock();
    let err = core
        .unlock_from_server_blob(old_blob, Some("old".to_string()), secret.clone())
        .unwrap_err();
    assert!(
        matches!(err, unissh_ffi::FfiError::Other { .. }),
        "старый блоб после change_password должен быть отвергнут, got {err:?}"
    );
    assert!(!core.is_unlocked());

    // А свежий блоб (gen 2) с новым паролем — открывается.
    let fresh_blob = std::fs::read(dir.path().join("keyset.bin")).unwrap();
    core.unlock_from_server_blob(fresh_blob, Some("new".to_string()), secret)
        .unwrap();
    assert!(core.is_unlocked());
}

/// NEGATIVE (anti-rollback, server-tz §13.13b): локальный `Core::unlock` обязан
/// ОТВЕРГНУТЬ устаревший keyset-сайдкар (generation ниже доверенного пола) — так
/// же, как `unlock_from_server_blob`. После смены пароля пол поднят; атакующий с
/// доступом к диску подменяет сайдкар СТАРЫМ (понижённой generation) блобом с
/// верным старым паролем — это downgrade, и обычный unlock обязан его отвергнуть.
#[test]
fn local_unlock_rejects_stale_sidecar() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    let secret = core.create_account(Some("pw1".to_string())).unwrap();
    // gen 1 блоб ДО смены пароля (захватываем для downgrade-атаки).
    let stale_blob = std::fs::read(dir.path().join("keyset.bin")).unwrap();

    // Смена пароля (в разблокированном состоянии): gen → 2, пол → 2.
    core.change_password(
        Some("pw1".to_string()),
        Some("pw2".to_string()),
        secret.clone(),
    )
    .unwrap();

    // POSITIVE: обычный unlock текущим (gen 2 ≥ пол 2) сайдкаром — открывается.
    core.lock();
    core.unlock(Some("pw2".to_string()), secret.clone())
        .unwrap();
    assert!(core.is_unlocked());

    // Атакующий подменяет сайдкар СТАРЫМ блобом (gen 1 < пол 2) и пробует unlock
    // верным старым паролем → отказ как rollback (FfiError::Other), не InvalidCredentials.
    core.lock();
    std::fs::write(dir.path().join("keyset.bin"), &stale_blob).unwrap();
    let err = core
        .unlock(Some("pw1".to_string()), secret.clone())
        .unwrap_err();
    assert!(
        matches!(err, unissh_ffi::FfiError::Other { .. }),
        "устаревший сайдкар должен быть отвергнут (rollback), got {err:?}"
    );
    assert!(
        !core.is_unlocked(),
        "состояние не должно быть установлено при отказе"
    );
}

#[test]
fn onboarding_path_b_pake_device_to_device() {
    use unissh_ffi::{OnboardInitiatorHandle, OnboardResponderHandle};

    // Устройство A (initiator): существующий разблокированный аккаунт.
    let dir_a = tempfile::tempdir().unwrap();
    let core_a = new_core(dir_a.path());
    let sk_a = core_a.create_account(Some("pw-a".to_string())).unwrap();

    let code = b"123456".to_vec(); // короткий OOB-код, показывается пользователю

    // initiator.start → хэндл + msg1 (релей responder'у)
    let init = OnboardInitiatorHandle::start(code.clone());
    let msg1 = init.msg();

    // responder.respond(code, msg1) → хэндл + msg2 (релей обратно)
    let resp = OnboardResponderHandle::respond(code.clone(), msg1).unwrap();
    let msg2 = resp.msg();

    // initiator.confirm_and_seal(msg2, sk_a) на core_a → msg3 (sealed keyset + shared SK)
    let msg3 = core_a
        .onboard_confirm_and_seal(init, msg2, sk_a.clone())
        .unwrap();

    // responder.finish_install(msg3, password) на НОВОМ устройстве B
    let dir_b = tempfile::tempdir().unwrap();
    let core_b = new_core(dir_b.path());
    let sk_b = core_b
        .onboard_finish_install(resp, msg3, Some("pw-b".to_string()))
        .unwrap();
    assert!(core_b.is_unlocked());

    // Модель A: устройство B получило ТОТ ЖЕ аккаунтный Secret Key, что и A.
    assert_eq!(
        sk_a, sk_b,
        "общий аккаунтный Secret Key на обоих устройствах"
    );
    // И записанный B на диск keyset реально открывается этим общим ключом после
    // «перезапуска» (свежий Core на тех же файлах) — иначе устройство залочилось бы.
    let core_b2 = new_core(dir_b.path());
    core_b2
        .unlock(Some("pw-b".to_string()), sk_b.clone())
        .unwrap();
    assert!(core_b2.is_unlocked());

    // неверный код → ConfirmationFailed где-то на пути confirm
    let init2 = OnboardInitiatorHandle::start(b"111111".to_vec());
    let resp2 = OnboardResponderHandle::respond(b"999999".to_vec(), init2.msg()).unwrap();
    assert!(core_a
        .onboard_confirm_and_seal(init2, resp2.msg(), sk_a.clone())
        .is_err());

    // одноразовость: повторный вызов на потреблённом хэндле — ошибка
    let init3 = OnboardInitiatorHandle::start(code.clone());
    let resp3 = OnboardResponderHandle::respond(code, init3.msg()).unwrap();
    let m2b = resp3.msg();
    let _ = core_a.onboard_confirm_and_seal(init3.clone(), m2b.clone(), sk_a.clone());
    assert!(core_a
        .onboard_confirm_and_seal(init3, m2b, sk_a.clone())
        .is_err());
}

mod sync_backend {
    use std::sync::Mutex;
    use unissh_ffi::{FfiError, FfiSyncTransport, SyncDeltaItem};
    use unissh_sync::{InMemoryTransport, SyncObject, SyncTransport};

    /// «Приложение»-сторона: foreign-реализация коллбэка поверх общего
    /// InMemoryTransport (модель сервера). Несколько устройств делят один Arc.
    pub struct AppTransport {
        pub inner: Mutex<InMemoryTransport>,
    }

    impl FfiSyncTransport for AppTransport {
        fn push_objects(&self, objects: Vec<Vec<u8>>) -> Result<Vec<u64>, FfiError> {
            let mut objs = Vec::with_capacity(objects.len());
            for b in &objects {
                objs.push(
                    SyncObject::from_bytes(b)
                        .map_err(|e| FfiError::Other { msg: e.to_string() })?,
                );
            }
            let mut t = self.inner.lock().unwrap();
            t.push_objects(&objs)
                .map_err(|e| FfiError::Other { msg: e.to_string() })
        }
        fn delta_since(&self, cursor: u64) -> Vec<SyncDeltaItem> {
            let t = self.inner.lock().unwrap();
            t.delta_since(cursor)
                .into_iter()
                .map(|(server_seq, o)| SyncDeltaItem {
                    server_seq,
                    object: o.to_bytes().unwrap(),
                })
                .collect()
        }
        fn report_version(&self) -> u64 {
            self.inner.lock().unwrap().report_version()
        }
    }
}

#[test]
fn sync_round_trip_via_callback_transport() {
    use std::sync::Mutex;
    use sync_backend::AppTransport;
    use unissh_sync::InMemoryTransport;

    // ВАЖНО: оба устройства должны быть ОДНИМ владельцем (общий keyset/Secret Key),
    // т.к. genesis_owner и VK-обёртки привязаны к keyset. Моделируем так: A создаёт
    // аккаунт, B онбордится Path A тем же keyset-блобом (как в Task 8).
    let dir_a = tempfile::tempdir().unwrap();
    let core_a = new_core(dir_a.path());
    let secret = core_a.create_account(Some("pw".to_string())).unwrap();
    let keyset_blob = std::fs::read(dir_a.path().join("keyset.bin")).unwrap();
    // Cloud-волт, привязанный к TENANT: только привязанные к синкаемому серверу
    // волты пушатся (1:1-binding). Local-волт не ушёл бы.
    core_a
        .create_cloud_vault("Synced".to_string(), TENANT.to_string())
        .unwrap();

    let dir_b = tempfile::tempdir().unwrap();
    let core_b = new_core(dir_b.path());
    core_b
        .unlock_from_server_blob(keyset_blob, Some("pw".to_string()), secret)
        .unwrap();

    // общий «сервер» за коллбэком
    let backend = Arc::new(AppTransport {
        inner: Mutex::new(InMemoryTransport::new()),
    });

    // A push
    let rep_a = core_a
        .sync_now(backend.clone(), TENANT.to_string())
        .unwrap();
    assert!(rep_a.pushed >= 1, "A должен запушить хотя бы vault-запись");

    // B pull → видит волт A
    let rep_b = core_b
        .sync_now(backend.clone(), TENANT.to_string())
        .unwrap();
    assert!(
        rep_b.applied >= 1,
        "B должен применить >=1 объект: {rep_b:?}"
    );
    let vaults_b = core_b.list_vaults().unwrap();
    assert!(vaults_b.iter().any(|v| v.name == "Synced"));

    // locked-негатив
    core_a.lock();
    assert!(matches!(
        core_a.sync_now(backend, TENANT.to_string()),
        Err(unissh_ffi::FfiError::Locked)
    ));
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn new_ffi_methods_never_return_private_key_material() {
    use unissh_ffi::{OnboardInitiatorHandle, OnboardResponderHandle};
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    // Secret Key (Emergency Kit) — единственный raw секрет, доступный тесту через
    // границу (сами keyset-секреты X25519/Ed25519 наружу не отдаются by design,
    // поэтому их 32-байтовые значения тест получить не может — это и есть гарантия
    // границы). Ни один возврат/сайдкар/relay-блоб не должен нести raw Secret Key.
    let secret_hex = core.create_account(Some("masterpw".to_string())).unwrap();
    let secret_raw = hex::decode(secret_hex.trim()).unwrap();
    // 128-бит Secret Key (SECRET_KEY_LEN=16). Сканируем именно эти raw-байты — это
    // усиление поверх ASCII-маркера 'OPENSSH PRIVATE KEY'.
    assert_eq!(secret_raw.len(), 16, "Secret Key — 16 байт (128 бит)");

    let vid = core
        .create_cloud_vault("Sec".to_string(), TENANT.to_string())
        .unwrap();
    core.add_member(
        vid.clone(),
        "11".repeat(32),
        "22".repeat(32),
        FfiMemberRole::Editor,
    )
    .unwrap();

    // Возвраты новых методов — публичный/непрозрачный материал.
    let aid = core.account_id().unwrap();
    let reg = core.build_registration().unwrap();
    let members = core.list_members(vid.clone()).unwrap();
    let fp = core.member_fingerprint("11".repeat(32)).unwrap();
    let sig = core
        .sign_server_challenge(
            "h".into(),
            aid.clone(),
            "d".into(),
            "k".into(),
            b"n".to_vec(),
            1,
        )
        .unwrap();

    // Path B: msg3 = sealed keyset (relay-блоб). Должен быть зашифрован — ни маркера
    // OpenSSH-приватника, ни raw Secret Key байт в открытом виде.
    let code = b"424242".to_vec();
    let init = OnboardInitiatorHandle::start(code.clone());
    let msg1 = init.msg();
    let resp = OnboardResponderHandle::respond(code, msg1).unwrap();
    let msg2 = resp.msg();
    let msg3 = core
        .onboard_confirm_and_seal(init, msg2, secret_hex.clone())
        .unwrap();

    // Маркер OpenSSH-приватника не встречается ни в одном возврате (вкл. msg3).
    let marker = b"OPENSSH PRIVATE KEY";
    for blob in [reg.as_slice(), sig.as_slice(), msg3.as_slice()] {
        assert!(!contains(blob, marker), "OpenSSH-маркер просочился");
        // И raw 32-байтовый секрет (Secret Key) — тоже нигде в открытом виде.
        assert!(
            !contains(blob, &secret_raw),
            "raw 32-byte secret просочился в relay/возврат"
        );
    }
    // account_id/fingerprint — детерминированные публичные строки (hex), не байты ключа.
    assert!(hex::decode(&aid).is_ok());
    assert_eq!(fp.len(), 64);
    assert!(members
        .iter()
        .all(|m| hex::decode(&m.ed25519_pub_hex).is_ok()));

    // На диске (после операций) — нет plaintext-приватника keyset/SSH и нет raw
    // Secret Key байт.
    core.lock();
    let db = std::fs::read(dir.path().join("inst.db")).unwrap();
    let keyset = std::fs::read(dir.path().join("keyset.bin")).unwrap();
    assert!(!contains(&db, marker));
    assert!(!contains(&keyset, marker));
    assert!(!contains(&db, &secret_raw), "raw Secret Key в БД на диске");
    assert!(
        !contains(&keyset, &secret_raw),
        "raw Secret Key в keyset-сайдкаре на диске"
    );
}

#[test]
fn new_methods_require_unlock() {
    use unissh_ffi::FfiError;
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    let vid = core
        .create_cloud_vault("L".to_string(), TENANT.to_string())
        .unwrap();
    core.lock();

    assert!(matches!(
        core.create_cloud_vault("x".into(), TENANT.to_string()),
        Err(FfiError::Locked)
    ));
    assert!(matches!(
        core.add_member(
            vid.clone(),
            "11".repeat(32),
            "22".repeat(32),
            FfiMemberRole::Editor
        ),
        Err(FfiError::Locked)
    ));
    assert!(matches!(
        core.list_members(vid.clone()),
        Err(FfiError::Locked)
    ));
    assert!(matches!(
        core.confirm_member_pin("a".into(), "11".repeat(32)),
        Err(FfiError::Locked)
    ));
    assert!(matches!(
        core.rotate_vk(vid.clone(), vec![]),
        Err(FfiError::Locked)
    ));
    assert!(matches!(
        core.purge_vault(vid.clone()),
        Err(FfiError::Locked)
    ));
    assert!(matches!(
        core.verify_chain(vid.clone()),
        Err(FfiError::Locked)
    ));
    assert!(matches!(core.account_id(), Err(FfiError::Locked)));
    assert!(matches!(core.build_registration(), Err(FfiError::Locked)));
    assert!(matches!(
        core.get_cache_policy(vid.clone()),
        Err(FfiError::Locked)
    ));
    assert!(matches!(core.audit_query(0), Err(FfiError::Locked)));
    assert!(matches!(
        core.sign_server_challenge(
            "h".into(),
            "a".into(),
            "d".into(),
            "k".into(),
            b"n".to_vec(),
            1
        ),
        Err(FfiError::Locked)
    ));
}

#[test]
fn new_methods_reject_bad_input_without_panic() {
    use unissh_ffi::FfiError;
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();

    // битый hex vault_id
    assert!(matches!(
        core.list_members("zz-not-hex".into()),
        Err(FfiError::Other { .. })
    ));
    // битый hex/длина pubkey
    let vid = core
        .create_cloud_vault("B".into(), TENANT.to_string())
        .unwrap();
    assert!(matches!(
        core.add_member(
            vid.clone(),
            "short".into(),
            "22".repeat(32),
            FfiMemberRole::Editor
        ),
        Err(FfiError::Other { .. })
    ));
    // member_fingerprint с битым ключом
    assert!(core.member_fingerprint("nope".into()).is_err());
    // rotate без членства (волт без manifest) → типизированная ошибка, не паника
    assert!(core.rotate_vk(vid.clone(), vec![]).is_err());
    // битый hex author в audit_append
    assert!(matches!(
        core.audit_append(vid, b"e".to_vec(), b"s".to_vec(), "zz".into()),
        Err(FfiError::Other { .. })
    ));
}

#[test]
fn e2e_cloud_membership_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(Some("pw".to_string())).unwrap();

    // 1) cloud-волт
    let vid = core
        .create_cloud_vault("Project X".to_string(), TENANT.to_string())
        .unwrap();

    // 2) добавить двух членов
    let alice_ed = "a1".repeat(32);
    let alice_x = "a2".repeat(32);
    let bob_ed = "b1".repeat(32);
    let bob_x = "b2".repeat(32);
    core.add_member(
        vid.clone(),
        alice_ed.clone(),
        alice_x.clone(),
        FfiMemberRole::Admin,
    )
    .unwrap();
    core.add_member(
        vid.clone(),
        bob_ed.clone(),
        bob_x.clone(),
        FfiMemberRole::Editor,
    )
    .unwrap();

    // 3) список: owner + alice + bob, fingerprints на месте
    let members = core.list_members(vid.clone()).unwrap();
    assert_eq!(members.len(), 3);
    assert!(members.iter().all(|m| m.fingerprint.len() == 64));

    // 4) verify_chain ok
    assert!(core.verify_chain(vid.clone()).unwrap().ok);

    // 5) ротация: оставить только alice (Admin), отозвать bob
    let new_epoch = core
        .rotate_vk(
            vid.clone(),
            vec![unissh_ffi::RemainingMember {
                ed25519_pub_hex: alice_ed.clone(),
                x25519_pub_hex: alice_x.clone(),
                role: FfiMemberRole::Admin,
            }],
        )
        .unwrap();
    assert!(new_epoch >= 2);
    assert!(core.verify_chain(vid.clone()).unwrap().ok);

    // bob отозван, alice осталась, owner остался
    let after = core.list_members(vid.clone()).unwrap();
    assert!(after.iter().all(|m| m.ed25519_pub_hex != bob_ed));
    assert!(after.iter().any(|m| m.ed25519_pub_hex == alice_ed));

    // 6) purge → волт исчез
    core.purge_vault(vid.clone()).unwrap();
    assert!(core
        .list_vaults()
        .unwrap()
        .iter()
        .all(|v| v.name != "Project X"));
    // verify_chain на удалённом → NotFound (через Vault::open)
    assert!(matches!(
        core.verify_chain(vid),
        Err(unissh_ffi::FfiError::NotFound)
    ));
}

#[test]
fn build_registration_request_matches_signature_and_payload_shape() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();

    let req = core.build_registration_request().unwrap();
    // payload = u16 len(account_id=16) || account_id(16) || x25519(32) || ed25519(32)
    assert_eq!(req.payload.len(), 2 + 16 + 32 + 32);
    assert_eq!(u16::from_be_bytes([req.payload[0], req.payload[1]]), 16);
    // Подпись = тот же блоб, что отдаёт sig-only метод (подписывается тот же
    // канонический payload) — гарантия, что payload и signature согласованы.
    let sig_only = core.build_registration().unwrap();
    assert_eq!(req.signature, sig_only);
    assert_eq!(req.signature.len(), 67); // header(3) + ed25519 sig(64)

    // на заблокированном ядре — Locked
    core.lock();
    assert!(matches!(
        core.build_registration_request(),
        Err(unissh_ffi::FfiError::Locked)
    ));
}

#[test]
fn sign_server_challenge_raw_matches_string_variant_and_accepts_non_utf8() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();

    // Для UTF-8-safe значений raw-вариант обязан давать ту же (детерминированную
    // Ed25519) подпись, что и строковый — он лишь снимает требование UTF-8 на id.
    let s = core
        .sign_server_challenge(
            "h".to_string(),
            "a".to_string(),
            "d".to_string(),
            "k".to_string(),
            b"n".to_vec(),
            1,
        )
        .unwrap();
    let r = core
        .sign_server_challenge_raw(
            b"h".to_vec(),
            b"a".to_vec(),
            b"d".to_vec(),
            b"k".to_vec(),
            b"n".to_vec(),
            1,
        )
        .unwrap();
    assert_eq!(s, r);
    assert_eq!(r.len(), 67);

    // raw-вариант принимает НЕ-UTF8 идентификаторы (случайные 16 байт сервера).
    let non_utf8 = vec![0u8, 159, 146, 150]; // невалидный UTF-8
    let sig = core
        .sign_server_challenge_raw(
            non_utf8.clone(),
            non_utf8.clone(),
            non_utf8.clone(),
            b"k".to_vec(),
            b"nonce".to_vec(),
            42,
        )
        .unwrap();
    assert_eq!(sig.len(), 67);
}

#[test]
fn vault_info_exposes_sync_target_and_tenant() {
    use unissh_ffi::FfiSyncTarget;
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();

    core.create_vault("local-1".to_string(), "Local".to_string())
        .unwrap();
    let cloud_hex = core
        .create_cloud_vault("Cloud".to_string(), TENANT.to_string())
        .unwrap();

    let vaults = core.list_vaults().unwrap();
    let local = vaults.iter().find(|v| v.name == "Local").unwrap();
    let cloud = vaults.iter().find(|v| v.name == "Cloud").unwrap();
    assert_eq!(local.sync_target, FfiSyncTarget::Local);
    assert_eq!(cloud.sync_target, FfiSyncTarget::Cloud);
    assert_eq!(cloud.vault_id, cloud_hex);
    // 1:1-binding: local-волт не привязан; cloud-волт привязан к TENANT (UI
    // показывает связанный сервер).
    assert_eq!(local.sync_tenant, None);
    assert_eq!(cloud.sync_tenant, Some(TENANT.to_string()));
}

#[test]
fn create_cloud_vault_requires_active_server() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    // Пустой tenant (нет активного сервера) → отказ с понятной ошибкой.
    assert!(matches!(
        core.create_cloud_vault("X".to_string(), String::new()),
        Err(unissh_ffi::FfiError::Other { .. })
    ));
}

#[test]
fn bind_unbound_cloud_vaults_binds_legacy_and_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();

    // Симулируем legacy: cloud-волт «без сервера» — создаём с одним tenant, затем
    // имитируем пустую привязку нельзя напрямую через ffi, поэтому проверяем штатно:
    // волт создан под TENANT → bind на ДРУГОЙ tenant ничего не меняет (уже привязан).
    core.create_cloud_vault("Legacy".to_string(), TENANT.to_string())
        .unwrap();
    let other = "b3RoZXItdGVuYW50"; // base64("other-tenant")
                                    // Уже привязанный волт не перепривязывается → 0 затронуто.
    assert_eq!(
        core.bind_unbound_cloud_vaults(other.to_string()).unwrap(),
        0
    );
    let v = core
        .list_vaults()
        .unwrap()
        .into_iter()
        .find(|v| v.name == "Legacy")
        .unwrap();
    assert_eq!(v.sync_tenant, Some(TENANT.to_string()));

    // Пустой tenant отвергается.
    assert!(core.bind_unbound_cloud_vaults(String::new()).is_err());
}

#[test]
fn sync_push_skips_vault_bound_to_other_tenant() {
    use std::sync::Mutex;
    use sync_backend::AppTransport;
    use unissh_sync::InMemoryTransport;

    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    // Волт привязан к TENANT.
    core.create_cloud_vault("Bound".to_string(), TENANT.to_string())
        .unwrap();

    // Синк с ДРУГИМ tenant: волт не пушится (привязан к другому серверу).
    let backend = Arc::new(AppTransport {
        inner: Mutex::new(InMemoryTransport::new()),
    });
    let other = "b3RoZXItdGVuYW50"; // base64("other-tenant")
    let rep = core.sync_now(backend, other.to_string()).unwrap();
    assert_eq!(
        rep.pushed, 0,
        "vault bound to TENANT must NOT push to other tenant"
    );
}

#[test]
fn cloud_vault_can_hold_items() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    let vid = core
        .create_cloud_vault("Cloud".to_string(), TENANT.to_string())
        .unwrap();
    // Put a secret in the CLOUD vault (id is hex) and read it back.
    core.save_password(vid.clone(), "p1".to_string(), "secret".to_string())
        .unwrap();
    let got = core.get_password(vid.clone(), "p1".to_string()).unwrap();
    assert_eq!(got, "secret");
    let items = core.list_items(vid).unwrap();
    assert_eq!(items.len(), 1);
}

#[test]
fn cloud_vault_rename_reflects_in_list() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path());
    core.create_account(None).unwrap();
    let vid = core
        .create_cloud_vault("Old".to_string(), TENANT.to_string())
        .unwrap();
    core.rename_vault(vid.clone(), "New".to_string()).unwrap();
    // list_vaults reads the name cache by the RAW id — the rename must show.
    let vaults = core.list_vaults().unwrap();
    let v = vaults.iter().find(|v| v.vault_id == vid).unwrap();
    assert_eq!(v.name, "New");
}
