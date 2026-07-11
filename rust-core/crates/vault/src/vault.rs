//! Local vault: Vault Key, per-item keys, item encryption/signing.
//!
//! Hierarchy (spec 5.1–5.3): a vault has its own random **VK** (256 bits). The VK is
//! wrapped under the owner's X25519 public key (HPKE) — this is also the sharing
//! format. Item content is encrypted with a **per-item key**, wrapped by the VK (not
//! by the VK itself) → granular revocation. Every item/vault record is signed with
//! the author's Ed25519 with a monotonic version and bound via associated data
//! `vault_id+item_id+version`.

use core::cell::Cell;

use zeroize::Zeroizing;

use unissh_crypto::{
    aead_decrypt, aead_decrypt_pre_agility, aead_encrypt, open_key_with_secret, seal_key_to_public,
    sign_version, unwrap_key, unwrap_key_pre_agility, verify_version, vk_wrap_info, wrap_key,
    AssociatedData, Ed25519VerifyingKey, SymmetricKey, VersionedObject, X25519PublicKey,
};
use unissh_keychain::UnlockedKeyset;
use unissh_storage::{CachePolicy, ItemRecord, MemberRole, Storage, SyncTarget, VaultRecord};

use crate::error::VaultError;
use crate::membership::{
    add_member, build_grant, build_manifest, verify_chain_to_epoch, verify_grant, verify_manifest,
    Member,
};

/// How many past versions of a secret to keep in history (per-item retention).
const HISTORY_RETAIN: usize = 20;

/// An opened local vault. The VK is held in memory (zeroized on Drop).
///
/// Borrows `Storage` and the unpacked `UnlockedKeyset` for the duration of use.
pub struct Vault<'a> {
    storage: &'a Storage,
    keyset: &'a UnlockedKeyset,
    vault_id: Vec<u8>,
    name: Zeroizing<Vec<u8>>,
    vk: SymmetricKey,
    version: u64,
    /// The current vault key epoch that stamps all records (`put_item`,
    /// `put_item_keep_history`, tombstone). Genesis (`create`) = 0; `open` reads
    /// it from the vault record; `establish_or_extend_membership`/`rotate_vk` raise
    /// it (interior mutability — the methods take `&self`). Writing `0` in
    /// membership mode is not allowed: `verify_record_authority` looks up manifest@epoch
    /// and requires epoch >= floor, otherwise the record is forever unreadable (`EpochInvalid`).
    key_epoch: Cell<u64>,
}

impl core::fmt::Debug for Vault<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Vault")
            .field("vault_id", &self.vault_id)
            .field("version", &self.version)
            .field("key_epoch", &self.key_epoch.get())
            .field("vk", &"<redacted>")
            .finish()
    }
}

/// A decrypted item (content in memory, zeroized on Drop).
#[derive(Clone)]
pub struct DecryptedItem {
    /// The item identifier.
    pub item_id: Vec<u8>,
    /// The item type (open metadata).
    pub item_type: u32,
    /// The item version.
    pub version: u64,
    /// The decrypted content.
    pub content: Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for DecryptedItem {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DecryptedItem")
            .field("item_id", &self.item_id)
            .field("item_type", &self.item_type)
            .field("version", &self.version)
            .field("content", &"<redacted>")
            .finish()
    }
}

/// Item metadata without decrypting the content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemMeta {
    /// The item identifier.
    pub item_id: Vec<u8>,
    /// The item type.
    pub item_type: u32,
    /// The item version.
    pub version: u64,
    /// When created (unix seconds, open storage metadata).
    pub created_at: i64,
    /// When last modified (unix seconds).
    pub updated_at: i64,
}

impl<'a> Vault<'a> {
    /// Creates a new local vault and persists its record.
    ///
    /// `vault_id` is passed by the caller. For cloud vaults the recommended source
    /// is [`crate::new_vault_id`] (UUIDv4); local vaults may use any
    /// unique bytes.
    pub fn create(
        storage: &'a Storage,
        keyset: &'a UnlockedKeyset,
        vault_id: impl Into<Vec<u8>>,
        name: &[u8],
    ) -> Result<Self, VaultError> {
        Self::create_with_target(storage, keyset, vault_id, name, SyncTarget::Local)
    }

    /// Creates a vault with an explicit `sync_target` (`Cloud` — for server sync,
    /// server-tz §4.2). The VK is generated and wrapped under the owner as in `create`;
    /// `cache_policy` defaults to `OfflineAllowed` (changed by `set_cache_policy`).
    pub fn create_with_target(
        storage: &'a Storage,
        keyset: &'a UnlockedKeyset,
        vault_id: impl Into<Vec<u8>>,
        name: &[u8],
        sync_target: SyncTarget,
    ) -> Result<Self, VaultError> {
        let vault_id = vault_id.into();
        let vk = SymmetricKey::generate();
        let version = 1u64;

        let name_blob = aead_encrypt(&vk, name, &name_aad(&vault_id, version))?;
        // The owner VK wrapping is bound to (vault_id, owner_ed, key_epoch) — like
        // member grants (D3): a stale wrapping epoch is rejected at the HPKE layer
        // regardless of the epoch floor. Genesis: key_epoch=0.
        let owner_ed = keyset.signing.verifying.to_bytes();
        let wrapped_vk = seal_key_to_public(
            &keyset.encryption.public,
            &vk,
            &vk_wrap_info(&vault_id, &owner_ed, 0)?,
        )?;

        // key_epoch=0 (genesis): membership starts at epoch 1 (establish/rotate).
        // sync_tenant is empty: the server binding is set by the calling layer
        // (ffi::create_cloud_vault) after creation — genesis does not know the tenant.
        let record = build_vault_record_epoch(
            keyset,
            &vault_id,
            &name_blob,
            &wrapped_vk,
            version,
            false,
            0,
            sync_target,
            CachePolicy::OfflineAllowed,
            Vec::new(),
        )?;
        storage.put_vault(&record)?;
        storage.mark_vault_dirty(&vault_id)?; // local create → needs push

        Ok(Vault {
            storage,
            keyset,
            vault_id,
            name: Zeroizing::new(name.to_vec()),
            vk,
            version,
            // Genesis: the vault is created outside membership mode, epoch 0 (as in
            // build_vault_record_epoch above). Raised on the first
            // establish_or_extend_membership/rotate_vk.
            key_epoch: Cell::new(0),
        })
    }

    /// Открывает существующий локальный волт: разворачивает VK, проверяет подпись.
    pub fn open(
        storage: &'a Storage,
        keyset: &'a UnlockedKeyset,
        vault_id: &[u8],
    ) -> Result<Self, VaultError> {
        let record = storage.get_vault(vault_id)?.ok_or(VaultError::NotFound)?;
        if record.tombstone {
            return Err(VaultError::NotFound);
        }
        verify_vault_record(&record)?;

        // Owner-обёртка привязана к (vault_id, owner_ed, key_epoch записи); тот же
        // info, что при seal. Открывает только владелец (члены идут через open_grant).
        let owner_ed = keyset.signing.verifying.to_bytes();
        // read-fallback: текущая привязка info, при провале — pre-round-2 (сырой
        // vault_id). Открывает только владелец (члены идут через open_grant).
        let vk = open_owner_vk(
            &keyset.encryption.secret,
            &record.wrapped_vk,
            &record.vault_id,
            &owner_ed,
            record.key_epoch,
        )?;
        let name = aead_decrypt_compat(
            &vk,
            &record.name_blob,
            &name_aad(&record.vault_id, record.version),
        )?;

        // Эпоха для штамповки новых записей: эпоха vault-записи, но в
        // membership-режиме — не ниже текущей (latest manifest), чтобы свежий
        // put_item не писался на устаревшую эпоху ниже пола (→ EpochInvalid).
        // record.key_epoch ре-якорится establish/rotate, но узлы синка могли
        // получить более новый manifest, чем переподписанную vault-запись.
        let key_epoch = match storage.latest_membership_epoch(&record.vault_id)? {
            Some(latest) => record.key_epoch.max(latest),
            None => record.key_epoch,
        };

        Ok(Vault {
            storage,
            keyset,
            vault_id: record.vault_id,
            name: Zeroizing::new(name),
            vk,
            version: record.version,
            key_epoch: Cell::new(key_epoch),
        })
    }

    /// Удаляет волт (tombstone с возросшей версией).
    pub fn delete(self) -> Result<(), VaultError> {
        let version = self.version + 1;
        let name_blob = aead_encrypt(
            &self.vk,
            self.name.as_slice(),
            &name_aad(&self.vault_id, version),
        )?;
        // Сохраняем актуальную эпоху/target/policy: tombstone membership-волта не
        // должен деградировать на эпоху 0 (downgrade → нечитаемая запись).
        let cur = self
            .storage
            .get_vault(&self.vault_id)?
            .ok_or(VaultError::NotFound)?;
        let stored_epoch = self.key_epoch.get().max(cur.key_epoch);
        let owner_ed = self.keyset.signing.verifying.to_bytes();
        let wrapped_vk = seal_key_to_public(
            &self.keyset.encryption.public,
            &self.vk,
            &vk_wrap_info(&self.vault_id, &owner_ed, stored_epoch)?,
        )?;
        let record = build_vault_record_epoch(
            self.keyset,
            &self.vault_id,
            &name_blob,
            &wrapped_vk,
            version,
            true,
            stored_epoch,
            cur.sync_target,
            cur.cache_policy,
            cur.sync_tenant.clone(),
        )?;
        // Атомарно: tombstone волта + очистка истории версий всех его items —
        // архивные VK-шифрованные версии секретов не должны переживать удаление.
        self.storage.transaction(|| {
            self.storage.put_vault(&record)?;
            self.storage.mark_vault_dirty(&self.vault_id)?; // tombstone → needs push
            for rec in self
                .storage
                .list_items_including_tombstones(&self.vault_id)?
            {
                self.storage
                    .clear_item_history(&self.vault_id, &rec.item_id)?;
            }
            Ok::<(), VaultError>(())
        })
    }

    /// **Кооперативный hard-delete волта** (`purge`, server-tz §6.4) по проверенному
    /// revoke-сигналу: физически удаляет vault-запись, ВСЕ items (вкл. tombstones),
    /// ВСЮ историю версий, ВСЕ membership-манифесты и гранты и пол эпохи волта
    /// (атомарно, через [`Storage::purge_vault_data`]), и **зануляет in-memory VK**
    /// (поглощает `self` → `Drop` зануляет `vk`).
    ///
    /// В отличие от [`Vault::delete`] (tombstone — логическое удаление с ростом
    /// версии, переживающее синк), `purge_vault` не оставляет на устройстве ни
    /// шифротекста, ни метаданных волта.
    ///
    /// **Best-effort/гигиена, НЕ remote-wipe:** данные, уже синкнутые на ДРУГИЕ или
    /// модифицированные клиенты, этим не отзываются (энфорс кооперативен). Жёсткий
    /// криптографический отзыв доступа даёт [`Vault::rotate_vk`] (ротация VK).
    pub fn purge_vault(self) -> Result<(), VaultError> {
        self.storage.purge_vault_data(&self.vault_id)?;
        // self (с vk: SymmetricKey + name: Zeroizing) уходит из области видимости →
        // ZeroizeOnDrop зануляет VK. Явный drop для наглядности.
        drop(self);
        Ok(())
    }

    /// Идентификатор волта.
    pub fn vault_id(&self) -> &[u8] {
        &self.vault_id
    }

    /// Расшифрованное имя волта.
    pub fn name(&self) -> &[u8] {
        self.name.as_slice()
    }

    /// Переименовывает волт: пере-шифровывает имя под VK с возросшей версией и
    /// переподписывает запись. Сохраняет актуальную `key_epoch`/`sync_target`/
    /// `cache_policy` записи (иначе membership-волт деградировал бы на эпоху 0 →
    /// нечитаемая vault-запись, как и items до фикса).
    pub fn set_name(&mut self, new_name: &[u8]) -> Result<(), VaultError> {
        let version = self.version + 1;
        let name_blob = aead_encrypt(&self.vk, new_name, &name_aad(&self.vault_id, version))?;
        let cur = self
            .storage
            .get_vault(&self.vault_id)?
            .ok_or(VaultError::NotFound)?;
        let stored_epoch = self.key_epoch.get().max(cur.key_epoch);
        let owner_ed = self.keyset.signing.verifying.to_bytes();
        let wrapped_vk = seal_key_to_public(
            &self.keyset.encryption.public,
            &self.vk,
            &vk_wrap_info(&self.vault_id, &owner_ed, stored_epoch)?,
        )?;
        let record = build_vault_record_epoch(
            self.keyset,
            &self.vault_id,
            &name_blob,
            &wrapped_vk,
            version,
            false,
            stored_epoch,
            cur.sync_target,
            cur.cache_policy,
            cur.sync_tenant.clone(),
        )?;
        self.storage.put_vault(&record)?;
        self.storage.mark_vault_dirty(&self.vault_id)?; // rename → needs push
        self.name = Zeroizing::new(new_name.to_vec());
        self.version = version;
        Ok(())
    }

    // --- items ---

    /// Кладёт (создаёт/обновляет) item: генерирует per-item ключ, обёртывает его
    /// VK, шифрует контент с привязкой, подписывает версию. Возвращает версию.
    pub fn put_item(
        &self,
        item_id: impl AsRef<[u8]>,
        item_type: u32,
        content: &[u8],
    ) -> Result<u64, VaultError> {
        let item_id = item_id.as_ref();
        let existing = self.storage.get_item(&self.vault_id, item_id)?;
        let version = existing.map(|r| r.version + 1).unwrap_or(1);

        let item_key = SymmetricKey::generate();
        let wrapped_item_key = wrap_key(&self.vk, &item_key, item_id)?;

        let aad = item_aad(&self.vault_id, item_id, version);
        let content_blob = aead_encrypt(&item_key, content, &aad)?;

        let vo = VersionedObject::from_content(aad, &content_blob);
        let signature = sign_version(&self.keyset.signing.signing, &vo)?;

        let record = ItemRecord {
            vault_id: self.vault_id.clone(),
            item_id: item_id.to_vec(),
            item_type,
            content_blob,
            wrapped_item_key,
            version,
            tombstone: false,
            signature,
            author_pubkey: self.keyset.signing.verifying.to_bytes().to_vec(),
            // Временные метки проставляет storage при записи.
            created_at: 0,
            updated_at: 0,
            // Актуальная эпоха ключа волта (НЕ 0): в membership-режиме запись на
            // эпохе без manifest / ниже пола отвергается verify_record_authority.
            key_epoch: self.key_epoch.get(),
        };
        self.storage.put_item(&record)?;
        self.storage.mark_item_dirty(&self.vault_id, item_id)?; // local edit → needs push
        Ok(version)
    }

    /// Возвращает расшифрованный item (проверяя подпись). `None`, если нет или удалён.
    pub fn get_item(&self, item_id: &[u8]) -> Result<Option<DecryptedItem>, VaultError> {
        match self.storage.get_item(&self.vault_id, item_id)? {
            Some(r) if !r.tombstone => Ok(Some(self.decrypt_record(&r)?)),
            _ => Ok(None),
        }
    }

    /// Проверяет подпись записи и расшифровывает её контент (общий путь для
    /// текущей версии и исторических).
    fn decrypt_record(&self, record: &ItemRecord) -> Result<DecryptedItem, VaultError> {
        let author = Ed25519VerifyingKey::from_bytes(&record.author_pubkey)
            .map_err(|_| VaultError::Format)?;
        let aad = item_aad(&self.vault_id, &record.item_id, record.version);
        let vo = VersionedObject::from_content(aad.clone(), &record.content_blob);
        // Локально откат версии исключён монотонностью storage (anti-rollback на
        // записи). TODO(Веха 2, синк): использовать crypto::verify_no_rollback
        // против доверенного last-seen-курсора (вне реплицируемой БД), чтобы
        // ловить snapshot-replay подменой всего файла БД.
        verify_version(&author, &vo, &record.signature)
            .map_err(|_| VaultError::SignatureInvalid)?;
        // Defense-in-depth: подпись валидна — но валидна ли она под ключом
        // ВЛАДЕЛЬЦА/ЧЛЕНА? Подменённый author_pubkey даёт самосогласованную
        // подпись под чужим ключом.
        //
        // Режим волта берётся из vault-level сигнала ВНУТРИ
        // verify_record_authority (membership ⇔ есть пол/manifest), НЕ из
        // record.key_epoch — иначе untrusted-DB даунгрейдит membership-волт на
        // owner==author подменой неподписанного key_epoch (P4-ревью, анти-rollback
        // bypass). В membership-режиме запись на эпохе без manifest / ниже пола /
        // от не-члена отвергается; в local-режиме — прежняя owner==author сверка.
        let genesis_owner = self.keyset.signing.verifying.to_bytes();
        verify_record_authority(
            self.storage,
            &self.vault_id,
            &record.author_pubkey,
            record.key_epoch,
            &genesis_owner,
        )?;

        // read-fallback на pre-round-2 item-обёртку/контент (см. *_compat хелперы).
        let item_key = unwrap_key_compat(&self.vk, &record.wrapped_item_key, &record.item_id)?;
        let content = aead_decrypt_compat(&item_key, &record.content_blob, &aad)?;

        Ok(DecryptedItem {
            item_id: record.item_id.clone(),
            item_type: record.item_type,
            version: record.version,
            content: Zeroizing::new(content),
        })
    }

    /// Как [`Vault::put_item`], но архивирует прошлую версию в историю (ретеншн
    /// [`HISTORY_RETAIN`]). Для секретов с историей версий (пароль/заметка).
    pub fn put_item_keep_history(
        &self,
        item_id: impl AsRef<[u8]>,
        item_type: u32,
        content: &[u8],
    ) -> Result<u64, VaultError> {
        let item_id = item_id.as_ref();
        let existing = self.storage.get_item(&self.vault_id, item_id)?;
        let version = existing.map(|r| r.version + 1).unwrap_or(1);

        let item_key = SymmetricKey::generate();
        let wrapped_item_key = wrap_key(&self.vk, &item_key, item_id)?;
        let aad = item_aad(&self.vault_id, item_id, version);
        let content_blob = aead_encrypt(&item_key, content, &aad)?;
        let vo = VersionedObject::from_content(aad, &content_blob);
        let signature = sign_version(&self.keyset.signing.signing, &vo)?;

        let record = ItemRecord {
            vault_id: self.vault_id.clone(),
            item_id: item_id.to_vec(),
            item_type,
            content_blob,
            wrapped_item_key,
            version,
            tombstone: false,
            signature,
            author_pubkey: self.keyset.signing.verifying.to_bytes().to_vec(),
            created_at: 0,
            updated_at: 0,
            // Актуальная эпоха ключа волта (НЕ 0) — см. put_item.
            key_epoch: self.key_epoch.get(),
        };
        self.storage.archive_and_put(&record, HISTORY_RETAIN)?;
        self.storage
            .mark_item_dirty(&self.vault_id, &record.item_id)?; // edit → push
        Ok(version)
    }

    /// Версии item, доступные для reveal: текущая (если жива) + архивные.
    pub fn list_item_versions(&self, item_id: &[u8]) -> Result<Vec<u64>, VaultError> {
        let mut versions = Vec::new();
        if let Some(r) = self.storage.get_item(&self.vault_id, item_id)? {
            if !r.tombstone {
                versions.push(r.version);
            }
        }
        for r in self.storage.list_item_history(&self.vault_id, item_id)? {
            versions.push(r.version);
        }
        Ok(versions)
    }

    /// Расшифровывает конкретную версию item (текущую или историческую), проверяя
    /// её подпись под её AAD. `None`, если такой версии нет.
    pub fn get_item_version(
        &self,
        item_id: &[u8],
        version: u64,
    ) -> Result<Option<DecryptedItem>, VaultError> {
        if let Some(r) = self.storage.get_item(&self.vault_id, item_id)? {
            if !r.tombstone && r.version == version {
                return Ok(Some(self.decrypt_record(&r)?));
            }
        }
        for r in self.storage.list_item_history(&self.vault_id, item_id)? {
            if r.version == version {
                return Ok(Some(self.decrypt_record(&r)?));
            }
        }
        Ok(None)
    }

    /// Метаданные не-удалённых items (без расшифровки контента).
    pub fn list_items(&self) -> Result<Vec<ItemMeta>, VaultError> {
        Ok(self
            .storage
            .list_items(&self.vault_id)?
            .into_iter()
            .map(|r| ItemMeta {
                item_id: r.item_id,
                item_type: r.item_type,
                version: r.version,
                created_at: r.created_at,
                updated_at: r.updated_at,
            })
            .collect())
    }

    /// Строит подписанную tombstone-запись (пустой контент, версия `version`).
    fn tombstone_record(
        &self,
        item_id: &[u8],
        item_type: u32,
        version: u64,
    ) -> Result<ItemRecord, VaultError> {
        let content_blob: Vec<u8> = Vec::new();
        let vo = VersionedObject::from_content(
            item_aad(&self.vault_id, item_id, version),
            &content_blob,
        );
        let signature = sign_version(&self.keyset.signing.signing, &vo)?;
        Ok(ItemRecord {
            vault_id: self.vault_id.clone(),
            item_id: item_id.to_vec(),
            item_type,
            content_blob,
            wrapped_item_key: Vec::new(),
            version,
            tombstone: true,
            signature,
            author_pubkey: self.keyset.signing.verifying.to_bytes().to_vec(),
            created_at: 0,
            updated_at: 0,
            // Актуальная эпоха ключа волта (НЕ 0) — tombstone тоже проходит
            // verify_record_authority в membership-режиме.
            key_epoch: self.key_epoch.get(),
        })
    }

    /// Удаляет item (tombstone с возросшей версией). Tombstone и очистка истории
    /// версий — **атомарно** (одна транзакция): краш не оставит tombstone с живой
    /// историей, иначе удалённый plaintext «воскрес» бы через `get_item_version`.
    pub fn delete_item(&self, item_id: &[u8]) -> Result<(), VaultError> {
        let existing = self
            .storage
            .get_item(&self.vault_id, item_id)?
            .ok_or(VaultError::NotFound)?;
        let record = self.tombstone_record(item_id, existing.item_type, existing.version + 1)?;
        self.storage.put_item_and_clear_history(&record)?;
        self.storage.mark_item_dirty(&self.vault_id, item_id)?; // tombstone → push
        Ok(())
    }

    /// Переименовывает (перемещает) item: создаёт `new_id` с тем же типом и
    /// контентом, помечает `old_id` tombstone. Per-item ключ и привязка (AAD)
    /// пересоздаются под новый id. Ошибка, если `new_id` уже занят живым item.
    /// Семантика синка: rename = удаление старого + создание нового (как в
    /// большинстве систем), история версий старого id обрывается tombstone'ом.
    pub fn rename_item(&self, old_id: &[u8], new_id: &[u8]) -> Result<(), VaultError> {
        if old_id == new_id {
            return Ok(());
        }
        if let Some(r) = self.storage.get_item(&self.vault_id, new_id)? {
            if !r.tombstone {
                return Err(VaultError::AlreadyExists);
            }
        }
        let item = self.get_item(old_id)?.ok_or(VaultError::NotFound)?;
        // Атомарно: создаём новый id и хороним старый в одной транзакции, чтобы
        // сбой между шагами не оставил контент живым под обоими id. Tombstone и
        // очистку истории старого id инлайним (не через delete_item, иначе был бы
        // вложенный BEGIN).
        self.storage.transaction(|| {
            self.put_item(new_id, item.item_type, item.content.as_slice())?;
            let tomb = self.tombstone_record(old_id, item.item_type, item.version + 1)?;
            self.storage.put_item(&tomb)?;
            self.storage.mark_item_dirty(&self.vault_id, old_id)?; // old-id tombstone → push
            self.storage.clear_item_history(&self.vault_id, old_id)?;
            Ok::<(), VaultError>(())
        })
    }

    /// **Устанавливает/расширяет членство волта** (server-tz §5): если manifest ещё
    /// нет — создаёт genesis-набор на эпохе 1; иначе расширяет проверенный набор
    /// последней эпохи и выпускает новый manifest на `latest+1`. Per-member гранты
    /// обёртывают **текущий VK** (`self.vk`) под X25519-pubkey каждого получателя.
    ///
    /// `members` — полный целевой набор (member-id = Ed25519-pubkey + роль).
    /// `x25519_by_ed` — соответствие `(member_ed25519_pub, member_x25519_pub)` для
    /// каждого члена-получателя обёртки VK. Владелец (`self.keyset`) обязан быть в
    /// наборе как `Admin` (иначе позднейшая запись от него не пройдёт authority).
    ///
    /// **VK наружу не уходит:** обёртка строится внутри (free `add_member`). Это путь
    /// записи manifest+гранты с self-verify до персиста; read-путь самодостаточно
    /// перепроверяет цепочку. Возвращает эпоху записанного manifest.
    pub fn establish_or_extend_membership(
        &self,
        admin_keyset: &UnlockedKeyset,
        members: &[Member],
        x25519_by_ed: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<u64, VaultError> {
        let genesis_owner = self.keyset.signing.verifying.to_bytes().to_vec();
        let (key_epoch, prev) = match self.storage.latest_membership_epoch(&self.vault_id)? {
            Some(latest) => {
                let prev =
                    verify_chain_to_epoch(self.storage, &self.vault_id, latest, &genesis_owner)?;
                (
                    latest.checked_add(1).ok_or(VaultError::EpochInvalid)?,
                    Some(prev),
                )
            }
            None => (1u64, None),
        };
        // гранты: (recipient_x25519, member_ed25519, role) для каждого члена,
        // у которого известен x25519.
        let mut grants: Vec<(Vec<u8>, Vec<u8>, MemberRole)> = Vec::new();
        for m in members {
            if let Some((_, x)) = x25519_by_ed.iter().find(|(ed, _)| ed == &m.ed25519_pub) {
                grants.push((x.clone(), m.ed25519_pub.clone(), m.role));
            }
        }
        let verified = add_member(
            self.storage,
            admin_keyset,
            &self.vault_id,
            key_epoch,
            prev.as_ref(),
            &genesis_owner,
            members,
            &grants,
            &self.vk,
        )?;

        // Ре-якорим vault-запись на свежий `key_epoch` (server-tz §5/§6.2): иначе
        // запись остаётся на key_epoch=0, а волт уже в membership-режиме — тогда
        // `verify_record_authority` ищет несуществующий manifest@0 и аудит падает.
        // VK не меняется (это не ротация) — переподписываем ту же обёртку с
        // version+1 и новой эпохой. Делаем это ТОЛЬКО когда владелец записи
        // (`self.keyset` = genesis_owner, автор и получатель `wrapped_vk`) состоит
        // в проверенном наборе@key_epoch И МОЖЕТ В НЕГО ПИСАТЬ (`can_write`, не просто
        // `contains`) — иначе переподписанная им запись будет авторизована Viewer'ом и
        // `verify_record_authority` её отвергнет (волт нечитаем). Owner всегда Admin в
        // штатном пути; проверка — defense-in-depth против Viewer-owner-набора.
        if verified.can_write(&genesis_owner) {
            let vrec = self
                .storage
                .get_vault(&self.vault_id)?
                .ok_or(VaultError::NotFound)?;
            let v_version = vrec
                .version
                .checked_add(1)
                .ok_or(VaultError::EpochInvalid)?;
            let name_blob = aead_encrypt(
                &self.vk,
                self.name.as_slice(),
                &name_aad(&self.vault_id, v_version),
            )?;
            let owner_ed = self.keyset.signing.verifying.to_bytes();
            let wrapped_vk = seal_key_to_public(
                &self.keyset.encryption.public,
                &self.vk,
                &vk_wrap_info(&self.vault_id, &owner_ed, key_epoch)?,
            )?;
            let new_vrec = build_vault_record_epoch(
                self.keyset,
                &self.vault_id,
                &name_blob,
                &wrapped_vk,
                v_version,
                false,
                key_epoch,
                vrec.sync_target,
                vrec.cache_policy,
                vrec.sync_tenant.clone(),
            )?;
            self.storage.put_vault(&new_vrec)?;
            self.storage.mark_vault_dirty(&self.vault_id)?; // re-anchored record → push
        }
        // Поднимаем in-memory эпоху, чтобы put_item на ЭТОМ же инстансе после
        // установления членства штамповал актуальную эпоху (а не 0). Переоткрытый
        // волт читает её из vault-записи в Vault::open.
        self.key_epoch.set(key_epoch);
        Ok(key_epoch)
    }

    /// Меняет cache-policy волта (server-tz §6.6): version+1, переподпись записи,
    /// `put_vault`. `cache_policy` — открытая метадата (вне подписываемого
    /// контента), но запись всё равно переподписывается с новой версией (LWW).
    pub fn set_cache_policy(&mut self, policy: CachePolicy) -> Result<(), VaultError> {
        let version = self.version + 1;
        let name_blob = aead_encrypt(
            &self.vk,
            self.name.as_slice(),
            &name_aad(&self.vault_id, version),
        )?;
        // сохраняем текущий key_epoch/sync_target из БД-записи.
        let cur = self
            .storage
            .get_vault(&self.vault_id)?
            .ok_or(VaultError::NotFound)?;
        let owner_ed = self.keyset.signing.verifying.to_bytes();
        let wrapped_vk = seal_key_to_public(
            &self.keyset.encryption.public,
            &self.vk,
            &vk_wrap_info(&self.vault_id, &owner_ed, cur.key_epoch)?,
        )?;
        let record = build_vault_record_epoch(
            self.keyset,
            &self.vault_id,
            &name_blob,
            &wrapped_vk,
            version,
            false,
            cur.key_epoch,
            cur.sync_target,
            policy,
            cur.sync_tenant.clone(),
        )?;
        self.storage.put_vault(&record)?;
        self.storage.mark_vault_dirty(&self.vault_id)?; // cache-policy edit → push
        self.version = version;
        Ok(())
    }

    /// Обёртывает VK под X25519-публичный ключ получателя, возвращая
    /// `Enc(VK, recipient_pub)` с тем же доменно-разделённым биндингом
    /// `vk_wrap_info(vault_id, recipient_ed25519, key_epoch)`, что и боевые
    /// per-member гранты (F17) — так конверт открывается ровно через
    /// [`crate::open_grant`] получателем, а не привязан к сырому `vault_id`.
    /// Привязка к текущей `key_epoch` волта.
    pub fn seal_vk_to_recipient(
        &self,
        recipient_x25519_pub: &[u8],
        recipient_ed25519_pub: &[u8],
    ) -> Result<Vec<u8>, VaultError> {
        let pk =
            X25519PublicKey::from_bytes(recipient_x25519_pub).map_err(|_| VaultError::Format)?;
        let info = vk_wrap_info(&self.vault_id, recipient_ed25519_pub, self.key_epoch.get())?;
        Ok(seal_key_to_public(&pk, &self.vk, &info)?)
    }

    /// **Eager-ротация Vault Key** (server-tz §6.2 / §1.1) для волта **с членством**.
    ///
    /// Генерирует новый `VK'`, поднимает эпоху (`new = current + 1`), выпускает
    /// новый admin-подписанный manifest над `remaining_members` (sigchain от
    /// прошлой эпохи), per-member гранты под `VK'` (биндинг
    /// `vk_wrap_info(vault_id, member, new_epoch)`), **re-wrap** каждого живого item
    /// под `VK'` (плейнтекст и per-item ключ не меняются — меняется только обёртка
    /// ключа и эпоха записи), обновляет vault-запись (`key_epoch=new`, `version+1`,
    /// `wrapped_vk` владельца под `VK'`) и поднимает **пол эпохи** до `new`. ВСЁ — в
    /// одной транзакции (атомарно: частичный сбой → консистентный rollback).
    ///
    /// **Scope (D-SCOPE):** применяется ТОЛЬКО к волтам с manifest на текущую эпоху.
    /// Одно-владельческий local-волт (manifest нет) → `VaultError::NotAMember` (не
    /// ротируется; D2 из P3 — их поведение не меняется).
    ///
    /// `admin_keyset` должен быть `Admin` в проверенном наборе текущей эпохи, иначе
    /// `VaultError::AuthorityInvalid`. Отозванный член просто **отсутствует** в
    /// `remaining_members`/`grants` → не получает грант под `VK'`.
    ///
    /// `grants` — `(recipient_x25519_pub, member_ed25519_pub, role)` на каждого
    /// получателя обёртки `VK'`. Возвращает новую эпоху.
    ///
    /// **Граница чистоты:** метод берёт `&self`, обновляет только storage; in-memory
    /// `self.vk`/`self.version` остаются старыми (валидны для re-wrap СТАРЫХ записей
    /// до commit). После ротации инстанс `Vault` устарел — для работы под `VK'`
    /// его следует переоткрыть (`Vault::open`/грант).
    ///
    /// **Чтение до-ротационной истории** не покрывается (server-tz §6.2): re-wrap
    /// касается только текущего поколения item-ключей; полноценный seed-chain —
    /// ⏳ ПОТОМ (свою крипту не писать).
    pub fn rotate_vk(
        &self,
        admin_keyset: &UnlockedKeyset,
        remaining_members: &[Member],
        grants: &[(Vec<u8>, Vec<u8>, MemberRole)],
    ) -> Result<u64, VaultError> {
        // genesis-якорь = pubkey создателя волта (= владелец keyset, открывший волт).
        let genesis_owner = self.keyset.signing.verifying.to_bytes().to_vec();

        // 0) vault-запись + текущая membership-эпоха.
        let vrec = self
            .storage
            .get_vault(&self.vault_id)?
            .ok_or(VaultError::NotFound)?;
        // D-SCOPE: ротация только для волта с manifest. Текущая membership-эпоха =
        // наибольшая эпоха существующего манифеста (vault-запись свежесозданного
        // волта несёт key_epoch=0, а genesis-manifest — на эпохе 1; они
        // синхронизируются только начиная с первой ротации). Манифеста нет →
        // одно-владельческий local-волт → не ротируется (D2 из P3).
        let current_epoch = match self.storage.latest_membership_epoch(&self.vault_id)? {
            Some(e) => e,
            None => return Err(VaultError::NotAMember),
        };
        // проверяем цепочку до current_epoch и что админ — Admin@current.
        let prev =
            verify_chain_to_epoch(self.storage, &self.vault_id, current_epoch, &genesis_owner)?;
        let admin_ed = admin_keyset.signing.verifying.to_bytes().to_vec();
        if !prev.is_admin(&admin_ed) {
            return Err(VaultError::AuthorityInvalid);
        }

        let new_epoch = current_epoch
            .checked_add(1)
            .ok_or(VaultError::EpochInvalid)?;

        // 1) VK'
        let vk_prime = SymmetricKey::generate();

        // 3) новый manifest @ new_epoch (sigchain от prev) + self-verify.
        let manifest = build_manifest(admin_keyset, &self.vault_id, new_epoch, remaining_members)?;
        let verified_new = verify_manifest(&manifest, &self.vault_id, Some(&prev), &genesis_owner)?;

        // P4-ревью (hardening): re-wrapped items И новую vault-запись подписывает
        // self.keyset (== genesis_owner). Если админ != владелец и опускает
        // владельца из remaining_members, эти записи на new_epoch авторствует
        // не-член → verify_record_authority позже вернёт NotAuthorized (волт станет
        // нечитаемым). Отвергаем такую ротацию ДО любых записей: автор re-wrap'а
        // обязан быть членом@new_epoch.
        if !verified_new.can_write(&genesis_owner) {
            return Err(VaultError::NotAMember);
        }

        // 4) per-member гранты под VK' + verify против нового набора.
        let mut built_grants = Vec::with_capacity(grants.len());
        for (recip_x, member_ed, role) in grants {
            let g = build_grant(
                admin_keyset,
                &self.vault_id,
                recip_x,
                member_ed,
                *role,
                new_epoch,
                &vk_prime,
            )?;
            verify_grant(&g, &self.vault_id, &verified_new)?;
            built_grants.push(g);
        }

        // 6) новая vault-запись: wrapped_vk владельца под VK', key_epoch=new, version+1.
        let v_version = vrec
            .version
            .checked_add(1)
            .ok_or(VaultError::EpochInvalid)?;
        let name_blob = aead_encrypt(
            &vk_prime,
            self.name.as_slice(),
            &name_aad(&self.vault_id, v_version),
        )?;
        let owner_ed = self.keyset.signing.verifying.to_bytes();
        let wrapped_vk = seal_key_to_public(
            &self.keyset.encryption.public,
            &vk_prime,
            &vk_wrap_info(&self.vault_id, &owner_ed, new_epoch)?,
        )?;
        let new_vrec = build_vault_record_epoch(
            self.keyset,
            &self.vault_id,
            &name_blob,
            &wrapped_vk,
            v_version,
            false,
            new_epoch,
            vrec.sync_target,
            vrec.cache_policy,
            vrec.sync_tenant.clone(),
        )?;

        // 5) re-wrap живых items под VK' (заранее, чтобы транзакция была короткой).
        let live = self.storage.list_items(&self.vault_id)?;
        let mut rewrapped = Vec::with_capacity(live.len());
        for it in &live {
            rewrapped.push(self.rewrap_item(it, &vk_prime, new_epoch)?);
        }

        // АТОМАРНО: manifest + гранты + items + vault-запись + пол эпохи.
        self.storage.transaction(|| {
            self.storage.put_membership_manifest(&manifest)?;
            for g in &built_grants {
                self.storage.put_membership_grant(g)?;
            }
            for r in &rewrapped {
                self.storage.put_item(r)?;
                self.storage.mark_item_dirty(&self.vault_id, &r.item_id)?;
            }
            self.storage.put_vault(&new_vrec)?;
            self.storage
                .set_vault_epoch_floor(&self.vault_id, new_epoch)?;
            // Rotation re-wrapped everything under VK' → all of it must re-sync.
            self.storage.mark_vault_dirty(&self.vault_id)?;
            self.storage
                .mark_membership_dirty(&self.vault_id, new_epoch)?;
            Ok::<(), VaultError>(())
        })?;

        // Поднимаем in-memory эпоху: хотя `self.vk`/`self.version` устарели (см.
        // докстринг — для работы под VK' волт переоткрывают), отражаем новую эпоху
        // в инстансе для консистентности Debug/повторных чтений до переоткрытия.
        self.key_epoch.set(new_epoch);
        Ok(new_epoch)
    }

    /// Re-wrap одного живого item под новый VK: разворачивает per-item ключ старым
    /// VK, заново обёртывает под `vk_prime` (AAD обёртки = item_id, не зависит от
    /// эпохи), bump версии, `key_epoch=new_epoch`, **пере-шифровывает контент тем же
    /// per-item ключом** под новый-версионный AAD (плейнтекст идентичен) и
    /// пере-подписывает. Возвращает готовую запись (storage кладёт в транзакции).
    fn rewrap_item(
        &self,
        record: &ItemRecord,
        vk_prime: &SymmetricKey,
        new_epoch: u64,
    ) -> Result<ItemRecord, VaultError> {
        // 1) per-item ключ из старого VK (AAD = item_id). read-fallback: legacy-волт
        //    (до round 2) читается старым keywrap, а re-wrap ниже — уже текущим.
        let item_key = unwrap_key_compat(&self.vk, &record.wrapped_item_key, &record.item_id)?;
        // 2) расшифровать контент под СТАРЫМ AAD (текущая версия записи).
        let old_aad = item_aad(&self.vault_id, &record.item_id, record.version);
        let plaintext = aead_decrypt_compat(&item_key, &record.content_blob, &old_aad)?;
        // 3) bump версии; новый AAD; пере-шифровать тем же per-item ключом.
        let new_version = record
            .version
            .checked_add(1)
            .ok_or(VaultError::EpochInvalid)?;
        let new_aad = item_aad(&self.vault_id, &record.item_id, new_version);
        let content_blob = aead_encrypt(&item_key, &plaintext, &new_aad)?;
        // 4) пере-обёртка per-item ключа под VK' (AAD = item_id).
        let wrapped_item_key = wrap_key(vk_prime, &item_key, &record.item_id)?;
        // 5) пере-подпись над (new_aad, новый content_blob).
        let vo = VersionedObject::from_content(new_aad, &content_blob);
        let signature = sign_version(&self.keyset.signing.signing, &vo)?;
        Ok(ItemRecord {
            vault_id: self.vault_id.clone(),
            item_id: record.item_id.clone(),
            item_type: record.item_type,
            content_blob,
            wrapped_item_key,
            version: new_version,
            tombstone: false,
            signature,
            author_pubkey: self.keyset.signing.verifying.to_bytes().to_vec(),
            created_at: 0,
            updated_at: 0,
            key_epoch: new_epoch,
        })
    }

    /// Read-only аудит целостности волта: пере-проверяет Ed25519-подпись
    /// vault-записи и **всех** item-записей (включая tombstones) против их
    /// `author_pubkey`, а сам авторитет автора сверяет **члено-осведомлённо**.
    /// Ловит порчу блобов (подпись не сходится), подмену автора (валидная подпись
    /// под чужим ключом), старо-эпоховые/не-членские записи и структурный мусор —
    /// БЕЗ разворота VK и расшифровки контента. Отчёт не содержит ни байта секрета.
    ///
    /// **Авторитет (D-VERIFY-CHAIN, P4):** режим определяется **vault-level
    /// сигналом** ([`vault_is_membership_mode`]), НЕ `key_epoch` отдельной записи
    /// (иначе downgrade подменой неподписанного `key_epoch` пройдёт аудит). В
    /// membership-режиме (есть пол ИЛИ хотя бы один manifest) автор проверяется
    /// полной D1-цепочкой авторитета до genesis, требует manifest@`key_epoch` И
    /// `key_epoch >= пол` (anti-rollback, §1.1) через [`verify_record_authority`];
    /// любое нарушение → `NotAuthorized`. В одно-владельческом режиме (нет ни пола,
    /// ни манифестов — D2, local-волты) — прежняя сверка `author == owner`.
    ///
    /// `Err` только при сбое storage верхнего уровня; плохие подписи/авторы — это
    /// данные отчёта.
    pub fn verify_chain(&self) -> Result<IntegrityReport, VaultError> {
        let trusted = self.keyset.signing.verifying.to_bytes();
        let mut issues = Vec::new();
        let mut checked = 0u64;

        if let Some(vrec) = self.storage.get_vault(&self.vault_id)? {
            checked += 1;
            let failure = vault_sig_failure(&vrec).or_else(|| {
                check_record_authority(
                    self.storage,
                    &self.vault_id,
                    &vrec.author_pubkey,
                    vrec.key_epoch,
                    &trusted,
                )
            });
            if let Some(failure) = failure {
                issues.push(IntegrityIssue {
                    item_id: Vec::new(),
                    version: vrec.version,
                    tombstone: vrec.tombstone,
                    failure,
                });
            }
        }
        let audit = |rec: &ItemRecord, issues: &mut Vec<IntegrityIssue>| {
            let failure = item_sig_failure(rec).or_else(|| {
                check_record_authority(
                    self.storage,
                    &self.vault_id,
                    &rec.author_pubkey,
                    rec.key_epoch,
                    &trusted,
                )
            });
            if let Some(failure) = failure {
                issues.push(IntegrityIssue {
                    item_id: rec.item_id.clone(),
                    version: rec.version,
                    tombstone: rec.tombstone,
                    failure,
                });
            }
        };
        for rec in self
            .storage
            .list_items_including_tombstones(&self.vault_id)?
        {
            checked += 1;
            audit(&rec, &mut issues);
        }
        // Архивные версии (история секретов) тоже подписаны — аудитим и их, иначе
        // подмена старой версии в item_history прошла бы незамеченной до reveal.
        for rec in self.storage.list_all_history(&self.vault_id)? {
            checked += 1;
            audit(&rec, &mut issues);
        }
        Ok(IntegrityReport {
            ok: issues.is_empty(),
            checked,
            issues,
        })
    }
}

// --- associated data хелперы ---

fn name_aad(vault_id: &[u8], version: u64) -> AssociatedData {
    AssociatedData::new(vault_id.to_vec(), b"__vault_name__".to_vec(), version)
}

fn vault_record_aad(vault_id: &[u8], version: u64) -> AssociatedData {
    AssociatedData::new(vault_id.to_vec(), b"__vault__".to_vec(), version)
}

fn item_aad(vault_id: &[u8], item_id: &[u8], version: u64) -> AssociatedData {
    AssociatedData::new(vault_id.to_vec(), item_id.to_vec(), version)
}

// --- read-fallback на pre-round-2 формат (см. SECURITY.md → On-disk format changes) ---
//
// Волты, созданные до round 2 (crypto-agility binding), обёрнуты старыми схемами:
// owner-VK с info=сырой vault_id (не vk_wrap_info), item-ключи без доменного тега
// keywrap, контент/имя без привязки заголовка в AAD. Подпись записи НЕ менялась
// (старые записи верифицируются). Эти хелперы читают и текущий, и pre-round-2
// формат: сперва текущая схема, при провале — замороженный legacy-кодек. Новые
// записи (put_item/set_name/rotate) уже пишутся текущей схемой, так что любая
// модификация естественно «подтягивает» запись вперёд; чистое чтение старых
// данных остаётся доступным без перезаписи/ре-подписи/синк-шума.

/// Открывает owner-VK: текущая привязка `vk_wrap_info`, при провале — pre-round-2
/// (`info` = сырой `vault_id`). Чужой keyset не пройдёт ни ту, ни другую → `Decrypt`.
fn open_owner_vk(
    secret: &unissh_crypto::X25519SecretKey,
    wrapped_vk: &[u8],
    vault_id: &[u8],
    owner_ed: &[u8; 32],
    key_epoch: u64,
) -> Result<SymmetricKey, VaultError> {
    let info = vk_wrap_info(vault_id, owner_ed, key_epoch)?;
    if let Ok(vk) = open_key_with_secret(secret, wrapped_vk, &info) {
        return Ok(vk);
    }
    // pre-round-2: owner-обёртка биндилась к сырому vault_id (без owner_ed/epoch).
    open_key_with_secret(secret, wrapped_vk, vault_id).map_err(|_| VaultError::Decrypt)
}

/// AEAD-расшифровка с fallback на pre-round-2 (заголовок не привязан к AAD).
fn aead_decrypt_compat(
    key: &SymmetricKey,
    blob: &[u8],
    aad: &AssociatedData,
) -> Result<Vec<u8>, VaultError> {
    if let Ok(pt) = aead_decrypt(key, blob, aad) {
        return Ok(pt);
    }
    aead_decrypt_pre_agility(key, blob, aad).map_err(|_| VaultError::Decrypt)
}

/// keywrap-unwrap с fallback на pre-round-2 (без доменного тега и привязки заголовка).
fn unwrap_key_compat(
    kek: &SymmetricKey,
    blob: &[u8],
    aad: &[u8],
) -> Result<SymmetricKey, VaultError> {
    if let Ok(k) = unwrap_key(kek, blob, aad) {
        return Ok(k);
    }
    unwrap_key_pre_agility(kek, blob, aad).map_err(|_| VaultError::Decrypt)
}

// --- подпись/проверка записи волта ---

fn vault_signed_content(wrapped_vk: &[u8], name_blob: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(wrapped_vk.len() + name_blob.len());
    out.extend_from_slice(wrapped_vk);
    out.extend_from_slice(name_blob);
    out
}

/// Строит подписанную vault-запись с явной `key_epoch`/`sync_target`/
/// `cache_policy`/`sync_tenant`. Единственный конструктор vault-записей: `create`
/// (genesis, эпоха 0, пустой `sync_tenant`), `set_name`/`delete` (сохраняют
/// текущую эпоху/target/policy/tenant), `set_cache_policy`/`establish`/`rotate`
/// (эпоха растёт, target/policy/tenant сохраняются). Эпоху 0 в membership-режиме
/// писать нельзя (downgrade). `sync_tenant` — открытая метка маршрутизации ВНЕ
/// подписи (подпись её не охватывает): перестроения переносят её 1:1 из БД.
#[allow(clippy::too_many_arguments)]
fn build_vault_record_epoch(
    keyset: &UnlockedKeyset,
    vault_id: &[u8],
    name_blob: &[u8],
    wrapped_vk: &[u8],
    version: u64,
    tombstone: bool,
    key_epoch: u64,
    sync_target: SyncTarget,
    cache_policy: CachePolicy,
    sync_tenant: Vec<u8>,
) -> Result<VaultRecord, VaultError> {
    let content = vault_signed_content(wrapped_vk, name_blob);
    let vo = VersionedObject::from_content(vault_record_aad(vault_id, version), &content);
    let signature = sign_version(&keyset.signing.signing, &vo)?;
    Ok(VaultRecord {
        vault_id: vault_id.to_vec(),
        sync_target,
        name_blob: name_blob.to_vec(),
        wrapped_vk: wrapped_vk.to_vec(),
        version,
        tombstone,
        signature,
        author_pubkey: keyset.signing.verifying.to_bytes().to_vec(),
        key_epoch,
        cache_policy,
        // sync_tenant — открытая метка маршрутизации, ВНЕ подписываемого контента
        // (как sync_target/cache_policy): re-sign её не охватывает, существующие
        // подписи остаются валидны. Конструкторы передают актуальное значение
        // (genesis — пусто; перестроения — сохраняют текущее из БД-записи).
        sync_tenant,
    })
}

fn verify_vault_record(record: &VaultRecord) -> Result<(), VaultError> {
    let author =
        Ed25519VerifyingKey::from_bytes(&record.author_pubkey).map_err(|_| VaultError::Format)?;
    let content = vault_signed_content(&record.wrapped_vk, &record.name_blob);
    let vo =
        VersionedObject::from_content(vault_record_aad(&record.vault_id, record.version), &content);
    verify_version(&author, &vo, &record.signature).map_err(|_| VaultError::SignatureInvalid)
}

// --- авторизация автора записи: member-set@эпоха ИЛИ owner==author (D2) ---

/// Определяет режим волта из **vault-level доверенного сигнала**, а НЕ из
/// `key_epoch` отдельной (потенциально подменённой) записи. Волт считается
/// membership-волтом, если у него есть пол эпохи (anti-rollback маркер,
/// выставляется ротацией) ИЛИ хотя бы один membership-manifest. Иначе — это
/// одно-владельческий local-волт (D2).
///
/// ## Почему vault-level, а не per-record (анти-rollback bypass, P4-ревью)
/// Прежняя версия выбирала режим из `get_membership_manifest(record.key_epoch)`:
/// `key_epoch` — **неподписанное** поле записи. Untrusted-DB/sync-peer ставил
/// валидно-owner-подписанной записи `key_epoch=0` (эпоху без manifest), и read-путь
/// «деградировал» на одно-владельческую сверку (owner==author проходил), пропуская
/// пол эпохи и D1-цепочку. Так до-ротационная/ниже-пола запись принималась и
/// `verify_chain`, и живым decrypt-путём. Привязка режима к vault-level сигналу
/// закрывает downgrade: запись с эпохой без manifest в membership-режиме отвергается.
fn vault_is_membership_mode(storage: &Storage, vault_id: &[u8]) -> Result<bool, VaultError> {
    // Пиненный per-vault якорь (A0, чужой волт) — тоже сигнал membership-режима:
    // без него в окне «якорь запинен, но manifest ещё не синкнут» запись автора-
    // тиммейта прошла бы одно-владельческой веткой (author==anchor) БЕЗ D1-цепочки.
    // Пиннятся только чужие волты, поэтому собственные (без якоря) не затронуты.
    Ok(storage.get_vault_epoch_floor(vault_id)?.is_some()
        || storage.latest_membership_epoch(vault_id)?.is_some()
        || storage.get_vault_trust_anchor(vault_id)?.is_some())
}

/// Проверяет право автора записи (ТЗ §13 п.8). **Режим волта** определяется
/// vault-level сигналом ([`vault_is_membership_mode`]), НЕ `record_epoch`:
///
/// - **membership-режим** (есть пол эпохи ИЛИ хотя бы один manifest): требуется
///   `record_epoch >= пол эпохи` И наличие manifest@`record_epoch` (его отсутствие =
///   downgrade-попытка → `EpochInvalid`) И `author ∈ члены@эпоха` по
///   перепроверенной D1-цепочке от genesis. Никакого fallback на owner==author.
/// - **одно-владельческий local-волт** (нет ни пола, ни манифестов): `author ==
///   genesis_owner`.
///
/// `genesis_owner` — доверенный якорь: pubkey создателя волта (= владелец keyset
/// для local-волтов). Не паникует: любое нарушение — типизированная `VaultError`.
///
/// ## Самодостаточность read-пути (untrusted-DB / sync-ready, ARCH.md)
/// Этот путь **НЕ доверяет** факту, что manifest лежит в storage. Он заново
/// перепроверяет **полную D1-цепочку** членства от genesis (epoch 1) до
/// `record_epoch`, якорясь на пиннингованном `genesis_owner` (см.
/// [`crate::membership::verify_chain_to_epoch`]). Так оператор-инъектированный
/// самосогласованный manifest (author=attacker, members=[attacker]) на любой
/// эпохе отклоняется: цепочка от genesis к attacker не ведёт. Это жёсткая
/// предпосылка перед member-via-grant получением VK и любым синком (P4) —
/// read-путь обязан опираться на якорь, а не на хранилище.
pub fn verify_record_authority(
    storage: &Storage,
    vault_id: &[u8],
    author_pubkey: &[u8],
    record_epoch: u64,
    genesis_owner: &[u8],
) -> Result<(), VaultError> {
    if !vault_is_membership_mode(storage, vault_id)? {
        // D2: одно-владельческий local-волт — прежний owner==author.
        return if author_pubkey == genesis_owner {
            Ok(())
        } else {
            Err(VaultError::NotAMember)
        };
    }
    // membership-режим (vault-level): downgrade на owner==author запрещён.
    // (b) anti-rollback: пол эпохи (дефолт 0).
    let floor = storage.get_vault_epoch_floor(vault_id)?.unwrap_or(0);
    if record_epoch < floor {
        return Err(VaultError::EpochInvalid);
    }
    // Запись на эпохе без manifest в membership-режиме — downgrade-попытка.
    // (Цепочка не может якориться на отсутствующем manifest@record_epoch.)
    if storage
        .get_membership_manifest(vault_id, record_epoch)?
        .is_none()
    {
        return Err(VaultError::EpochInvalid);
    }
    // (a) Перепроверяем D1-цепочку от genesis_owner до record_epoch —
    // самодостаточно, без доверия storage. Возвращает проверенный набор@эпоха.
    let members =
        crate::membership::verify_chain_to_epoch(storage, vault_id, record_epoch, genesis_owner)?;
    // автор ∈ проверенный набор@эпоха.
    if !members.contains(author_pubkey) {
        return Err(VaultError::NotAMember);
    }
    // ...И имеет роль с правом записи КОНТЕНТА (Editor/Admin). Viewer (read-only)
    // не вправе авторить item/vault-записи: иначе read-only член мог бы создавать,
    // перезаписывать (LWW с бампом версии) и ставить tombstone на записи общего
    // волта, а verify-before-apply у других членов принял бы их как аутентичные —
    // обход роли Viewer/Editor/Admin (write-integrity gap). Манифесты/гранты
    // гейтятся отдельно (admin-авторитет в verify_manifest/verify_grant).
    if !members.can_write(author_pubkey) {
        return Err(VaultError::AuthorityInvalid);
    }
    Ok(())
}

// --- аудит целостности (verify_chain) ---

/// Причина, по которой запись не прошла проверку целостности.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IntegrityFailure {
    /// Подпись не верифицируется под заявленным `author_pubkey` (порча
    /// content/метаданных или повреждённый sig-блоб).
    SignatureInvalid,
    /// `author_pubkey` записи не совпадает с доверенным владельцем волта —
    /// подмена автора (подпись может быть валидной под чужим ключом).
    AuthorMismatch,
    /// `author_pubkey`/подпись структурно некорректны (не парсятся).
    Malformed,
    /// Автор записи не входит в подписанный member-set волта на её эпоху, либо
    /// эпоха записи ниже доверенного пола (anti-rollback) — для membership-волтов.
    NotAuthorized,
}

/// Одна проблемная запись в отчёте целостности.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityIssue {
    /// `item_id` записи; пусто для самой vault-записи.
    pub item_id: Vec<u8>,
    /// Версия записи, к которой относится проблема.
    pub version: u64,
    /// Tombstone ли это (удалённые записи тоже проверяются).
    pub tombstone: bool,
    /// Машиночитаемая причина.
    pub failure: IntegrityFailure,
}

/// Read-only отчёт о целостности волта. Без секретов и без plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityReport {
    /// `true` ⇔ `issues` пуст (vault-запись и все items, включая tombstones, ок).
    pub ok: bool,
    /// Сколько записей проверено (vault-запись + все item-записи с tombstones).
    pub checked: u64,
    /// Проблемные записи (vault-запись помечается пустым `item_id`).
    pub issues: Vec<IntegrityIssue>,
}

/// Проверяет одну item-запись: парс автора → `Malformed`; подпись над
/// `(AAD vault_id+item_id+version, content_blob)` → `SignatureInvalid`; сверка
/// `author_pubkey` с доверенным владельцем → `AuthorMismatch`. `None` == ок.
/// Не разворачивает VK и не расшифровывает контент.
pub fn check_item_record(record: &ItemRecord, trusted_owner: &[u8]) -> Option<IntegrityFailure> {
    let author = match Ed25519VerifyingKey::from_bytes(&record.author_pubkey) {
        Ok(a) => a,
        Err(_) => return Some(IntegrityFailure::Malformed),
    };
    let aad = item_aad(&record.vault_id, &record.item_id, record.version);
    let vo = VersionedObject::from_content(aad, &record.content_blob);
    if verify_version(&author, &vo, &record.signature).is_err() {
        return Some(IntegrityFailure::SignatureInvalid);
    }
    if record.author_pubkey.as_slice() != trusted_owner {
        return Some(IntegrityFailure::AuthorMismatch);
    }
    None
}

/// Member-aware проверка авторитета записи для [`Vault::verify_chain`]. Режим
/// волта определяется **vault-level сигналом** ([`vault_is_membership_mode`]), а
/// НЕ `record_epoch` отдельной записи (иначе downgrade подменой неподписанного
/// `key_epoch` пройдёт аудит — P4-ревью). В membership-режиме авторитет сверяется
/// через [`verify_record_authority`] (D1-цепочка + пол + manifest@epoch);
/// любое нарушение → `NotAuthorized`. В одно-владельческом режиме — сверка
/// `author == trusted_owner` (→ `AuthorMismatch` при расхождении). Ошибки storage
/// внутри аудита трактуются консервативно как `NotAuthorized` (а не паника);
/// верхнеуровневые storage-вызовы `verify_chain` возвращают `Err` через `?`.
fn check_record_authority(
    storage: &Storage,
    vault_id: &[u8],
    author_pubkey: &[u8],
    record_epoch: u64,
    trusted_owner: &[u8],
) -> Option<IntegrityFailure> {
    match vault_is_membership_mode(storage, vault_id) {
        Ok(true) => match verify_record_authority(
            storage,
            vault_id,
            author_pubkey,
            record_epoch,
            trusted_owner,
        ) {
            Ok(()) => None,
            Err(_) => Some(IntegrityFailure::NotAuthorized),
        },
        Ok(false) => {
            // одно-владельческая модель (D2): нет пола и нет манифестов.
            if author_pubkey == trusted_owner {
                None
            } else {
                Some(IntegrityFailure::AuthorMismatch)
            }
        }
        Err(_) => Some(IntegrityFailure::NotAuthorized),
    }
}

/// Проверяет только структуру+подпись item-записи (без сверки автора с владельцем
/// — авторитет сверяет [`check_record_authority`]).
fn item_sig_failure(record: &ItemRecord) -> Option<IntegrityFailure> {
    let author = match Ed25519VerifyingKey::from_bytes(&record.author_pubkey) {
        Ok(a) => a,
        Err(_) => return Some(IntegrityFailure::Malformed),
    };
    let aad = item_aad(&record.vault_id, &record.item_id, record.version);
    let vo = VersionedObject::from_content(aad, &record.content_blob);
    if verify_version(&author, &vo, &record.signature).is_err() {
        return Some(IntegrityFailure::SignatureInvalid);
    }
    None
}

/// Аналог [`item_sig_failure`] для vault-записи.
fn vault_sig_failure(record: &VaultRecord) -> Option<IntegrityFailure> {
    let author = match Ed25519VerifyingKey::from_bytes(&record.author_pubkey) {
        Ok(a) => a,
        Err(_) => return Some(IntegrityFailure::Malformed),
    };
    let content = vault_signed_content(&record.wrapped_vk, &record.name_blob);
    let vo =
        VersionedObject::from_content(vault_record_aad(&record.vault_id, record.version), &content);
    if verify_version(&author, &vo, &record.signature).is_err() {
        return Some(IntegrityFailure::SignatureInvalid);
    }
    None
}

/// Аналог [`check_item_record`] для vault-записи (подпись над
/// `wrapped_vk || name_blob`).
pub fn check_vault_record(record: &VaultRecord, trusted_owner: &[u8]) -> Option<IntegrityFailure> {
    let author = match Ed25519VerifyingKey::from_bytes(&record.author_pubkey) {
        Ok(a) => a,
        Err(_) => return Some(IntegrityFailure::Malformed),
    };
    let content = vault_signed_content(&record.wrapped_vk, &record.name_blob);
    let vo =
        VersionedObject::from_content(vault_record_aad(&record.vault_id, record.version), &content);
    if verify_version(&author, &vo, &record.signature).is_err() {
        return Some(IntegrityFailure::SignatureInvalid);
    }
    if record.author_pubkey.as_slice() != trusted_owner {
        return Some(IntegrityFailure::AuthorMismatch);
    }
    None
}

#[cfg(test)]
mod legacy_read_tests {
    use super::*;
    use unissh_crypto::{aead_encrypt_pre_agility, wrap_key_pre_agility};
    use unissh_keychain::{create_account, KdfParams, UnlockedKeyset};
    use unissh_storage::{ItemRecord, Storage};

    fn keyset() -> UnlockedKeyset {
        // SecretKeyOnly → без Argon2id, быстро.
        create_account(None, KdfParams::recommended()).unwrap().2
    }

    /// Кует pre-round-2 («Scheme A») волт прямо в storage: owner-VK с HPKE-`info` =
    /// сырой `vault_id` (не `vk_wrap_info`), имя и item-контент без привязки заголовка
    /// в AAD, item-ключ без доменного тега keywrap. Подпись — ТЕКУЩАЯ (механизм
    /// подписи не менялся, поэтому такие записи у пользователя и верифицируются).
    fn forge_legacy_vault(
        st: &Storage,
        ks: &UnlockedKeyset,
        vault_id: &[u8],
        name: &[u8],
        item_id: &[u8],
        item_type: u32,
        content: &[u8],
    ) {
        let vk = SymmetricKey::generate();
        let version = 1u64;
        let name_blob = aead_encrypt_pre_agility(&vk, name, &name_aad(vault_id, version)).unwrap();
        // owner-обёртка биндилась к сырому vault_id (до round 2).
        let wrapped_vk = seal_key_to_public(&ks.encryption.public, &vk, vault_id).unwrap();
        let record = build_vault_record_epoch(
            ks,
            vault_id,
            &name_blob,
            &wrapped_vk,
            version,
            false,
            0,
            SyncTarget::Local,
            CachePolicy::OfflineAllowed,
            Vec::new(),
        )
        .unwrap();
        st.put_vault(&record).unwrap();

        let item_key = SymmetricKey::generate();
        let wrapped_item_key = wrap_key_pre_agility(&vk, &item_key, item_id).unwrap();
        let aad = item_aad(vault_id, item_id, version);
        let content_blob = aead_encrypt_pre_agility(&item_key, content, &aad).unwrap();
        let vo = VersionedObject::from_content(aad, &content_blob);
        let signature = sign_version(&ks.signing.signing, &vo).unwrap();
        let irec = ItemRecord {
            vault_id: vault_id.to_vec(),
            item_id: item_id.to_vec(),
            item_type,
            content_blob,
            wrapped_item_key,
            version,
            tombstone: false,
            signature,
            author_pubkey: ks.signing.verifying.to_bytes().to_vec(),
            created_at: 0,
            updated_at: 0,
            key_epoch: 0,
        };
        st.put_item(&irec).unwrap();
    }

    #[test]
    fn legacy_vault_opens_and_item_decrypts_via_fallback() {
        let st = Storage::open_in_memory(&[7u8; 32]).unwrap();
        let ks = keyset();
        forge_legacy_vault(
            &st,
            &ks,
            b"v-legacy",
            b"Old Vault",
            b"ssh-old",
            1,
            b"OLD-SECRET-CONTENT",
        );

        // boot-путь: open (owner-VK + имя) и get_item (item-ключ + контент) — всё
        // через read-fallback на pre-round-2.
        let v = Vault::open(&st, &ks, b"v-legacy").unwrap();
        assert_eq!(v.name(), b"Old Vault");
        let got = v.get_item(b"ssh-old").unwrap().unwrap();
        assert_eq!(got.content.as_slice(), b"OLD-SECRET-CONTENT");
        assert_eq!(got.item_type, 1);
    }

    #[test]
    fn wrong_keyset_still_fails_on_legacy_vault() {
        // fallback не должен открывать legacy-волт ЧУЖИМ keyset — обе схемы провалятся.
        let st = Storage::open_in_memory(&[7u8; 32]).unwrap();
        let ks = keyset();
        forge_legacy_vault(&st, &ks, b"v", b"n", b"i", 1, b"c");
        let other = keyset();
        assert!(matches!(
            Vault::open(&st, &other, b"v"),
            Err(VaultError::Decrypt)
        ));
    }

    #[test]
    fn current_vault_unaffected_by_fallback() {
        // Регрессия: текущий формат открывается первой же попыткой, fallback не мешает.
        let st = Storage::open_in_memory(&[7u8; 32]).unwrap();
        let ks = keyset();
        let v = Vault::create(&st, &ks, b"v-cur".to_vec(), b"New").unwrap();
        v.put_item(b"i", 1, b"new-secret").unwrap();
        let v2 = Vault::open(&st, &ks, b"v-cur").unwrap();
        assert_eq!(
            v2.get_item(b"i").unwrap().unwrap().content.as_slice(),
            b"new-secret"
        );
    }
}
