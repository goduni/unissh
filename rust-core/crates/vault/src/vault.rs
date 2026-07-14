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
    add_member, build_grant, build_manifest, open_grant, verify_chain_to_epoch, verify_grant,
    verify_manifest, Member,
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
    /// The trusted authority anchor of this vault: the pinned genesis-owner pubkey.
    /// Own vaults (owner path) → the local keyset's Ed25519 pubkey; a teammate's
    /// shared vault (member path) → the TOFU-pinned creator pubkey read from
    /// `get_vault_trust_anchor`. `decrypt_record`/`verify_chain` anchor the D1
    /// authority chain on this (NOT on the local keyset), so a member reading a
    /// shared vault verifies against the true owner. Resolved once in `open`.
    genesis_owner: Vec<u8>,
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
            // The creator is the genesis owner (own vault; no anchor row exists yet).
            genesis_owner: owner_ed.to_vec(),
        })
    }

    /// Opens an existing local vault: unwraps the VK, verifies the signature.
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

        // Resolve the trusted authority anchor exactly as the sync engine does
        // (`sync::engine::vault_anchor`): the TOFU-pinned per-vault genesis owner
        // (a teammate's shared vault) or the local keyset (own vault, no anchor row).
        // Read from storage, never from the untrusted vault record.
        let genesis_owner: Vec<u8> = match storage.get_vault_trust_anchor(&record.vault_id)? {
            Some(a) => a.genesis_owner_pubkey,
            None => keyset.signing.verifying.to_bytes().to_vec(),
        };
        let own_ed = keyset.signing.verifying.to_bytes();

        let vk = if genesis_owner == own_ed {
            // Owner path (UNCHANGED): the owner wrapping is bound to (vault_id,
            // owner_ed, the record's key_epoch); the same info as at seal time.
            // read-fallback: current info binding, on failure — pre-round-2 (raw vault_id).
            open_owner_vk(
                &keyset.encryption.secret,
                &record.wrapped_vk,
                &record.vault_id,
                &own_ed,
                record.key_epoch,
            )?
        } else {
            // Member path: this account is not the genesis owner. Acquire the VK from
            // this member's own grant at the latest membership epoch, anchoring
            // authority on the pinned owner. Mirrors `sync::engine::process_grant`'s
            // verification set (verify_chain_to_epoch + verify_grant) exactly.
            let epoch = match storage.latest_membership_epoch(&record.vault_id)? {
                Some(latest) => latest,
                // No manifest synced yet for a pinned teammate vault: fall back to the
                // record's epoch so verify_chain_to_epoch surfaces a clean error (an
                // epoch of 0 or without a manifest → EpochInvalid/AuthorityInvalid).
                None => record.key_epoch,
            };
            let members = verify_chain_to_epoch(storage, &record.vault_id, epoch, &genesis_owner)?;
            // This member's own grant at the latest epoch. A revoked member has NO grant
            // at the latest epoch → read denied (NotAMember, the same kind the owner-set
            // authority check surfaces for a non-member).
            let grant = storage
                .list_membership_grants(&record.vault_id, epoch)?
                .into_iter()
                .find(|g| g.member_pubkey == own_ed)
                .ok_or(VaultError::NotAMember)?;
            verify_grant(&grant, &record.vault_id, &members)?;
            // `now` for local not_after enforcement (F16): wall-clock unix seconds
            // (the FFI only exposes a monotonic Instant, so read SystemTime here).
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            open_grant(
                &grant,
                &record.vault_id,
                &keyset.encryption.secret,
                &own_ed,
                epoch,
                now,
            )?
        };
        let name = aead_decrypt_compat(
            &vk,
            &record.name_blob,
            &name_aad(&record.vault_id, record.version),
        )?;

        // The epoch for stamping new records: the vault record's epoch, but in
        // membership mode — not below the current one (latest manifest), so that a fresh
        // put_item is not written at a stale epoch below the floor (→ EpochInvalid).
        // record.key_epoch is re-anchored by establish/rotate, but sync nodes may have
        // received a newer manifest than the re-signed vault record.
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
            genesis_owner,
        })
    }

    /// Deletes the vault (tombstone with a bumped version).
    pub fn delete(self) -> Result<(), VaultError> {
        let version = self.version + 1;
        let name_blob = aead_encrypt(
            &self.vk,
            self.name.as_slice(),
            &name_aad(&self.vault_id, version),
        )?;
        // Preserve the current epoch/target/policy: a membership vault's tombstone must
        // not degrade to epoch 0 (downgrade → an unreadable record).
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
        // Atomically: the vault tombstone + clearing the version history of all its items —
        // archived VK-encrypted versions of secrets must not survive deletion.
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

    /// **Cooperative hard-delete of a vault** (`purge`, server-tz §6.4) on a verified
    /// revoke signal: physically removes the vault record, ALL items (incl. tombstones),
    /// the ENTIRE version history, ALL membership manifests and grants, and the vault's epoch floor
    /// (atomically, via [`Storage::purge_vault_data`]), and **zeroizes the in-memory VK**
    /// (consumes `self` → `Drop` zeroizes `vk`).
    ///
    /// Unlike [`Vault::delete`] (tombstone — a logical deletion with a bumped
    /// version, surviving sync), `purge_vault` leaves neither
    /// ciphertext nor vault metadata on the device.
    ///
    /// **Best-effort/hygiene, NOT a remote-wipe:** data already synced to OTHER or
    /// modified clients is not revoked by this (enforcement is cooperative). Hard
    /// cryptographic revocation of access is provided by [`Vault::rotate_vk`] (VK rotation).
    pub fn purge_vault(self) -> Result<(), VaultError> {
        self.storage.purge_vault_data(&self.vault_id)?;
        // self (with vk: SymmetricKey + name: Zeroizing) goes out of scope →
        // ZeroizeOnDrop zeroizes the VK. Explicit drop for clarity.
        drop(self);
        Ok(())
    }

    /// The vault identifier.
    pub fn vault_id(&self) -> &[u8] {
        &self.vault_id
    }

    /// The decrypted vault name.
    pub fn name(&self) -> &[u8] {
        self.name.as_slice()
    }

    /// Renames the vault: re-encrypts the name under the VK with a bumped version and
    /// re-signs the record. Preserves the record's current `key_epoch`/`sync_target`/
    /// `cache_policy` (otherwise a membership vault would degrade to epoch 0 →
    /// an unreadable vault record, as items did before the fix).
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

    /// Puts (creates/updates) an item: generates a per-item key, wraps it under the
    /// VK, encrypts the content with binding, signs the version. Returns the version.
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
            // Timestamps are set by storage on write.
            created_at: 0,
            updated_at: 0,
            // The vault key's current epoch (NOT 0): in membership mode a record at
            // an epoch without a manifest / below the floor is rejected by verify_record_authority.
            key_epoch: self.key_epoch.get(),
        };
        self.storage.put_item(&record)?;
        self.storage.mark_item_dirty(&self.vault_id, item_id)?; // local edit → needs push
        Ok(version)
    }

    /// Returns the decrypted item (verifying the signature). `None` if absent or deleted.
    pub fn get_item(&self, item_id: &[u8]) -> Result<Option<DecryptedItem>, VaultError> {
        match self.storage.get_item(&self.vault_id, item_id)? {
            Some(r) if !r.tombstone => Ok(Some(self.decrypt_record(&r)?)),
            _ => Ok(None),
        }
    }

    /// Verifies the record's signature and decrypts its content (the shared path for
    /// the current version and historical ones).
    fn decrypt_record(&self, record: &ItemRecord) -> Result<DecryptedItem, VaultError> {
        let author = Ed25519VerifyingKey::from_bytes(&record.author_pubkey)
            .map_err(|_| VaultError::Format)?;
        let aad = item_aad(&self.vault_id, &record.item_id, record.version);
        let vo = VersionedObject::from_content(aad.clone(), &record.content_blob);
        // Locally, version rollback is excluded by storage monotonicity (anti-rollback on
        // write). TODO(Milestone 2, sync): use crypto::verify_no_rollback
        // against a trusted last-seen cursor (outside the replicated DB), to
        // catch snapshot-replay by swapping the whole DB file.
        verify_version(&author, &vo, &record.signature)
            .map_err(|_| VaultError::SignatureInvalid)?;
        // Defense-in-depth: the signature is valid — but is it valid under the
        // OWNER's/MEMBER's key? A swapped author_pubkey yields a self-consistent
        // signature under someone else's key.
        //
        // The vault mode is taken from the vault-level signal INSIDE
        // verify_record_authority (membership ⇔ there is a floor/manifest), NOT from
        // record.key_epoch — otherwise an untrusted DB downgrades a membership vault to
        // owner==author by swapping the unsigned key_epoch (P4 review, anti-rollback
        // bypass). In membership mode a record at an epoch without a manifest / below the floor /
        // from a non-member is rejected; in local mode — the former owner==author check.
        //
        // The anchor is the vault's pinned genesis owner (resolved once in `open`): for
        // own vaults it equals the local keyset's pubkey; for a teammate's shared vault
        // it is the TOFU-pinned creator, so a member verifies against the TRUE owner.
        verify_record_authority(
            self.storage,
            &self.vault_id,
            &record.author_pubkey,
            record.key_epoch,
            &self.genesis_owner,
        )?;

        // read-fallback to the pre-round-2 item wrapping/content (see the *_compat helpers).
        let item_key = unwrap_key_compat(&self.vk, &record.wrapped_item_key, &record.item_id)?;
        let content = aead_decrypt_compat(&item_key, &record.content_blob, &aad)?;

        Ok(DecryptedItem {
            item_id: record.item_id.clone(),
            item_type: record.item_type,
            version: record.version,
            content: Zeroizing::new(content),
        })
    }

    /// Like [`Vault::put_item`], but archives the previous version into history (retention
    /// [`HISTORY_RETAIN`]). For secrets with a version history (password/note).
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
            // The vault key's current epoch (NOT 0) — see put_item.
            key_epoch: self.key_epoch.get(),
        };
        self.storage.archive_and_put(&record, HISTORY_RETAIN)?;
        self.storage
            .mark_item_dirty(&self.vault_id, &record.item_id)?; // edit → push
        Ok(version)
    }

    /// The item versions available for reveal: the current one (if live) + archived ones.
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

    /// Decrypts a specific item version (current or historical), verifying
    /// its signature under its AAD. `None` if there is no such version.
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

    /// Metadata of non-deleted items (without decrypting the content).
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

    /// Builds a signed tombstone record (empty content, version `version`).
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
            // The vault key's current epoch (NOT 0) — a tombstone also passes
            // verify_record_authority in membership mode.
            key_epoch: self.key_epoch.get(),
        })
    }

    /// Deletes an item (tombstone with a bumped version). The tombstone and clearing the version
    /// history are **atomic** (one transaction): a crash will not leave a tombstone with live
    /// history, otherwise the deleted plaintext would "resurrect" through `get_item_version`.
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

    /// Renames (moves) an item: creates `new_id` with the same type and
    /// content, marks `old_id` as a tombstone. The per-item key and binding (AAD)
    /// are re-created under the new id. Errors if `new_id` is already taken by a live item.
    /// Sync semantics: rename = delete the old + create the new (as in
    /// most systems), the version history of the old id is cut off by the tombstone.
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
        // Atomically: create the new id and bury the old one in one transaction, so
        // a failure between steps does not leave the content live under both ids. The tombstone
        // and clearing the old id's history are inlined (not via delete_item, otherwise there would be
        // a nested BEGIN).
        self.storage.transaction(|| {
            self.put_item(new_id, item.item_type, item.content.as_slice())?;
            let tomb = self.tombstone_record(old_id, item.item_type, item.version + 1)?;
            self.storage.put_item(&tomb)?;
            self.storage.mark_item_dirty(&self.vault_id, old_id)?; // old-id tombstone → push
            self.storage.clear_item_history(&self.vault_id, old_id)?;
            Ok::<(), VaultError>(())
        })
    }

    /// **Establishes/extends vault membership** (server-tz §5): if there is no manifest
    /// yet — creates the genesis set at epoch 1; otherwise extends the verified set
    /// of the latest epoch and issues a new manifest at `latest+1`. Per-member grants
    /// wrap the **current VK** (`self.vk`) under each recipient's X25519 pubkey.
    ///
    /// `members` — the full target set (member-id = Ed25519 pubkey + role).
    /// `x25519_by_ed` — the mapping `(member_ed25519_pub, member_x25519_pub)` for
    /// each member receiving a VK wrapping. The owner (`self.keyset`) must be in the
    /// set as `Admin` (otherwise a later record from them will not pass authority).
    ///
    /// **The VK does not leave:** the wrapping is built internally (free `add_member`). This is the
    /// write path for manifest+grants with self-verify before persist; the read path
    /// self-sufficiently re-verifies the chain. Returns the epoch of the written manifest.
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
        // grants: (recipient_x25519, member_ed25519, role) for each member
        // whose x25519 is known.
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

        // Re-anchor the vault record onto the fresh `key_epoch` (server-tz §5/§6.2): otherwise
        // the record stays at key_epoch=0 while the vault is already in membership mode — then
        // `verify_record_authority` looks for a nonexistent manifest@0 and the audit fails.
        // The VK does not change (this is not a rotation) — we re-sign the same wrapping with
        // version+1 and the new epoch. We do this ONLY when the record's owner
        // (`self.keyset` = genesis_owner, the author and recipient of `wrapped_vk`) is in
        // the verified set@key_epoch AND CAN WRITE TO IT (`can_write`, not just
        // `contains`) — otherwise a record they re-sign would be authorized as a Viewer and
        // `verify_record_authority` would reject it (the vault becomes unreadable). The owner is always Admin on
        // the normal path; the check is defense-in-depth against a Viewer-owner set.
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
        // Raise the in-memory epoch, so that put_item on THIS same instance after
        // establishing membership stamps the current epoch (not 0). A re-opened
        // vault reads it from the vault record in Vault::open.
        self.key_epoch.set(key_epoch);
        Ok(key_epoch)
    }

    /// Changes the vault's cache-policy (server-tz §6.6): version+1, re-signing the record,
    /// `put_vault`. `cache_policy` is open metadata (outside the signed
    /// content), but the record is re-signed with a new version anyway (LWW).
    pub fn set_cache_policy(&mut self, policy: CachePolicy) -> Result<(), VaultError> {
        let version = self.version + 1;
        let name_blob = aead_encrypt(
            &self.vk,
            self.name.as_slice(),
            &name_aad(&self.vault_id, version),
        )?;
        // preserve the current key_epoch/sync_target from the DB record.
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

    /// Wraps the VK under the recipient's X25519 public key, returning
    /// `Enc(VK, recipient_pub)` with the same domain-separated binding
    /// `vk_wrap_info(vault_id, recipient_ed25519, key_epoch)` as the production
    /// per-member grants (F17) — so the envelope is opened exactly via
    /// [`crate::open_grant`] by the recipient, and is not bound to the raw `vault_id`.
    /// Bound to the vault's current `key_epoch`.
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

    /// **Eager Vault Key rotation** (server-tz §6.2 / §1.1) for a vault **with membership**.
    ///
    /// Generates a new `VK'`, raises the epoch (`new = current + 1`), issues
    /// a new admin-signed manifest over `remaining_members` (a sigchain from
    /// the previous epoch), per-member grants under `VK'` (binding
    /// `vk_wrap_info(vault_id, member, new_epoch)`), **re-wraps** each live item
    /// under `VK'` (the plaintext and per-item key do not change — only the key wrapping
    /// and the record's epoch change), updates the vault record (`key_epoch=new`, `version+1`,
    /// the owner's `wrapped_vk` under `VK'`) and raises the **epoch floor** to `new`. ALL in
    /// one transaction (atomically: a partial failure → a consistent rollback).
    ///
    /// **Scope (D-SCOPE):** applies ONLY to vaults with a manifest at the current epoch.
    /// A single-owner local vault (no manifest) → `VaultError::NotAMember` (not
    /// rotated; D2 from P3 — their behavior does not change).
    ///
    /// `admin_keyset` must be `Admin` in the verified set of the current epoch, otherwise
    /// `VaultError::AuthorityInvalid`. A revoked member is simply **absent** from
    /// `remaining_members`/`grants` → does not receive a grant under `VK'`.
    ///
    /// `grants` — `(recipient_x25519_pub, member_ed25519_pub, role)` for each
    /// recipient of the `VK'` wrapping. Returns the new epoch.
    ///
    /// **Purity boundary:** the method takes `&self`, updates only storage; the in-memory
    /// `self.vk`/`self.version` stay old (valid for re-wrapping the OLD records
    /// before commit). After rotation the `Vault` instance is stale — to work under `VK'`
    /// it should be re-opened (`Vault::open`/grant).
    ///
    /// **Reading pre-rotation history** is not covered (server-tz §6.2): the re-wrap
    /// touches only the current generation of item keys; a full seed-chain is
    /// ⏳ LATER (do not roll your own crypto).
    pub fn rotate_vk(
        &self,
        admin_keyset: &UnlockedKeyset,
        remaining_members: &[Member],
        grants: &[(Vec<u8>, Vec<u8>, MemberRole)],
    ) -> Result<u64, VaultError> {
        // genesis anchor = the vault creator's pubkey (= the owner keyset that opened the vault).
        let genesis_owner = self.keyset.signing.verifying.to_bytes().to_vec();

        // 0) vault record + current membership epoch.
        let vrec = self
            .storage
            .get_vault(&self.vault_id)?
            .ok_or(VaultError::NotFound)?;
        // D-SCOPE: rotation only for a vault with a manifest. The current membership epoch =
        // the highest epoch of an existing manifest (the vault record of a freshly created
        // vault carries key_epoch=0, while the genesis manifest is at epoch 1; they
        // synchronize only starting from the first rotation). No manifest →
        // a single-owner local vault → not rotated (D2 from P3).
        let current_epoch = match self.storage.latest_membership_epoch(&self.vault_id)? {
            Some(e) => e,
            None => return Err(VaultError::NotAMember),
        };
        // verify the chain up to current_epoch and that the admin is Admin@current.
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

        // 3) new manifest @ new_epoch (sigchain from prev) + self-verify.
        let manifest = build_manifest(admin_keyset, &self.vault_id, new_epoch, remaining_members)?;
        let verified_new = verify_manifest(&manifest, &self.vault_id, Some(&prev), &genesis_owner)?;

        // P4 review (hardening): the re-wrapped items AND the new vault record are signed by
        // self.keyset (== genesis_owner). If the admin != owner and drops
        // the owner from remaining_members, these records at new_epoch are authored by
        // a non-member → verify_record_authority will later return NotAuthorized (the vault becomes
        // unreadable). We reject such a rotation BEFORE any writes: the re-wrap's author
        // must be a member@new_epoch.
        if !verified_new.can_write(&genesis_owner) {
            return Err(VaultError::NotAMember);
        }

        // 4) per-member grants under VK' + verify against the new set.
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

        // 6) new vault record: the owner's wrapped_vk under VK', key_epoch=new, version+1.
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

        // 5) re-wrap live items under VK' (in advance, to keep the transaction short).
        let live = self.storage.list_items(&self.vault_id)?;
        let mut rewrapped = Vec::with_capacity(live.len());
        for it in &live {
            rewrapped.push(self.rewrap_item(it, &vk_prime, new_epoch)?);
        }

        // ATOMICALLY: manifest + grants + items + vault record + epoch floor.
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

        // Raise the in-memory epoch: although `self.vk`/`self.version` are stale (see
        // the docstring — to work under VK' the vault is re-opened), we reflect the new epoch
        // in the instance for consistency of Debug/repeated reads before re-opening.
        self.key_epoch.set(new_epoch);
        Ok(new_epoch)
    }

    /// Re-wraps one live item under the new VK: unwraps the per-item key with the old
    /// VK, re-wraps it under `vk_prime` (the wrapping AAD = item_id, independent of
    /// the epoch), bumps the version, `key_epoch=new_epoch`, **re-encrypts the content with the same
    /// per-item key** under the new-version AAD (the plaintext is identical) and
    /// re-signs. Returns the ready record (storage puts it in a transaction).
    fn rewrap_item(
        &self,
        record: &ItemRecord,
        vk_prime: &SymmetricKey,
        new_epoch: u64,
    ) -> Result<ItemRecord, VaultError> {
        // 1) per-item key from the old VK (AAD = item_id). read-fallback: a legacy vault
        //    (before round 2) is read with the old keywrap, while the re-wrap below uses the current one.
        let item_key = unwrap_key_compat(&self.vk, &record.wrapped_item_key, &record.item_id)?;
        // 2) decrypt the content under the OLD AAD (the record's current version).
        let old_aad = item_aad(&self.vault_id, &record.item_id, record.version);
        let plaintext = aead_decrypt_compat(&item_key, &record.content_blob, &old_aad)?;
        // 3) bump the version; new AAD; re-encrypt with the same per-item key.
        let new_version = record
            .version
            .checked_add(1)
            .ok_or(VaultError::EpochInvalid)?;
        let new_aad = item_aad(&self.vault_id, &record.item_id, new_version);
        let content_blob = aead_encrypt(&item_key, &plaintext, &new_aad)?;
        // 4) re-wrap the per-item key under VK' (AAD = item_id).
        let wrapped_item_key = wrap_key(vk_prime, &item_key, &record.item_id)?;
        // 5) re-sign over (new_aad, new content_blob).
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

    /// Read-only integrity audit of the vault: re-verifies the Ed25519 signature of
    /// the vault record and **all** item records (including tombstones) against their
    /// `author_pubkey`, and checks the author's authority itself **member-aware**.
    /// Catches blob corruption (signature does not verify), author swapping (a valid signature
    /// under someone else's key), stale-epoch/non-member records and structural garbage —
    /// WITHOUT unwrapping the VK and decrypting the content. The report contains not a byte of a secret.
    ///
    /// **Authority (D-VERIFY-CHAIN, P4):** the mode is determined by the **vault-level
    /// signal** ([`vault_is_membership_mode`]), NOT the `key_epoch` of an individual record
    /// (otherwise a downgrade by swapping the unsigned `key_epoch` would pass the audit). In
    /// membership mode (there is a floor OR at least one manifest) the author is verified by
    /// the full D1 authority chain up to genesis, requires manifest@`key_epoch` AND
    /// `key_epoch >= floor` (anti-rollback, §1.1) via [`verify_record_authority`];
    /// any violation → `NotAuthorized`. In single-owner mode (neither a floor,
    /// nor manifests — D2, local vaults) — the former `author == owner` check.
    ///
    /// `Err` only on a top-level storage failure; bad signatures/authors are
    /// report data.
    pub fn verify_chain(&self) -> Result<IntegrityReport, VaultError> {
        // Anchor the audit on the vault's pinned genesis owner (own vault → the local
        // keyset; a teammate's shared vault → the TOFU-pinned creator). Using the local
        // keyset here would make a member's audit re-verify the D1 chain against their
        // OWN key and reject every owner-authored record.
        let trusted = self.genesis_owner.as_slice();
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
                    trusted,
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
                    trusted,
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
        // Archived versions (secret history) are also signed — we audit them too, otherwise
        // swapping an old version in item_history would go unnoticed until reveal.
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

// --- associated data helpers ---

fn name_aad(vault_id: &[u8], version: u64) -> AssociatedData {
    AssociatedData::new(vault_id.to_vec(), b"__vault_name__".to_vec(), version)
}

fn vault_record_aad(vault_id: &[u8], version: u64) -> AssociatedData {
    AssociatedData::new(vault_id.to_vec(), b"__vault__".to_vec(), version)
}

fn item_aad(vault_id: &[u8], item_id: &[u8], version: u64) -> AssociatedData {
    AssociatedData::new(vault_id.to_vec(), item_id.to_vec(), version)
}

// --- read-fallback to the pre-round-2 format (see SECURITY.md → On-disk format changes) ---
//
// Vaults created before round 2 (crypto-agility binding) are wrapped with the old schemes:
// owner-VK with info=raw vault_id (not vk_wrap_info), item keys without the keywrap
// domain tag, content/name without the header binding in the AAD. The record signature did NOT change
// (old records verify). These helpers read both the current and the pre-round-2
// format: first the current scheme, on failure — the frozen legacy codec. New
// records (put_item/set_name/rotate) are already written with the current scheme, so any
// modification naturally "pulls" the record forward; plain reading of old
// data stays available without rewrite/re-sign/sync noise.

/// Opens the owner-VK: the current `vk_wrap_info` binding, on failure — pre-round-2
/// (`info` = raw `vault_id`). Another keyset passes neither → `Decrypt`.
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
    // pre-round-2: the owner wrapping was bound to the raw vault_id (without owner_ed/epoch).
    open_key_with_secret(secret, wrapped_vk, vault_id).map_err(|_| VaultError::Decrypt)
}

/// AEAD decryption with a fallback to pre-round-2 (the header is not bound to the AAD).
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

/// keywrap-unwrap with a fallback to pre-round-2 (without the domain tag and header binding).
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

// --- signing/verification of the vault record ---

fn vault_signed_content(wrapped_vk: &[u8], name_blob: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(wrapped_vk.len() + name_blob.len());
    out.extend_from_slice(wrapped_vk);
    out.extend_from_slice(name_blob);
    out
}

/// Builds a signed vault record with an explicit `key_epoch`/`sync_target`/
/// `cache_policy`/`sync_tenant`. The only constructor of vault records: `create`
/// (genesis, epoch 0, empty `sync_tenant`), `set_name`/`delete` (preserve
/// the current epoch/target/policy/tenant), `set_cache_policy`/`establish`/`rotate`
/// (the epoch grows, target/policy/tenant are preserved). Epoch 0 in membership mode
/// must not be written (downgrade). `sync_tenant` is an open routing label OUTSIDE
/// the signature (the signature does not cover it): rebuilds carry it over 1:1 from the DB.
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
        // sync_tenant is an open routing label, OUTSIDE the signed content
        // (like sync_target/cache_policy): a re-sign does not cover it, existing
        // signatures stay valid. Constructors pass the current value
        // (genesis — empty; rebuilds — preserve the current one from the DB record).
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

// --- record author authorization: member-set@epoch OR owner==author (D2) ---

/// Determines the vault mode from the **vault-level trusted signal**, and NOT from
/// the `key_epoch` of an individual (potentially swapped) record. A vault is considered
/// a membership vault if it has an epoch floor (an anti-rollback marker,
/// set by rotation) OR at least one membership manifest. Otherwise it is
/// a single-owner local vault (D2).
///
/// ## Why vault-level, not per-record (anti-rollback bypass, P4 review)
/// The previous version chose the mode from `get_membership_manifest(record.key_epoch)`:
/// `key_epoch` is an **unsigned** record field. An untrusted DB/sync peer set
/// a validly-owner-signed record to `key_epoch=0` (an epoch without a manifest), and the read path
/// "degraded" to the single-owner check (owner==author passed), skipping
/// the epoch floor and the D1 chain. That way a pre-rotation/below-floor record was accepted by both
/// `verify_chain` and the live decrypt path. Tying the mode to the vault-level signal
/// closes the downgrade: a record with an epoch without a manifest in membership mode is rejected.
fn vault_is_membership_mode(storage: &Storage, vault_id: &[u8]) -> Result<bool, VaultError> {
    // A pinned per-vault anchor (A0, someone else's vault) is also a membership-mode signal:
    // without it, in the window "the anchor is pinned but the manifest is not yet synced" a
    // teammate-author's record would pass through the single-owner branch (author==anchor) WITHOUT the D1 chain.
    // Only someone else's vaults are pinned, so one's own (without an anchor) are unaffected.
    Ok(storage.get_vault_epoch_floor(vault_id)?.is_some()
        || storage.latest_membership_epoch(vault_id)?.is_some()
        || storage.get_vault_trust_anchor(vault_id)?.is_some())
}

/// Verifies the record author's right (spec §13 item 8). The **vault mode** is determined
/// by the vault-level signal ([`vault_is_membership_mode`]), NOT `record_epoch`:
///
/// - **membership mode** (there is an epoch floor OR at least one manifest): requires
///   `record_epoch >= epoch floor` AND the presence of manifest@`record_epoch` (its absence =
///   a downgrade attempt → `EpochInvalid`) AND `author ∈ members@epoch` by
///   a re-verified D1 chain from genesis. No fallback to owner==author.
/// - **single-owner local vault** (neither a floor nor manifests): `author ==
///   genesis_owner`.
///
/// `genesis_owner` — the trusted anchor: the vault creator's pubkey (= the owner keyset
/// for local vaults). Does not panic: any violation is a typed `VaultError`.
///
/// ## Self-sufficiency of the read path (untrusted-DB / sync-ready, ARCH.md)
/// This path does **NOT trust** the fact that the manifest is in storage. It re-verifies
/// the **full D1 chain** of membership from genesis (epoch 1) to
/// `record_epoch` from scratch, anchoring on the pinned `genesis_owner` (see
/// [`crate::membership::verify_chain_to_epoch`]). That way an operator-injected
/// self-consistent manifest (author=attacker, members=[attacker]) at any
/// epoch is rejected: the chain from genesis does not lead to the attacker. This is a hard
/// precondition before a member-via-grant obtains the VK and before any sync (P4) —
/// the read path must rely on the anchor, not on storage.
pub fn verify_record_authority(
    storage: &Storage,
    vault_id: &[u8],
    author_pubkey: &[u8],
    record_epoch: u64,
    genesis_owner: &[u8],
) -> Result<(), VaultError> {
    if !vault_is_membership_mode(storage, vault_id)? {
        // D2: single-owner local vault — the former owner==author.
        return if author_pubkey == genesis_owner {
            Ok(())
        } else {
            Err(VaultError::NotAMember)
        };
    }
    // membership mode (vault-level): a downgrade to owner==author is forbidden.
    // (b) anti-rollback: the epoch floor (default 0).
    let floor = storage.get_vault_epoch_floor(vault_id)?.unwrap_or(0);
    if record_epoch < floor {
        return Err(VaultError::EpochInvalid);
    }
    // A record at an epoch without a manifest in membership mode — a downgrade attempt.
    // (The chain cannot anchor on a missing manifest@record_epoch.)
    if storage
        .get_membership_manifest(vault_id, record_epoch)?
        .is_none()
    {
        return Err(VaultError::EpochInvalid);
    }
    // (a) Re-verify the D1 chain from genesis_owner to record_epoch —
    // self-sufficiently, without trusting storage. Returns the verified set@epoch.
    let members =
        crate::membership::verify_chain_to_epoch(storage, vault_id, record_epoch, genesis_owner)?;
    // author ∈ the verified set@epoch.
    if !members.contains(author_pubkey) {
        return Err(VaultError::NotAMember);
    }
    // ...AND has a role with the right to write CONTENT (Editor/Admin). A Viewer (read-only)
    // may not author item/vault records: otherwise a read-only member could create,
    // overwrite (LWW with a version bump) and place a tombstone on the records of a shared
    // vault, and other members' verify-before-apply would accept them as authentic —
    // a bypass of the Viewer/Editor/Admin role (write-integrity gap). Manifests/grants
    // are gated separately (admin authority in verify_manifest/verify_grant).
    if !members.can_write(author_pubkey) {
        return Err(VaultError::AuthorityInvalid);
    }
    Ok(())
}

// --- integrity audit (verify_chain) ---

/// The reason a record failed the integrity check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IntegrityFailure {
    /// The signature does not verify under the claimed `author_pubkey` (corruption of
    /// content/metadata or a damaged sig blob).
    SignatureInvalid,
    /// The record's `author_pubkey` does not match the vault's trusted owner —
    /// author swapping (the signature may be valid under someone else's key).
    AuthorMismatch,
    /// The `author_pubkey`/signature are structurally invalid (do not parse).
    Malformed,
    /// The record's author is not in the vault's signed member-set at its epoch, or
    /// the record's epoch is below the trusted floor (anti-rollback) — for membership vaults.
    NotAuthorized,
}

/// One problematic record in the integrity report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityIssue {
    /// The record's `item_id`; empty for the vault record itself.
    pub item_id: Vec<u8>,
    /// The version of the record the problem relates to.
    pub version: u64,
    /// Whether this is a tombstone (deleted records are also checked).
    pub tombstone: bool,
    /// The machine-readable reason.
    pub failure: IntegrityFailure,
}

/// A read-only report on the vault's integrity. Without secrets and without plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityReport {
    /// `true` ⇔ `issues` is empty (the vault record and all items, including tombstones, are ok).
    pub ok: bool,
    /// How many records were checked (the vault record + all item records with tombstones).
    pub checked: u64,
    /// The problematic records (the vault record is marked with an empty `item_id`).
    pub issues: Vec<IntegrityIssue>,
}

/// Checks one item record: parsing the author → `Malformed`; the signature over
/// `(AAD vault_id+item_id+version, content_blob)` → `SignatureInvalid`; comparing
/// `author_pubkey` with the trusted owner → `AuthorMismatch`. `None` == ok.
/// Does not unwrap the VK and does not decrypt the content.
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

/// Member-aware check of a record's authority for [`Vault::verify_chain`]. The vault
/// mode is determined by the **vault-level signal** ([`vault_is_membership_mode`]), and
/// NOT the `record_epoch` of an individual record (otherwise a downgrade by swapping the unsigned
/// `key_epoch` would pass the audit — P4 review). In membership mode the authority is checked
/// via [`verify_record_authority`] (D1 chain + floor + manifest@epoch);
/// any violation → `NotAuthorized`. In single-owner mode — the check
/// `author == trusted_owner` (→ `AuthorMismatch` on a mismatch). Storage errors
/// inside the audit are treated conservatively as `NotAuthorized` (not a panic);
/// top-level storage calls in `verify_chain` return `Err` via `?`.
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
            // single-owner model (D2): no floor and no manifests.
            if author_pubkey == trusted_owner {
                None
            } else {
                Some(IntegrityFailure::AuthorMismatch)
            }
        }
        Err(_) => Some(IntegrityFailure::NotAuthorized),
    }
}

/// Checks only the structure+signature of an item record (without comparing the author to the owner
/// — the authority is checked by [`check_record_authority`]).
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

/// Analog of [`item_sig_failure`] for a vault record.
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

/// Analog of [`check_item_record`] for a vault record (the signature over
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
        // SecretKeyOnly → without Argon2id, fast.
        create_account(None, KdfParams::recommended()).unwrap().2
    }

    /// Forges a pre-round-2 ("Scheme A") vault directly into storage: owner-VK with HPKE-`info` =
    /// the raw `vault_id` (not `vk_wrap_info`), name and item content without the header binding
    /// in the AAD, item key without the keywrap domain tag. The signature is CURRENT (the signing
    /// mechanism did not change, which is why such records verify on the user's side).
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
        // the owner wrapping was bound to the raw vault_id (before round 2).
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

        // boot path: open (owner-VK + name) and get_item (item key + content) — all
        // via the read-fallback to pre-round-2.
        let v = Vault::open(&st, &ks, b"v-legacy").unwrap();
        assert_eq!(v.name(), b"Old Vault");
        let got = v.get_item(b"ssh-old").unwrap().unwrap();
        assert_eq!(got.content.as_slice(), b"OLD-SECRET-CONTENT");
        assert_eq!(got.item_type, 1);
    }

    #[test]
    fn wrong_keyset_still_fails_on_legacy_vault() {
        // the fallback must not open a legacy vault with ANOTHER keyset — both schemes fail.
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
        // Regression: the current format opens on the first attempt, the fallback does not interfere.
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
