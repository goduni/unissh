use unissh_storage::Storage;

#[test]
fn trust_mutations_invalidate_but_reads_and_sync_metadata_do_not() {
    let s = Storage::open_in_memory(&[7; 32]).unwrap();
    let initial = s.automation_revision().unwrap();
    s.set_meta("test", b"value").unwrap();
    s.get_known_host("example", 22).unwrap();
    assert_eq!(initial, s.automation_revision().unwrap());
    s.put_known_host("example", 22, b"test-key").unwrap();
    let pinned = s.automation_revision().unwrap();
    assert_ne!(initial, pinned);
    s.remove_known_host("example", 22).unwrap();
    assert_ne!(pinned, s.automation_revision().unwrap());
    let reopened = Storage::open_in_memory(&[7; 32]).unwrap();
    assert_ne!(initial[0], reopened.automation_revision().unwrap()[0]);
}

#[test]
fn another_connection_cannot_mutate_trust_without_invalidating_the_reader() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("instance.db");
    let reader = Storage::open(&path, &[9; 32]).unwrap();
    let writer = Storage::open(&path, &[9; 32]).unwrap();
    let before = reader.automation_revision().unwrap();
    writer
        .put_known_host("example", 22, b"replacement-key")
        .unwrap();
    assert_ne!(reader.automation_revision().unwrap(), before);
    let stable = reader.automation_revision().unwrap();
    reader.list_known_hosts().unwrap();
    assert_eq!(reader.automation_revision().unwrap(), stable);
}

#[test]
fn recordings_do_not_revoke_but_cross_type_changes_do() {
    use unissh_storage::ItemRecord;
    let s = Storage::open_in_memory(&[7; 32]).unwrap();
    let mut item = ItemRecord {
        vault_id: b"v".to_vec(),
        item_id: b"r".to_vec(),
        item_type: 10,
        content_blob: vec![],
        wrapped_item_key: vec![],
        version: 1,
        tombstone: false,
        signature: vec![],
        author_pubkey: vec![],
        created_at: 0,
        updated_at: 0,
        key_epoch: 0,
    };
    let before = s.automation_revision().unwrap();
    s.put_item(&item).unwrap();
    item.version += 1;
    item.content_blob = vec![1];
    s.put_item(&item).unwrap();
    item.version += 1;
    item.tombstone = true;
    s.put_item(&item).unwrap();
    assert_eq!(before, s.automation_revision().unwrap());
    for ty in [1, 10, 2, 10] {
        let before = s.automation_revision().unwrap();
        item.version += 1;
        item.item_type = ty;
        s.put_item(&item).unwrap();
        assert_ne!(before, s.automation_revision().unwrap());
    }
}

#[test]
fn external_recording_writes_remain_conservative() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let reader = Storage::open(&path, &[8; 32]).unwrap();
    let writer = Storage::open(&path, &[8; 32]).unwrap();
    let before = reader.automation_revision().unwrap();
    let local = writer.automation_revision().unwrap();
    writer
        .put_item(&unissh_storage::ItemRecord {
            vault_id: b"v".to_vec(),
            item_id: b"r".to_vec(),
            item_type: 10,
            content_blob: vec![],
            wrapped_item_key: vec![],
            version: 1,
            tombstone: false,
            signature: vec![],
            author_pubkey: vec![],
            created_at: 0,
            updated_at: 0,
            key_epoch: 0,
        })
        .unwrap();
    assert_eq!(local, writer.automation_revision().unwrap());
    assert_ne!(before, reader.automation_revision().unwrap());
    writer.purge_vault_data(b"v").unwrap();
    assert_eq!(local, writer.automation_revision().unwrap());
}
