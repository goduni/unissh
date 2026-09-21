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
