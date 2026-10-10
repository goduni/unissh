//! The terminal workspace layout: stored encrypted per instance and tied to its unlock.
use unissh_ffi::{Core, FfiError};

#[test]
fn workspace_is_local_encrypted_and_locked_with_the_instance() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("instance.db");
    let keyset = dir.path().join("keyset.bin");
    let core = Core::new(db.display().to_string(), keyset.display().to_string());
    assert!(matches!(
        core.terminal_workspace_load(),
        Err(FfiError::Locked)
    ));
    let secret = core.create_account(None).unwrap();
    let (epoch, document) = core.terminal_workspace_load().unwrap();
    assert_eq!(document, None);
    let document =
        r#"{"version":1,"activeVaultId":"v","vaults":{"v":{"title":"private-workspace-label"}}}"#;
    let revision = core.automation_revision().unwrap();
    let fingerprint = core.automation_access_fingerprint().unwrap();
    core.terminal_workspace_save(epoch, document.into())
        .unwrap();
    assert_eq!(
        core.terminal_workspace_load().unwrap().1.as_deref(),
        Some(document)
    );
    // Version 2 adds named layouts; the UI migrates the existing automatic layout.
    let document = r#"{"version":2,"activeVaultId":"v","vaults":{"v":{"tabs":[]}},"named":{"v":[{"id":"saved","name":"private-workspace-label","layout":{"tabs":[]}}]}}"#;
    core.terminal_workspace_save(epoch, document.into())
        .unwrap();
    // Moving a divider must not revoke unrelated MCP permissions.
    assert_eq!(core.automation_revision().unwrap(), revision);
    assert_eq!(core.automation_access_fingerprint().unwrap(), fingerprint);
    // Unsupported versions cannot overwrite an existing layout.
    assert!(core
        .terminal_workspace_save(epoch, r#"{"version":3}"#.into())
        .is_err());
    assert!(core
        .terminal_workspace_save(epoch, "not json".into())
        .is_err());
    assert_eq!(
        core.terminal_workspace_load().unwrap().1.as_deref(),
        Some(document)
    );
    // Local metadata does not create vault content or sync objects.
    assert!(core.list_vaults().unwrap().is_empty());
    core.lock();
    assert!(matches!(
        core.terminal_workspace_load(),
        Err(FfiError::Locked)
    ));
    assert!(matches!(
        core.terminal_workspace_save(epoch, document.into()),
        Err(FfiError::Locked)
    ));
    core.unlock(None, secret.clone()).unwrap();
    assert!(matches!(
        core.terminal_workspace_save(epoch, document.into()),
        Err(FfiError::Locked)
    ));
    core.lock();
    drop(core);
    let bytes = std::fs::read(&db).unwrap();
    assert!(!bytes
        .windows(b"private-workspace-label".len())
        .any(|w| w == b"private-workspace-label"));
    let reopened = Core::new(db.display().to_string(), keyset.display().to_string());
    reopened.unlock(None, secret).unwrap();
    assert_eq!(
        reopened.terminal_workspace_load().unwrap().1.as_deref(),
        Some(document)
    );
}
