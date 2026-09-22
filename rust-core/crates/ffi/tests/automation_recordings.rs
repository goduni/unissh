use base64::{engine::general_purpose::STANDARD, Engine};
use unissh_ffi::{ConnectionProfile, Core, ProfileAuth};

fn setup() -> (tempfile::TempDir, std::sync::Arc<Core>, String) {
    let dir = tempfile::tempdir().unwrap();
    let core = Core::new(
        dir.path().join("db").to_str().unwrap().into(),
        dir.path().join("keyset").to_str().unwrap().into(),
    );
    let kit = core.create_account(None).unwrap();
    core.create_vault("v".into(), "V".into()).unwrap();
    core.save_connection(
        "v".into(),
        ConnectionProfile {
            profile_id: "h".into(),
            uid: String::new(),
            label: "Host".into(),
            host: "example".into(),
            port: 22,
            user: "user".into(),
            auth: ProfileAuth::PromptPassword,
            proxy: None,
            username_template: None,
            jumps: vec![],
            tags: vec![],
            startup_snippet_ids: vec![],
            record_sessions: true,
            agent_forward: false,
        },
    )
    .unwrap();
    (dir, core, kit)
}
fn cast(core: &Core, id: &str) -> serde_json::Value {
    let body = core.get_recording("v".into(), format!("mcp-{id}")).unwrap();
    serde_json::from_str(body.lines().next().unwrap()).unwrap()
}

#[test]
fn records_original_command_binary_streams_and_preserves_revision() {
    let (_dir, core, _) = setup();
    let target = core.automation_target("v".into(), "h".into()).unwrap();
    let rec = core
        .automation_recording(&target, "one", "Agent", "printf hello", Some("/tmp"))
        .unwrap()
        .unwrap();
    rec.data(false, b"hello\n");
    rec.data(true, &[0, 255, 1]);
    rec.exited(Some(7));
    rec.finish("failed");
    assert_eq!(rec.status(), "saved");
    assert_eq!(core.automation_revision().unwrap(), target.revision);
    let m = cast(&core, "one")["unissh_mcp"].clone();
    assert_eq!(m["command"], "printf hello");
    assert_eq!(m["cwd"], "/tmp");
    assert_eq!(m["outcome"], "completed");
    assert_eq!(m["exit_code"], 7);
    assert_eq!(
        STANDARD
            .decode(m["events"][1]["data"].as_str().unwrap())
            .unwrap(),
        [0, 255, 1]
    );
    assert_eq!(m["events"][1]["stream"], "stderr");
    rec.data(false, b"late");
    rec.finish("cancelled");
    assert_eq!(core.list_recordings("v".into()).unwrap().len(), 1);
    assert!(core
        .automation_recording(&target, "one", "Agent", "other", None)
        .is_err());
    core.delete_recording("v".into(), "mcp-one".into()).unwrap();
    assert_eq!(core.automation_revision().unwrap(), target.revision);
}

#[test]
fn lock_flushes_partial_capture_and_late_handle_cannot_write_after_unlock() {
    let (_dir, core, kit) = setup();
    let target = core.automation_target("v".into(), "h".into()).unwrap();
    let rec = core
        .automation_recording(&target, "lock", "Agent", "sleep 30", None)
        .unwrap()
        .unwrap();
    rec.data(false, b"before lock");
    core.lock();
    assert_eq!(rec.status(), "saved");
    core.unlock(None, kit).unwrap();
    rec.data(false, b"after lock");
    rec.exited(Some(0));
    rec.finish("completed");
    let m = cast(&core, "lock")["unissh_mcp"].clone();
    assert_eq!(m["outcome"], "interrupted");
    assert_eq!(m["events"].as_array().unwrap().len(), 1);
    assert!(core
        .automation_recording(&target, "stale", "Agent", "true", None)
        .is_err());
}

#[test]
fn preference_limits_and_failure_outcomes() {
    let (_dir, core, _) = setup();
    let target = core.automation_target("v".into(), "h".into()).unwrap();
    for outcome in ["failed", "cancelled"] {
        let rec = core
            .automation_recording(&target, outcome, "Agent", "cmd", None)
            .unwrap()
            .unwrap();
        rec.data(false, &vec![b'x'; 2 * 1024 * 1024]);
        rec.finish(outcome);
        assert_eq!(cast(&core, outcome)["unissh_mcp"]["outcome"], outcome);
        let list = core.list_recordings("v".into()).unwrap();
        assert!(list
            .iter()
            .all(|r| r.truncated && r.size_bytes < 8 * 1024 * 1024));
    }
    let mut profile = core.get_connection("v".into(), "h".into()).unwrap();
    profile.record_sessions = false;
    core.save_connection("v".into(), profile).unwrap();
    let target = core.automation_target("v".into(), "h".into()).unwrap();
    assert!(core
        .automation_recording(&target, "disabled", "Agent", "true", None)
        .unwrap()
        .is_none());
}

#[test]
fn tiny_events_and_escaped_binary_stay_bounded_and_save_errors_are_visible() {
    let (_dir, core, _) = setup();
    let target = core.automation_target("v".into(), "h".into()).unwrap();
    let rec = core
        .automation_recording(&target, "tiny", "Agent", "binary", None)
        .unwrap()
        .unwrap();
    for _ in 0..8200 {
        rec.data(true, &[0x7f; 64]);
    }
    rec.finish("cancelled");
    let meta = core.list_recordings("v".into()).unwrap().remove(0);
    assert!(meta.truncated);
    assert!(meta.size_bytes < 8 * 1024 * 1024);
    let rec = core
        .automation_recording(&target, "lost-vault", "Agent", "cmd", None)
        .unwrap()
        .unwrap();
    core.delete_vault("v".into()).unwrap();
    rec.finish("failed");
    assert_eq!(rec.status(), "failed");
}

#[test]
fn cloud_vault_binary_ids_are_resolved_without_utf8_assumptions() {
    let (_dir, core, _) = setup();
    let cloud = core
        .create_cloud_vault("Cloud".into(), "tenant".into())
        .unwrap();
    let profile = core.get_connection("v".into(), "h".into()).unwrap();
    core.save_connection(cloud.clone(), profile).unwrap();
    let target = core.automation_target(cloud.clone(), "h".into()).unwrap();
    let rec = core
        .automation_recording(&target, "cloud", "Agent", "pwd", None)
        .unwrap()
        .unwrap();
    rec.finish("failed");
    assert_eq!(rec.status(), "saved");
    assert_eq!(rec.vault_id, cloud);
    assert_eq!(
        core.list_recordings(cloud).unwrap()[0]
            .mcp
            .as_ref()
            .unwrap()
            .application,
        "Agent"
    );
}

#[test]
fn concurrent_item_creation_is_not_overwritten_by_recording_save() {
    let (_dir, core, _) = setup();
    let target = core.automation_target("v".into(), "h".into()).unwrap();
    let rec = core
        .automation_recording(&target, "collision", "Agent", "cmd", None)
        .unwrap()
        .unwrap();
    core.save_password("v".into(), "mcp-collision".into(), "keep".into())
        .unwrap();
    rec.finish("failed");
    assert_eq!(rec.status(), "failed");
    assert_eq!(
        core.get_password("v".into(), "mcp-collision".into())
            .unwrap(),
        "keep"
    );
}
