#![cfg(feature = "core")]
use std::{sync::Arc, time::Instant};
use unissh_automation::{
    core::{CoreExecutor, PromptFactory},
    ApprovalMode, Broker, Cancel,
};
use unissh_ffi::{AuthPrompter, ConnectionProfile, Core, ProfileAuth};

struct NoPrompts;
impl PromptFactory for NoPrompts {
    fn for_connection(&self, _: &str, _: Cancel, _: Instant) -> Arc<dyn AuthPrompter> {
        panic!("Restoring consent must not connect or request credentials")
    }
}
fn broker(core: Arc<Core>) -> Arc<Broker> {
    Broker::new(Arc::new(CoreExecutor {
        core,
        prompts: Arc::new(NoPrompts),
    }))
}
#[test]
fn encrypted_native_consent_restores_only_unchanged_targets_and_is_revocable() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("db").to_str().unwrap().to_string();
    let keyset = dir.path().join("keyset").to_str().unwrap().to_string();
    let core = Core::new(db.clone(), keyset.clone());
    let kit = core.create_account(None).unwrap();
    core.create_vault("v".into(), "Vault".into()).unwrap();
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
            record_sessions: false,
            agent_forward: false,
        },
    )
    .unwrap();
    let b = broker(core.clone());
    b.grant_with_limits(
        "agent",
        "Agent".into(),
        vec![("v".into(), "h".into())],
        Some(3600),
        &b.grant_ticket().unwrap(),
        ApprovalMode::Trusted,
        3_600_000,
    )
    .unwrap();
    b.suspend();
    core.lock();
    assert!(b.review()["grants"].as_array().unwrap().is_empty());
    drop(b);
    drop(core);
    let core = Core::new(db, keyset);
    let b = broker(core.clone());
    assert!(b.review()["grants"].as_array().unwrap().is_empty());
    core.unlock(None, kit).unwrap();
    let review = b.review();
    assert_eq!(review["grants"][0]["approval_mode"], "trusted");
    assert!(review["grants"][0]["remaining_seconds"].as_u64().unwrap() <= 3600);
    assert_eq!(review["grants"][0]["targets"][0]["profile_id"], "h");
    let mut profile = core.get_connection("v".into(), "h".into()).unwrap();
    profile.host = "redirected.example".into();
    core.save_connection("v".into(), profile).unwrap();
    let review = b.review();
    assert!(review["grants"].as_array().unwrap().is_empty());
    assert_eq!(review["saved_access"][0]["targets"][0]["host"], "example");
    b.forget_access(Some("agent")).unwrap();
    b.suspend();
    b.resume();
    assert!(b.review()["saved_access"].as_array().unwrap().is_empty());
}
