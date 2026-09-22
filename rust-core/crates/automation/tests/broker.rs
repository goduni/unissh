use serde_json::{json, Value};
use std::{
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use unissh_automation::*;
use unissh_mcp::{
    contract::{parse, ToolError},
    Backend, IntegrationId,
};

#[derive(Default)]
struct Fake {
    revision: AtomicU64,
    connects: Arc<AtomicUsize>,
    execs: Arc<AtomicUsize>,
    closes: Arc<AtomicUsize>,
    command_closes: Arc<AtomicUsize>,
}
struct Conn {
    command_closes: Arc<AtomicUsize>,
    execs: Arc<AtomicUsize>,
    closes: Arc<AtomicUsize>,
    closed: std::sync::atomic::AtomicBool,
}
struct Cmd(Arc<AtomicUsize>);
impl Command for Cmd {
    fn close(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
impl Connection for Conn {
    fn exec(
        &self,
        command: &str,
        sink: Arc<dyn Output>,
        _: Cancel,
        _: Instant,
    ) -> Result<Arc<dyn Command>> {
        self.execs.fetch_add(1, Ordering::SeqCst);
        if command == "split-text" {
            sink.data(false, b"hello \xf0\x9f".to_vec());
            sink.data(true, b"warning \xe2".to_vec());
            sink.data(false, b"\x8c\x8d\n".to_vec());
            sink.data(true, b"\x82\xac\n".to_vec());
            sink.exited(Some(0));
            return Ok(Arc::new(Cmd(self.command_closes.clone())));
        }
        sink.data(
            false,
            if command == "large" {
                vec![b'x'; 2 * 1024 * 1024]
            } else {
                b"\xe2\x82\xac\0".to_vec()
            },
        );
        if command != "hold" {
            sink.exited(Some(0));
        }
        Ok(Arc::new(Cmd(self.command_closes.clone())))
    }
    fn valid(&self) -> bool {
        !self.closed.load(Ordering::SeqCst)
    }
    fn close(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            self.closes.fetch_add(1, Ordering::SeqCst);
        }
    }
}
impl Executor for Fake {
    fn revision(&self) -> Result<[u64; 2]> {
        Ok([1, self.revision.load(Ordering::SeqCst)])
    }
    fn resolve(&self, vault: &str, profile: &str) -> Result<Target> {
        Ok(Target {
            info: TargetInfo {
                vault_id: vault.into(),
                profile_id: profile.into(),
                label: "test".into(),
                host: "localhost".into(),
                port: 22,
                user: "test".into(),
            },
            revision: self.revision()?,
            payload: Arc::new(()),
        })
    }
    fn connect(
        &self,
        _: &Target,
        stop: Cancel,
        _: Option<Instant>,
        _: &str,
    ) -> Result<Arc<dyn Connection>> {
        if stop.load(Ordering::SeqCst) {
            return Err(ToolError::GrantExpired);
        }
        self.connects.fetch_add(1, Ordering::SeqCst);
        Ok(Arc::new(Conn {
            command_closes: self.command_closes.clone(),
            execs: self.execs.clone(),
            closes: self.closes.clone(),
            closed: false.into(),
        }))
    }
}
async fn call(b: &Broker, owner: &str, name: &str, args: Value) -> Result<Value> {
    b.call(
        IntegrationId(owner.into()),
        parse(name, args.as_object().unwrap().clone()).unwrap_or_else(|_| panic!("test arguments")),
    )
    .await
}
async fn target(b: &Broker, owner: &str) -> String {
    b.grant(owner, owner.into(), vec![("v".into(), "p".into())], 30)
        .unwrap();
    call(b, owner, "list_targets", json!({})).await.unwrap()["targets"][0]["target_id"]
        .as_str()
        .unwrap()
        .into()
}
async fn wait(b: &Broker, owner: &str, rid: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let r = call(b, owner, "get_command", json!({"run_id":rid}))
                .await
                .unwrap();
            if r["state"] == "completed" || r["state"] == "failed" {
                return r;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn approval_and_request_key_prevent_unapproved_or_duplicate_execution() {
    let fake = Arc::new(Fake::default());
    let b = Broker::new(fake.clone());
    let t = target(&b, "a").await;
    let args = json!({"session_id":null,"target_id":t,"command":"pwd","request_key":"k"});
    let r = call(&b, "a", "run_command", args.clone()).await.unwrap();
    let rid = r["run_id"].as_str().unwrap();
    assert_eq!(fake.execs.load(Ordering::SeqCst), 0);
    assert_eq!(
        call(&b, "a", "run_command", args.clone()).await.unwrap()["run_id"],
        rid
    );
    assert_eq!(
        call(
            &b,
            "a",
            "run_command",
            json!({"session_id":null,"target_id":t,"command":"other","request_key":"k"})
        )
        .await
        .unwrap_err(),
        ToolError::RequestConflict
    );
    b.approve(rid, true).unwrap();
    let r = wait(&b, "a", rid).await;
    assert_eq!(r["chunks"][0]["data"], "4oKsAA==");
    assert_eq!(
        call(&b, "a", "run_command", args).await.unwrap()["run_id"],
        rid
    );
    assert_eq!(fake.execs.load(Ordering::SeqCst), 1);
    assert_eq!(
        b.approve(rid, true).unwrap_err(),
        ToolError::ApprovalExpired
    );
}

#[tokio::test]
async fn persistent_commands_reuse_connection_and_one_shots_close_theirs() {
    let f = Arc::new(Fake::default());
    let b = Broker::new(f.clone());
    let t = target(&b, "a").await;
    let opened = call(
        &b,
        "a",
        "open_ssh_session",
        json!({"target_id":t,"request_key":"open"}),
    )
    .await
    .unwrap();
    let sid = opened["session_id"].as_str().unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let s = call(&b, "a", "list_ssh_sessions", json!({})).await.unwrap();
            if s["sessions"][0]["state"] == "ready" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    for k in ["1", "2"] {
        let r = call(
            &b,
            "a",
            "run_command",
            json!({"session_id":sid,"command":"pwd","request_key":k}),
        )
        .await
        .unwrap();
        let rid = r["run_id"].as_str().unwrap();
        b.approve(rid, true).unwrap();
        wait(&b, "a", rid).await;
    }
    assert_eq!(f.connects.load(Ordering::SeqCst), 1);
    for k in ["3", "4"] {
        let r = call(
            &b,
            "a",
            "run_command",
            json!({"session_id":null,"target_id":t,"command":"pwd","request_key":k}),
        )
        .await
        .unwrap();
        let rid = r["run_id"].as_str().unwrap();
        b.approve(rid, true).unwrap();
        wait(&b, "a", rid).await;
    }
    call(&b, "a", "close_ssh_session", json!({"session_id":sid}))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while f.closes.load(Ordering::SeqCst) != 3 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(f.connects.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn foreign_ids_stale_approval_and_revision_changes_are_denied() {
    let f = Arc::new(Fake::default());
    let b = Broker::new(f.clone());
    let t = target(&b, "a").await;
    target(&b, "b").await;
    let r = call(
        &b,
        "a",
        "run_command",
        json!({"session_id":null,"target_id":t,"command":"pwd","request_key":"k"}),
    )
    .await
    .unwrap();
    let rid = r["run_id"].as_str().unwrap();
    assert_eq!(
        call(&b, "b", "get_command", json!({"run_id":rid}))
            .await
            .unwrap_err(),
        ToolError::OutcomeUnknown
    );
    assert_eq!(
        call(&b, "b", "cancel_command", json!({"run_id":rid}))
            .await
            .unwrap_err(),
        ToolError::OutcomeUnknown
    );
    f.revision.fetch_add(1, Ordering::SeqCst);
    assert_eq!(
        b.approve(rid, true).unwrap_err(),
        ToolError::ApprovalExpired
    );
    assert_eq!(
        call(&b, "a", "list_targets", json!({})).await.unwrap_err(),
        ToolError::GrantRequired
    );
    assert_eq!(f.execs.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn output_is_capped_and_pages_have_stable_cursors() {
    let f = Arc::new(Fake::default());
    let b = Broker::new(f);
    let t = target(&b, "a").await;
    let r = call(
        &b,
        "a",
        "run_command",
        json!({"session_id":null,"target_id":t,"command":"large","request_key":"k"}),
    )
    .await
    .unwrap();
    let rid = r["run_id"].as_str().unwrap();
    b.approve(rid, true).unwrap();
    let r = wait(&b, "a", rid).await;
    assert_eq!(r["truncated"], true);
    assert_eq!(r["chunks"].as_array().unwrap().len(), 4);
    let again = call(
        &b,
        "a",
        "get_command",
        json!({"run_id":rid,"output_cursor":"0"}),
    )
    .await
    .unwrap();
    assert_eq!(r, again);
    assert_eq!(
        call(
            &b,
            "a",
            "get_command",
            json!({"run_id":rid,"output_cursor":"9999"})
        )
        .await
        .unwrap_err(),
        ToolError::OutputExpired
    );
    b.revoke(None);
    assert_eq!(
        call(&b, "a", "get_command", json!({"run_id":rid}))
            .await
            .unwrap_err(),
        ToolError::GrantRequired
    );
}

struct Delayed {
    fake: Arc<Fake>,
    entered: std::sync::atomic::AtomicBool,
    release: std::sync::atomic::AtomicBool,
    resolve: bool,
}
impl Delayed {
    fn pause(&self) {
        self.entered.store(true, Ordering::SeqCst);
        let until = Instant::now() + Duration::from_secs(3);
        while !self.release.load(Ordering::SeqCst) {
            assert!(Instant::now() < until, "test barrier timed out");
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}
impl Executor for Delayed {
    fn revision(&self) -> Result<[u64; 2]> {
        self.fake.revision()
    }
    fn resolve(&self, v: &str, p: &str) -> Result<Target> {
        if self.resolve {
            self.pause();
        }
        self.fake.resolve(v, p)
    }
    fn connect(
        &self,
        _: &Target,
        _: Cancel,
        _: Option<Instant>,
        _: &str,
    ) -> Result<Arc<dyn Connection>> {
        self.pause(); // Deliberately ignore cancellation to simulate a late auth reply.
        self.fake.connects.fetch_add(1, Ordering::SeqCst);
        Ok(Arc::new(Conn {
            command_closes: self.fake.command_closes.clone(),
            execs: self.fake.execs.clone(),
            closes: self.fake.closes.clone(),
            closed: false.into(),
        }))
    }
}
async fn entered(d: &Delayed) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !d.entered.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn revoke_during_connect_discards_late_connection_and_cannot_execute() {
    for explicit in [true, false] {
        let d = Arc::new(Delayed {
            fake: Arc::new(Fake::default()),
            entered: false.into(),
            release: false.into(),
            resolve: false,
        });
        let b = Broker::new(d.clone());
        let t = target(&b, "a").await;
        if explicit {
            call(
                &b,
                "a",
                "open_ssh_session",
                json!({"target_id":t,"request_key":"open"}),
            )
            .await
            .unwrap();
        } else {
            let r = call(
                &b,
                "a",
                "run_command",
                json!({"session_id":null,"target_id":t,"command":"pwd","request_key":"run"}),
            )
            .await
            .unwrap();
            b.approve(r["run_id"].as_str().unwrap(), true).unwrap();
        }
        entered(&d).await;
        b.revoke(None);
        d.release.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(2), async {
            while d.fake.closes.load(Ordering::SeqCst) != 1 {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(d.fake.execs.load(Ordering::SeqCst), 0);
        assert!(b.review()["sessions"].as_array().unwrap().is_empty());
        assert!(b.review()["runs"].as_array().unwrap().is_empty());
    }
}

#[tokio::test]
async fn grant_preparation_cannot_publish_after_native_revocation() {
    let d = Arc::new(Delayed {
        fake: Arc::new(Fake::default()),
        entered: false.into(),
        release: false.into(),
        resolve: true,
    });
    let b = Broker::new(d.clone());
    let worker = b.clone();
    let task = std::thread::spawn(move || {
        worker.grant("a", "a".into(), vec![("v".into(), "p".into())], 30)
    });
    entered(&d).await;
    b.revoke(None);
    d.release.store(true, Ordering::SeqCst);
    assert_eq!(task.join().unwrap().unwrap_err(), ToolError::GrantExpired);
    assert!(b.review()["grants"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn get_command_wait_is_bounded_and_does_not_approve() {
    let fake = Arc::new(Fake::default());
    let b = Broker::new(fake.clone());
    let t = target(&b, "a").await;
    let r = call(
        &b,
        "a",
        "run_command",
        json!({"session_id":null,"target_id":t,"command":"pwd","request_key":"run"}),
    )
    .await
    .unwrap();
    let start = Instant::now();
    let pending = call(
        &b,
        "a",
        "get_command",
        json!({"run_id":r["run_id"],"wait_ms":60}),
    )
    .await
    .unwrap();
    assert!(start.elapsed() >= Duration::from_millis(60));
    assert_eq!(pending["state"], "awaiting_approval");
    assert_eq!(fake.execs.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn displayed_grant_selection_is_invalid_after_revoke_or_target_edit() {
    let fake = Arc::new(Fake::default());
    let b = Broker::new(fake.clone());
    let selected = b.grant_ticket().unwrap();
    b.revoke(None);
    assert_eq!(
        b.grant_with_ticket(
            "a",
            "a".into(),
            vec![("v".into(), "p".into())],
            30,
            &selected
        ),
        Err(ToolError::GrantExpired)
    );
    let selected = b.grant_ticket().unwrap();
    fake.revision.fetch_add(1, Ordering::SeqCst);
    assert_eq!(
        b.grant_with_ticket(
            "a",
            "a".into(),
            vec![("v".into(), "p".into())],
            30,
            &selected
        ),
        Err(ToolError::GrantExpired)
    );
    assert!(b.review()["grants"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn physical_connection_limits_cover_cancelling_and_other_owners() {
    let d = Arc::new(Delayed {
        fake: Arc::new(Fake::default()),
        entered: false.into(),
        release: false.into(),
        resolve: false,
    });
    let b = Broker::new(d.clone());
    for owner in ["a", "b"] {
        let target = target(&b, owner).await;
        for n in 0..4 {
            call(
                &b,
                owner,
                "open_ssh_session",
                json!({"target_id":target,"request_key":n.to_string()}),
            )
            .await
            .unwrap();
        }
        assert_eq!(
            call(
                &b,
                owner,
                "open_ssh_session",
                json!({"target_id":target,"request_key":"overflow"})
            )
            .await,
            Err(ToolError::Busy)
        );
    }
    let t = target(&b, "c").await;
    b.revoke(Some("a"));
    // Cancelling a connect doesn't free a physical slot before its worker cleans up.
    assert_eq!(
        call(
            &b,
            "c",
            "open_ssh_session",
            json!({"target_id":t,"request_key":"overflow"})
        )
        .await,
        Err(ToolError::Busy)
    );
    b.revoke(None);
    d.release.store(true, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(2), async {
        while d.fake.closes.load(Ordering::SeqCst) != 8 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelling_a_run_preserves_only_explicit_connections() {
    for explicit in [true, false] {
        let fake = Arc::new(Fake::default());
        let b = Broker::new(fake.clone());
        let t = target(&b, "a").await;
        let session = if explicit {
            let s = call(
                &b,
                "a",
                "open_ssh_session",
                json!({"target_id":t,"request_key":"open"}),
            )
            .await
            .unwrap()["session_id"]
                .clone();
            tokio::time::timeout(Duration::from_secs(2), async {
                while call(&b, "a", "list_ssh_sessions", json!({})).await.unwrap()["sessions"][0]
                    ["state"]
                    != "ready"
                {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            })
            .await
            .unwrap();
            s
        } else {
            Value::Null
        };
        let mut args = json!({"session_id":session,"command":"hold","request_key":"run"});
        if !explicit {
            args["target_id"] = json!(t);
        }
        let rid = call(&b, "a", "run_command", args).await.unwrap()["run_id"].clone();
        b.approve(rid.as_str().unwrap(), true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while fake.execs.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap();
        call(&b, "a", "cancel_command", json!({"run_id":rid}))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while call(&b, "a", "get_command", json!({"run_id":rid}))
                .await
                .unwrap()["state"]
                != "cancelled"
            {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(fake.command_closes.load(Ordering::SeqCst), 1);
        assert_eq!(fake.closes.load(Ordering::SeqCst), usize::from(!explicit));
        if explicit {
            assert_eq!(
                call(&b, "a", "list_ssh_sessions", json!({})).await.unwrap()["sessions"][0]
                    ["state"],
                "ready"
            );
        }
        b.revoke(None);
    }
}

#[derive(Default)]
struct FailedConnect {
    prompt_cancel: std::sync::Mutex<Option<Cancel>>,
}
impl Executor for FailedConnect {
    fn revision(&self) -> Result<[u64; 2]> {
        Ok([1, 0])
    }
    fn resolve(&self, vault: &str, profile: &str) -> Result<Target> {
        Fake::default().resolve(vault, profile)
    }
    fn connect(
        &self,
        _: &Target,
        stop: Cancel,
        _: Option<Instant>,
        _: &str,
    ) -> Result<Arc<dyn Connection>> {
        // A timed-out SSH future leaves the blocking prompter holding this flag.
        *self.prompt_cancel.lock().unwrap() = Some(stop);
        Err(ToolError::TargetUnavailable)
    }
}

#[tokio::test]
async fn failed_connections_cancel_native_prompts_in_both_modes() {
    for explicit in [true, false] {
        let executor = Arc::new(FailedConnect::default());
        let broker = Broker::new(executor.clone());
        let target_id = target(&broker, "a").await;
        if explicit {
            call(
                &broker,
                "a",
                "open_ssh_session",
                json!({"target_id":target_id,"request_key":"open"}),
            )
            .await
            .unwrap();
        } else {
            let run = call(&broker, "a", "run_command", json!({"session_id":null,"target_id":target_id,"command":"true","request_key":"run"})).await.unwrap();
            broker
                .approve(run["run_id"].as_str().unwrap(), true)
                .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let review = broker.review();
                let done = if explicit {
                    review["sessions"][0]["state"] == "closed"
                } else {
                    review["runs"][0]["state"] == "failed"
                };
                if done {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(
            executor
                .prompt_cancel
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .load(Ordering::SeqCst),
            "the closed operation must dismiss its orphaned native prompt"
        );
    }
}

#[tokio::test]
async fn custom_grant_duration_accepts_long_leases_without_becoming_unbounded() {
    let b = Broker::new(Arc::new(Fake::default()));
    for seconds in [1, 1801, 3600, 86400, 604800, u32::MAX] {
        b.grant("a", "a".into(), vec![("v".into(), "p".into())], seconds)
            .unwrap();
        let remaining = b.review()["grants"][0]["remaining_seconds"]
            .as_u64()
            .unwrap();
        assert!(remaining <= u64::from(seconds));
        assert!(remaining >= u64::from(seconds) - 1);
    }
    // Zero is invalid and must not replace the existing authorization.
    assert_eq!(
        b.grant("a", "a".into(), vec![("v".into(), "p".into())], 0),
        Err(ToolError::TargetUnavailable)
    );
    let targets = call(&b, "a", "list_targets", json!({})).await.unwrap();
    let target = targets["targets"][0]["target_id"].as_str().unwrap();
    let session = call(
        &b,
        "a",
        "open_ssh_session",
        json!({"target_id":target,"request_key":"long"}),
    )
    .await
    .unwrap();
    assert!(session["expires_at"].as_u64().unwrap() > u64::from(u32::MAX));
    b.revoke(Some("a"));
    assert!(b.review()["grants"].as_array().unwrap().is_empty());
    assert_eq!(
        call(&b, "a", "list_targets", json!({})).await,
        Err(ToolError::GrantRequired)
    );
}

#[tokio::test]
async fn unbounded_grant_keeps_command_limits_and_explicit_revocation() {
    let f = Arc::new(Fake::default());
    let b = Broker::new(f.clone());
    b.grant("a", "a".into(), vec![("v".into(), "p".into())], None)
        .unwrap();
    assert!(b.review()["grants"][0]["remaining_seconds"].is_null());
    let targets = call(&b, "a", "list_targets", json!({})).await.unwrap();
    let target = targets["targets"][0]["target_id"].as_str().unwrap();
    let session = call(
        &b,
        "a",
        "open_ssh_session",
        json!({"target_id":target,"request_key":"open"}),
    )
    .await
    .unwrap();
    assert!(session["expires_at"].is_null());
    let run = call(&b, "a", "run_command", json!({"target_id":target,"session_id":null,"request_key":"run","command":"hold","timeout_ms":30})).await.unwrap();
    let rid = run["run_id"].as_str().unwrap();
    assert_eq!(run["state"], "awaiting_approval");
    assert_eq!(f.execs.load(Ordering::SeqCst), 0);
    b.approve(rid, true).unwrap();
    let done = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let r = call(&b, "a", "get_command", json!({"run_id":rid}))
                .await
                .unwrap();
            if r["state"] != "running" && r["state"] != "connecting" {
                break r;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_ne!(done["state"], "completed");
    assert_eq!(b.review()["grants"].as_array().unwrap().len(), 1);
    b.revoke(Some("a"));
    assert!(b.review()["grants"].as_array().unwrap().is_empty());
    assert_eq!(
        call(&b, "a", "list_targets", json!({})).await,
        Err(ToolError::GrantRequired)
    );
}

#[tokio::test]
async fn unbounded_grant_still_requires_new_consent_after_vault_mutation() {
    let f = Arc::new(Fake::default());
    let b = Broker::new(f.clone());
    b.grant("a", "a".into(), vec![("v".into(), "p".into())], None)
        .unwrap();
    f.revision.fetch_add(1, Ordering::SeqCst);
    assert_eq!(
        call(&b, "a", "list_targets", json!({})).await,
        Err(ToolError::GrantRequired)
    );
    assert!(b.review()["grants"].as_array().unwrap().is_empty());
}

async fn trusted_target(b: &Broker, owner: &str) -> String {
    let ticket = b.grant_ticket().unwrap();
    b.grant_with_policy(
        owner,
        owner.into(),
        vec![("v".into(), "p".into())],
        None,
        &ticket,
        ApprovalMode::Trusted,
    )
    .unwrap();
    call(b, owner, "list_targets", json!({})).await.unwrap()["targets"][0]["target_id"]
        .as_str()
        .unwrap()
        .into()
}

#[tokio::test]
async fn trusted_commands_wait_return_readable_output_and_deduplicate() {
    let fake = Arc::new(Fake::default());
    let b = Broker::new(fake.clone());
    let t = trusted_target(&b, "a").await;
    assert_eq!(b.review()["grants"][0]["approval_mode"], "trusted");
    let args = json!({"session_id":null,"target_id":t,"command":"split-text","request_key":"k","wait_ms":1000});
    let r = call(&b, "a", "run_command", args.clone()).await.unwrap();
    assert_eq!(r["state"], "completed");
    assert_eq!(r["exit_code"], 0);
    let chunks = r["chunks"].as_array().unwrap();
    assert!(chunks.iter().all(|c| c["encoding"] == "utf8"));
    for (stream, text) in [("stdout", "hello 🌍\n"), ("stderr", "warning €\n")] {
        assert_eq!(
            chunks
                .iter()
                .filter(|c| c["stream"] == stream)
                .map(|c| c["data"].as_str().unwrap())
                .collect::<String>(),
            text
        );
    }
    let mut retry = args.clone();
    retry["wait_ms"] = json!(0);
    assert_eq!(
        call(&b, "a", "run_command", retry).await.unwrap()["run_id"],
        r["run_id"]
    );
    assert_eq!(fake.execs.load(Ordering::SeqCst), 1);
    let next = call(
        &b,
        "a",
        "get_command",
        json!({"run_id":r["run_id"],"output_cursor":r["next_cursor"]}),
    )
    .await
    .unwrap();
    assert!(next["chunks"].as_array().unwrap().is_empty());
    assert_eq!(
        call(&b, "other", "get_command", json!({"run_id":r["run_id"]}))
            .await
            .unwrap_err(),
        ToolError::GrantRequired
    );
}

#[tokio::test]
async fn open_wait_returns_ready_and_trusted_persistent_execution_reuses_connection() {
    let fake = Arc::new(Fake::default());
    let b = Broker::new(fake.clone());
    let t = trusted_target(&b, "a").await;
    let open = json!({"target_id":t,"request_key":"open","wait_ms":1000});
    let session = call(&b, "a", "open_ssh_session", open.clone())
        .await
        .unwrap();
    assert_eq!(session["state"], "ready");
    assert_eq!(
        call(&b, "a", "open_ssh_session", open).await.unwrap()["session_id"],
        session["session_id"]
    );
    for key in ["one", "two"] {
        let r = call(&b, "a", "run_command", json!({"session_id":session["session_id"],"command":"pwd","request_key":key,"wait_ms":1000})).await.unwrap();
        assert_eq!(r["state"], "completed");
        assert_eq!(r["chunks"][0]["encoding"], "base64"); // NUL marks this fixture as binary.
    }
    assert_eq!(fake.connects.load(Ordering::SeqCst), 1);
    assert_eq!(fake.execs.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn cwd_is_reviewed_and_bound_to_submission_while_wait_never_approves() {
    let fake = Arc::new(Fake::default());
    let b = Broker::new(fake.clone());
    let t = target(&b, "a").await;
    let mut args = json!({"session_id":null,"target_id":t,"command":"pwd","cwd":"/srv/a ' $HOME","request_key":"k","wait_ms":30000});
    let r = tokio::time::timeout(
        Duration::from_secs(1),
        call(&b, "a", "run_command", args.clone()),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(r["state"], "awaiting_approval");
    assert_eq!(b.review()["runs"][0]["cwd"], args["cwd"]);
    assert_eq!(b.review()["runs"][0]["command"], "pwd");
    args["cwd"] = json!("/srv/other");
    assert_eq!(
        call(&b, "a", "run_command", args).await.unwrap_err(),
        ToolError::RequestConflict
    );
    assert_eq!(fake.execs.load(Ordering::SeqCst), 0);
    b.revoke(Some("a"));
    assert_eq!(
        b.approve(r["run_id"].as_str().unwrap(), true).unwrap_err(),
        ToolError::ApprovalExpired
    );
}

#[tokio::test]
async fn trusted_wait_is_bounded_and_revocation_interrupts_waiting() {
    let fake = Arc::new(Fake::default());
    let b = Broker::new(fake.clone());
    let t = trusted_target(&b, "a").await;
    let start = Instant::now();
    let r = call(
        &b,
        "a",
        "run_command",
        json!({"session_id":null,"target_id":t,"command":"hold","request_key":"hold","wait_ms":60}),
    )
    .await
    .unwrap();
    assert!(start.elapsed() >= Duration::from_millis(60));
    assert!(start.elapsed() < Duration::from_secs(2));
    assert_eq!(r["state"], "running");
    let other = b.clone();
    let retry = tokio::spawn(async move {
        call(&other, "a", "run_command", json!({"session_id":null,"target_id":t,"command":"hold","request_key":"hold","wait_ms":30000})).await
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    b.revoke(Some("a"));
    assert!(tokio::time::timeout(Duration::from_secs(1), retry)
        .await
        .unwrap()
        .unwrap()
        .is_err());
    assert_eq!(fake.execs.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn replacing_trusted_access_with_manual_revokes_old_runs_and_defaults_remain_manual() {
    let fake = Arc::new(Fake::default());
    let b = Broker::new(fake.clone());
    let t = trusted_target(&b, "a").await;
    let old = call(
        &b,
        "a",
        "run_command",
        json!({"session_id":null,"target_id":t,"command":"hold","request_key":"old","wait_ms":30}),
    )
    .await
    .unwrap();
    let t = target(&b, "a").await;
    assert_eq!(b.review()["grants"][0]["approval_mode"], "manual");
    assert_eq!(
        call(&b, "a", "get_command", json!({"run_id":old["run_id"]}))
            .await
            .unwrap_err(),
        ToolError::OutcomeUnknown
    );
    let new = call(
        &b,
        "a",
        "run_command",
        json!({"session_id":null,"target_id":t,"command":"pwd","request_key":"new","wait_ms":1000}),
    )
    .await
    .unwrap();
    assert_eq!(new["state"], "awaiting_approval");
    assert_eq!(fake.execs.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn revoking_trusted_access_during_connection_prevents_execution_after_late_auth() {
    let fake = Arc::new(Fake::default());
    let delayed = Arc::new(Delayed {
        fake: fake.clone(),
        entered: false.into(),
        release: false.into(),
        resolve: false,
    });
    let b = Broker::new(delayed.clone());
    let t = trusted_target(&b, "a").await;
    let run = call(
        &b,
        "a",
        "run_command",
        json!({"session_id":null,"target_id":t,"command":"pwd","request_key":"late"}),
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while !delayed.entered.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    b.revoke(Some("a"));
    delayed.release.store(true, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(1), async {
        while fake.closes.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(fake.execs.load(Ordering::SeqCst), 0);
    assert!(
        call(&b, "a", "get_command", json!({"run_id":run["run_id"]}))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn waiting_for_open_is_bounded_and_does_not_reopen_or_survive_revocation() {
    let fake = Arc::new(Fake::default());
    let delayed = Arc::new(Delayed {
        fake: fake.clone(),
        entered: false.into(),
        release: false.into(),
        resolve: false,
    });
    let b = Broker::new(delayed.clone());
    let t = target(&b, "a").await;
    let args = json!({"target_id":t,"request_key":"open","wait_ms":50});
    let start = Instant::now();
    let s = call(&b, "a", "open_ssh_session", args.clone())
        .await
        .unwrap();
    assert_eq!(s["state"], "connecting");
    assert!(start.elapsed() >= Duration::from_millis(50));
    let other = b.clone();
    let mut retry = args;
    retry["wait_ms"] = json!(30000);
    let wait = tokio::spawn(async move { call(&other, "a", "open_ssh_session", retry).await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    b.revoke(Some("a"));
    delayed.release.store(true, Ordering::SeqCst);
    assert!(tokio::time::timeout(Duration::from_secs(1), wait)
        .await
        .unwrap()
        .unwrap()
        .is_err());
    assert_eq!(fake.execs.load(Ordering::SeqCst), 0);
}

#[derive(Default)]
struct Capture {
    bytes: AtomicUsize,
    finishes: AtomicUsize,
    outcome: std::sync::Mutex<String>,
}
impl Recording for Capture {
    fn data(&self, _: bool, bytes: &[u8]) {
        self.bytes.fetch_add(bytes.len(), Ordering::SeqCst);
    }
    fn exited(&self, _: Option<u32>) {}
    fn finish(&self, outcome: &str) {
        *self.outcome.lock().unwrap() = outcome.into();
        self.finishes.fetch_add(1, Ordering::SeqCst);
    }
    fn review(&self) -> Value {
        json!({"status": "saved"})
    }
}
#[derive(Default)]
struct RecordingExecutor {
    fake: Fake,
    captures: std::sync::Mutex<Vec<Arc<Capture>>>,
}
impl Executor for RecordingExecutor {
    fn revision(&self) -> Result<[u64; 2]> {
        self.fake.revision()
    }
    fn resolve(&self, v: &str, p: &str) -> Result<Target> {
        self.fake.resolve(v, p)
    }
    fn connect(
        &self,
        t: &Target,
        c: Cancel,
        d: Option<Instant>,
        a: &str,
    ) -> Result<Arc<dyn Connection>> {
        self.fake.connect(t, c, d, a)
    }
    fn record(
        &self,
        _: &Target,
        _: &str,
        _: &str,
        _: &str,
        _: Option<&str>,
    ) -> Result<Option<Arc<dyn Recording>>> {
        let c = Arc::new(Capture::default());
        self.captures.lock().unwrap().push(c.clone());
        Ok(Some(c))
    }
}
#[tokio::test]
async fn recordings_capture_before_output_limits_and_finalize_without_polling() {
    let executor = Arc::new(RecordingExecutor::default());
    let b = Broker::new(executor.clone());
    let t = target(&b, "a").await;
    let args = json!({"session_id":null,"target_id":t,"command":"large","request_key":"record"});
    let run = call(&b, "a", "run_command", args.clone()).await.unwrap();
    assert!(executor.captures.lock().unwrap().is_empty());
    b.approve(run["run_id"].as_str().unwrap(), true).unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if executor
                .captures
                .lock()
                .unwrap()
                .first()
                .is_some_and(|c| c.finishes.load(Ordering::SeqCst) == 1)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    call(&b, "a", "run_command", args).await.unwrap();
    let captures = executor.captures.lock().unwrap();
    assert_eq!(captures.len(), 1);
    assert_eq!(captures[0].bytes.load(Ordering::SeqCst), 2 * 1024 * 1024);
    assert_eq!(*captures[0].outcome.lock().unwrap(), "completed");
    assert_eq!(b.review()["runs"][0]["recording"]["status"], "saved");
}
#[tokio::test]
async fn revocation_removes_output_but_finalizes_the_recording() {
    let executor = Arc::new(RecordingExecutor::default());
    let b = Broker::new(executor.clone());
    let t = target(&b, "a").await;
    let run = call(
        &b,
        "a",
        "run_command",
        json!({"session_id":null,"target_id":t,"command":"hold","request_key":"hold-record"}),
    )
    .await
    .unwrap();
    b.approve(run["run_id"].as_str().unwrap(), true).unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while executor.fake.execs.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    b.revoke(Some("a"));
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if executor.captures.lock().unwrap()[0]
                .finishes
                .load(Ordering::SeqCst)
                == 1
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        *executor.captures.lock().unwrap()[0].outcome.lock().unwrap(),
        "cancelled"
    );
    assert!(b.review()["runs"].as_array().unwrap().is_empty());
}
