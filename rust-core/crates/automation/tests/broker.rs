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
        _: Instant,
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
    fn connect(&self, _: &Target, _: Cancel, _: Instant, _: &str) -> Result<Arc<dyn Connection>> {
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
        _: Instant,
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
