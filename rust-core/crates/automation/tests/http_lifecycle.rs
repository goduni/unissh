//! Real HTTP -> credentials -> broker lifecycle; SSH execution is a counting fake.
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use unissh_automation::*;
use unissh_mcp::{credentials::Credentials, CancellationToken, LocalServer};

#[derive(Default)]
struct Execution(Arc<AtomicUsize>);
impl Command for Execution {
    fn close(&self) {}
}
impl Connection for Execution {
    fn exec(
        &self,
        _: &str,
        _stdin: Option<&str>,
        sink: Arc<dyn Output>,
        _: Cancel,
        _: Instant,
    ) -> Result<Arc<dyn Command>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        sink.data(false, b"approved result".to_vec());
        sink.exited(Some(0));
        Ok(Arc::new(Execution(self.0.clone())))
    }
    fn valid(&self) -> bool {
        true
    }
    fn close(&self) {}
}
impl Executor for Execution {
    fn revision(&self) -> Result<[u64; 2]> {
        Ok([1, 0])
    }
    fn resolve(&self, v: &str, p: &str) -> Result<Target> {
        Ok(Target {
            info: TargetInfo {
                vault: "Test vault".into(),
                groups: vec![],
                tags: vec![],
                vault_id: v.into(),
                profile_id: p.into(),
                label: "Fixture".into(),
                host: "localhost".into(),
                port: 22,
                user: "fixture".into(),
            },
            revision: [1, 0],
            payload: Arc::new(()),
        })
    }
    fn connect(
        &self,
        _: &Target,
        _: Cancel,
        _: Option<Instant>,
        _: &str,
    ) -> Result<Arc<dyn Connection>> {
        Ok(Arc::new(Execution(self.0.clone())))
    }
}
async fn rpc(url: &str, token: &str, name: &str, args: Value) -> Value {
    reqwest::Client::builder().no_proxy().build().unwrap().post(url).bearer_auth(token)
        .header("Accept","application/json, text/event-stream")
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":args}}))
        .send().await.unwrap().json().await.unwrap()
}
#[tokio::test]
async fn reconnect_retry_native_approval_and_rotation_preserve_authority() {
    let dir = tempfile::tempdir().unwrap();
    let credentials = Arc::new(Credentials::load(dir.path().join("mcp.json")).unwrap());
    let (owner, token) = credentials.create("Fixture".into()).unwrap();
    let executor = Arc::new(Execution::default());
    let broker = Broker::new(executor.clone());
    let server = LocalServer::bind(0, credentials.clone(), broker.clone())
        .await
        .unwrap();
    let url = format!("http://{}/mcp", server.local_addr().unwrap());
    let stop = CancellationToken::new();
    let serving = tokio::spawn(server.serve(stop.clone()));
    assert_eq!(
        rpc(&url, &token, "list_targets", json!({})).await["result"]["structuredContent"]["code"],
        "grant_required"
    );
    broker
        .grant(&owner, "Fixture".into(), vec![("v".into(), "p".into())], 30)
        .unwrap();
    let target = rpc(&url, &token, "list_targets", json!({})).await["result"]["structuredContent"]
        ["targets"][0]["target_id"]
        .clone();
    let args = json!({"session_id":null,"target_id":target,"command":"fixture command","request_key":"submission"});
    // Each RPC deliberately uses a fresh HTTP client/connection.
    let first =
        rpc(&url, &token, "run_command", args.clone()).await["result"]["structuredContent"].clone();
    let retry = rpc(&url, &token, "run_command", args).await["result"]["structuredContent"].clone();
    assert_eq!(first, retry);
    assert_eq!(executor.0.load(Ordering::SeqCst), 0);
    let run = first["run_id"].as_str().unwrap();
    broker.approve(run, true).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let output = rpc(
                &url,
                &token,
                "get_command",
                json!({"run_id":run,"wait_ms":100}),
            )
            .await;
            if output["result"]["structuredContent"]["state"] == "completed" {
                assert!(!output["result"]["structuredContent"]["chunks"]
                    .as_array()
                    .unwrap()
                    .is_empty());
                break;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(executor.0.load(Ordering::SeqCst), 1);
    broker.revoke(Some(&owner));
    let (_, replacement) = credentials.rotate(&owner).unwrap();
    let rejected = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(&url)
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(
        rpc(&url, &replacement, "get_command", json!({"run_id":run})).await["result"]
            ["structuredContent"]["code"],
        "grant_required"
    );
    stop.cancel();
    serving.await.unwrap().unwrap();
}

#[tokio::test]
async fn trusted_http_wait_returns_utf8_and_cannot_elevate_manual_policy() {
    let dir = tempfile::tempdir().unwrap();
    let credentials = Arc::new(Credentials::load(dir.path().join("mcp.json")).unwrap());
    let (owner, token) = credentials.create("Fixture".into()).unwrap();
    let executor = Arc::new(Execution::default());
    let broker = Broker::new(executor.clone());
    let server = LocalServer::bind(0, credentials, broker.clone())
        .await
        .unwrap();
    let url = format!("http://{}/mcp", server.local_addr().unwrap());
    let stop = CancellationToken::new();
    let serving = tokio::spawn(server.serve(stop.clone()));
    broker
        .grant_with_policy(
            &owner,
            "Fixture".into(),
            vec![("v".into(), "p".into())],
            None,
            &broker.grant_ticket().unwrap(),
            ApprovalMode::Trusted,
        )
        .unwrap();
    let target = rpc(&url, &token, "list_targets", json!({})).await["result"]["structuredContent"]
        ["targets"][0]["target_id"]
        .clone();
    let session = rpc(
        &url,
        &token,
        "open_ssh_session",
        json!({"target_id":target,"request_key":"open","wait_ms":1000}),
    )
    .await["result"]["structuredContent"]
        .clone();
    assert_eq!(session["state"], "ready");
    let args = json!({"session_id":session["session_id"],"command":"pwd","cwd":"/srv/project","request_key":"run","wait_ms":1000});
    let result =
        rpc(&url, &token, "run_command", args.clone()).await["result"]["structuredContent"].clone();
    assert_eq!(result["state"], "completed");
    assert_eq!(result["chunks"][0]["encoding"], "utf8");
    assert_eq!(result["chunks"][0]["data"], "approved result");
    let retry = rpc(&url, &token, "run_command", args).await["result"]["structuredContent"].clone();
    assert_eq!(retry, result);
    assert_eq!(executor.0.load(Ordering::SeqCst), 1);
    broker
        .grant(&owner, "Fixture".into(), vec![("v".into(), "p".into())], 30)
        .unwrap();
    let target = rpc(&url, &token, "list_targets", json!({})).await["result"]["structuredContent"]
        ["targets"][0]["target_id"]
        .clone();
    let args = json!({"session_id":null,"target_id":target,"command":"pwd","request_key":"manual","wait_ms":1000,"approval_mode":"trusted"});
    assert!(rpc(&url, &token, "run_command", args).await["error"].is_object());
    assert_eq!(executor.0.load(Ordering::SeqCst), 1);
    stop.cancel();
    serving.await.unwrap().unwrap();
}
