use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use reqwest::{Client, RequestBuilder, StatusCode};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use unissh_mcp::{
    contract::ToolRequest, Authenticator, Backend, BackendResult, CancellationToken, IntegrationId,
    LocalServer, NoGrants,
};

// Test-only credentials. Production authentication is supplied by the native app.
struct TestAuth;
impl Authenticator for TestAuth {
    fn authenticate(&self, token: &str) -> Option<IntegrationId> {
        match token {
            "test-alpha" => Some(IntegrationId("alpha".into())),
            "test-beta" => Some(IntegrationId("beta".into())),
            _ => None,
        }
    }
}

#[derive(Default)]
struct RecordingBackend(Mutex<Vec<String>>);
impl Backend for RecordingBackend {
    fn call(&self, identity: IntegrationId, _: ToolRequest) -> BackendResult<'_> {
        self.0.lock().unwrap().push(identity.0.clone());
        Box::pin(async move { Ok(json!({"integration":identity.0})) })
    }
}

struct Fixture {
    client: Client,
    url: String,
    port: u16,
    stop: CancellationToken,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Fixture {
    async fn start(backend: Arc<dyn Backend>) -> Self {
        let server = LocalServer::bind(0, Arc::new(TestAuth), backend)
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        assert!(addr.ip().is_loopback());
        let stop = CancellationToken::new();
        let task = tokio::spawn(server.serve(stop.clone()));
        Self {
            client: Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            url: format!("http://{addr}/mcp"),
            port: addr.port(),
            stop,
            task,
        }
    }

    fn post(&self, body: Value) -> RequestBuilder {
        self.client
            .post(&self.url)
            .header("Accept", "application/json, text/event-stream")
            .json(&body)
    }

    async fn rpc(&self, body: Value) -> Value {
        let response = self
            .post(body)
            .bearer_auth("test-alpha")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert!(response.headers().get("mcp-session-id").is_none());
        response.json().await.unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.cancel();
        self.task.abort();
    }
}

fn call(name: &str, args: Value) -> Value {
    json!({"jsonrpc":"2.0", "id":2, "method":"tools/call", "params":{"name":name,"arguments":args}})
}

#[tokio::test]
async fn legacy_initialize_discovery_and_fail_closed_calls() {
    let fixture = Fixture::start(Arc::new(NoGrants)).await;
    let init = fixture.rpc(json!({"jsonrpc":"2.0", "id":1, "method":"initialize", "params":{
        "protocolVersion":"2025-11-25", "capabilities":{}, "clientInfo":{"name":"fixture", "version":"1"}
    }})).await;
    assert_eq!(init["result"]["serverInfo"]["name"], "unissh");
    let list = fixture
        .rpc(json!({"jsonrpc":"2.0", "id":2,"method":"tools/list"}))
        .await;
    assert_eq!(list["result"]["tools"].as_array().unwrap().len(), 9);
    for name in ["list_targets", "list_ssh_sessions"] {
        let result = fixture.rpc(call(name, json!({}))).await;
        assert_eq!(result["result"]["isError"], true);
        assert_eq!(
            result["result"]["structuredContent"]["code"],
            "grant_required"
        );
    }
}

#[tokio::test]
async fn modern_discovery_and_per_request_metadata() {
    let fixture = Fixture::start(Arc::new(NoGrants)).await;
    let meta = json!({
        "io.modelcontextprotocol/protocolVersion":"2026-07-28",
        "io.modelcontextprotocol/clientInfo":{"name":"fixture", "version":"1"},
        "io.modelcontextprotocol/clientCapabilities":{}
    });
    for method in ["server/discover", "tools/list"] {
        let response = fixture
            .post(json!({"jsonrpc":"2.0", "id":1, "method":method, "params":{"_meta":meta}}))
            .bearer_auth("test-alpha")
            .header("MCP-Protocol-Version", "2026-07-28")
            .header("Mcp-Method", method)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let result: Value = response.json().await.unwrap();
        assert!(result.get("result").is_some(), "{result}");
    }
}

#[tokio::test]
async fn request_guard_rejects_bad_credentials_browser_and_authority() {
    let backend = Arc::new(RecordingBackend::default());
    let fixture = Fixture::start(backend.clone()).await;
    let body = call("list_targets", json!({}));
    for request in [
        fixture.post(body.clone()),
        fixture.post(body.clone()).bearer_auth("wrong"),
        fixture
            .post(body.clone())
            .header("Authorization", "Basic test-alpha"),
        fixture
            .post(body.clone())
            .bearer_auth("test-alpha")
            .header("Authorization", "Bearer test-beta"),
    ] {
        assert_eq!(
            request.send().await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }
    for origin in ["null", "https://example.com", "http://127.0.0.1"] {
        let response = fixture
            .post(body.clone())
            .bearer_auth("test-alpha")
            .header("Origin", origin)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    for host in [
        "attacker.example".into(),
        format!("localhost:{}", fixture.port),
        "127.0.0.1:1".into(),
    ] {
        let response = fixture
            .post(body.clone())
            .bearer_auth("test-alpha")
            .header("Host", host)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    let response = fixture
        .client
        .post(format!("{}?token=test-alpha", fixture.url))
        .bearer_auth("test-alpha")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(backend.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn identity_is_authenticated_on_each_call_and_arguments_cannot_override_it() {
    let backend = Arc::new(RecordingBackend::default());
    let fixture = Fixture::start(backend.clone()).await;
    for (token, identity) in [("test-alpha", "alpha"), ("test-beta", "beta")] {
        let response: Value = fixture
            .post(call("list_targets", json!({})))
            .bearer_auth(token)
            .header("Mcp-Session-Id", "untrusted-transport-id")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(
            response["result"]["structuredContent"]["integration"],
            identity
        );
    }
    let result = fixture.rpc(call("run_command", json!({"session_id":"s", "command":"sensitive-command", "request_key":"k", "integration_id":"beta"}))).await;
    assert_eq!(result["error"]["code"], -32602);
    assert!(!result.to_string().contains("sensitive-command"));
    assert_eq!(*backend.0.lock().unwrap(), ["alpha", "beta"]);
}

#[tokio::test]
async fn oversized_body_never_reaches_backend() {
    let backend = Arc::new(RecordingBackend::default());
    let fixture = Fixture::start(backend.clone()).await;
    let response = fixture
        .post(call(
            "run_command",
            json!({"session_id":"s", "command":"x".repeat(128 * 1024),"request_key":"k"}),
        ))
        .bearer_auth("test-alpha")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(backend.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn chunked_body_cannot_bypass_size_limit() {
    let backend = Arc::new(RecordingBackend::default());
    let fixture = Fixture::start(backend.clone()).await;
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", fixture.port))
        .await
        .unwrap();
    let body = call(
        "run_command",
        json!({"session_id":"s", "command":"x".repeat(128 * 1024),"request_key":"k"}),
    )
    .to_string();
    let mut wire = format!("POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer test-alpha\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n", fixture.port);
    for chunk in body.as_bytes().chunks(4096) {
        wire.push_str(&format!(
            "{:x}\r\n{}\r\n",
            chunk.len(),
            std::str::from_utf8(chunk).unwrap()
        ));
    }
    wire.push_str("0\r\n\r\n");
    let response = tokio::time::timeout(Duration::from_secs(5), async {
        stream.write_all(wire.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    })
    .await
    .unwrap();
    assert!(response.starts_with("HTTP/1.1 413"), "{response}");
    assert!(backend.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn every_tool_dispatches_only_after_validating_arguments() {
    let fixture = Fixture::start(Arc::new(NoGrants)).await;
    for (name, arguments) in [
        ("list_targets", json!({})),
        (
            "open_ssh_session",
            json!({"target_id":"t", "request_key":"k"}),
        ),
        ("list_ssh_sessions", json!({})),
        ("close_ssh_session", json!({"session_id":"s"})),
        (
            "run_command",
            json!({"session_id":null, "target_id":"t", "command":"pwd", "request_key":"k"}),
        ),
        ("get_command", json!({"run_id":"r", "wait_ms":0})),
        ("cancel_command", json!({"run_id":"r"})),
    ] {
        let result = fixture.rpc(call(name, arguments)).await;
        assert_eq!(
            result["result"]["structuredContent"]["code"], "grant_required",
            "{name}: {result}"
        );
    }
    let result = fixture
        .rpc(call(
            "run_command",
            json!({"target_id":"t", "command":"pwd", "request_key":"k"}),
        ))
        .await;
    assert_eq!(result["error"]["code"], -32602);
}

#[tokio::test]
async fn occupied_port_fails_and_shutdown_releases_listener() {
    let mut fixture = Fixture::start(Arc::new(NoGrants)).await;
    assert!(
        LocalServer::bind(fixture.port, Arc::new(TestAuth), Arc::new(NoGrants))
            .await
            .is_err()
    );
    fixture.stop.cancel();
    tokio::time::timeout(Duration::from_secs(3), &mut fixture.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(fixture
        .post(call("list_targets", json!({})))
        .send()
        .await
        .is_err());
    assert!(
        LocalServer::bind(fixture.port, Arc::new(TestAuth), Arc::new(NoGrants))
            .await
            .is_ok()
    );
}

/// Opt-in interoperability check; only config/health-check subcommands run, no model call.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an installed Claude Code CLI; uses an isolated temporary config"]
async fn claude_cli_http_interoperability() {
    let fixture = Fixture::start(Arc::new(NoGrants)).await;
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("config");
    std::fs::create_dir(&config).unwrap();
    let configure = std::process::Command::new("claude")
        .current_dir(temp.path())
        .env("CLAUDE_CONFIG_DIR", &config)
        .args([
            "mcp",
            "add",
            "--transport",
            "http",
            "--scope",
            "local",
            "UniSSH-fixture",
            &fixture.url,
            "--header",
            "Authorization: Bearer test-alpha",
        ])
        .output()
        .unwrap();
    assert!(configure.status.success(), "CLI configuration failed");
    let output = std::process::Command::new("claude")
        .current_dir(temp.path())
        .env("CLAUDE_CONFIG_DIR", &config)
        .env("MCP_TIMEOUT", "10000")
        .args(["mcp", "list"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "CLI health check failed");
    assert!(
        text.contains("UniSSH-fixture") && text.contains("Connected"),
        "CLI did not connect: {text}"
    );
}

struct DelayedOutput(tokio::sync::Notify);
impl Backend for DelayedOutput {
    fn call(&self, _: IntegrationId, _: ToolRequest) -> BackendResult<'_> {
        Box::pin(async move {
            self.0.notify_one();
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok(json!({"state":"running","chunks":[]}))
        })
    }
}

// Paused time with real sockets: keep the runtime awake so only our explicit
// advances move the clock, instead of automatically jumping to network deadlines.
struct ManualClock(tokio::task::JoinHandle<()>);
impl ManualClock {
    fn start() -> Self {
        tokio::time::pause();
        Self(tokio::spawn(async {
            loop {
                tokio::task::yield_now().await;
            }
        }))
    }
}
impl Drop for ManualClock {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tokio::test]
async fn reused_connection_finishes_poll_across_original_socket_deadline() {
    let backend = Arc::new(DelayedOutput(tokio::sync::Notify::new()));
    let fixture = Fixture::start(backend.clone()).await;
    fixture
        .rpc(json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))
        .await;
    let _clock = ManualClock::start();
    tokio::time::advance(Duration::from_secs(50)).await;
    let request = fixture
        .post(call(
            "get_command",
            json!({"run_id":"fixture","wait_ms":30000}),
        ))
        .bearer_auth("test-alpha")
        .timeout(Duration::from_secs(40));
    let response =
        tokio::spawn(async move { request.send().await.unwrap().json::<Value>().await.unwrap() });
    backend.0.notified().await;
    tokio::time::advance(Duration::from_secs(15)).await;
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
    assert!(
        !response.is_finished(),
        "the old socket age must not abort an active poll"
    );
    tokio::time::advance(Duration::from_secs(16)).await;
    assert_eq!(
        response.await.unwrap()["result"]["structuredContent"]["state"],
        "running"
    );
}

#[tokio::test]
async fn trickled_headers_still_have_an_absolute_deadline() {
    let fixture = Fixture::start(Arc::new(NoGrants)).await;
    let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", fixture.port))
        .await
        .unwrap();
    socket
        .write_all(
            format!(
                "GET /mcp HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
                fixture.port
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        headers.push(socket.read_u8().await.unwrap());
    }
    assert!(String::from_utf8_lossy(&headers).contains("401"));
    // The first response proves this exact connection is accepted and being polled.
    let _clock = ManualClock::start();
    socket
        .write_all(b"GET /mcp HTTP/1.1\r\nX-Slow: ")
        .await
        .unwrap();
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
    for _ in 0..2 {
        tokio::time::advance(Duration::from_secs(20)).await;
        socket.write_all(b"x").await.unwrap();
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }
    }
    tokio::time::advance(Duration::from_secs(21)).await;
    let mut response = Vec::new();
    socket.read_to_end(&mut response).await.unwrap();
    assert!(response.is_empty() || String::from_utf8_lossy(&response).contains("408"));
}

struct SlowBackend;
impl Backend for SlowBackend {
    fn call(&self, _: IntegrationId, _: ToolRequest) -> BackendResult<'_> {
        Box::pin(async {
            tokio::time::sleep(Duration::from_millis(1250)).await;
            Ok(json!({"commands":[]}))
        })
    }
}
#[tokio::test]
async fn progress_is_opt_in_and_ends_with_the_request() {
    let fixture = Fixture::start(Arc::new(SlowBackend)).await;
    let mut request = call("list_commands", json!({}));
    request["params"]["_meta"] = json!({"progressToken":"progress-test"});
    let response = fixture
        .post(request)
        .bearer_auth("test-alpha")
        .send()
        .await
        .unwrap();
    assert!(response.headers()["content-type"]
        .to_str()
        .unwrap()
        .starts_with("text/event-stream"));
    let body = response.text().await.unwrap();
    let messages: Vec<Value> = body
        .lines()
        .filter_map(|line| {
            line.strip_prefix("data: ")
                .or_else(|| line.strip_prefix("data:"))
        })
        .map(|data| serde_json::from_str(data).unwrap())
        .collect();
    assert!(messages
        .iter()
        .any(|m| m["method"] == "notifications/progress"
            && m["params"]["progressToken"] == "progress-test"));
    assert!(messages.last().unwrap().get("result").is_some());
    let response = fixture
        .post(call("list_commands", json!({})))
        .bearer_auth("test-alpha")
        .send()
        .await
        .unwrap();
    assert!(response.headers()["content-type"]
        .to_str()
        .unwrap()
        .starts_with("application/json"));
    assert_eq!(
        response.json::<Value>().await.unwrap()["result"]["structuredContent"]["commands"],
        json!([])
    );
}
