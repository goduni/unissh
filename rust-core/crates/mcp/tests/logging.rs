//! Exercise the SDK with tracing-to-log enabled, as in the native application.
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use unissh_mcp::{
    Authenticator, Backend, BackendResult, CancellationToken, IntegrationId, LocalServer,
};

struct Capture(Mutex<Vec<String>>);
static LOG: Capture = Capture(Mutex::new(Vec::new()));
impl log::Log for Capture {
    fn enabled(&self, meta: &log::Metadata<'_>) -> bool {
        unissh_mcp::diagnostics_allowed(meta.target())
    }
    fn log(&self, record: &log::Record<'_>) {
        if self.enabled(record.metadata()) {
            self.0.lock().unwrap().push(format!("{}", record.args()));
        }
    }
    fn flush(&self) {}
}
struct Fixture;
impl Authenticator for Fixture {
    fn authenticate(&self, s: &str) -> Option<IntegrationId> {
        (s == "TOKEN_SENTINEL_9c31").then(|| IntegrationId("fixture".into()))
    }
}
impl Backend for Fixture {
    fn call(&self, _: IntegrationId, _: unissh_mcp::contract::ToolRequest) -> BackendResult<'_> {
        Box::pin(async { Ok(json!({"sentinel":"OUTPUT_SENTINEL_518a"})) })
    }
}
#[tokio::test]
async fn sdk_payloads_never_reach_the_embedding_log_sink() {
    log::set_logger(&LOG).unwrap();
    log::set_max_level(log::LevelFilter::Trace);
    log::info!(target:"unissh_mcp_test", "capture is active");
    for target in [
        "rmcp",
        "rmcp::service",
        "rmcp::transport::streamable_http_server",
    ] {
        for level in [
            log::Level::Error,
            log::Level::Warn,
            log::Level::Info,
            log::Level::Debug,
            log::Level::Trace,
        ] {
            log::log!(target:target, level, "FILTER_SENTINEL_434e");
        }
    }
    let server = LocalServer::bind(0, Arc::new(Fixture), Arc::new(Fixture))
        .await
        .unwrap();
    let url = format!("http://{}/mcp", server.local_addr().unwrap());
    let stop = CancellationToken::new();
    let task = tokio::spawn(server.serve(stop.clone()));
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let response: Value = client.post(&url)
        .bearer_auth("TOKEN_SENTINEL_9c31")
        .header("Accept", "application/json, text/event-stream")
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run_command","arguments":{"session_id":null,"target_id":"t","request_key":"k","command":"COMMAND_SENTINEL_738c","stdin":"STDIN_SENTINEL_410a","env":{"VALUE":"ENV_SENTINEL_420b"}}}}))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(
        response["result"]["structuredContent"]["sentinel"],
        "OUTPUT_SENTINEL_518a"
    );
    let _ = client.post(&url).bearer_auth("TOKEN_SENTINEL_9c31")
        .header("Accept", "application/json, text/event-stream")
        .json(&json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"NOTIFICATION_SENTINEL_b21f","progress":1}}))
        .send().await.unwrap();
    stop.cancel();
    task.await.unwrap().unwrap();
    let logs = LOG.0.lock().unwrap().join("\n");
    assert!(logs.contains("capture is active"));
    for secret in [
        "TOKEN_SENTINEL",
        "COMMAND_SENTINEL",
        "STDIN_SENTINEL",
        "ENV_SENTINEL",
        "OUTPUT_SENTINEL",
        "NOTIFICATION_SENTINEL",
        "FILTER_SENTINEL",
    ] {
        assert!(
            !logs.contains(secret),
            "sensitive diagnostic escaped the filter"
        );
    }
}
