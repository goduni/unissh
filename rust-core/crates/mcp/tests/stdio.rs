//! Stdio transport: the natively chosen caller identity, the request-size bound
//! and the HTTP guard's limit on requests in flight.
#![expect(
    clippy::unwrap_used,
    reason = "integration-test helpers; allow-*-in-tests covers only #[test] fns and cfg(test) modules"
)]

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};
use unissh_mcp::{
    contract::{ToolError, ToolRequest},
    serve_io, Backend, BackendResult, CancellationToken, IntegrationId, MAX_REQUEST_BYTES,
};

#[derive(Default)]
struct RecordingBackend(Mutex<Vec<String>>);
impl Backend for RecordingBackend {
    fn call(&self, identity: IntegrationId, _: ToolRequest) -> BackendResult<'_> {
        self.0.lock().unwrap().push(identity.0.clone());
        Box::pin(async move { Ok(json!({"integration":identity.0})) })
    }
}

/// A backend whose calls never finish, like commands still waiting.
struct Stuck;
impl Backend for Stuck {
    fn call(&self, _: IntegrationId, _: ToolRequest) -> BackendResult<'_> {
        Box::pin(std::future::pending::<Result<Value, ToolError>>())
    }
}

/// A client end of a stdio session served for `identity`.
fn start(
    backend: Arc<dyn Backend>,
    identity: &str,
) -> (
    DuplexStream,
    BufReader<DuplexStream>,
    tokio::task::JoinHandle<std::io::Result<()>>,
) {
    let (client_out, server_in) = tokio::io::duplex(1024 * 1024);
    let (server_out, client_in) = tokio::io::duplex(1024 * 1024);
    let task = tokio::spawn(serve_io(
        server_in,
        server_out,
        IntegrationId(identity.into()),
        backend,
        CancellationToken::new(),
    ));
    (client_out, BufReader::new(client_in), task)
}

async fn send(out: &mut DuplexStream, message: Value) {
    let mut line = serde_json::to_vec(&message).unwrap();
    line.push(b'\n');
    out.write_all(&line).await.unwrap();
}

async fn receive(input: &mut BufReader<DuplexStream>) -> Value {
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(5), input.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    serde_json::from_str(&line).unwrap()
}

/// No credential travels over stdio: every call acts as the integration the
/// embedding application chose when it started the session.
#[tokio::test]
async fn every_stdio_call_acts_as_the_natively_chosen_integration() {
    let backend = Arc::new(RecordingBackend::default());
    let (mut out, mut input, _task) = start(backend.clone(), "cli-agent");
    assert_eq!(
        initialize(&mut out, &mut input).await["result"]["serverInfo"]["name"],
        "unissh"
    );
    send(
        &mut out,
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
            "name":"get_access_status","arguments":{}
        }}),
    )
    .await;
    let result = receive(&mut input).await;
    assert_eq!(
        result["result"]["structuredContent"]["integration"],
        "cli-agent"
    );
    assert_eq!(*backend.0.lock().unwrap(), ["cli-agent"]);
}

/// Opens the session: `initialize`, then `initialized`.
async fn initialize(out: &mut DuplexStream, input: &mut BufReader<DuplexStream>) -> Value {
    send(out, json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}
    }}))
    .await;
    let reply = receive(input).await;
    send(
        out,
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )
    .await;
    reply
}

/// As over HTTP, sixteen requests may be in flight; the next one is refused at
/// once instead of queueing behind them.
#[tokio::test]
async fn a_request_beyond_sixteen_in_flight_is_refused() {
    let (mut out, mut input, _task) = start(Arc::new(Stuck), "cli-agent");
    initialize(&mut out, &mut input).await;
    for id in 2..=18 {
        send(
            &mut out,
            json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{
                "name":"get_access_status","arguments":{}
            }}),
        )
        .await;
    }
    // Seventeen sent, sixteen stuck: the one answer is the refusal.
    let refused = receive(&mut input).await;
    assert_eq!(
        refused["error"]["message"], "Too many UniSSH requests at once",
        "{refused}"
    );
}

/// The same bound as an HTTP body: an endless line ends the session instead of
/// growing the SDK's line buffer without limit.
#[tokio::test]
async fn a_line_longer_than_the_request_limit_ends_the_session() {
    let (mut out, mut input, task) = start(Arc::new(RecordingBackend::default()), "cli-agent");
    let oversized = vec![b'x'; MAX_REQUEST_BYTES + 1];
    out.write_all(&oversized).await.unwrap();
    let ended = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    assert!(ended.is_err());
    let mut rest = String::new();
    assert_eq!(input.read_line(&mut rest).await.unwrap(), 0);
}
