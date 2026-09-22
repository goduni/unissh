//! Narrow model-facing requests. Do not derive Debug for command-bearing types.

use std::collections::BTreeMap;

use rmcp::model::{JsonObject, Tool, ToolAnnotations};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListRequest {
    pub cursor: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OpenSession {
    #[schemars(length(min = 1))]
    pub target_id: String,
    #[schemars(length(min = 1, max = 128))]
    pub request_key: String,
    /// Wait up to 30 seconds for readiness; omitted or zero returns immediately.
    #[schemars(range(max = 30_000))]
    pub wait_ms: Option<u32>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CloseSession {
    #[schemars(length(min = 1))]
    pub session_id: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExistingSessionCommand {
    #[schemars(length(min = 1))]
    pub session_id: String,
    /// At most 32 KiB of UTF-8; each invocation has independent shell state.
    #[schemars(length(min = 1, max = 32768))]
    pub command: String,
    /// Initial UTF-8 input (at most 32 KiB), followed by EOF. No interactive stdin.
    #[schemars(length(max = 32768))]
    pub stdin: Option<String>,
    /// Literal POSIX environment values for this invocation only. At most 64 entries / 16 KiB.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[schemars(length(min = 1, max = 128))]
    pub request_key: String,
    #[schemars(range(min = 1, max = 86_400_000))]
    pub timeout_ms: Option<u32>,
    /// Absolute POSIX directory for this exec only. No ~ or variable expansion.
    #[schemars(length(min = 1, max = 32768), pattern(r"^/"))]
    pub cwd: Option<String>,
    /// Wait up to 30 seconds for completion/output; never approves a command.
    #[schemars(range(max = 30_000))]
    pub wait_ms: Option<u32>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OneShotCommand {
    /// Explicit JSON null. Unit, rather than Option, keeps this field required.
    pub session_id: (),
    #[schemars(length(min = 1))]
    pub target_id: String,
    /// At most 32 KiB of UTF-8; each invocation has independent shell state.
    #[schemars(length(min = 1, max = 32768))]
    pub command: String,
    /// Initial UTF-8 input (at most 32 KiB), followed by EOF. No interactive stdin.
    #[schemars(length(max = 32768))]
    pub stdin: Option<String>,
    /// Literal POSIX environment values for this invocation only. At most 64 entries / 16 KiB.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[schemars(length(min = 1, max = 128))]
    pub request_key: String,
    #[schemars(range(min = 1, max = 86_400_000))]
    pub timeout_ms: Option<u32>,
    /// Absolute POSIX directory for this exec only. No ~ or variable expansion.
    #[schemars(length(min = 1, max = 32768), pattern(r"^/"))]
    pub cwd: Option<String>,
    /// Wait up to 30 seconds for completion/output; never approves a command.
    #[schemars(range(max = 30_000))]
    pub wait_ms: Option<u32>,
}

/// The variants are disjoint: a target override on an existing session is invalid.
#[derive(Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum RunCommand {
    Existing(ExistingSessionCommand),
    OneShot(OneShotCommand),
}

#[derive(Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetCommand {
    #[schemars(length(min = 1))]
    pub run_id: String,
    pub output_cursor: Option<String>,
    #[schemars(range(max = 30_000))]
    pub wait_ms: Option<u32>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CancelCommand {
    #[schemars(length(min = 1))]
    pub run_id: String,
}

pub enum ToolRequest {
    GetAccessStatus(ListRequest),
    ListCommands(ListRequest),
    ListTargets(ListRequest),
    OpenSession(OpenSession),
    ListSessions(ListRequest),
    CloseSession(CloseSession),
    RunCommand(RunCommand),
    GetCommand(GetCommand),
    CancelCommand(CancelCommand),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidRequest {
    UnknownTool,
    InvalidArguments,
}

/// Return only fixed errors: serde error messages can contain caller-supplied secrets.
pub fn parse(name: &str, arguments: JsonObject) -> Result<ToolRequest, InvalidRequest> {
    fn decode<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, InvalidRequest> {
        serde_json::from_value(value).map_err(|_| InvalidRequest::InvalidArguments)
    }
    let value = Value::Object(arguments);
    let request = match name {
        "get_access_status" => ToolRequest::GetAccessStatus(decode(value)?),
        "list_commands" => ToolRequest::ListCommands(decode(value)?),
        "list_targets" => ToolRequest::ListTargets(decode(value)?),
        "open_ssh_session" => ToolRequest::OpenSession(decode(value)?),
        "list_ssh_sessions" => ToolRequest::ListSessions(decode(value)?),
        "close_ssh_session" => ToolRequest::CloseSession(decode(value)?),
        "run_command" => ToolRequest::RunCommand(decode(value)?),
        "get_command" => ToolRequest::GetCommand(decode(value)?),
        "cancel_command" => ToolRequest::CancelCommand(decode(value)?),
        _ => return Err(InvalidRequest::UnknownTool),
    };
    let valid = match &request {
        ToolRequest::ListTargets(_)
        | ToolRequest::ListSessions(_)
        | ToolRequest::ListCommands(_)
        | ToolRequest::GetAccessStatus(_) => true,
        ToolRequest::OpenSession(r) => {
            !r.target_id.is_empty()
                && !r.request_key.is_empty()
                && r.request_key.len() <= 128
                && valid_wait(r.wait_ms)
        }
        ToolRequest::CloseSession(r) => !r.session_id.is_empty(),
        ToolRequest::RunCommand(RunCommand::Existing(r)) => {
            !r.session_id.is_empty()
                && valid_command(&r.command, &r.request_key, r.timeout_ms, r.cwd.as_deref())
                && valid_input(r.stdin.as_deref(), &r.env)
                && valid_wait(r.wait_ms)
        }
        ToolRequest::RunCommand(RunCommand::OneShot(r)) => {
            !r.target_id.is_empty()
                && valid_command(&r.command, &r.request_key, r.timeout_ms, r.cwd.as_deref())
                && valid_input(r.stdin.as_deref(), &r.env)
                && valid_wait(r.wait_ms)
        }
        ToolRequest::GetCommand(r) => !r.run_id.is_empty() && valid_wait(r.wait_ms),
        ToolRequest::CancelCommand(r) => !r.run_id.is_empty(),
    };
    valid
        .then_some(request)
        .ok_or(InvalidRequest::InvalidArguments)
}

fn valid_input(stdin: Option<&str>, env: &BTreeMap<String, String>) -> bool {
    stdin.is_none_or(|s| s.len() <= 32768)
        && env.len() <= 64
        && env.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>() <= 16384
        && env.iter().all(|(k, v)| {
            let mut bytes = k.bytes();
            bytes
                .next()
                .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
                && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
                && !v.contains('\0')
        })
}

fn valid_wait(wait: Option<u32>) -> bool {
    wait.is_none_or(|ms| ms <= 30_000)
}

fn valid_command(
    command: &str,
    request_key: &str,
    timeout: Option<u32>,
    cwd: Option<&str>,
) -> bool {
    !command.is_empty()
        && command.len() <= 32 * 1024
        && !command.contains('\0')
        && cwd
            .is_none_or(|path| path.starts_with('/') && path.len() <= 32768 && !path.contains('\0'))
        && !request_key.is_empty()
        && request_key.len() <= 128
        && timeout.is_none_or(|ms| (1..=86_400_000).contains(&ms))
}

fn tool<T: JsonSchema>(name: &'static str, description: &'static str, read: bool) -> Tool {
    let mut schema = serde_json::to_value(schemars::schema_for!(T))
        .expect("schemas serialize")
        .as_object()
        .expect("object schema")
        .clone();
    // MCP tool input is always an object, including the disjoint run variants.
    schema.insert("type".into(), Value::String("object".into()));
    Tool::new(name, description, schema).annotate(
        ToolAnnotations::new()
            .read_only(read)
            .destructive(!read)
            .idempotent(read)
            .open_world(!read),
    )
}

/// Stable ordering; no target inventory, credential names or user text in discovery.
pub fn tools() -> Vec<Tool> {
    let mut tools = vec![
        tool::<ListRequest>("get_access_status", "Inspect this application's native grant, approval mode, expiry and execution limits. Works while UniSSH is locked; never unlocks or grants access. Cursor is unsupported.", true),
        tool::<ListRequest>("list_commands", "List this application's retained commands (up to 128), including request keys, previews, status and exit codes. No output or other applications' commands. Cursor is unsupported. Command metadata and request keys remain until the grant ends; output expires after 10 minutes.", true),
        tool::<ListRequest>("list_targets", "List servers allowed by the current UniSSH grant.", true),
        tool::<OpenSession>("open_ssh_session", "Open a reusable SSH connection to an allowed target. Optional wait_ms (0..30000, default 0) waits for readiness; otherwise poll list_ssh_sessions. A connection does not share shell state or approve commands.", false),
        tool::<ListRequest>("list_ssh_sessions", "List this integration's explicit SSH connections and their states. User terminal tabs and one-shot connections are excluded.", true),
        tool::<CloseSession>("close_ssh_session", "Close an SSH connection and cancel its commands. Detached remote processes may continue.", false),
        tool::<RunCommand>("run_command", "Run a command under the native grant policy: manual confirmation or trusted application. Use session_id for an open connection, or explicit null plus target_id for a one-shot connection. Every command has independent shell state: cd and exports never persist. Optional stdin supplies up to 32 KiB UTF-8 followed by EOF; env sets literal POSIX variables for this invocation. Optional cwd is an absolute POSIX path for this invocation, without expansion. Optional wait_ms (0..30000, default 0) waits for completion; awaiting_approval returns immediately. The result includes an output page; continue get_command using next_cursor. Reuse request_key only for the same command, stdin, env, cwd, target/session and timeout; changing wait_ms is allowed.", false),
        tool::<GetCommand>("get_command", "Get command state and a bounded output page. Chunks use encoding=utf8 for text or base64 for binary bytes; honor encoding per chunk. Resume using next_cursor, even after completion, until no more chunks. Optional wait_ms (0..30000) waits for new output or completion. Polling never renews permissions.", true),
        tool::<CancelCommand>("cancel_command", "Cancel a command's channel. This does not guarantee termination of detached remote processes.", false),
    ];
    for t in &mut tools {
        let schema = match t.name.as_ref() {
            "get_access_status" => schemars::schema_for!(AccessStatusResult),
            "list_commands" => schemars::schema_for!(CommandsResult),
            "list_targets" => schemars::schema_for!(TargetsResult),
            "list_ssh_sessions" => schemars::schema_for!(SessionsResult),
            "open_ssh_session" | "close_ssh_session" => schemars::schema_for!(SessionResult),
            "get_command" | "run_command" => schemars::schema_for!(CommandOutputResult),
            _ => schemars::schema_for!(RunResult),
        };
        t.output_schema = Some(std::sync::Arc::new(
            serde_json::to_value(schema)
                .expect("output schema")
                .as_object()
                .expect("object schema")
                .clone(),
        ));
    }
    tools
}

/// Stable public errors. Raw transport/core messages must never cross this boundary.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ToolError {
    TimeoutLimit,
    RequestConflict,
    Locked,
    GrantRequired,
    GrantExpired,
    TargetUnavailable,
    HostUntrusted,
    HostChanged,
    SessionNotReady,
    SessionClosed,
    ConnectionLost,
    Busy,
    ApprovalDenied,
    ApprovalExpired,
    OutputExpired,
    OutcomeUnknown,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct TargetResult {
    pub target_id: String,
    pub alias: String,
    pub available: bool,
    pub vault: String,
    pub groups: Vec<String>,
    pub tags: Vec<String>,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct TargetsResult {
    pub targets: Vec<TargetResult>,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct SessionResult {
    /// Upper bound in Unix seconds, or null for no grant expiry. Idle closure may be earlier.
    pub expires_at: Option<u64>,
    pub session_id: String,
    pub target_id: String,
    pub state: String,
    pub error: Option<ToolError>,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct SessionsResult {
    pub sessions: Vec<SessionResult>,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct RunResult {
    pub run_id: String,
    pub session_id: Option<String>,
    pub target_id: String,
    pub state: String,
    pub error: Option<ToolError>,
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum OutputEncoding {
    Utf8,
    Base64,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct OutputChunk {
    pub cursor: String,
    pub stream: String,
    /// utf8 is literal text; base64 preserves binary or invalid UTF-8 bytes.
    pub encoding: OutputEncoding,
    pub data: String,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct CommandOutputResult {
    #[serde(flatten)]
    pub run: RunResult,
    pub chunks: Vec<OutputChunk>,
    pub next_cursor: String,
    pub truncated: bool,
    pub exit_code: Option<u32>,
}

impl ToolError {
    pub fn message(self) -> &'static str {
        match self {
            Self::TimeoutLimit => "The requested timeout exceeds the native grant limit. Check get_access_status or change access in UniSSH.",
            Self::RequestConflict => "The request key was already used for different arguments.",
            Self::Locked => "Unlock UniSSH in the desktop application.",
            Self::GrantRequired => "Allow this integration's access in UniSSH.",
            Self::GrantExpired => "The access grant has expired or was revoked.",
            Self::TargetUnavailable => "The target is unavailable.",
            Self::HostUntrusted => "Verify the SSH host key in UniSSH before connecting.",
            Self::HostChanged => "The SSH host key changed. Review it in UniSSH.",
            Self::SessionNotReady => "The SSH session is not ready.",
            Self::SessionClosed => "The SSH session is closed or unavailable.",
            Self::ConnectionLost => "The SSH connection was lost; commands are not retried.",
            Self::Busy => "The requested operation is busy. Try again later.",
            Self::ApprovalDenied => "The command was denied in UniSSH.",
            Self::ApprovalExpired => "The command approval request expired.",
            Self::OutputExpired => "The retained command output has expired.",
            Self::OutcomeUnknown => {
                "The remote outcome is unknown. Do not automatically repeat the command."
            }
        }
    }
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct AccessStatusResult {
    pub status: String,
    pub message: String,
    pub approval_mode: Option<String>,
    pub remaining_seconds: Option<u64>,
    pub limits: AccessLimits,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct AccessLimits {
    pub max_timeout_ms: u32,
    pub default_timeout_ms: u32,
    pub max_connections: u32,
    pub max_active_commands: u32,
    pub max_retained_commands: u32,
    pub max_session_records: u32,
    pub output_per_run_bytes: u32,
    pub output_page_bytes: u32,
    pub output_retention_seconds: u32,
    pub idle_session_seconds: u32,
    pub stdin_bytes: u32,
    pub env_bytes: u32,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct CommandsResult {
    pub commands: Vec<CommandSummary>,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct CommandSummary {
    #[serde(flatten)]
    pub run: RunResult,
    pub request_key: String,
    pub command_preview: String,
    pub exit_code: Option<u32>,
    pub elapsed_ms: u64,
}
