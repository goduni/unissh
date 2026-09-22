# unissh-mcp

Embeddable HTTP MCP transport for the desktop application. This crate is a
library, not a separate executable or a public server. It has no dependency on
the vault, SSH transport or Tauri. The native application supplies authentication
and an authorization broker through `Authenticator` and `Backend`.

The initial implementation provides seven tools and strict request decoding:
`list_targets`, `open_ssh_session`, `list_ssh_sessions`, `close_ssh_session`,
`run_command`, `get_command`, and `cancel_command`.

`run_command` requires an explicit `session_id`. A string selects an existing
SSH connection and forbids `target_id`; null requires `target_id` and selects a
one-shot connection. Commands use independent exec channels, not shared shell
state. Optional cwd selects a literal absolute POSIX directory for that invocation.
Open/run accept wait_ms (0..30000, default 0) for short operations; waiting never
authorizes commands or changes grant/runtime deadlines. Run returns an output page
and next_cursor, including when still awaiting native approval. UTF-8 text chunks
use encoding=utf8; binary or invalid bytes use base64. Clients must honor encoding
and continue pagination after completion. Submission keys bind command, cwd,
target/session and timeout, but not wait_ms; they are not JSON-RPC IDs.

Command admission follows the native grant policy (manual confirmation by default,
or explicitly trusted application). No tool argument can elevate that policy.

`LocalServer::bind` accepts a port, never a bind address. Requests require the
exact loopback authority and a bearer credential; browser Origin headers and
URL query strings are refused. Authentication runs on every request, and the
credential is removed before dispatch to the MCP SDK. Request bodies are bounded.
No HTTP protocol session is used as an authentication or SSH-session identifier.

`NoGrants` denies all valid operations for transport testing. The desktop app
embeds this adapter with `unissh-automation` and its native Core executor.
The broker must enforce grants, ownership, deadlines, output limits and lifecycle
revocation before this adapter can be enabled in the product. It must revoke
access before stopping the listener. HTTP disconnection does not revoke access.

The embedding application MUST suppress all `rmcp` diagnostic targets (including
`rmcp::...`) in every tracing/log sink before enabling this adapter. The SDK logs
raw requests, responses and notifications, including at info level; removing the
Authorization header alone does not protect command text or output. An environment
log-level override must not bypass that suppression. This crate does not install a
global logger. The native logger applies `diagnostics_allowed` before every sink; adversarial
captured-log tests exercise real SDK requests with tracing-to-log enabled.

Manual bearer headers are the supported authentication mechanism; this is not
MCP OAuth discovery. Loopback HTTP assumes a trusted local environment: it does
not authenticate the server endpoint or isolate hostile local OS users. A model
provider may receive results forwarded by the local AI client.

The transport pins official `rmcp` 3.4.0 (Rust 1.88 minimum; repository toolchain
1.94). Tests exercise real loopback HTTP with both legacy initialization and
modern per-request protocol metadata. No user vault or real SSH server is needed.

```sh
cargo test -p unissh-mcp
cargo clippy -p unissh-mcp --all-targets -- -D warnings
```
