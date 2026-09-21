# Desktop MCP access

UniSSH can expose selected saved SSH hosts to a local AI application through an
embedded MCP server. Enable it in **Settings → MCP** on desktop. The server runs
inside UniSSH at `http://127.0.0.1:<port>/mcp`; there is no companion executable,
cloud relay, or change to your SSH servers. It is disabled by default.

## Setup

1. Connect to the intended hosts in UniSSH and verify their host keys first.
   MCP requires existing pins for the target and every bastion. It cannot approve
   an unknown or changed host key. Resolve trust and Personal identity binding
   errors in the ordinary host settings before granting access again.
2. Enable MCP. Port `0` chooses an available port on first setup; the actual
   port is saved. An occupied saved port produces an error and requires an
   explicit port change.
3. Add an integration, for example “Local coding assistant”. Copy the token
   when it is shown; only its digest is stored. Rotating a token revokes its old
   permissions and connections. Deleting the integration disables its token.
4. Configure your AI application with the displayed endpoint and an
   `Authorization: Bearer <TOKEN>` header. The copied configuration contains a
   placeholder, never the actual token. Keep the real token in the application's
   secret storage or private user configuration, outside a Git repository.
5. Grant that integration access to specific saved hosts for 1–30 minutes and
   acknowledge that command output can be sent to the AI provider. Each command
   still requires a separate confirmation in UniSSH.

A Streamable HTTP client that accepts custom headers can use this configuration:

```json
{
  "mcpServers": {
    "UniSSH": {
      "type": "http",
      "url": "http://127.0.0.1:12345/mcp",
      "headers": { "Authorization": "Bearer <TOKEN>" }
    }
  }
}
```

Use the port shown by UniSSH. Client configuration formats vary: this is the
Claude Code HTTP shape, not a promise that every IDE accepts identical JSON.
The opt-in test `claude_cli_http_interoperability` checks the installed Claude
Code CLI using an isolated temporary configuration and a fixture token; it makes
no model request. The connection health check was verified with Claude Code
2.1.252 on Linux. IDE interoperability and actual macOS/Windows lifecycle checks
require validation on those applications/devices. Manual bearer-header
provisioning is supported; OAuth discovery
and browser login are not implemented. Clients requiring OAuth or stdio-only
servers are unsupported.

## Tools and connection lifetime

| Tool | Purpose |
| --- | --- |
| `list_targets` | Get opaque IDs and aliases for the current grant |
| `open_ssh_session` | Open a persistent non-PTY SSH connection asynchronously |
| `list_ssh_sessions` | Inspect this integration's explicit connections |
| `close_ssh_session` | Cancel its work and close its owned connection chain |
| `run_command` | Submit an immutable command for native confirmation |
| `get_command` | Poll state and read bounded stdout/stderr pages |
| `cancel_command` | Cancel a pending command or close its active exec channel |

For a persistent connection, call `open_ssh_session` with `target_id` and a unique
`request_key`, wait until `list_ssh_sessions` reports `ready`, then submit:

```json
{"session_id":"<session-id>","command":"uname -a","request_key":"<unique-key>"}
```

Commands use independent exec channels on that same authenticated connection.
They share neither a shell nor working directory/environment changes. Only one
pending/running command is admitted per explicit session. MCP connections never
attach to the user's terminal tabs.

For one connection per command, explicitly pass null:

```json
{"session_id":null,"target_id":"<target-id>","command":"df -h","request_key":"<unique-key>"}
```

The one-shot connection opens after approval and closes on completion, failure,
expiry or cancellation. Omitting `session_id` is invalid. A non-null session
rejects `target_id`; neither mode accepts address, user or credential overrides.
Stdin is closed immediately. No PTY, interactive shell, forwarding, file transfer,
local command, key export, or vault-reveal tool is exposed.

`run_command` returns a `run_id` in `awaiting_approval`. Poll `get_command` with
that ID and optionally `output_cursor` and `wait_ms` (up to 30,000). Chunks retain
separate stdout/stderr streams and encode raw bytes as base64; decode bytes in
order and preserve decoder state across chunks if displaying UTF-8. Advance to
`next_cursor`; `truncated` means some bytes were discarded while SSH output kept
draining. A nonzero `exit_code` is a completed remote process, not transport
success for the command's purpose.

If a submission response is lost, repeat the same request with the same
`request_key`. Different arguments with an existing key yield `request_conflict`.
Request keys are limited to 128 UTF-8 bytes. Use a new key only for an intentionally
new operation. No SSH reconnect or command
replay occurs automatically. HTTP disconnects do not close an SSH session or undo
an accepted command.

## Permissions, limits and troubleshooting

- Tokens identify integrations, not individual chats. Processes using the same
  token share that integration's grant and visibility. Create separate tokens
  for independent clients.
- A token cannot unlock UniSSH or grant access. Lock/unlock and app restart never
  restore grants. Revocation, expiry, token rotation/deletion, disabling MCP,
  observed OS screen lock/suspend, app exit/reset/update and security-relevant
  vault changes invalidate access. Native deadlines do not rely on UI timers.
- Revision invalidation is deliberately conservative: any vault item, membership,
  identity or trusted-key mutation, including verified sync, revokes current
  grants. Regrant after editing/syncing; MCP never silently follows a changed host.
- The maximum grant is 30 minutes; explicit idle sessions close after 5 minutes.
  Listing and polling do not renew either lifetime. Approvals expire after
  2 minutes. Command timeout defaults to 2 minutes, with a 10-minute maximum
  bounded by the grant. Review displays the exact immutable command in escaped
  JSON string notation, so newlines, terminal controls and bidi controls are visible.
- There are at most 8 SSH connections overall and 4 simultaneous connections
  per grant, shared by explicit and one-shot modes, 8 outstanding commands per
  integration, 128 command records
  per grant / 256 overall, and 32 KiB per command. Resource exhaustion returns
  `busy`. Output retains up to 1 MiB per run / 8 MiB total, pages up to 64 KiB,
  for at most 10 minutes and never beyond the grant. Evicted output reports
  `output_expired`. Regranting discards previous records and IDs.
- Cancellation closes local SSH channels; it cannot prove that detached remote
  children stopped or reverse filesystem/network effects. Treat `outcome_unknown`
  as uncertain execution, not permission to retry.
- All HTTP requests need the token and exact endpoint authority. Browser Origins,
  query strings and other authorities are rejected. Do not open the listener on
  LAN or put a reverse proxy in front of it. WSL, containers and remote IDE
  backends with another loopback namespace are not supported by this transport.
- Localhost does not authenticate UniSSH to the AI application and does not
  isolate local users. Another process can impersonate a stopped listener and
  capture a client's bearer token. This feature assumes a trusted local OS/user
  environment. It is not a sandbox against local malware or prompt injection.
- Approved shell commands can read remote secrets and send them out; credential
  isolation is not output redaction. Review the command and the selected host.

Registration uses a separate version-1 local `mcp.json` file with atomic writes,
owner-only permissions on Unix and the application's user-directory ACL on Windows.
It contains digests and metadata, never raw tokens, grants or SSH credentials.
Unknown/corrupt versions disable MCP instead of resetting trust. No vault format,
AAD encoding, encrypted-sync wire format or database schema migration is added.
