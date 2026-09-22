# Desktop MCP access

UniSSH can expose selected saved SSH hosts to a local AI application through an
embedded MCP server. Open **MCP** in the desktop main menu to enable it. The server runs
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
   when it is shown; only its digest is stored. The token itself has no expiry.
   Rotating a token revokes its old permissions and connections. Deleting the integration disables its token.
4. Configure your AI application with the displayed endpoint and an
   `Authorization: Bearer <TOKEN>` header. The copied configuration contains a
   placeholder, never the actual token. Keep the real token in the application's
   secret storage or private user configuration, outside a Git repository.
5. Grant access to saved hosts with **No expiry**, a preset duration, or a custom
   number of minutes, hours or days. The duration starts when you grant access.
   Choose a vault first, then select its hosts; selections can span several vaults.
   Choose **Confirm in UniSSH** (the default) to review each command, or explicitly
   select **Trust application** to execute commands immediately on these hosts
   with the SSH user's permissions. In trusted mode, configure confirmations in
   your AI client; UniSSH cannot verify that the client asks you. Acknowledge that
   command output can be sent to the AI provider. Editing access replaces the
   previous grant and cancels its sessions/runs; MCP tools cannot change this policy.

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

### Client-specific setup

Expand **Connect your AI application** in an application's MCP workspace. Select
your client to get its configuration format, copy it, and replace `<TOKEN>` with
that application's token. The examples use the listener's current address and
never embed the token automatically. Enable MCP before copying a configuration.

| Client | Setup shown in UniSSH | Reference |
| --- | --- | --- |
| Claude Code | `claude mcp add --transport http --scope user` with a bearer header | [Claude Code MCP](https://code.claude.com/docs/en/mcp) |
| Codex | `[mcp_servers.UniSSH]` with `url` and `http_headers` in `~/.codex/config.toml` | [Codex MCP](https://developers.openai.com/codex/mcp) |
| OpenCode | Remote server with `oauth: false` in the personal OpenCode configuration; select 1.x or 2.x to match its schema | [OpenCode 1.x](https://opencode.ai/docs/mcp-servers/), [OpenCode 2.x](https://opencode.ai/v2/docs/mcp-servers) |
| Cursor | `url` and `headers` under `mcpServers` in `~/.cursor/mcp.json` | [Cursor MCP](https://cursor.com/docs/mcp) |

Merge file-based examples with existing settings rather than replacing the whole
file. Keep token-bearing configuration outside version control. Run the client on
the same device as UniSSH; a remote agent cannot reach this loopback endpoint.

## Tools and connection lifetime

| Tool | Purpose |
| --- | --- |
| `list_targets` | Get opaque IDs and aliases for the current grant |
| `open_ssh_session` | Open a persistent non-PTY SSH connection, optionally waiting for readiness |
| `list_ssh_sessions` | Inspect this integration's explicit connections |
| `close_ssh_session` | Cancel its work and close its owned connection chain |
| `run_command` | Run an immutable command under the native grant policy, optionally waiting for completion |
| `get_command` | Poll state and read bounded stdout/stderr pages |
| `cancel_command` | Cancel a pending command or close its active exec channel |

For a persistent connection, call `open_ssh_session` with `target_id` and a unique
`request_key`. Pass `wait_ms` (0..30,000) to wait for readiness in the same call;
if it still returns `connecting`, poll `list_ssh_sessions`. Then submit:

```json
{"session_id":"<session-id>","command":"uname -a","request_key":"<unique-key>"}
```

Commands use independent exec channels on that same authenticated connection.
They share neither a shell nor working directory/environment changes. Only one
pending/running command is admitted per explicit session. MCP connections never
attach to the user's terminal tabs.

Use `cwd` for an individual command's working directory:

```json
{"session_id":"<session-id>","command":"git status --short","cwd":"/srv/my project","request_key":"<unique-key>","wait_ms":1000}
```

`cwd` must be an absolute POSIX path (at most 32 KiB, no NUL); omitted/null uses
the SSH server's initial directory. It is quoted literally: spaces and quotes
work, while `~`, `$HOME` and command substitutions are not expanded. This option
requires a POSIX-compatible remote shell. If changing directory fails, the
command is not executed. Both command and directory appear in manual review and
are bound to the submission key. A preceding `cd` or `export` in another exec
never affects this invocation.

For one connection per command, explicitly pass null:

```json
{"session_id":null,"target_id":"<target-id>","command":"df -h","request_key":"<unique-key>"}
```

The one-shot connection opens after native approval or immediately under a trusted grant and closes on completion, failure,
expiry or cancellation. Omitting `session_id` is invalid. A non-null session
rejects `target_id`; neither mode accepts address, user or credential overrides.
Stdin is closed immediately. No PTY, interactive shell, forwarding, file transfer,
local command, key export, or vault-reveal tool is exposed.

`run_command` always returns a `run_id` and the same output-page fields as
`get_command`: `chunks`, `next_cursor`, `truncated`, and `exit_code`. With manual
confirmation it immediately returns `awaiting_approval`, even with `wait_ms`.
With trusted access, optional `wait_ms` (0..30,000; omitted/zero means no wait)
waits for completion, returning the current state and first output page when the
wait expires. The command continues asynchronously. The wait does not extend
`timeout_ms` or the grant lifetime, and disconnecting never cancels a run.

Continue with `get_command` using `run_id` and the returned `next_cursor` as
`output_cursor`. Its optional `wait_ms` waits for new output or a state change.
Drain pages even after `completed` until `chunks` is empty. Chunks keep separate
stdout/stderr streams: `encoding: "utf8"` carries literal text, while
`encoding: "base64"` preserves invalid UTF-8 or binary data containing NUL.
Honor the encoding per chunk; do not base64-decode UTF-8 text. For example:

```json
{"cursor":"0","stream":"stdout","encoding":"utf8","data":"hello\n"}
```

Partial UTF-8 characters are buffered independently for each stream (up to three
bytes) across SSH packets and internal chunk boundaries. At termination an
incomplete character is returned as base64, never replaced. Published chunks and
cursors stay immutable. Stream-local byte order is preserved; a partial character
can appear after an intervening chunk from the other stream. `truncated` means
some bytes were discarded while SSH output kept draining. A nonzero `exit_code`
is a completed remote process, not transport success for the command's purpose.

Existing clients must honor `encoding` and use the output cursor returned by
`run_command` when continuing, or start at `"0"` to deliberately reread output.

If a submission response is lost, repeat the same request with the same
`request_key`. Different command, cwd, target/session or timeout arguments with an
existing key yield `request_conflict`. Changing only `wait_ms` is permitted.
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
- Grants can have no time limit or a finite expiry (a positive `u32` number of
  seconds through the native API; the UI offers presets and custom minutes,
  hours or days). No expiry does not bypass lock, restart or
  revision invalidation. Explicit idle sessions close after 5 minutes.
  Listing and polling do not renew either lifetime. Approvals expire after
  2 minutes. Command timeout defaults to 2 minutes, with a 10-minute maximum
  bounded by the grant when it has an expiry. Review displays the exact immutable command in escaped
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

Session results expose `expires_at: null` when the grant has no expiry. A Unix
timestamp is returned for timed grants. Idle closure and revocation apply to both.

## Command recordings

The host's **Record sessions** preference also records authorized MCP commands.
Each executed command has its own encrypted recording in the host's vault,
including one-shot commands and commands on a persistent SSH connection. Denied
requests are not recorded. Recording does not depend on the agent polling output.
The MCP caller cannot enable, disable, read or delete recordings through MCP tools.

Open a saved recording from native MCP command history or **Recordings**, where
it is marked **MCP** with the integration's native application label. Replay shows
the original command, explicit working directory, outcome and exit code. A nonzero
exit code is retained even though the transport completed normally. Failed and
cancelled runs are saved too. Vault lock flushes unfinished captures before
releasing encryption keys and marks them interrupted. Recording failures appear
in native command history while that history is retained; recordings are not a
durable audit guarantee against process crashes, disk failures or vault removal.

Capture retains at most **512 KiB of raw output or 8,192 chunks per command**,
whichever comes first; partial recordings are explicitly marked. The cap is
separate from the agent's output buffer. Recordings have the same encryption,
sync, export and deletion behavior as existing terminal recordings, so command
text and output may persist and sync when this preference is enabled.

Export remains asciicast v2: standard `o` events provide a readable preview with
terminal control sequences escaped. The optional header field `unissh_mcp` is a
**version 1** extension containing `application`, `host`, `port`, `user`, `command`, `cwd`, `outcome`,
`exit_code`, `truncated`, `duration_secs`, and `events`. Each original event has a
relative `time`, `stream` (`stdout` or `stderr`), `encoding: "base64"`, and `data`.
These raw events preserve binary bytes and stream identity losslessly up to the
capture limit; the readable preview may replace invalid UTF-8. Existing terminal
recordings and their encrypted envelopes require no migration.
