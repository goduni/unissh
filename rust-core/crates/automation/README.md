# unissh-automation

Native authorization and execution broker for the embedded desktop MCP adapter.
The default build uses an executor trait for deterministic tests. The `core`
feature connects it to UniSSH's existing vault, Personal identity resolver and SSH
transport. HTTP cannot create grants, approve commands or supply authentication.

Grants can be unbounded (`None`) or timed (a positive `u32` number of seconds). They are never
persisted; lock, restart and revocation still invalidate unbounded grants. Security-relevant vault/trust/identity writes
conservatively invalidate all current grants, including verified sync changes.
Explicit SSH connections expire after five idle minutes. The native grant chooses
manual confirmation (default, two-minute immutable review of command, cwd, stdin and env) or
trusted application (immediate execution). MCP cannot select or elevate this
policy. Both paths share admission checks and cancellation. A null session creates
an owned one-shot connection after authorization. Neither mode retries commands.
Optional bounded waits on open/run preserve asynchronous execution and deduplication;
wait expiry does not cancel the operation. cwd is a literal absolute POSIX directory
for one exec; it never changes the reusable connection's shell state.

Eight physical connections overall, four connections per grant shared by both
modes, bounded
records, 1 MiB output per run and 8 MiB total bound resource use. Output pages use
UTF-8 text where valid and base64 for binary/NUL or invalid UTF-8. Each stream
buffers at most three incomplete UTF-8 bytes; termination flushes them losslessly.
Published chunks/cursors are immutable and bytes in these buffers count toward limits.
Discarded output is marked truncated while the SSH reader continues draining.
Cancellation closes a channel; detached remote processes may continue.

`Broker::grant`, `grant_with_policy`, `approve`, `review` and `revoke` are trusted native APIs. Keep
them out of the MCP router. Install native SDK log suppression before binding
real broker data to HTTP, as documented by `unissh-mcp`.

Host-enabled MCP recordings are created after native authorization through the
Core executor. The transport sink captures before broker retention limits;
blocking workers finalize independently of polling and preserve cancellation
history even after revocation removes broker rows. Recorder creation/finalization
must run outside the broker state lock. Core owns the active registry, encrypted
writes and lock-time partial flush. Recording references/status appear only in
native review, never in MCP tool responses. See `docs/desktop-mcp.md` for limits
and the versioned export extension.

The native `grant_with_limits` API sets a command-duration ceiling (default 10
minutes, at most 24 hours). MCP timeout arguments can only reduce it. Bounded
initial stdin is followed by EOF; POSIX environment values are quoted literally.
Inputs participate in submission-key conflicts and are shown in native review.
`list_commands` is grant/caller scoped; `get_access_status` can explain missing
access without exposing target inventory. Target context contains only the granted
host's vault/group labels and tags. No remote file or standalone note tools exist.
