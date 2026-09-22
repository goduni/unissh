# unissh-automation

Native authorization and execution broker for the embedded desktop MCP adapter.
The default build uses an executor trait for deterministic tests. The `core`
feature connects it to UniSSH's existing vault, Personal identity resolver and SSH
transport. HTTP cannot create grants, approve commands or supply authentication.

Grants can be unbounded (`None`) or timed (a positive `u32` number of seconds). They are never
persisted; lock, restart and revocation still invalidate unbounded grants. Vault/trust/identity writes
conservatively invalidate all current grants, including verified sync changes.
Explicit SSH connections expire after five idle minutes; each command needs a
separate, immutable native approval within two minutes. A null session creates
an owned one-shot connection after approval. Neither mode retries commands.

Eight physical connections overall, four connections per grant shared by both
modes, bounded
records, 1 MiB output per run and 8 MiB total bound resource use. Output pages use
base64 chunks to preserve binary and split UTF-8 bytes; callers decode explicitly.
Discarded output is marked truncated while the SSH reader continues draining.
Cancellation closes a channel; detached remote processes may continue.

`Broker::grant`, `approve`, `review` and `revoke` are trusted native APIs. Keep
them out of the MCP router. Install native SDK log suppression before binding
real broker data to HTTP, as documented by `unissh-mcp`.
