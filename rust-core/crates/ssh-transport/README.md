# unissh-ssh-transport

UniSSH SSH transport on [`russh`](https://crates.io/crates/russh) `0.63` (spec 10.4).
Builds on `ssh-agent` (key-based authentication) and `storage` (host key TOFU/pinning).

## Features

- **Connect + authentication** with a key from the embedded agent (`Auth::Agent`) or
  a password (`Auth::Password`). If the server rejects the `password` method but
  offers `keyboard-interactive` (a typical sshd with PAM), the client automatically
  tries it, answering each prompt with the same password (like OpenSSH); the number
  of InfoRequest rounds is bounded — a malicious server cannot keep the client in
  an endless loop. Interactive scenarios (OTP prompts in the UI) are out of scope.
- **ProxyJump and chains** of jump hosts — `SshClient::connect_through`.
- **Forwards:** local (`local_forward`), dynamic SOCKS5 (`dynamic_forward`),
  remote (`remote_forward`).
- **SFTP** (protocol v3, a manual implementation on top of the `sftp` subsystem) —
  `SshClient::open_sftp` → `Sftp`: `list_dir`, `read_file`, `write_file`, `stat`,
  `mkdir`/`rmdir`, `remove`, `rename`, `realpath`.
- **Host key TOFU + pinning:** on the first connect the key is pinned in
  `storage.known_hosts`; on subsequent ones it is verified. A mismatch →
  `TransportError::HostKeyMismatch { host, port, fingerprint }` (protection against MITM,
  spec 5.4). Consciously "trust the new key" — `trust_host_key(host, port, storage)`.
- **Certificates:** user certificates are supported for client authentication.
  Host certificates/host CA trust are not yet supported ([#89](https://github.com/goduni/unissh/issues/89));
  certificate negotiation stays disabled and presented host certificates are rejected.
- **Import of `~/.ssh/config`** — `SshConfig` (directives `Host`/`HostName`/`Port`/
  `User`/`IdentityFile`/`ProxyJump`, `*`/`?` patterns, "first value wins"
  semantics; `host_aliases()` — the list of concrete aliases for import).

```rust
use unissh_ssh_transport::{SshClient, ConnectOptions, Auth};

let opts = ConnectOptions::new("10.0.0.5", 22, "deploy",
    Auth::Agent { key_id: b"id_ed25519".to_vec() });
let client = SshClient::connect(&opts, &agent, &storage).await?;
let out = client.exec("uname -a").await?;

// through a bastion:
let client = SshClient::connect_through(&[bastion], &target, &agent, &storage).await?;
// local forward:
let guard = client.local_forward("127.0.0.1:0", "db.internal", 5432).await?;
```

## Security

- **Agent forwarding is DISABLED by default** (spec 10.2): the handler does not
  enable agent-forward; ProxyJump is used instead (the key is not handed to the bastion).
- The private key for authentication is taken from the agent transiently (bridged
  via the stable OpenSSH format, since `ssh-agent` is on `ssh-key 0.6` and `russh`
  is on `0.7`) and zeroized right away. The persistent secret stays `mlock`-ed in the agent.

## Tests

- `tests/ssh_config.rs` — unit tests of the parser (no network).
- `tests/integration.rs` — against a **real `sshd`** (brought up on a free
  port): connect + authentication with a key from the agent + `exec`, TOFU pinning,
  **ProxyJump chain**, **local forward**, **SFTP roundtrip** (against
  `sftp-server`), **`trust_host_key` after a mismatch**. Require `/usr/sbin/sshd`,
  `ssh-keygen` and `sftp-server`.

Implemented and compiling, but without a live test in this environment: dynamic SOCKS
and remote forward (covered at the code level; the direct-tcpip direction matches the
tested local forward).

## Out of scope (⏳ LATER)

The relay/bastion service and CA (spec 11). `#![forbid(unsafe_code)]`.
