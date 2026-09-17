---
title: Quickstart (local, no server)
description: Drive the UniSSH core end-to-end from the terminal — create a local vault, generate an SSH key, and connect — with no server and no UI.
---

The fastest way to feel UniSSH is the **local, single-device** flow: an encrypted local vault, a generated SSH key, and a real connection — **no server, no sync, no UI**. The core ships a temporary CLI harness (`unissh`, crate `unissh-cli`) that drives the same [FFI facade](../../components/crates/) the desktop client uses.

This is a genuinely useful standalone product on its own: a fully working single-device SSH client with an encrypted local store.

## Prerequisites

You need the [core build prerequisites](../install/): Rust 1.95+, a C toolchain, and system OpenSSL. No network access is required.

## End-to-end flow

```bash
# 1) Initialize an identity. Prints the Secret Key (your Emergency Kit) on the last line.
SK=$(cargo run -p unissh-cli -- init --password pw | tail -1)

# 2) Create a local vault.
cargo run -p unissh-cli -- create-vault \
    --secret-key $SK --password pw --id default --name Default

# 3) Generate an SSH key as an item inside the vault.
#    The private key is encrypted into the vault; only the public key leaves the core.
cargo run -p unissh-cli -- gen-key \
    --secret-key $SK --password pw --vault default --item id_ed25519

# 4) Run a command on a host, optionally through a bastion (ProxyJump).
cargo run -p unissh-cli -- exec \
    --secret-key $SK --password pw --vault default --item id_ed25519 \
    --host 10.0.0.5 --user deploy --command "uname -a" \
    --jump bastion:22:admin:id_ed25519

# 5) Or open an interactive terminal (PTY).
cargo run -p unissh-cli -- shell \
    --secret-key $SK --password pw --vault default --item id_ed25519 \
    --host 10.0.0.5 --user deploy
```

### What just happened

- `init` generated your **keyset** and a high-entropy **Secret Key** on the device. The Secret Key is your Emergency Kit — it **never leaves the device** in normal operation and is the only path back if you lose everything. Store it safely.
- `create-vault` made a **local vault** (sync target `none`) with its own random 256-bit Vault Key.
- `gen-key` stored an SSH **private key as an encrypted item** in the vault. On disk it is only ciphertext; the plaintext private key is never written to disk.
- At connect time the vault is unlocked, the per-item key decrypts the private key **into memory**, it is handed to the in-memory SSH agent (`mlock`-ed, `zeroize`-d after use), and `russh` authenticates via `russh::auth::Signer` — the private key never leaves the agent.
- The interactive session (`shell`) streams output through a `SessionObserver` callback.

:::note[On the Emergency Kit]
If you supply `--password`, the unlock key is `combine(Argon2id(password), Secret Key)`. You can also run password-less (SSO + trusted-devices style) where the Secret Key is the root. Either way: **lose every device and the Secret Key, and that instance's data is gone.** This is the honest cost of zero-knowledge — see the [security model](../../architecture/zero-knowledge-model/).
:::

## Where to go next

- Add a server for multi-device sync and team sharing → [Docker Compose deployment](../../operations/deploy/).
- Understand the design → [System overview](../../architecture/system-overview/) and the [crypto & key hierarchy](../../architecture/crypto-and-keys/).
- Use the desktop app instead of the CLI → [Desktop & mobile client](../../components/client/).
