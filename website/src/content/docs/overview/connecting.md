---
title: Connecting to hosts
description: Two-factor logins, hardware keys through the system ssh-agent, agent forwarding, persistent tmux sessions, algorithm policy, and what each one costs you.
---

Everything on this page is per host and off unless you turn it on, with one
exception: post-quantum key exchange, which is on for every connection and has
been since the first release.

Several of these options trade something real for what they give you. Where that
is the case, this page says what the trade is rather than only what the feature
does.

## Two-factor logins

If a host asks for a one-time code, a push confirmation or a forced password
change, UniSSH asks you. Nothing to configure.

The mechanism is SSH's `keyboard-interactive`. A stored password still answers a
plain PAM round by itself — that is the case where the server only wants the
password it already has and there is nothing for you to decide. A second round,
which is where a TOTP code or a Duo push lives, is put to you.

The field is masked when the server says the answer is secret and shown when it
says otherwise, because that flag is the server telling you whether you are
typing a login name or a code.

## Hardware keys, via the system ssh-agent

Set a host's authentication to **System agent** and pick an identity. Signing
then happens in your operating system's ssh-agent rather than in UniSSH.

That is the route to hardware, and it covers more than one kind at once:

- FIDO/U2F security keys (YubiKey and friends)
- PKCS#11 smart cards
- Secure Enclave keys on macOS
- 1Password's SSH agent, `gpg-agent`, and anything else speaking the protocol

The picker lists what the agent currently holds, so "my token isn't plugged in"
is visible before a connection fails rather than after.

:::caution[What this costs]
For a host set up this way, the guarantee that a key never leaves UniSSH does not
apply — the key was never UniSSH's. It lives in the agent, and anything that can
reach the agent socket can ask it to sign. That is the same trust the tool
providing the key already asks of you, and it is the price of a token being
usable at all. UniSSH stores only the public key, which is a handle, not a
secret. See the [threat model](https://github.com/goduni/unissh/blob/main/THREAT_MODEL.md).
:::

If UniSSH cannot find the key in the agent it says so and names the fix, instead
of reporting a generic authentication failure that would send you to check the
key when the real problem is an unplugged token.

## Forwarding the agent

**Off by default.** Turn it on for a host and programs running *there* — `git`,
`scp`, `ssh` to a third machine — can sign with the key that session is using,
without the key ever being copied to that host.

UniSSH's forwarding is deliberately narrower than OpenSSH's:

- **One key.** Only the key this connection authenticated with is offered.
  OpenSSH forwards your whole agent, which hands the remote host a list of every
  key you hold — in effect a map of everywhere you log in — and lets it request a
  signature with any of them.
- **Every signature asks you.** A prompt names the host and, when the payload is
  an SSH login, the identity that signature would log in as. Refusing is the
  default: closing the dialog, dismissing it, or leaving it unanswered all
  decline.
- **Read-only.** Requests to add, remove, lock or unlock keys are refused
  outright. Those arrive from the remote machine, and a forwarded agent has no
  business honouring them.
- **Target only.** A jump host never gets a forwarded agent. A bastion is
  precisely the machine `ProxyJump` exists to keep your key away from.

:::caution[What this costs]
While a forwarded session is open, anything that can reach the socket on that
host can ask you to sign — every process running as your user there, not only
root. The confirmation prompt is what makes this visible instead of silent. If
you do not need `git` or `ssh` to work *on the remote machine*, leave it off:
`ProxyJump` already reaches a target through a bastion without forwarding
anything.
:::

## Persistent sessions (tmux)

Attach to a `tmux` session on the host instead of starting a bare shell, so work
keeps running when the connection drops or a phone sleeps, and reconnecting
returns you to it. Requires `tmux` on the server.

The session name is derived from the host's stable id, so it survives renaming
the host — reattaching would otherwise break the moment you edited the label.

:::note[Where your work lives]
The session, its scrollback and anything still running stay on that host after
you disconnect, and anyone who can log in as that user there can attach to it.
That is the point of the feature, and worth knowing before you enable it on a
shared machine.
:::

## Snippets and startup commands

A snippet is a command you keep. It is vault content, so it is encrypted at rest
and syncs with everything else — a command line routinely carries hostnames,
ticket ids and the occasional pasted token.

- **⌘K** finds snippets by name or by what they run, and types the chosen one
  into the active pane. It does not execute: pressing Enter stays your decision,
  so a mis-click cannot be destructive.
- **Per host**, snippets can be marked to run on connect. Those *do* execute, in
  the order you picked them — a startup command that needed a manual Enter every
  time would do nothing for anyone.

## Session recording

Per host, records what happens in interactive sessions as
[asciicast v2](https://docs.asciinema.org/manual/asciicast/v2/), encrypted in the
vault like any other item.

Because the format is standard, a recording can be exported to a file and played
with `asciinema` by someone who does not run UniSSH — which is what makes it
usable as evidence rather than only as a convenience.

Capped at 8 MB per session. A recording that reaches the cap is marked truncated
rather than ending quietly, because a partial recording that looks complete is
worse than no recording.

:::note[Where your output lives]
Enabling this stops terminal output being ephemeral. It is stored and synced like
any vault item — encrypted, so your server cannot read it — but anything that
appeared on screen, including a token echoed by a command or a dumped config, is
now kept.
:::

## Algorithm policy

By default UniSSH negotiates a vetted set, with **hybrid post-quantum key
exchange first**: `mlkem768x25519-sha256` (ML-KEM-768 + X25519, NIST FIPS 203),
falling back to classical curve25519 on servers that do not offer it. Hybrid
means an attacker has to break both halves, and it is what defends traffic
recorded today against being decrypted later.

**Modern only** (Settings → Connection) tightens that: post-quantum key exchange
**required** with no classical fallback, Ed25519 host keys, AEAD ciphers,
encrypt-then-MAC. A server that cannot meet it stops connecting rather than
quietly downgrading — which is the point, and why it is off by default.

There is deliberately no "compatibility" mode that re-enables SHA-1 MACs, CBC
ciphers or small DH groups. The defaults already exclude them; a switch that put
them back would be a footgun in a client whose argument is that its defaults can
be trusted.

## Importing `~/.ssh/config`

UniSSH applies `Host` patterns (including `!` negation), `HostName`, `Port`,
`User`, `IdentityFile`, `ProxyJump`, `LocalForward`, `RemoteForward`,
`DynamicForward`, `SetEnv`, `ServerAliveInterval`, `ConnectTimeout` and
`Compression`, and follows `Include`.

Everything it cannot apply — `ProxyCommand`, `Match` blocks, anything else — is
**reported with its line number** in the import preview. A real config is mostly
directives no GUI client implements, and importing one in silence leaves you
believing your `ProxyCommand` came across when it did not.
