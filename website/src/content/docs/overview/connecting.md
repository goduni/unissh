---
title: Connecting to hosts
description: Two-factor logins, the saved password at sudo prompts, hardware keys through the system ssh-agent, agent forwarding, snippets, session recording, algorithm policy, and what each one costs you.
---

Everything on this page is per host and off unless you turn it on, with two
exceptions: post-quantum key exchange, which is on for every connection and has
been since the first release, and the offer to insert a saved password at a
password prompt, which only ever offers.

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

## The saved password at `sudo` and other prompts

On a host you logged into with a saved password, a later prompt for that same
password — `[sudo] password for you:`, `doas (you@host) password:` — brings up
an offer in the pane: **Insert saved password**, naming the saved
password. Click it, or press **Ctrl+Shift+P** (**⇧⌘P** on macOS) while the offer
is shown. The password is typed, not submitted: Enter is still yours. The
offer sits at the edge of the pane away from the cursor, so the prompt stays in
sight.

Bare `Password:` prompts (`pkexec`, `login`) are offered only if you also turn
on **Also offer at bare “Password:” prompts** in Settings → Terminal. A bare
prompt names no one, and it could be any program on any machine. `su` asks for
the other account's password, not yours, so the offer is no use there.

What it cannot do: **tell which machine is asking.** The app sees what is
printed in the terminal, not where it comes from. After you `ssh`, `telnet` or
`ftp` from that host to another one, a prompt there can bring up the same offer,
and accepting it sends this host's password there. That is why the offer never
names a host, and why it is never offered for a host with a username template:
that password is the gateway's, and the prompts are the machines behind it.

What it will not do, on purpose:

- **Offer it anywhere else.** The prompt is recognised by the app's core, not
  guessed at by the window, and a prompt for someone else's password is not
  offered: `sudo` asking for another user, a nested `ssh` asking for
  `user@other-host's password`, a key passphrase, a `git` credential, a database
  client's `Enter password:`.
- **Retry a wrong password by itself.** Start typing and the offer goes away.
  If the same prompt comes straight back after a fill — `sudo` asking again —
  the saved password was probably refused; you are told so, and it is not typed
  again in that session until you change it in the vault, because typing a
  wrong password repeatedly is how accounts get locked. A program that simply
  exits on a wrong password (`doas`, `su`), or a prompt that comes back much
  later, is not recognised as a refusal: you get the offer again, and each
  attempt still takes your click. The other way round, a second prompt of the
  same kind within seconds — `sudo a; sudo -k; sudo b` — looks like a refusal:
  type that one yourself. The saved password then stays off for the rest of the
  session; a new session offers it again.
- **Show it.** The password never reaches the window or the clipboard. If a
  prompt turns out to echo what it reads, the password is masked on screen and
  in the session recording, the line is cleared, and you are warned.

Settings → Terminal turns the offers off.

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
