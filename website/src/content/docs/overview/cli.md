---
title: Command-line client
description: Use UniSSH on a machine without a GUI — sign a server in as a device, sync the vaults there, and connect to their hosts from its terminal.
---

`unissh` is UniSSH in a terminal. It is for the machine with no desktop on it,
most often a server you reached over plain SSH and want to go on from. It signs
that machine in as a device of a UniSSH account, keeps a synced, encrypted copy
of the account's vaults there, and connects to their hosts. It uses the same core
as the desktop app, with the same vault format, host-key pinning and
verify-before-apply sync, and it never takes a secret on the command line.

## Install

Each [release](https://github.com/goduni/unissh/releases) carries the client as
one static Linux binary per architecture, so it runs on any distribution,
however old its libc: `unissh-cli_<version>_linux-x86_64` and
`unissh-cli_<version>_linux-aarch64`. Check it against the release's signed
`SHA256SUMS` before installing it:

```bash
V=0.7.0 A=x86_64   # the release you want; A=aarch64 on ARM
curl -fLO https://github.com/goduni/unissh/releases/download/v$V/unissh-cli_${V}_linux-$A
curl -fLO https://github.com/goduni/unissh/releases/download/v$V/SHA256SUMS
curl -fLO https://github.com/goduni/unissh/releases/download/v$V/SHA256SUMS.minisig
minisign -Vm SHA256SUMS -P 'RWQvV7DIid665aUPiJiN5NXimAehmWEjgRS9uLgi2nSWIUiiBY7ZKCAs'
sha256sum -c SHA256SUMS --ignore-missing
sudo install -m 755 unissh-cli_${V}_linux-$A /usr/local/bin/unissh
```

The desktop app's own binary on Linux is also called `unissh`. On a machine that
has the app installed, give the command-line client another name, for example
`/usr/local/bin/unissh-cli`, so the app's launcher keeps starting the app.

Or build it from source (see [Build from source](../../operations/build/) for the
prerequisites):

```bash
cargo build -p unissh-cli --release     # → target/release/unissh
```

## Sign the machine in

Pick one of three ways, depending on which account the machine should be.

**A separate account, joined by invite.** Use this for a shared or production
server. Create an invite in the app or the admin panel, then run:

```bash
unissh login join https://unissh.example.com
```

It asks for the invite (the token or the join link) on the terminal rather
than taking it as an argument, where any user of the machine could read it
before it is redeemed. Then it creates a new account on the machine, shows its
Emergency Kit once, and joins the server. The account can open only the vaults a vault admin grants it,
so the machine never holds more than it needs. Run `unissh sync` after the grant
to pull them.

**The same account as your app, by pairing.** In a signed-in app open
Settings → Server → Add device, then on the machine run:

```bash
unissh login pair
```

Paste the seven lines the app shows, and keep the card open until pairing
finishes. They hold the pairing secret, so they are not echoed: a dot shows for
each line received. The account's keys travel over the end-to-end encrypted pairing
channel; the server only relays the messages.

**The same account, by password and Secret Key.** This needs escrow sign-in to be
on for the account:

```bash
unissh login escrow https://unissh.example.com <handle>
```

Pairing and escrow both put your **whole** account on that machine. Use them on
machines you trust as much as your laptop.

Pairing and joining ask for a master password for this machine's copy; escrow
keeps the account password. Each keeps the Secret Key in an owner-only file so
that unlocking needs only that password, as the app keeps it in the OS keychain.
`--no-remember` asks for the Secret Key at every unlock instead.

## Connect

```bash
unissh                          # pick from a list; back to the list after each session
unissh hosts                    # list hosts: [filter] --tag prod --json
unissh ssh web                  # terminal on "web"   (~. ends it, ~? lists escapes)
unissh ssh root@web             # as another user
unissh ssh web -- systemctl status nginx    # one command; the exit code comes back
tar c ./site | unissh ssh web -- tar x -C /srv   # stdin goes to the command
unissh cp web:/var/log/app.log .            # one file, either direction
```

Hosts are named by label, `vault/label`, the start of a label, or their address.
A name that fits several hosts is refused, with the candidates listed.

Hosts resolve as they do in the app. A host with a personal identity uses yours,
jump hosts and proxies are followed, two-factor prompts are asked on the
terminal, and a host that records sessions is recorded, with the recording
uploaded when the session ends. The first connection to a host pins its key and
shows the fingerprint. If the key later changes, the connection stops, and
accepting the new key takes an explicit `unissh known-hosts trust <host> <fingerprint>`.

## Unlocking, syncing, scripts

Every command unlocks the instance for its own run. The master password is asked
on the terminal, so pipes still work, or read from an owner-only file:

```bash
UNISSH_PASSWORD_FILE=~/.config/unissh-password unissh ssh web -- uptime
```

A command that reads hosts syncs first when the local copy is more than five
minutes old. If that sync fails, you get a warning and the command uses the copy
on the machine. `--offline` never contacts the server, and `unissh sync` syncs now.
The interactive list locks after 15 minutes without input, and asks for the
master password on the terminal again, even when a password file is set.

Ctrl-C at a password prompt cancels it. `unissh ssh web -- cmd | head` stops
when `head` does (status 141, as with `ssh`). `unissh cp` replaces a downloaded
file only once the copy is complete, so a failed copy leaves the old one as it
was; uploads are written in place, as `scp` does.

Nothing that could resume a server session is stored. Each command that needs
the server signs in with the unlocked keys and signs out when done.

## Sign out

```bash
unissh logout          # revokes this device on the server, deletes its data here
unissh logout --local  # server unreachable: delete locally, revoke from another device
```

`logout` syncs once more before it deletes anything. If a joined account has no
other device, it says so first: deleting its data then loses the account. With
`--yes` the warning is still printed; only the question is skipped.

## What it does not do yet

Agent forwarding, the saved-password offer at `sudo` prompts, startup snippets,
auto-reconnect, port forwarding, editing hosts and vaults, claiming an instance,
SSO sign-in, and more than one server per machine. Interactive use needs a Unix
terminal. One-off commands are not recorded, the same as Fleet commands in the
app.

## Security

An unlocked `unissh` is a device of the account. Whoever controls the machine it
runs on can read what it holds while it runs, which is why a shared machine
should get an account of its own with only the vaults it needs. The
[threat model](https://github.com/goduni/unissh/blob/main/THREAT_MODEL.md) covers
the details.
