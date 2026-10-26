# unissh-cli

`unissh` is UniSSH in a terminal. It signs a machine without a GUI — typically a
server you reached over plain SSH — in as a device of a UniSSH account, keeps a
synced, encrypted copy of the account's vaults there, and connects to their hosts:
an interactive terminal, a one-off command, a file copy. It is the same core as the
desktop app, with the same vault format, host-key pinning and verify-before-apply
sync, and it never takes a secret on the command line.

The crate also builds `unissh-harness`, the original core harness for driving the
FFI facade without a server. It takes secrets as arguments and is for debugging
only.

## Getting it

Releases carry a static Linux binary per architecture,
`unissh-cli_<version>_linux-{x86_64,aarch64}` (musl, no shared libraries), hashed
into the signed `SHA256SUMS`. Install it as `unissh` on a server. The desktop
app's Linux binary has that name too, so on a machine with the app, use another
one such as `unissh-cli`. From source: `cargo build -p unissh-cli --release`.

## Signing in

There are three ways, and each creates this machine's instance:

```bash
unissh login pair                                     # the same account as a signed-in app
unissh login escrow https://unissh.example.com alice  # the same account, by password + Secret Key
unissh login join   https://unissh.example.com        # a separate account (asks for the invite)
```

- **pair**: in a signed-in app, open Settings → Server → Add device, then paste the
  seven lines it shows. They carry the pairing secret, so nothing of them is echoed,
  only a dot per line. The account's keys arrive over the end-to-end encrypted
  pairing channel, and the server only relays it. You choose a master password
  for this machine's copy.
- **escrow**: asks for the account password and Secret Key, then fetches the
  escrowed keyset. Escrow sign-in has to be on for the account. The machine
  enrolls as its own device, labelled `CLI · <OS>`.
- **join**: asks for the invite (the token or the join link; never an argument,
  where every user of the machine could read it), creates a new account here,
  prints its Emergency Kit once, and redeems the invite. **This is the right choice for a shared or production server.** The
  machine then holds only the vaults a vault admin grants that account, not
  everything your own account can open.

By default the Secret Key is kept in an owner-only file, so an unlock needs only
the master password; this matches the app keeping it in the OS keychain. Use
`--no-remember` to be asked for it on every unlock. For pair and join,
`--no-password` leaves this machine's copy without a master password, so the
Secret Key file alone unlocks it; an escrow sign-in always keeps the account
password.

## Using it

```bash
unissh                         # pick a host from a list; back to the list after each session
unissh hosts [filter] [--tag prod] [--json]
unissh ssh web                 # interactive terminal (~. ends it, ~? lists escapes)
unissh ssh root@web            # another user (not for Personal hosts)
unissh ssh web -- uptime       # one-off command; stdin is piped, the exit code comes back
unissh cp web:/var/log/app.log .        # one file, either direction; --force replaces
unissh known-hosts list|trust|forget
unissh sync | status | logout
```

Hosts are named by label, `vault/label`, the start of a label, or their address.
A name that matches several hosts is refused, with the candidates listed.

Every command unlocks the instance for that process only. The master password comes
from the terminal (`/dev/tty`, so pipes still work) or from an owner-only
`--password-file` / `UNISSH_PASSWORD_FILE`. A command that reads hosts syncs first
when the local copy is more than five minutes old; a sync that fails is a warning,
and the command uses the copy on this machine. `--offline` never contacts the server.

The interactive list locks the instance after 15 minutes without input and asks
for the master password again, on the terminal even when a password file is set.
A copy without a master password unlocks again with its kept Secret Key alone.

A password prompt reads a key at a time with the terminal's signals off: Ctrl-C
cancels it and puts the terminal back. `unissh ssh host -- cmd | head` ends when
the reader does, with status 141 as `ssh` would. `unissh cp` downloads into a
temporary file beside the destination and renames it into place when the copy is
complete, so a failed copy leaves an existing file as it was. An upload, as with
`scp`, writes the remote file in place.

### Editing the vaults

What the app edits, the CLI edits too, with the same fields and checks:

```bash
unissh hosts add web deploy@10.0.0.5 --key deploy-key --group Production --tags prod,web
unissh hosts add db admin@db.internal:2222 --auth password      # asks for a new password
unissh hosts add bastion-app app.internal --identity me --jump bastion
unissh hosts edit web --port 2222 --record on                   # only what the flags say
unissh hosts rm web
unissh groups list | add <label> [--parent G] | edit <group> | rm <group>
unissh secrets list [--json]
unissh secrets add-password <name> | add-note <name>            # asked on the terminal
unissh secrets show <name> [--reveal]                           # --reveal prints the secret
unissh secrets rm <name>
unissh keys generate <name> | import <name> <file|-> | public <name> | certificate <name> <file|->
unissh keys rotate <name>                                       # a new pair in place
unissh keys rotation list | abandon <name>
unissh identities list | add <name> --user U [--key K] | edit <name> | rm <name>
unissh snippets add [--label L] [--command C | --stdin]         # else $EDITOR
unissh snippets edit <name> | rm <name>
```

A new item goes into the account's only vault, or the one `--vault` names; for an
existing one, `--vault` narrows the lookup. Items are named as hosts are: by
label (a secret by its name), `vault/label`, the start of a label, or their id.
A host's `--key`, `--password-item`, `--agent-key` or `--identity` also says how
it logs in; `--auth` says it outright. A jump host is a saved host (referenced, so
its own settings apply) or `user@host[:port]` with `--jump-key` or
`--jump-password-item`. A list flag such as `--tags` replaces the list, and an
empty value (`--tags ""`) clears it, as it clears `--color`, `--group` or
`--proxy`.

A password, note or private key is never an argument: it is asked on the
terminal (a password twice), read from stdin with `--stdin`, or from an owner-only
file with `--from-file`. `secrets show` prints only what an item is; with
`--reveal` it prints the password, the note or the private key, and nothing else.
`keys public` prints a public key freely. `keys import` asks for a passphrase on
the terminal when the key has one.

Every change syncs right away, as in the app; with `--offline` it stays on this
machine until the next sync. A change the server refuses (an account that may
only view that vault, say) fails the command with the server's reason, and stays
here to be offered again. Deleting asks first on the terminal; `--yes` skips the
question. `keys rotate` replaces a key at once, which locks out every host that
has only the old public key; the app's guided rotation moves each machine over
first, and the rotations it begins can be listed and abandoned here.

## Data

Everything lives in one directory, created 0700: `--home`, `UNISSH_HOME`,
`$XDG_DATA_HOME/unissh` or `~/.local/share/unissh`, in that order.

| File | What |
| --- | --- |
| `unissh.db`, `unissh-keyset.bin` | the core's encrypted instance |
| `link.json` | which server, account and device; nothing secret |
| `secret-key` | the account Secret Key, when kept (0600; refused if others can read it) |
| `last-sync`, `sync.lock` | when it last synced; one sync at a time |

No session token is written to disk. Each command that needs the server signs in
with the unlocked keyset, using the same challenge signature as the app, and signs
out when it is done.

`unissh logout` revokes the device on the server and deletes this directory's
UniSSH files, after a last sync so that nothing made here is lost with it. It warns
first when a joined account has no other device, because deleting its data then
loses the account; `--yes` skips the question but still prints the warning.
`--local` skips the server, for a
machine that can no longer reach it; revoke the device from another one afterwards.

## Not here (yet)

Agent forwarding (each signature needs an approval prompt, which a raw terminal
cannot show), the saved-password offer at `sudo` prompts, startup snippets,
auto-reconnect, port forwarding, creating or sharing vaults, the guided key
rotation (begin and finish it in the app), claiming an instance,
SSO sign-in, and more than one server per machine. Interactive use needs a Unix
terminal.

Sessions are recorded when the host asks for it, as in the app, and the recording
is sent to the server when the session ends. One-off commands are not recorded,
the same as Fleet commands in the app.

## Security

An unlocked CLI is a device of the account. Anyone who controls that machine
(root, or whoever compromises it) can read what the process holds in memory while
it runs. On a machine you do not fully trust, use `login join` with an account
that sees only what that machine needs, and revoke it when you are done.
[`THREAT_MODEL.md`](../../../THREAT_MODEL.md) has the full analysis.
