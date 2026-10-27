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
unissh cp -r ./site web:/srv/www        # a directory and everything in it, either direction
unissh tunnel web -L 5432:db:5432 -D 1080   # forward ports until Ctrl-C (-L, -R, -D as with ssh)
unissh run --tag prod -- uptime         # one command on many hosts: --tag, --group or host names
unissh snippets list [--json]
unissh snippets run restart web db --set service=nginx
unissh known-hosts list|trust|forget
unissh recordings list|play|export|rm   # see Recordings below
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

`unissh run` runs one command on many hosts, as the app's Fleet does: the hosts
with a tag (`--tag`, repeated for hosts with every one), the hosts of a group
(`--group`, nested groups included), or hosts by name. Each host connects as
`unissh ssh` would connect to it, up to `--parallel` (8) at a time, and the
command then has `--timeout` (30) seconds to finish; 0 means no limit. Each
line of output is led by the host's label (`web | ...`), stdout to stdout and
stderr to stderr, as each host finishes, and a summary line ends the run.
`--json` prints, per host, the command, its output, exit status and error
instead. `--dry-run` shows which host would run what, as which user, without
connecting. Hosts that want a password typed at every connection are skipped,
as in Fleet: use `unissh ssh` for those. The exit code is 0 when every host ran
the command with status 0, and 1 otherwise (a host failed, timed out, or did
not run).

Parameters in the command (`{{name}}`, `{{name:default}}`) are filled as in the
app, for `unissh run` as for a snippet: `{{host}}`, `{{user}}` and `{{port}}`
come from each host, and the rest are asked once on the terminal (Enter takes
the default) unless given with `--set name=value`; `--set name=` gives an
empty value. Without a terminal a parameter takes its default, and one without
a default needs a `--set`. A `--set` for a parameter the command does not have
is refused. `\{{` is a literal `{{`; `{{ spaced }}` and other braces are left
as written. `unissh snippets run` runs a saved snippet the same way.

A password prompt reads a key at a time with the terminal's signals off: Ctrl-C
cancels it and puts the terminal back. `unissh ssh host -- cmd | head` ends when
the reader does, with status 141 as `ssh` would. `unissh cp` downloads into a
temporary file beside the destination and renames it into place when the copy is
complete, so a failed copy leaves an existing file as it was. An upload, as with
`scp`, writes the remote file in place.

`unissh cp -r` copies a directory: into the destination when that is an
existing directory, else as the destination. Each file goes as a single-file
copy would, four at a time over one connection (`--parallel 1` to `16`, as the
app's Parallel transfers setting). Directories that exist are merged into; a
file that exists is replaced only with `--force`. Symbolic links inside the tree
are not followed, and they and anything else that is not a regular file or a
directory (sockets, pipes, devices) are named as skipped; the app's SFTP pane
copies links as links, the CLI does not copy them at all. A file that fails is
named and the copy goes on; the command then exits 1. Unlike `scp`, a download
creates the destination's missing parent directories. A remote name this system
cannot hold (on Windows, one with `\` or `:`) is skipped, and on macOS and
Windows so is a name that differs from another in its directory only in case.
A copy stopped with Ctrl-C can leave `.unissh-part` files behind.

`unissh tunnel` takes `-L [bind:]port:host:hostport`, `-R [bind:]port:host:hostport`
and `-D [bind:]port`, each as often as needed (IPv6 addresses in brackets), and
needs at least one. A forward listens on `127.0.0.1` (for `-R`, on the host)
unless an address is given; every interface has to be spelled out as `0.0.0.0`,
never an empty address or `*`, and a SOCKS proxy (`-D`) listens only on loopback.
Port 0 asks for any free port. The forwards open in groups, whatever order they
were typed in: every `-L`, then every `-R`, then every `-D`. Each one prints a
line once it listens, with the real port. If stdout's reader is gone when a
line is written, the forwards close and the exit status is 141. Each forward
is its own connection, so a host with two-factor sign-in asks once per forward. A forward that cannot open fails the command and closes
the ones already open. The tunnels stay up until Ctrl-C or SIGTERM, then close
cleanly; a second Ctrl-C while they close quits at once (status 130). A hang-up
ends the process as usual, without the clean close, and under `nohup` the tunnels
stay up. A connection that drops is not reopened.

### Recordings

```bash
unissh recordings list [filter] [--json]       # every vault's, newest first; times in UTC
unissh recordings play <id> [--speed 2] [--idle-limit 3]
unissh recordings export <id> session.cast     # --force replaces; `-` writes to stdout
unissh recordings rm <id> [--yes]
```

A recording is named by its id, or by any part of it that only one id contains
(the distinctive end is usually enough); an ambiguous part is refused, with the
candidates listed. The filter matches the label, host or vault.

`play` replays the output with its timing, `--speed` times as fast, with every
pause longer than `--idle-limit` seconds cut to that. Ctrl-C stops it. Keys
typed meanwhile go nowhere. However it ends (Ctrl-C, SIGTERM, SIGHUP, an error),
the terminal is put back: the main screen if the recording left it, a visible
cursor, plain text, no mouse reporting or bracketed paste, and the keyboard as it
was. A replay stopped by Ctrl-C exits with 130, by a signal with 128 plus its
number. It needs stdout to be a terminal; it warns when this one is smaller than
the recording's.

A recording is not trusted: whoever can write to a shared vault, or a recorded
host that was compromised, decides what is in it. So `play` passes on what draws
on the screen and drops what reaches past it: every OSC string (the clipboard,
the title), DCS, SOS, PM and APC strings, and the queries a terminal answers by
typing the answer in (device attributes, cursor and status reports, mode and
window reports, its version, ENQ), in their 8-bit forms too. It also drops the
modes that change what the keyboard sends or lock it (keyboard lock, local echo,
newline mode, VT52), and the reset at the end puts back the screen modes a
recording may leave on (VT52, synchronized output, reverse video, cursor shape,
margins). Keys are read from the controlling terminal
itself, and when the replay ends what is still coming in is read and discarded
before the keyboard is given back, so nothing reaches the shell as typed input.
That last guarantee is Unix-only: on Windows, `play` writes to stdout and does
not read the console, so an answer a console gives to something the filter let
through could still land in the shell's input.

`export` writes the recording exactly as the core keeps it: an
[asciicast v2](https://docs.asciinema.org/manual/asciicast/v2/) document that
`asciinema play` plays and anyone can read without UniSSH. The file is
owner-only (0600): `--force` writes a new file beside it and renames it over the
old one, so the old file's mode does not carry over; it refuses a symbolic link.
`--json` lists only metadata, never what was recorded.

`rm` asks first (`--yes` skips the question). On a cloud vault it sends the
deletion to the server, so the recording goes from every device of the vault;
with `--offline`, or when the server cannot be reached, it goes with the next
sync. In a vault this account can only view (a Viewer), `rm` is refused before
anything is deleted, and the recording stays where it is. Should the server
still refuse a deletion this machine allowed (the role changed since the last
sync, say), the command fails and says the recording is deleted on this machine
only.

**An export holds what the session showed**, in plain text: everything the
remote printed, including what it echoed of what was typed. Keystrokes are not
recorded. A password typed at a prompt that does not echo is not in it; in the
app, a saved password it fills at a prompt is masked out of the output should
that prompt echo it, but anything else the session printed is there. A recording
of an MCP command also carries, in its header, the exact command, its standard
input and environment, and its raw output. Treat an export like the vault item
it came from.

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
auto-reconnect, editing hosts or vaults, claiming an instance,
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
