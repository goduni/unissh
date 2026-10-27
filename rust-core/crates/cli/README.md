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
unissh hosts add|edit|rm, groups, secrets, keys, identities, snippets add   # see Editing the vaults
unissh sync | status | logout
unissh mcp                     # an MCP server for a local AI agent (see below)
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
unissh secrets show <name> [--reveal [--yes]]                   # --reveal prints the secret
unissh secrets rm <name>
unissh keys generate <name> | import <name> <file|-> | public <name> | certificate <name> <file|->
unissh keys rotate <name>                                       # a new pair in place
unissh keys rotation list | abandon <name>
unissh identities list | add <name> --user U [--key K] | edit <name> | rm <name>
unissh snippets add [--label L] [--command C | --stdin]         # else $EDITOR
unissh snippets edit <name> | rm <name>
```

`add`, `edit` and `rm` after `unissh hosts` are subcommands now. To list the
hosts that mention one of those words, put `--` first: `unissh hosts -- add`.

A new item goes into the account's only vault, or the one `--vault` names; for an
existing one, `--vault` narrows the lookup. Items are named as hosts are: by
label (a secret by its name), `vault/label`, the start of a label, or their id.
A host's `--key`, `--password-item`, `--agent-key` or `--identity` also says how
it logs in; `--auth` says it outright.

A jump host is either `user@host[:port]` with `--jump-key` or
`--jump-password-item`, or another saved host of the same vault, referenced so
that its own settings apply. A saved host can be a jump host only if it logs in
with a key, a stored password or the system ssh-agent, the same hosts the app
offers. `--jump` gives the whole chain, and on `edit` it replaces the chain, so
`--jump-key` and `--jump-password-item` go with `--jump` there too.

A list flag such as `--tags` replaces the list, and an empty value (`--tags ""`)
clears it, as it clears `--color`, `--group` or `--proxy`. `--color` and
`--icon` take the ids the app's picker offers, listed in `--help`.

A password, note or private key is never an argument: it is asked on the
terminal (a password twice), read from stdin with `--stdin`, or from an owner-only
file with `--from-file`. `secrets show` prints only what an item is; with
`--reveal` it prints the password, the note or the private key, and nothing else.
A private key is printed only after you confirm the app's export warning on the
terminal. `--yes` skips the question, and without a terminal it is required.
`keys public` prints a public key freely. `keys import` asks for a passphrase on
the terminal when the key has one.

Every change syncs right away, as in the app. With `--offline`, or when the
server cannot be reached, the change is saved here and goes with the next sync;
a local vault does not sync at all. A vault this account can only view refuses
the change on this machine, before anything is stored. A change the server
refuses fails the command with its reason. A `hosts add` or `hosts edit` that
saved the host but not all that goes with it (the identity link, the group) says
what is missing and fails. Do not run `add` again then: finish the host with
`hosts edit`.

Deleting asks first on the terminal; `--yes` skips the question. `keys rotate`
replaces a key at once, which locks out every host that has only the old public
key. The app's guided rotation moves each machine over first; the rotations it
begins can be listed and abandoned here.
## MCP server

`unissh mcp` is the desktop app's MCP server (`docs/desktop-mcp.md`) in a terminal:
the same nine tools, the same broker and grant policy, over this machine's vaults.
An agent reaches only the hosts you grant it, and you decide how its commands are
approved. Nothing the agent sends can grant, approve or widen anything.

**What it cannot protect against.** An agent with a shell on the same OS account,
on a device that unlocks without a typed password (`--password-file`, or a copy
without a master password), has whatever the vaults hold: it can read that file and
run `unissh` itself. CLI grants and approvals cannot constrain it; they bound what an
agent does through MCP. A typed master password only raises the bar: such an agent
can catch it the next time you type it (its own `unissh` first on `PATH`, a line in
your shell's rc file), and it can replace the token digests in `mcp.json` to use an
existing grant from a client of its own. Give such an agent a separate OS account or
machine.

```bash
unissh mcp integrations add "Claude Code"            # prints a token, used only with --http
unissh mcp grants set "Claude Code" web --trusted --for 8h --command-limit 30m
unissh mcp grants set "Claude Code" web db           # confirm each command (--http only)
unissh mcp grants list [--json] | unissh mcp grants rm "Claude Code" (or --all)
unissh mcp limits [--max-connections 8] [--command-history 256] [--output-total 8]
claude mcp add unissh -- unissh mcp                  # stdio: trusted grants only (below)
unissh mcp --http [--port 8765]                      # loopback HTTP, in a terminal of its own
```

- **Transports.** By default it speaks MCP on stdin/stdout: the agent launches it,
  and as the process owner it acts for one integration (`--integration NAME`, or the
  only one there is), with no token. An integration is named by its id or as a
  host is (its label in any case, or the one label the name begins). `--http` serves `http://127.0.0.1:<port>/mcp`
  exactly like the desktop: every integration authenticates with its own
  `Authorization: Bearer <token>`. The port is remembered for next time. Global
  flags (`--offline`, `--home`, `--password-file`) go anywhere; the serving flags
  (`--integration`, `--http`, `--port`, `--verbose`) only with `unissh mcp` itself,
  not next to a subcommand.
- **stdio runs trusted grants only.** A client that starts `unissh mcp` owns its
  terminal (Claude Code draws its screen there), so a stdio server asks nothing on
  any terminal: commands of confirm grants are refused with the
  `approval_unavailable` tool error, and so are connections to hosts that ask for a
  password or a one-time code (store their key or password in the vault instead).
  It starts only if the vaults open without a question: `--password-file` (or
  `UNISSH_PASSWORD_FILE`) or no master password, and a kept Secret Key. The same
  holds for `--http` started without a terminal of its own (systemd, `nohup`, stdin
  redirected).
- **Approvals** happen only in `unissh mcp --http` started in a terminal of your own
  and kept in its foreground (its stdin is the controlling terminal; sent to the
  background with Ctrl-Z/`bg` or started with `&`, it answers each question with
  `approval_unavailable` and logs a warning). A command under a confirm grant is then
  asked about there, on `/dev/tty`: the exact command, working directory,
  environment and stdin in escaped string notation, the host, and the application
  asking. Only a typed `yes` allows it; anything else denies, and an unanswered
  question expires after two minutes, as in the app. Sign-in prompts of the hosts
  an agent connects to are asked on the same terminal, one question at a time.
- **Grants** mirror the desktop's access editor: hosts (named as for `unissh ssh`,
  across vaults), an expiry (`--for 30m|8h|7d`, default none), confirmation or
  `--trusted`, the longest a command may run (`--command-limit`, 1m–24h, default
  10m) and the per-grant resource limits (`--max-connections`,
  `--max-active-commands`, `--command-history`, `--session-history`,
  `--output-per-command`). `grants set` replaces the integration's previous grant.
  A grant is saved in the
  encrypted database and resumes after a restart while its hosts and the security
  records are unchanged; `grants list` says when one needs granting again.
- **Widening needs the master password, typed.** `grants set`, `integrations add`
  and `integrations rotate` first print what they will do (for a grant: the hosts as
  named, the expiry, whether commands are confirmed, the ceilings), then ask for the
  master password on the terminal: typing it is the confirmation, whatever
  `--password-file` says. They run only in the foreground of a terminal of their own,
  so a process that runs them with its input piped is refused. (A copy without a
  master password asks for a typed confirmation of the resolved hosts instead.)
  Revoking (`grants rm`, `integrations rm`) asks for nothing more than any command.
- **Changes from another terminal** apply to a running server at once, through the
  database: a revocation stops that integration's work immediately. Any write to the
  database by another process (a grant for any integration, a sync, a vault edit by
  another `unissh` command) also cancels every command and session in flight on the
  server before the unchanged grants come back, so the outcome of a command that
  was running may be unknown to the agent. A running `--http` server reads tokens
  only at start: restart it after `integrations rotate` or `rm`, or it keeps
  accepting the old token.
- **Lock and sleep (Linux).** Like the desktop, a running server pauses when the
  session locks or the machine goes to sleep (logind's `Lock`, the session's
  `LockedHint`, and `PrepareForSleep`): access is revoked, running commands are
  cancelled, and the saved grants resume on unlock, or on a wake while the session is
  not locked. Only logind is heard: a signal from any other process is ignored. A
  desktop that locks without telling logind does not pause it, and on macOS and
  Windows nothing is observed. Without logind it logs a warning at start.
- **Lifetime.** The vaults are unlocked for the life of the process (the interactive
  list's idle lock does not apply). It stops when the agent closes stdin, or on
  Ctrl-C, SIGTERM or SIGHUP; access is revoked before the transport stops, recorded
  commands are written and sent to the server (unless `--offline`), and the vaults
  are locked. Hosts with **Record sessions** on record each command, as in the app.
- **Logs** go to stderr: warnings, and with `--verbose` the broker's audit lines
  (grants and authorized commands, by id). The MCP SDK's own diagnostics are never
  logged at any level: they carry raw commands and output.

## Data

Everything lives in one directory, created 0700: `--home`, `UNISSH_HOME`,
`$XDG_DATA_HOME/unissh` or `~/.local/share/unissh`, in that order.

| File | What |
| --- | --- |
| `unissh.db`, `unissh-keyset.bin` | the core's encrypted instance |
| `link.json` | which server, account and device; nothing secret |
| `secret-key` | the account Secret Key, when kept (0600; refused if others can read it) |
| `last-sync`, `sync.lock` | when it last synced; one sync at a time |
| `mcp.json`, `mcp-limits.json` | `unissh mcp` integrations (token digests, never tokens) and its shared limits, in the desktop's formats |

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
cannot show), the saved-password offer at `sudo` prompts, running a host's
startup snippets, auto-reconnect, creating or sharing vaults, the guided key
rotation (begin and finish it in the app), claiming an instance, SSO sign-in,
and more than one server per machine. Interactive use needs a Unix terminal.

Sessions are recorded when the host asks for it, as in the app, and the recording
is sent to the server when the session ends. One-off commands are not recorded,
the same as Fleet commands in the app.

## Security

An unlocked CLI is a device of the account. Anyone who controls that machine
(root, or whoever compromises it) can read what the process holds in memory while
it runs. On a machine you do not fully trust, use `login join` with an account
that sees only what that machine needs, and revoke it when you are done.
[`THREAT_MODEL.md`](../../../THREAT_MODEL.md) has the full analysis.
