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

A password prompt reads a key at a time with the terminal's signals off: Ctrl-C
cancels it and puts the terminal back. `unissh ssh host -- cmd | head` ends when
the reader does, with status 141 as `ssh` would. `unissh cp` downloads into a
temporary file beside the destination and renames it into place when the copy is
complete, so a failed copy leaves an existing file as it was. An upload, as with
`scp`, writes the remote file in place.

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
  only one there is), with no token. `--http` serves `http://127.0.0.1:<port>/mcp`
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
cannot show), the saved-password offer at `sudo` prompts, startup snippets,
auto-reconnect, port forwarding, editing hosts or vaults, claiming an instance,
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
