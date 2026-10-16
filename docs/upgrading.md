# Upgrading UniSSH

Read the **Compatibility** and any **Breaking changes** entries in the
[changelog](../CHANGELOG.md#061--2026-10-16) before upgrading. The changes in
0.6.1 preserve the vault format, AAD encodings and encrypted-sync
protocol; no vault conversion is required.

## Before installing

1. Keep your Secret Key / Emergency Kit and the password needed to unlock the
   instance. An application update does not replace either credential.
2. Export a portable encrypted backup of each important vault and keep its backup
   passphrase separately. A backup can be restored into a new local vault; it is
   not a replacement for server state or device enrollment.
3. Let transfers finish or stop them explicitly. Active SSH sessions, tunnels and
   transfers do not survive an application restart. SFTP retry plans are held in
   memory and do not survive exiting the app.
4. If you self-host, back up the server database and configuration using the
   [server backup procedure](../server/README.md#backups--restore-read-carefully).

## Install and verify

For a server-backed installation, upgrade the **server first**, then clients.
Server and client versions move together but are deployed separately. A newer
server serves older clients; a newer client against an older server is not
promised. Local-only installations have no server step.

Install the matching OS/architecture build through the desktop updater or the
[release downloads](https://github.com/goduni/unissh/releases). For a manual
installation, follow [release integrity verification](../README.md#verifying-release-integrity).

After opening the updated client:

- Unlock the existing instance and check its vaults, saved hosts and keys.
- Connect to a known host. A host-key change still needs independent verification;
  upgrading the client is not a reason to accept a different host key.
- For synced vaults, synchronize both devices, create a temporary note, verify it
  arrives on the other device, then remove it and synchronize again.
- To check a backup, restore it under a **new** vault name and verify representative
  items. Restore creates a local vault and never overwrites an existing vault.

## Changes to expect in 0.5.0

### SFTP

Folder transfers preserve symbolic links, ordinary Unix permissions and modification
times. Files are prepared beside their destination before commit. An SFTP server
must support `posix-rename@openssh.com` to overwrite an existing remote entry;
if it does not, the overwrite fails and leaves the old entry intact. Choose a new
name or a server with that extension.

Pause/retry keeps completed files and chosen destination names in the current
queue. An incomplete file starts again from zero. Equal file sizes do not prove
that an existing file is a valid partial copy. See the full
[transfer integrity notes](../client/README.md#transfer-integrity), including
Windows symlink permissions and concurrent source edits.

### Desktop MCP

MCP is optional and disabled by default. Open **MCP** in the main menu and follow
[the setup guide](desktop-mcp.md#setup) to register an application and grant hosts.
Manual command confirmation is the default.

Locking UniSSH ends active MCP work. Saved access can resume after unlock or
restart if its security data is unchanged and its original expiry has not passed;
commands are never replayed. Revoking access or rotating/deleting its token removes
saved permission. Keep token-bearing AI client configuration outside version control.

## Moving a local vault to a server

A local vault can be converted into a Cloud vault without re-typing anything.
Sign in to the server, then open **Settings → Vaults** and choose
**Move to server…** on the local vault.
The confirmation shows the target server and space, what will move, and offers
**Export backup first**, which runs the regular portable backup export and returns
to the confirmation.

The vault keeps its name, groups, items and host identities; host jumps and
Personal-identity bindings on this device that referred to it are re-pointed, and
if it was the account's Personal vault it remains the Personal vault. A reference
re-pointed inside another Cloud vault is an ordinary edit to that vault and
reaches your other devices when that vault syncs. It is a
re-keyed copy under a new vault id, made in one transaction: the local copy is
replaced, item version history starts fresh on the server, and the vault is
pushed right away. On the device that makes the move, items keep their created
and changed dates; those dates are not part of what syncs, so every other device
stamps an item when it first receives it. Keys shared with
the system SSH agent, a key rotation in progress and recordings of sessions still
open follow the vault to its new id; hosts selected for a local MCP integration
stay selected, but that access is paused until you confirm it again, as after any
vault change.

The vault becomes a **personal** vault of your account — only your account
administers it on the server — unless you pick one of the spaces you administer
in the confirmation. Nothing is picked for you. In a space, the admins of that
space can invite people to the vault, and you keep administering it only while
you are one of them; they cannot read it, in either case reading takes access you
grant. Cloud vaults made by 0.5 are personal and stay personal: nothing is
migrated, and a server holds both kinds side by side. The same choice, with the
same default, applies when you create a Cloud vault. Placing a vault in a space
needs the server reachable at that moment; a personal vault does not.

If the first push fails, the move is kept: a vault moved into the server's
primary space is retried by every sync until it is uploaded; one moved into
another space is not covered by automatic sync and stays on this device until it
is uploaded. An item the server refuses as too large (a long session recording
against a server older than 0.6, or one whose `limits.max_object_bytes` is set
low) does not hold the rest back: everything else uploads and the client names
the item, which stays on the device until the limit is raised and you press
**Sync now**.
Vault format and server protocol are unchanged; the server receives it like any
new Cloud vault.

Placing a vault in a space reserves its id on the server before the vault is
moved or created there. If the move or the creation then fails, the client keeps
that id and a retry into the same space uses it again. If you choose a different
space or **Personal** instead, or never retry, the id stays reserved in the first
space as a vault with no data: it is listed, empty and without a name, among the
vaults of that server, holds nothing and gives nobody access to anything. 0.6 has
no way to remove such a reservation; it is safe to leave.

## Server operators: size limits in 0.6

Session recordings are vault items of up to 17 MiB, and 0.6 is the first release
that syncs them whole. Three things to check when you upgrade:

- **Reverse proxy body limit.** The shipped nginx configurations now say
  `client_max_body_size 24m`. A proxy you configured for an earlier release with
  `client_max_body_size 16m` answers `413` to any object over about 12 MiB
  (objects travel base64-encoded) before the server sees it. Raise it to `24m`,
  or to whatever you set `limits.max_body_bytes` to.
- **An explicit `max_object_bytes`.** The default rose from 1 MiB to 17 MiB, but a
  configuration file that says `max_object_bytes = 1048576` keeps saying it.
  Remove the line or raise the value, or recordings over 1 MiB stay on the
  device that made them.
- **A 0.6 client against a 0.5 server** uploads in requests of at most about
  1 MiB of objects, which that server accepts, and reports any larger item as not
  uploaded instead of syncing it. Upgrade the server to sync those items.

In each case the client does not fail the sync: it uploads everything else, names
the items the server (or the proxy) refused, and offers them again when you press
**Sync now**.

Pulls are paged by size as well as by count from 0.6 (`limits.delta_max_page_bytes`,
8 MiB by default). Older clients follow the paging unchanged. The limits are
listed in [`server/config.example.toml`](../server/config.example.toml).

## If verification fails

Keep the original instance files and server backup intact. Restore a portable
vault backup into a separate local vault or a separate installation to inspect it.
Do not delete the instance or reset the server to troubleshoot an update.

A stale server backup can trigger `TransportRollback`. Follow the documented
[server restore and sequence recovery procedure](../server/README.md#backups--restore-read-carefully);
that error is an integrity check, not an invitation to bypass it.
