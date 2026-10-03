# Upgrading UniSSH

Read the **Compatibility** and any **Breaking changes** entries in the
[changelog](../CHANGELOG.md#050--2026-10-02) before upgrading. The changes in
0.5.0 preserve the vault format, AAD encodings and encrypted-sync
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
replaced, item version history starts fresh on the server, and the first sync
pushes the vault. If that push fails, the move is kept: a vault moved into the
server's primary space uploads on the next sync; one moved into another space is
not covered by automatic sync and stays on this device until it is uploaded.
Vault format and server protocol are unchanged; the server receives it like any
new Cloud vault.

## If verification fails

Keep the original instance files and server backup intact. Restore a portable
vault backup into a separate local vault or a separate installation to inspect it.
Do not delete the instance or reset the server to troubleshoot an update.

A stale server backup can trigger `TransportRollback`. Follow the documented
[server restore and sequence recovery procedure](../server/README.md#backups--restore-read-carefully);
that error is an integrity check, not an invitation to bypass it.
