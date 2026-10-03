// Remote `~/.ssh/authorized_keys` edits, as shell commands run over the host's
// exec channel. One builder per edit so the copy-key modal and the guided key
// rotation run the exact same command. Pure: builds strings, runs nothing.

/** Single-quote a public-key line so the remote shell treats it literally.
 *  OpenSSH public keys never contain a single quote; escape defensively. */
function quoteKey(openssh: string): string {
  return "'" + openssh.trim().replace(/'/g, "'\\''") + "'";
}

/** Idempotent ssh-copy-id: create `~/.ssh` with the permissions sshd's
 *  StrictModes requires, then append the key only if an identical line is not
 *  already there. Running it twice leaves one line. */
export function authorizedKeysAppendCmd(openssh: string): string {
  const q = quoteKey(openssh);
  return (
    `mkdir -p ~/.ssh && chmod 700 ~/.ssh && ` +
    `touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && ` +
    `{ grep -qxF ${q} ~/.ssh/authorized_keys || printf '%s\\n' ${q} >> ~/.ssh/authorized_keys; }`
  );
}

/** Remove exactly the line `oldOpenssh` from `authorized_keys`, nothing else.
 *  Refuses unless `keepOpenssh` (the key that replaces it) is present as a whole
 *  line, so the file can never be left without either key. The rewrite is
 *  atomic: the filtered copy goes to a temp file beside the original — created
 *  by `cp -p`, so it keeps the original's mode — then `mv` replaces it in one
 *  step. `grep -v` exits 1 when no line is left, which is still a success.
 *  Removing a line that is already gone is a no-op, so a rerun converges. */
export function authorizedKeysRemoveCmd(oldOpenssh: string, keepOpenssh: string): string {
  const o = quoteKey(oldOpenssh);
  const k = quoteKey(keepOpenssh);
  return (
    `f=~/.ssh/authorized_keys; ` +
    `grep -qxF ${k} "$f" || { echo 'new key is not in authorized_keys; old key left in place' >&2; exit 1; }; ` +
    `t=$(mktemp "$f.XXXXXX") && cp -p "$f" "$t" && ` +
    `{ grep -vxF ${o} "$f" > "$t"; [ $? -le 1 ]; } && mv -f "$t" "$f" || { rm -f "$t"; exit 1; }`
  );
}
