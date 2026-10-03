// Remote `~/.ssh/authorized_keys` edits, as shell commands run over the host's
// exec channel. One builder per edit so the copy-key modal and the guided key
// rotation run the exact same command. Pure: builds strings, runs nothing.
//
// Each command is handed to `sh -c`: the exec channel runs it through the
// account's login shell, and a fish or csh login shell would not parse POSIX
// `{ …; }`, `$?` or `$(…)`.

/** Single-quote a string for a POSIX shell. */
function shQuote(s: string): string {
  return "'" + s.replace(/'/g, "'\\''") + "'";
}

/** A public-key line, quoted. OpenSSH public keys never contain a single quote;
 *  escaped defensively all the same. */
const quoteKey = (openssh: string) => shQuote(openssh.trim());

/** Run `script` under POSIX sh whatever the login shell is. */
const posix = (script: string) => `sh -c ${shQuote(script)}`;

/** Exit status of `authorizedKeysRemoveCmd` when the exact line is gone but the
 *  old key is still authorized in another form (options prefix, CRLF, another
 *  comment). Nothing else was changed; the line has to be removed by hand. */
export const REMOVE_EXIT_STILL_PRESENT = 3;
/** Exit status of `authorizedKeysRemoveCmd` when there is no authorized_keys. */
export const REMOVE_EXIT_NO_FILE = 4;

/** Idempotent ssh-copy-id: create `~/.ssh` with the permissions sshd's
 *  StrictModes requires, then append the key only if an identical line is not
 *  already there. Running it twice leaves one line. A file whose last line has
 *  no newline gets one first, as ssh-copy-id does — otherwise the key would be
 *  glued onto that line, breaking it and installing nothing. */
export function authorizedKeysAppendCmd(openssh: string): string {
  const q = quoteKey(openssh);
  return posix(
    `f=~/.ssh/authorized_keys; ` +
      `mkdir -p ~/.ssh && chmod 700 ~/.ssh && ` +
      `touch "$f" && chmod 600 "$f" && ` +
      `{ grep -qxF ${q} "$f" || { ` +
      `{ [ ! -s "$f" ] || [ -z "$(tail -c1 "$f")" ] || echo >> "$f"; } && ` +
      `printf '%s\\n' ${q} >> "$f"; }; }`,
  );
}

/** Remove exactly the line `oldOpenssh` from `authorized_keys`, nothing else.
 *  Refuses unless `keepOpenssh` (the key that replaces it) is present as a whole
 *  line, so the file can never be left without either key. The rewrite is
 *  atomic: the filtered copy goes to a temp file beside the original — created
 *  by `cp -p`, so it keeps the original's mode — then `mv` replaces it in one
 *  step. `grep -v` exits 1 when no line is left, which is still a success.
 *  Afterwards, if the old key's base64 blob still appears on any line (the key
 *  installed with options, a CRLF ending or another comment), it exits with
 *  `REMOVE_EXIT_STILL_PRESENT` rather than claim the key is gone. A key that is
 *  truly absent is a success, so a rerun converges. */
export function authorizedKeysRemoveCmd(oldOpenssh: string, keepOpenssh: string): string {
  const o = quoteKey(oldOpenssh);
  const k = quoteKey(keepOpenssh);
  const blob = shQuote(oldOpenssh.trim().split(/\s+/)[1] ?? oldOpenssh.trim());
  return posix(
    `f=~/.ssh/authorized_keys; ` +
      `[ -f "$f" ] || { echo 'no ~/.ssh/authorized_keys on this host' >&2; exit ${REMOVE_EXIT_NO_FILE}; }; ` +
      `grep -qxF ${k} "$f" || { echo 'new key is not in authorized_keys; old key left in place' >&2; exit 1; }; ` +
      `t=$(mktemp "$f.XXXXXX") && cp -p "$f" "$t" && ` +
      `{ grep -vxF ${o} "$f" > "$t"; [ $? -le 1 ]; } && mv -f "$t" "$f" || { rm -f "$t"; exit 1; }; ` +
      `if grep -qF ${blob} "$f"; then echo 'old key still present in another form' >&2; exit ${REMOVE_EXIT_STILL_PRESENT}; fi`,
  );
}
