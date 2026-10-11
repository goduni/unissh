// Remote `~/.ssh/authorized_keys` edits, as shell commands run over the host's
// exec channel. One builder per edit so the copy-key modal and the guided key
// rotation run the exact same command. Pure: builds strings, runs nothing.
//
// Each command is handed to `sh -c`: the exec channel runs it through the
// account's login shell, and a fish or csh login shell would not parse POSIX
// `{ …; }`, `$?` or `$(…)`. That login shell still reads the whole line first,
// and csh/tcsh expand `!word` as history even inside single quotes — so the
// scripts never write `!` in front of anything but a blank.

/** Single-quote a string for a POSIX shell. */
function shQuote(s: string): string {
  return "'" + s.replace(/'/g, "'\\''") + "'";
}

/** A public-key line, quoted. OpenSSH public keys never contain a single quote;
 *  escaped defensively all the same. */
const quoteKey = (openssh: string) => shQuote(openssh.trim());

/** Run `script` under POSIX sh whatever the login shell is. */
const posix = (script: string) => `sh -c ${shQuote(script)}`;

/** Exit status of `authorizedKeysRemoveCmd` when the old key's plain lines are
 *  gone but its blob is still on a line sshd reads, in a form this command does
 *  not touch: a line with an options prefix (`from=…`, `command=…`), which
 *  still authorizes the key, or the same blob under another key type name.
 *  Nothing else was changed; what is left has to be looked at and removed by
 *  hand. */
export const REMOVE_EXIT_STILL_PRESENT = 3;
/** Exit status of `authorizedKeysRemoveCmd` when there is no authorized_keys. */
export const REMOVE_EXIT_NO_FILE = 4;

/** The `<type>` and `<base64 blob>` of a public-key line, each quoted for the
 *  shell. Both are checked against the alphabet OpenSSH writes: they are handed
 *  to `awk -v`, which would expand a backslash escape. */
function keyFields(openssh: string): { type: string; blob: string } {
  const [type, blob] = openssh.trim().split(/\s+/);
  if (!type || !blob || !/^[A-Za-z0-9@._+-]+$/.test(type) || !/^[A-Za-z0-9+/=]+$/.test(blob))
    throw new Error("not an OpenSSH public key line");
  return { type: shQuote(type), blob: shQuote(blob) };
}

/** Idempotent ssh-copy-id: append the key only if an identical line is not
 *  already there. Running it twice leaves one line. A file whose last line has
 *  no newline gets one first, as ssh-copy-id does — otherwise the key would be
 *  glued onto that line, breaking it and installing nothing.
 *
 *  `~/.ssh` and the file get the permissions sshd's StrictModes requires only
 *  when this command creates them: an existing directory or file keeps the mode
 *  its owner chose. The append goes through `>>`, so a symlinked
 *  authorized_keys stays a symlink and its target is what grows. */
export function authorizedKeysAppendCmd(openssh: string): string {
  const q = quoteKey(openssh);
  return posix(
    `d=~/.ssh; f=$d/authorized_keys; ` +
      `{ [ -d "$d" ] || { mkdir -p "$d" && chmod 700 "$d"; }; } && ` +
      `{ [ -e "$f" ] || { touch "$f" && chmod 600 "$f"; }; } && ` +
      `{ grep -qxF ${q} "$f" || { ` +
      `{ [ ! -s "$f" ] || [ -z "$(tail -c1 "$f")" ] || echo >> "$f"; } && ` +
      `printf '%s\\n' ${q} >> "$f"; }; }`,
  );
}

/** awk pattern: this line is a plain public-key line for key type `t` and blob
 *  `b` — the key type is the first field (no options prefix), the blob the
 *  second, whatever comment follows and whether or not the line ends in CR. */
const AWK_KEY_LINE = `{ k = $2; sub(/\\r$/, "", k) } $1 == t && k == b`;

/** Remove the old key's plain lines from `authorized_keys`, nothing else: every
 *  line whose key type and blob are `oldOpenssh`'s, whatever its trailing
 *  comment (ssh-copy-id writes `user@host` there) and line ending (LF or CRLF).
 *  A line that authorizes the old key behind an options prefix (`from=…`,
 *  `command=…`) is left alone — it was put there deliberately and is reported,
 *  see below.
 *
 *  Refuses unless `keepOpenssh` (the key that replaces it) is present as a plain
 *  line, so the file can never be left without either key; the filtered copy is
 *  checked for it again before it replaces anything. The rewrite is atomic: the
 *  copy goes to a temp file beside the real file — created by `cp -p`, so it
 *  keeps the original's mode — then `mv` replaces it in one step. A symlinked
 *  authorized_keys is followed first, so the link stays and its target is what
 *  gets rewritten.
 *
 *  Afterwards, if the old key's base64 blob still appears on any line sshd
 *  reads, it exits with `REMOVE_EXIT_STILL_PRESENT` rather than claim the key
 *  is gone. A comment line (first non-blank character `#`) is not one of
 *  those: sshd skips it, so it accepts nothing and may keep the blob. A key
 *  that is truly absent is a success, so a rerun converges. */
export function authorizedKeysRemoveCmd(oldOpenssh: string, keepOpenssh: string): string {
  const o = keyFields(oldOpenssh);
  const k = keyFields(keepOpenssh);
  return posix(
    `f=~/.ssh/authorized_keys; ` +
      `[ -f "$f" ] || { echo 'no ~/.ssh/authorized_keys on this host' >&2; exit ${REMOVE_EXIT_NO_FILE}; }; ` +
      `while [ -L "$f" ]; do ` +
      `l=$(readlink "$f") || { echo 'cannot resolve the authorized_keys symlink; old key left in place' >&2; exit 1; }; ` +
      `case $l in /*) f=$l ;; *) f=$(dirname "$f")/$l ;; esac; done; ` +
      `has() { awk -v t="$1" -v b="$2" '${AWK_KEY_LINE} { found = 1 } END { exit found ? 0 : 1 }' "$3"; }; ` +
      `has ${k.type} ${k.blob} "$f" || { echo 'new key is not in authorized_keys; old key left in place' >&2; exit 1; }; ` +
      `t=$(mktemp "$f.XXXXXX") || exit 1; ` +
      `cp -p "$f" "$t" && ` +
      `awk -v t=${o.type} -v b=${o.blob} '${AWK_KEY_LINE} { next } { print }' "$f" > "$t" && ` +
      `has ${k.type} ${k.blob} "$t" && mv -f "$t" "$f" || { rm -f "$t"; exit 1; }; ` +
      `if awk -v b=${o.blob} '/^[ \\t]*#/ { next } index($0, b) { found = 1 } END { exit found ? 0 : 1 }' "$f"; then ` +
      `echo 'old key data still in authorized_keys: a line with options, or the same key under another key type' >&2; exit ${REMOVE_EXIT_STILL_PRESENT}; fi`,
  );
}
