#!/usr/bin/env python3
"""Fail if `tauri icon` left any scaffolded default icon in place.

`tauri android init` / `tauri ios init` generate the mobile projects carrying
TAURI'S OWN default icons, and the `tauri icon` call that follows overwrites them
with ours. gen/ is gitignored and regenerated on every run, so that overwrite
happens fresh each time — and nothing downstream ever looks at an icon again.

That makes the failure mode silent rather than loud. A hard error from
`tauri icon` fails the step (GitHub runs `run:` under `bash -e`), but the
interesting case is subtler: an upstream change to the generated project layout
would let `tauri icon` exit 0 having written nothing the build consumes, and CI
would go green on an APK wearing someone else's logo.

So the workflow hashes the icons the init step scaffolded, hashes them again
after `tauri icon`, and calls this. Requiring that every scaffolded file CHANGED
asserts exactly "ours replaced theirs" — without this script needing to know what
either icon looks like, which is what keeps it from rotting when the art changes.

    assert-icons-replaced.py BEFORE AFTER

Both files are `sha256sum` / `shasum -a 256` output.
"""

from __future__ import annotations

import sys
from pathlib import Path


def load(path: str) -> dict[str, str]:
    """Parse `<hash>  <path>` lines into {path: hash}."""
    digests: dict[str, str] = {}
    for line in Path(path).read_text().splitlines():
        if not line.strip():
            continue
        digest, _, name = line.partition("  ")
        digests[name.strip()] = digest.strip()
    return digests


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2

    before, after = load(argv[1]), load(argv[2])

    # An empty "before" is itself the regression: it means the glob no longer
    # matches where init puts icons, so the comparison would pass vacuously and
    # guard nothing.
    if not before:
        print(
            "no scaffolded launcher icons were found — the generated project "
            "layout changed, and this check is no longer looking where the icons "
            "actually live. Fix the find(1) pattern in the workflow.",
            file=sys.stderr,
        )
        return 1

    unchanged = sorted(name for name, digest in before.items() if after.get(name) == digest)
    if unchanged:
        print(
            "`tauri icon` did not replace these scaffolded default icons:",
            file=sys.stderr,
        )
        for name in unchanged:
            print(f"  {name}", file=sys.stderr)
        print(
            "\nThe build would ship Tauri's default logo instead of UniSSH's.",
            file=sys.stderr,
        )
        return 1

    missing = sorted(set(before) - set(after))
    if missing:
        print(f"icons vanished after `tauri icon`: {', '.join(missing)}", file=sys.stderr)
        return 1

    print(f"all {len(before)} scaffolded icons were replaced")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
