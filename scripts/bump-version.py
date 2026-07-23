#!/usr/bin/env python3
"""Read and write the product version in every manifest that declares it.

The version lives in five files. The root workspace's [workspace.package] version
covers rust-core/crates/* and server (they inherit it with `version.workspace = true`);
the client and server-ui sit outside the root workspace and carry their own.

Keeping those in sync by hand is exactly what failed: v0.1.1 was tagged and released
while every manifest still said 0.1.0, so Tauri named the bundles UniSSH_0.1.0_* and
Settings -> About reported 0.1.0. `tauri-action`'s tagName input names the release, not
the artifacts, so nothing caught it.

This script is therefore both the writer and the verifier:

    bump-version.py 0.1.2           rewrite all five
    bump-version.py --check 0.1.2   fail unless all five already say 0.1.2

`just release` calls the first, and .github/workflows/client.yml calls the second on
every tagged build, so a tag pushed by hand cannot ship mislabeled binaries.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SEMVER = re.compile(r"^\d+\.\d+\.\d+$")

# (path, the section header the `version` key must sit under). Scoping to a section
# matters: a blind search would also hit dependency pins like `serde = { version = ... }`,
# which are not the product version.
TOML_TARGETS: list[tuple[Path, str]] = [
    (ROOT / "Cargo.toml", "[workspace.package]"),
    (ROOT / "client/src-tauri/Cargo.toml", "[package]"),
]

# Top-level "version" keys, at exactly two spaces of indentation in all three files.
JSON_TARGETS: list[Path] = [
    ROOT / "client/package.json",
    ROOT / "client/src-tauri/tauri.conf.json",
    ROOT / "server-ui/package.json",
]

JSON_VERSION = re.compile(r'^  "version"(\s*):(\s*)"([^"]+)"', re.M)


def read_toml(path: Path, section: str) -> str:
    """The version currently declared under `section`."""
    in_section = False
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_section = stripped == section
            continue
        if in_section:
            m = re.match(r'^version\s*=\s*"([^"]+)"', stripped)
            if m:
                return m.group(1)
    raise SystemExit(f"{path}: no `version` key under {section}")


def write_toml(path: Path, section: str, version: str) -> str:
    in_section = False
    lines = path.read_text().splitlines(keepends=True)
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("["):
            in_section = stripped == section
            continue
        if in_section and re.match(r'^version\s*=\s*"', stripped):
            old = re.search(r'"([^"]+)"', stripped).group(1)
            lines[i] = re.sub(r'"[^"]+"', f'"{version}"', line, count=1)
            path.write_text("".join(lines))
            return old
    raise SystemExit(f"{path}: no `version` key under {section}")


def read_json(path: Path) -> str:
    m = JSON_VERSION.search(path.read_text())
    if not m:
        raise SystemExit(f'{path}: no top-level "version" key at two-space indent')
    return m.group(3)


def write_json(path: Path, version: str) -> str:
    """Rewrite the version string textually.

    Deliberately not json.load/json.dump: these files are hand-maintained, and a
    round-trip would reflow indentation and key order into a diff nobody can review.
    """
    text = path.read_text()
    m = JSON_VERSION.search(text)
    if not m:
        raise SystemExit(f'{path}: no top-level "version" key at two-space indent')
    old = m.group(3)
    path.write_text(text[: m.start(3)] + version + text[m.end(3) :])
    return old


def current() -> list[tuple[Path, str]]:
    found = [(p, read_toml(p, s)) for p, s in TOML_TARGETS]
    found += [(p, read_json(p)) for p in JSON_TARGETS]
    return found


def cmd_check(version: str) -> int:
    found = current()
    bad = [(p, v) for p, v in found if v != version]
    for path, value in bad:
        print(f"::error::{path.relative_to(ROOT)} says {value}, expected {version}")
    if bad:
        print(f"\n{len(bad)} manifest(s) disagree with {version} — run 'just release {version}'")
        return 1
    print(f"all {len(found)} manifests agree: {version}")
    return 0


def cmd_bump(version: str) -> int:
    for path, section in TOML_TARGETS:
        old = write_toml(path, section, version)
        print(f"{path.relative_to(ROOT)}: {old} -> {version}")
    for path in JSON_TARGETS:
        old = write_json(path, version)
        print(f"{path.relative_to(ROOT)}: {old} -> {version}")
    return 0


def main(argv: list[str]) -> int:
    args = argv[1:]
    check = False
    if args and args[0] == "--check":
        check = True
        args = args[1:]
    if len(args) != 1 or not SEMVER.match(args[0]):
        print("usage: bump-version.py [--check] <major.minor.patch>", file=sys.stderr)
        return 2
    return cmd_check(args[0]) if check else cmd_bump(args[0])


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
