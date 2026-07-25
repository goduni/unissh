#!/usr/bin/env python3
"""Fail if the built docs site links to a page or anchor that does not exist.

A documentation site's whole job is to be navigable, and its characteristic
failure is not a crash but a 404: a page gets renamed or a heading reworded, the
build stays green, and the link rots silently until a reader hits it. Nothing
else in this repo would notice — `astro build` resolves imports, not hrefs.

This walks the BUILT output rather than the markdown source, so it sees the URLs
readers actually get: Starlight's slug routing, the sidebar, redirects and
trailing-slash handling have all already been applied. It checks two things:

  * every internal href resolves to a built page or asset;
  * every `#fragment` exists as an id on the page it points at.

External links are deliberately not checked. They fail for reasons outside this
repo — rate limits, transient outages, sites that block CI — and a check that
goes red for someone else's downtime is a check people learn to ignore.

    check-site-links.py website/dist
"""

from __future__ import annotations

import re
import sys
import urllib.parse
from pathlib import Path

SKIP_SCHEMES = ("http://", "https://", "mailto:", "tel:", "data:", "javascript:")

HREF = re.compile(r'href="([^"]+)"')
ID = re.compile(r'\bid="([^"]+)"')


def page_url(dist: Path, page: Path) -> str:
    """The URL path a built file is served at, so relative hrefs resolve correctly."""
    rel = page.relative_to(dist).as_posix()
    if rel.endswith("index.html"):
        rel = rel[: -len("index.html")]
    return "/" + rel


def target_file(dist: Path, url_path: str) -> Path | None:
    """The file serving a URL path, trying the ways a static host would."""
    rel = url_path.lstrip("/")
    if not rel:
        index = dist / "index.html"
        return index if index.is_file() else None
    for candidate in (dist / rel, dist / rel / "index.html", dist / (rel + ".html")):
        if candidate.is_file():
            return candidate
    return None


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2

    dist = Path(argv[1])
    if not dist.is_dir():
        print(f"{dist} is not a directory — build the site first", file=sys.stderr)
        return 2

    pages = sorted(dist.rglob("*.html"))
    if not pages:
        # Silence here would mean "no broken links" when it really means "nothing
        # was checked", which is the more dangerous of the two.
        print(f"no HTML found under {dist} — the build produced nothing", file=sys.stderr)
        return 1

    anchor_cache: dict[Path, set[str]] = {}
    broken: list[tuple[str, str]] = []
    dangling: list[tuple[str, str]] = []
    checked = 0

    for page in pages:
        base = page_url(dist, page)
        html = page.read_text(errors="ignore")
        for href in HREF.findall(html):
            if href.startswith(SKIP_SCHEMES) or href.startswith("#"):
                continue
            checked += 1
            resolved = urllib.parse.urljoin(base, urllib.parse.unquote(href))
            path, _, fragment = resolved.partition("#")
            target = target_file(dist, path)
            if target is None:
                broken.append((base, href))
                continue
            if fragment:
                if target not in anchor_cache:
                    anchor_cache[target] = set(ID.findall(target.read_text(errors="ignore")))
                if fragment not in anchor_cache[target]:
                    dangling.append((base, href))

    for label, hits in (("broken link", broken), ("dangling anchor", dangling)):
        for source, href in hits:
            print(f"{label}: {source} -> {href}", file=sys.stderr)

    total = len(broken) + len(dangling)
    if total:
        print(
            f"\n{total} of {checked} internal links are broken across {len(pages)} pages.",
            file=sys.stderr,
        )
        return 1

    print(f"{checked} internal links across {len(pages)} pages all resolve")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
