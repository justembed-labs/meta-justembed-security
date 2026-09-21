#!/usr/bin/env python3
"""Checks that relative markdown links in this repo's own docs resolve to
a real file. Skips http(s) links, mailto:, and pure in-page anchors --
this is not a full link checker, just a guard against a doc pointing at
a file that was renamed or never created.
"""
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")


def find_markdown_files():
    for path in REPO_ROOT.rglob("*.md"):
        if "/sources/" in str(path) or "/.git/" in str(path):
            continue
        yield path


def check_file(path):
    errors = []
    text = path.read_text()
    for match in LINK_RE.finditer(text):
        target = match.group(1).strip()
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        if target.startswith("#"):
            continue
        target = target.split("#", 1)[0]
        if not target:
            continue
        resolved = (path.parent / target).resolve()
        if not resolved.exists():
            errors.append(f"{path.relative_to(REPO_ROOT)}: broken link -> {target}")
    return errors


def main():
    all_errors = []
    for path in find_markdown_files():
        all_errors.extend(check_file(path))

    if all_errors:
        print(f"{len(all_errors)} broken relative link(s) found:")
        for e in all_errors:
            print(f"  - {e}")
        return 1

    print("All relative markdown links resolve.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
