#!/bin/sh
# Assemble a GitLab Pages-ready `public/` directory from an evidence
# store -- reindex.py + copy the vendored pages/ viewer + the store,
# minus the multi-MB raw dumps (cve.json, cve.txt, parsed/packages.json
# -- scan-time inputs, never served, re-derivable by re-running the
# scan). No credentials needed: GitLab Pages auto-publishes any
# `public/` artifact from a CI job literally named `pages`, using that
# job's own built-in permissions. This script does the copying; wiring
# it into `.gitlab-ci.yml` is the consumer's job (see README.md for the
# handful of lines this replaces).
#
# Usage:
#   publish_gitlab_pages.sh <store-root> <output-dir>
#
#   <store-root>   the JE_EVIDENCE_STORE/cve-reports directory
#                  (one subdir per machine, one per run).
#   <output-dir>   usually `public` in a GitLab CI job's workspace.
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"

[ $# -ge 2 ] || { sed -n '2,20p' "$0"; exit 2; }
STORE="$1"
OUT="$2"

[ -d "$STORE" ] || { echo "no such store: $STORE" >&2; exit 1; }

python3 "$HERE/reindex.py" "$STORE"

mkdir -p "$OUT"
cp -r "$HERE/../pages/." "$OUT/"
mkdir -p "$OUT/store"

# Both resolved to absolute paths before the `cd "$STORE"` below -- a
# relative $OUT would resolve against the wrong cwd once inside that
# subshell, silently copying nothing into the real output dir.
STORE="$(cd "$STORE" && pwd)"
OUT="$(cd "$OUT" && pwd)"

( cd "$STORE" && find . -type f \
    ! -name 'cve.json' ! -name 'cve.txt' ! -path '*/parsed/packages.json' \
    -exec sh -c 'mkdir -p "$1/$(dirname "$2")" && cp "$0/$2" "$1/$2"' \
        "$STORE" "$OUT/store" {} \; )

echo "published: $OUT (serve as GitLab Pages, or locally with"
echo "  python3 -m http.server -d $OUT)"
