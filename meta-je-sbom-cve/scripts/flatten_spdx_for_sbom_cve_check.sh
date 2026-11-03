#!/bin/sh
# Flattens a Yocto create-spdx-2.2 output tree into one directory of
# *.spdx.json files, for Bootlin's sbom-cve-check (pip install
# sbom-cve-check) to consume.
#
# Usage: flatten_spdx_for_sbom_cve_check.sh <deploy/spdx/2.2/MACHINE> <out-dir>
#
# Real, confirmed bug (not a usage mistake): sbom-cve-check's SPDX2
# parser (sbom_cve_check/sbom/sbom_spdx2.py) uses a NON-RECURSIVE glob
# (`sbom_dir.glob("*.spdx.json")`) to find package/recipe/runtime
# documents. Yocto's real create-spdx-2.2.bbclass output nests them
# under packages/, recipes/, runtime/ subdirectories -- pointed at any
# of deploy/spdx/2.2/MACHINE itself, that subdirectory alone, or a
# hand-copied single combined file, sbom-cve-check silently returns
# zero packages every time (confirmed against a real qemuarm64 build,
# three different input shapes, same empty result each time). No
# error, no warning -- just an empty package list, so this is easy to
# mistake for "the SBOM really is clean."
#
# The actual package metadata itself is correct and complete once
# every file lands in one flat directory (confirmed: the same real
# build then produces real CVE matches, in the exact
# yocto-cve-check-manifest format cve-check.bbclass itself uses).
set -eu

SRC="$1"
OUT="$2"

mkdir -p "$OUT"
find "$SRC" -name '*.spdx.json' -exec cp -t "$OUT" {} +
echo "$(find "$OUT" -name '*.spdx.json' | wc -l) SPDX documents flattened into $OUT"
