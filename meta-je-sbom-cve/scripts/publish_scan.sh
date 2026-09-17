#!/bin/sh
# Collate one evidence run from a finished build into the evidence store.
#
# Usage:
#   publish_scan.sh <run-id> <machine> <deploy-images-dir> <store-root> [build-meta.json]
#
#   <run-id>              one path component, [A-Za-z0-9._-]. A release tag
#                         "X.Y", or "YYYY-MM-DD-<short-sha>" for schedule/manual.
#   <machine>            MACHINE the image was built for.
#   <deploy-images-dir>  .../deploy-*/images/<machine> (where the image +
#                         its cve/spdx manifests land).
#   <store-root>          absolute path ending in /cve-reports. One
#                         subdir per machine, one per run.
#   <build-meta.json>     optional; collect_build_meta.sh output.
#
# Idempotent per run-id: an existing <store>/<machine>/<run-id>/ is
# wiped first so a re-run starts clean.
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"

[ $# -ge 4 ] || { sed -n '2,20p' "$0"; exit 2; }
RUN_ID="$1"; MACHINE="$2"; IMG_DIR="$3"; STORE="$4"; BUILD_META="${5:-}"

case "$STORE" in
    /*/cve-reports|/*/cve-reports/) ;;
    *) echo "store must be an absolute path ending in /cve-reports: $STORE" >&2; exit 2 ;;
esac
STORE="${STORE%/}"
case "$RUN_ID" in
    *[!A-Za-z0-9._-]*|""|.|..) echo "bad run-id: $RUN_ID" >&2; exit 2 ;;
esac
case "$MACHINE" in
    *[!A-Za-z0-9._-]*|"") echo "bad machine: $MACHINE" >&2; exit 2 ;;
esac
[ -d "$IMG_DIR" ] || { echo "no such deploy dir: $IMG_DIR" >&2; exit 2; }

RUN_DIR="$STORE/$MACHINE/$RUN_ID"
PREV_ID=""
[ -L "$STORE/$MACHINE/latest" ] && PREV_ID="$(readlink "$STORE/$MACHINE/latest")"
[ "$PREV_ID" = "$RUN_ID" ] && PREV_ID=""   # re-run: diff against the one before

rm -rf "$RUN_DIR"
mkdir -p "$RUN_DIR/parsed"

echo "== collecting artifacts =="
# The cve-check image manifest is exactly ${IMAGE_NAME}.json -- ending
# in .rootfs.json or .rootfs-<digits>.json and nothing else (not
# .testdata.json, .spdx.json, or any other <image-name>.<suffix>.json
# sibling a different tool may drop in the same deploy dir -- an
# allowlist anchored pattern, not a growing blocklist). Resolve the
# newest matching one to its real (timestamped) path, then derive
# every sibling artifact from that exact prefix so a deploy dir
# holding several images picks one set.
CVE_LINK="$(ls -t "$IMG_DIR"/*.rootfs.json "$IMG_DIR"/*.rootfs-*.json 2>/dev/null \
    | grep -E '\.rootfs(-[0-9]+)?\.json$' | head -1 || true)"
[ -n "$CVE_LINK" ] || { echo "no cve manifest in $IMG_DIR -- built with kas/evidence.yml?" >&2; exit 1; }
CVE_MANIFEST="$(readlink -f "$CVE_LINK")"
PREFIX="${CVE_MANIFEST%.json}"       # .../images/<m>/<IMAGE_NAME>
IMG_BASE="$(basename "$PREFIX")"

cp -v "$CVE_MANIFEST"          "$RUN_DIR/cve.json"
cp -v "$PREFIX.cve"            "$RUN_DIR/cve.txt"                     2>/dev/null || true
cp -v "$PREFIX.spdx.tar.zst"   "$RUN_DIR/sbom-recipes.spdx.tar.zst"  2>/dev/null || true
cp -v "$PREFIX.manifest"       "$RUN_DIR/packages.manifest"          2>/dev/null || true

# bootloader cve-check: u-boot / TF-A / OP-TEE aren't rootfs packages,
# so their CVE data only exists as per-recipe files. The dir depends on
# whether the BSP overrode DEPLOY_DIR/CVE_CHECK_DIR -- scarthgap put it
# under ${TMPDIR}/deploy/cve here even though meta-ti sets DEPLOY_DIR to
# deploy-ti. Cast a wide net rather than assume one layout.
TOP="$(git rev-parse --show-toplevel 2>/dev/null || echo .)"
BOOT_CVE=""
for d in "$TOP"/build/*/deploy/cve "$TOP"/build/deploy-*/cve \
         "${IMG_DIR%/images/*}/cve"; do
    [ -d "$d" ] || continue
    for f in "$d"/u-boot*_cve.json "$d"/*bootloader*_cve.json \
             "$d"/*trusted-firmware*_cve.json "$d"/optee-os*_cve.json; do
        [ -f "$f" ] || continue
        BOOT_CVE="$f"
        cp -v "$f" "$RUN_DIR/cve-bootloader.json"
        break 2
    done
done
[ -n "$BOOT_CVE" ] || echo "note: no bootloader _cve.json found -- run \`bitbake virtual/bootloader -c cve_check\`"

# license manifest (license_image class):
#   ${TMPDIR}/deploy/licenses/<machine_underscored>/<IMAGE_NAME>/license.manifest
LIC="$(find "$TOP"/build/tmp*/deploy/licenses -maxdepth 3 -name license.manifest \
        -path "*/${IMG_BASE}/*" 2>/dev/null | head -1 || true)"
[ -n "$LIC" ] && cp -v "$LIC" "$RUN_DIR/license.manifest" || echo "note: no license.manifest for ${IMG_BASE}"

[ -n "$BUILD_META" ] && [ -f "$BUILD_META" ] && cp -v "$BUILD_META" "$RUN_DIR/build-meta.json" || true

echo "== parse cve =="
python3 "$HERE/parse_cve.py" "$RUN_DIR/parsed" \
    "$RUN_DIR/cve.json" "$RUN_DIR/cve-bootloader.json" 2>/dev/null \
  || python3 "$HERE/parse_cve.py" "$RUN_DIR/parsed" "$RUN_DIR/cve.json"

echo "== spdx components =="
SPDX_SRC="$RUN_DIR/sbom-recipes.spdx.tar.zst"
[ -f "$SPDX_SRC" ] || SPDX_SRC="$RUN_DIR/sbom.spdx.json"
python3 "$HERE/spdx_components.py" "$SPDX_SRC" "$RUN_DIR/components.tsv" || true

echo "== layer inventory (#13) =="
[ -f "$RUN_DIR/parsed/packages.json" ] && \
    python3 "$HERE/layer_inventory.py" "$RUN_DIR/parsed/packages.json" \
        "$RUN_DIR/components.tsv" "$RUN_DIR/inventory" || true

if [ -n "$PREV_ID" ] && [ -d "$STORE/$MACHINE/$PREV_ID" ]; then
    echo "== diff vs $PREV_ID =="
    P="$STORE/$MACHINE/$PREV_ID"
    python3 "$HERE/diff_cve.py"  "$RUN_DIR/parsed" "$P/parsed" "$RUN_DIR/diff-cve"  || true
    python3 "$HERE/diff_sbom.py" "$RUN_DIR/components.tsv" "$P/components.tsv" "$RUN_DIR/diff-sbom" || true
else
    echo "== baseline run (no previous) =="
fi

GEN="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
REF="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
NVD_DATE="$(find "${IMG_DIR%/deploy-*}" -name "nvdcve-*.db" -newer /proc 2>/dev/null | head -1 || true)"
cat > "$RUN_DIR/run.json" <<EOF
{
  "id": "$RUN_ID",
  "machine": "$MACHINE",
  "previous": "${PREV_ID:-null}",
  "generated": "$GEN",
  "commit": "$COMMIT",
  "ref": "$REF",
  "has_diff": $( [ -f "$RUN_DIR/diff-cve.json" ] && echo true || echo false )
}
EOF

echo "== reindex =="
python3 "$HERE/reindex.py" "$STORE"

echo "done: $RUN_DIR"
