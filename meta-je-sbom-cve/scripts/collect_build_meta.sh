#!/bin/sh
# Emit build-meta.json for one evidence run.
#
# Usage: collect_build_meta.sh <kas-target-spec> <image-recipe> > build-meta.json
#
# <kas-target-spec> is the same colon-joined list passed to `kas build`
# (e.g. kas/base.yml:kas/machine/<your-machine>.yml:kas/evidence.yml).
# Run from the repo root, after the build, with kas on PATH.
set -eu

SPEC="$1"
IMAGE="$2"

# One `bitbake -e` call, parsed for the vars we want.
ENV="$(kas shell "$SPEC" -c "bitbake -e $IMAGE" 2>/dev/null)"
val() { printf '%s\n' "$ENV" | sed -n "s/^$1=\"\(.*\)\"\$/\1/p" | head -1; }

MACHINE="$(val MACHINE)"
DISTRO="$(val DISTRO)"
DISTRO_VERSION="$(val DISTRO_VERSION)"
TUNE="$(val DEFAULTTUNE)"
IMAGE_NAME="$(val IMAGE_NAME)"

KVER="$(kas shell "$SPEC" -c "bitbake -e virtual/kernel" 2>/dev/null \
        | sed -n 's/^PV="\(.*\)"$/\1/p' | head -1)"
UVER="$(kas shell "$SPEC" -c "bitbake -e virtual/bootloader" 2>/dev/null \
        | sed -n 's/^PV="\(.*\)"$/\1/p' | head -1)"

GIT_COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
GIT_REF="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
GIT_DIRTY=false
git diff --quiet 2>/dev/null || GIT_DIRTY=true

# Layer revisions: name -> commit, from the poky/oe layer checkouts kas made.
LAYERS="$(
  for d in poky meta-openembedded meta-arm meta-ti meta-qt5 meta-qt6; do
    [ -d "$d/.git" ] || continue
    printf '    "%s": "%s",\n' "$d" "$(git -C "$d" rev-parse HEAD 2>/dev/null || echo unknown)"
  done
  for d in sources/meta-justembed-*; do
    [ -d "$d" ] || continue
    printf '    "%s": "in-tree",\n' "$(basename "$d")"
  done | sed '$ s/,$//'
)"

cat <<EOF
{
  "machine": "${MACHINE}",
  "distro": "${DISTRO}",
  "distro_version": "${DISTRO_VERSION}",
  "tune": "${TUNE}",
  "image": "${IMAGE}",
  "image_name": "${IMAGE_NAME}",
  "kernel_version": "${KVER}",
  "bootloader_version": "${UVER}",
  "git_commit": "${GIT_COMMIT}",
  "git_ref": "${GIT_REF}",
  "git_dirty": ${GIT_DIRTY},
  "layers": {
$(printf '%s' "$LAYERS")
  }
}
EOF
