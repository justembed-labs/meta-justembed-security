# Adds OSTree to an image recipe -- generic, board-agnostic part
# only: installs the ostree tool itself, the generic image dependency
# any OSTree-based deployment needs.
#
#   IMAGE_CLASSES += "je-ostree-fota"
#
# Requires meta-openembedded/meta-oe (ostree_2024.5.bb or newer) --
# already in base.yml, no extra layer needed.
#
# What this class deliberately does NOT do, and why it can't (unlike
# je-swupdate-fota, which leans on meta-swupdate's own
# swupdate.bbclass/do_swuimage): there is currently no maintained
# Yocto-level automation that turns a built rootfs into an OSTree
# commit plus a bootable deployment. meta-updater
# (github.com/advancedtelematic/meta-updater), historically the layer
# that provided this, has had no commits since 2021-12-09 and no
# scarthgap (or any post-2021) branch -- checked via `git ls-remote`
# and the GitHub API, not assumed. So "commit this rootfs into an
# OSTree repo and deploy it" has no drop-in bitbake class to inherit
# here. A consuming BSP has to implement that step itself -- most
# realistically a host-side script driving the plain `ostree` CLI
# against a normally-built rootfs image, outside bitbake's own task
# graph, plus its own bootloader-deployment-pointer integration. Same
# hardware-specific split as je-swupdate-fota's partition layout and
# sw-description.

IMAGE_INSTALL:append = " ostree"
