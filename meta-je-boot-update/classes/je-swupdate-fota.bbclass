# Adds swupdate to an image recipe -- generic, board-agnostic part
# only: the agent, its built-in webserver mode, and the raw ext4.gz
# output swupdate needs to write to an inactive copy partition.
#
#   IMAGE_CLASSES += "je-swupdate-fota"
#
# Requires meta-swupdate (github.com/sbabic/meta-swupdate, scarthgap).
#
# What this class deliberately does NOT do, and why it can't: generate
# the actual .swu update bundle. That needs a real dual-copy partition
# layout, a real `sw-description` (partition device paths, u-boot env
# variable names), and the board's own bootloader integration -- all
# genuinely board-specific (see meta-je-boot-update/README.md's
# "Staying hardware-agnostic" section). A BSP using this class defines
# its own update-image recipe inheriting `swupdate` (from meta-swupdate
# itself, not this class) with its own `sw-description`, same pattern
# as meta-swupdate-boards' per-board examples.

IMAGE_INSTALL:append = " swupdate"

# Raw partition-writable rootfs image, needed by any board's swupdate
# `sw-description` regardless of its specific partition layout.
IMAGE_FSTYPES:append = " ext4.gz"

# swupdate.cfg (webserver mode, ports, etc.) is board-specific -- provided
# by the BSP via a swupdate recipe bbappend, same as meta-swupdate-boards'
# own per-board examples. Nothing generic to set here.
