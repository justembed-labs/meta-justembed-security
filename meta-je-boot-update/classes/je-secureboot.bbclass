# U-Boot-verifies-kernel/DT FIT signing -- generic, board-agnostic
# wiring of oe-core's own kernel-fitimage.bbclass + uboot-sign.bbclass
# (poky/meta/classes-recipe/), not custom mkimage/signing tooling. See
# the consuming BSP's docs/decisions.md for the full design and why
# the deeper SPL-verifies-u-boot link isn't wired up here.
#
#   INHERIT += "je-secureboot"
#
# Global INHERIT, not IMAGE_CLASSES -- this has to affect the kernel
# recipe's own build (KERNEL_CLASSES/KERNEL_IMAGETYPE), not just image
# assembly.
#
# What this class deliberately does NOT do, and why it can't:
# - Enable CONFIG_OF_SEPARATE/CONFIG_FIT/CONFIG_FIT_SIGNATURE in the
#   target's own u-boot .config. u-boot.bbclass has no kernel-style
#   .cfg fragment merge mechanism -- add a do_configure:append() on
#   the BSP's own u-boot recipe instead.
# - Inherit uboot-sign.bbclass on the u-boot recipe (embeds this same
#   key's public half into u-boot.dtb, what makes U-Boot able to
#   verify a signature, not just kernel-fitimage.bbclass producing
#   one). A class inherited here can't force another recipe to
#   inherit a different class -- add it directly on the BSP's own
#   u-boot recipe, pointing at the same UBOOT_SIGN_KEYDIR/KEYNAME
#   below.

KERNEL_CLASSES:append = " kernel-fitimage"
# Hard assignment, not "?=" -- most machine .conf/.inc files set this
# unconditionally (e.g. ti33x.inc's KERNEL_IMAGETYPE = "zImage"), which
# a later "?=" here can never win against regardless of inherit order.
# Confirmed by a real build (2026-09-16): "?=" silently produced a
# plain zImage, no fitImage at all, no error either.
KERNEL_IMAGETYPE = "fitImage"

# One key pair, shared by this class (kernel/DT signing) and the
# BSP's own u-boot recipe (uboot-sign.bbclass, public half into
# u-boot.dtb) -- both must point at the same KEYDIR/KEYNAME. Dev-key
# autogeneration on by default for bring-up; a real product provisions
# its own key material out of band and points KEYDIR at it instead.
UBOOT_SIGN_ENABLE ?= "1"
UBOOT_SIGN_KEYDIR ?= "${TOPDIR}/../je-secureboot-keys"
UBOOT_SIGN_KEYNAME ?= "je-secureboot-dev"
FIT_GENERATE_KEYS ?= "1"

# kernel-fitimage.bbclass always generates a second, image-node-signing
# key pair alongside the conf-signing one above, regardless of
# FIT_SIGN_INDIVIDUAL -- leaving this unset produces a confusing bare
# ".crt"/".key" pair (empty basename) in UBOOT_SIGN_KEYDIR. Must be a
# genuinely DIFFERENT name from UBOOT_SIGN_KEYNAME, not just any
# non-empty one -- kernel-fitimage.bbclass hard-errors ("Keys used to
# sign images and configuration nodes must be different") if they
# match, confirmed by a real build (2026-09-16): this is a deliberate
# anti-mix-and-match-attack check, not an arbitrary restriction, per
# uboot-sign.bbclass's own comment on the same requirement. Unused
# either way here (FIT_SIGN_INDIVIDUAL stays "0", the oe-core-
# recommended default) but has to exist and be distinct.
UBOOT_SIGN_IMG_KEYNAME ?= "${UBOOT_SIGN_KEYNAME}-img"
