SUMMARY = "Shared shell helper: swupdate rollback/replay guard (-N/-R)"
DESCRIPTION = "\
Not a conf.d file itself -- conf.d entries each fully replace \
SWUPDATE_ARGS, so a second one here would just be overwritten by the \
BSP's own. A BSP's conf.d sources this and folds the result into its \
own SWUPDATE_ARGS. See the file's own header for the exact usage."
LICENSE = "Apache-2.0"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/Apache-2.0;md5=89aea4e17d99a7cacdbeed46a0096b10"

SRC_URI = "file://je-downgrade-guard.sh"

RDEPENDS:${PN} = "swupdate"

do_install() {
    install -d ${D}${libdir}/swupdate
    install -m 0644 ${WORKDIR}/je-downgrade-guard.sh ${D}${libdir}/swupdate/je-downgrade-guard.sh
}

FILES:${PN} = "${libdir}/swupdate/je-downgrade-guard.sh"
