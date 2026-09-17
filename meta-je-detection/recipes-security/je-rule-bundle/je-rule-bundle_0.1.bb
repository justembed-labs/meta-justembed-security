SUMMARY = "meta-je-detection rule bundle (per-CVE audit rules + OCSF descriptors)"
DESCRIPTION = "One auditd rule + one JSON descriptor per detected CVE \
(rules.d/<CVE>.rules + <CVE>.json) -- deliberately its own recipe, \
separate from je-detection-agent, so this content can be versioned \
and (eventually) signed and shipped independently of the agent \
binary/firmware, over whatever channel meta-je-boot-update's FOTA \
uses, on its own faster cadence. Per the source plan (\$4): 'The rule \
bundle ... is versioned and signed independently of firmware, \
shipped over the same secure channel as FOTA but on its own faster \
cadence -- this decoupling is the actual patch-latency-gap-closing \
mechanism.'"
LICENSE = "Apache-2.0"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/Apache-2.0;md5=89aea4e17d99a7cacdbeed46a0096b10"

SRC_URI = " \
    file://rules.d/CVE-2026-73283.rules \
    file://rules.d/CVE-2026-73283.json \
"

do_install() {
    install -d ${D}${sysconfdir}/je-detection/rules.d
    install -m 0644 ${WORKDIR}/rules.d/CVE-2026-73283.json ${D}${sysconfdir}/je-detection/rules.d/

    install -d ${D}${sysconfdir}/audit/rules.d
    install -m 0640 ${WORKDIR}/rules.d/CVE-2026-73283.rules ${D}${sysconfdir}/audit/rules.d/
}

FILES:${PN} = " \
    ${sysconfdir}/je-detection \
    ${sysconfdir}/audit/rules.d/CVE-2026-73283.rules \
"
