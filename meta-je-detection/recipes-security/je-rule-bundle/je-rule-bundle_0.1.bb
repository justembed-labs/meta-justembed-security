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

    # -m 0750 matches auditd's own /etc/audit + /etc/audit/rules.d mode
    # exactly -- a bare `install -d` (default 0755) here makes rpm see
    # two packages declaring the same directory path with different
    # permission bits and refuse the transaction as a real conflict,
    # not a false positive (confirmed: auditd's own package lists both
    # dirs as drwxr-x---). Both directories named explicitly -- `install
    # -d -m` only applies the given mode to the named path components,
    # not to a parent it creates implicitly along the way (confirmed:
    # naming only rules.d left the auto-created /etc/audit at the
    # default 0755, still conflicting).
    install -d -m 0750 ${D}${sysconfdir}/audit ${D}${sysconfdir}/audit/rules.d
    install -m 0640 ${WORKDIR}/rules.d/CVE-2026-73283.rules ${D}${sysconfdir}/audit/rules.d/
}

RDEPENDS:${PN} += "auditd"

FILES:${PN} = " \
    ${sysconfdir}/je-detection \
    ${sysconfdir}/audit/rules.d/CVE-2026-73283.rules \
"
