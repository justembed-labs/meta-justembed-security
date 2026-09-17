SUMMARY = "CVE-to-rule compensating detection agent (meta-je-detection)"
DESCRIPTION = "Watches auditd for matches against per-CVE rules \
(rules.d/<CVE>.rules + <CVE>.json, installed by the separate \
je-rule-bundle recipe -- deliberately not this one, so the rule \
content can be versioned/signed/shipped independently of this agent \
binary) and emits OCSF Security Finding (class_uid 2001) events as \
JSON lines for Fluent Bit to ship to a Splunk HEC endpoint. Detection \
+ OCSF formatting only -- no transport, per the meta-je-detection \
design (see README.md)."
LICENSE = "Apache-2.0"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/Apache-2.0;md5=89aea4e17d99a7cacdbeed46a0096b10"

SRC_URI = " \
    file://je-detection-agent \
    file://je-detection-agent.service \
    file://je-detection-agent.init \
    file://je-detection-fluentbit.conf \
    file://je-detection-fluentbit.service \
    file://je-detection-fluentbit.init \
    file://splunk-hec.env.example \
"

RDEPENDS:${PN} = "auditd fluentbit python3-core python3-modules"

inherit update-rc.d systemd

INITSCRIPT_NAME = "je-detection-agent"
INITSCRIPT_PARAMS = "start 95 2 3 4 5 . stop 05 0 1 6 ."
SYSTEMD_SERVICE:${PN} = "je-detection-agent.service je-detection-fluentbit.service"

do_install() {
    install -d ${D}${bindir}
    install -m 0755 ${WORKDIR}/je-detection-agent ${D}${bindir}/je-detection-agent

    install -d ${D}${sysconfdir}/je-detection
    install -m 0644 ${WORKDIR}/splunk-hec.env.example ${D}${sysconfdir}/je-detection/
    install -m 0644 ${WORKDIR}/je-detection-fluentbit.conf ${D}${sysconfdir}/je-detection/fluent-bit.conf

    # /var/lib/je-detection (ausearch checkpoints) and
    # /var/log/je-detection (event output) are created at runtime by
    # the agent itself (os.makedirs), not pre-created here -- /var/log
    # is a symlink on this distro, so packaging a real directory under
    # it fails do_package.

    if ${@bb.utils.contains('DISTRO_FEATURES', 'sysvinit', 'true', 'false', d)}; then
        install -d ${D}${sysconfdir}/init.d
        install -m 0755 ${WORKDIR}/je-detection-agent.init ${D}${sysconfdir}/init.d/je-detection-agent
        install -m 0755 ${WORKDIR}/je-detection-fluentbit.init ${D}${sysconfdir}/init.d/je-detection-fluentbit
    fi
    if ${@bb.utils.contains('DISTRO_FEATURES', 'systemd', 'true', 'false', d)}; then
        install -d ${D}${systemd_system_unitdir}
        install -m 0644 ${WORKDIR}/je-detection-agent.service ${D}${systemd_system_unitdir}/je-detection-agent.service
        install -m 0644 ${WORKDIR}/je-detection-fluentbit.service ${D}${systemd_system_unitdir}/je-detection-fluentbit.service
    fi
}

FILES:${PN} = " \
    ${bindir}/je-detection-agent \
    ${sysconfdir}/je-detection \
    ${sysconfdir}/init.d/je-detection-agent \
    ${sysconfdir}/init.d/je-detection-fluentbit \
    ${systemd_system_unitdir}/je-detection-agent.service \
    ${systemd_system_unitdir}/je-detection-fluentbit.service \
"
