# JE hygiene baseline, enforced at do_rootfs QA time -- fails the
# build (not just a warning) when an enforced check is unmet. See
# meta-je-hygiene/README.md for the full checklist and which checks
# are enforced vs. report-only.
#
# Inherit this class from an image recipe (or IMAGE_CLASSES globally)
# to turn it on:
#   IMAGE_CLASSES += "je-hygiene"

JE_HYGIENE_REQUIRE_NO_DEFAULT_CREDS ?= "1"
JE_HYGIENE_REQUIRE_KEY_ONLY_SSH ?= "1"
# Off by default -- no image has an allowlist defined yet, and turning
# this on unconditionally would fail every existing image immediately.
# Set JE_HYGIENE_ALLOWED_SERVICES and this to "1" together, per image.
JE_HYGIENE_REQUIRE_MINIMAL_SERVICE_SURFACE ?= "0"
JE_HYGIENE_ALLOWED_SERVICES ?= ""
# Off by default -- real target testing (2026-09-16) found roughly
# half the baseline flags already set, the rest not; enabling this
# hard-fails until those are reviewed and either turned on or accepted
# per image.
JE_HYGIENE_REQUIRE_KERNEL_HARDENING_FLAGS ?= "0"
JE_HYGIENE_KERNEL_CONFIG ?= "${STAGING_KERNEL_BUILDDIR}/.config"
JE_HYGIENE_REPORT_DIR ?= "${DEPLOY_DIR_IMAGE}"

# ":append" (not "+=") is required here: rootfs-postcommands.bbclass's
# own security-relevant postprocessing (zap_empty_root_password,
# ssh_allow_root_login, read_only_rootfs_hook, ...) is appended to this
# same variable by a class inherited earlier (image.bbclass's own
# ${IMAGE_CLASSES} inherit runs before it inherits rootfs-postcommands),
# so a plain "+=" here lands je_hygiene_qa_check FIRST in the command
# list -- checking the rootfs before that postprocessing has actually
# run. ":append" is applied after every plain assignment regardless of
# inherit order, so this always runs last, against the final rootfs.
ROOTFS_POSTPROCESS_COMMAND:append = " je_hygiene_qa_check; "

je_hygiene_qa_check() {
	python3 '${LAYERDIR_JE_HYGIENE}/files/je_hygiene_check.py' \
		--rootfs "${IMAGE_ROOTFS}" \
		--report '${JE_HYGIENE_REPORT_DIR}/${IMAGE_NAME}.je-hygiene.json' \
		--allowed-services '${JE_HYGIENE_ALLOWED_SERVICES}' \
		$( [ "${JE_HYGIENE_REQUIRE_NO_DEFAULT_CREDS}" = "1" ] && echo --require-no-default-creds ) \
		$( [ "${JE_HYGIENE_REQUIRE_KEY_ONLY_SSH}" = "1" ] && echo --require-key-only-ssh ) \
		$( [ "${JE_HYGIENE_REQUIRE_MINIMAL_SERVICE_SURFACE}" = "1" ] && echo --require-minimal-service-surface ) \
		$( [ -f "${JE_HYGIENE_KERNEL_CONFIG}" ] && echo --kernel-config "${JE_HYGIENE_KERNEL_CONFIG}" ) \
		$( [ "${JE_HYGIENE_REQUIRE_KERNEL_HARDENING_FLAGS}" = "1" ] && echo --require-kernel-hardening-flags )
}
