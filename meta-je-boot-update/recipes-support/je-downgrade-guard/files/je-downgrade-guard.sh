# Shared helper, sourced by a BSP's own swupdate conf.d file -- not a
# conf.d file itself, since conf.d entries each fully replace
# SWUPDATE_ARGS (see meta-swupdate's swupdate.sh) rather than append,
# so a second conf.d drop-in here would just get overwritten by the
# BSP's own.
#
# Usage, in the BSP's own conf.d/*.sh:
#   . @LIBDIR@/swupdate/je-downgrade-guard.sh
#   SWUPDATE_ARGS="-v -k /etc/swupdate.pem $(je_downgrade_guard_args)"
#
# je-swupdate-fota's own examples/sw-description use a single top-level
# `version` field for the whole bundle (not per-image versions), so the
# whole-bundle guard (-N/-R) is the correct mechanism here, not
# swupdate's separate per-image install-if-higher/sw-versions path.
je_downgrade_guard_args() {
	cur=""
	if [ -r /etc/sw-versions ]; then
		cur=$(awk '{print $2}' /etc/sw-versions 2>/dev/null | sort -V | tail -1)
	fi
	if [ -n "$cur" ]; then
		printf '%s' "-N $cur -R $cur --gen-swversions /etc/sw-versions"
	else
		# First boot, nothing installed yet via swupdate -- nothing to
		# guard against. Still ask swupdate to start recording versions
		# from here on.
		printf '%s' "--gen-swversions /etc/sw-versions"
	fi
}
