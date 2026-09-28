"""Kernel-level hardening config."""

# Kconfig hardening baseline, each entry a real symbol confirmed to
# exist in this project's own kernel tree (grepped directly against
# the built git checkout, not assumed from a generic KSPP list) --
# CONFIG_RANDOMIZE_BASE deliberately excluded: it's an s390-only
# symbol in this tree, not a real option on this target's arch at all.
KERNEL_HARDENING_FLAGS = (
    "CONFIG_STACKPROTECTOR",
    "CONFIG_STACKPROTECTOR_STRONG",
    "CONFIG_STRICT_KERNEL_RWX",
    "CONFIG_STRICT_MODULE_RWX",
    "CONFIG_VMAP_STACK",
    "CONFIG_HARDENED_USERCOPY",
    "CONFIG_FORTIFY_SOURCE",
    "CONFIG_SLAB_FREELIST_HARDENED",
    "CONFIG_BUG_ON_DATA_CORRUPTION",
    "CONFIG_INIT_ON_ALLOC_DEFAULT_ON",
    "CONFIG_INIT_ON_FREE_DEFAULT_ON",
)


def check_kernel_hardening_flags(kernel_config):
    """Report per-flag pass/fail against KERNEL_HARDENING_FLAGS. Needs
    --kernel-config (e.g. STAGING_KERNEL_BUILDDIR/.config) -- without
    it there's nothing to check."""
    if kernel_config is None:
        return {
            "status": "not_implemented",
            "detail": "no --kernel-config given",
            "flags": {},
        }
    if not kernel_config.is_file():
        return {
            "status": "fail",
            "detail": f"--kernel-config {kernel_config} not found",
            "flags": {},
        }

    text = kernel_config.read_text(errors="replace")
    flags = {}
    for symbol in KERNEL_HARDENING_FLAGS:
        if f"{symbol}=y" in text:
            flags[symbol] = "set"
        elif f"# {symbol} is not set" in text:
            flags[symbol] = "unset"
        else:
            flags[symbol] = "absent"

    unset = [k for k, v in flags.items() if v != "set"]
    if unset:
        return {
            "status": "fail",
            "detail": f"not set: {', '.join(unset)}",
            "flags": flags,
        }
    return {"status": "pass", "detail": "all baseline hardening flags set", "flags": flags}
