#!/usr/bin/env python3
"""JE hygiene baseline check, run against a built rootfs at do_rootfs
QA time. Exits non-zero (failing the build) if any *enforced* check
fails. Always writes a JSON report covering every check -- see
README.md in this layer for the full checklist and which checks are
enforced vs. report-only, and why.

Usage:
    je_hygiene_check.py --rootfs DIR --report FILE
        [--require-no-default-creds] [--require-key-only-ssh]
        [--require-minimal-service-surface] [--allowed-services LIST]
        [--require-kernel-hardening-flags] [--kernel-config FILE]
"""
import argparse
import json
import sys
from pathlib import Path

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

# Password-field values that mean "locked, no password login possible" --
# not a default/blank credential.
LOCKED_HASH_MARKERS = ("!", "*")


def check_no_default_credentials(rootfs):
    """Every /etc/shadow account either has a real hash or is locked.
    A blank password field means the account needs no password at all."""
    shadow = rootfs / "etc" / "shadow"
    if not shadow.is_file():
        return {"status": "pass", "detail": "no /etc/shadow in rootfs"}

    blank = []
    for line in shadow.read_text(errors="replace").splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) < 2:
            continue
        user, pwhash = fields[0], fields[1]
        if pwhash == "":
            blank.append(user)
    if blank:
        return {
            "status": "fail",
            "detail": f"blank password field for: {', '.join(blank)}",
        }
    return {"status": "pass", "detail": "no blank password fields"}


def check_key_only_ssh(rootfs):
    """sshd_config must explicitly disable password auth and
    unrestricted root login, if sshd is shipped at all."""
    sshd_config = rootfs / "etc" / "ssh" / "sshd_config"
    if not sshd_config.is_file():
        return {"status": "pass", "detail": "no sshd_config in rootfs (no sshd shipped)"}

    directives = {}
    for line in sshd_config.read_text(errors="replace").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            key, val = parts[0], parts[1].strip()
            # sshd_config takes the first occurrence of a directive.
            directives.setdefault(key, val)

    problems = []
    pw_auth = directives.get("PasswordAuthentication")
    if pw_auth != "no":
        problems.append(
            f"PasswordAuthentication is {pw_auth!r}, must be explicitly 'no'"
        )
    root_login = directives.get("PermitRootLogin")
    if root_login not in ("no", "prohibit-password"):
        problems.append(
            f"PermitRootLogin is {root_login!r}, must be 'no' or 'prohibit-password'"
        )

    if problems:
        return {"status": "fail", "detail": "; ".join(problems)}
    return {"status": "pass", "detail": "PasswordAuthentication no, PermitRootLogin restricted"}


def not_implemented(reason):
    return {"status": "not_implemented", "detail": reason}


def check_minimal_service_surface(rootfs, allowed):
    """Every systemd unit enabled in the rootfs (a symlink under
    etc/systemd/system/*.wants/) must be in the caller-supplied
    allowlist. No allowlist means every enabled unit is unlisted --
    fails loud rather than silently passing, so JE_HYGIENE_ALLOWED_SERVICES
    has to be set deliberately, not left to a default that means
    nothing."""
    systemd_dir = rootfs / "etc" / "systemd" / "system"
    if not systemd_dir.is_dir():
        return {"status": "pass", "detail": "no etc/systemd/system in rootfs (not a systemd image)"}

    enabled = set()
    for wants_dir in sorted(systemd_dir.glob("*.wants")):
        if not wants_dir.is_dir():
            continue
        for entry in wants_dir.iterdir():
            if entry.is_symlink() or entry.is_file():
                enabled.add(entry.name)

    if not enabled:
        return {"status": "pass", "detail": "no enabled units found"}

    unlisted = sorted(enabled - allowed)
    if unlisted:
        return {
            "status": "fail",
            "detail": f"enabled units not in allowlist: {', '.join(unlisted)}",
        }
    return {"status": "pass", "detail": f"{len(enabled)} enabled unit(s), all allowlisted"}


def check_read_only_rootfs(rootfs):
    """Report-only, permanently -- feasibility is per-target (storage
    wear, whether the app writes to disk at runtime), never a
    universal hard requirement. Reads etc/fstab's root entry, the same
    place OE's read-only-rootfs IMAGE_FEATURE actually changes."""
    fstab = rootfs / "etc" / "fstab"
    if not fstab.is_file():
        return {"status": "report", "detail": "no etc/fstab in rootfs, can't determine"}

    for line in fstab.read_text(errors="replace").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        if len(fields) < 4:
            continue
        mount_point, options = fields[1], fields[3]
        if mount_point == "/":
            opts = options.split(",")
            if "ro" in opts:
                return {"status": "report", "detail": "root mounted read-only (fstab: ro)"}
            return {"status": "report", "detail": f"root mounted read-write (fstab options: {options})"}

    return {"status": "report", "detail": "no root (/) entry in fstab, can't determine"}


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rootfs", required=True, type=Path)
    ap.add_argument("--report", required=True, type=Path)
    ap.add_argument("--require-no-default-creds", action="store_true")
    ap.add_argument("--require-key-only-ssh", action="store_true")
    ap.add_argument("--require-minimal-service-surface", action="store_true")
    ap.add_argument(
        "--allowed-services",
        default="",
        help="space- or comma-separated systemd unit names",
    )
    ap.add_argument("--require-kernel-hardening-flags", action="store_true")
    ap.add_argument("--kernel-config", type=Path)
    args = ap.parse_args()

    allowed_services = {
        s for s in args.allowed_services.replace(",", " ").split() if s
    }

    results = {
        "no_default_credentials": {
            **check_no_default_credentials(args.rootfs),
            "enforced": args.require_no_default_creds,
        },
        "key_only_ssh": {
            **check_key_only_ssh(args.rootfs),
            "enforced": args.require_key_only_ssh,
        },
        "minimal_service_surface": {
            **check_minimal_service_surface(args.rootfs, allowed_services),
            "enforced": args.require_minimal_service_surface,
        },
        "read_only_rootfs": {
            **check_read_only_rootfs(args.rootfs),
            "enforced": False,
        },
        "kernel_hardening_flags": {
            **check_kernel_hardening_flags(args.kernel_config),
            "enforced": args.require_kernel_hardening_flags,
        },
    }

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(results, indent=2) + "\n")

    failed = [
        name
        for name, r in results.items()
        if r["enforced"] and r["status"] == "fail"
    ]
    for name, r in results.items():
        print(f"je-hygiene: {name}: {r['status']} -- {r['detail']}", file=sys.stderr)

    if failed:
        print(
            f"je-hygiene: FAILED build -- unmet enforced checks: {', '.join(failed)}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
