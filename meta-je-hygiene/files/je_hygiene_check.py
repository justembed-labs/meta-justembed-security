#!/usr/bin/env python3
"""JE hygiene baseline check, run against a built rootfs at do_rootfs
QA time. Exits non-zero (failing the build) if any *enforced* check
fails. Always writes a JSON report covering every check -- see
README.md in this layer for the full checklist and which checks are
enforced vs. report-only, and why.

Each check lives in checks/, grouped by what it's actually checking
(credentials, service surface, filesystem, kernel) -- this file is
just the CLI/orchestration layer: argparse, running each check,
assembling and writing the report.

Usage:
    je_hygiene_check.py --rootfs DIR --report FILE
        [--require-no-default-creds] [--require-key-only-ssh]
        [--require-minimal-service-surface] [--allowed-services LIST]
        [--require-kernel-hardening-flags] [--kernel-config FILE]
        [--require-swupdate-webserver-protected]
"""
import argparse
import json
import sys
from pathlib import Path

from checks.credentials import check_no_default_credentials, check_key_only_ssh
from checks.service_surface import (
    check_minimal_service_surface,
    check_swupdate_webserver_protected,
)
from checks.filesystem import check_read_only_rootfs
from checks.kernel import check_kernel_hardening_flags


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
    ap.add_argument("--require-swupdate-webserver-protected", action="store_true")
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
        "swupdate_webserver_protected": {
            **check_swupdate_webserver_protected(args.rootfs),
            "enforced": args.require_swupdate_webserver_protected,
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
