#!/usr/bin/env python3
"""Wrap OE-core's improve_kernel_cve_report.py for kernel CVE triage,
instead of extending kernel_cve_triage.py's own heuristic further.

Per the upstream-alignment review (docs/evidence-upstream-alignment-plan.md):
kernel_cve_triage.py's config-inapplicable check is a real, build-specific
git-ancestor/Kconfig heuristic, but it only fires when a CVE summary
quotes a commit subject that maps cleanly to one Kconfig symbol via a
Makefile regex -- a subset of cases. improve_kernel_cve_report.py's
compiled-sources check (real kernel.org CNA data + SPDX/debug-sources
compiled-file list) covers every CVE with `programFiles` metadata,
independent of the fix commit being findable at all. This script calls
the real upstream tool (not a reimplementation) and re-buckets its
output into kernel_cve_triage.py's existing 4-bucket JSON/MD shape, so
prioritize_cves.py and everything downstream (cve-applicability.md,
GitLab Pages publishing) needs no changes.

Opt-in, standalone -- not wired into je-cve-diff.bbclass's default task
flow. Needs a real upstream CVE data source
(git.kernel.org/pub/scm/linux/security/vulns.git) and, for the
config-inapplicable bucket specifically, a kernel SPDX document built
with SPDX_INCLUDE_COMPILED_SOURCES:pn-linux-yocto = "1" (or a debug-
sources zstd file) -- without either, only the CPE-version-range
buckets (fixed-version / cpe-mismatch / needs-review) are populated.

Usage:
    kernel_cve_upstream_triage.py CVE_SUMMARY_JSON DATADIR IMPROVE_SCRIPT
        [--package NAME] [--spdx PATH] [--debug-sources-file PATH]
        [--out-prefix PREFIX]

CVE_SUMMARY_JSON  raw cve-check JSON (CVE_CHECK_FORMAT_JSON output,
                  e.g. evidence-store/.../cve.json) -- NOT parse_cve.py's
                  unpatched.csv.
DATADIR           a local clone of
                  git.kernel.org/pub/scm/linux/security/vulns.git
                  (its cve/ subdirectory).
IMPROVE_SCRIPT    path to a local OE-core checkout's
                  scripts/contrib/improve_kernel_cve_report.py -- not
                  vendored into this repo (upstream-first: call it, don't
                  copy it).
PACKAGE           cve-check package name to triage (default: linux-ti-staging)
OUT_PREFIX        output file prefix (default: kernel-cve-upstream-triage)

Writes OUT_PREFIX.json/.md in kernel_cve_triage.py's own report shape.
Each bucket entry also carries "source": "upstream" and the raw
upstream "detail" string, for anyone who wants the finer-grained
upstream vocabulary without breaking existing consumers that only read
["cve"].
"""
import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from kernel_cve_triage import write_report  # noqa: E402

# improve_kernel_cve_report.py's (status, detail) -> our existing bucket
# name. "detail" is None for entries it left untouched (no CPE metadata
# to reassess) or for a raw cve-check entry that never had a "detail"
# field at all (see _normalize_missing_detail below).
STATUS_TO_BUCKET = {
    ("Ignored", "not-applicable-config"): "config_inapplicable_candidates",
    ("Patched", "fixed-version"): "fixed_version_candidates",
    ("Patched", "cpe-stable-backport"): "fixed_version_candidates",
    ("Patched", "version-not-in-range"): "cpe_mismatch_candidates",
    ("Unpatched", "version-in-range"): "needs_human_review",
    ("Unpatched", None): "needs_human_review",
}
# CNA-rejected entries aren't real CVEs -- excluded from every bucket,
# same as they'd be excluded from a human triage pass.
EXCLUDED_DETAILS = {("Ignored", "rejected")}


def _normalize_missing_detail(cve_report):
    """Real compatibility shim, not a logic change: this project's
    cve-check version doesn't emit a "detail" field on existing issue
    entries at all (confirmed against a real evidence-store run --
    every one of 15001 kernel issue entries lacked it), but
    improve_kernel_cve_report.py's cve_update() unconditionally reads
    cve_data[cve]['detail'] on any entry it's about to overwrite.
    Defaulting the missing field to None is functionally identical to
    how the upstream script already treats an unrecognized detail
    value -- it only special-cases the literal string
    "backported-patch"."""
    for pkg in cve_report.get("package", []):
        for issue in pkg.get("issue", []):
            issue.setdefault("detail", None)
    return cve_report


def _suggested_status(cve, prefix, description):
    """Avoids doubling the prefix -- some upstream `description` strings
    already embed their own `detail` keyword (e.g. "fixed-version" ->
    "fixed-version: Fixed from version 6.0"), others don't (e.g.
    "cpe-stable-backport" -> "Backported in 6.3")."""
    body = description if description.lower().startswith(prefix.lower()) \
        else f"{prefix}: {description}"
    return f'CVE_STATUS[{cve}] = "{body}"'


def rebucket(enhanced_report, package):
    inapplicable, fixed, mismatch, review = [], [], [], []
    for pkg in enhanced_report.get("package", []):
        if pkg.get("name") != package:
            continue
        for issue in pkg.get("issue", []):
            detail = issue.get("detail")
            key = (issue.get("status"), detail)
            if key in EXCLUDED_DETAILS:
                continue
            bucket = STATUS_TO_BUCKET.get(key)
            if bucket is None:
                continue
            cve = issue["id"]
            description = issue.get("description", "")
            entry = {"cve": cve, "source": "upstream", "detail": detail}
            if bucket == "config_inapplicable_candidates":
                entry["config_symbol"] = "upstream-compiled-sources"
                entry["file"] = description
                entry["reason"] = description
                entry["suggested_cve_status"] = _suggested_status(
                    cve, "not-applicable-config", description)
                inapplicable.append(entry)
            elif bucket == "fixed_version_candidates":
                entry["commit"] = "cpe-range"
                entry["subject"] = description
                entry["suggested_cve_status"] = _suggested_status(cve, detail, description)
                fixed.append(entry)
            elif bucket == "cpe_mismatch_candidates":
                entry["reason"] = f"upstream CPE version-range analysis: {description}"
                mismatch.append(entry)
            elif bucket == "needs_human_review":
                entry["reason"] = description or "no CPE metadata available upstream"
                review.append(entry)
    return inapplicable, fixed, mismatch, review


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("cve_summary_json")
    parser.add_argument("datadir")
    parser.add_argument("improve_script")
    parser.add_argument("--package", default="linux-ti-staging")
    parser.add_argument("--spdx")
    parser.add_argument("--debug-sources-file")
    parser.add_argument("--out-prefix", default="kernel-cve-upstream-triage")
    args = parser.parse_args()

    with open(args.cve_summary_json, encoding="ISO-8859-1") as f:
        cve_report = json.load(f)
    cve_report = _normalize_missing_detail(cve_report)

    kernel_version = None
    for pkg in cve_report["package"]:
        if pkg["name"] == args.package:
            kernel_version = pkg["version"].split("-")[0]
    if kernel_version is None:
        sys.exit(f"package {args.package!r} not found in {args.cve_summary_json}")

    with tempfile.TemporaryDirectory() as tmp:
        normalized_path = Path(tmp) / "cve-normalized.json"
        normalized_path.write_text(json.dumps(cve_report))
        enhanced_path = Path(tmp) / "cve-enhanced.json"

        cmd = [
            sys.executable, args.improve_script,
            "--old-cve-report", str(normalized_path),
            "--datadir", args.datadir,
            "--kernel-version", kernel_version,
            "--new-cve-report", str(enhanced_path),
        ]
        if args.spdx:
            cmd += ["--spdx", args.spdx]
        if args.debug_sources_file:
            cmd += ["--debug-sources-file", args.debug_sources_file]
        subprocess.run(cmd, check=True)

        enhanced_report = json.loads(enhanced_path.read_text(encoding="ISO-8859-1"))

    inapplicable, fixed, mismatch, review = rebucket(enhanced_report, args.package)
    total = sum(len(b) for b in (inapplicable, fixed, mismatch, review))
    write_report(args.out_prefix, args.package, kernel_version,
                 total, inapplicable, fixed, mismatch, review)
    print(f"{total} scanned (upstream): {len(inapplicable)} config-inapplicable, "
          f"{len(fixed)} fixed-version, {len(mismatch)} cpe-mismatch, "
          f"{len(review)} needs-review -> {args.out_prefix}.json/.md")


if __name__ == "__main__":
    main()
