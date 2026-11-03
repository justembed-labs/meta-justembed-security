#!/usr/bin/env python3
"""Converts CIP kernel-cve-triage's report.json into this project's own
4-bucket shape (same as kernel_cve_triage.py/kernel_cve_upstream_triage.py/
kernel_backport_check.py), so prioritize_cves.py and the pages viewer
consume it with no changes.

CIP kernel-cve-triage (https://gitlab.com/cip-project/cip-kernel/kernel-cve-triage)
runs kmax -- a SAT-solver over the whole Kconfig/Makefile graph -- to check,
at both the commit that introduced a CVE and the one that fixed it, whether
the affected file was actually compiled in. Real measured result against
this project's own kernel/config, on the subset kernel_cve_upstream_triage.py
couldn't resolve: 111/722 (15.4%) -- a real, modest addition on top of
upstream's own 96.4%, not a replacement for it. See docs/cve-triage.md.

Intended as a SECOND PASS, run only on a prior stage's needs_human_review
output (CIP's own real measured edge is much smaller against the raw,
unfiltered candidate set than against this hard remainder -- see
docs/cve-triage.md for both real numbers, not just one).

Usage: cip_triage_adapter.py CIP_REPORT_JSON [package] [out_prefix] [our_ref]

CIP_REPORT_JSON is the real `cve-triage triage -o CIP_REPORT_JSON ...`
output -- run via the real kernel-cve-triage CLI
(pip install kmax fuzzysearch unidiff pyyaml; clone kernel-cve-triage;
pip install -e it; needs clang/clang-tools too), not reimplemented here.
"""
import json
import sys
from pathlib import Path

# Priority order matters: a CVE with both a file-compiled hit and an
# ancestry hit is classified by whichever this checks first -- file-
# compiled is the stronger claim ("the code can't run at all" beats
# "a fix commit exists"), matching kernel_cve_triage.py's own ordering.
FILE_COMPILED_CHECKS = ("check_introduced_by_file_compiled", "check_fixed_by_file_compiled")
ANCESTRY_CHECKS = ("check_fixed_by", "check_introduced_by")
IGNORE_CHECKS = ("check_ignore",)


def classify(entry):
    """Return (bucket, reason) for the first non-'relevant' check hit."""
    hits = {c["name"]: c for c in entry["check_results"] if c["result"] != "relevant"}
    for name in FILE_COMPILED_CHECKS:
        if name in hits:
            return "config_inapplicable_candidates", hits[name].get("reason", name)
    for name in ANCESTRY_CHECKS:
        if name in hits:
            return "fixed_version_candidates", hits[name].get("reason", name)
    for name in IGNORE_CHECKS:
        if name in hits:
            return "cpe_mismatch_candidates", hits[name].get("reason", name)
    return "needs_human_review", "no CIP check resolved this"


def triage(cip_report_path):
    data = json.loads(Path(cip_report_path).read_text())
    buckets = {"config_inapplicable_candidates": [], "fixed_version_candidates": [],
               "cpe_mismatch_candidates": [], "needs_human_review": []}
    for entry in data:
        bucket, reason = classify(entry)
        buckets[bucket].append({"cve": entry["cve"]["name"], "reason": reason,
                                 "source": "cip-kernel-cve-triage"})
    return len(data), buckets


def write_report(out_prefix, package, our_ref, total, buckets):
    inapplicable = buckets["config_inapplicable_candidates"]
    fixed = buckets["fixed_version_candidates"]
    mismatch = buckets["cpe_mismatch_candidates"]
    review = buckets["needs_human_review"]
    report = {
        "package": package,
        "our_ref": our_ref,
        "total_scanned": total,
        **buckets,
    }
    Path(f"{out_prefix}.json").write_text(json.dumps(report, indent=2))

    resolved = len(inapplicable) + len(fixed) + len(mismatch)
    lines = [
        f"# CIP kernel-cve-triage (kmax): {package} @ {our_ref[:12]}",
        "",
        f"{total} CVEs scanned (run on a prior stage's remainder, not the raw "
        f"candidate set -- see docs/cve-triage.md) -- "
        f"**{len(inapplicable)} config-inapplicable**, "
        f"**{len(fixed)} fixed-version candidates**, "
        f"**{len(mismatch)} ignored**, "
        f"{len(review)} still need human review "
        f"({resolved}/{total} = {100 * resolved / total:.1f}% resolved).",
        "",
        "## Config-inapplicable (kmax: file not compiled in, at either the "
        "introducing or fixing commit)",
        "",
    ]
    if inapplicable:
        lines += ["| cve | reason |", "|---|---|"]
        lines += [f"| {c['cve']} | {c['reason']} |" for c in inapplicable]
    else:
        lines.append("(none)")
    lines += ["", "## Fixed-version candidates (commit ancestry)", ""]
    if fixed:
        lines += ["| cve | reason |", "|---|---|"]
        lines += [f"| {f['cve']} | {f['reason']} |" for f in fixed]
    else:
        lines.append("(none)")
    lines += ["", "## Ignored (CIP's own ignore list)", ""]
    if mismatch:
        lines += ["| cve | reason |", "|---|---|"]
        lines += [f"| {m['cve']} | {m['reason']} |" for m in mismatch]
    else:
        lines.append("(none)")
    lines += ["", "## Needs human review", ""]
    if review:
        lines += ["| cve | reason |", "|---|---|"]
        lines += [f"| {r['cve']} | {r['reason']} |" for r in review]
    else:
        lines.append("(none)")
    Path(f"{out_prefix}.md").write_text("\n".join(lines) + "\n")


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    cip_report_path = sys.argv[1]
    package = sys.argv[2] if len(sys.argv) > 2 else "linux-yocto"
    out_prefix = sys.argv[3] if len(sys.argv) > 3 else "triage-kernel-cip"
    our_ref = sys.argv[4] if len(sys.argv) > 4 else "unknown"

    total, buckets = triage(cip_report_path)
    write_report(out_prefix, package, our_ref, total, buckets)
    resolved = sum(len(buckets[b]) for b in
                   ("config_inapplicable_candidates", "fixed_version_candidates", "cpe_mismatch_candidates"))
    print(f"{total} scanned -- {len(buckets['config_inapplicable_candidates'])} config-inapplicable, "
          f"{len(buckets['fixed_version_candidates'])} fixed-version, "
          f"{len(buckets['cpe_mismatch_candidates'])} ignored, "
          f"{len(buckets['needs_human_review'])} still need human review "
          f"({resolved}/{total} = {100 * resolved / total:.1f}% resolved) -> {out_prefix}.json/.md")


if __name__ == "__main__":
    main()
