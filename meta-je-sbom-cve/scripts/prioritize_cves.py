#!/usr/bin/env python3
"""Chain kernel_cve_triage.py's noise reduction into kev_epss_enrich.py,
so real-world-exploitation triage runs against a noise-reduced CVE
list, not the raw cve-check firehose.

Without this: kev_epss_enrich.py cross-references CISA KEV/EPSS against
*every* "unpatched" CVE, including ones kernel_cve_triage.py already
knows are noise. On the real AM335x scan, this is exactly how
CVE-2023-3079 ended up reported as a confirmed-actively-exploited
(KEV) hit -- it's a Chrome/V8 CVE mismatched onto the linux_kernel CPE
(kernel_cve_triage.py's own cpe_mismatch_candidates bucket), nothing to
do with this kernel at all. Chaining the two catches that before KEV/
EPSS ever sees it.

Usage:
    prioritize_cves.py UNPATCHED_CSV TRIAGE_JSONS OUT_PREFIX
        [--kev-file FILE] [--epss-file FILE] [--offline]

UNPATCHED_CSV  parsed/unpatched.csv from parse_cve.py (all packages).
TRIAGE_JSONS   comma-separated kernel_cve_triage.py OUT_PREFIX.json
               paths -- one per package triaged (e.g. kernel, u-boot).
               Each one's config_inapplicable_candidates,
               fixed_version_candidates, and cpe_mismatch_candidates
               buckets are excluded; needs_human_review passes
               through, same as every CVE for a package nobody ran
               kernel_cve_triage.py against at all.
OUT_PREFIX     writes OUT_PREFIX.filtered.csv (the reduced input, kept
               for inspection) and hands off to kev_epss_enrich.py for
               OUT_PREFIX.json/.md -- same flags (--kev-file/
               --epss-file/--offline) passed straight through.
"""
import csv
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent


def noise_cve_ids(triage_json_paths):
    """triage_json_paths: one or more kernel_cve_triage.py report paths --
    merges their noise sets, and returns per-report summaries for the
    printed breakdown."""
    noise = set()
    reports = []
    for path in triage_json_paths:
        report = json.loads(Path(path).read_text())
        reports.append(report)
        for bucket in ("config_inapplicable_candidates", "fixed_version_candidates",
                       "cpe_mismatch_candidates"):
            for entry in report.get(bucket, []):
                noise.add(entry["cve"])
    return noise, reports


def filter_unpatched(unpatched_csv, noise, out_path):
    with open(unpatched_csv, newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        fieldnames = reader.fieldnames
    kept = [r for r in rows if r["cve"] not in noise]
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(kept)
    return len(rows), len(kept)


def main():
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    unpatched_csv, triage_jsons_arg, out_prefix = sys.argv[1:4]
    passthrough_args = sys.argv[4:]
    triage_json_paths = [p for p in triage_jsons_arg.split(",") if p]

    noise, reports = noise_cve_ids(triage_json_paths)
    filtered_csv = f"{out_prefix}.filtered.csv"
    total, kept = filter_unpatched(unpatched_csv, noise, filtered_csv)

    breakdown = "; ".join(
        f"{r.get('package', '?')}: "
        f"{len(r.get('config_inapplicable_candidates', []))} config-inapplicable, "
        f"{len(r.get('fixed_version_candidates', []))} fixed-version, "
        f"{len(r.get('cpe_mismatch_candidates', []))} cpe-mismatch"
        for r in reports
    )
    print(f"noise reduction: {total} unpatched CVEs -> {len(noise)} excluded "
          f"as noise ({breakdown}) -> {kept} remaining for KEV/EPSS triage")

    subprocess.run(
        [sys.executable, str(HERE / "kev_epss_enrich.py"),
         filtered_csv, out_prefix, *passthrough_args],
        check=True,
    )


if __name__ == "__main__":
    main()
