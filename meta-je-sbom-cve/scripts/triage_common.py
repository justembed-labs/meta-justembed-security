#!/usr/bin/env python3
"""Shared remainder computation for chained triage stages.

Extracted from prioritize_cves.py so a new stage (e.g. ai_cve_escalation.py)
can ask "what does every enabled stage so far still consider unresolved"
without re-deriving the union/dedup logic -- getting this wrong once already
silently dropped CVEs in the Pages viewer (see docs/cve-triage.md).
"""
import csv
import json
from pathlib import Path

RESOLVED_BUCKETS = ("config_inapplicable_candidates", "fixed_version_candidates",
                     "cpe_mismatch_candidates")


def noise_cve_ids(triage_json_paths):
    """triage_json_paths: one or more triage-stage report paths (same
    4-bucket shape). Returns (noise_set, reports) -- the union of every
    CVE ID any report resolved, plus the parsed reports themselves (for
    printed breakdowns)."""
    noise = set()
    reports = []
    for path in triage_json_paths:
        report = json.loads(Path(path).read_text())
        reports.append(report)
        for bucket in RESOLVED_BUCKETS:
            for entry in report.get(bucket, []):
                noise.add(entry["cve"])
    return noise, reports


def filter_unpatched(unpatched_csv, noise, out_path=None):
    """Rows from unpatched_csv whose CVE isn't in noise. Writes out_path
    (same shape as unpatched_csv) when given. Returns (total, kept_rows)."""
    with open(unpatched_csv, newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        fieldnames = reader.fieldnames
    kept = [r for r in rows if r["cve"] not in noise]
    if out_path:
        with open(out_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(kept)
    return len(rows), kept


def compute_remainder(unpatched_csv, triage_json_paths):
    """The true cumulative remainder across every given triage report --
    unpatched.csv rows whose CVE no enabled stage resolved. This is what
    a next stage (human review, or AI escalation) should actually see --
    not any single stage's own needs_human_review field, which only
    reflects what *that* stage looked at, not what every stage after it
    went on to resolve."""
    noise, reports = noise_cve_ids(triage_json_paths)
    _, kept = filter_unpatched(unpatched_csv, noise)
    return kept, reports


def latest_review_context(triage_json_paths):
    """Per-CVE context (reason, candidate_commits, etc.) from the
    needs_human_review bucket of each report, later reports in the list
    overriding earlier ones for the same CVE -- the most recent stage to
    have looked at a CVE usually has the most specific hint."""
    context = {}
    for path in triage_json_paths:
        report = json.loads(Path(path).read_text())
        for entry in report.get("needs_human_review", []):
            context[entry["cve"]] = entry
    return context
