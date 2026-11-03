#!/usr/bin/env python3
"""Unit tests for triage_common.py's remainder computation -- the
extraction that replaced prioritize_cves.py's own local copy. Regression
coverage for the exact dedup/union logic that failed once already in the
Pages viewer (see docs/cve-triage.md).

Usage: python3 test_triage_common.py
"""
import csv
import json
import tempfile
import unittest
from pathlib import Path

from triage_common import noise_cve_ids, filter_unpatched, compute_remainder, latest_review_context

UNPATCHED_FIELDS = ["cve", "package", "version", "layer", "cvss", "severity", "vector", "summary", "link"]


def write_csv(path, rows):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=UNPATCHED_FIELDS)
        w.writeheader()
        w.writerows(rows)


def write_report(path, resolved_buckets=None, review=None):
    report = {
        "config_inapplicable_candidates": [], "fixed_version_candidates": [],
        "cpe_mismatch_candidates": [], "needs_human_review": review or [],
    }
    report.update(resolved_buckets or {})
    Path(path).write_text(json.dumps(report))


class RemainderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_noise_cve_ids_unions_across_reports(self):
        r1 = self.dir / "r1.json"
        r2 = self.dir / "r2.json"
        write_report(r1, {"fixed_version_candidates": [{"cve": "CVE-1"}]})
        write_report(r2, {"config_inapplicable_candidates": [{"cve": "CVE-2"}]})
        noise, reports = noise_cve_ids([str(r1), str(r2)])
        self.assertEqual(noise, {"CVE-1", "CVE-2"})
        self.assertEqual(len(reports), 2)

    def test_filter_unpatched_excludes_noise_only(self):
        csv_path = self.dir / "unpatched.csv"
        write_csv(csv_path, [
            {"cve": "CVE-1", "package": "linux-yocto"},
            {"cve": "CVE-2", "package": "linux-yocto"},
            {"cve": "CVE-3", "package": "linux-yocto"},
        ])
        total, kept = filter_unpatched(csv_path, {"CVE-1"})
        self.assertEqual(total, 3)
        self.assertEqual({r["cve"] for r in kept}, {"CVE-2", "CVE-3"})

    def test_compute_remainder_is_true_cumulative_remainder(self):
        """The exact bug class this extraction guards against: a CVE
        resolved by stage 2 must not reappear in the remainder just
        because stage 1's own needs_human_review still lists it."""
        csv_path = self.dir / "unpatched.csv"
        write_csv(csv_path, [{"cve": f"CVE-{i}", "package": "linux-yocto"} for i in range(1, 5)])

        stage1 = self.dir / "stage1.json"
        write_report(stage1, review=[{"cve": "CVE-1"}, {"cve": "CVE-2"}, {"cve": "CVE-3"}, {"cve": "CVE-4"}])

        stage2 = self.dir / "stage2.json"
        write_report(stage2, {"fixed_version_candidates": [{"cve": "CVE-2"}, {"cve": "CVE-3"}]})

        remainder, _ = compute_remainder(csv_path, [str(stage1), str(stage2)])
        self.assertEqual({r["cve"] for r in remainder}, {"CVE-1", "CVE-4"})

    def test_latest_review_context_prefers_later_report(self):
        stage1 = self.dir / "stage1.json"
        write_report(stage1, review=[{"cve": "CVE-1", "reason": "early guess"}])
        stage2 = self.dir / "stage2.json"
        write_report(stage2, review=[{"cve": "CVE-1", "reason": "later, more specific"}])

        ctx = latest_review_context([str(stage1), str(stage2)])
        self.assertEqual(ctx["CVE-1"]["reason"], "later, more specific")


if __name__ == "__main__":
    unittest.main()
