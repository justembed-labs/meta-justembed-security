#!/usr/bin/env python3
"""Unit tests for kernel_backport_check.py's rebucket() -- the mapping
from real git-apply verdicts onto kernel_cve_triage.py's existing
4-bucket output shape.

Usage: python3 test_kernel_backport_check.py
"""
import unittest

from kernel_backport_check import rebucket


class RebucketTests(unittest.TestCase):
    def test_not_applicable_config_goes_to_inapplicable(self):
        results = [{"cve": "CVE-1", "commit": "abc123def456", "verdict": "not-applicable-config"}]
        inapplicable, fixed, mismatch, review = rebucket(results)
        self.assertEqual([e["cve"] for e in inapplicable], ["CVE-1"])
        self.assertEqual((fixed, mismatch, review), ([], [], []))

    def test_patched_goes_to_fixed(self):
        results = [{"cve": "CVE-1", "commit": "abc123def456", "verdict": "patched"}]
        inapplicable, fixed, mismatch, review = rebucket(results)
        self.assertEqual([e["cve"] for e in fixed], ["CVE-1"])
        self.assertIn("abc123def456"[:12], fixed[0]["subject"])

    def test_vulnerable_goes_to_review_confirmed(self):
        results = [{"cve": "CVE-1", "commit": "abc123def456", "verdict": "vulnerable"}]
        inapplicable, fixed, mismatch, review = rebucket(results)
        self.assertEqual([e["cve"] for e in review], ["CVE-1"])
        self.assertTrue(review[0]["confirmed"])
        self.assertIn("CONFIRMED", review[0]["reason"])

    def test_diverged_goes_to_review_unconfirmed(self):
        results = [{"cve": "CVE-1", "commit": "abc123def456", "verdict": "diverged"}]
        inapplicable, fixed, mismatch, review = rebucket(results)
        self.assertEqual([e["cve"] for e in review], ["CVE-1"])
        self.assertFalse(review[0]["confirmed"])
        self.assertIn("diverged", review[0]["reason"])

    def test_mismatch_bucket_always_empty(self):
        results = [{"cve": c, "commit": "x", "verdict": v} for c, v in
                   [("CVE-1", "vulnerable"), ("CVE-2", "patched"),
                    ("CVE-3", "diverged"), ("CVE-4", "not-applicable-config")]]
        _, _, mismatch, _ = rebucket(results)
        self.assertEqual(mismatch, [])

    def test_mixed_batch_lands_in_correct_buckets(self):
        results = [
            {"cve": "CVE-V", "commit": "v1", "verdict": "vulnerable"},
            {"cve": "CVE-P", "commit": "p1", "verdict": "patched"},
            {"cve": "CVE-N", "commit": "n1", "verdict": "not-applicable-config"},
            {"cve": "CVE-D", "commit": "d1", "verdict": "diverged"},
        ]
        inapplicable, fixed, mismatch, review = rebucket(results)
        self.assertEqual([e["cve"] for e in inapplicable], ["CVE-N"])
        self.assertEqual([e["cve"] for e in fixed], ["CVE-P"])
        self.assertEqual({e["cve"] for e in review}, {"CVE-V", "CVE-D"})

    def test_missing_commit_does_not_crash(self):
        results = [{"cve": "CVE-1", "commit": None, "verdict": "diverged"}]
        inapplicable, fixed, mismatch, review = rebucket(results)
        self.assertEqual([e["cve"] for e in review], ["CVE-1"])


if __name__ == "__main__":
    unittest.main()
