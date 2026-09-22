#!/usr/bin/env python3
"""Unit tests for kernel_cve_upstream_triage.py's re-bucketing logic --
the mapping from improve_kernel_cve_report.py's (status, detail) pairs
onto kernel_cve_triage.py's existing 4-bucket output shape, and the
compatibility shim for cve-check output missing the "detail" field.

Usage: python3 test_kernel_cve_upstream_triage.py
"""
import unittest

from kernel_cve_upstream_triage import _normalize_missing_detail, _suggested_status, rebucket


def issue(id_, status, detail, description=""):
    return {"id": id_, "status": status, "detail": detail, "description": description}


class NormalizeMissingDetailTests(unittest.TestCase):
    def test_adds_missing_detail_as_none(self):
        report = {"package": [{"name": "linux-ti-staging", "issue": [
            {"id": "CVE-1999-0061", "status": "Patched"},
        ]}]}
        out = _normalize_missing_detail(report)
        self.assertIsNone(out["package"][0]["issue"][0]["detail"])

    def test_leaves_existing_detail_untouched(self):
        report = {"package": [{"name": "linux-ti-staging", "issue": [
            {"id": "CVE-2025-1", "status": "Unpatched", "detail": "version-in-range"},
        ]}]}
        out = _normalize_missing_detail(report)
        self.assertEqual(out["package"][0]["issue"][0]["detail"], "version-in-range")


class SuggestedStatusTests(unittest.TestCase):
    def test_no_double_prefix_when_description_already_has_it(self):
        s = _suggested_status("CVE-2022-4994", "fixed-version",
                               "fixed-version: Fixed from version 6.0")
        self.assertEqual(
            s, 'CVE_STATUS[CVE-2022-4994] = "fixed-version: Fixed from version 6.0"')

    def test_adds_prefix_when_description_lacks_it(self):
        s = _suggested_status("CVE-2022-1", "cpe-stable-backport", "Backported in 6.3")
        self.assertEqual(
            s, 'CVE_STATUS[CVE-2022-1] = "cpe-stable-backport: Backported in 6.3"')


class RebucketTests(unittest.TestCase):
    def _report(self, issues):
        return {"package": [{"name": "linux-ti-staging", "version": "6.12.57+git",
                              "issue": issues}]}

    def test_not_applicable_config_goes_to_inapplicable(self):
        report = self._report([
            issue("CVE-1", "Ignored", "not-applicable-config", "Source code not compiled."),
        ])
        inapplicable, fixed, mismatch, review = rebucket(report, "linux-ti-staging")
        self.assertEqual([e["cve"] for e in inapplicable], ["CVE-1"])
        self.assertEqual(fixed, [])
        self.assertEqual(mismatch, [])
        self.assertEqual(review, [])

    def test_fixed_version_and_cpe_stable_backport_both_go_to_fixed(self):
        report = self._report([
            issue("CVE-1", "Patched", "fixed-version", "fixed-version: Fixed from version 6.0"),
            issue("CVE-2", "Patched", "cpe-stable-backport", "Backported in 6.3"),
        ])
        inapplicable, fixed, mismatch, review = rebucket(report, "linux-ti-staging")
        self.assertEqual({e["cve"] for e in fixed}, {"CVE-1", "CVE-2"})

    def test_version_not_in_range_goes_to_cpe_mismatch(self):
        report = self._report([
            issue("CVE-1", "Patched", "version-not-in-range", "No CPE match"),
        ])
        inapplicable, fixed, mismatch, review = rebucket(report, "linux-ti-staging")
        self.assertEqual([e["cve"] for e in mismatch], ["CVE-1"])

    def test_version_in_range_and_missing_detail_go_to_review(self):
        report = self._report([
            issue("CVE-1", "Unpatched", "version-in-range", "needs backporting"),
            issue("CVE-2", "Unpatched", None, ""),
        ])
        inapplicable, fixed, mismatch, review = rebucket(report, "linux-ti-staging")
        self.assertEqual({e["cve"] for e in review}, {"CVE-1", "CVE-2"})

    def test_cna_rejected_excluded_from_every_bucket(self):
        report = self._report([
            issue("CVE-1", "Ignored", "rejected", "Rejected by CNA"),
        ])
        inapplicable, fixed, mismatch, review = rebucket(report, "linux-ti-staging")
        self.assertEqual((inapplicable, fixed, mismatch, review), ([], [], [], []))

    def test_ignores_other_packages(self):
        report = {"package": [
            {"name": "u-boot-ti-staging", "issue": [
                issue("CVE-1", "Unpatched", "version-in-range", "x"),
            ]},
        ]}
        inapplicable, fixed, mismatch, review = rebucket(report, "linux-ti-staging")
        self.assertEqual((inapplicable, fixed, mismatch, review), ([], [], [], []))

    def test_entries_carry_source_and_detail_for_transparency(self):
        report = self._report([
            issue("CVE-1", "Unpatched", "version-in-range", "needs backporting"),
        ])
        _, _, _, review = rebucket(report, "linux-ti-staging")
        self.assertEqual(review[0]["source"], "upstream")
        self.assertEqual(review[0]["detail"], "version-in-range")


if __name__ == "__main__":
    unittest.main()
