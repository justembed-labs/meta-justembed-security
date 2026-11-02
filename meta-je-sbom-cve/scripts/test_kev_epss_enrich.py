#!/usr/bin/env python3
"""Unit tests for kev_epss_enrich.py's priority_score() -- Honda OSS
Summit EU 2026's weighting (EPSS 40%, CVSS 35%, KEV 25%), adopted as
hardcoded policy (see docs/cve-triage.md).

Usage: python3 test_kev_epss_enrich.py
"""
import unittest

from kev_epss_enrich import priority_score


class PriorityScoreTests(unittest.TestCase):
    def test_all_signals_present_maxes_at_100(self):
        self.assertEqual(priority_score(10.0, 1.0, True), 100.0)

    def test_no_signals_is_zero(self):
        self.assertEqual(priority_score(None, None, False), 0.0)

    def test_kev_alone_is_25_percent(self):
        self.assertEqual(priority_score(None, None, True), 25.0)

    def test_cvss_alone_scales_by_35_percent(self):
        self.assertEqual(priority_score(9.8, None, False), round(100 * 0.35 * 0.98, 1))

    def test_epss_alone_scales_by_40_percent(self):
        self.assertEqual(priority_score(None, 0.5, False), 20.0)

    def test_missing_signal_does_not_skew_the_others(self):
        """A CVE with only a CVSS score shouldn't outrank one with real
        KEV + EPSS signal just because its one known signal is maxed."""
        cvss_only = priority_score(10.0, None, False)
        kev_and_epss = priority_score(None, 0.9, True)
        self.assertLess(cvss_only, kev_and_epss)


if __name__ == "__main__":
    unittest.main()
