#!/usr/bin/env python3
"""Unit tests for ai_cve_escalation.py -- the parts that don't need a
real model call or a real kernel checkout: re-verification dispatch and
bucketing. The model never resolves anything on its own, so what matters
here is that a verified claim lands in the right bucket and an
unverified one never does.

Usage: python3 test_ai_cve_escalation.py
"""
import unittest
from unittest.mock import patch

from ai_cve_escalation import reverify, rebucket, cache_key


class ReverifyTests(unittest.TestCase):
    @patch("ai_cve_escalation.verify_one")
    def test_cited_commit_confirmed_patched(self, mock_verify):
        mock_verify.return_value = ("patched", "deadbeef")
        verified, evidence = reverify("/kdir", "ref", "", None,
                                       {"verdict": "evidence_of_impact", "cited_commit": "deadbeef"})
        self.assertEqual(verified, "patched")
        self.assertEqual(evidence, "deadbeef")

    @patch("ai_cve_escalation.verify_one")
    def test_cited_commit_diverged_is_not_accepted(self, mock_verify):
        """'diverged'/'vulnerable' verdicts must never be silently
        accepted as resolved -- only patched/not-applicable-config do."""
        mock_verify.return_value = ("diverged", "deadbeef")
        verified, evidence = reverify("/kdir", "ref", "", None,
                                       {"verdict": "evidence_of_impact", "cited_commit": "deadbeef"})
        self.assertIsNone(verified)

    @patch("ai_cve_escalation.config_status")
    @patch("ai_cve_escalation.find_config_symbol")
    def test_cited_file_not_compiled(self, mock_symbol, mock_status):
        mock_symbol.return_value = "FOO"
        mock_status.return_value = "not-set"
        verified, evidence = reverify("/kdir", "ref", "CONFIG_FOO is not set", None,
                                       {"verdict": "evidence_against_impact", "cited_file": "drivers/foo.c"})
        self.assertEqual(verified, "not-applicable-config")
        self.assertEqual(evidence, "drivers/foo.c")

    def test_no_evidence_cited_stays_unverified(self):
        verified, evidence = reverify("/kdir", "ref", "", None,
                                       {"verdict": "inconclusive", "justification": "no idea"})
        self.assertIsNone(verified)
        self.assertIsNone(evidence)

    @patch("ai_cve_escalation.config_status")
    @patch("ai_cve_escalation.find_config_symbol")
    def test_inconclusive_verdict_never_reverified_even_with_cited_file(self, mock_symbol, mock_status):
        """Real bug found on the first live pilot run (CVE-2024-47703):
        the model said verdict=inconclusive but named a file in its
        justification narrative as a hypothetical example, not as
        asserted evidence. reverify() must not treat that name as a
        citation just because the field is non-empty -- an inconclusive
        verdict stays unverified regardless of what text happens to be
        in cited_file/cited_commit."""
        mock_symbol.return_value = "FOO"
        mock_status.return_value = "not-set"
        verified, evidence = reverify("/kdir", "ref", "CONFIG_FOO is not set", None,
                                       {"verdict": "inconclusive", "cited_file": "security/bpf/hooks.c",
                                        "justification": "not confident, just speculating"})
        self.assertIsNone(verified)
        self.assertIsNone(evidence)
        mock_symbol.assert_not_called()


class RebucketTests(unittest.TestCase):
    def test_verified_patched_goes_to_fixed(self):
        results = [{"cve": "CVE-1", "draft": {"justification": "x"}, "verified": "patched", "evidence": "deadbeef"}]
        inapplicable, fixed, mismatch, review = rebucket(results)
        self.assertEqual([e["cve"] for e in fixed], ["CVE-1"])
        self.assertEqual(inapplicable, [])
        self.assertEqual(review, [])

    def test_verified_not_applicable_goes_to_inapplicable(self):
        results = [{"cve": "CVE-1", "draft": {"justification": "x"}, "verified": "not-applicable-config", "evidence": "f.c"}]
        inapplicable, fixed, mismatch, review = rebucket(results)
        self.assertEqual([e["cve"] for e in inapplicable], ["CVE-1"])

    def test_unverified_stays_in_review_with_draft_attached(self):
        draft = {"verdict": "inconclusive", "justification": "nothing found", "confidence": "low"}
        results = [{"cve": "CVE-1", "draft": draft, "verified": None, "evidence": None}]
        inapplicable, fixed, mismatch, review = rebucket(results)
        self.assertEqual(inapplicable, [])
        self.assertEqual(fixed, [])
        self.assertEqual(len(review), 1)
        self.assertFalse(review[0]["confirmed"])
        self.assertEqual(review[0]["ai_draft"], draft)

    def test_mismatch_bucket_always_empty(self):
        results = [{"cve": "CVE-1", "draft": {"justification": "x"}, "verified": "patched", "evidence": "c"}]
        _, _, mismatch, _ = rebucket(results)
        self.assertEqual(mismatch, [])


class CacheKeyTests(unittest.TestCase):
    def test_deterministic_for_same_inputs(self):
        self.assertEqual(cache_key("CVE-1", "model-a", "rev-1"), cache_key("CVE-1", "model-a", "rev-1"))

    def test_changes_with_prompt_revision(self):
        """A changed prompt is a new generation -- see freeze_triage_inputs.py."""
        self.assertNotEqual(cache_key("CVE-1", "model-a", "rev-1"), cache_key("CVE-1", "model-a", "rev-2"))

    def test_changes_with_model(self):
        self.assertNotEqual(cache_key("CVE-1", "model-a", "rev-1"), cache_key("CVE-1", "model-b", "rev-1"))


if __name__ == "__main__":
    unittest.main()
