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
    @patch("ai_cve_escalation.config_status")
    @patch("ai_cve_escalation.find_config_symbol")
    @patch("pathlib.Path.is_file", return_value=True)
    def test_vulnerable_code_not_present_confirmed(self, mock_is_file, mock_symbol, mock_status):
        mock_symbol.return_value = "FOO"
        mock_status.return_value = "not-set"
        draft = {"justification": "vulnerable_code_not_present", "affected_files": ["drivers/foo.c"]}
        verified, evidence = reverify("/kdir", "CONFIG_FOO is not set", draft)
        self.assertEqual(verified, "vulnerable_code_not_present")
        self.assertEqual(evidence, ["drivers/foo.c"])

    @patch("pathlib.Path.is_file", return_value=False)
    def test_nonexistent_file_never_confirmed(self, mock_is_file):
        """Real bug found on the first live pilot run: the model named a
        file (security/bpf/hooks.c) that isn't real in the Linux kernel at
        all. A nonexistent path must never be accepted as evidence, even
        if it happens to look plausible."""
        draft = {"justification": "vulnerable_code_not_present", "affected_files": ["security/bpf/hooks.c"]}
        verified, evidence = reverify("/kdir", "CONFIG_FOO is not set", draft)
        self.assertIsNone(verified)
        self.assertIsNone(evidence)

    @patch("ai_cve_escalation.find_config_symbol")
    @patch("pathlib.Path.is_file", return_value=True)
    def test_no_config_symbol_found_stays_unverified(self, mock_is_file, mock_symbol):
        mock_symbol.return_value = None
        draft = {"justification": "vulnerable_code_not_present", "affected_files": ["drivers/foo.c"]}
        verified, evidence = reverify("/kdir", "CONFIG_FOO is not set", draft)
        self.assertIsNone(verified)
        self.assertIsNone(evidence)

    @patch("ai_cve_escalation.config_status")
    @patch("ai_cve_escalation.find_config_symbol")
    @patch("pathlib.Path.is_file", return_value=True)
    def test_config_symbol_set_is_not_accepted(self, mock_is_file, mock_symbol, mock_status):
        """The code IS compiled in (symbol is 'y') -- not reachable evidence."""
        mock_symbol.return_value = "FOO"
        mock_status.return_value = "y"
        draft = {"justification": "vulnerable_code_not_present", "affected_files": ["drivers/foo.c"]}
        verified, evidence = reverify("/kdir", "CONFIG_FOO=y", draft)
        self.assertIsNone(verified)

    @patch("ai_cve_escalation.config_status")
    @patch("ai_cve_escalation.find_config_symbol")
    @patch("pathlib.Path.is_file", return_value=True)
    def test_partial_evidence_rejects_whole_claim(self, mock_is_file, mock_symbol, mock_status):
        """Two files named, only one confirmed not-set -- the whole claim
        must fail, not partially succeed (OpenVEX requires complete
        evidence, not a majority of it)."""
        mock_symbol.return_value = "FOO"
        mock_status.side_effect = ["not-set", "y"]
        draft = {"justification": "vulnerable_code_not_present",
                 "affected_files": ["drivers/foo.c", "drivers/bar.c"]}
        verified, evidence = reverify("/kdir", "irrelevant", draft)
        self.assertIsNone(verified)
        self.assertIsNone(evidence)

    def test_insufficient_evidence_never_reverified(self):
        draft = {"justification": "insufficient_evidence", "affected_files": ["drivers/foo.c"]}
        verified, evidence = reverify("/kdir", "CONFIG_FOO is not set", draft)
        self.assertIsNone(verified)
        self.assertIsNone(evidence)

    def test_non_reachability_justification_never_reverified(self):
        """vulnerable_code_cannot_be_controlled_by_adversary and
        inline_mitigations_already_exist describe deployment/mitigation
        facts, not this source tree's compiled code -- nothing here can
        confirm or refute them, so they always stay with a human."""
        draft = {"justification": "inline_mitigations_already_exist", "affected_files": []}
        verified, evidence = reverify("/kdir", "irrelevant", draft)
        self.assertIsNone(verified)
        self.assertIsNone(evidence)

    def test_no_files_named_stays_unverified(self):
        draft = {"justification": "vulnerable_code_not_present", "affected_files": []}
        verified, evidence = reverify("/kdir", "CONFIG_FOO is not set", draft)
        self.assertIsNone(verified)
        self.assertIsNone(evidence)

    def test_no_kconfig_stays_unverified(self):
        draft = {"justification": "vulnerable_code_not_present", "affected_files": ["drivers/foo.c"]}
        verified, evidence = reverify("/kdir", "", draft)
        self.assertIsNone(verified)
        self.assertIsNone(evidence)


class RebucketTests(unittest.TestCase):
    def test_verified_goes_to_inapplicable(self):
        draft = {"justification_text": "x"}
        results = [{"cve": "CVE-1", "draft": draft, "verified": "vulnerable_code_not_present",
                    "evidence": ["drivers/foo.c"]}]
        inapplicable, fixed, mismatch, review = rebucket(results)
        self.assertEqual([e["cve"] for e in inapplicable], ["CVE-1"])
        self.assertEqual(fixed, [])
        self.assertEqual(review, [])

    def test_never_populates_fixed_bucket(self):
        """This stage never confirms a CVE is fixed -- that stays
        kernel_backport_check.py's job."""
        draft = {"justification_text": "x"}
        results = [{"cve": "CVE-1", "draft": draft, "verified": "vulnerable_code_not_in_execute_path",
                    "evidence": ["f.c"]}]
        _, fixed, _, _ = rebucket(results)
        self.assertEqual(fixed, [])

    def test_unverified_stays_in_review_with_draft_attached(self):
        draft = {"justification": "insufficient_evidence", "justification_text": "nothing found", "confidence": "low"}
        results = [{"cve": "CVE-1", "draft": draft, "verified": None, "evidence": None}]
        inapplicable, fixed, mismatch, review = rebucket(results)
        self.assertEqual(inapplicable, [])
        self.assertEqual(fixed, [])
        self.assertEqual(len(review), 1)
        self.assertFalse(review[0]["confirmed"])
        self.assertEqual(review[0]["ai_draft"], draft)

    def test_mismatch_bucket_always_empty(self):
        draft = {"justification_text": "x"}
        results = [{"cve": "CVE-1", "draft": draft, "verified": "vulnerable_code_not_present", "evidence": ["f.c"]}]
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
