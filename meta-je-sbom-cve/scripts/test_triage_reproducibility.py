#!/usr/bin/env python3
"""Reproducibility validation (docs/cve-triage.md rule 1): running the
same frozen inputs twice must give identical output. Mocks the actual
model call (no real API cost in CI) to isolate what this test is
actually checking -- that --response-cache makes a second run reuse the
first run's draft verbatim rather than drawing a fresh one, and that
freeze_triage_inputs.py's generation hash is stable across repeated
calls against the same inputs and changes when an input does.

Usage: python3 test_triage_reproducibility.py
"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ai_cve_escalation import draft_one
from freeze_triage_inputs import sha256_file


class ResponseCacheReproducibilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cache_dir = self.tmp.name

    @patch("ai_cve_escalation.call_model")
    def test_second_run_reuses_cached_draft_without_calling_model(self, mock_call):
        mock_call.return_value = {"verdict": "inconclusive", "justification": "first call", "confidence": "low"}

        first = draft_one("CVE-1", "summary", None, "fake-key", "model-a", "rev-1", self.cache_dir)
        self.assertEqual(mock_call.call_count, 1)

        mock_call.return_value = {"verdict": "evidence_of_impact", "justification": "should not be seen", "confidence": "high"}
        second = draft_one("CVE-1", "summary", None, "fake-key", "model-a", "rev-1", self.cache_dir)

        self.assertEqual(mock_call.call_count, 1, "second run must not re-call the model")
        self.assertEqual(first, second)

    @patch("ai_cve_escalation.call_model")
    def test_changed_prompt_revision_is_a_new_generation_not_a_cache_hit(self, mock_call):
        mock_call.return_value = {"verdict": "inconclusive", "justification": "rev-1 draft", "confidence": "low"}
        draft_one("CVE-1", "summary", None, "fake-key", "model-a", "rev-1", self.cache_dir)

        mock_call.return_value = {"verdict": "inconclusive", "justification": "rev-2 draft", "confidence": "low"}
        second = draft_one("CVE-1", "summary", None, "fake-key", "model-a", "rev-2", self.cache_dir)

        self.assertEqual(mock_call.call_count, 2, "a prompt-revision change is a new generation, per docs/cve-triage.md rule 1")
        self.assertEqual(second["justification"], "rev-2 draft")


class InputHashStabilityTests(unittest.TestCase):
    def test_same_file_same_hash(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("frozen content")
            path = f.name
        self.addCleanup(lambda: Path(path).unlink(missing_ok=True))
        self.assertEqual(sha256_file(path), sha256_file(path))

    def test_changed_content_changes_hash(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("version one")
            path = f.name
        self.addCleanup(lambda: Path(path).unlink(missing_ok=True))
        before = sha256_file(path)
        Path(path).write_text("version two")
        after = sha256_file(path)
        self.assertNotEqual(before, after)

    def test_missing_file_hashes_as_none_not_a_crash(self):
        self.assertIsNone(sha256_file("/nonexistent/path/does/not/exist"))


if __name__ == "__main__":
    unittest.main()
