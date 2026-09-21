#!/usr/bin/env python3
"""Unit tests for je-detection-agent's audit-event correlation --
grouping raw ausearch lines by their shared audit(timestamp:serial)
identifier before building one OCSF finding per real event, instead of
one finding per raw line (the bug this replaces: one openat() produced
6 duplicate findings from 6 related lines).

Loads the deployed script directly via importlib (it ships extension-
less as a single bindir file, not a package) -- no production code
changes needed to make this testable, and no new runtime dependency.

Usage: python3 test_detection_agent.py
"""
import importlib.util
import os
import sys
import unittest
from importlib.machinery import SourceFileLoader

AGENT_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "recipes-security", "je-detection-agent", "files", "je-detection-agent",
)

# Extension-less file (ships as a plain bindir script) -- an explicit
# SourceFileLoader is needed since spec_from_file_location can't infer
# a loader for a path with no recognized suffix.
loader = SourceFileLoader("je_detection_agent", AGENT_PATH)
spec = importlib.util.spec_from_loader("je_detection_agent", loader)
agent = importlib.util.module_from_spec(spec)
loader.exec_module(agent)

RULE = {
    "cve": "CVE-2026-73283",
    "audit_key": "je-cve-2026-73283",
    "title": "OpenSSH restrict bypass: tunnel forwarding via CVE-2026-73283",
    "desc": "test rule",
    "severity_id": 4,
    "observables": [{"name": "file.path", "type": "File Name", "value": "/dev/net/tun"}],
}


def compound_event_lines(ts="1789935915.360", serial="4"):
    return [
        f'type=SYSCALL msg=audit({ts}:{serial}): arch=c00000b7 syscall=56 success=yes '
        f'exit=3 items=1 ppid=123 pid=456 auid=0 uid=0 gid=0 comm="sh" '
        f'exe="/bin/busybox" key="je-cve-2026-73283"',
        f'type=CWD msg=audit({ts}:{serial}): cwd="/root"',
        f'type=PATH msg=audit({ts}:{serial}): item=0 name="/dev/net/tun" inode=123 '
        f'dev=00:05 mode=020666 ouid=0 ogid=0 rdev=0a:00 nametype=NORMAL',
        # "cat\0/dev/net/tun" hex-encoded
        f'type=PROCTITLE msg=audit({ts}:{serial}): proctitle=636174002F6465762F6E65742F74756E',
    ]


class TestAuditEventGrouping(unittest.TestCase):
    def test_complete_compound_event_yields_one_group(self):
        lines = compound_event_lines()
        groups = agent.group_by_audit_event(lines)
        self.assertEqual(len(groups), 1)
        audit_id, group_lines = groups[0]
        self.assertEqual(audit_id, "1789935915.360:4")
        self.assertEqual(len(group_lines), 4)

    def test_complete_compound_event_yields_one_finding(self):
        lines = compound_event_lines()
        groups = agent.group_by_audit_event(lines)
        events = [agent.build_event(RULE, audit_id, grp) for audit_id, grp in groups]
        self.assertEqual(len(events), 1)

    def test_two_independent_events_yield_two_findings(self):
        lines = compound_event_lines(serial="4") + compound_event_lines(serial="5")
        groups = agent.group_by_audit_event(lines)
        self.assertEqual(len(groups), 2)
        events = [agent.build_event(RULE, audit_id, grp) for audit_id, grp in groups]
        self.assertEqual(len(events), 2)
        self.assertNotEqual(events[0]["finding"]["uid"], events[1]["finding"]["uid"])

    def test_interleaved_records_from_two_events_still_separate_correctly(self):
        # out-of-order tolerance: SYSCALL(4), SYSCALL(5), PATH(4), PATH(5)
        a = compound_event_lines(serial="4")
        b = compound_event_lines(serial="5")
        interleaved = [a[0], b[0], a[2], b[2], a[1], b[1], a[3], b[3]]
        groups = agent.group_by_audit_event(interleaved)
        self.assertEqual(len(groups), 2)
        ids = {g[0] for g in groups}
        self.assertEqual(ids, {"1789935915.360:4", "1789935915.360:5"})

    def test_incomplete_event_still_produces_one_bounded_finding(self):
        # Only SYSCALL present (PATH/CWD/PROCTITLE never arrived) --
        # must not hang or wait; finalizes immediately with partial
        # context.
        lines = [compound_event_lines()[0]]
        groups = agent.group_by_audit_event(lines)
        self.assertEqual(len(groups), 1)
        events = [agent.build_event(RULE, audit_id, grp) for audit_id, grp in groups]
        self.assertEqual(len(events), 1)
        ctx = events[0]["unmapped"]["audit_context"]
        self.assertEqual(ctx["audit_record_types"], ["SYSCALL"])
        self.assertNotIn("path", ctx)  # PATH line never arrived

    def test_trailing_interpreted_line_attaches_to_prior_event_not_a_new_one(self):
        # Real observed behaviour: `ausearch --format raw` can still
        # emit trailing interpreted-summary lines with no audit(...) id
        # of their own, right after a real event's raw block. These
        # must not become phantom extra findings.
        lines = compound_event_lines() + [
            'ARCH=aarch64 SYSCALL=openat AUID="unset" UID="root" GID="root"',
            'OUID="root" OGID="root"',
        ]
        groups = agent.group_by_audit_event(lines)
        self.assertEqual(len(groups), 1)
        audit_id, group_lines = groups[0]
        self.assertEqual(audit_id, "1789935915.360:4")
        self.assertEqual(len(group_lines), 6)
        events = [agent.build_event(RULE, aid, grp) for aid, grp in groups]
        self.assertEqual(len(events), 1)

    def test_malformed_line_gets_safe_fallback_group_not_a_crash(self):
        lines = ["this is not a real audit line at all", "neither=is this=one really"]
        groups = agent.group_by_audit_event(lines)
        # each malformed line with no audit(...) id gets its own group
        self.assertEqual(len(groups), 2)
        events = [agent.build_event(RULE, audit_id, grp) for audit_id, grp in groups]
        self.assertEqual(len(events), 2)  # no exception raised

    def test_context_preserves_real_fields_not_just_syscall(self):
        lines = compound_event_lines()
        groups = agent.group_by_audit_event(lines)
        event = agent.build_event(RULE, *groups[0])
        ctx = event["unmapped"]["audit_context"]
        self.assertEqual(ctx["syscall"], "56")
        self.assertEqual(ctx["pid"], "456")
        self.assertEqual(ctx["ppid"], "123")
        self.assertEqual(ctx["uid"], "0")
        self.assertEqual(ctx["comm"], "sh")
        self.assertEqual(ctx["exe"], "/bin/busybox")
        self.assertEqual(ctx["cwd"], "/root")
        self.assertEqual(ctx["path"], "/dev/net/tun")
        self.assertEqual(ctx["proctitle"], "cat /dev/net/tun")
        self.assertEqual(ctx["audit_event_id"], "1789935915.360:4")

    def test_burst_of_20_triggers_yields_20_findings_not_120(self):
        lines = []
        for serial in range(1, 21):
            lines.extend(compound_event_lines(serial=str(serial)))
        groups = agent.group_by_audit_event(lines)
        self.assertEqual(len(groups), 20)
        events = [agent.build_event(RULE, audit_id, grp) for audit_id, grp in groups]
        self.assertEqual(len(events), 20)

    def test_decode_proctitle_handles_invalid_hex_safely(self):
        # must not raise on malformed input
        result = agent.decode_proctitle("not-valid-hex!!")
        self.assertEqual(result, "not-valid-hex!!")


if __name__ == "__main__":
    unittest.main()
