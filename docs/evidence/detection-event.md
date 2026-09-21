## Claim

A real Linux event that matches a `je-rule-bundle` auditd rule is
captured by `auditd`, correlated into exactly one OCSF Security
Finding by `je-detection-agent`, and forwarded by Fluent Bit -- using
the **shipped, unmodified** `je-detection-fluentbit.conf` -- to a test
collector. One real trigger produces one finding, not several,
including when `ausearch` emits extra interpreted-summary lines
alongside the raw record.

## Environment

- Yocto version / branch: scarthgap (Poky)
- MACHINE: `qemuarm64`
- Target/platform: QEMU, not real hardware
- Relevant layers: `meta-je-detection` (`je-detection-agent`,
  `je-rule-bundle`), `meta-oe`'s `fluentbit` recipe
- Relevant package: `je-detection-agent` 0.1 (audit-event correlation,
  self-contained Fluent Bit parser config, bounded log rotation --
  see `docs/evidence/detection-resource-behaviour.md` for the
  stabilization work this entry supersedes)

## Setup

Normal boot with `je-detection-agent`, `auditd`, and
`je-detection-fluentbit` all running as installed -- **no manual
config patch**. `/etc/je-detection/splunk-hec.env` (copied from the
shipped `.example` template, per the documented adopter setup) points
at a local Python `http.server`-based TLS listener on the same
target, not a real external SIEM -- the shipped config's `TLS On` is
honored as-is, so the test listener speaks TLS with a throwaway
self-signed certificate (`TLS.Verify Off` accepts it, same as it
would accept any collector's cert in this dev configuration).

## Test

```
auditctl -l
exec 3</dev/net/tun; exec 3<&-
```

## Expected result

One real audit event (one `openat` syscall) becomes exactly one OCSF
event in `events.jsonl`, and that one event is forwarded intact by
the shipped Fluent Bit config.

## Actual result

**Audit rule loaded:**

```
-w /dev/net/tun -p rwa -k je-cve-2026-73283
```

**Fluent Bit, shipped config, real startup log** (no `Parsers_File`
patch applied):

```
[ info] [fluent bit] version=1.9.7, commit=, pid=307
[ info] [output:splunk:splunk.0] worker #0 started
[ info] [output:splunk:splunk.0] worker #1 started
[ info] [input:tail:tail.0] inotify_fs_add(): inode=... watch_fd=1 name=/var/log/je-detection/events.jsonl
```

no `parser 'json' is not registered` error -- the parser loads from
`/etc/je-detection/parsers.conf`, a file this package ships and owns.

**Trigger -> event count**, real measured:

```
before: 0 lines in events.jsonl
exec 3</dev/net/tun; exec 3<&-
after:  1 line in events.jsonl
```

**The one real OCSF event** (trimmed to the fields that matter here;
full raw JSON preserved in `unmapped.audit_raw`):

```json
{
  "class_uid": 2001, "activity_id": 1, "severity_id": 4,
  "finding": {"uid": "24d5a4a2-cb37-40d0-8767-e6360a31f59d", ...},
  "vulnerabilities": [{"cve": {"uid": "CVE-2026-73283"}}],
  "attacks": [{"technique": {"uid": "T1572", "name": "Protocol Tunneling"}}],
  "unmapped": {
    "audit_context": {
      "syscall": "56", "exe": "/usr/bin/busybox.nosuid",
      "pid": "202", "ppid": "1", "uid": "0", "comm": "sh",
      "cwd": "/root", "path": "/dev/net/tun", "proctitle": "-sh",
      "audit_event_id": "1790000583.510:19",
      "audit_record_types": ["SYSCALL", "UNKNOWN", "CWD", "PATH", "UNKNOWN", "PROCTITLE"]
    }
  }
}
```

Real, useful context preserved from the correlated records (syscall,
exe, pid, ppid, uid, comm, cwd, path, proctitle, the audit event ID) --
not just the first line kept and the rest discarded.

**Fluent Bit forwarding, shipped config**, real captured POST arriving
at the local test collector:

```
Authorization: Splunk test-token-not-real
Content-Type: application/json

{"time":1790000586.533421,"source":"je-detection-agent","sourcetype":"ocsf:2001",
 "event":{"class_uid":2001, ... same event as above, byte-identical ...}}
```

**Burst check** (20 triggers): `events.jsonl` grew by exactly 20 lines,
all with distinct `audit_event_id` values -- confirmed via
`len(ids) == len(set(ids)) == 20`. See
`docs/evidence/detection-resource-behaviour.md` for the full burst/
resource pass.

## Raw evidence

Console output, the OCSF event, and the forwarded POST body above are
copied directly from the real test run described.

## Previously observed issue (resolved, kept for history)

Two real bugs were found and fixed in the course of producing this
evidence:

1. **Duplicate findings.** `ausearch --format raw` returns multiple
   related lines per real audit event (`SYSCALL`, `CWD`, `PATH`,
   `PROCTITLE`, and -- a second finding from this same pass --
   occasional trailing interpreted-summary lines with no
   `audit(...)` identifier of their own). The agent previously turned
   *each line* into its own OCSF finding, so one real trigger produced
   6 duplicate findings (and a 20-trigger burst produced 120, not
   20). Fixed by correlating records on their shared
   `audit(timestamp:serial)` identifier before building a finding --
   see `je-detection-agent`'s `group_by_audit_event()` and
   `meta-je-detection/scripts/test_detection_agent.py` for the test
   coverage (complete/incomplete/malformed/interleaved/trailing-
   interpreted-line cases, all passing).
2. **Fluent Bit config not self-contained.** The shipped config
   referenced fluentbit's own default `/etc/td-agent-bit/parsers.conf`
   for its `json` parser, a file this package's own `FILES`/`RDEPENDS`
   never guaranteed the path or content of. Fixed by shipping and
   owning `je-detection-parsers.conf` directly.

This entry replaces the earlier evidence (which documented the 6x
duplication as current behavior); that finding is not current
behavior any more.

## Limitations

- QEMU-only; the hardware-verified case (real CVE-2026-73283 exploit
  chain over SSH) is separately documented, not independently
  reproducible from this repository, per `meta-je-detection/README.md`.
- The trigger here is a direct syscall against the watched path, not
  the full real-world exploit chain the rule is named for.
- Fluent Bit forwarding is proven against a local TLS listener on the
  same target, not a real SIEM/collector -- no external SIEM test was
  performed or claimed.
- Correlation is scoped to one poll's batch (see
  `group_by_audit_event()`'s own docstring for why a compound event
  splitting across two poll cycles isn't expected in practice, and
  what happens if it somehow did).

## Reproduction

Boot `qemuarm64` with `je-detection-agent`/`je-rule-bundle` installed,
confirm the rule with `auditctl -l`, copy
`splunk-hec.env.example` to `splunk-hec.env` pointed at a local test
listener, trigger as shown above, and inspect
`/var/log/je-detection/events.jsonl`. No config patch needed -- the
shipped `/etc/je-detection/fluent-bit.conf` and
`/etc/je-detection/parsers.conf` work as installed.
