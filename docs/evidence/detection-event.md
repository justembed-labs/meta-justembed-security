# Claim

A real Linux event that matches a `je-rule-bundle` auditd rule is
captured by `auditd`, turned into OCSF Security Finding JSON by
`je-detection-agent`, and forwarded by Fluent Bit to an HTTP
listener -- shown here end to end with real captured output at every
stage, including a genuine data-quality characteristic (one triggering
syscall produces multiple OCSF events, not one) found while running
this test, not glossed over.

## Environment

- Yocto version / branch: scarthgap (Poky)
- MACHINE: `qemuarm64`
- Target/platform: QEMU, not real hardware
- Relevant layers: `meta-je-detection` (`je-detection-agent`,
  `je-rule-bundle`), `meta-oe`'s `fluentbit` recipe

## Setup

Normal boot with `je-detection-agent`, `auditd`, and
`je-detection-fluentbit` all running as installed. The shipped
`je-detection-fluentbit.conf` could not be used as-is (see "A real bug
found while capturing this evidence" below) -- forwarding was proven
against a local test copy of the config with one line added, pointed
at a local Python `http.server`-based listener on the same target
(logging received POST bodies/headers), not a real external SIEM.

## Test

Confirm the rule is loaded, trigger it directly (open `/dev/net/tun`,
the watched device for `CVE-2026-73283`'s rule), then read back what
was captured at each stage.

```
auditctl -l
exec 3</dev/net/tun; exec 3<&-
```

## Expected result

One real audit record for the `openat` on `/dev/net/tun`, at least one
corresponding OCSF event appended to `events.jsonl`, and that event
forwarded intact to the configured collector.

## Actual result

**Audit rule loaded:**

```
-w /dev/net/tun -p rwa -k je-cve-2026-73283
```

**Raw audit record** (`ausearch -k je-cve-2026-73283 -if
/var/log/audit/audit.log --format raw`, real captured output):

```
type=SYSCALL msg=audit(...): arch=... syscall=openat ... key="je-cve-2026-73283"
type=PATH msg=audit(...): item=0 name="/dev/net/tun" ...
```

**OCSF events written** (`/var/log/je-detection/events.jsonl`, real
captured line, fields trimmed to the ones this test checked):

```json
{"class_uid": 2001, "category_uid": 2, "activity_id": 1, "severity_id": 4,
 "finding": {...}, "vulnerabilities": [{"cve": {"uid": "CVE-2026-73283"}}],
 "metadata": {...}}
```

**Fluent Bit forwarding**, real captured POST received by the local
test listener:

```
POST / HTTP/1.1
Authorization: Splunk <token>
Content-Type: application/json

{"time": ..., "source": "je-detection-agent", "sourcetype": "ocsf:2001",
 "event": {"class_uid": 2001, ...}}
```

confirming the exact OCSF event content above arrived intact, wrapped
in a Splunk-HEC-style envelope -- this is what `meta-je-detection`'s
own `splunk` output-plugin configuration actually produces, observed
against a local listener, not asserted from the config file alone.

## A real bug found while capturing this evidence

One real trigger (one `openat` syscall) produced **6 separate OCSF
events**, not 1. `ausearch --format raw` returns multiple related
lines per syscall event (`SYSCALL`, `CWD`, `PATH`, a continuation-fields
line, `PROCTITLE`), and `je-detection-agent`'s poll loop treats each
line independently (`for line in out.stdout.splitlines(): ...`),
turning each into its own OCSF record with a distinct `finding.uid` but
otherwise identical CVE/title/description. Confirmed by direct count:
`wc -l events.jsonl` went from a stable baseline to exactly +6 after a
single isolated trigger, repeatably. This is a genuine architectural
characteristic of the current implementation, not a one-off flake --
see `docs/detect.md`'s "Unsupported / not implemented" section and
`docs/evidence/detection-resource-behaviour.md`, where it explains a
20-trigger burst producing exactly 120 events (20 x 6).

Separately, the **shipped** `je-detection-fluentbit.conf`
(`meta-je-detection/recipes-security/je-detection-agent/files/je-detection-fluentbit.conf`)
uses `Parser json` in its `[INPUT]` block but has no `Parsers_File`
directive in `[SERVICE]`, so Fluent Bit fails immediately with
`parser 'json' is not registered`. This has never surfaced in the real
deployment because a separate, also-missing prerequisite
(`/etc/je-detection/splunk-hec.env`, shipped only as a `.example`
template by design -- no real token is ever baked into the image)
makes `je-detection-fluentbit.service` fail even earlier, at
environment-file load, masking the parser error underneath it. Adding
`Parsers_File /etc/td-agent-bit/parsers.conf` (the real vendored
`parsers.conf` already ships the needed `json` parser definition)
resolves it -- confirmed on this target with a local copy of the
config. **This is a real, currently-unfixed bug in the shipped config
file**, reported here rather than silently patched around, since
fixing it changes a file this evidence pass's scope did not otherwise
touch; see `ROADMAP.md`.

## Raw evidence

The audit record, OCSF JSON line, and HTTP POST capture above are
copied directly from a real test run.

## Limitations

- QEMU-only; the hardware-verified case (real CVE-2026-73283 exploit
  chain over SSH) is separately documented, not independently
  reproducible from this repository, per `meta-je-detection/README.md`.
- The trigger here is a direct syscall against the watched path, not
  the full real-world exploit chain the rule is named for -- it proves
  the detection *pipeline*, not that this specific exploit technique
  is what the rule was originally validated against (that validation
  is the separate hardware-verified case above).
- Fluent Bit forwarding is proven against a local HTTP listener on the
  same target, not a real SIEM/collector -- no external SIEM test was
  performed or claimed.
- The 6-events-per-trigger characteristic and the `Parsers_File` bug
  are both real findings from this test pass, not yet fixed in the
  actual shipped recipes as of this evidence entry.

## Reproduction

Boot `qemuarm64` with `je-detection-agent`/`je-rule-bundle` installed,
confirm the rule with `auditctl -l`, trigger it as shown above, and
inspect `/var/log/je-detection/events.jsonl`. Fluent Bit forwarding
needs the `Parsers_File` fix noted above (or the config left broken, to
reproduce the masked-failure finding itself) and a listener of some
kind at the configured `splunk-hec.env` endpoint.
