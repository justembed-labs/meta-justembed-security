# Detect

Lightweight embedded detection and security telemetry -- not full
EDR. This document describes only what `meta-je-detection`'s actual
code does, checked directly against `je-detection-agent` and
`je-rule-bundle`'s recipes and scripts.

## Architecture

```text
Linux event (auditd)
        |
        v
je-detection-agent (polls ausearch per rule, every 5s)
        |
        v
OCSF Security Finding (class_uid 2001), JSON line
        |
        v
Fluent Bit (tails events.jsonl)
        |
        v
external collector / SIEM (adopter-configured; Splunk HEC-style out of the box)
```

## Event flow, exactly as implemented

1. **Detection logic is auditd, not a custom kernel module or eBPF
   probe.** `je-rule-bundle` ships one auditd rule per CVE
   (`/etc/audit/rules.d/<CVE>.rules`) plus one JSON descriptor
   (`/etc/je-detection/rules.d/<CVE>.json`) keyed by the same
   `audit_key`. Works on any target with `CONFIG_AUDIT=y` +
   `CONFIG_AUDITSYSCALL=y` -- no Falco/eBPF dependency today (a stated
   future upgrade path for kernels with `CONFIG_BPF_SYSCALL`/BTF, not
   implemented).
2. **`je-detection-agent`** (Python 3, stdlib only) loads every
   `*.json` descriptor from `/etc/je-detection/rules.d`, then, every 5
   seconds, runs `ausearch -k <key> -if /var/log/audit/audit.log
   --format raw --checkpoint <checkpoint-file>` per rule. `-if` is
   required explicitly -- confirmed on real hardware that `ausearch
   -k` alone silently finds nothing even with a correct
   `auditd.conf`.
3. Each new raw audit line becomes one OCSF **Security Finding**
   (`class_uid` 2001) JSON object, appended to
   `/var/log/je-detection/events.jsonl`. See "OCSF fields" below for
   the exact shape.
4. **Fluent Bit** (`meta-oe`'s `fluentbit` recipe, binary
   `/usr/bin/td-agent-bit`) tails that file and forwards it via its
   `splunk` output plugin (`sourcetype=ocsf:2001`) to a host/port/token
   read from `/etc/je-detection/splunk-hec.env` at service start --
   never baked into the image.
5. **Checkpoint self-heal.** If `ausearch`'s own checkpoint file comes
   back malformed (observed on real hardware: right after boot, before
   enough of the audit log exists yet), the agent deletes it and
   retries once rather than staying silently wedged on every
   subsequent poll.

## Supported capabilities

- One auditd rule + OCSF descriptor per CVE, loaded from a directory
  (any number of rules, not hardcoded to one).
- OCSF `class_uid` 2001 (Security Finding) output with real structured
  fields: `vulnerabilities[].cve.uid`, `attacks[].technique.{uid,name}`
  (MITRE ATT&CK), `observables`, `device`, `metadata.product`.
- Independent rule-bundle delivery over swupdate's `rawfile` handler,
  no reboot -- see `docs/update-boot.md`.
- Self-healing against one specific, observed `ausearch` checkpoint
  failure mode.

## Unsupported / not implemented

- **No Falco/eBPF backend.** auditd only, today.
- **No built-in transport encryption/auth beyond what Fluent Bit's
  `splunk` output plugin itself provides** (TLS to the configured
  host, HEC token) -- this project does not add its own.
- **No buffering/backpressure control beyond what Fluent Bit's own
  `tail` input already does** (its own DB-tracked offset file) -- see
  `docs/evidence/detection-resource-behaviour.md` for what was
  actually measured here.
- **No automatic CVE-to-rule generation.** Every rule in
  `je-rule-bundle` is hand-authored; the top-level README's flow
  diagram implying `meta-je-sbom-cve`'s prioritized output
  automatically seeds new rules is aspirational, not implemented (see
  `docs/architecture.md`, "Cross-layer dependencies").
- **No rule staging/canary activation.** A rule-bundle update applies
  and reloads immediately on `postinst` (see
  `docs/evidence/signed-rule-update.md`) -- there is no
  staged-then-confirmed activation step.
- **One real syscall event can produce multiple OCSF events.**
  `ausearch --format raw` returns several related lines per syscall
  occurrence (`SYSCALL`, `CWD`, `PATH`, a continuation-fields line,
  `PROCTITLE`), and the agent's poll loop turns each line into its own
  OCSF record independently -- confirmed on real test hardware
  (QEMU): one trigger produced 6 events with distinct `finding.uid`
  but identical CVE/title/description. This is a genuine data-quality
  characteristic of the current implementation, not deduplicated
  anywhere in the pipeline today. See
  `docs/evidence/detection-event.md`.

## Failure / resource considerations

- **Collector unreachable:** Fluent Bit's own retry/buffering behavior
  applies (this project adds no additional queue) -- events keep
  accumulating in `events.jsonl` on disk regardless, since the agent
  writes to that file independently of whether Fluent Bit can ship
  it.
- **`events.jsonl` growth is not bounded by this project.** No log
  rotation, size cap, or disk-usage guard is implemented in
  `je-detection-agent` or its packaging today -- a real, current gap,
  not hidden. See `docs/evidence/detection-resource-behaviour.md`.
- **Poll interval is fixed at 5 seconds**, not configurable via a
  build-time variable today (a code constant, `POLL_SECONDS`).

## Current maturity

Per `PROJECT.md`'s maturity model: **Demonstrated** on real hardware
against one real, disclosed CVE (CVE-2026-73283) end to end (audit
rule fires -> OCSF event -> Fluent Bit -> indexed and searchable
downstream). **Demonstrated** again on QEMU in this evidence pass,
triggering the same underlying audit mechanism directly rather than
the full SSH exploit chain -- see
`docs/evidence/detection-event.md`. Not yet **Tested** in this
project's own maturity-model sense (repeated runs, negative cases,
reproducible resource data) beyond what's captured in
`docs/evidence/`.
