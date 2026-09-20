# Evidence

> Evidence documents describe a specific tested configuration and do
> not imply identical assurance on other hardware, BSPs or Yocto
> releases.

This directory holds reproducible records for claims made elsewhere in
this project's documentation. A claim without an entry here (or a
direct pointer to one in `meta-je-example-bsp`) is a claim made in
prose only -- true as far as this project knows, but not yet packaged
so an outside reader can rerun it themselves.

## Template for a new entry

```
# Claim

One sentence: what this entry proves.

# Environment

- Yocto version / branch:
- MACHINE:
- Target/platform (QEMU or real hardware, and which):
- Relevant package/layer versions:

# Setup

What has to exist before the test can run (build steps, artifacts,
keys) that aren't part of the test itself.

# Test

Exact steps or commands run.

# Expected result

# Actual result

# Raw evidence

Log excerpts, file hashes, or a link to a published run (e.g. the
GitHub Pages evidence site linked from `meta-je-example-bsp`).

# Limitations

What this does *not* prove -- a different target, a different Yocto
release, a case not exercised.

# Reproduction

Exact commands an outside reader can run themselves. If reproduction
requires hardware this project doesn't publish access to, say so
explicitly instead of implying anyone can rerun it.
```

Only add an entry for something that was actually run and observed.
If a claim in a README is not yet backed by an entry here, that's a
real gap -- track it in `ROADMAP.md`, don't backfill an evidence file
that describes what *should* happen.

## Index

| Capability | Evidence | Status |
|---|---|---|
| SBOM generation | Published run, linked from [`meta-je-example-bsp`](https://github.com/justembed-labs/meta-je-example-bsp) ("Live evidence") | demonstrated |
| CVE scan/diff, KEV/EPSS enrichment | Published run, linked from `meta-je-example-bsp` | demonstrated |
| CVE applicability decision (one real candidate) | [`cve-applicability.md`](cve-applicability.md) | demonstrated |
| `je-secureboot` FIT verification (valid image) | [`fit-verification.md`](fit-verification.md) | demonstrated (QEMU) |
| `je-secureboot` FIT tamper rejection | [`fit-verification.md`](fit-verification.md) | demonstrated (QEMU) |
| `je-swupdate-fota` signed A/B update | [`signed-ab-update.md`](signed-ab-update.md) | demonstrated (QEMU); hardware-verified per `meta-je-boot-update/README.md` |
| `je-swupdate-fota` rollback (uncommitted update reverts) | [`ab-rollback.md`](ab-rollback.md) | demonstrated (QEMU) |
| Detection event (audit -> agent -> OCSF) | [`detection-event.md`](detection-event.md) | demonstrated (QEMU); hardware-verified against a real CVE per `meta-je-detection/README.md` |
| OCSF output structure check | [`ocsf-validation.md`](ocsf-validation.md) | tested (structural, see file for exact scope) |
| Fluent Bit local forwarding | [`detection-event.md`](detection-event.md) | demonstrated (local listener, not a real SIEM -- see file) |
| Signed rule-bundle update (valid) | [`signed-rule-update.md`](signed-rule-update.md) | demonstrated (QEMU) |
| Signed rule-bundle update (tampered, rejected) | [`signed-rule-update.md`](signed-rule-update.md) | demonstrated (QEMU) |
| Rule-bundle update rollback/staging | [`signed-rule-update.md`](signed-rule-update.md) | **not implemented** -- documented as a gap, not tested as if it exists |
| Detect resource/failure behavior | [`detection-resource-behaviour.md`](detection-resource-behaviour.md) | measured (QEMU, see file for exact scope and what's *not* bounded) |
| `meta-je-hygiene` enforced check fails a real build | Documented in [`meta-je-hygiene/README.md`](../../meta-je-hygiene/README.md), also standalone-testable per that README's "Usage" section | hardware-verified; standalone check independently testable without hardware |
| `meta-je-detection` real CVE detection (CVE-2026-73283, hardware) | Documented in [`meta-je-detection/README.md`](../../meta-je-detection/README.md#verified-on-real-hardware) | hardware-verified; not independently reproducible from this repository alone |
| `je-swupdate-fota`, real hardware A/B cycle | Documented in [`meta-je-boot-update/README.md`](../../meta-je-boot-update/README.md) | hardware-verified; not independently reproducible from this repository alone |

Rows marked "hardware-verified" without a linked evidence file here
reflect a real run this project's own engineering team observed
directly, per `CONTRIBUTING.md`'s standard -- but reproducing them
independently needs the same physical target, which this project
doesn't publish access to. That's a real limitation, not a hedge;
closing it (a public real-hardware reference platform) is on the
roadmap. No status in this table is asserted without either a linked
entry or an explicit pointer to where the underlying claim is made and
by whom.
