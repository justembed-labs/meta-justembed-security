# Evidence

> Evidence documents describe a specific tested configuration. They
> do not imply identical assurance on other hardware, BSPs, Yocto
> releases or deployment environments.

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

- Yocto release:
- MACHINE:
- target/platform:
- relevant layer revision:
- relevant package/version:
- configuration:

# Setup

What has to exist before the test can run (build steps, artifacts,
keys) that aren't part of the test itself.

# Test

Exact steps or commands run.

# Expected result

# Actual result

# Raw evidence

Log excerpts, file hashes, JSON/OCSF examples, or a link to a
published run (e.g. the GitHub Pages evidence site linked from
`meta-je-example-bsp`). Small excerpts only -- for anything larger,
use `docs/evidence/artifacts/` and link to it, rather than pasting a
large dump into this file.

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

| Capability | Status | Environment | Evidence |
|---|---|---|---|
| SBOM generation | demonstrated | QEMU, `qemuarm64` | [`sbom-cve-enrichment.md`](sbom-cve-enrichment.md); published run also linked from [`meta-je-example-bsp`](https://github.com/justembed-labs/meta-je-example-bsp) |
| CVE scan (NVD-sourced), diff | demonstrated | QEMU, `qemuarm64` | [`sbom-cve-enrichment.md`](sbom-cve-enrichment.md) |
| CISA KEV enrichment | demonstrated | QEMU, `qemuarm64` | [`sbom-cve-enrichment.md`](sbom-cve-enrichment.md) |
| FIRST EPSS enrichment | demonstrated | QEMU, `qemuarm64` | [`sbom-cve-enrichment.md`](sbom-cve-enrichment.md) |
| CVE applicability evidence / documented disposition (one real candidate) | demonstrated | QEMU, `qemuarm64` | [`cve-applicability.md`](cve-applicability.md) |
| `je-secureboot` FIT verification (valid image) | demonstrated | QEMU, `qemuarm64` | [`fit-verification.md`](fit-verification.md) |
| `je-secureboot` FIT tamper rejection | demonstrated | QEMU, `qemuarm64` | [`fit-verification.md`](fit-verification.md) |
| `je-swupdate-fota` signed A/B update (valid) | demonstrated (QEMU); hardware-verified | QEMU, `qemuarm64`; also real hardware per `meta-je-boot-update/README.md` | [`signed-ab-update.md`](signed-ab-update.md) |
| `je-swupdate-fota` signed A/B update (tampered, rejected) | demonstrated | QEMU, `qemuarm64` | [`signed-ab-update.md`](signed-ab-update.md) |
| `je-swupdate-fota` rollback (uncommitted update reverts) | demonstrated | QEMU, `qemuarm64` | [`ab-rollback.md`](ab-rollback.md) |
| Detection event, correlated (one trigger -> one finding) | demonstrated (QEMU); hardware-verified against a real CVE | QEMU, `qemuarm64`; also real hardware per `meta-je-detection/README.md` | [`detection-event.md`](detection-event.md) |
| OCSF generation | demonstrated (structural check, see file for exact scope) | QEMU, `qemuarm64` | [`ocsf-validation.md`](ocsf-validation.md) |
| Fluent Bit forwarding with shipped config | demonstrated (local TLS test listener, not a real SIEM; no manual config patch) | QEMU, `qemuarm64` | [`detection-event.md`](detection-event.md) |
| Signed rule-bundle update (valid) | demonstrated | QEMU, `qemuarm64` | [`signed-rule-update.md`](signed-rule-update.md) |
| Signed rule-bundle update (tampered, rejected) | demonstrated | QEMU, `qemuarm64` | [`signed-rule-update.md`](signed-rule-update.md) |
| Rule-bundle update rollback/staging | **not implemented** -- documented as a gap, not tested as if it exists | n/a | [`signed-rule-update.md`](signed-rule-update.md) |
| Bounded local retention (Detect event storage) | demonstrated (rotation with configurable max size/backups; real rotation confirmed) | QEMU, `qemuarm64` | [`detection-resource-behaviour.md`](detection-resource-behaviour.md) |
| Detect resource/failure behavior | measured (idle/burst RSS+CPU, collector-unreachable behavior) | QEMU, `qemuarm64` | [`detection-resource-behaviour.md`](detection-resource-behaviour.md) |
| `meta-je-hygiene` enforced check fails a real build | hardware-verified; standalone check independently testable without hardware | real hardware + standalone script | [`meta-je-hygiene/README.md`](../../meta-je-hygiene/README.md) |
| `meta-je-detection` real CVE detection (CVE-2026-73283) | hardware-verified; not independently reproducible from this repository alone | real hardware | [`meta-je-detection/README.md`](../../meta-je-detection/README.md#verified-on-real-hardware) |
| `je-swupdate-fota`, real hardware A/B cycle | hardware-verified; not independently reproducible from this repository alone | real hardware | [`meta-je-boot-update/README.md`](../../meta-je-boot-update/README.md) |

Rows marked "hardware-verified" without a linked evidence file here
reflect a real run this project's own engineering team observed
directly, per `CONTRIBUTING.md`'s standard -- but reproducing them
independently needs the same physical target, which this project
doesn't publish access to. That's a real limitation, not a hedge;
closing it (a public real-hardware reference platform) is on the
roadmap. No status in this table is asserted without either a linked
entry or an explicit pointer to where the underlying claim is made and
by whom.
