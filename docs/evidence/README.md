# Evidence

This directory holds reproducible records for claims made elsewhere in
this project's documentation. A claim without an entry here (or a
direct pointer to one in `meta-je-example-bsp`) is a claim made in
prose only -- true as far as this project knows, but not yet packaged
so an outside reader can rerun it themselves.

## Template for a new entry

```
## Claim

One sentence: what this entry proves.

## Environment

- Yocto version / branch:
- MACHINE:
- Target/platform (QEMU or real hardware, and which):
- Relevant package/layer versions:

## Test

Exact steps or commands run.

## Expected result

## Actual result

## Evidence

Log excerpts, file hashes, screenshots, or a link to a published run
(e.g. the GitHub Pages evidence site linked from `meta-je-example-bsp`).

## Limitations

What this does *not* prove -- a different target, a different Yocto
release, a case not exercised.

## Reproduction

Exact commands an outside reader can run themselves. If reproduction
requires hardware this project doesn't publish access to, say so
explicitly instead of implying anyone can rerun it.
```

Only add an entry for something that was actually run and observed.
If a claim in a README is not yet backed by an entry here, that's a
real gap -- track it in `ROADMAP.md`, don't backfill an evidence file
that describes what *should* happen.

## Index

| Claim | Status | Entry |
|---|---|---|
| `je-secureboot` FIT signature verification (accept signed, reject tampered) | Reproducible on QEMU, entry below | [`je-secureboot-fit-verification.md`](je-secureboot-fit-verification.md) |
| `je-swupdate-fota` signed A/B update cycle (commit and rollback) | Reproducible on QEMU, entry below | [`je-swupdate-fota-ab-cycle.md`](je-swupdate-fota-ab-cycle.md) |
| SBOM generation, CVE scan/diff, KEV/EPSS enrichment | Reproducible on QEMU | Real run output published via GitHub Pages, linked from [`meta-je-example-bsp`](https://github.com/justembed-labs/meta-je-example-bsp)'s README ("Live evidence") |
| `meta-je-detection` real CVE detection (CVE-2026-73283, OCSF event, Fluent Bit forward) | Asserted, hardware-verified | Documented in [`meta-je-detection/README.md`](../../meta-je-detection/README.md#verified-on-real-hardware); requires physical target hardware to reproduce independently, not reproducible from this repository alone |
| `je-swupdate-fota` signed A/B update, real hardware (both directions, real reboot) | Asserted, hardware-verified | Documented in [`meta-je-boot-update/README.md`](../../meta-je-boot-update/README.md); requires physical target hardware to reproduce independently |
| `meta-je-hygiene` enforced check fails a real build | Asserted, hardware-verified | Documented in [`meta-je-hygiene/README.md`](../../meta-je-hygiene/README.md); also directly testable standalone against a synthetic rootfs per that README's "Usage" section, without hardware |

Rows marked "Asserted, hardware-verified" reflect a real run this
project's own engineering team observed directly, per
`CONTRIBUTING.md`'s standard -- but reproducing them independently
needs access to the same physical target, which this project doesn't
publish. That's a real limitation, not a hedge; closing it (a public
real-hardware reference platform) is on the roadmap.
