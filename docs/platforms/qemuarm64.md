# QEMU (`qemuarm64`)

The current reference implementation. See
[`docs/platform-validation-matrix.md`](../platform-validation-matrix.md)
for how this row compares to (not-yet-started) physical platforms --
this page is the detail behind that one row.

## Platform

QEMU, `virt` machine, `cortex-a57`. No physical hardware.

## Yocto release

`scarthgap`, distro version `5.0.20` -- confirmed from a real boot's
own console banner (`Poky (Yocto Project Reference Distro) 5.0.20
qemuarm64 ttyAMA0`, see
[`meta-je-example-bsp`'s `docs/secure-boot.md`](https://github.com/justembed-labs/meta-je-example-bsp/blob/main/docs/secure-boot.md)),
not read off a changelog.

## Branch / BSP

- Reference build: [`meta-je-example-bsp`](https://github.com/justembed-labs/meta-je-example-bsp),
  `main` branch, `kas.yml`.
- Security layers: this repo (`meta-justembed-security`), `main`
  branch -- `meta-je-hygiene`, `meta-je-sbom-cve`, `meta-je-detection`,
  `meta-je-boot-update`, all four inherited by `kas.yml`.
- `meta-je-example-bsp`'s `kas.yml` tracks `meta-justembed-security`'s
  `main` **by branch name, not a pinned commit SHA** -- the exact SHA
  that produced the evidence linked below is recorded under "Relevant
  commit SHAs," but a fresh `kas build` today pulls whatever `main`
  currently is. Per this project's own rule: the same board tested
  against a different point on `main` does not automatically inherit
  this page's validation -- re-run the evidence, don't assume it still
  holds.

## MACHINE

`qemuarm64` (`meta-je-example-bsp/kas.yml`: `machine: qemuarm64`,
`distro: poky`, `target: core-image-minimal`).

## Kernel version

`linux-yocto` (`meta/recipes-kernel/linux/linux-yocto_6.6.bb`) -- the
default `scarthgap` recipe version for `qemuarm64`; `kas.yml` doesn't
override it with its own pin.

## U-Boot version

`u-boot` (`meta/recipes-bsp/u-boot/u-boot_2024.01.bb`) -- same basis:
the default `scarthgap` recipe version, not independently pinned by
this BSP.

## Relevant commit SHAs

- `meta-je-example-bsp`: `c5dc3d3b9fdbd67c5853a808cfcb16867af962d4`
  (2026-09-21, `main`).
- `meta-justembed-security`: `main` as of this writing --
  `28b272de4c5831332fe6948d9f5254b5c8c6fd7e`. Floats, see the
  branch/BSP note above for why this isn't pinned.

## Validated capabilities

### Build

A real `kas build kas.yml` produces `core-image-minimal` for
`qemuarm64` with all four layers inherited -- confirmed by every other
capability below, each of which depends on that image existing.

### Hygiene

`je-hygiene`'s `no_default_credentials` check runs and correctly
fails the build until explicitly opted out
(`JE_HYGIENE_REQUIRE_NO_DEFAULT_CREDS = "0"` in `kas.yml`, since
`core-image-minimal` ships a blank root password by default) -- the
check enforcing something real, not a no-op inherit.

### Evidence

- [SBOM/CVE/KEV/EPSS enrichment, one real run](../evidence/sbom-cve-enrichment.md)
  -- real SPDX SBOM, real NVD-sourced CVE scan, real KEV/EPSS
  enrichment, exact commands and output paths.
- [CVE applicability/disposition evidence](../evidence/cve-applicability.md)
- [Disposition-to-OpenVEX vocabulary mapping](../vulnerability-disposition-mapping.md)
- [OpenVEX round-trip attempt](../evidence/vex-roundtrip.md) (real
  attempt, real blockers documented -- not a completed round-trip)

### Detect

- [Detection event: one trigger, one OCSF finding, real Fluent Bit forwarding](../evidence/detection-event.md)
- [OCSF 1.4.0 schema validation against real captured events](../evidence/ocsf-validation.md)
- [Resource footprint, bounded storage rotation, collector failure/recovery](../evidence/detection-resource-behaviour.md)
- [Resource measurements](../evidence/detection-resource-measurements.md)
  and [methodology](../evidence/resource-measurement-methodology.md)

### Update

- **Signed Update**: [signed A/B update, both directions (valid accepted, tampered rejected)](../evidence/signed-ab-update.md),
  confirmed against real disk state.
- **Rollback**: [trial-boot rollback, both directions (committed stays, unconfirmed reverts)](../evidence/ab-rollback.md),
  confirmed against real disk state.
- Related, not the same claim: [signed detection-rule-bundle update](../evidence/signed-rule-update.md)
  (a different artifact -- a rule bundle via `swupdate`'s `rawfile`
  handler, not an OS image; no rollback/staging for this path, stated
  explicitly in that doc).

### Boot verification

- [FIT verification: real signed boot, real tamper rejection](../evidence/fit-verification.md)
- [Full console transcript, both the positive and negative case](https://github.com/justembed-labs/meta-je-example-bsp/blob/main/docs/secure-boot.md)
  -- real `Verifying Hash Integrity ... OK` on a valid image, real
  `sha256 error! ... ERROR: can't get kernel image!` on a tampered one.
- See [`docs/update-boot.md`](../update-boot.md)'s stage-by-stage trust
  table for exactly what this does and doesn't prove -- summarized in
  the [boot trust table](../platform-validation-matrix.md#boot-trust-precisely).

## Resource measurements

[Measured](../evidence/detection-resource-measurements.md), with
[methodology documented separately](../evidence/resource-measurement-methodology.md)
so the numbers are reproducible, not just asserted. These are QEMU
numbers on this host -- see "Known limitations" below before treating
them as representative of any physical target.

## Known limitations

- **QEMU is a reference implementation, not hardware assurance.** It
  proves the software/layer logic is correct and wired together
  properly; it does not prove anything about how that logic behaves
  on real silicon.
- **QEMU does not demonstrate an immutable hardware root of trust.**
  Per the boot-trust table above: Boot ROM and SPL are both `N/A` on
  this platform (QEMU has no boot-ROM concept at all), and nothing
  attests U-Boot itself before it runs. The verified FIT step is real,
  but the chain it's anchored to is not hardware-anchored. See
  `docs/update-boot.md` for the full argument.
- **QEMU resource results are not representative production-hardware
  benchmarks.** Timing, memory, and I/O characteristics on this
  development host's emulated CPU do not transfer to a physical
  target's real silicon, thermal envelope, or storage medium.
- **Platform-specific boot chains and BSP behaviour still require
  physical-platform validation.** Every physical platform in
  `docs/platform-validation-matrix.md` is `Planned` -- none of the
  capabilities demonstrated here have been re-verified on any of them.

## Not tested

- Any physical hardware boot ROM / SPL verification stage (QEMU has
  neither).
- Behavior under real power-loss/brownout conditions during an update
  (the rollback evidence above simulates an unconfirmed update via a
  controlled reboot, not an actual power interruption).
- Long-duration (multi-day+) resource/stability soak testing --
  current resource measurements are single-run snapshots, not a soak
  test.
- Any capability not listed under "Validated capabilities" above.
