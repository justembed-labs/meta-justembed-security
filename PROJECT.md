# Project Definition

This file is the project's own guardrail: what it is, who it's for, and
what it deliberately does not try to be. If a README claim and this file
disagree, this file wins until it's updated.

## Problem

Embedded Linux security work is usually split into disconnected
activities done by different tools, at different times, by different
people: hardening a rootfs at build time, generating an SBOM, scanning
for CVEs, watching for runtime misuse, and shipping an update. Each
piece exists in the open-source ecosystem already. What's missing on
most Yocto-built products is the connective tissue between them -- the
same CVE that shows up in a scan doesn't automatically become something
the device can detect at runtime, and a detection rule doesn't
automatically ship without waiting for the next full firmware release.
That gap between disclosure and a device actually being protected or
patched is what this project targets.

## Goal

Provide reusable, independently adoptable Yocto/OpenEmbedded layers
that a real embedded Linux product can build on, each wired to mature
upstream tooling rather than reimplementing it, each with claims backed
by something reproducible.

## Target users

- Yocto/OpenEmbedded engineers integrating security tooling into an
  existing BSP.
- Embedded Linux platform teams.
- Product security engineers responsible for an embedded/IoT product's
  vulnerability handling and update process.
- IoT device manufacturers building on Yocto.

This project does not currently target a broad OT/SIS (safety
instrumented system) audience -- see Non-goals and Roadmap themes.

## Architecture

Four independent layers, each adoptable on its own:

| Building block | Layer | Main purpose |
|---|---|---|
| Hygiene | `meta-je-hygiene` | Build-time hardening baseline, enforced at `do_rootfs` QA time. |
| Evidence | `meta-je-sbom-cve` | SBOM generation, CVE scan/diff, and evidence-based (KEV/EPSS) prioritization. |
| Detect | `meta-je-detection` | Lightweight embedded detection: turns a CVE into a runtime rule, emits standardized (OCSF) events for an existing collector/SIEM. |
| Update & Boot | `meta-je-boot-update` | Verified boot (U-Boot FIT signing) and signed atomic A/B updates (swupdate). |

Compact framing used throughout this project's docs:

`Hygiene -> Evidence -> Detect -> Update & Boot`

## Design principles

- **Composable, not monolithic.** Each layer has its own `layer.conf`
  and can be added to a BSP independently of the others.
- **Use mature upstream projects instead of reinventing them.**
  `create-spdx`, `cve-check`, `kernel-fitimage`, `uboot-sign`,
  `meta-swupdate`, Linux audit, Fluent Bit, OCSF -- wired up, not
  rebuilt.
- **No mandatory cloud/backend dependency.** Nothing here requires a
  JustEmbed-operated service to function.
- **Evidence over unsupported claims.** A capability is described as
  proven only when it was actually run and observed, not inferred from
  a successful build.
- **Preserve uncertainty in vulnerability analysis.** Automated CVE
  triage cites its evidence and hands ambiguous cases to a human
  reviewer instead of silently resolving them.
- **Integrate with existing security infrastructure.** This project
  ships events and evidence to a collector/SIEM/CI pipeline the
  adopter already runs; it does not ship its own backend.
- **Independently adoptable layers.** Adopting one layer must never
  require adopting all four.

## Scope

Embedded Linux and IoT products built with Yocto/OpenEmbedded, running
a normal Linux userspace (systemd, in the current implementation)
capable of integrating with an external collector/SIEM and an update
server the adopter already operates or chooses.

## Non-goals

- Not a CRA (EU Cyber Resilience Act) compliance product, and does not
  by itself establish regulatory compliance.
- Not a SIEM.
- Not a fleet-management backend.
- Not a plant-wide OT security system.
- Not a Safety Instrumented System (SIS) runtime security platform.
- Not a replacement for product-specific threat modeling or risk
  assessment.
- Not a certification framework (e.g. IEC 62443).

## Maturity model

Used consistently across this project's documentation:

- **Experimental** -- exists in code, not yet run end-to-end and
  observed; behavior may change without notice.
- **Demonstrated** -- run end-to-end at least once (on QEMU or real
  hardware) with the result directly observed and, where practical,
  captured as reproducible evidence (see `docs/evidence/`).
- **Tested** -- demonstrated repeatedly, including negative/failure
  cases, with reproducible evidence covering both.
- **Supported** -- tested, with a maintained reproduction path an
  external adopter can run themselves (not yet reached by any
  component in this project as of this writing).

## Roadmap themes

See `ROADMAP.md` for specifics. Themes, no dates:

- Reproducibility and evidence quality.
- Broader BSP/Yocto-release compatibility testing.
- Vulnerability applicability/VEX-style status investigation.
- A real-hardware reference platform alongside the QEMU example.
- A constrained industrial HMI/gateway profile (future OT-adjacent
  direction, not current scope).
- Technical (not legal) mapping to CRA-relevant activities.
