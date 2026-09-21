# meta-justembed-security

**Reusable Yocto security building blocks for embedded Linux products.**

Reduce exposure. Understand vulnerabilities. Detect what cannot
immediately be fixed. Securely remediate.

`Hygiene -> Evidence -> Detect -> Update & Boot`

**[Try it in QEMU -- no hardware required](https://github.com/justembed-labs/meta-je-example-bsp)** &nbsp;|&nbsp; [Evidence](docs/evidence/) &nbsp;|&nbsp; [Documentation](docs/architecture.md)

## Two repositories, two roles

```text
meta-justembed-security      reusable layers (this repo)
meta-je-example-bsp          runnable QEMU reference implementation
```

[`meta-je-example-bsp`](https://github.com/justembed-labs/meta-je-example-bsp)
is not a side project -- it's the primary way to evaluate this project
without hardware. If you want to see it run before reading further,
start there.

## Why this exists

Embedded-product security is usually a set of disconnected activities:
hardening, SBOM generation, CVE scanning, monitoring, updates. A CVE
report alone doesn't answer:

- is this actually applicable to my build?
- is it known to be exploited?
- can we patch immediately?
- if not, can we detect exploitation?
- can we securely remediate later?

`Reduce -> Know -> Detect -> Remediate`

## Building blocks

| Building block | Purpose |
|---|---|
| **Hygiene** | Build-time security hygiene and selected baseline checks |
| **Evidence** | SBOM, CVE evidence, and KEV/EPSS context |
| **Detect** | Lightweight host detection -> OCSF -> Fluent Bit |
| **Update & Boot** | Signed updates, A/B lifecycle, and verified boot where supported |

Each layer is independently adoptable. Full detail:
[`docs/architecture.md`](docs/architecture.md).

## Try it without hardware

The QEMU reference BSP integrates all four layers into a runnable
example:

```bash
git clone https://github.com/justembed-labs/meta-je-example-bsp.git
cd meta-je-example-bsp
kas build kas.yml
```

builds `core-image-minimal` for `qemuarm64` with Hygiene, Evidence,
Detect, and Update & Boot all wired in. See
[`meta-je-example-bsp`](https://github.com/justembed-labs/meta-je-example-bsp)
for booting it, verifying secure boot, and running the full signed
update cycle.

## Evidence

| Capability | Status | Evidence |
|---|---|---|
| SBOM / CVE scan, diff, KEV/EPSS | demonstrated | [published run](https://justembed-labs.github.io/meta-je-example-bsp/) |
| CVE applicability evidence / documented disposition (real candidate) | demonstrated | [`cve-applicability.md`](docs/evidence/cve-applicability.md) |
| Detection -> OCSF -> Fluent Bit | demonstrated (QEMU); hardware-verified against a real CVE | [`detection-event.md`](docs/evidence/detection-event.md) |
| Signed rule-bundle update | demonstrated (QEMU) | [`signed-rule-update.md`](docs/evidence/signed-rule-update.md) |
| Signed A/B firmware update | demonstrated (QEMU); hardware-verified | [`signed-ab-update.md`](docs/evidence/signed-ab-update.md) |
| FIT verification (valid + tamper rejected) | demonstrated (QEMU) | [`fit-verification.md`](docs/evidence/fit-verification.md) |
| Build-time hygiene enforcement | hardware-verified | [`meta-je-hygiene/README.md`](meta-je-hygiene/README.md) |

Full index, exact commands, and raw output: [`docs/evidence/`](docs/evidence/).
No status here is asserted without a linked entry or an explicit
pointer to who observed it. Which platforms this has actually been
validated on (QEMU today; physical hardware planned, not yet
started): [Platform validation matrix](docs/platform-validation-matrix.md).

## CRA relevance

The EU Cyber Resilience Act increases the need for manufacturers to
understand software inventory, handle vulnerabilities, monitor
relevant security events, and provide secure remediation throughout
the product lifecycle. These layers provide technical building blocks
and evidence that can support those engineering activities.

**They do not by themselves establish CRA compliance.** See
[`docs/cra/CRA_TECHNICAL_MAPPING.md`](docs/cra/CRA_TECHNICAL_MAPPING.md).

## What this is not

- Not a CRA compliance product.
- Not a SIEM or fleet-management backend.
- Not a full EDR platform.
- Not a plant-wide OT security solution.

Full non-goals: [`PROJECT.md`](PROJECT.md).

## Built on

[Yocto / OpenEmbedded](https://www.yoctoproject.org/) ·
[SWUpdate](https://github.com/sbabic/meta-swupdate) ·
[U-Boot](https://www.denx.de/wiki/U-Boot) ·
[Linux Audit](https://github.com/linux-audit/audit-userspace) ·
[Fluent Bit](https://fluentbit.io/) ·
[OCSF](https://schema.ocsf.io/) ·
[NVD](https://nvd.nist.gov/) ·
[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) ·
[FIRST EPSS](https://www.first.org/epss/)

These layers integrate existing open-source components and public
data sources rather than reimplementing them. See `NOTICE` for full
attribution.

## Project status

Early-stage open-source engineering. Current focus is embedded Linux
and IoT; a QEMU reference is available today, and real-hardware
evidence is called out explicitly only where it actually exists (see
`docs/evidence/`). OT deployment is a roadmap direction, not a current
capability. See [`PROJECT.md`](PROJECT.md) and
[`ROADMAP.md`](ROADMAP.md).

## Getting started

### Try without hardware
-> [`meta-je-example-bsp`](https://github.com/justembed-labs/meta-je-example-bsp)

### Integrate into your BSP
-> [`docs/getting-started.md`](docs/getting-started.md)

### Optional: Claude Code bootstrap
-> [`.claude/skills/meta-je-bootstrap/SKILL.md`](.claude/skills/meta-je-bootstrap/SKILL.md)
-- an accelerator for an AI coding agent doing the integration above,
not a requirement to use this project.

## Contributing

Issues, testing feedback, and contributions are welcome. See
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## Vulnerability reporting

See [`SECURITY.md`](SECURITY.md) -- don't open a public issue.

## License

Apache-2.0 + NOTICE (see [`LICENSE`](LICENSE)/[`NOTICE`](NOTICE)) --
patent grant, attribution, no copyleft.
