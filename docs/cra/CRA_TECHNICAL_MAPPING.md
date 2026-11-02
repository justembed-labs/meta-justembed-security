# CRA technical mapping

The EU Cyber Resilience Act increases the need for manufacturers to
understand software inventory, handle vulnerabilities, monitor
relevant security events, and provide secure remediation throughout a
product's lifecycle. This document maps each building block to the
CRA-relevant *engineering activity* it provides a technical mechanism
for -- it is not a legal analysis and does not determine CRA
conformity for any product.

**This project does not by itself establish CRA compliance.** Whether
a given product satisfies its CRA obligations depends on the whole
product (hardware, process, documentation, vulnerability-handling
policy) and is a legal question outside this project's scope. What
follows is a technical mapping only: which essential-requirement
*category* (CRA Annex I) each building block provides a mechanism for,
and where the reproducible evidence for that mechanism lives.

| Building block | Annex I category (technical, not legal) | What it actually provides | Evidence |
|---|---|---|---|
| Hygiene | Secure-by-default configuration, protection from unauthorized access, minimized attack surface | Build-time checks (no default credentials, key-only SSH, minimal service surface, kernel hardening flags) enforced at `do_rootfs` -- an unmet enforced check fails the build. | [`meta-je-hygiene/README.md`](../../meta-je-hygiene/README.md), hardware-verified per its own "Usage" section. |
| Evidence | Software inventory, vulnerability identification | SPDX SBOM generation and CVE scan/diff, with KEV/EPSS enrichment for real-world exploitation signal and kernel-specific CPE-mismatch/backport triage. | [`cve-applicability.md`](../evidence/cve-applicability.md), [`meta-je-sbom-cve/README.md`](../../meta-je-sbom-cve/README.md). |
| Detect | Vulnerability monitoring, security-relevant event handling | Turns a disclosed CVE into a runtime detection rule (auditd + OCSF), shipped independently of firmware so detection coverage doesn't wait for a full release cycle. Forwarding to an external collector is **best-effort, not a guaranteed-delivery mechanism** -- confirmed directly that events buffered during a collector outage can be permanently lost if the outage outlasts the forwarder's own retry window (memory-only storage in the shipped config). | [`detection-event.md`](../evidence/detection-event.md), [`docs/detect.md`](../detect.md), [`detection-resource-measurements.md`](../evidence/detection-resource-measurements.md) ("Collector unavailable" / "Collector recovery" -- the real test that found this). |
| Update & Boot | Protection from unauthorized modification, secure update delivery | U-Boot FIT signature verification and signed A/B firmware updates (swupdate), plus independently signed detection-rule updates. Firmware updates have trial-boot rollback; **rule-bundle updates do not** -- a validly signed rule bundle applies immediately with no staged/canary activation or rollback path. | [`fit-verification.md`](../evidence/fit-verification.md), [`signed-ab-update.md`](../evidence/signed-ab-update.md), [`ab-rollback.md`](../evidence/ab-rollback.md), [`signed-rule-update.md`](../evidence/signed-rule-update.md) (states the rollback gap explicitly). |

## Vulnerability handling process -- two distinct things

CRA vulnerability-handling obligations apply to a *manufacturer's own
product*. This project provides technical building blocks (SBOM, CVE
triage, detection) that can inform an adopter's own process for
*their* product -- it does not run that process for them, and does
not itself constitute an adopter's CRA vulnerability-handling
process.

Separately, **this project has its own vulnerability-reporting
process for vulnerabilities in its own code** (a bug in
`meta-je-hygiene`'s check logic, a bypass in `je-rule-bundle`'s
signature verification, etc.) -- see [`SECURITY.md`](../../SECURITY.md):
private reporting to `security@justembed.nl`, acknowledgment within 5
business days, a 90-day default disclosure timeline. This is the
security process *for this open-source project*, not a component an
adopter can point to as satisfying their own product's CRA reporting
obligations to ENISA/CSIRTs -- those are the adopter's own, separate
responsibility.

## What this mapping is not

- Not a conformity assessment, gap analysis, or certification
  artifact.
- Not a claim that any specific CRA article or annex point is
  satisfied -- the table above names essential-requirement
  *categories* for technical orientation, not article-by-article
  compliance status.
- Not a substitute for a manufacturer's own legal review, technical
  documentation obligations, or vulnerability-handling process under
  the CRA.

## Where to look for more

- [`PROJECT.md`](../../PROJECT.md)'s Non-goals -- this project's
  explicit scope boundaries.
- [`docs/evidence/`](../evidence/) -- the reproducible record behind
  every technical claim referenced above.
- [`SECURITY.md`](../../SECURITY.md) -- how to report a vulnerability
  in this project itself.
