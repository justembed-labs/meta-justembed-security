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
| Hygiene | Secure-by-default configuration, protection from unauthorized access, minimized attack surface | Build-time checks (no default credentials, key-only SSH, minimal service surface, kernel hardening flags) enforced at `do_rootfs` -- an unmet enforced check fails the build. | `meta-je-hygiene/README.md`, hardware-verified per its own "Usage" section. |
| Evidence | Software inventory, vulnerability identification | SPDX SBOM generation and CVE scan/diff, with KEV/EPSS enrichment for real-world exploitation signal and kernel-specific CPE-mismatch/backport triage. | `docs/evidence/cve-applicability.md`, `meta-je-sbom-cve/README.md`. |
| Detect | Vulnerability monitoring, security-relevant event handling | Turns a disclosed CVE into a runtime detection rule (auditd + OCSF), shipped independently of firmware so detection coverage doesn't wait for a full release cycle. | `docs/evidence/detection-event.md`, `docs/detect.md`. |
| Update & Boot | Protection from unauthorized modification, secure update delivery | U-Boot FIT signature verification and signed A/B firmware updates (swupdate), plus independently signed detection-rule updates. | `docs/evidence/fit-verification.md`, `docs/evidence/signed-ab-update.md`, `docs/evidence/signed-rule-update.md`. |

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

- `PROJECT.md`'s Non-goals -- this project's explicit scope
  boundaries.
- `docs/evidence/` -- the reproducible record behind every technical
  claim referenced above.
- `SECURITY.md` -- how to report a vulnerability in this project
  itself.
