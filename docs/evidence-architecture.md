# Evidence architecture: upstream-first

This document sets the target architecture for `meta-je-sbom-cve`: use
upstream Yocto/OpenEmbedded and Bootlin tooling for SBOM generation,
base CVE matching, and kernel applicability filtering wherever it
already does the job well, and keep JustEmbed's own code scoped to
what upstream genuinely doesn't provide -- real-world exploitation
context (KEV/EPSS), product/build context, explicit disposition
evidence, and lifecycle linkage into Detect and Update & Boot.

This is a target, not a completed migration -- see
`docs/evidence-upstream-alignment-plan.md` for what's actually being
changed now versus planned.

## Target flow

```text
Yocto / SPDX (create-spdx.bbclass)
        |
        v
sbom-cve-check (Bootlin) or cve-check.bbclass (OE-core)
        |
        v
candidate vulnerabilities
        |
        v
upstream applicability / VEX
  (improve_kernel_cve_report.py compiled-sources filtering,
   sbom-cve-check OpenVEX/SPDX3-VEX consumption)
        |
        v
JustEmbed Evidence
        |
        +-- CISA KEV enrichment
        +-- EPSS enrichment
        +-- product/build context
        +-- explicit disposition evidence
        +-- unresolved/unknown tracking
        +-- lifecycle linkage
                |
                v
          Detect / Remediate
```

## Upstream owns

- **SBOM generation** -- `create-spdx.bbclass` (OE-core). Already
  wrapped, not reimplemented (`je-sbom.bbclass` is a 7-line
  `inherit create-spdx` with one default).
- **SPDX parsing/consumption** -- both `improve_kernel_cve_report.py`
  and Bootlin's `sbom-cve-check` read Yocto's own SPDX output
  directly; no reason for a third independent SPDX parser.
- **Base CVE matching** -- `cve-check.bbclass` (OE-core, already
  wrapped) and/or `sbom-cve-check` (real NVD + CVE List sources,
  confirmed via its own documentation -- see
  `docs/evidence-upstream-alignment-plan.md`'s capability matrix for
  the exact sourcing).
- **Kernel source applicability (compiled-vs-not)** --
  `improve_kernel_cve_report.py` (OE-core, `scripts/contrib/`, present
  since scarthgap), using real CNA data from `linux-vulns` and the
  SPDX compiled-sources list. Documented by the Yocto Project itself
  to cut kernel CVE false positives 70-80% -- a stronger, more
  authoritative mechanism than a hand-rolled Kconfig/Makefile
  heuristic.
- **VEX consumption/parsing** -- `sbom-cve-check` reads OpenVEX files
  (`--add-db openvex-file`) and a "Yocto Project VEX manifest" format
  (`--yocto-vex-manifest`) natively.
- **Generic vulnerability report semantics** -- `sbom-cve-check`'s own
  VEX status vocabulary is exactly OpenVEX's four statuses
  (`affected`, `not_affected`, `fixed`, `under_investigation`),
  verified directly against its real CLI (`--export-filter-vex-status`)
  and its OpenVEX annotation-reader source code.

## JustEmbed adds

- **CISA KEV enrichment** -- confirmed upstream tools do not source
  this (Bootlin's own announcement lists NVD + CVE List only).
- **EPSS enrichment** -- confirmed upstream tools do not source this
  either.
- **Product/build context** -- what's actually enabled/installed/
  exposed in a specific image, beyond generic package-version
  matching.
- **Prioritisation** -- chaining kernel applicability triage into
  KEV/EPSS so a confirmed-exploited signal isn't drowned out by (or
  mistakenly applied to) a config-inapplicable or CPE-mismatched
  candidate.
- **Explicit disposition evidence and decision traceability** -- see
  `docs/vulnerability-disposition-mapping.md`.
- **Unresolved/unknown tracking** -- a CVE never silently disappears;
  see the same mapping document.
- **Linkage to Detect** -- connecting an evidence disposition to a
  `je-rule-bundle` detection rule where one exists (see
  `docs/evidence-upstream-alignment-plan.md` for current state).
- **Linkage to secure remediation** -- connecting a disposition to the
  signed update path that actually fixes it (same document).

## Why this split

Per this project's own maturity model
([`PROJECT.md`](../PROJECT.md)): a capability is only credible when
it's actually run and observed, not merely claimed. Upstream CVE
matching, kernel applicability, and VEX handling are maintained by
people whose full-time focus is exactly that -- duplicating it here
means JustEmbed inherits the burden of keeping pace with NVD schema
changes, kernel CNA data, and CPE quirks, without adding anything an
adopter couldn't already get upstream. The parts that are genuinely
this project's own value (real-world exploitation signal, product
context, and lifecycle linkage into detection/remediation) are also
the parts an embedded-product team can't get from a generic CVE
scanner at all.
