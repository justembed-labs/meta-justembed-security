# Architecture

Four independent building blocks. Each maps to exactly one layer in
this repository; none requires another to function, though a real
product typically adopts all four together for the full
patch-latency-gap-closing effect described in the top-level README.

```text
Hygiene -> Evidence -> Detect -> Update & Boot

Reduce  -> Know     -> Detect -> Remediate
```

## Hygiene (`meta-je-hygiene`)

Build-time security hygiene and baseline checks, enforced at
`do_rootfs` QA time -- an unmet enforced check fails the build, not
just a logged warning. No default credentials, key-only SSH, minimal
service surface, kernel hardening flags. Layer-internal only; nothing
here reads output from the other three layers, and nothing else reads
its `.je-hygiene.json` report today (a real, current architecture gap
-- see "Cross-layer dependencies" below).

## Evidence (`meta-je-sbom-cve`)

SBOM (SPDX) generation, CVE scan/diff, and applicability evidence:
kernel/u-boot-specific triage that separates config-inapplicable code
paths and confirmed-fixed backports from genuinely open CVEs, then
KEV/EPSS enrichment for real-world exploitation signal. Produces a
persistent evidence store (`JE_EVIDENCE_STORE`) that `meta-je-example-bsp`
publishes as a static site. Standalone; doesn't require Detect or
Update & Boot to run.

## Detect (`meta-je-detection`)

Lightweight embedded detection and standardized security telemetry:
turns a disclosed CVE into an auditd rule plus an OCSF-formatted
event, shipped via Fluent Bit to whatever collector/SIEM the adopter
already runs. See `docs/detect.md` for the full pipeline. Consumes
`meta-je-boot-update`'s FOTA channel for its own rule-bundle updates,
but the detection agent and rule loading work without it (a rule
bundle can also just be baked into the image at build time).

## Update & Boot (`meta-je-boot-update`)

Verified boot (U-Boot FIT signing, `je-secureboot.bbclass`) and signed
atomic A/B updates (`je-swupdate-fota.bbclass`, swupdate-based). See
`docs/update-boot.md` for the full trust-chain and update-flow
breakdown. Independent of the other three layers -- a target can adopt
verified boot and FOTA with zero Hygiene/Evidence/Detect content
installed.

## Design principles

- **Independently adoptable.** Each layer has its own `layer.conf` and
  can be added to a BSP alone.
- **No mandatory cloud/backend dependency.** Nothing here requires a
  JustEmbed-operated service.
- **Mature upstream components over reimplementation.** `create-spdx`,
  `cve-check`, `kernel-fitimage`, `uboot-sign`, `meta-swupdate`, Linux
  audit, Fluent Bit, OCSF -- wired up, not rebuilt.
- **Integration and evidence, not a full security stack.** JustEmbed
  Labs builds the connective tissue between existing tools and the
  evidence that it works; it does not build a SIEM, a fleet manager,
  or an OT platform (see `PROJECT.md`'s Non-goals).

## Cross-layer dependencies

Real, current couplings between layers, checked against the code
rather than assumed:

| From | To | Nature | Hard requirement? |
|---|---|---|---|
| `meta-je-detection` (rule-bundle updates) | `meta-je-boot-update` | Rule-bundle content ships over swupdate's `rawfile` handler through the same signing key/channel as firmware updates. | No -- a rule bundle can be baked into the image at build time instead; the independent-update path is what needs `meta-je-boot-update`. |
| `meta-je-hygiene`'s JSON report | *(nothing, currently)* | Written to `${DEPLOY_DIR_IMAGE}` but not consumed by any other layer or by CI. | N/A -- this is a gap, not a dependency: the report exists but nothing currently reads it back. |
| `meta-je-sbom-cve`'s evidence store | *(nothing, currently)* | `meta-je-detection` is designed to eventually consume prioritized CVE output to seed which rules matter most, per the top-level README's flow diagram; the code does not implement this hand-off today -- rule bundles are hand-authored. | N/A -- roadmap item, not a current dependency. |

No layer currently has a hard build-time dependency on another that
would block independent adoption. The two "nothing, currently" rows
are genuine architecture gaps (the pipeline described in the top-level
README's mermaid diagram is aspirational for those two hand-offs, not
yet wired in code) -- tracked in `ROADMAP.md`, not silently implied to
already work.
