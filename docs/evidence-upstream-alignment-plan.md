# Evidence upstream-alignment plan

Analysis first, migration second. This document is the actual
deliverable of this review. The initial pass (P0) was documentation
and attribution only. A follow-up pass implemented and locally
verified the one P1 item with clear, evidenced benefit (the kernel
config-inapplicable wrapper, `scripts/kernel_cve_upstream_triage.py`)
as an opt-in script, not wired into CI or the default build --
everything else below remains a plan, not yet executed.

**Upstream versions analyzed**: OpenEmbedded-core `scarthgap`
(`create-spdx.bbclass`, `create-spdx-2.2.bbclass`,
`create-spdx-3.0.bbclass`, `cve-check.bbclass`, and
`scripts/contrib/improve_kernel_cve_report.py`, confirmed present in
this exact release per the Yocto Project's own scarthgap security
manual); Bootlin `sbom-cve-check` v1.3.5 (installed directly from
PyPI and inspected for this document -- CLI help, source code,
published announcement blog post); `bootlin/meta-sbom-cve-check`
(Yocto integration layer, reviewed via its public description, not
locally built in this pass).

## Capability matrix

| Current capability | Current implementation | Upstream equivalent? | Overlap level | Recommendation |
|---|---|---|---|---|
| SBOM generation | `je-sbom.bbclass` (`inherit create-spdx`) | Yes -- `create-spdx.bbclass` (OE-core), already the actual generator | Full (already wrapped) | `KEEP` |
| Base CVE scanning | `je-cve-scan.bbclass` (`inherit cve-check`) | Yes -- `cve-check.bbclass` (OE-core), already the actual scanner | Full (already wrapped) | `KEEP` |
| CVE manifest normalization (JSON -> stable CSV/JSON) | `scripts/parse_cve.py` | No direct upstream equivalent -- reformats `cve-check`'s own output for diffing, doesn't re-match CVEs | None -- lifecycle tooling, not CVE matching | `KEEP` |
| SBOM component extraction (SPDX -> diffable TSV) | `scripts/spdx_components.py` | No direct upstream equivalent -- reads `create-spdx`'s own output, doesn't re-generate | None -- lifecycle tooling | `KEEP` |
| CVE/SBOM diffing (run-to-run) | `scripts/diff_cve.py`, `scripts/diff_sbom.py` | No direct upstream equivalent found | None -- lifecycle tooling, this project's real differentiator | `KEEP` |
| Kernel CVE config-inapplicable filtering | `scripts/kernel_cve_triage.py` (Kconfig-symbol-to-source-file heuristic via hand-parsed Makefiles); `scripts/kernel_cve_upstream_triage.py` (new -- wraps upstream, opt-in) | **Yes** -- `improve_kernel_cve_report.py` (OE-core, scarthgap+), uses real compiled-sources data from SPDX + real CNA data from `linux-vulns`, documented 70-80% false-positive reduction | High -- same job, upstream's mechanism is more authoritative (real compiled-file data vs. a heuristic) | `WRAP_UPSTREAM` -- wrapper implemented and tested against real am335x evidence data this pass; not yet wired into `je-cve-diff.bbclass`/CI (see Migration plan P1) |
| Kernel CVE fixed-version detection (git ancestor check) | `scripts/kernel_cve_triage.py` | Partially -- `improve_kernel_cve_report.py`'s own description mentions "preserving backported-patch status," suggesting overlapping intent; exact mechanism not confirmed in this pass | Uncertain -- needs confirmation | `INVESTIGATE` |
| Bootloader/non-kernel package CVE triage (same script, generalized) | `scripts/kernel_cve_triage.py` | No upstream equivalent found -- `improve_kernel_cve_report.py` is kernel-specific per its own name and CNA data source | None for this specific use | `KEEP` (scoped to non-kernel packages if the kernel path moves upstream) |
| KEV/EPSS enrichment | `scripts/kev_epss_enrich.py` | **No** -- confirmed directly: Bootlin's own announcement lists NVD + CVE List as `sbom-cve-check`'s only sources, no KEV/EPSS mention anywhere in its docs or CLI options | None | `KEEP` -- this is real, confirmed JustEmbed-unique value |
| KEV/EPSS-aware prioritization chained with kernel triage | `scripts/prioritize_cves.py` | No | None | `KEEP` |
| VEX consumption | *(none implemented)* | **Yes** -- `sbom-cve-check` reads OpenVEX files (`--add-db openvex-file`) and SPDX3-embedded VEX (`--export-spdx-pkg-include-vex`) natively | N/A (JustEmbed doesn't do this today) | `WRAP_UPSTREAM` if/when disposition evidence needs to round-trip into a re-scan -- see VEX feasibility below |
| VEX/disposition status vocabulary | *(prose only, no formal vocabulary today)* | Yes -- OpenVEX's own 4-status vocabulary, confirmed exactly matched by `sbom-cve-check`'s own `--export-filter-vex-status` option | N/A | `WRAP_UPSTREAM` -- see `docs/vulnerability-disposition-mapping.md` |
| Layer/license inventory | `scripts/layer_inventory.py` | Partial -- SPDX itself carries license data; this script's per-*layer* rollup (not per-package) view wasn't confirmed to exist upstream | Uncertain | `KEEP` (not reviewed in depth this pass -- lower priority, not CVE-matching) |
| Evidence store collation, GitLab Pages publishing | `scripts/publish_scan.sh`, `scripts/publish_gitlab_pages.sh`, `scripts/reindex.py`, `scripts/collect_build_meta.sh` | No upstream equivalent -- this is JustEmbed's own lifecycle/evidence-publishing orchestration | None | `KEEP` |
| Report generation (viewer) | `meta-je-sbom-cve/pages/` (static HTML/JS viewer) | Partial -- `sbom-cve-check` has its own `summary`/`csv` export formats; not a hosted viewer | Low | `KEEP` (not reviewed in depth this pass) |
| Periodic re-scan without a full rebuild | `je_cve_diff` task re-runs at build time only (`addtask ... after do_image_complete`) | **Yes** -- `sbom-cve-check`'s own stated design goal is exactly this: run CVE analysis against an already-produced SBOM, independent of the build, on a schedule | Real overlap in *capability*, not code | `INVESTIGATE` -- see Migration plan P2 |

## Code classification

| File/component | Classification | Reason |
|---|---|---|
| `classes/je-sbom.bbclass` | `KEEP` | Thin wrapper, already upstream-first. |
| `classes/je-cve-scan.bbclass` | `KEEP` | Thin wrapper, already upstream-first. |
| `classes/je-cve-diff.bbclass` | `KEEP`, revisit orchestration in P2 | Real lifecycle value (persistent store, diffing); the *periodic re-scan* half of its job may partially overlap `sbom-cve-check`'s own design goal -- worth investigating, not urgent. |
| `scripts/parse_cve.py` | `KEEP` | Normalizes upstream output; doesn't duplicate CVE matching. |
| `scripts/spdx_components.py` | `KEEP` | Reads upstream SPDX output; doesn't duplicate SBOM generation. |
| `scripts/diff_cve.py` | `KEEP` | Lifecycle diffing, no upstream equivalent found. |
| `scripts/diff_sbom.py` | `KEEP` | Lifecycle diffing, no upstream equivalent found. |
| `scripts/kernel_cve_triage.py` | `KEEP` for non-kernel packages (u-boot, busybox); kernel path now has a working `WRAP_UPSTREAM` alternative | Its own git-ancestor/Kconfig check actually catches real stable/vendor-tree backports `improve_kernel_cve_report.py`'s pure CPE-version-range matching can't see -- not strictly inferior, just different evidence. See `scripts/kernel_cve_upstream_triage.py` and Migration plan P1. |
| `scripts/kernel_cve_upstream_triage.py` | `KEEP` (new this pass) | Wraps `improve_kernel_cve_report.py` (not a reimplementation), re-buckets its output into `kernel_cve_triage.py`'s exact JSON/MD shape -- verified `prioritize_cves.py` reads it unchanged. Opt-in, not wired into CI. See `docs/cve-triage.md`. |
| `scripts/test_kernel_cve_upstream_triage.py` | `KEEP` (new this pass) | Unit tests for the re-bucketing/normalization logic, 11 cases, all passing. |
| `scripts/kev_epss_enrich.py` | `KEEP` | Confirmed unique value -- no upstream KEV/EPSS source found. |
| `scripts/prioritize_cves.py` | `KEEP`, minor rework if P1 lands | Chains kernel triage into KEV/EPSS; if `kernel_cve_triage.py`'s kernel path is replaced, this script's input shape needs to accept `improve_kernel_cve_report.py`'s output format instead (or alongside). |
| `scripts/layer_inventory.py` | `KEEP` (not deeply reviewed) | Out of this pass's critical path (not CVE-matching); low risk either way. |
| `scripts/publish_scan.sh` | `KEEP` | Orchestration/evidence-publishing, no upstream equivalent. |
| `scripts/publish_gitlab_pages.sh` | `KEEP` | Evidence-publishing, JustEmbed-specific. |
| `scripts/reindex.py` | `KEEP` (not deeply reviewed) | Supporting script for the viewer/store; low risk. |
| `scripts/collect_build_meta.sh` | `KEEP` (not deeply reviewed) | CLI/CI entry point helper; low risk. |
| `pages/` (viewer) | `KEEP` (not deeply reviewed) | Presentation layer; not CVE-matching logic. |

No component in this layer independently re-implements NVD matching,
CPE logic, or CVE data sourcing -- the design already avoided the
biggest duplication risk the task was worried about (own CVE matching
engine) from the start, by wrapping `cve-check.bbclass` rather than
reimplementing it.

## VEX feasibility

- **OpenVEX generation**: not implemented by JustEmbed today, and not
  attempted in this pass (would be new code -- out of scope per "geen
  eigen VEX format verzinnen," and not yet needed since generation
  wasn't proven necessary for the round-trip attempt below to be
  meaningful).
- **Consumption**: confirmed real and working upstream --
  `sbom-cve-check --add-db openvex-file PATH` loads a real OpenVEX
  file's `not_affected`/`affected`/`fixed`/`under_investigation`
  statements as an annotation database, verified by installing the
  tool and reading its `annot_openvex.py` source directly (the
  justification-string mapping matches OpenVEX's own spec exactly).
- **Round-trip**: attempted for real in this pass -- see
  `docs/evidence/vex-roundtrip.md` for the outcome (real attempt,
  real blocker or real proof, not assumed).
- **SPDX 3**: confirmed available in this exact scarthgap release
  today (`create-spdx-3.0.bbclass` exists alongside the SPDX 2.2
  default) but not the current default (`create-spdx.bbclass`'s own
  comment: "will be updated to the latest stable version that is
  supported" -- currently resolves to `create-spdx-2.2`). Switching
  `je-sbom.bbclass` to `inherit create-spdx-3.0` is a one-line, low-risk
  change, but changes the SBOM output format/paths this project's
  own `spdx_components.py` parses -- flagged as a real, small,
  well-scoped P1 migration item, not done silently in this pass (see
  "Backward compatibility" below).
- **Blockers found**: `sbom-cve-check`'s default CVE data source is a
  full clone of `CVEProject/cvelistV5` (large, didn't complete within
  a reasonable time budget in this sandboxed environment); switching
  to its lighter `cve-db-nvd-fkie` source (a smaller, curated NVD JSON
  mirror) was necessary to make a real test practical at all.

## Ownership boundaries

| Concern | Owner |
|---|---|
| SPDX generation | Yocto (`create-spdx.bbclass`) |
| Base CVE matching | Upstream (`cve-check.bbclass` and/or `sbom-cve-check`) |
| Kernel applicability (compiled-vs-not) | Upstream where possible (`improve_kernel_cve_report.py`) -- `INVESTIGATE`, not yet migrated |
| VEX parsing | Upstream (`sbom-cve-check`) |
| KEV enrichment | JustEmbed |
| EPSS enrichment | JustEmbed |
| Product context | JustEmbed |
| Disposition evidence | JustEmbed (expressed in OpenVEX vocabulary, see `docs/vulnerability-disposition-mapping.md`) |
| Detect linkage | JustEmbed |
| Remediation linkage | JustEmbed |
| Lifecycle diffing/evidence store | JustEmbed |

## Backward compatibility

`spdx_components.py`, `parse_cve.py`, and everything downstream of
them (`diff_sbom.py`, `diff_cve.py`, the evidence store, the viewer,
`docs/evidence/*.md`) all assume the current SPDX 2.2 / `cve-check`
JSON manifest shapes. Any P1 migration (SPDX 3, or swapping
`kernel_cve_triage.py`'s kernel path for `improve_kernel_cve_report.py`)
changes at least one of those input shapes and needs the
corresponding parser updated in the same change -- not a silent
breaking change, and not attempted in this pass. `docs/evidence/`
entries that cite exact file paths/formats from the current pipeline
(e.g. `cve-applicability.md`'s real `triage.json` structure) would
need a compatibility note or a rerun once any such migration lands.

## Migration plan

### P0 (this pass -- see "Small safe changes")

- Documentation only: this document, `docs/evidence-architecture.md`,
  `docs/vulnerability-disposition-mapping.md`,
  `docs/upstream-questions.md`, and (if it succeeded)
  `docs/evidence/vex-roundtrip.md`.
- Upstream attribution added/verified in `README.md` and
  `meta-je-sbom-cve/README.md`.

### P1 (next, needs its own dedicated pass)

- **Kernel config-inapplicable wrapper -- code done and wired into
  `je-cve-diff.bbclass`, gated off by default.**
  `scripts/kernel_cve_upstream_triage.py` calls
  `improve_kernel_cve_report.py` for real and re-buckets its output
  into `kernel_cve_triage.py`'s existing shape; `prioritize_cves.py`
  confirmed to consume it unmodified. `je-cve-diff.bbclass` now clones/
  fetches `linux-vulns`, auto-extracts the kernel's recipe SPDX
  document from the run's own `sbom-recipes.spdx.tar.zst` (archive
  layout confirmed real), and calls the wrapper -- all behind
  `JE_EVIDENCE_ENABLE_UPSTREAM_KERNEL_TRIAGE ??= "0"`.

  Verified against a real `am335x-smarc-t335x-hmi` evidence run
  (2026-09-15T045754Z): kernel.org's real CNA data tracks 20,284
  kernel CVEs for this kernel version versus 15,001 from NVD alone,
  and 5,448 Unpatched versus 2,418 -- switching data source surfaces
  real CVEs NVD doesn't track, it does not by itself reduce the count.

  **Still unmeasured**: the actual noise-reduction half
  (config-inapplicable filtering) needs the BSP to separately set
  `SPDX_INCLUDE_COMPILED_SOURCES:pn-linux-ti-staging = "1"` and run a
  real build -- extraction of the kernel SPDX document is verified
  working, but no build with that flag enabled has been run yet, so
  whether it actually reduces the count (per Yocto's 70-80% claim) is
  not yet confirmed for this BSP. See `docs/cve-triage.md` for the
  full writeup and the real `detail`-field compatibility bug hit along
  the way.
- Evaluate migrating `je-sbom.bbclass` from `create-spdx` (currently
  SPDX 2.2) to `create-spdx-3.0` explicitly, updating
  `spdx_components.py` for the new output shape. Prerequisite for
  some upstream VEX/SPDX3 tooling that expects SPDX 3 input.

### P2 (investigate, not yet planned in detail)

- Evaluate whether `je-cve-diff`'s periodic-rescan role could
  partially delegate to `sbom-cve-check`'s own independent-of-build
  re-scan capability, keeping JustEmbed's own evidence-store/diffing/
  publishing layer on top rather than duplicating the re-scan
  mechanism itself.
- Evaluate OpenVEX *generation* from JustEmbed's own disposition
  evidence, once a concrete consuming use case (beyond this pass's
  round-trip proof) justifies the work.

## Risks

1. Migrating the kernel-applicability path changes the exact shape of
   `triage-kernel.json`, which `prioritize_cves.py` and
   `docs/evidence/cve-applicability.md` both depend on -- needs a
   coordinated update, not a silent swap.
2. `improve_kernel_cve_report.py`'s exact CLI/output stability across
   Yocto releases wasn't verified beyond scarthgap in this pass.
3. Bootlin's `sbom-cve-check` is still landing in OE-core
   incrementally (patch series in review per the search performed for
   this document) -- its interface may still change before it's fully
   upstream.
4. SPDX 3 migration is low-risk in isolation but touches every
   downstream parser in this layer -- needs its own dedicated pass
   with tests, not a quick swap.
5. `sbom-cve-check`'s default CVE data source (a full `cvelistV5`
   clone) is heavy; any future integration needs an explicit,
   documented choice of data source, not the tool's own default.
6. `improve_kernel_cve_report.py` expects an issue-entry `detail`
   field that this project's `cve-check` version doesn't emit at all
   (confirmed: all 15,001 kernel issue entries in a real evidence run
   lacked it) -- worked around with an input-normalization shim in
   `kernel_cve_upstream_triage.py`, not by patching upstream's script.
   A real, if minor, version-skew signal worth flagging to upstream
   (see `docs/upstream-questions.md`).
