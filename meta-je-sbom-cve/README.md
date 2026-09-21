# meta-je-sbom-cve

SBOM generation and CVE scan/diff for any Yocto-built image, plus
evidence-based (KEV/EPSS) prioritization and kernel-specific CVE noise
reduction.

## What it does

```
INHERIT += "je-sbom je-cve-scan"
```

turns on SPDX SBOM generation (`create-spdx.bbclass`) and CVE scanning
(`cve-check.bbclass`) with sane defaults. Add `je-cve-diff` to also get
a `je_cve_diff` image task that collates one run into a persistent
store and diffs it against that store's previous run for the same
`MACHINE`. `scripts/` holds the rest of the toolkit: `parse_cve.py`,
`diff_cve.py` (kernel/non-kernel split, >50%-drop guard),
`spdx_components.py`, `diff_sbom.py` (SRCREV-normalised),
`layer_inventory.py`, `kev_epss_enrich.py` (KEV/EPSS enrichment),
`kernel_cve_triage.py` / `prioritize_cves.py` (kernel-specific noise
reduction). Full detail on the triage scripts:
[`docs/cve-triage.md`](../docs/cve-triage.md).

## Requirements

Any target with a normal Yocto kernel/bootloader recipe. The
source-level triage pipeline needs the build to retain a real git
checkout and `.config` for the package being triaged -- true by
default for most kernel/bootloader recipes.

## Enable it

```
INHERIT += "je-sbom je-cve-scan je-cve-diff"
bitbake <image>
bitbake <image> -c je_cve_diff
```

Set `JE_EVIDENCE_STORE` to a real persistent path (defaults under
`DEPLOY_DIR`, fine for local iteration, not for CI where `DEPLOY_DIR`
is typically ephemeral per-run). For KEV/EPSS enrichment (needs
network access -- a scheduled/nightly CI job, not local builds):

```
JE_EVIDENCE_ENABLE_KEV_EPSS = "1"
```

## Quick test

```
python3 scripts/kev_epss_enrich.py <run-dir>/parsed/unpatched.csv <run-dir>/triage
```

writes `triage.json`/`triage.md`, KEV hits first then by EPSS
descending -- see [`docs/evidence/cve-applicability.md`](../docs/evidence/cve-applicability.md)
for a real worked example end to end.

## Configuration

- `JE_EVIDENCE_STORE` -- persistent evidence store path.
- `JE_EVIDENCE_ENABLE_KEV_EPSS` -- default off; turns on network-fetch
  KEV/EPSS enrichment in `do_je_cve_diff`.
- `--kev-file`/`--epss-file`/`--offline` on `kev_epss_enrich.py` --
  pre-downloaded feeds or skip enrichment entirely.

## Known limitations

- `cve-check`'s version-range matching can't see stable/vendor-tree
  backports already merged, or catch a CPE mismatch onto an unrelated
  CVE -- in a real hardware reference scan, `kernel_cve_triage.py`
  automatically resolved 9.8% of scanned kernel candidates (237 of
  2418), each with cited evidence, and correctly left the remaining
  90.2% for human review rather than guessing. See
  [`docs/cve-triage.md`](../docs/cve-triage.md) for that run's exact
  bucket breakdown -- this is one measured result, not a general
  "typical" figure across scans.
- The ancestor-check and config-inapplicable triage buckets depend on
  a quoted commit subject in the CVE summary (common for kernel CVEs,
  not for bootloader CVEs) -- only the CPE-mismatch keyword check
  applies reliably across all packages today.
- KEV/EPSS enrichment and kernel-specific triage aren't automatically
  chained by default -- `scripts/prioritize_cves.py` exists to run
  KEV/EPSS against the *noise-reduced* triage output instead of the
  raw CVE list, but isn't wired into `do_je_cve_diff` automatically.

## More documentation

- [`docs/cve-triage.md`](../docs/cve-triage.md) -- full triage-bucket
  detail, prioritization chaining, GitLab Pages publishing.
- [`docs/evidence/cve-applicability.md`](../docs/evidence/cve-applicability.md) --
  a real CPE-mismatch candidate taken end to end.
