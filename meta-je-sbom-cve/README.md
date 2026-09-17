# meta-je-sbom-cve

SBOM generation and CVE scan/diff for any Yocto-built image.

```
INHERIT += "je-sbom je-cve-scan"
```

turns on SPDX SBOM generation (`create-spdx.bbclass`) and CVE
scanning (`cve-check.bbclass`) with sane defaults. Add `je-cve-diff` to
also get a `je_cve_diff` image task that collates one run into a
persistent store and diffs it against that store's previous run for
the same `MACHINE`:

```
INHERIT += "je-sbom je-cve-scan je-cve-diff"
bitbake <image>
bitbake <image> -c je_cve_diff
```

Set `JE_EVIDENCE_STORE` to a real persistent path (defaults under
`DEPLOY_DIR`, fine for local iteration, not for CI where `DEPLOY_DIR`
is typically ephemeral per-run).

`scripts/` holds the toolkit: `parse_cve.py` / `diff_cve.py`
(kernel/non-kernel split, >50%-drop guard) / `spdx_components.py` /
`diff_sbom.py` (SRCREV-normalised) / `layer_inventory.py` (per-layer
license/origin table) / `publish_scan.sh` (the collation/diff
orchestrator, also what `je-cve-diff.bbclass`'s task calls) /
`reindex.py` / `collect_build_meta.sh` (CLI/CI entry point -- inside a
running build, `je-cve-diff.bbclass` builds its own minimal build-meta
instead, since the recipe already has those variables).

## KEV/EPSS triage

NVD/CVSS (what `parse_cve.py` already reports) says how bad a CVE
could be. It doesn't say whether anyone is actually exploiting it.
`scripts/kev_epss_enrich.py` cross-references a run's unpatched CVEs
against two free, unauthenticated feeds:

- **CISA KEV** -- a curated, binary catalog of CVEs *confirmed*
  exploited in the wild.
- **FIRST.org EPSS** -- a daily-scored probability (0-1) of
  exploitation in the next 30 days.

```
python3 scripts/kev_epss_enrich.py <run-dir>/parsed/unpatched.csv <run-dir>/triage
```

writes `triage.json` (full data) and `triage.md` (KEV hits first, then
by EPSS descending, rows below 0.1 EPSS and not in KEV omitted from the
table but still in the JSON). Typical effect: a few thousand
"unpatched" CVEs (mostly kernel version-range noise) collapse down to
a handful of confirmed-exploited or high-EPSS ones -- the actual input
`meta-je-detection` needs.

Needs network access, so `je-cve-diff.bbclass` only runs it when
`JE_EVIDENCE_ENABLE_KEV_EPSS = "1"` (default off) -- turn that on for a
**scheduled/nightly CI job only**, not local/interactive builds, same
reasoning as `cve-check`'s own NVD sync. `--kev-file`/`--epss-file`
accept pre-downloaded copies if you'd rather fetch outside the build
sandbox entirely, and `--offline` skips enrichment without failing the
run.

Runs through the real `do_je_cve_diff` task, not just as a standalone
script -- bitbake tasks are network-isolated by default, so
`do_je_cve_diff` declares `do_je_cve_diff[network] = "1"` and exports
`SSL_CERT_FILE` itself (probing common distro CA-bundle locations)
rather than assuming one is already set in the task environment.

## Package CVE triage -- kernel, u-boot, any package

`cve-check`'s version-range matching can't see stable/vendor-tree
backports already merged, or catch a CPE mismatch onto an unrelated
CVE entirely -- on a typical embedded target, the kernel alone can
account for the overwhelming majority of "unpatched" CVE hits, which
drowns out the handful that matter. `scripts/kernel_cve_triage.py`
automates the tractable part of that (never edits a recipe itself):

```
kernel_cve_triage.py PARSED_DIR KERNEL_GIT_DIR OUR_REF KCONFIG [PACKAGE] [OUT_PREFIX]
```

`PARSED_DIR` is a `parse_cve.py` output dir; `KERNEL_GIT_DIR` is the
real kernel source tree bitbake actually built from (e.g.
`build/tmp-glibc/work-shared/<machine>/kernel-source`); `OUR_REF` is
that tree's checked-out commit for this build (not a branch name --
those move); `KCONFIG` is your build's actual `.config`. Writes a
JSON+MD report, four buckets:

- **Config-inapplicable** -- the fix commit's own touched files map
  (via the governing `Makefile`'s `obj-$(CONFIG_X) += file.o`) to a
  Kconfig symbol that's flat-out not set in `KCONFIG` -- the
  vulnerable code was never compiled in, so the CVE can't be reached
  regardless of the fix's presence. Checked *before* the other
  buckets, since "the code isn't built" is a stronger answer than
  "here's its patch status".
- **Fixed-version candidates** -- the CVE summary names an upstream
  commit subject, found in the kernel mirror, and confirmed via `git
  merge-base --is-ancestor` as actually present in `OUR_REF` (not
  `--all`, which only proves the commit exists *somewhere* in the
  mirror). Safe to record as `CVE_STATUS[...] = "fixed-version: ..."`
  -- the exact line is included in the report, ready to review and
  paste in.
- **CPE mismatch candidates** -- summary doesn't mention "linux" or
  "kernel" at all (a common real-world case: an unrelated project's
  CVE mismatched onto the `linux_kernel` CPE). Needs a human to
  confirm before recording `CVE_STATUS[...] = "not-applicable-config: ..."`.
- **Needs human review** -- everything else, including a candidate
  commit matched by subject text but not confirmed as an ancestor of
  `OUR_REF` -- equivalent-but-different fix vs. genuinely open can't be
  told apart from commit presence alone.

Typical effect on a real kernel scan: roughly a tenth of "unpatched"
kernel CVEs get resolved automatically across the three buckets above,
each cited with the specific evidence used, leaving the rest correctly
flagged for human review rather than silently dismissed.

Performance note if you extend this: a per-CVE `git log --grep`
against a large mirror is fine alone but doesn't scale across
thousands of CVEs -- one upfront `git log --all --format=...` pass
building an in-memory subject-to-commit index is what makes this
tractable. Likewise, `git merge-base --is-ancestor` is far cheaper
with a commit-graph present (`git commit-graph write --reachable`,
one-time, same repo) than without. The script builds the commit-graph
itself (safe, idempotent, no tracked content touched) rather than
assume it exists.

### Beyond the kernel: u-boot, busybox, any package

`PACKAGE` and the CPE-mismatch keyword list are both parameters (an
optional 7th CLI arg, comma-separated -- defaults per-package:
`linux-ti-staging` -> `linux,kernel`; `u-boot-ti-staging` -> `u-boot,
uboot,das u-boot`; `busybox` -> `busybox`). Run against a package's own
git tree/`.config` the same way as the kernel (a real checkout under
`work/<machine>/<recipe>/<pv>/git`, a real `.config` under
`.../build/.config`, where the recipe builds one).

**Honest limitation**: the ancestor-check and config-inapplicable
buckets both depend on finding a specific commit via the CVE summary's
quoted subject line (a style common to kernel CVE records) --
bootloader CVEs are typically traditional human-written prose, so
neither of those two checks fires reliably there yet. Only the
CPE-mismatch keyword check applies across the board today; pick
keywords carefully -- a keyword that's also used in an unrelated
project's own advisory text can be actively counterproductive rather
than just useless.

## Chaining kernel triage into KEV/EPSS: noise-reduced prioritization

`scripts/prioritize_cves.py` -- runs KEV/EPSS triage (real-world
exploitation signal) against the *output* of `kernel_cve_triage.py`
(backport/config-noise reduction), not the raw unpatched CVE list.

```
prioritize_cves.py UNPATCHED_CSV KERNEL_TRIAGE_JSON OUT_PREFIX [--offline]
```

Why this matters: running KEV/EPSS against a raw unpatched-CVE list
can flag a CVE as confirmed actively exploited when it's actually a
CPE mismatch that `kernel_cve_triage.py` already knows about --
without chaining the two, an honest report can overstate real
exposure. Chained, the noise-reduced list is what's actually
"unresolved and either confirmed-exploited or high-probability" -- not
a bigger pile with a false positive baked in.

## Publishing to GitLab Pages

`scripts/publish_gitlab_pages.sh <store-root> <output-dir>` assembles
a ready-to-serve directory from a `JE_EVIDENCE_STORE` -- the vendored
`pages/` viewer plus the store, minus the multi-MB raw dumps. No
credentials needed: GitLab Pages auto-publishes any `public/` artifact
from a CI job literally named `pages`, using that job's own built-in
permissions.

```yaml
pages:
  stage: deploy
  image: alpine:3.20
  rules:
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
  before_script:
    - apk add --no-cache python3
  script:
    - meta-je-sbom-cve/scripts/publish_gitlab_pages.sh <path-to-your-store>/cve-reports public
  artifacts:
    paths:
      - public
```
