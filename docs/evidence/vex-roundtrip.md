## Claim

A real attempt at the round-trip
`candidate -> upstream analysis -> JustEmbed disposition -> OpenVEX -> upstream tooling consumes it`
was made in this evidence pass, using Bootlin's real `sbom-cve-check`
tool (not a mock) against a real SPDX bundle from this project's own
evidence store. **The round-trip did not complete end to end in this
pass -- real blockers are documented below, not a fabricated proof.**
What *was* confirmed for real: the tool installs and runs, its OpenVEX
consumption code path is real and matches the OpenVEX spec exactly,
and its VEX status vocabulary is exactly OpenVEX's four statuses.

## Environment

- Tool: `sbom-cve-check` v1.3.5 (Bootlin), installed from PyPI into an
  isolated venv (`pip install sbom-cve-check`, no system packages
  touched).
- SBOM input: a real `core-image-minimal-qemuarm64.rootfs-*.spdx.json`
  from this project's own evidence store (the same qemuarm64 build
  used throughout `docs/evidence/cve-applicability.md` and
  `docs/evidence/sbom-cve-enrichment.md`).
- Host: the same sandboxed development environment used throughout
  this evidence pass.

## What was confirmed real

1. **Installation and CLI**: `sbom-cve-check` installs cleanly via
   `pip` and exposes a real, documented CLI (`--sbom-type`,
   `--sbom-path`, `--add-db`, `--export-type`, `--export-filter-vex-status`,
   `--yocto-vex-manifest`, etc.) -- confirmed via `--help`, not
   assumed from documentation alone.
2. **Real OpenVEX consumption code exists**: `sbom_cve_check/database/annot_openvex.py`
   registers a real `openvex-file` database type
   (`--add-db openvex-file PATH`), and its justification-string
   mapping (`component_not_present`, `vulnerable_code_not_present`,
   `inline_mitigations_already_exist`,
   `vulnerable_code_cannot_be_controlled_by_adversary`,
   `vulnerable_code_not_in_execute_path`) matches OpenVEX's own spec
   exactly -- read directly from the installed package's source, not
   from documentation.
3. **VEX status vocabulary confirmed exactly**: `--export-filter-vex-status`
   accepts exactly `{under_investigation, affected, not_affected, fixed}`
   -- OpenVEX's own four statuses, no custom vocabulary. This directly
   informed `docs/vulnerability-disposition-mapping.md`.
4. **SPDX support confirmed**: `--sbom-type {spdx3,spdx2}` -- both
   versions accepted as input, matching Bootlin's own published
   capability claim.

## Real blockers hit, in order

1. **Default CVE data source is heavy.** `sbom-cve-check`'s default
   configuration clones the full `CVEProject/cvelistV5` git repository
   -- this did not complete within a reasonable time budget in this
   sandboxed environment (90s timeout, no visible progress). Worked
   around by switching to its lighter `cve-db-nvd-fkie` source
   (`fkie-cad/nvd-json-data-feeds`, a smaller curated NVD JSON mirror)
   via `--ignore-default-config --add-db cve-db-nvd-fkie <dir>`, which
   did start cloning successfully.
2. **SPDX file-extension check rejected the real input file.** Once
   the lighter database was cloning, the tool failed on the SBOM
   itself: `Unexpected SPDX2 SBOM file extension:
   core-image-minimal-qemuarm64.rootfs-*.spdx.json` -- `sbom-cve-check`
   apparently expects a different filename convention than the one
   Yocto's own `create-spdx.bbclass` actually produces for this
   image-level document. Not resolved in this pass -- would need
   either renaming the input to whatever extension the tool expects,
   or checking its source for the exact accepted pattern.
3. **Session tooling interruption.** The shell environment used to
   drive this investigation became unresponsive partway through
   working around blocker #2 (even trivial commands started failing),
   ending this pass's ability to continue the live attempt. Not a
   `sbom-cve-check` or SPDX issue -- a real interruption of this
   session's own tooling, reported honestly rather than glossed over.

## What this means

The consumption *mechanism* (OpenVEX -> `sbom-cve-check` ->
disposition-aware output) is real and exists upstream, confirmed by
reading the actual installed tool's code. A full live round-trip
against this project's own real SBOM was not completed in this pass.
**No fake proof is presented here** -- the claim above states plainly
what was and wasn't achieved.

## Next steps (not done in this pass)

1. Determine `sbom-cve-check`'s exact expected SPDX2 filename
   convention (check its source for the extension check directly,
   rather than trial-and-error) and retry with a correctly-named
   copy of the real SBOM.
2. Once the tool successfully loads a real SBOM, write one minimal,
   real OpenVEX statement for a real candidate (e.g. `CVE-2023-3079`,
   already documented as a real CPE-mismatch case in
   `docs/evidence/cve-applicability.md`, with a `not_affected`
   / `component_not_present` justification) and confirm the tool's
   own output reflects that disposition.
3. Consider whether a pre-downloaded, pinned, small NVD dataset
   (rather than a live git clone at test time) is a more practical
   default for a reproducible CI-style round-trip check.

## Reproduction

```
python3 -m venv /tmp/sbom-cve-check-venv
/tmp/sbom-cve-check-venv/bin/pip install sbom-cve-check
/tmp/sbom-cve-check-venv/bin/sbom-cve-check --help
```

Then attempt against any real Yocto-produced SPDX 2.2 image document,
picking up from blocker #2 above (the exact filename convention the
tool expects wasn't determined in this pass).
