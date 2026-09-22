# Questions for upstream maintainers

Concrete, short questions arising from this project's upstream-
alignment review (see `docs/evidence-upstream-alignment-plan.md`).
Not yet sent anywhere -- kept here as a real, specific list rather
than a general "we should ask upstream sometime" note.

1. **`sbom-cve-check` extension point**: is the intended way for a
   downstream layer to add enrichment (KEV/EPSS, product context) a
   plugin (`--plugins PATH` exists in the CLI already) or should
   third-party tooling consume its export output (`csv`, `spdx3`,
   `yocto-cve-check-manifest`) instead?
2. Related: should a layer like `meta-je-sbom-cve` extend
   `sbom-cve-check`'s own class/API once `meta-sbom-cve-check`'s
   OE-core integration lands, or keep consuming its report output at
   arm's length?
3. **Preferred VEX format going forward**: OpenVEX is confirmed
   consumed today; is OpenVEX also the intended *authoring* format for
   third-party disposition evidence, or is the "Yocto Project VEX
   manifest" format (`--yocto-vex-manifest`) preferred for
   Yocto-originated dispositions specifically?
4. **Product-context disposition representation**: OpenVEX's
   standard justifications cover code-level "not affected" reasons
   (component/code not present, etc.) -- is there a recommended way to
   express a *product-level* "not affected because this feature/
   service is disabled in this specific image" that isn't purely a
   code-presence fact?
5. **SPDX 3 interface stability**: how stable is `create-spdx-3.0.bbclass`'s
   output shape expected to be across Yocto releases, for a downstream
   parser (like this project's `spdx_components.py`) planning to
   depend on it?
6. **Where should KEV/EPSS enrichment live**: is there any interest
   in `sbom-cve-check` itself gaining KEV/EPSS as optional data
   sources, or is real-world-exploitation enrichment considered
   intentionally out of scope for that tool (leaving it to
   downstream, as this project currently does)?
7. **`improve_kernel_cve_report.py` stability/roadmap**: is this
   script expected to remain a `scripts/contrib/` utility, or is
   there a plan to integrate it more tightly with `cve-check.bbclass`/
   `sbom-cve-check` as a build-time or re-scan-time task?
