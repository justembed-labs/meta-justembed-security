# Roadmap

Themes, not a schedule -- no dates are implied or promised. See
`PROJECT.md` for the maturity model these themes are measured against.

## Current focus

- External usability -- can an engineer outside JustEmbed adopt a
  layer from the README alone.
- Reproducible evidence -- `docs/evidence/` growing to cover every
  claim currently made in prose only.
- Compatibility -- confirming behavior across more than the one Yocto
  release/target combination each layer has been run against so far.
- CVE/applicability quality -- reducing `meta-je-sbom-cve`'s remaining
  "needs human review" bucket without weakening its evidence citations.
- Resource measurements -- real numbers (image size, boot time, memory)
  for adopters evaluating cost, not just functional claims.

## Next

- VEX (Vulnerability Exploitability eXchange) feasibility: whether
  `meta-je-sbom-cve`'s existing triage buckets can be expressed as a
  standard VEX status output.
- A broader CI compatibility matrix (more machines, more Yocto
  releases).
- A first real-hardware reference platform published alongside the
  QEMU-based `meta-je-example-bsp`, so hardware-verified claims have a
  reproducible path an external adopter can also follow.

## Later

- A constrained industrial HMI/gateway deployment profile.
- Offline operation (no assumption of a reachable backend).
- Bounded resource behavior on more constrained targets.
- Staged/manual detection-rule activation workflows.
- IEC 62443 technical mapping (engineering-level mapping only, not a
  certification claim).
- An OT-adjacent reference architecture.

## Explicitly outside current scope

- Safety Instrumented System (SIS) runtime integration.
- A plant-wide OT security platform.
- Any certification or regulatory-compliance claim.
