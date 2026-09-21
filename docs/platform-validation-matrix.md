# Platform validation matrix

> This matrix tracks what has actually been built, tested and
> evidenced on each platform. `Planned` entries are roadmap items and
> must not be interpreted as supported configurations.

This is explicitly **not** a support matrix and **not** a
compatibility guarantee -- it is a validation roadmap / evidence
index. A row's status reflects what has been reproducibly
demonstrated (linked below) or hardware-verified and documented
elsewhere in this project, never an aspiration.

| Platform | SoC / Board | Yocto release | Branch / BSP | Build | Hygiene | Evidence | Detect | Update | Boot verification | Resource tests | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|
| QEMU | `qemuarm64` | scarthgap (5.0.20) | `meta-je-example-bsp`, `main` | Demonstrated | Demonstrated | Demonstrated | Demonstrated | Demonstrated | FIT verified in QEMU (not a hardware root of trust -- see `docs/update-boot.md`) | [Measured](evidence/detection-resource-measurements.md) | Reference |
| Embedian | TI AM335x | TBD | TBD | Planned | Planned | Planned | Planned | Planned | Planned | Planned | Planned |
| NXP | i.MX6 SOM | TBD | TBD | Planned | Planned | Planned | Planned | Planned | Planned | Planned | Planned |
| NXP | i.MX8 | TBD | TBD | Planned | Planned | Planned | Planned | Planned | Planned | Planned | Planned |
| BeagleBone | AM335x | TBD | TBD | Planned | Planned | Planned | Planned | Planned | Planned | Planned | Planned |

Detailed BSP/kernel/U-Boot revisions belong in the platform-specific
evidence document (`docs/platforms/`, see that directory's own
`README.md`), not in this top-level matrix.

## Column definitions

- **Build**: does a real image build succeed on this platform.
- **Hygiene / Evidence / Detect / Update**: does the corresponding
  `meta-je-*` building block run and produce evidence on this
  platform (see `docs/architecture.md` for what each block is).
- **Boot verification**: intentionally not a single checkbox. Use
  precise wording per platform, e.g. `FIT verified`, `Bootloader
  authenticated`, `Hardware root of trust`, `Full chain verified`,
  `Partial`, `Not tested`, `Not available`, `Planned`. **QEMU's `FIT
  verified in QEMU` is not the same claim as a hardware-anchored root
  of trust** -- see `docs/update-boot.md`'s stage-by-stage table for
  exactly what QEMU does and doesn't prove, and never read a future
  hardware row's status as equivalent to QEMU's just because both
  contain the word "verified."
- **Resource tests**: `Measured` (see
  `docs/evidence/detection-resource-measurements.md`), `Planned`, or
  `Not run`.
- **Status**: `Reference` (the primary example platform this project
  develops and evidences against), `Planned` (roadmap, not yet
  started), or, once real hardware work begins,
  `In progress`/`Demonstrated`/`Tested` per `PROJECT.md`'s maturity
  model -- never `Supported`, which this project reserves for a
  maintained reproduction path an external adopter can run themselves
  (not yet reached by any platform, including QEMU, as of this
  writing).

## Why these five rows

QEMU is the current reference implementation
(`meta-je-example-bsp`), already evidenced throughout `docs/evidence/`.
The four physical platforms are the near-term hardware validation
roadmap -- each will get its own entry in `docs/platforms/` and a row
update here **only** as real build/boot/evidence work actually
happens on it, one platform at a time, never in advance of that work.
