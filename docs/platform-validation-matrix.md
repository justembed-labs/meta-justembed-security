# Platform validation matrix

> This matrix tracks what has actually been built, tested and
> evidenced on each platform. `Planned` entries are roadmap items and
> must not be interpreted as supported configurations.

This is explicitly **not** a support matrix and **not** a
compatibility guarantee -- it is a validation roadmap / evidence
index. A row's status reflects what has been reproducibly
demonstrated (linked below) or hardware-verified and documented
elsewhere in this project, never an aspiration.

| Platform | SoC / Board | Yocto release | Branch / BSP | Build | Hygiene | Evidence | Detect | Signed Update | Rollback | Boot verification | Resource tests | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| QEMU | `qemuarm64` | scarthgap (5.0.20) | `meta-je-example-bsp`, `main` | Demonstrated | Demonstrated | Demonstrated | Demonstrated | Demonstrated | Demonstrated | FIT verified in QEMU (not a hardware root of trust -- see `docs/update-boot.md`) | [Measured](evidence/detection-resource-measurements.md) | Reference |
| TI | AM335x SOM | TBD | TBD | Planned | Planned | Planned | Planned | Planned | Planned | Planned | Planned | Planned |
| NXP | i.MX6 SOM | TBD | TBD | Planned | Planned | Planned | Planned | Planned | Planned | Planned | Planned | Planned |
| NXP | i.MX8 | TBD | TBD | Planned | Planned | Planned | Planned | Planned | Planned | Planned | Planned | Planned |
| BeagleBone | AM335x | TBD | TBD | Planned | Planned | Planned | Planned | Planned | Planned | Planned | Planned | Planned |

See [`docs/platforms/qemuarm64.md`](platforms/qemuarm64.md) for QEMU's
full evidence breakdown, one link per capability -- this row is a
summary, not the evidence itself.

## Boot trust, precisely

QEMU's `Demonstrated` FIT verification above is a real, verified step
-- it is **not** the same claim as a hardware-anchored secure boot
chain. Folding "verified" for both into one word would make a future
physical platform's row look equivalent to QEMU's just because both
say "verified." This table breaks the chain into its real stages
instead, matching [`docs/update-boot.md`](update-boot.md)'s
stage-by-stage framing exactly:

| Platform | ROM authentication | SPL authentication | U-Boot authentication | FIT verification | Hardware root of trust |
|---|---|---|---|---|---|
| QEMU | N/A -- no boot-ROM concept, firmware loaded directly by the emulator | N/A -- not used in this reference implementation | N/A -- nothing attests U-Boot itself before it runs | Demonstrated -- [`docs/evidence/fit-verification.md`](evidence/fit-verification.md), real signed-boot and real tamper-rejection | N/A |
| TI | Planned | Planned | Planned | Planned | Planned |
| NXP i.MX6 | Planned | Planned | Planned | Planned | Planned |
| NXP i.MX8 | Planned | Planned | Planned | Planned | Planned |
| BeagleBone | Planned | Planned | Planned | Planned | Planned |

Never write "Secure boot demonstrated" for any row in this table.
Use the precise term for what was actually verified: `FIT verified`,
`Bootloader authenticated`, `Hardware root of trust`, `Full chain
verified`, `Partial`, or `Not tested`.

Detailed BSP/kernel/U-Boot revisions belong in the platform-specific
evidence document (`docs/platforms/`, see that directory's own
`README.md`), not in this top-level matrix.

## Column definitions

- **Build**: does a real image build succeed on this platform.
- **Hygiene / Evidence / Detect**: does the corresponding `meta-je-*`
  building block run and produce evidence on this platform (see
  `docs/architecture.md` for what each block is).
- **Signed Update / Rollback**: `je-swupdate-fota`'s two separate
  real-world claims -- a signed update is verified and applied
  (`Signed Update`), and a bad/unconfirmed update actually reverts
  (`Rollback`). Keep them separate: a platform can demonstrate one
  without the other (e.g. update flashing proven before rollback
  testing happens).
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
