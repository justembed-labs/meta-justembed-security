# meta-je-boot-update

Secure boot + atomic FOTA: `je-secureboot.bbclass` (U-Boot verified
boot) and `je-swupdate-fota.bbclass` (signed A/B firmware updates over
swupdate).

## What it does

- **`je-swupdate-fota`** wraps `meta-swupdate` + swupdate's own
  built-in webserver mode (accepts a pushed update directly, no
  device-management backend required). Adds swupdate to the image and
  the `ext4.gz` output format it needs to write an inactive copy
  partition. Building the actual update bundle is board-specific
  (real dual-copy partition layout, `sw-description`, bootloader
  integration) -- a consuming BSP defines its own update-image recipe
  inheriting `swupdate`, the same pattern `meta-swupdate-boards` uses.
- **`je-secureboot`** reuses OpenEmbedded-core's own
  `kernel-fitimage.bbclass` + `uboot-sign.bbclass` for FIT signing
  rather than custom tooling -- wires `KERNEL_CLASSES`/
  `KERNEL_IMAGETYPE=fitImage` and the shared signing-key variables on
  the kernel recipe. Enabling `CONFIG_FIT`/`CONFIG_FIT_SIGNATURE`/
  `CONFIG_RSA` in the target's own U-Boot `.config` and inheriting
  `uboot-sign.bbclass` on the BSP's U-Boot recipe is genuinely
  board-specific and stays there instead.

Full trust-chain breakdown (what's verified, by what, anchored where):
[`docs/update-boot.md`](../docs/update-boot.md).

## Requirements

- `je-swupdate-fota`: an A/B-style partition layout compatible with
  swupdate's raw-write mode.
- `je-secureboot`: a U-Boot build with FIT signature support
  (`CONFIG_FIT`, `CONFIG_FIT_SIGNATURE`, `CONFIG_RSA`,
  `CONFIG_OF_SEPARATE`).

## Enable it

```
IMAGE_CLASSES += "je-swupdate-fota"
INHERIT += "je-secureboot"
```

Each is independent -- adopt either without the other.

## Quick test

See [`meta-je-example-bsp`](https://github.com/justembed-labs/meta-je-example-bsp)
for a complete, working `kas.yml` that wires both in on QEMU, with the
exact boot/update commands.

## Configuration

- `je-swupdate-fota`: signing key variables, `sw-description`, and A/B
  partition layout are all board-specific -- see the class's own
  comments and `meta-je-example-bsp`'s `kas.yml` for a real example.
- `je-secureboot`: shares its signing-key variables with
  `je-swupdate-fota`'s update signing by convention, not by
  requirement.

## Known limitations

- **Push-mode only, no outbound update-polling today.** swupdate's
  webserver mode needs something to reach *the device* to push an
  update -- fine on a local network, not realistic behind NAT/cellular
  with no inbound path. swupdate's own `suricatta` daemon mode (device
  polls a remote server, typically hawkBit) is the fix for that when a
  deployment needs it.
- **No staged/canary rollout, no application-level health check**
  beyond "reached multi-user boot" -- see
  [`docs/update-boot.md`](../docs/update-boot.md).
- **Real-hardware boot-to-login not yet demonstrated for
  `je-secureboot`.** The signing mechanism is verified with real
  cryptography and demonstrated end to end (including tamper
  rejection) on QEMU; getting a signed image to boot a real target
  end to end is separate per-BSP integration work.
- **This layer stays hardware-agnostic by design.** Board-specific
  content (a bootloader's A/B boot script, bootcount handling, a given
  SoC's secure-boot ceiling) is expected to be proven out in the
  adopting BSP first, and promoted into a separately-maintained
  companion layer once it's real and verified across more than one
  target -- the same precedent as `meta-swupdate` (generic) vs.
  `meta-swupdate-boards` (per-board).

## CRA relevance

Secure boot and update-integrity are the technical, structural side of
CRA Annex I's protection-from-unauthorized-modification and
secure-update-delivery requirements -- a technical mechanism, not a
legal conformity determination. See
[`CRA_TECHNICAL_MAPPING.md`](../CRA_TECHNICAL_MAPPING.md).

## More documentation

- [`docs/update-boot.md`](../docs/update-boot.md) -- full trust-chain
  table, firmware/rule-update flow diagrams.
- [`docs/evidence/signed-ab-update.md`](../docs/evidence/signed-ab-update.md),
  [`docs/evidence/ab-rollback.md`](../docs/evidence/ab-rollback.md) --
  A/B update and rollback, QEMU.
- [`docs/evidence/fit-verification.md`](../docs/evidence/fit-verification.md) --
  FIT verification, valid and tampered, QEMU.
- [`docs/evidence/signed-rule-update.md`](../docs/evidence/signed-rule-update.md) --
  `meta-je-detection`'s independent rule-bundle update, valid and
  tampered, QEMU.
- Real-hardware A/B and rule-bundle-update verification: see
  `meta-je-detection/README.md`'s "Verified on real hardware" section
  (same hardware run covers both).
