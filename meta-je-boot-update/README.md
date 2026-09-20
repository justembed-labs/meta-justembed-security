# meta-je-boot-update

Secure boot + atomic FOTA layer: `je-secureboot.bbclass` (U-Boot
verified boot) and `je-swupdate-fota.bbclass` (signed A/B firmware
updates over swupdate).

## `je-swupdate-fota`

Wraps `meta-swupdate` + swupdate's own built-in webserver mode
(accepts a pushed update directly) -- no device-management backend
required for a working setup.

```
IMAGE_CLASSES += "je-swupdate-fota"
```

adds swupdate to the image (agent, webserver mode, the raw `ext4.gz`
output format swupdate needs to write to an inactive copy partition).
Deliberately generic: building the actual update bundle needs a real
dual-copy partition layout, a real `sw-description`, and bootloader
integration, all genuinely board-specific -- a consuming BSP defines
its own update-image recipe inheriting `swupdate` (from `meta-swupdate`
itself) with its own `sw-description`, the same pattern
`meta-swupdate-boards` uses for its own per-board examples.

**Hardware-verified**: a signed, hash-checked update was written to
both A/B partitions on real hardware, in both directions, with a real
reboot and a real trial-boot commit/rollback-arm confirmed each time.
A second, independent update for `meta-je-detection`'s own rule bundle
(signed, no-reboot, service-reinit-only) has also been verified live
on hardware -- see `meta-je-detection/README.md`.

**Also demonstrated on QEMU**, independently, both directions: a
committed update stays on the new copy, an update that's armed but
never confirmed (simulated crash) reverts to the original copy --
confirmed against real disk state (filesystem UUIDs), not inferred
from log output. See `docs/evidence/je-swupdate-fota-ab-cycle.md` and
`meta-je-example-bsp`'s README for the exact commands.

**Push-mode only, no outbound update-polling today.** swupdate's
built-in webserver mode needs something to reach *the device* to push
an update -- fine on a local network, not realistic for a device
behind NAT/cellular with no direct inbound path. swupdate's own
`suricatta` daemon mode (device polls a remote server, typically
hawkBit, for updates) is the real fix for that when a deployment needs
it.

## `je-secureboot`

Reuses OpenEmbedded-core's own `kernel-fitimage.bbclass` +
`uboot-sign.bbclass` for FIT signing rather than custom tooling.

```
INHERIT += "je-secureboot"
```

wires `KERNEL_CLASSES`/`KERNEL_IMAGETYPE=fitImage` and the shared
signing-key variables on the kernel recipe. What it deliberately can't
do -- enabling `CONFIG_FIT`/`CONFIG_FIT_SIGNATURE`/`CONFIG_RSA` in the
target's own U-Boot `.config`, and inheriting `uboot-sign.bbclass` on
the BSP's own U-Boot recipe -- is genuinely board-specific and wired
there instead (`u-boot.bbclass` has no kernel-style `.cfg`
fragment-merge mechanism, so this is typically a small
`do_configure:append()` on the U-Boot recipe).

**Status: signing mechanism verified with real cryptography, and
demonstrated end to end on QEMU.** The built U-Boot's own device tree
carries a genuinely embedded RSA-2048 public key with `required =
"conf"` (verification is mandatory once wired in, not merely
possible), and the signed kernel/DT image carries real,
non-placeholder signature bytes matching that key -- confirmed by
decoding the actual output binaries, not by trusting a build's exit
code. On QEMU, this has been carried all the way through: U-Boot
verifying the signature, booting the verified kernel and devicetree,
and reaching a real Linux login prompt -- and, separately, correctly
*rejecting* a tampered image. See `docs/evidence/je-secureboot-fit-verification.md`.

**Not yet demonstrated: the same boot-to-login proof on real hardware.**
Getting a signed image to actually boot a real target end to end is
separate integration work per BSP (making sure every devicetree the
target needs is part of the signed image, then a real flashed-hardware
boot test).

### Where the verified chain actually starts and stops

For the current QEMU reference implementation
(`meta-je-example-bsp`), stage by stage:

| Stage | Present here? | Cryptographically verified? |
|---|---|---|
| Boot ROM | QEMU has no boot-ROM concept -- firmware (U-Boot) is loaded directly by the emulator. | No -- there is nothing to verify it. |
| SPL | Not used in this reference implementation. | N/A |
| U-Boot | Yes (the bootloader itself). | No -- U-Boot is not attested by anything before it. It is the root of trust for everything *after* it, not itself verified. |
| FIT (kernel + devicetree) | Yes. | **Yes** -- RSA-2048 signature checked by U-Boot before boot; a tampered image is rejected. |
| Root filesystem | Yes. | No boot-time verification. `meta-je-sbom-cve`/`je-swupdate-fota` check a per-file SHA-256 of the rootfs image *at update time*, not on every boot. |

The same table applies conceptually to a real board, with two
differences: a real SoC's boot ROM may or may not verify the
first-stage bootloader (a property of the silicon, checked per
target), and a real BSP typically has an SPL stage between ROM and
U-Boot. On silicon whose boot ROM doesn't verify the first-stage
bootloader (common on general-purpose, as opposed to security-oriented,
silicon tiers across most vendors), the verified chain can only ever
start *at* U-Boot, same as on QEMU -- not a gap in this layer, a
property of the silicon tier. A security-oriented SoC variant with
boot-ROM verification is where a real hardware-anchored chain becomes
possible; this layer doesn't chase `uboot-sign.bbclass`'s deeper
SPL-verifies-U-Boot link on silicon where SPL itself is unverified by
the boot ROM, since that link would look like a chain of trust without
being an anchored one.

## CRA Annex I connection

Secure boot and update-integrity are the technical, structural side of
the EU Cyber Resilience Act's essential cybersecurity requirements
(Annex I) -- protection from unauthorized modification, a documented
mechanism for delivering security updates. This is a build-time/
boot-time technical mechanism, **not a legal CRA conformity
determination**: the tooling proves what's technically true about a
build and its update path; whether that satisfies CRA obligations for
a given product is a legal question outside this layer's scope.

## Staying hardware-agnostic

This layer should only ever contain what works unmodified on any
Yocto BSP -- the real precedent is `meta-swupdate` (generic) vs.
`meta-swupdate-boards` (one directory per board). Board-specific
content -- a bootloader's A/B boot script, bootcount handling, a given
SoC's secure-boot ceiling -- is expected to be proven out in the
adopting BSP first, and promoted into a separately-maintained
companion layer once it's real and verified across more than one
target, not before.
