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

**Status: signing mechanism verified with real cryptography.** The
built U-Boot's own device tree carries a genuinely embedded RSA-2048
public key with `required = "conf"` (verification is mandatory once
wired in, not merely possible), and the signed kernel/DT image carries
real, non-placeholder signature bytes matching that key -- confirmed
by decoding the actual output binaries, not by trusting a build's exit
code. Getting a signed image to actually *boot* the target end to end
is separate integration work per BSP (making sure every devicetree the
target needs is part of the signed image, then a real flashed-hardware
boot test) -- not yet demonstrated.

**Ceiling on some silicon, not a gap in this layer**: on a SoC whose
boot ROM performs no cryptographic check of the first-stage
bootloader (common on general-purpose, as opposed to
security-oriented, silicon tiers across most vendors), there is no
hardware root of trust under U-Boot. `je-secureboot` on such a target
can only ever be a chain starting *at* U-Boot -- FIT-signed
kernel/DT/rootfs verification -- never a full ROM-anchored chain of
trust, because U-Boot itself can't be attested. That's a property of
the silicon, not something this layer can close. A security-oriented
SoC variant is where a real hardware-anchored chain becomes possible.
This is also why this class doesn't chase `uboot-sign.bbclass`'s
deeper SPL-verifies-U-Boot link on such silicon: SPL itself is
unverified by the boot ROM there too, so that link would look like a
chain of trust without being an anchored one.

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
