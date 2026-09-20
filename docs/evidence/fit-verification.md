## Claim

`je-secureboot` produces a real, RSA-signed FIT image that U-Boot
verifies before booting -- a signed kernel+devicetree boots, a
tampered one is rejected -- not just a build that completes without
error.

## Environment

- Yocto version / branch: scarthgap (Poky)
- MACHINE: `qemuarm64`
- Target/platform: QEMU (`qemu-system-aarch64`, `-machine virt -cpu
  cortex-a57`), not real hardware
- Relevant layers: `meta-je-boot-update` (`je-secureboot.bbclass`),
  OpenEmbedded-core's `kernel-fitimage.bbclass` and
  `uboot-sign.bbclass`, `meta-je-example-bsp`'s own
  `recipes-bsp/u-boot/u-boot_%.bbappend` and
  `recipes-bsp/devicetree/` (the consuming-BSP-side wiring
  `je-secureboot.bbclass` deliberately leaves to the adopter)

## Setup

`kas build kas.yml` against `meta-je-example-bsp` (RSA-2048 dev keypair
generated and committed there for reproducibility; `je-secureboot`
inherited, `uboot-sign.bbclass` wired onto the U-Boot recipe, a
captured QEMU devicetree provided as `virtual/dtb` -- see that repo's
README for why each of those is needed). Produces a signed `fitImage`
and a U-Boot binary whose devicetree carries the matching public key.

## Test

Boot U-Boot as the real bootloader (not `runqemu`'s default fast path,
which loads the kernel directly and never exercises U-Boot), load the
signed FIT via QEMU's fw_cfg device, and `bootm` it naming the FIT
configuration explicitly. Full setup and exact commands: see
`meta-je-example-bsp`'s README, "Secure boot, verified live" section.

Positive case: `bootm <addr>#conf-qemu-virt.dtb` on the real,
build-produced signed `fitImage`.

Negative case: same command against a copy of the same `fitImage` with
a single byte flipped inside the kernel payload.

## Expected result

Positive: U-Boot verifies both the kernel and devicetree images'
signatures and boots. Negative: U-Boot detects the corrupted payload
and refuses to boot it.

## Actual result

Positive case, real console output:

```
   Verifying Hash Integrity ... OK
   ...
   Verifying Hash Integrity ... sha256+ OK
## Loading fdt from FIT Image at 40400000 ...
   ...
   Verifying Hash Integrity ... sha256+ OK
   Booting using the fdt blob at 0x40c95920
```

(the `+` marks a signature-backed check, not a bare hash) -- followed
by a real Linux boot to a `qemuarm64 login:` prompt, with
`je-detection-agent` running as a live service on the booted system.

Negative case, real console output:

```
   Verifying Hash Integrity ... sha256 error!
Bad hash value for 'hash-1' hash node in 'kernel-1' image node
Bad Data Hash
ERROR: can't get kernel image!
```

## Raw evidence

The console output above is the raw evidence for this entry -- both
transcripts are direct copies of the real U-Boot serial console, not
summarized or reconstructed from memory.

## What FIT protects, and where the chain actually starts

- **What's protected**: the kernel image and devicetree blob, as a
  single signed FIT configuration (`sign-images = "kernel", "fdt"`) --
  not the root filesystem, and not U-Boot itself.
- **Where the key lives**: the *public* half is embedded in U-Boot's
  own devicetree at build time (`uboot-sign.bbclass`, `required =
  "conf"` -- verification is mandatory, not optional). The *private*
  half signs the FIT at build time and never ships on the target.
- **Where the trust chain begins**: at U-Boot. Nothing before U-Boot is
  verified in this reference implementation -- see the stage-by-stage
  table in `docs/update-boot.md`.
- **Why QEMU isn't proof of an immutable hardware root of trust**: QEMU
  has no boot-ROM concept at all -- U-Boot is loaded directly by the
  emulator with no verification step before it. This entry proves the
  FIT signature mechanism is real and correctly rejects tampering; it
  says nothing about whether any given real SoC's boot ROM verifies
  U-Boot itself. That's a separate, per-silicon property -- see
  `docs/update-boot.md`.

## Limitations

- QEMU-only. This does not demonstrate a hardware root of trust -- see
  `meta-je-boot-update/README.md`'s own note on SoCs whose boot ROM
  doesn't cryptographically verify the first-stage bootloader: on such
  silicon (and on QEMU, which has no boot-ROM verification concept at
  all), the verified chain starts *at* U-Boot, not before it.
- The dev signing key shipped in `meta-je-example-bsp` is a throwaway
  keypair for reproducibility, explicitly not for production use (see
  that repo's own key README).
- Booting the signed image to a login prompt currently requires driving
  U-Boot by hand at its console (`qfw load` + `bootm`), not an
  automatic boot script -- QEMU's generic `virt` machine has no
  compiled-in board boot command the way a real board would.

## Reproduction

Follow `meta-je-example-bsp`'s README, "Secure boot, verified live"
section, verbatim -- it gives the exact `qemu-system-aarch64`
invocation, the exact U-Boot commands, and how to reproduce the
tampering step. No physical hardware required.
