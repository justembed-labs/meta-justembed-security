## Claim

`je-swupdate-fota` performs a real signed A/B update on QEMU, proven
both ways: a valid signed `.swu` is verified and written to the
inactive partition, the system boots the new copy, and the correct
slot is active afterward; a tampered `.swu` is rejected before any
write occurs -- both confirmed against actual disk state, not
inferred from log messages.

## Environment

- Yocto version / branch: scarthgap (Poky)
- MACHINE: `qemuarm64`
- Target/platform: QEMU (`qemu-system-aarch64`, virtio-blk disk), not
  real hardware
- Relevant layers: `meta-je-boot-update` (`je-swupdate-fota.bbclass`),
  `meta-swupdate`, `meta-je-example-bsp`'s own dual-copy partition
  layout, `sw-description`, and activation/select/commit recipes (the
  board-specific half `je-swupdate-fota.bbclass` deliberately leaves
  to the adopter, same as this class's own documented design)

## Setup

`kas build kas.yml` produces `core-image-minimal-qemuarm64.rootfs.wic`
(a 4-partition disk: `boot`, `rootA`, `rootB`, `state`) and, via
`bitbake -c swuimage update-image`, a signed `.swu` bundling the new
rootfs image plus two activation scripts (one per target copy). Same
dev RSA keypair as `je-secureboot`'s.

## Test

**Positive case:**
1. Boot the system from `rootA`.
2. Copy the signed `.swu` onto the running system (a second, temporary
   virtio-blk "disk" carrying the raw `.swu` bytes, `dd`'d off onto
   the persistent rootfs -- a test-harness detail, not part of the
   update mechanism itself).
3. Run `je-swupdate-select /path/to/update.swu`, which reads the
   running system's own `root=` to pick the *other* copy and invokes
   `swupdate -i ... -e stable,copyN -k /etc/swupdate.pem -m`.

**Negative case:** same starting disk snapshot, same procedure, but
with one byte flipped in the copied `.swu` (offset 23144448 of
46288896 bytes, inside the compressed rootfs payload -- well past any
cpio header, so the archive structure itself stays parseable and only
the payload content changes) via `je-swupdate-select
/root/update-tampered.swu`.

## Expected result

Positive: swupdate verifies the signature, writes the new rootfs to
the inactive partition, and the activation script records the
candidate slot on the state partition. Negative: swupdate detects the
per-file hash mismatch and refuses to install, before any write to
the inactive partition or the state partition.

## Actual result

**Positive case**, real console output:

```
[INFO ] : SWUPDATE running :  Installation in progress
[INFO ] : SWUPDATE successful ! SWUPDATE successful !
```

confirmed against real disk state (state partition mounted directly
and read back, not inferred from the log line above):

```
rootpart=3
bootstate=trial
```

Continuing to the next boot (see `docs/update-boot.md` for the full
trial-boot sequence): the kernel mounts the *new* filesystem's own UUID
(`7d124cd8-...`) -- the candidate slot is genuinely the one that boots.

**Negative case**, real console output:

```
[INFO ] : SWUPDATE started :  Software Update started !
[ERROR] : SWUPDATE failed [0] ERROR : HASH mismatch : dd81c50e889fbffd8cc2ba94f6de94146a495d2be0b1554d95c2c9c489216ef9 <--> b5ea36f327f42043ff80b3facd246be8c74e78ac3afa960d575697263abe902e
[ERROR] : SWUPDATE failed [1] Image invalid or corrupted. Not installing ...
[ERROR] : SWUPDATE failed [0] ERROR : SWUpdate *failed* !
```

confirmed against real disk state: the state partition's `bootstate`
file still reads `good` (its pre-attempt value) after the rejected
attempt -- no write, no arming, no candidate recorded.

## Raw evidence

The console transcripts and the disk-state reads above are direct
output from the real test runs.

## Limitations

- QEMU-only; not run against real hardware in this evidence entry (a
  real-hardware A/B cycle, on different hardware, is separately
  documented as hardware-verified in `meta-je-boot-update/README.md`,
  with its own limitations noted there).
- The U-Boot trial-boot check is driven by hand at the console in this
  example, standing in for a real board's own compiled-in boot script
  -- see `docs/update-boot.md`.
- `qemu_arm64_defconfig`'s U-Boot has no ext4 write support; the
  `boot`/`state` partitions in this example are `vfat` for that reason
  (the mirror image of a real hardware target's own U-Boot, which can
  just as easily have ext4 write but no FAT write command -- pick
  whichever write path is real for the target).
- The dev signing key shipped in `meta-je-example-bsp` is a throwaway
  keypair for reproducibility, explicitly not for production use.
- The "health decision" that leads to committing this update is
  binary and shallow (reached multi-user boot) -- see
  `docs/evidence/ab-rollback.md` and `docs/update-boot.md`.
- The negative case catches a **payload hash mismatch**, protected by
  the RSA signature over `sw-description` (which declares that hash)
  -- the same trust boundary as `docs/evidence/signed-rule-update.md`'s
  negative case. A stripped/corrupted `sw-description.sig` itself
  (signature-only tamper, hash left intact) was not separately tested
  here.

## Reproduction

Follow `meta-je-example-bsp`'s README, "FOTA, verified live" section,
verbatim -- exact partition layout, exact `swupdate` invocation. No
physical hardware required.
