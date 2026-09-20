## Claim

`je-swupdate-fota` performs a real signed A/B update on QEMU, and the
trial-boot/rollback mechanism genuinely goes both ways: a committed
update stays on the new copy on the next boot, and an update that's
armed but never confirmed (simulated crash) reverts to the original
copy -- confirmed against actual disk state, not inferred from log
messages.

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

## Test

1. Apply a real signed `.swu` update (built via `bitbake -c swuimage
   update-image`) against the running system's own inactive copy via
   `je-swupdate-select`.
2. Reboot; at the U-Boot prompt, read the persisted state and arm a
   trial boot (standing in here for what a real board's compiled-in
   boot script would do automatically -- QEMU's generic `virt` machine
   has no such script).
3. Branch A (success path): let the system boot normally, let
   `je-swupdate-commit` run, reboot again, confirm the system stays on
   the new copy.
4. Branch B (rollback path): from the same post-activation disk state,
   kill the VM right after arming the trial and before any commit could
   run, then reboot and confirm the system reverts to the original
   copy.

Full setup and exact commands: `meta-je-example-bsp`'s README, "FOTA,
verified live" section.

## Expected result

Branch A: the system boots the new copy again after a committed
update, no revert. Branch B: the system reverts to the original,
previously-running copy after an uncommitted (crashed) update attempt.

## Actual result

The update itself, real console output:

```
[INFO ] : SWUPDATE running :  Installation in progress
[INFO ] : SWUPDATE successful ! SWUPDATE successful !
```

confirmed against real disk state (state partition mounted directly
and read back):

```
rootpart=3
bootstate=trial
```

Branch A (committed): after `je-swupdate-commit` runs and the system
reboots again, the state partition's marker file reads
`bootstate=good`, and the kernel mounts the *same* filesystem UUID
(`7d124cd8-...`) that swupdate wrote -- confirmed the system stayed on
the new copy, not inferred.

Branch B (uncommitted, simulated crash): the next U-Boot boot reads
`bootstate=trying` (never cleared), reverts `rootpart` to the other
copy, and the kernel mounts the *original* rootfs filesystem's own UUID
(`03f759c3-...`, the one present before the update was ever applied) --
confirmed the system reverted, not inferred.

## Limitations

- QEMU-only; not run against real hardware in this evidence entry (a
  real-hardware A/B cycle, on different hardware, is separately
  documented as hardware-verified in `meta-je-boot-update/README.md`,
  with its own limitations noted there).
- The U-Boot trial-boot check is driven by hand at the console in this
  example, standing in for a real board's own compiled-in boot script
  -- see the README section for exactly which commands and why.
- `qemu_arm64_defconfig`'s U-Boot has no ext4 write support; the
  `boot`/`state` partitions in this example are `vfat` for that reason
  (the mirror image of the real AM335x hardware's own U-Boot, which
  has ext4 write but no FAT write command -- pick whichever write path
  is real for the target).
- The dev signing key shipped in `meta-je-example-bsp` is a throwaway
  keypair for reproducibility, explicitly not for production use.

## Reproduction

Follow `meta-je-example-bsp`'s README, "FOTA, verified live" section,
verbatim -- it gives the exact partition layout, the exact `swupdate`
invocation, and the exact U-Boot commands for both the success and
rollback branches. No physical hardware required.
