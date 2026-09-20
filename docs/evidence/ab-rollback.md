## Claim

`je-swupdate-fota`'s trial-boot rollback genuinely goes both ways: a
committed update stays on the new copy on the next boot, and an
update that's armed but never confirmed (simulated crash, before any
health decision) reverts to the original copy -- confirmed against
actual disk state, not inferred from log messages.

## Environment

- Yocto version / branch: scarthgap (Poky)
- MACHINE: `qemuarm64`
- Target/platform: QEMU, not real hardware
- Relevant layers: `meta-je-boot-update` (`je-swupdate-fota.bbclass`),
  `meta-je-example-bsp`'s own state-partition trial-boot mechanism

## Setup

Starting from the same post-activation disk state as
`docs/evidence/signed-ab-update.md` (a real signed update already
written to the inactive copy, state partition already reading
`rootpart=<N>` / `bootstate=trial`), snapshotted before either branch
below so both start from an identical, real starting point.

## Test

**Branch A (success path)**: boot normally, arm the trial (write a
`trying` marker before booting the candidate -- standing in here for
what a real board's compiled-in boot script would do), let the system
reach multi-user boot, let `je-swupdate-commit` run, reboot again.

**Branch B (rollback path)**: from the identical starting snapshot,
arm the trial the same way, then kill the VM immediately afterward --
before the candidate ever boots to multi-user mode, so no health
decision is ever reached -- then boot again.

## Expected result

Branch A: system boots the new copy again, no revert. Branch B: system
reverts to the original, previously-running copy.

## Actual result

**Branch A**: after `je-swupdate-commit` runs and the system reboots
again, the state partition's marker file reads `bootstate=good`, and
the kernel mounts the *same* filesystem UUID (`7d124cd8-...`) that
swupdate wrote -- confirmed the system stayed on the new copy.

**Branch B**: the next boot's trial-boot check reads `bootstate=trying`
(never cleared, since the VM was killed before any commit could run),
reverts `rootpart` to the other copy, and the kernel mounts the
*original* rootfs filesystem's own UUID (`03f759c3-...`, the one
present before the update was ever applied) -- confirmed the system
reverted.

## Raw evidence

Both filesystem-UUID confirmations above come from direct kernel boot
log lines (`EXT4-fs (vdaN): mounted filesystem <uuid>`) on the real
test runs, cross-checked against the UUIDs recorded before either
branch started.

## Limitations

- QEMU-only.
- The "health decision" that gates commit vs. rollback is binary and
  shallow: "did the system reach multi-user boot," not an
  application-level check. A candidate that boots far enough to run
  `je-swupdate-commit` but is otherwise unhealthy would still be
  committed -- not tested here, and not something the current
  implementation checks for.
- The trial-boot check itself is driven by hand at the U-Boot console
  in this example -- see `docs/update-boot.md`.
- This tests the crash-before-commit case specifically. A crash
  *during* the raw write itself (partial write) is a different failure
  mode, not exercised in this entry.

## Reproduction

Follow `meta-je-example-bsp`'s README, "FOTA, verified live" section --
it gives the exact commands for both branches, starting from the same
post-activation snapshot. No physical hardware required.
