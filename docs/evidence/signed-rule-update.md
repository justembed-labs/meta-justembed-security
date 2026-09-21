# Claim

A detection rule bundle delivered over `swupdate`'s `rawfile` handler is
verified before being written: a validly signed bundle is accepted and
applied live (no reboot), and a bundle whose payload was tampered with
is rejected before any file on the target is touched -- confirmed
against real target state in both directions, not inferred from log
messages alone. Rollback/staging for this update path does not exist
in the current implementation; that is documented as a gap below, not
tested as if it were present.

## Environment

- Yocto version / branch: scarthgap (Poky)
- MACHINE: `qemuarm64`
- Target/platform: QEMU, not real hardware
- Relevant layers: `meta-je-detection` (`je-rule-bundle`,
  `je-detection-agent`), a local `rules-update` swupdate recipe built
  for this evidence pass (same `sw-description`/`apply-rules.sh`
  structure as the real AM335x hardware BSP's own rule-update recipe,
  machine name changed to `qemuarm64`)

## Setup

`bitbake -c swuimage rules-update` builds `rules-update-qemuarm64.rootfs.swu`,
a signed `.swu` (RSA-2048 dev keypair, same one `je-secureboot` and
`je-swupdate-fota` use) bundling:

- `CVE-2026-73283.rules` / `CVE-2026-73283.json` -- the same rule
  content already shipped in the base image via `je-rule-bundle` (this
  test redelivers an unchanged rule; it demonstrates the *update
  mechanism and postinst pipeline*, not a content diff -- see
  Limitations)
- `apply-rules.sh` -- unchanged, copied verbatim from the real AM335x
  hardware BSP's own rule-update recipe (`augenrules --load`, then
  `systemctl restart je-detection-agent` if `/run/systemd/system`
  exists, else a SysV fallback)

`sw-description` uses swupdate's `rawfile` handler targeting
`/etc/je-detection/rules.d/CVE-2026-73283.json` and
`/etc/audit/rules.d/CVE-2026-73283.rules` directly on the running
rootfs -- no partition write, no A/B slot, no reboot.

A tampered copy was made by flipping one byte inside the
`CVE-2026-73283.rules` payload (inside the `-w /dev/net/tun` text),
leaving `sw-description`/`sw-description.sig` untouched -- i.e. a
payload-integrity tamper, not a signature-stripping tamper.

## Test

**Positive case**, booted normally (full systemd boot, not
`init=/bin/sh`, so postinst's `systemctl restart` path is exercised
for real):

```
swupdate -i /root/rules-update.swu -e "detection,rules" \
  -k /etc/swupdate.pem -m
```

**Negative case**, same target, same command against the tampered
`.swu`:

```
swupdate -i /root/rules-update-tampered.swu -e "detection,rules" \
  -k /etc/swupdate.pem -m
```

(`-e "detection,rules"` selects the software/mode pair `sw-description`
declares for this bundle -- there is no A/B slot concept here, so this
is invoked directly, not through `je-swupdate-select`, which is
copy1/copy2 firmware-selection specific. `-m`/`--no-state-marker`
disables swupdate's own separate bootloader-env state write, unrelated
to this update path -- carried over from the same finding made during
the A/B FOTA testing, since `/etc/fw_env.config` isn't backed by a real
U-Boot environment partition on this target either way.)

## Expected result

Positive: signature and per-file hash checks pass, both files are
written, `apply-rules.sh` runs at `postinst` and reloads/restarts the
detection stack. Negative: verification fails before any file is
written; nothing on disk changes; no postinst side effects occur.

## Actual result

**Positive case**, real console output:

```
[INFO ] : SWUPDATE started :  Software Update started !
[INFO ] : SWUPDATE running :  Installation in progress
[INFO ] : SWUPDATE successful ! SWUPDATE successful !
```

(The `Cannot initialize environment from /etc/fw_env.config` lines
around it are the same non-fatal bootloader-env probe noted in
`docs/evidence/signed-ab-update.md` -- unrelated to this update's own
success/failure, and the run still ends `successful`.)

Confirmed against real target state, not just the log line:

- `md5sum` of both target files unchanged from their pre-update value
  (this test redelivers identical content -- see Limitations), but
  `journalctl -u je-detection-agent` shows a real stop/start cycle at
  the update's timestamp:

  ```
  systemd[1]: Stopping JE detection agent ...
  systemd[1]: je-detection-agent.service: Deactivated successfully.
  systemd[1]: Stopped JE detection agent ...
  systemd[1]: Started JE detection agent ...
  je-detection-agent: ausearch failed for key=je-cve-2026-73283: Corrupted
    checkpoint file. Inode match, but newer complete event found before
    loaded checkpoint
  je-detection-agent: removing checkpoint ... and retrying
  ```

  confirming `apply-rules.sh` really executed `systemctl restart
  je-detection-agent` (not a no-op) -- and, as a side finding, that the
  agent's own documented checkpoint self-heal logic (`docs/detect.md`)
  fired for real on this restart, not just in the code path it was
  written for.
- `auditctl -l` still shows `-w /dev/net/tun -p rwa -k
  je-cve-2026-73283` loaded after the restart, confirming
  `augenrules --load` succeeded.

**Negative case**, real console output:

```
[INFO ] : SWUPDATE started :  Software Update started !
[ERROR] : SWUPDATE failed [0] ERROR : HASH mismatch : a48565bd...ba668 <--> a09747a2...9a2
[ERROR] : SWUPDATE failed [1] Image invalid or corrupted. Not installing ...
[ERROR] : SWUPDATE failed [0] ERROR : SWUpdate *failed* !
```

Confirmed against real target state: `md5sum` of both target files
identical to their pre-attempt value, and `journalctl -u
je-detection-agent` shows no new stop/start entry after this
attempt -- the service was never touched, confirming the tamper was
caught before any write or postinst script ran.

## Raw evidence

Console transcripts and the `md5sum`/`journalctl`/`auditctl` output
above are copied directly from the real test runs.

## What this actually verifies

- The hash caught here is the **per-file SHA-256 that `sw-description`
  declares for each embedded file**, not a signature over the raw
  bytes directly. `sw-description` itself is what's RSA-signed
  (`sw-description.sig`, checked against `/etc/swupdate.pem`) -- so an
  attacker who flips a payload byte without also recomputing that hash
  and re-signing `sw-description` is caught by the hash check (as
  happened here); an attacker who could forge a new signature over a
  modified `sw-description` (i.e. holds or forges the private key)
  is out of scope for this test, same trust boundary as
  `docs/evidence/fit-verification.md`'s FIT signing.
- This test did not separately exercise a corrupted/missing
  `sw-description.sig` with an otherwise-untouched payload (a stricter
  "signature-only" negative case) -- only a tampered payload with an
  intact signature block covering the old (correct) hash was tested.

## Limitations

- QEMU-only.
- The rule content delivered here is byte-identical to what the base
  image already ships (this test project has no second, differently-
  worded version of the CVE-2026-73283 rule to deliver) -- this proves
  the update mechanism, signature/hash verification, and postinst
  pipeline work end to end, but does not independently prove that
  *changed* rule content lands correctly. The file-write mechanism
  (`rawfile` handler writing to an arbitrary absolute path) and the
  reload mechanism (`augenrules --load` + agent restart) are the same
  regardless of content, so this is not expected to behave differently
  with different content, but it wasn't tested with different content.
- **No rollback or staged/canary activation exists for this update
  path today.** A rule bundle that passes verification is applied
  immediately and unconditionally at `postinst` -- there is no
  "trial" period, no health check, and no way to revert to the
  previous rule set short of pushing another signed bundle with the
  old content. This is not a partially-working feature being described
  cautiously; it is not implemented at all. Do not describe this
  update path as having a "secure rule lifecycle" -- it has verified
  delivery and verified application, and nothing past that point.
- The signature-only negative case (valid tampered `sw-description`
  hash, but signature itself corrupted/missing) was not separately
  tested -- see "What this actually verifies" above.

## Reproduction

Build the `rules-update` recipe shown in this evidence pass's branch
(`sources/<test-layer>/dynamic-layers/meta-swupdate/recipes-support/swupdate/rules-update_1.0.bb`
in the `meta-je-clean-replay` test project), copy the resulting `.swu`
onto a running `qemuarm64` instance, and run the exact `swupdate`
command above. No physical hardware required. A byte-for-byte tampered
copy (flip one byte anywhere inside a bundled payload file, leave
`sw-description`/`sw-description.sig` untouched) reproduces the
negative case.
