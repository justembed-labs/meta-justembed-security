# Update & Boot

Two independent lifecycle mechanisms, `je-secureboot.bbclass` (verified
boot) and `je-swupdate-fota.bbclass` (signed atomic updates), plus a
third, separate update channel for `meta-je-detection`'s own rule
content. Kept apart deliberately -- a firmware update and a boot-time
verification check are different trust questions, and a rule-content
update is neither.

## Firmware update flow

```text
signed .swu artifact
        |
        v
swupdate verifies RSA signature + per-file SHA-256
        |
        v
raw write to the inactive A/B slot
        |
        v
activation script arms the slot as boot candidate
        |
        v
next boot: boot the candidate slot
        |
        v
health decision (this project's v1: "reached multi-user boot" only)
        |
   +----+----+
   |         |
 accept   rollback
(commit,  (never committed --
bootstate  next boot reverts
 =good)    to the other slot)
```

Implemented as: `je-swupdate-select` picks the inactive slot from the
running system's own `root=`; `sw-description` (board-specific, per
`je-swupdate-fota.bbclass`'s own documented design) does the raw write
and runs an activation shellscript that writes the candidate slot
number and a `trial` flag to a small state partition; on the next boot,
the bootloader (or, on the QEMU reference implementation, a manual
console sequence standing in for what a real board's compiled-in boot
script would do) reads that state, arms a `trying` marker, and boots
the candidate; `je-swupdate-commit` (a systemd service run once
multi-user boot is reached) clears the marker to `good`. See
`docs/evidence/signed-ab-update.md` and `docs/evidence/ab-rollback.md`.

**Health decision today is binary and shallow**: "did the system reach
multi-user boot," not an application-level health check. That's an
honest v1, not a hidden gap -- documented here so it isn't assumed to
be more than it is.

## Detection rule update

Deliberately a **separate** update, not routed through the firmware
flow above:

```text
signed rule-bundle artifact (no rootfs image)
        |
        v
swupdate verifies RSA signature + per-file SHA-256
        |
        v
rawfile write: rule + OCSF descriptor land directly on the running rootfs
        |
        v
shellscript: augenrules --load (hot-reload auditd), restart je-detection-agent
        |
        v
no reboot, no A/B slot involved
```

See `docs/evidence/signed-rule-update.md` for the positive and negative
(tampered) test, and the honest limitation: **no rollback or staged
activation exists for this update path today** -- a tampered/invalid
bundle is rejected outright (see the evidence file), but a validly
signed bundle that turns out to contain a bad rule has no automatic
revert. Don't read "signed" as "safe lifecycle" here; it's signed
delivery, not a lifecycle with rollback.

## Boot verification (`je-secureboot`)

Reuses OpenEmbedded-core's own `kernel-fitimage.bbclass` +
`uboot-sign.bbclass` -- FIT signing, not custom crypto tooling.

### Trust chain, stage by stage

For the current reference implementation
(`meta-je-example-bsp`, QEMU, `qemuarm64`):

| Stage | Present? | Verified? | Verifier | Key / trust anchor | Immutable hardware root of trust? |
|---|---|---|---|---|---|
| Boot ROM | No -- QEMU has no boot-ROM concept; firmware is loaded directly by the emulator. | N/A | N/A | N/A | No |
| SPL | Not used in this reference implementation. | N/A | N/A | N/A | N/A |
| U-Boot | Yes | **No** -- nothing attests U-Boot itself before it runs. | -- | -- | No |
| FIT (kernel + devicetree) | Yes | **Yes** | U-Boot (`uboot-sign.bbclass`-embedded RSA-2048 public key, `required = "conf"`) | Dev keypair (`meta-je-example-bsp`), swapped for a real one in production | No -- verification is real, but the *root* it verifies against (U-Boot itself) isn't hardware-anchored |
| Root filesystem | Yes | **No boot-time check.** `meta-je-sbom-cve`/`je-swupdate-fota` check a per-file SHA-256 *at update time*, not on every boot. | -- | -- | No |

**A real board with a boot ROM that cryptographically verifies the
first-stage bootloader** would add a real "Yes" at the ROM stage, and
typically an SPL stage between ROM and U-Boot -- turning this into a
genuine hardware-anchored chain. On silicon whose boot ROM doesn't do
that (common on general-purpose, as opposed to security-oriented,
silicon tiers across most vendors), the verified chain can only ever
start *at* U-Boot, exactly as on QEMU -- a property of the silicon
tier, not something this layer can close.

**Never call this "full secure boot."** The FIT verification step is
real and cryptographically sound; the chain as a whole is only as
anchored as whatever loads U-Boot, which on QEMU (and on unverified-ROM
silicon) is nothing. See `docs/evidence/fit-verification.md` for the
live positive/negative proof of the one step that *is* verified.

## What this deliberately does not do

- No device-management backend, fleet dashboard, or update-orchestration
  service -- swupdate's own push-mode webserver or `suricatta`
  polling mode is the delivery mechanism; this project doesn't add
  another layer on top.
- No staged/canary rollout logic.
- No application-level health check beyond "reached multi-user boot."
