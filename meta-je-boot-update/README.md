# meta-je-boot-update

Secure boot + atomic FOTA: `je-secureboot.bbclass` (U-Boot verified
boot), `je-swupdate-fota.bbclass` (signed A/B firmware updates over
swupdate), and `je-ostree-fota.bbclass` (OSTree-based atomic updates,
PoC stage) -- a BSP picks whichever FOTA mechanism fits it, or both.

## What it does

- **`je-swupdate-fota`** wraps `meta-swupdate` + swupdate's own
  built-in webserver mode (accepts a pushed update directly, no
  device-management backend required). Adds swupdate to the image and
  the `ext4.gz` output format it needs to write an inactive copy
  partition. Building the actual update bundle is board-specific
  (real dual-copy partition layout, `sw-description`, bootloader
  integration) -- a consuming BSP defines its own update-image recipe
  inheriting `swupdate`, the same pattern `meta-swupdate-boards` uses.
- **`je-downgrade-guard`** (pulled in automatically by `je-swupdate-fota`)
  installs a shell helper, `je_downgrade_guard_args()`, that a BSP's own
  swupdate conf.d file sources and folds into its `SWUPDATE_ARGS`. It
  reads `/etc/sw-versions` and returns `-N`/`-R` (swupdate's own
  no-downgrading/no-reinstalling flags) for the current version, plus
  `--gen-swversions` to keep that file current after each install.
  Signing (`-k`) proves a bundle came from you; it does not stop a
  captured, still-validly-signed *old* bundle from being replayed --
  that's what this closes. Not wired up automatically: conf.d entries
  each fully replace `SWUPDATE_ARGS` (see `meta-swupdate`'s
  `swupdate.sh`), so the BSP has to source and fold it in itself. See
  `meta-je-example-bsp`'s `je-swupdate-conf.sh` for the one-line
  integration.
- **`je-ostree-fota`** (PoC stage, not yet hardware-verified) installs
  `ostree` itself -- already available via meta-openembedded/meta-oe,
  no extra layer needed. Unlike `je-swupdate-fota`, it has no upstream
  bitbake automation to lean on for the actual "commit this rootfs
  into an OSTree repo and deploy it" step: `meta-updater`, historically
  the layer that provided this, has had no commits since 2021-12-09
  and no branch past 2021 -- confirmed via `git ls-remote` and the
  GitHub API, not assumed dead from memory. A consuming BSP implements
  that step itself (realistically a host-side script against the
  built rootfs, not a bitbake image_type), plus its own bootloader-
  deployment-pointer integration -- same hardware-specific split as
  `je-swupdate-fota`'s partition layout and `sw-description`.
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
- `je-ostree-fota`: a BSP-provided rootfs-to-commit + deployment
  mechanism -- this class alone does not provide one (see "What it
  does").
- `je-secureboot`: a U-Boot build with FIT signature support
  (`CONFIG_FIT`, `CONFIG_FIT_SIGNATURE`, `CONFIG_RSA`,
  `CONFIG_OF_SEPARATE`).

## Enable it

```
IMAGE_CLASSES += "je-swupdate-fota"
IMAGE_CLASSES += "je-ostree-fota"
INHERIT += "je-secureboot"
```

Each is independent -- adopt any combination. `je-swupdate-fota` and
`je-ostree-fota` are meant as *alternatives* for the same job (atomic
FOTA); a BSP choosing both at once needs its own reason to.

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
- `je-ostree-fota`: no board-agnostic configuration exists yet --
  everything (repo URL, deployment-pointer mechanism) is BSP-side,
  PoC stage. See the class's own comments.

## Known limitations

- **`je-ostree-fota` is PoC stage, generic-wiring only.** It installs
  `ostree`; it does not provide a working update mechanism by itself.
  No QEMU demo, no real-hardware test yet -- unlike `je-swupdate-fota`
  and `je-secureboot`, which both have at least one of those. Treat
  any BSP adopting this as genuinely experimental until a real build
  and boot test exists.

- **`je-downgrade-guard` covers whole-bundle replay/rollback only.**
  It uses swupdate's global `-N`/`-R` flags against a single top-level
  `version` in `sw-description` -- the pattern this project's own
  examples use. swupdate also has a separate, finer-grained
  per-component mechanism (`install-if-higher` + per-image versions in
  `sw-description`) for BSPs that version each partition/component
  independently; not what this helper implements.
- **swupdate's webserver push channel has no channel protection by
  default** (`meta-je-example-bsp`'s own `SWUPDATE_WEBSERVER_ARGS` has
  no `--ssl`/`--global-auth-file`) -- fine for the QEMU demo, not for a
  real deployment. `meta-je-hygiene`'s `swupdate_webserver_protected`
  check catches this; see that layer's README.
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
[`docs/cra/CRA_TECHNICAL_MAPPING.md`](../docs/cra/CRA_TECHNICAL_MAPPING.md).

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
