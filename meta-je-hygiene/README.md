# meta-je-hygiene

Hardening baseline layer. Build first -- the other three `meta-je-*`
layers depend on it. Enforced at `do_rootfs` QA time via
`ROOTFS_POSTPROCESS_COMMAND`: an unmet *enforced* check fails the
build, it does not just get logged.

**Why these specific checks**: they're the technical, structural side
of the EU Cyber Resilience Act's essential cybersecurity requirements
(Annex I) -- secure-by-default configuration, protection from
unauthorized access, minimized attack surface, exploitation-mitigation
mechanisms. This is a build-time technical check, **not a legal CRA
conformity determination** -- the tooling proves what's technically
true about a build; whether that satisfies CRA obligations for a
given product is a legal question outside this layer's scope.

```
IMAGE_CLASSES += "je-hygiene"
```

Every check (enforced or not) writes a result to
`${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.je-hygiene.json`.

## Checklist

| check | enforced? | what it does |
|---|---|---|
| No default credentials | yes (`JE_HYGIENE_REQUIRE_NO_DEFAULT_CREDS`, default on) | Every `/etc/shadow` entry has either a real password hash or is locked (`!`/`*`) -- fails on a blank password field. |
| Key-only SSH | yes (`JE_HYGIENE_REQUIRE_KEY_ONLY_SSH`, default on) | If `/etc/ssh/sshd_config` is shipped, requires `PasswordAuthentication no` and `PermitRootLogin no`/`prohibit-password` explicitly set. Passes trivially if no sshd is shipped. |
| Minimal service surface | opt-in (`JE_HYGIENE_REQUIRE_MINIMAL_SERVICE_SURFACE`, default off) | Every systemd unit enabled in the rootfs (a symlink under `etc/systemd/system/*.wants/`) must be listed in `JE_HYGIENE_ALLOWED_SERVICES`. Off by default -- set both together, per image. Passes trivially on a non-systemd rootfs. |
| Read-only root where feasible | report-only by design, permanently | Reads `etc/fstab`'s root (`/`) entry and reports whether it's mounted `ro`. Feasibility is per-target (storage wear, whether the app writes at runtime) -- this never hard-fails, by design. |
| Kernel hardening flags | opt-in (`JE_HYGIENE_REQUIRE_KERNEL_HARDENING_FLAGS`, default off) | Checks Kconfig symbols (`CONFIG_STACKPROTECTOR{,_STRONG}`, `CONFIG_STRICT_{KERNEL,MODULE}_RWX`, `CONFIG_VMAP_STACK`, `CONFIG_HARDENED_USERCOPY`, `CONFIG_FORTIFY_SOURCE`, `CONFIG_SLAB_FREELIST_HARDENED`, `CONFIG_BUG_ON_DATA_CORRUPTION`, `CONFIG_INIT_ON_{ALLOC,FREE}_DEFAULT_ON`) against `JE_HYGIENE_KERNEL_CONFIG` (defaults to `STAGING_KERNEL_BUILDDIR/.config`, the real built kernel's own config). The checklist is architecture-aware: a symbol only appears if it's a real option for the kernel tree being checked (an ASLR-style symbol that's only meaningful on some architectures, for example, is left out rather than reported as a false failure). Off by default -- a fresh target is unlikely to have every flag set, and enabling this hard-fails until the gaps are reviewed and either turned on (per-`MACHINE` kernel config fragment) or explicitly accepted. |

Set any `JE_HYGIENE_REQUIRE_*` to `"0"` to turn an enforced check into
report-only for a specific image -- do this deliberately, not as a way
to make a failing build pass silently.

## Usage

`files/je_hygiene_check.py` is a standalone script (rootfs dir in,
JSON report + exit code out) -- test it directly against a synthetic
rootfs tree without a full Yocto build:

```
python3 files/je_hygiene_check.py --rootfs /path/to/test/rootfs \
    --report /tmp/report.json --require-no-default-creds --require-key-only-ssh
```

Verified end-to-end through a real `do_rootfs` build on physical
embedded Linux hardware: an unmet enforced check correctly fails the
build, and the JSON report lands at
`<deploy-dir>/<image-name>.je-hygiene.json` as designed.
