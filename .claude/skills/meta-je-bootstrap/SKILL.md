---
name: meta-je-bootstrap
description: Bootstrap the meta-je-* security layers (hygiene, SBOM/CVE, detection) onto a new Yocto BSP target -- kas overlays, required kernel config, RDEPENDS/binary-name gotchas, and end-to-end hardware validation. Use when adding these layers to a machine/BSP for the first time, or when a layer that worked on one target fails to start on another.
---

# meta-je-* bootstrap

Follow in order. Don't skip step 5 -- a layer that builds and deploys
but was never actually exercised on hardware is not verified, per this
project's own "real build before trust" discipline.

## 1. Add the kas dependency

```yaml
repos:
  meta-justembed-security:
    url: <your fork or the upstream repo URL>
    branch: main
    layers:
      meta-je-hygiene:      # and/or meta-je-sbom-cve, meta-je-detection
```

Use a real git `url:`/`branch:`, not a local `path:` shortcut -- a
`path:` entry only resolves on a machine with both repos checked out
side by side, which breaks on any CI runner with a different
workspace layout.

**Known trap**: kas does not re-fetch an already-checked-out branch on
its own. After pushing a fix to the layer repo, `git -C
<checkout>/meta-justembed-security fetch && git reset --hard
origin/<branch>` before rebuilding, or the build will silently use
stale layer content.

## 2. meta-je-detection needs two kernel config fragments

Both off by default on a typical embedded kernel config. Add via a
`.bbappend` on the kernel recipe, same pattern as any other feature
fragment (`SRC_URI += "file://x.cfg"` +
`KERNEL_CONFIG_FRAGMENTS += " ${WORKDIR}/x.cfg"`):

- `CONFIG_AUDIT=y`, `CONFIG_AUDITSYSCALL=y` -- without this, `auditd`
  installs fine but `augenrules --load` fails outright: "Error - audit
  support not in kernel" / "Cannot open netlink audit socket". Needed
  unconditionally, for any CVE-to-rule detection to work at all.
- Whatever kernel feature the *specific* CVE's rule needs (e.g.
  `CONFIG_TUN=y` for the sample tunnel-forwarding rule). Check this
  per rule, per target -- a rule watching a path/device that doesn't
  exist on this kernel is trivially not-applicable-config, not a
  working detector. Don't assume a fragment that mattered on one
  target applies to the next.

## 3. je-detection-agent RDEPENDS, exactly

```
RDEPENDS:${PN} = "auditd fluentbit python3-core python3-modules"
```

Two wrong-seeming-right names below are common mistakes:

- **`auditd`, not `audit`** -- meta-oe's `audit` recipe's *default*
  package (bare `PN`) is just the base/library bits. The actual
  daemon, `auditd.service`, `auditctl`, `ausearch` all live in the
  `auditd` sub-package (`PACKAGES += "auditd ..."`,
  `SYSTEMD_PACKAGES = "auditd"` in the recipe). Depending on bare
  `audit` installs nothing you actually need.
- **`python3-modules`, not a specific stdlib split package** -- Yocto
  splits Python's stdlib into many small packages. Don't chase each
  import with its own RDEPENDS entry (`python3-json`, `python3-glob`,
  ...) -- `python3-modules` is OE-core's umbrella covering the whole
  split, and any agent script touching more than a couple of stdlib
  modules will hit this eventually.

Fluent Bit's binary is `/usr/bin/td-agent-bit`, **not**
`/usr/bin/fluent-bit` (legacy branding -- the recipe's own
`SYSTEMD_SERVICE:${PN} = "td-agent-bit.service"` says so if you look).
Any `ExecStart=`/`--exec` referencing `fluent-bit` fails with systemd
`status=203/EXEC`.

## 4. ausearch needs the log file spelled out

```python
subprocess.run(["ausearch", "-k", key, "-if", "/var/log/audit/audit.log",
                 "--format", "raw", "--checkpoint", checkpoint])
```

`ausearch -k <key>` alone can silently find nothing even with a
confirmed-correct rule and a confirmed-present matching record in the
raw log, on some audit-userspace builds -- their own default log-file
lookup can be unreliable. Always pass `-if <path>` explicitly.

**Also self-heal the checkpoint.** A checkpoint written by a poll that
finds zero matches very early (e.g. right after boot, before much of
the audit log exists yet) can come back malformed on every later call
("Missing dev/inode lines from checkpoint file"), permanently and
*silently* wedging the agent -- `ausearch` exits 1 either way, so code
that treats every rc=1 as "no matches" never notices. Check `stderr`,
not just the return code: rc=1 with a real message on stderr is a real
error, not "nothing found." On a checkpoint-related error, delete the
checkpoint file and retry once.

## 5. Validate on real hardware, not just a build

A clean `kas build` + deploy proves the recipe is well-formed. It
proves nothing about whether the layer actually *works* -- every gotcha
above builds cleanly and only shows up at runtime. Minimum bar before
calling a target done:

1. Deploy, boot, SSH/console in.
2. Confirm every RDEPENDS binary is actually present and every service
   is `active (running)`, not just `enabled` (`systemctl status
   <unit>` -- `loaded, enabled` with `Active: inactive (dead)` or
   `activating (auto-restart)` means something's still broken).
3. Confirm the audit rule is actually loaded (`auditctl -l`).
4. Trigger the real condition the rule watches for -- not a synthetic/
   hand-built event standing in for it -- and confirm a real matching
   record lands in the raw audit log.
5. Confirm the agent's own output file gets a real, non-synthetic
   event from that trigger, not just from a manually-crafted test.
6. If there's a downstream sink (SIEM, etc.), confirm the event
   actually lands there via a real query against it, not just that the
   shipper process is running.

None of steps 2-6 are optional shortcuts -- each one is a real class of
bug that only shows up at runtime, not at build time. Skipping straight
from "it builds" to "it's done" is how bugs like these ship unnoticed.
