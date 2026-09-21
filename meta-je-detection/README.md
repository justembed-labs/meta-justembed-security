# meta-je-detection

CVE-to-rule compensating detection: turns a disclosed CVE into a
real-time detection rule your device can act on, independent of the
firmware release cycle. Two recipes:

```
IMAGE_INSTALL:append = " je-detection-agent je-rule-bundle"
```

## Architecture

`je-rule-bundle` (one auditd rule + one OCSF-mapping JSON descriptor
per CVE) ships independently of firmware, over the same signed channel
as `meta-je-boot-update`'s FOTA mechanism but on its own, faster
cadence -- that decoupling is what closes the patch-latency gap.
`je-detection-agent` (Python, stdlib only) polls auditd via `ausearch`
and emits matches as OCSF Security Finding JSON lines; Fluent Bit
tails and ships them downstream, with backend host/port/token never
baked into the image. Full pipeline, exact commands, and what's
supported vs. not: [`docs/detect.md`](../docs/detect.md).

## OCSF fields

- `class_uid` **2001 Security Finding** -- checked against real
  downstream SIEM support for the OCSF-CIM mapping used in the demo
  environment this was validated against; use the class your own
  backend actually supports.
- `vulnerabilities[].cve.uid` -- the CVE, in OCSF's actual structured
  field (per `schema.ocsf.io`), not an ad hoc string.
- `attacks[].technique.{uid,name}` -- MITRE ATT&CK mapping, e.g.
  `T1572` / "Protocol Tunneling" for the sample rule below. Populated
  from `attack_technique`/`attack_technique_name` in the rule's own
  JSON descriptor -- the agent stays CVE/technique-agnostic, all of
  that lives in `je-rule-bundle`'s data files.

## Sample rule: CVE-2026-73283 -- MITRE ATT&CK T1572 (Protocol Tunneling)

OpenSSH < 10.5: `authorized_keys`' `restrict` keyword was supposed to
block tunnel forwarding but didn't. A restrict-flagged session opening
`/dev/net/tun` is the bug itself, giving a clean detection signature
without needing memory-corruption exploit development. Rule: `-w
/dev/net/tun -p rwa -k je-cve-2026-73283`.

Needs two kernel config fragments most default configs won't have:
`CONFIG_TUN=y`, `CONFIG_AUDIT=y`+`CONFIG_AUDITSYSCALL=y`.

## Verified on real hardware

A `restrict`-flagged SSH key genuinely established tunnel forwarding
against a real `sshd` on physical embedded Linux hardware (`tun0` came
up) -- the audit rule fired on the real `openat("/dev/net/tun")`,
`je-detection-agent` turned it into a real OCSF event, Fluent Bit
shipped it, it landed indexed and searchable downstream. Reproduced
cleanly, no manual intervention.

The independent rule-bundle update mechanism (below) has also been
verified live on hardware, hot-reloading `auditd` and the detection
agent with no reboot.

## Independent rule-bundle delivery

Rule-bundle content ships as its own signed, no-reboot update
(swupdate's `rawfile` handler) through `meta-je-boot-update`'s FOTA
channel -- new detection content lands and `auditd`/
`je-detection-agent` hot-reload with no firmware image involved.

## More documentation

- [`docs/detect.md`](../docs/detect.md) -- full pipeline, OCSF field
  detail, supported/unsupported capabilities, resource considerations.
- [`docs/evidence/detection-event.md`](../docs/evidence/detection-event.md) --
  a real trigger through to a real OCSF event and forward, QEMU.
- [`docs/evidence/signed-rule-update.md`](../docs/evidence/signed-rule-update.md) --
  the independent rule-bundle update, valid and tampered, QEMU.
- [`../meta-je-boot-update/README.md`](../meta-je-boot-update/README.md) --
  the update channel this layer's rule-bundle delivery rides on.
