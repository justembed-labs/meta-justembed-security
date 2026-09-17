# meta-je-detection

CVE-to-rule compensating detection: turns a disclosed CVE into a
real-time detection rule your device can act on, independent of the
firmware release cycle. Two recipes:

```
IMAGE_INSTALL:append = " je-detection-agent je-rule-bundle"
```

## Architecture

- **`je-rule-bundle`** -- one auditd rule + one JSON descriptor per CVE
  (`rules.d/<CVE>.rules`, the actual `-w`/`-a` audit rule; `rules.d/
  <CVE>.json`, title/description/severity/observables/ATT&CK mapping,
  keyed by the same `audit_key`). Deliberately its **own recipe**, not
  part of `je-detection-agent`: the rule bundle is versioned and signed
  independently of firmware, shipped over the same secure channel as
  the FOTA mechanism (`meta-je-boot-update`) but on its own, faster
  cadence -- that decoupling is what actually closes the patch-latency
  gap.
- **Detection engine: auditd** -- kernel-native, works on any target.
  Falco/eBPF is a natural future upgrade path for targets whose kernel
  qualifies (`CONFIG_BPF_SYSCALL`/BTF), not required today.
- **`je-detection-agent`** (Python, stdlib only) polls `ausearch -k
  <key> -if <audit.log> --checkpoint ...` per rule in `je-rule-bundle`
  and emits matches as OCSF **Security Finding** (`class_uid 2001`)
  JSON lines to `/var/log/je-detection/events.jsonl`. Detection + OCSF
  formatting only -- no transport. Self-heals a corrupted `ausearch`
  checkpoint rather than staying silently wedged.
- **Fluent Bit** (`meta-oe`'s `fluentbit` recipe -- binary is
  `/usr/bin/td-agent-bit`, legacy branding, not `fluent-bit`) tails
  that file and ships events downstream (e.g. to a SIEM's HTTP Event
  Collector-style endpoint), `sourcetype=ocsf:2001`, as its own
  systemd unit (`je-detection-fluentbit`), independent of `fluentbit`'s
  own default unit.
- Backend host/port/token are **never baked into the image** --
  `/etc/je-detection/splunk-hec.env` (copy from `splunk-hec.env.example`
  and fill in on the target) is read by the Fluent Bit unit at start.

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
`je-detection-agent` hot-reload with no firmware image involved. See
`meta-je-boot-update/README.md`.
