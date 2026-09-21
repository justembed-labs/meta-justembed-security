## Claim

`je-detection-agent`'s resource footprint stays small and stable
after the correlation fix (see `docs/evidence/detection-event.md`),
its local event storage is now genuinely bounded (rotation with a
configurable max size and backup count, not unbounded growth), and
the detection agent keeps working normally when the downstream
collector is unreachable -- all real numbers from this run, not
fabricated or extrapolated.

## Environment

- Yocto version / branch: scarthgap (Poky)
- MACHINE: `qemuarm64`
- Target/platform: QEMU, `-m 512` (512MB RAM), single vCPU
- Relevant layers: `meta-je-detection` (`je-detection-agent` 0.1,
  post-stabilization: audit-event correlation +
  `logging.handlers.RotatingFileHandler`-based bounded storage)

## Setup

Normal boot with `je-detection-agent` running. `events.jsonl` at a
known baseline line count before each measurement (the process holds
an open file handle for its whole lifetime -- restarting the service,
not deleting the file out from under it, is how each measurement
below establishes a clean baseline).

## Test

1. **Idle memory**: read `je-detection-agent`'s RSS via
   `/proc/<pid>/status` at rest, before and after a burst.
2. **Burst**: trigger `/dev/net/tun` open/close 20 times in rapid
   succession, compare `events.jsonl` line count before/after and
   confirm no duplicate `audit_event_id` values.
3. **Storage rotation**: run the agent with
   `JE_DETECTION_MAX_LOG_BYTES=3000 JE_DETECTION_MAX_LOG_BACKUPS=3`
   (scaled down from the real defaults of 5MB/5 backups specifically
   to make rotation observable without generating millions of events)
   and trigger 60 times to force multiple rotations.
4. **Collector unreachable**: point `splunk-hec.env` at a host/port
   with nothing listening, trigger events, and observe both
   `je-detection-agent` and `je-detection-fluentbit`'s state and CPU
   usage.

## Expected result

Idle RSS should be small and stable, not growing across a burst.
Finding count should track trigger count exactly (20 triggers -> 20
findings). Rotation should cap the number of files and total disk
use at the configured limits, discarding the oldest data. Collector
unavailability should not block the agent, crash-loop destructively,
or spin CPU.

## Actual result

**Idle memory**: RSS held at **14036-14092 KB** across every
measurement in this run (multiple reads, before and after triggering
events) -- no meaningful growth observed.

**Idle CPU**: over a 10-second idle window (2 poll cycles),
accumulated CPU time increased by 11 clock ticks total (~0.11s) --
consistent with `ausearch` being spawned and exiting each 5-second
poll, not a busy loop.

**Burst behavior, post-fix**: 20 triggers produced **exactly 20 new
events** (0 -> 20), confirmed independently by counting unique
`audit_event_id` values (20 total, 20 unique -- no duplicates, no
merges). This replaces the pre-fix behavior (20 triggers -> 120
events, a 6x amplification) documented previously -- see
`docs/evidence/detection-event.md`'s "Previously observed issue"
section. Post-burst RSS: 14084 KB, a 48 KB delta from the idle
baseline -- negligible.

**Storage rotation, real measured result** (3000-byte threshold, 3
backups, 60 triggers):

```
events.jsonl     2252 bytes
events.jsonl.1    2252 bytes
events.jsonl.2    2252 bytes
events.jsonl.3    2252 bytes
```

exactly 4 files (current + configured backup count), no `.4` --
confirming the oldest rotated file is discarded once the cap is
reached, not retained indefinitely. Total on-disk use: ~9 KB, bounded
by design (`maxBytes * (backupCount + 1)` is the theoretical
ceiling -- 12 KB here, real usage came in under that since files
rotate at or before the threshold, not after).

**File permissions**: all 4 files `-rw-r-----` (0640, owner
read/write, group read, no world access) -- including the 3 rotated
files, not just the live one (a small custom `RotatingFileHandler`
subclass re-applies `chmod` after every rotation; plain
`RotatingFileHandler` only gets the process umask's permissions on a
newly-rotated file, which would have been correct here too by
default umask, but explicit re-application doesn't depend on that).

**Real production defaults** (not what was used for the rotation
test above, which used a scaled-down threshold to make rotation
observable quickly): `JE_DETECTION_MAX_LOG_BYTES=5242880` (5MB),
`JE_DETECTION_MAX_LOG_BACKUPS=5` -- a ~30MB total ceiling, both
overridable via environment variables without patching the script.

**Collector unreachable**: with `splunk-hec.env` pointing at a closed
port, `je-detection-fluentbit.service` stayed `active (running)` the
entire test (Fluent Bit's own internal retry, not a crash loop), and
`je-detection-agent.service` also stayed `active (running)` throughout
-- 5 triggers during this window still produced exactly 5 new events,
confirming the agent's own writes are fully decoupled from Fluent
Bit's ability to deliver them. CPU sanity: `td-agent-bit`'s
accumulated CPU ticks increased by only 1 tick (~10ms) over a 6-second
window while failing to connect -- no busy-wait/spin.

## Raw evidence

RSS values, `wc -l`/`ls -la` byte counts, `systemctl status`/CPU-ticks
readouts, and the unique-ID count above are copied directly from the
real test run described.

## What was NOT tested

- **1000 events/sec sustained load.** Not attempted this pass either
  -- see `docs/detect.md` for why this specific rate isn't treated as
  a meaningful operating point for the current 5-second-poll design.
- **Long-duration (hours/days) disk growth** at the real 5MB/5-backup
  defaults -- the rotation test used a scaled-down threshold
  specifically to make rotation observable in a short test run; the
  mechanism is the same regardless of threshold, but multi-day
  behavior at the real defaults wasn't separately run.
- **Full performance/throughput benchmarking** -- this is a sanity
  check confirming no obvious regression after the correlation fix,
  not the dedicated resource-and-failure-measurement phase.

## The real questions this section exists to answer

**Can Detect put a target under pressure, or let disk/RAM grow
unbounded?**

- **RAM: no evidence of growth** across a 20-trigger burst (48 KB
  delta, effectively noise).
- **Disk: now genuinely bounded.** Previously a real, unenforced gap
  (`events.jsonl` grew forever). Now capped by
  `JE_DETECTION_MAX_LOG_BYTES` / `JE_DETECTION_MAX_LOG_BACKUPS`,
  confirmed by real rotation behavior above -- the oldest data is
  discarded per policy, not retained forever, and this is **not** a
  guaranteed-delivery mechanism: Fluent Bit/a real collector remains
  the long-term destination, and locally-retained events older than
  the configured cap are gone if never shipped.

## Limitations

- QEMU-only, single vCPU, 512MB RAM.
- The rotation test used a deliberately small threshold to observe
  rotation without an impractically long trigger loop -- the
  mechanism (Python's standard `RotatingFileHandler`) doesn't behave
  differently at the real 5MB default, but that exact threshold
  wasn't separately re-run start-to-rotation in this pass.
- Measurements come from one test session, not repeated statistical
  runs.

## Reproduction

Boot `qemuarm64` per `docs/evidence/detection-event.md`. For the
resource/burst numbers, read `/proc/<pid>/status`'s `VmRSS` and
`/proc/<pid>/stat`'s utime/stime fields before and after triggering.
For rotation, run
`JE_DETECTION_MAX_LOG_BYTES=3000 JE_DETECTION_MAX_LOG_BACKUPS=3
/usr/bin/je-detection-agent` directly (bypassing the systemd unit's
defaults) and trigger repeatedly until `ls -la
/var/log/je-detection/` shows multiple rotated files. For the
collector-unreachable case, point `splunk-hec.env` at a closed port
and check `systemctl status`/CPU ticks for both services.
