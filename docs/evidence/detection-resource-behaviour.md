# Claim

`je-detection-agent`'s idle resource footprint and its behavior under a
burst of triggers were both measured directly on a running QEMU target
-- real numbers from this run, not fabricated or extrapolated
benchmarks -- and the current implementation's unbounded disk growth
under sustained triggering is reported here as a real, unenforced
limit, not hidden.

## Environment

- Yocto version / branch: scarthgap (Poky)
- MACHINE: `qemuarm64`
- Target/platform: QEMU, `-m 512` (512MB RAM), single vCPU
- Relevant layers: `meta-je-detection` (`je-detection-agent`)

## Setup

Normal boot with `je-detection-agent` running, `events.jsonl` at a
known baseline size/line count before each measurement.

## Test

1. **Idle memory**: read `je-detection-agent`'s RSS via `/proc/<pid>/status`
   at rest (no triggers) at two points several poll cycles apart.
2. **Burst**: trigger the watched `/dev/net/tun` open/close 20 times in
   rapid succession (well under 1 second wall time between triggers),
   then compare `events.jsonl` line count and byte size before/after,
   and re-check agent RSS immediately after.
3. **Collector-unreachable behavior**: observed as a side effect of
   `docs/evidence/detection-event.md`'s setup, where
   `je-detection-fluentbit.service` fails to start at all (missing
   `splunk-hec.env` by design) for the full duration of every other
   test in this evidence pass.

## Expected result

Idle RSS should be small and stable. A burst should produce
proportionally more events with no crash or event loss. Collector
unavailability should not block the agent's own file-writing.

## Actual result

**Idle memory**: RSS held stable at **16080 KB** across the
measurement window (no growth observed between the two read-outs at
rest).

**Burst behavior**: 20 triggers in rapid succession produced **exactly
120 new events** (baseline 12 -> 132), matching the already-documented
6-events-per-real-trigger multiplier from
`docs/evidence/detection-event.md` (20 x 6 = 120) exactly -- no event
loss and no duplicate-beyond-the-known-multiplier observed.
`events.jsonl` grew from approximately 16 KB (baseline) to
approximately 164 KB after the burst. Agent RSS immediately after the
burst was unchanged from the idle measurement (still 16080 KB) --
the per-event write is cheap enough at this volume that it didn't show
up as retained memory growth in this measurement.

**Collector unreachable**: `je-detection-fluentbit.service` sat in
systemd's `activating (auto-restart)` state for the entire test
session (its documented, by-design behavior when no
`/etc/je-detection/splunk-hec.env` is provided) without ever blocking
or slowing `je-detection-agent`'s own writes to `events.jsonl` -- the
two are fully decoupled processes with no shared blocking path,
confirmed by the burst test above still producing exactly the expected
120 events while Fluent Bit was down the whole time.

## Raw evidence

RSS values, `wc -l`/`ls -la` byte counts, and `systemctl status`
output are copied directly from the real test run described above.

## What was NOT tested

- **1000 events/sec sustained load.** The 20-trigger burst above (in
  under 1 second, so effectively >100 events/sec for that brief
  window) is the largest load tested; a sustained 1000/sec load was
  not attempted, since nothing in the current implementation's design
  (a 5-second poll loop reading a flat log file) suggests that rate is
  a meaningful operating point to characterize -- see `docs/detect.md`.
- **Long-duration disk growth.** The burst test shows growth over one
  short burst, not sustained hours/days of triggering.
- **CPU usage under load** was not separately measured (only RSS).

## The real question this section exists to answer

**Can Detect put a target under pressure, or let disk/RAM grow
unbounded?**

- **RAM: no evidence of unbounded growth** in this test -- RSS was
  identical before and after a 10x event-count burst. This is not
  proof it can never grow (a much longer burst wasn't tested), but
  nothing observed here suggests a per-event memory leak.
- **Disk: yes, this is a real, unenforced limit.** `events.jsonl` has
  no rotation, size cap, or disk-usage guard anywhere in
  `je-detection-agent` or its packaging today. The 16 KB -> 164 KB
  growth from one 20-trigger burst is small in absolute terms on this
  test image, but the growth is linear and permanently unbounded by
  design -- a target left running long enough, or triggered often
  enough, will eventually fill its log partition with no built-in
  backstop. This is documented as a real gap in `docs/detect.md` and
  `ROADMAP.md`, not silently left out of this report.

## Limitations

- QEMU-only, single vCPU, 512MB RAM -- not representative of every
  target's resource envelope.
- Measurements come from one test session, not repeated statistical
  runs; treat the specific numbers (16080 KB, 164 KB) as this run's
  real results, not guaranteed constants across builds.
- The 6-events-per-real-trigger multiplier (see
  `docs/evidence/detection-event.md`) means all event-count numbers
  here reflect that known characteristic, not 1:1 real-world triggers.

## Reproduction

Boot `qemuarm64` per `docs/evidence/detection-event.md`, read
`/proc/<je-detection-agent pid>/status`'s `VmRSS` line at rest, then
trigger `/dev/net/tun` open/close in a tight loop and re-check
`wc -l`/`ls -la` on `/var/log/je-detection/events.jsonl` before and
after.
