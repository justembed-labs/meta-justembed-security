# Resource measurement methodology

How the numbers in `docs/evidence/detection-resource-measurements.md`
were actually produced -- so an outside reader can judge how much
weight to put on them, and reproduce or challenge them.

## Tools used

No benchmarking suite was installed -- only what the target already
ships:

- **Memory**: `/proc/<pid>/status`'s `VmRSS` line, read directly. This
  is resident set size (real physical pages currently mapped), not
  `VmSize` (virtual address space, includes unmapped/shared
  reservations and is a poor proxy for actual memory pressure on a
  constrained target).
- **CPU**: `/proc/<pid>/stat` fields 14 (`utime`) and 15 (`stime`),
  in clock ticks (`sysconf(_SC_CLK_TCK)`, 100 Hz on this kernel --
  each tick is 10ms). Reported as a **delta between two reads**
  separated by a known wall-clock interval, not an instantaneous
  value -- `/proc/<pid>/stat` is a cumulative counter since process
  start.
- **Disk**: `ls -la` / `wc -l` on `/var/log/je-detection/` directly.
- **Event counting**: the real `events.jsonl` line count (agent
  side), and, on the forwarding side, a real counter incremented by
  **parsing each received HTTP body as a stream of concatenated JSON
  objects** (`json.JSONDecoder().raw_decode()` in a loop), not by
  counting HTTP requests. **This was a real correction made mid-test**:
  Fluent Bit's `splunk` output plugin batches multiple OCSF events
  into a single POST body (JSON objects concatenated back-to-back,
  no array wrapper, no separator) -- an early version of the test
  listener counted 1 per POST and appeared to show massive event
  loss (17 of 600 forwarded) that was actually a counting bug, not a
  forwarding failure. Confirmed by inspecting raw received bodies
  directly before fixing the counter.
- **Load generation**: a small shell script (`gen.sh`, not part of
  the product, written for this test only) that opens and closes
  `/dev/net/tun` in a loop with a configurable inter-trigger sleep,
  timestamping real start/end with `date +%s.%N` so the *achieved*
  rate is measured, not assumed to match the requested one.

## Sampling approach

- RSS: point-in-time reads, not averaged -- multiple reads at
  different points (idle, post-load) show whether it moved.
- CPU: always reported as (end_ticks - start_ticks) / elapsed_seconds
  over a stated window, never a single absolute reading.
- Idle samples were taken at real, but not perfectly round, intervals
  (see `detection-resource-measurements.md`'s "Idle" section for the
  exact gaps actually used) -- the target was regression/relative
  behavior (is it flat, or growing), not a precise time-series.

## QEMU-specific limitations

- **Single vCPU, host-scheduled.** CPU tick counts reflect time
  actually scheduled by the host kernel for QEMU's vCPU thread, which
  competes with everything else running on the host machine (this
  session's own tooling included) -- absolute CPU numbers here are
  not a clean measurement of "how much silicon this needs" on real
  hardware, only of relative behavior (flat vs. growing, busy-spin vs.
  idle) under this specific host's load at the time of the test.
- **`ausearch`/audit subsystem behavior is real** (same kernel audit
  code as real hardware), but syscall/interrupt timing characteristics
  on QEMU's emulated `virt` machine are not representative of a real
  SoC's actual interrupt latency or storage I/O characteristics.
- **No real persistent storage device.** The `virtio-blk` backing
  file lives on the host's own filesystem/disk cache -- write latency
  and wear characteristics that matter on real eMMC/NAND aren't
  exercised here at all.
- **Host contention.** This entire test session ran on a shared
  development machine with other processes active. Where a number
  looks like it moved for no algorithmic reason, host scheduling
  noise is the more likely explanation than a product behavior change
  -- called out explicitly wherever it applies.

> QEMU measurements are useful for regression and relative behaviour,
> but are not representative production-hardware benchmarks.

## A second real correction: poll lag

`je-detection-agent` polls every `POLL_SECONDS` (5s) -- reading
`events.jsonl`'s line count immediately after a load-generation script
exits undercounts by however many real events are still waiting for
the agent's next poll cycle. Confirmed directly: right after a
600-trigger run, `events.jsonl` showed 474 new lines; the real raw
audit log (`ausearch --format raw`) already had exactly 600 new
`SYSCALL` records at that same moment. Waiting one more poll interval
(a few seconds) before reading the final count showed all 600
accounted for, with zero loss and zero duplication (matched 1:1 by
unique `audit_event_id`). All "generated vs. detected" numbers in
`detection-resource-measurements.md` were read only after confirming
this settle time had passed, not immediately after load generation
stopped.

## What this methodology does NOT attempt

- Statistically rigorous sampling (many repeated runs, confidence
  intervals) -- these are single real runs, reported as such.
- Kernel-level tracing (ftrace, perf) -- out of scope for a
  stdlib-only, no-new-dependency measurement pass.
- Network-level byte counting beyond what's noted qualitatively (see
  `detection-resource-measurements.md`'s Limitations).
