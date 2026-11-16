# Performance

Status: M10 scaffolding (2026-11-15). Baselines not yet recorded on production-class hardware.

"Blazing fast" must be a number, not a feeling. Measure first, set targets second, tune only what wins an A/B test.

## Goals

- Record honest baselines against OpenSSH (TCP) on the same hosts and against an `ssxd` build with every opt-in feature off.
- Publish p50 / p99 / p99.9 numbers for the metrics below.
- Keep only features that show a measured win when enabled by default; losers stay opt-in or are dropped.
- Provide a repeatable harness (network namespaces + `tc netem`) and a nightly CI regression that fails on threshold breach.

## Metrics

<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:a3de62b87ff3e1ad78e089b337c8dbfee8a083fed5304923d46dbd706f0a33cc -->

| Metric | How measured | Notes |
|--------|--------------|-------|
| Full handshakes / s / core | Parallel `ssx` connections that complete auth + `OpenShell` then exit | Exclude warm-up; report median of ≥5 runs |
| Keystroke-echo latency (server + client) | Client sends single byte, measures time until same byte is echoed on the local TTY after server PTY round-trip | p50 / p99 / p99.9; subtract pure local loopback baseline |
| Bulk throughput / core | Pending a throughput driver through the supported PTY-shell interface | Driver must configure terminal modes, count transferred bytes in both directions, and time completion; report MiB/s after QUIC warm-up |
| CPU & RSS per connection | 1k / 10k / 50k idle authenticated sessions | `ps` / `smem` / cgroup; workers pinned |
| Syscalls / s, context switches, cache misses | `bpftrace`, `perf stat` during steady keystroke and bulk loads | Capture both client and server |

<!-- /coderabbit-ai-generated:v1 -->

All numbers are recorded for:

1. OpenSSH (OpenSSH_9.x, default config, same hosts, TCP).
2. `ssxd` with every opt-in feature **off** (the true baseline).
3. `ssxd` with the current default feature set.
4. Individual A/B variants of each tuning lever.

## Harness

The harness lives under `scripts/bench/`.

```text
scripts/bench/
  run-all.sh          # orchestrates baselines + profiles
  netns-setup.sh      # creates client/server namespaces + veth + optional netem
  measure-handshake.sh
  measure-latency.sh
  measure-throughput.sh
  measure-idle.sh
  compare-openssh.sh
  flamegraph.sh       # perf record + flamegraph.pl wrapper
  lib.sh              # common helpers (paths, JSON result writer)
```

### Network topology

```
[ client ns ] --- veth --- [ server ns ]
                 (optional tc netem on the server side of the veth)
```

Profiles applied with `tc netem`:

| Profile | delay | loss | reorder | Use |
|---------|-------|------|---------|-----|
| `lan` | 0.3 ms ± 0.1 ms | 0 % | — | local baseline |
| `metro` | 5 ms ± 1 ms | 0.01 % | — | same-city |
| `wan` | 40 ms ± 5 ms | 0.1 % | 0.1 % | cross-region |
| `lossy` | 20 ms ± 10 ms | 1 % | 1 % | stress |

Run from the repository root:

```bash
# Build release binaries first
./scripts/cargo-pinned.sh build --release --locked

# Full baseline suite (writes target/bench/<timestamp>/)
sudo scripts/bench/run-all.sh --profile lan
sudo scripts/bench/run-all.sh --profile wan --openssh

# Single metric
sudo scripts/bench/measure-latency.sh --profile lan --iterations 5000
```

<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:66ff6244e382d4e86bc0ef2512d76857684b61d9cfeb82348eef4697194acf0e -->

Results are JSON lines under `target/bench/<run-id>/` plus a human-readable `summary.md`. `run-all.sh --flame` only prints instructions; it does not capture flamegraphs. Start a live workload and capture manually with `scripts/bench/flamegraph.sh` (see below).

<!-- /coderabbit-ai-generated:v1 -->

### Privileges

Most measurements need `CAP_NET_ADMIN` (netns / tc) and, for accurate CPU pinning / IRQ affinity experiments, root. The harness refuses to run without the required capabilities rather than silently downgrading.

## Tuning levers

Each lever is A/B tested against the previous winner. A change is kept as a default only when it improves at least one primary metric without regressing any other primary metric beyond the noise floor (±3 % on the same hardware).

| Lever | Config key / knob | Expected effect | Status |
|-------|-------------------|-----------------|--------|
| `SEND_ZC` / `SENDMSG_ZC` + size threshold | `io.zerocopy_send`, `io.zerocopy_min_bytes` | Lower CPU on large writes | to measure |
| GSO / GRO segment size | `io.gso`, `io.gro`, `io.buffer_size` | Fewer syscalls, better batching | to measure |
| `SQPOLL` + idle timeout | `io.sqpoll`, `io.sqpoll_idle_ms` | Lower submit latency vs CPU cost | to measure |
| CQE batching min-wait | ring runtime | Amortise completions | to measure |
| NAPI busy poll / `SO_PREFER_BUSY_POLL` | `io.napi_busy_poll_us` | Lower latency under load | to measure |
| Huge-page ring + buffers | `io.hugepages` / `features.hugepages` | TLB pressure | to measure |
| `SO_TXTIME` + `fq` qdisc | `io.txtime_pacing` | Smoother pacing, fewer bursts | to measure |
| CPU pinning / IRQ affinity / NUMA | `io.pin_cpus` + external affinity | Cache locality | to measure |
| Congestion control | quiche BBR2 vs CUBIC | Throughput under loss | to measure |
| QUIC flow-control windows / `max_ack_delay` | quiche config | Latency vs throughput trade-off | to measure |
| Socket buffer sizes | `SO_SNDBUF` / `SO_RCVBUF` | Burst absorption | to measure |
| `IORING_RECVSEND_BUNDLE` | only if a stream-socket path appears | Likely N/A for UDP/PTY | evaluate later |

## Numeric targets (placeholders)

Targets are agreed **after** the first full baseline run on representative hardware. The table below is the template; numbers will be filled in and versioned in this file.

| Metric | OpenSSH baseline | ssxd features-off | Target (tuned) | Measured |
|--------|------------------|-------------------|----------------|----------|
| Handshakes / s / core | — | — | — | — |
| Keystroke p50 (µs) | — | — | — | — |
| Keystroke p99 (µs) | — | — | — | — |
| Keystroke p99.9 (µs) | — | — | — | — |
| Bulk TX MiB/s / core | — | — | — | — |
| Bulk RX MiB/s / core | — | — | — | — |
| RSS @ 1k idle (MiB) | — | — | — | — |
| RSS @ 10k idle (MiB) | — | — | — | — |
| RSS @ 50k idle (MiB) | — | — | — | — |

## CI regression

A nightly job (GitLab CI or equivalent) runs the `lan` profile with a fixed feature set and compares against the numbers recorded in this document. Thresholds:

- Any primary metric that regresses more than 5 % fails the job.
- New opt-in features that become defaults must bring a measured win in the same job.

Until the first baseline is published, the job is advisory (warn-only).

## Flamegraphs

```bash
sudo scripts/bench/flamegraph.sh --side server --duration 30 --workload latency
sudo scripts/bench/flamegraph.sh --side client --duration 30 --workload bulk
```

<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:1872925f82b1013958fab134739a47af85c2b460f0531bc354d052ec854113b4 -->

Start the server or client under the desired workload first; this script profiles an existing process and does not generate the workload. Use `--pid PID` to select it explicitly.

Requires `perf`, `stackcollapse-perf.pl`, and `flamegraph.pl` on `PATH` (or set `STACKCOLLAPSE_PERF_PL` and `FLAMEGRAPH_PL` to their executable paths). The script records `perf.data`, converts it to `perf.script`, collapses it to `perf.folded`, and renders `flame.svg` in its output directory. Use `--out DIR` to select that directory; the default is `$BENCH_ROOT/<UTC-timestamp>-flame-<side>-<workload>/`, with `BENCH_ROOT` defaulting to `target/bench` under the repository root.

<!-- /coderabbit-ai-generated:v1 -->

## Reproducing a published number

Every row in the results tables must record:

- commit SHA
- kernel version (`uname -r`)
- CPU model and core count
- `ssxd` / `ssx` feature flags and config hash
- netem profile
- exact command line of the measurement script

The harness writes this metadata automatically into each `summary.md`.

## Open work

- [ ] First full baseline on dedicated hardware (OpenSSH + features-off + defaults)
- [ ] Agree numeric targets and update the table above
- [ ] A/B every lever; enable only winners by default
- [ ] Wire nightly regression with hard thresholds
- [ ] Publish flamegraphs for the winning configuration

**Assisted By:** Grok (xAI)
