# Benchmark methodology

## Purpose

NTIP benchmarks establish reproducible baselines, reveal bottlenecks, and
quantify idle cost. They do not justify a claim that NTIP is faster than
WireGuard unless identical-hardware evidence consistently supports that exact
claim. Failed, unstable, or unfavorable results are still published.

## Required environment record

Every result set includes:

- date, NTIP commit/version, Zig 0.16.0 mode, and all build commands;
- CPU model, sockets, cores/threads, frequency policy, mitigations, and relevant
  crypto instruction support;
- total RAM, NUMA topology, and memory speed when known;
- NIC model/firmware/driver, link rate, queue count, offload settings, and IRQ
  affinity;
- Linux distribution, exact kernel, sysctls, nftables policy, conntrack state,
  and relevant loaded modules;
- physical/virtual topology, underlay addressing, hops, RTT, packet loss, and
  whether sender/receiver share a host or hypervisor;
- inner and outer MTU, UDP socket buffer sizes, TUN queue count, and CPU
  affinity;
- WireGuard version/configuration when it is a comparison;
- exact test commands, warm-up, duration, repetitions, and raw machine-readable
  output.

Do not compare an encrypted NTIP path to an unencrypted baseline as though they
were equivalent. Disable or retain GRO/GSO/checksum offload consistently and
record the choice. Avoid running unrelated workloads, thermal throttling, or
power-saving transitions during measurement.

## Topology

Use three physical hosts when possible: traffic generator, Master, and Node.
For Node-to-Node tests use two endpoint hosts plus the Master. Connect at a link
rate above the expected result so the benchmark measures software rather than
an accidental port limit. Run a namespace-only baseline separately; never mix
it with physical-NIC numbers.

For every NTIP result, record these controls on the same hardware:

1. plain routed Linux without a tunnel;
2. WireGuard using equivalent addressing, MTU, topology, cipher defaults, and
   firewall/NAT behavior;
3. NTIP Master-to-Node;
4. NTIP Node-to-Node through the Master when applicable.

## Measurement protocol

Use at least 10 seconds of warm-up, 60 seconds of measurement, and five
independent repetitions. Report every repetition plus median, minimum, maximum,
and 95th percentile where meaningful. Recreate the session between repetitions
for connection-setup tests; retain it for steady-state throughput tests.

The repository harness captures metadata and raw repetitions after the operator
starts an `iperf3` server and selects rates from a prior lossless-rate probe:

```sh
TARGET=10.1.0.2 \
UDP_RATES="250M 500M 750M 900M 1G 1.1G" \
WIREGUARD_TARGET=10.9.0.2 \
scripts/benchmark.sh
```

The rate list must correspond to the required percentage sweep for that host;
the example numbers are not universal thresholds.

### TCP throughput

Run at least one and eight parallel streams in both directions:

```sh
iperf3 --client TARGET --time 60 --omit 10 --parallel 1 --json
iperf3 --client TARGET --time 60 --omit 10 --parallel 8 --reverse --json
```

Report sender and receiver goodput, retransmits, RTT, CPU, and drops. Explain
whether firewall/NAT/conntrack was active.

### UDP throughput and loss

Sweep offered load through 25%, 50%, 75%, 90%, 100%, and 110% of the best known
lossless rate:

```sh
iperf3 --client TARGET --udp --bitrate RATE --length 1200 \
  --time 60 --omit 10 --json
```

Report offered/received bits per second, packets, loss count/percentage,
out-of-order count, jitter, and application/kernel/NTIP drop counters.

### Small-packet rate

Measure 64-byte inner packets separately because tunnel overhead and per-packet
work dominate. Use a reproducible packet generator and report offered and
received packets per second, loss, batch size (one in portable v0.1), CPU per
core, IRQ distribution, and queue occupancy. Do not label Ethernet wire size as
inner IPv4 size.

### Latency

Measure idle and loaded round-trip latency with at least 10,000 samples. Report
median, p95, p99, p99.9, maximum, and loss. Loaded latency runs concurrently at
50% and 90% of measured lossless throughput. Record clock source and whether
one-way clocks are synchronized; otherwise report RTT only.

### CPU and memory

Sample per-process and system CPU at one-second intervals. Include softirq and
the relevant `ntip` data/control worker threads. Report cycles/packet or
instructions/packet only when the counter setup and multiplexing ratio are
recorded.

Measure RSS after a 60-second idle stabilization for:

- daemon with zero Nodes;
- 1 idle Node;
- 64 idle Nodes;
- 256 idle Nodes.

Report base RSS and incremental bytes per Node. Then repeat under a malformed
UDP flood to prove memory remains bounded. Record allocator counters showing no
hot-path allocation after initialization.

## Traffic-state observations

Record transitions among COLD, WARM, HOT, and SATURATED with timestamps, EWMA
packet/bit rates, queue occupancy, backpressure, and drops. v0.1 states are
telemetry only, so a transition must not be presented as an acceleration
feature. Verify the initial defaults: 30-second COLD idle, HOT at 100 kpps or
1 Gb/s, SATURATED at 80% queue occupancy or backpressure/drop, and five-second
hysteresis.

## Result format

Store metadata and raw outputs under a unique result directory:

```text
results/YYYYMMDD-HHMMSS-hostname/
├── metadata.txt
├── ntip-status.json
├── kernel.txt
├── network.txt
├── cpu-memory.csv
├── tcp-*.json
├── udp-*.json
├── latency-*.txt
├── wireguard-*.json
└── summary.md
```

Commit only deliberate, reviewed result sets or publish them as release assets.
Never overwrite an old run. Redact public endpoints and sensitive topology
without removing information necessary to reproduce the experiment.

## Acceptance interpretation

The beta gate requires correct behavior, bounded memory, clean soak, and native
architecture success—not a particular throughput number. Regressions should be
compared against confidence intervals and raw counters before attribution.
Optimization work must name the measured bottleneck, expected effect, and
fallback if it harms correctness or portability.
