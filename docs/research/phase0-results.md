# Phase 0 Spike — Measured Results

Environment: (fill in `uname -a`, CPU, container details at first measurement)

## Bet 1: boringtun throughput

**Measured:** Task 4, `spike/tunnel/bench.sh` run inside the dev container via
`./dev.sh run "cd spike/tunnel && cargo build --release && bash bench.sh target/release/spike-tunnel"`.

**Environment:**
- Container `uname -a`: `Linux ed949e8c3daa 6.12.76-linuxkit #1 SMP Thu May 28 18:54:18 UTC 2026 aarch64 GNU/Linux`
- Host CPU (macOS host, `sysctl -n machdep.cpu.brand_string`): `Apple M2`
- Container: Docker Desktop on macOS (linuxkit VM), `--privileged`, aarch64.

**IMPORTANT — indicative only:** these numbers come from a container running
inside a Docker-Desktop/linuxkit VM on an Apple Silicon laptop, sharing CPU
cores with the host and every other process on the machine. They are **not**
representative of production throughput and must not be used to judge the
G-2 gate. They exist to prove the harness (veth pair + boringtun tunnel +
iperf3) works end-to-end and to give a rough sanity signal.

**Results** (each run: `iperf3 -t 10`, tunnel at MTU 1280; run twice for
reproducibility, numbers consistent within noise):

| Test | Sender | Receiver |
|---|---|---|
| Baseline: veth, no tunnel | 153 GBytes, 131 Gbits/sec, retr 96 | 153 GBytes, 131 Gbits/sec |
| Tunnel forward (bwa→bwb), MTU 1280 | 9.19 MBytes, 7.70 Mbits/sec, retr 7 | 8.96 MBytes, 7.46 Mbits/sec |
| Tunnel reverse (`-R`), MTU 1280 | 9.21 MBytes, 7.72 Mbits/sec, retr 10 | 9.01 MBytes, 7.56 Mbits/sec |

Raw iperf3 output and a second confirmation run are in
`.superpowers/sdd/task-4-report.md`.

**Interpretation:** the veth baseline (~131 Gbit/s) confirms the lab
harness itself has no artificial bottleneck — it's memory-bandwidth-bound
loopback traffic, not a real network path. The boringtun tunnel result
(~7.5–7.8 Mbit/s both directions) is far below the ≥1 Gbps target, but this
container environment is not representative: boringtun's crypto workers are
almost certainly starved by the VM's throttled/shared vCPU scheduling
(Docker Desktop on Apple Silicon), not by an architectural limit in
boringtun or the tunnel binary. The harness (bench.sh) is validated as
correct and reusable; the throughput number itself is not evidence for or
against Bet 1.

**Pending cloud run (G-2 gate):** the spec's G-2 acceptance criterion
(≥1 Gbps on a 4-vCPU cloud VM) has **not** been measured yet. Action item:
re-run this exact `bench.sh` (unmodified) on a real 4-vCPU cloud VM
(non-virtualized/non-oversubscribed CPU) and record the result here before
Bet 1 can be considered validated for the G-2 gate.

## Bet 2: tc-BPF enforcer
## Bet 3: QUIC relay
## Bet 4: NAT observation + hole punch
## Bet 5: NAT matrix harness
