# G-2 / Bet 1: the receive-side cap reproduces on bare metal — Bet 1 reopens

**Date:** 2026-08-27. **Measured by:** the team lead, on `aether-prod-fi-01`
(AMD EPYC 9454P, 48c/96t Zen 4, max 3.81 GHz, performance governor, Debian,
kernel with netns; bare metal, no virtualization). **Verdict: the Phase-0
receive-side cap is NOT environmental. Per the pre-ratified decision rule in
`docs/research/phase0-report.md` ("if the ~98% receive-side loss reproduces on
non-virtualized hardware, the bottleneck is boringtun's receive pipeline …
reopen the assessment and pursue a vendored fork"), Bet 1 REOPENS.**

## The measurement (Phase-0 `bench.sh` harness, recovered from `378f45e:spike/tunnel/`)

Two netns joined by veth, two `spike-tunnel` instances (boringtun 0.6.0
`DeviceHandle`, `n_threads = 2`), WG tun MTU 1280, iperf3 10s runs.

| run | result |
|---|---|
| veth baseline (no tunnel) | **36.9 Gbit/s** — the environment is not the limit |
| boringtun tunnel, TCP, pinned 4 vCPU (2 cores + SMT: 0,1,48,49) | **3.04 Mbit/s** (7 retr) |
| boringtun tunnel, TCP reverse | 2.88 Mbit/s |
| boringtun tunnel, TCP, **unpinned (96 CPUs)** | 2.81 Mbit/s |
| boringtun tunnel, UDP 100M offered | 3.32 Mbit/s delivered, **97% datagram loss** |

G-2's target is ≥ 1 Gbps: **missed by ~300×**. The Phase-0 container number
(~7.7 Mbit/s, ~98% loss) was the same phenomenon, not a linuxkit artifact.

## Localization — the loss is at the receiver's UDP socket, and it is drain-rate-bound

- Underlay veth of the receiving netns: **all 83,982 encrypted packets
  delivered, 0 interface drops** (`ip -s link`).
- Receiving netns `/proc/net/snmp`: `Udp: InErrors 78,674 =
  RcvbufErrors 78,674` — every lost datagram died because boringtun's UDP
  socket receive buffer was full.
- `net.core.rmem_default/rmem_max = 16 MiB`: **no change** (84–97% loss,
  ~3 Mbit/s). The buffer size is irrelevant because the *drain rate* is the
  constant: ~270 packets/second, i.e. ~3.7 ms consumed per datagram.
- `n_threads = 8` (rebuilt, verified in source): **no change.** The
  bottleneck is serial and per-packet.
- Pinned (4 logical CPUs) vs unpinned (96): **no change.** Not CPU quantity.

~270 pps on a 3.8 GHz Zen 4 core is not crypto cost (ChaCha20-Poly1305 does
GB/s per core); something in boringtun 0.6.0's device event loop stalls on the
order of milliseconds per packet on this path. Identifying the exact stall
(timer granularity, rate limiter, epoll wakeup pattern, TUN write path) is the
first task of the reopened bet, under perf/strace on this host — the harness
at `aether-prod-fi-01:/root/g2bench/spike/tunnel/` (with `bench2.sh`, the
diagnostic variant that reports the socket counters) reproduces it in seconds.

## The production data plane is the same engine

`crates/wiremesh-gateway/src/tunnel.rs` constructs `boringtun::device::
DeviceHandle` with `n_threads: 2` from crates.io boringtun 0.6.0 — the exact
configuration measured. The live fabric corroborates: it carries interactive
admin traffic fine (a ~3 Mbit/s ceiling is invisible to ssh) and has never
been bulk-load-tested; a live px→fi iperf3 attempt was inconclusive for
unrelated reasons (the pair had settled on the relay path that day).

## What this is not

- Not the environment (36.9 Gbit/s baseline; bare metal; loss reproduced).
- Not policy/enforcer (the harness runs no enforcer).
- Not the spike wrapper (14 lines; hands everything to `DeviceHandle`, same as
  the gateway).
- Not send-side (sender pushes line rate; 0 send-side loss in Phase 0 and here).

## Decision space (owner's call, pre-framed by the Phase-0 rule)

1. **Vendored boringtun fork patching the receive path** — the pre-ratified
   route. First step is diagnosis (perf top on the device threads), since a
   multi-ms per-packet stall may be a small fix (timerfd, busy-poll flag,
   syscall batching with recvmmsg) rather than a rewrite.
2. Kernel WireGuard as the primary data plane — a spec change (drops the
   LXC/no-module use case to optional), explicitly listed as the fallback,
   not the default, in the Phase-0 report.
3. Upstream triage first: check boringtun's issue tracker/master for a known
   fix newer than 0.6.0 before forking.

**G-2 remains unmet and unmeasurable until the data plane is fixed; the
number recorded for the gate today is 3.04 Mbit/s pinned-4-vCPU TCP.**
