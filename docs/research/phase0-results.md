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

Raw iperf3 transcripts for both runs are in the appendix at the end of this
section.

**Interpretation:** the veth baseline (~131 Gbit/s) confirms the lab
harness itself has no artificial bottleneck — it's memory-bandwidth-bound
loopback traffic, not a real network path. The boringtun tunnel result
(~7.5–7.8 Mbit/s both directions) is far below the ≥1 Gbps target. **The
cause has not been isolated.** A follow-up diagnostic (independent reviewer,
reusing the exact same netns/tunnel setup, MTU 1280, same binary; container
`nproc` = 8) found:

- UDP burst at `-b 500M`: the sender pushed the full offered rate with 0%
  send-side loss, but the receiver delivered only ~7.27 Mbit/s with **98%
  datagram loss** (250169/254031 lost).
- Parallel TCP `-P 4`: aggregate ~8.0 Mbit/s — parallelism does not move
  the cap.
- TCP retransmits were low (7–10 per 10 s run) — ruling out MSS problems or
  a retransmit storm.

The pattern — a fixed ~7.3–7.8 Mbit/s **receive-side delivery cap**,
independent of protocol, parallelism, and offered rate — is the signature of
a receive-pipeline bottleneck (decrypt→TUN write, or an internal queue
overflowing and dropping), and is **inconsistent with pure environment
noise** such as shared-vCPU scheduling. It may still be an artifact of this
Docker-Desktop/linuxkit-on-Apple-Silicon environment, but that is a
hypothesis, not a finding. The harness (bench.sh) is validated as correct
and reusable; the throughput number itself is not evidence for or against
Bet 1.

**Pending cloud run (G-2 gate):** the spec's G-2 acceptance criterion
(≥1 Gbps on a 4-vCPU cloud VM) has **not** been measured yet. Action item:
re-run this exact `bench.sh` (unmodified) on a real 4-vCPU cloud VM
(non-virtualized/non-oversubscribed CPU) and record the result here before
Bet 1 can be considered validated for the G-2 gate. **First thing to check
on that run:** whether the receive-side delivery cap reproduces — rerun
iperf3 with `-u -b 0` and inspect the **Lost/Total datagrams** column, not
just Mbit/s. If the ~98% receive-side loss reproduces on real hardware, the
bottleneck is in the boringtun receive pipeline, not this environment, and
Bet 1 is at risk.

### Appendix: raw iperf3 output (Bet 1)

Run 1 (full `cargo build --release` + bench; build finished in 7.52 s):

```
== baseline: veth, no tunnel ==
[  5]   0.00-10.00  sec   152 GBytes   131 Gbits/sec   26             sender
[  5]   0.00-10.00  sec   152 GBytes   131 Gbits/sec                  receiver

iperf Done.
spike-tunnel: device spike-tunnel: device wg1wg0 up; configure with `wg set  up; configure with `wg set wg1wg0 ...`
 ...`
== boringtun tunnel, mtu 1280 ==
[  5]   0.00-10.00  sec  9.27 MBytes  7.78 Mbits/sec    6             sender
[  5]   0.00-10.07  sec  9.08 MBytes  7.56 Mbits/sec                  receiver

iperf Done.
== boringtun tunnel, udp + reverse ==
[  5]   0.00-10.01  sec  9.34 MBytes  7.83 Mbits/sec   10             sender
[  5]   0.00-10.00  sec  9.02 MBytes  7.57 Mbits/sec                  receiver

iperf Done.
```

Run 2 (confirmation, no rebuild):

```
== baseline: veth, no tunnel ==
[  5]   0.00-10.00  sec   153 GBytes   131 Gbits/sec   96             sender
[  5]   0.00-10.00  sec   153 GBytes   131 Gbits/sec                  receiver

iperf Done.
spike-tunnel: device wg1 up; configure with `wg set wg1 ...`
spike-tunnel: device wg0 up; configure with `wg set wg0 ...`
== boringtun tunnel, mtu 1280 ==
[  5]   0.00-10.00  sec  9.19 MBytes  7.70 Mbits/sec    7             sender
[  5]   0.00-10.07  sec  8.96 MBytes  7.46 Mbits/sec                  receiver

iperf Done.
== boringtun tunnel, udp + reverse ==
[  5]   0.00-10.00  sec  9.21 MBytes  7.72 Mbits/sec   10             sender
[  5]   0.00-10.00  sec  9.01 MBytes  7.56 Mbits/sec                  receiver

iperf Done.
```

(The interleaved `spike-tunnel: device ...` lines in run 1 are the two
tunnel processes' startup messages racing on stderr — cosmetic only.)

## Bet 2: tc-BPF enforcer

### Task 6: aya tc classifier scaffold — attach-on-tun + default-deny (2026-07-15)

**Result: validated.** tc-BPF (aya) attaches to a real WireGuard tun device
(boringtun via `spike-tunnel`), L3 parsing works with no ethernet header
(byte 0 is the IP header), and default-deny + pinned counters behave as
designed. Integration test `default_deny_drops_overlay_ping_and_counts`
(spike/enforcer/enforcer/tests/enforce.rs) is green, twice consecutively:
pre-enforcement overlay ping succeeds through the two-node WG lab; after
attaching `aeth_ingress`/`aeth_egress` on ns b's `wg0` with an empty rule
table, the overlay ping is dropped and the pinned `deny` counter reads >= 2.

Canonical command:
```
./dev.sh run "cd spike/enforcer && SPIKE_TUNNEL_BIN=/work/spike/tunnel/target/release/spike-tunnel cargo test -- --test-threads=1 --nocapture"
# test default_deny_drops_overlay_ping_and_counts ... ok
# test result: ok. 1 passed; 0 failed  (finished in ~5.1s)
```

**Environment:** Docker Desktop for Mac (aarch64), container Debian 12,
kernel `6.12.76-linuxkit`. Because the kernel is >= 6.6, aya 0.14 attaches
`SchedClassifier` via the **TCX link API**, not legacy netlink tc filters —
so `tc filter show dev ... ingress` shows nothing; use `bpftool prog show` /
`bpftool link show` to observe the attachment (link type shows as raw
`type 11` = BPF_LINK_TYPE_TCX with the container's bpftool).

**Docker Desktop / container BPF quirks found (both fixed in the enforcer,
not in dev tooling — a real gateway needs the same guarantees):**

1. `/sys/fs/bpf` is a plain sysfs directory, **not a mounted bpffs** — no
   `sys-fs-bpf.mount` equivalent in the container. `create_dir_all` /
   `BPF_OBJ_PIN` under it fail ENOENT. Fix: `enforcer run` now checks
   `statfs(/sys/fs/bpf).f_type == BPF_FS_MAGIC (0xcafe4a11)` and mounts
   bpffs itself before creating the pin dir.
2. **bpffs mounts don't cross `ip netns exec` invocations.** `ip netns exec`
   does its own `unshare(CLONE_NEWNS)` + `/sys` remount per invocation, and
   every bpffs mount is an independent, empty superblock — so maps pinned by
   the running enforcer are invisible to a later `enforcer stats` invocation
   in the "same" namespace. BPF object IDs are system-global, though: `stats`
   falls back to `aya::maps::loaded_maps()` and opens the map named
   `COUNTERS` by id (`MapData::from_id`) when the pin path is absent.
   Spike-grade: assumes one enforcer per kernel; revisit if that changes.
3. The aya template's `.cargo/config.toml` sets `runner = "sudo -E"`, which
   breaks all `cargo test`/`cargo run` in the root-only, sudo-less dev
   container ("No such file or directory" before any test executes). Runner
   removed — we're already root.

**aya API friction (vs. the Task 6 brief, which assumed aya 0.13):** the
template pins **aya 0.14.0 / aya-ebpf 0.2.1**; the brief's code nonetheless
matched the real API almost verbatim. Notable 0.14-era facts: aya raises
`RLIMIT_MEMLOCK` internally during `Ebpf::load` (the template's manual
`libc::setrlimit` dance is dead code); `#[classifier]` emits every tc program
into one shared `"classifier"` ELF section, discovered by symbol name (both
`aeth_ingress` and `aeth_egress` live there — expected, not a collision);
`cargo generate` for the template needs `$USER` set plus explicit
`-d default_iface=... -d direction=...` args to run non-interactively.
Full detail: `.superpowers/sdd/task-6-report.md`.

Also caught by the test author (recorded here so Task 7/8 tests don't trip
on it): `natlab::Ns::exec` bails with `Err` on any non-zero exit, so
"expect this command to fail" assertions must use `.is_err()`, never
`!output.status.success()`.

## Bet 3: QUIC relay
## Bet 4: NAT observation + hole punch
## Bet 5: NAT matrix harness
