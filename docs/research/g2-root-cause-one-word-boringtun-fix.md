# G-2 root cause: `Type::STREAM` in boringtun's per-peer connect — one word, 378×

**Date:** 2026-08-27, same session as
`g2-bet1-receive-cap-reproduced-on-bare-metal.md`, which this note SUPERSEDES
in its verdict: **Bet 1 does not reopen. The receive cap is a one-line bug in
upstream boringtun 0.6.0, found, patched (vendored), and proven on the same
harness within the hour.**

## The diagnosis chain (each step one measurement)

1. `strace -c` on the receiving `DeviceHandle` under 100 Mbit UDP load:
   1,719 `recvfrom` in 6 s (≈286 pps — the observed drain rate), 79% of
   syscall time in `epoll_wait` (4.1 ms/call), and the tell: **1,724
   `socket()` calls, 1,718 of them failing** — a socket-creation attempt per
   received packet.
2. errno capture: `socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_UDP)
   = -1 EPROTONOSUPPORT` — **`SOCK_STREAM` with `IPPROTO_UDP`**, an invalid
   combination, on every packet.
3. Source: `boringtun-0.6.0/src/device/peer.rs:120` builds the per-peer
   **connected** UDP socket with `Type::STREAM`; the listening sockets at
   `device/mod.rs:430/440` correctly use `Type::DGRAM`. A one-word typo.
   Consequence: the connected-socket fast path (which registers the peer's
   epoll-driven receive route) can never be created; every inbound packet
   takes an error path that re-attempts the socket and drains ~1 packet per
   multi-ms epoll cycle. Send side is unaffected — hence Phase 0's "0% send
   loss, ~98% receive loss" signature.

## The fix, proven

Vendored boringtun 0.6.0 with `Type::STREAM → Type::DGRAM` at `peer.rs:120`
(`[patch.crates-io]` in the harness). Same host, same harness, same day:

| configuration | before | after |
|---|---|---|
| TCP, unpinned | 2.81 Mbit/s | **1.15 Gbit/s** |
| TCP, pinned 4 vCPU (2 cores + SMT), MTU 1280 | 3.04 Mbit/s | **966 Mbit/s** (best; 899–966 across runs; n_threads=2 optimal, =4 worse on 2 cores; 16 MiB socket buffers no help) |
| TCP reverse, pinned | 2.88 Mbit/s | 943 Mbit/s |
| UDP 100M offered | 97% loss | **0% loss** |

## G-2 standing

- **The cap is gone; the mechanism is closed.** ~380× on the pinned shape.
- The pinned-4-vCPU single-flow number on EPYC 9454P hovers **at** the ≥1 Gbps
  bar (966 best), and clears it unpinned (1.15 G). The criterion's platform is
  c6i.xlarge-class (Ice Lake ~3.5 GHz sustained all-core vs EPYC's lower
  per-core under this pin) — the gate number should be taken on that platform,
  or the marginal EPYC number accepted by owner ruling.
- Still unmeasured: the **8-tunnel ≥1 Gbps aggregate** half of G-2 (needs an
  8-peer harness — does not exist yet).

## What ships (follow-ups filed)

1. **Vendor the one-line boringtun patch into wiremesh** (fork or
   `[patch.crates-io]`), release, and roll to the fleet — every deployed
   gateway currently carries the 0.6.0 bug and a ~3 Mbit/s ceiling.
2. **Upstream the fix** to cloudflare/boringtun.
3. Build the 8-tunnel aggregate harness; take the canonical single-flow number
   on a c6i.xlarge-class instance (or rule the EPYC number sufficient).
4. Harness quirks recorded for reuse (`aether-prod-fi-01:/root/g2bench/`):
   `bench.sh`'s original `pkill -f` self-kill (fixed with `pkill -x`); the
   `bench2.sh`/`bench3.sh` diagnostic variants (socket counters; strace/perf).
