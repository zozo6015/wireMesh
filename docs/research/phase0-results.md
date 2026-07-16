# Phase 0 Spike — Measured Results

Environment (all measurements): dev container on Docker Desktop for Mac (linuxkit
VM, `--privileged`, aarch64), kernel `6.12.76-linuxkit`, `nproc=8`, host CPU Apple
M2. Per-bet environment specifics are repeated in each section. **These container
numbers are indicative only — never the G-2 gate** (see Bet 1). Final synthesis and
go/no-go per bet: [`phase0-report.md`](phase0-report.md).

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
   in the "same" namespace. BPF object IDs are system-global, though: at
   startup (after pinning) `enforcer run` writes a pin-dir-keyed map-id file
   to `/tmp/enforcer-<sanitized pin dir>.mapids.json` (`/tmp`, unlike `/sys`,
   survives the unshares as one shared mount), and `stats --pin-dir X` tries
   the pin first, then that instance's id file (`MapData::from_id`, with the
   map's name re-verified via `MapInfo` to catch stale ids from dead
   enforcers). It never enumerates loaded maps by name — with multiple
   enforcers per kernel (Task 8 runs two) that silently returns whichever
   instance loaded first. Verified manually: two concurrent enforcers with
   `--pin-dir /sys/fs/bpf/aeth-a`/`aeth-b`, traffic denied on side A only →
   `stats` reads `deny:3` vs `deny:0` deterministically via both resolution
   paths, and a bogus id in the file errors out loudly instead of guessing.
   (Off-tun aside from that check: on a veth, most frames hit the
   "unparseable => SHOT, no counter" path because byte 0 is an ethernet MAC,
   not an IPv4 header — the enforcer is tun-only by design, spec §1.)
   The id-file name embeds an FNV-1a hash of the full pin-dir path (plain
   sanitization is not injective: `aeth_a` vs `aeth/a`). Known limitation:
   the stale-id guard re-verifies only the map NAME, and every enforcer
   instance names its map COUNTERS — name-based re-verification cannot
   detect id reuse by a same-named map from another instance; the window
   requires a stale id file AND kernel id reuse.
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

### Task 7: first-match rule scan + atomic A/B table flip + SIGHUP reload (2026-07-15)

**Result: validated.** First-match linear rule scan (`scan_rules` in
`spike/enforcer/enforcer-ebpf/src/main.rs`) reads `ACTIVE` exactly once per
packet, then walks the selected table (`RULES_A`/`RULES_B`, prefix + proto +
port match, first match wins, default-deny on no match). Userspace
`apply_rules` (`spike/enforcer/enforcer/src/main.rs`) parses the rules JSON,
writes the **inactive** table, sets that table's `RULE_LEN` entry, then does
a single `ACTIVE.set(0, target, 0)` as the atomic flip. `enforcer run` now
installs a `signal-hook` SIGHUP handler *before* the first `apply_rules`
call and loops on `signals.forever()`, re-running `apply_rules` on every
`SIGHUP` instead of parking.

Canonical command, run 3 times consecutively (no flakiness observed):
```
./dev.sh run "cd spike/enforcer && SPIKE_TUNNEL_BIN=/work/spike/tunnel/target/release/spike-tunnel cargo test -- --test-threads=1 --nocapture"
# test allow_rule_permits_tcp_and_denies_others ... ok
# test default_deny_drops_overlay_ping_and_counts ... ok
# test rule_flip_under_traffic_never_transiently_denies ... ok
# test result: ok. 3 passed; 0 failed  (each run ~25.8s for the enforce.rs harness)
```

**Flip-under-traffic test (`rule_flip_under_traffic_never_transiently_denies`):**
continuous `ping -i 0.2 -c 60` (~12s) from ns `a` overlapped with 50
`kill -HUP` reloads of the *same* icmp-allow ruleset at 100ms intervals
(~5s of flipping) against the enforcer in ns `b`. On **all 3 runs**: 0%
packet loss and the pinned `deny` counter unchanged across the flip storm —
the read-once-`ACTIVE` design gives every in-flight packet a consistent
view of either the pre-flip or post-flip table, never a transiently-empty
one. No transient denies or drops were observed on the first attempt or on
either repeat run.

**Verifier note:** the brief's kernel-side sketch used
`while i < len { ... i += 1; }` over the (runtime-bounded, `.min(64)`)
table length. Implemented instead as `for i in 0..64u32 { if i >= len {
break; } ... }` — a compile-time-bounded loop with a runtime early-exit —
per the plan's guidance, to keep the iteration count visibly finite to the
verifier rather than relying on it proving termination from a
data-dependent `while`. This compiled clean on the first attempt; no
verifier rejection was actually hit, but the bounded form was used
preemptively rather than risking one.

**Prerequisite bug found and fixed (this task's real "finding"):** the
Task-6 scaffold's `run()` had no signal handler at all — a bare
`std::thread::park()` loop. The test author's RED report identified that
`SIGHUP`'s default disposition is process termination, so the *first* of
the flip test's 50 `kill -HUP` calls killed the enforcer outright (not
"reloaded" it), silently detaching TCX enforcement from `wg0` and leaving
the rest of the ping run passing through unenforced — a false-positive-
looking near-0%-loss result for the wrong reason. Fixed by installing the
`signal-hook` `Signals::new([SIGHUP])` handler *before* the first
`apply_rules` call in `run()`, so the process's disposition for `SIGHUP` is
never the default. Once fixed, the test measures what it's meant to:
repeated real reloads under live traffic. No residual read-once/visibility
anomaly was found — the A/B flip design behaved exactly as specced across
all 3 runs.

### Task 8: stateful reply path with enforcers on both gateways (2026-07-15)

**Result: validated.** New test `reply_traffic_passes_via_flow_table_with_enforcers_on_both_sides`
(spike/enforcer/enforcer/tests/enforce.rs) runs enforcers on **both** sides of
the tunnel at once (ns b: allow inbound tcp:5201; ns a: allow nothing
inbound) and proves the SYN-ACK reply, which arrives at A's tun ingress with
no rule permitting it, is let through solely by A's egress-recorded flow
table — confirmed for the right reason via A-side stats after the iperf3
run: `allow:0, deny:0, flow_hit:938` (A's static table never matched
anything and default-deny never fired; every reply packet was resolved by
the flow table first). Full suite green 4/4 twice consecutively
(`./dev.sh run "cd spike/enforcer && SPIKE_TUNNEL_BIN=/work/spike/tunnel/target/release/spike-tunnel cargo test -- --test-threads=1 --nocapture"`,
~30.7-30.8s per run). No implementation changes were needed — the two
likely-failure-cause hypotheses in the task brief (pin-dir collision, fixed
in commit be8f904; FlowKey byte-order asymmetry) did not materialize.

### Task 9: ICMP embedded-error pass/deny via egress-recorded flows (2026-07-15)

**Result: validated — Bet 2 COMPLETE.** New kernel branch in `try_ingress`
(`spike/enforcer/enforcer-ebpf/src/main.rs`), inserted between the flow-table
lookups and the rules scan: for inbound ICMP (proto 1) with type 3/11/12
(dest-unreachable / time-exceeded / parameter-problem), parse the EMBEDDED
original IPv4 header at `ihl + 8`, extract its src/dst/proto and first 8 L4
bytes (ports), and pass (`TC_ACT_PIPE`, bumping `icmp_err_pass`) iff that
embedded 4-tuple+proto matches a flow this segment recorded at egress — the
spec §5.3 / Cilium approach. Non-matching ICMP errors fall through to the
rules scan and default-deny.

New crafted-packet injector `spike/enforcer/enforcer/src/bin/pktgen.rs`
(raw ICMPv4 socket via socket2): sends one type-3/code-4 frag-needed packet
embedding a caller-specified fake original IPv4+TCP header.

Test `icmp_error_for_recorded_flow_passes_unrelated_icmp_error_dropped`
(tests/enforce.rs): A enforces with an empty ruleset; a python3
source-port-44444 connect attempt from A records the outbound flow (the
container image ships no `nc`/`ncat`/`socat` — test-only substitution, no
implementation change); B injects (1) a frag-needed embedding the exact
recorded flow — asserted to bump `icmp_err_pass` by **exactly** 1 — and (2)
one embedding an unrecorded 4-tuple — asserted to bump `deny`. Green for the
right reason on strict assertions.

Canonical command, full suite 5/5 twice consecutively (~33.4s), plus the new
test re-run in isolation for a flakiness check:
```
./dev.sh run "cd spike/enforcer && SPIKE_TUNNEL_BIN=/work/spike/tunnel/target/release/spike-tunnel cargo test -- --test-threads=1 --nocapture"
# test result: ok. 5 passed; 0 failed
```

**Verifier fights:** none — the branch compiled and loaded clean on the first
attempt (bounded explicit offsets, `.map_err(|_| ())?` on required loads,
`.unwrap_or(0)` on the embedded L4 port loads). The only friction was
userspace: socket2 0.5's `Type::RAW` is gated behind its `all` feature, so
the dep is `socket2 = { version = "0.5", features = ["all"] }`.

**Bet 2 summary — COMPLETE.** Kernel `6.12.76-linuxkit` (Docker Desktop,
aarch64, aya 0.14 via TCX). All five enforcer behaviors proven by the 5-test
suite: (1) attach-on-tun with L3-only parsing (no ethernet header, Task 6);
(2) default-deny + pinned counters (Task 6); (3) first-match scan + atomic
A/B table flip under live traffic, 0% loss across 50 SIGHUP reloads (Task 7);
(4) stateful reply path via egress-recorded flow table with enforcers on both
gateways (Task 8); (5) ICMP embedded-error pass/deny (Task 9).

**Carried design finding (deferred, tracked for MVP):** ICMP-ECHO
reverse-flow keying is asymmetric (egress records echo as `{sport: id,
dport: 0}`; ingress reverse lookup swaps to `{sport: 0, dport: id}`), so
inside-initiated echo *replies* don't match the flow table — ICMP *errors*
work (proven here, disjoint type set, independent of the echo encoding);
echo return-path keying still needs a dedicated fix task.

## Bet 3: QUIC relay

### Task 13: QUIC datagram relay with mandatory mutual TLS (2026-07-15)

**Result: validated.** `spike/relay`'s `mkcerts`/`relay`/`Client` (quinn 0.11
+ rustls 0.23 + rcgen 0.13) prove all three of Bet 3's claims in one
integration test, `spike/relay/tests/bridge.rs::bridges_datagrams_and_rejects_certless_clients`,
run entirely in the root netns on loopback (no NAT needed to prove bridging
+ auth). Green twice consecutively:

```
./dev.sh run "cd spike/relay && cargo test -- --test-threads=1 --nocapture"
# test bridges_datagrams_and_rejects_certless_clients ... ok
# test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.94-0.96s
```

1. **Bridging:** `gw-A.send_to("gw-B", b"hello")` arrives at `gw-B.recv()`
   as `(src="gw-A", data=b"hello")` — the relay's `[8B dest_id][payload]` →
   `[8B src_id][payload]` rewrite is correct end-to-end.
2. **Datagram size (spec §6.1 floor: WG tunnel MTU 1280 + WireGuard overhead
   32 + this relay's 8-byte id header = 1320 bytes required):**
   `max_datagram_size()` measured **`Some(1414)`**, both immediately after
   `Client::connect` and again after a 500ms settle (identical both times —
   on loopback, DPLPMTUD's initial probe already lands at its ceiling, so
   there is nothing further to discover). **1414 >= 1320, ~94 bytes of
   headroom.** Loopback is not representative of the WG(1280)-constrained
   path the spec is actually worried about; re-measure once Task 14 (NAT
   punch integration) or a netns path with a real Ethernet-ish MTU is in
   play.
3. **Mandatory mutual TLS:** `Client::connect_no_cert` (no client
   certificate) cannot complete the connect+register+bridge flow — it
   returns `Err`. The rejection is **asynchronous**, not a clean handshake
   error: the client-side `endpoint.connect(...).await` and the subsequent
   `open_bi()`/id-write both succeed before the server's rejection lands;
   the failure actually surfaces one step later, awaiting the relay's
   registration ack (`recv.read_to_end(1)`), with message:
   `await registration ack: read error: connection lost: connection lost:
   aborted by peer: the cryptographic handshake failed: error 116: peer
   sent no certificates`. A naive assertion on the raw
   `endpoint.connect(...).await` future (bypassing the registration round
   trip) would be unreliable — the test asserts on `Client::connect_no_cert`'s
   aggregate `Result` instead, which is guaranteed to be `Err` regardless of
   which internal step actually surfaces the rejection, since it wraps
   connect + open_bi + write + ack-read into one `Result`-returning async
   fn. Mutual TLS is enforced for real, not merely by convention.

**API friction vs. the brief** (rustls-pemfile needed for on-disk PEM→DER,
explicit process-default `CryptoProvider` install, quinn's rustls→QuicConfig
conversion step, `IdleTimeout` not being a bare `Duration`, datagrams needing
enabling on both endpoints not just the server, and — the one substantive
design fix, not just an API-version gap — registration switched from a
uni-stream to an acked bi-stream to close a real race where `send_to` could
fire before the relay's registry insert had happened) is recorded in full in
`.superpowers/sdd/task-13-report.md`.

### Task 14: WireGuard over the QUIC relay, end to end, at tun MTU 1280 (2026-07-15)

**Result: validated — the single most load-bearing spike result.** Real
WireGuard traffic (boringtun via `spike-tunnel`) handshakes and flows
through Task 13's authenticated QUIC relay via a new `udpshim` bridge
(`spike/relay/src/bin/udpshim.rs`), across a 3-netns lab where the two
gateways (`a`, `b`) have **no direct underlay link at all** — `r` (running
`relay`) is the only path between them. `udpshim <bind> <relay_addr>
<certdir> <my_id> <peer_id>` bridges a local UDP socket (where WireGuard's
peer "endpoint" is pointed) to the relay: local recv → `Client::send_to`
to a fixed peer id; relay `recv()` → forwarded to whichever local address
last sent something.

Topology (`spike/relay/tests/wg_over_relay.rs::wireguard_handshakes_and_pings_at_mtu_1280_over_relay`):
```
a::u0 (10.9.3.1/24) --veth-- r::ur0 (10.9.3.2/24)   [relay binds here: 10.9.3.2:4443]
b::u1 (10.9.4.1/24) --veth-- r::ur1 (10.9.4.2/24)   [b routes 10.9.3.0/24 via 10.9.4.2]
wg0 in a and b: overlay 10.10.0.1 <-> 10.10.0.2, tun MTU 1280,
  peer "endpoint" = 127.0.0.1:51999 in BOTH — each side's own local udpshim,
  never the other side's underlay address (none exists).
```
Confirmed there is no other path before trusting a ping success as proof:
`a`'s ping to `b`'s underlay address (10.9.4.1) fails outright (no route) —
any overlay traffic that gets through therefore *must* have traversed the
relay. Also confirmed directly in the relay's own log:
`relay: registered "gw-A" from 10.9.3.1:...` and `registered "gw-B" from
10.9.4.1:...` both present every run.

**Shim peer-learning chicken/egg (a real design property, not a bug):**
`udpshim`'s downlink can only deliver a relayed datagram to whichever local
address last sent it something — there is no local peer on record until the
local WireGuard instance has sent at least once through its own shim. If
only one side pinged, that side's handshake-initiation would reach the
peer's shim and be silently dropped (peer's shim has no local address on
record yet). The test runs a background ping from **both** `a` and `b`
concurrently before checking for a handshake, so each side's own wg0
independently queues outbound traffic and primes its own shim, regardless of
whether the peer's messages arrive first.

All three required properties, green twice consecutively (`cargo test --
--test-threads=1 --nocapture`, full suite including Task 13's `bridge.rs`):

1. **WG handshake completes over the relay:** `wg show wg0 latest-handshakes`
   goes non-zero on both sides within ~1.1s of the background pings
   starting (`elapsed=1.09s` both runs). *Friction/curiosity, not a
   blocker:* the reported epoch value itself was `1` on both sides both
   runs, not a plausible Unix wall-clock timestamp (~1.7×10⁹) — suggests
   boringtun's UAPI `latest-handshakes` in this build may not be reporting
   true wall-clock time. Not investigated further: the brief's own bar is
   "non-zero," which this unambiguously clears, and the handshake's actual
   effect (overlay ping/iperf3 below) is independently proven to work.
2. **MTU boundary is real, both directions:** `ping -c 3 -M do -s 1232` (1260
   bytes on the wire, under the 1280 tun MTU) succeeds; `ping -c 1 -M do -s
   1400` (1428 bytes, over 1280) fails outright. Both held on both runs —
   the relay carries traffic exactly up to the design MTU and not beyond.
3. **iperf3 through the relay:**
   - Run 1: sender 2.41 MBytes / 3.00s = **6.74 Mbits/sec**; receiver 2.19
     MBytes / 3.10s = 5.93 Mbits/sec.
   - Run 2: sender 2.90 MBytes / 3.00s = **8.11 Mbits/sec**; receiver 2.72
     MBytes / 3.09s = 7.38 Mbits/sec.
   - Single-hop QUIC-relayed throughput on loopback-class veth links in the
     dev container; not a production bandwidth estimate (no real WAN RTT/
     loss in this lab), but confirms the relay path carries sustained TCP
     traffic at the 1280 MTU without stalling or erroring.

Canonical command (both runs green):
```
./dev.sh run "cd spike/tunnel && cargo build --release && cd ../relay && \
  SPIKE_TUNNEL_BIN=/work/spike/tunnel/target/release/spike-tunnel \
  cargo test -- --test-threads=1 --nocapture"
# tests/bridge.rs::bridges_datagrams_and_rejects_certless_clients ... ok
# tests/wg_over_relay.rs::wireguard_handshakes_and_pings_at_mtu_1280_over_relay ... ok
# test result: ok. 1 passed; 0 failed (bridge.rs, ~0.95s)
# test result: ok. 1 passed; 0 failed (wg_over_relay.rs, ~10.2-10.3s)
```

## Bet 4: NAT observation + hole punch

### Task 11: UDP-native NAT observation endpoint (2026-07-15)

**Result: validated.** `spike/punch`'s `observe`/`whoami`/`punch::observe` prove
a UDP-native observation endpoint reports the client's post-NAT public
mapping, never the private address (`spike/punch/tests/observe.rs`,
`observation_reports_nat_mapping_not_local_addr`). Full detail:
`.superpowers/sdd/task-11-report.md`.

### Task 12: brokered UDP hole punch — validated, with two real findings (2026-07-15)

**Result: validated.** `spike/punch/tests/punch.rs` builds the full
two-NAT topology (`pa--ra--inet--rb--pb`; `observe` + `broker` on the
`inet` ns; fresh Lab per cell) and proves the Bet 4 punch matrix, green and
deterministic across 3 consecutive full-suite runs:

| Cell | A result | B result | Verdict |
|---|---|---|---|
| PortRestricted x PortRestricted | `PUNCHED 198.51.100.130:6100` (exit 0) | `PUNCHED 198.51.100.2:6100` (exit 0) | brokered simultaneous punch works ✓ (3/3 runs, identical output) |
| Symmetric x Symmetric | `punch failed (timeout)` (exit 1) | `punch failed (timeout)` (exit 1) | pair does NOT punch ✓ (3/3 runs) |

**Right-reason check (asserted in the test, not just eyeballed):** each
side's `PUNCHED` address is the *peer router's public out0 address*
(`198.51.100.130` seen by A, `198.51.100.2` seen by B) — never loopback,
never a private address. In the symmetric cell each side's observed
candidate had a different random external port per run (e.g. A observed
`:53805`, `:2626`, `:16215` across the 3 runs) — per-destination mapping
means the registered candidate is the wrong port for the peer, exactly why
punching fails and **exactly the case the QUIC relay (Tasks 13–14) exists
for**.

**Time-to-punch:** with the lab's modeled 40ms one-way inter-NAT latency
(see finding 2), the positive cell resolves in well under a second — a
manual end-to-end run measured ~160ms from puncher spawn to both PUNCHED
(includes observation + broker registration + go + first PING/PONG
round trip); the whole punch.rs suite (positive cell + symmetric cell's
full 5s timeout burn) runs in ~6.9s. Canonical command:

```
./dev.sh run "cd spike/punch && cargo test -- --test-threads=1 --nocapture"
# test observation_reports_nat_mapping_not_local_addr ... ok
# test port_restricted_pair_punches ... ok
# test symmetric_pair_fails_to_punch ... ok
```

**Finding 1 (implementation bug, found by these tests, fixed in
`puncher.rs`):** the initial puncher advertised a `0.0.0.0:{port}`
"local guess" candidate. Linux silently rewrites `sendto()` to destination
`0.0.0.0` into `127.0.0.1`, so every puncher PINGed *itself* over loopback
and instantly self-"punched" (`PUNCHED 127.0.0.1:6100` for both peers, in
both NAT cells, 3/3 runs — deterministic, masking the real punch outcome
entirely and making even the symmetric cell spuriously "succeed"). Fixed by
registering only the observed post-NAT candidate plus a defensive skip of
unspecified/loopback candidates in the PING loop. The positive test now
asserts the punched address is the peer's real public address, so this
class of bug cannot regress silently.

**Finding 2 (lab-fidelity requirement — the important one for Sync's
design):** with zero-latency veth links, brokered simultaneous punch
through Linux-masquerade NATs fails **deterministically** (0% punch, both
cells). Cause, confirmed via `/proc/net/nf_conntrack` mid-punch: the peer's
first PING arrives at the local router *before* the local side's own first
outbound has crossed it; the unsolicited inbound creates a local-stack
conntrack entry occupying the `:6100` reply tuple, so the local side's
masquerade is forced onto a mutated source port (observed: A's mapping
pushed to `sport=51642` beneath an `[UNREPLIED] .130:6100 -> .2:6100`
entry) — after which neither direction can match, for conntrack's 30s UDP
unreplied timeout (far beyond the 5s punch window). Simultaneous punch
relies on each side's first outbound beating the peer's inbound through its
own NAT; on the real internet, one-way path latency (tens of ms) >> broker
go-skew (µs–ms), guaranteeing it. The lab restores that invariant with
`tc netem delay 20ms` on each internet-side link (40ms one-way). With
delay: 3/3 success; without: 0% — this is a modeled-physics fix, not a
flakiness mask. **Design implication for Sync (spec §6.1):** go-skew
between the two peers must stay below the inter-peer one-way latency, or a
Linux-NAT'd peer's mapping gets poisoned for ~30s; a production broker
should send "go" as simultaneously as possible (and/or peers should
tolerate/retry after a mapping-poisoning window). Recorded for the MVP
design, not fixed in the spike.

**Topology note (deviation from the task brief):** the brief's sketch gave
ra's public link a /24 (`198.51.100.2/24`), which makes ra consider rb's
public address (`198.51.100.130`) on-link and ARP for it into the void —
no punch traffic can flow in either direction (verified: `ip neigh` shows
`INCOMPLETE`, 100% loss both ways). The test uses a /25 split instead
(`198.51.100.0/25` on ra's side, `198.51.100.128/25` on rb's), which routes
cleanly via `inet`.

Full diagnosis narrative: `.superpowers/sdd/task-12-report.md`.

<details>
<summary>Superseded interim entry (test author's BLOCKED_ON_IMPL report for finding 1, kept for the record)</summary>

### Task 12 (interim): brokered UDP hole punch — BLOCKED_ON_IMPL, real bug found (2026-07-15)

**Status: blocked, not committed.** The test author (`spike/punch/tests/punch.rs`,
`port_restricted_pair_punches` / `symmetric_pair_fails_to_punch`) built the
brief's exact `pa--ra--inet--rb--pb` topology and ran the brokered punch for
both `NatKind::PortRestricted` and `NatKind::Symmetric`. **Every single run
(3/3, fully deterministic, no flakiness) printed `PUNCHED 127.0.0.1:6100`
for both peers, in both NAT cells** — never the peer's real masqueraded
address (e.g. `198.51.100.130:6100`). That address is impossible for a
genuine cross-NAT punch (pa/pb/ra/rb/inet are separate netns; a real reply
would show up as the peer's public `198.51.100.x` address, never loopback),
so the `PUNCHED` result is not evidence the brokered design works — it's a
different bug entirely.

**Root cause (confirmed by direct reproduction, independent of natlab):**
`puncher.rs` registers two candidates per side — `observed` and a
`local_guess` of `"0.0.0.0:{port}"` — and blasts `PING` at both. On this
kernel, `sendto()` to destination `0.0.0.0:<port>` is silently rewritten to
`127.0.0.1:<port>` (classic Linux/BSD INADDR_ANY-as-destination behavior).
Verified directly:

```
$ python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('0.0.0.0', 9999))
s.settimeout(2); s.sendto(b'hello', ('0.0.0.0', 9999))
print(s.recvfrom(64))"
received from ('127.0.0.1', 9999)
```

Since every puncher binds and blasts from the *same* port it's pinging, this
means **every puncher instance PINGs itself over loopback and replies to
itself** — a self-punch that resolves near-instantly (same-process
loopback, no network hop), always winning the race against any real
cross-NAT round trip. Total suite time (~1.6s for both cells, both with 5s
internal timeouts available) corroborates: nothing waited on a real
network round trip.

**Why this blocks both test cells:** the implementer's phase-1 report
(`.superpowers/sdd/task-12-report.md`) explicitly assessed this candidate as
"dead weight ... simply unreachable in practice," verified only via a
same-host root-netns smoke test with no NAT/netns isolation in the path —
that assessment does not hold once real network namespaces are involved.
With the bug live, the positive cell (`port_restricted_pair_punches`)
currently passes, but for an unverifiable reason — the real
`observed`-candidate exchange may or may not be working; the self-loop masks
it either way. The negative cell (`symmetric_pair_fails_to_punch`) fails
outright because the same self-loop makes the symmetric case spuriously
"succeed" too, which is exactly the CLAUDE.md-flagged "failing behavior test
may be a real finding" case — investigated, and the finding is an
implementation bug, not a surprising real symmetric-punch success.

**Recommended fix (for the implementer, not applied here — out of scope for
test authorship):** `puncher.rs` should filter out any candidate whose
address is unspecified/loopback (`0.0.0.0`, `127.0.0.0/8`) before sending,
or simply drop the `local_guess` candidate — per the implementer's own doc
comment it never represents a dialable on-link peer in this lab.

**Not committed:** `spike/punch/tests/punch.rs` is written (matches the
brief, both cells) and correctly surfaces this bug, but per the task's
BLOCKED_ON_IMPL protocol, it is left uncommitted pending a `puncher.rs` fix
by the implementer and a re-run to confirm the tests then measure the real
positive/negative punch behavior described in the brief.

*(Interim entry ends here — superseded by the validated Task 12 entry
above: the implementer fixed the candidate bug, after which a second real
issue — the zero-latency conntrack poisoning, finding 2 — was diagnosed and
addressed via lab-fidelity netem delay, and both cells went green 3/3.)*

</details>

## Bet 5: NAT matrix harness

### Task 10: NAT cells — port-restricted + symmetric, behavior-proven (2026-07-15)

**Result: validated.** `natlab` (spike/natlab) gained
`pub enum NatKind { PortRestricted, Symmetric }` and
`Lab::nat_router(name, kind) -> Result<Ns>`: a router namespace with
`net.ipv4.ip_forward=1` and an nftables `ip nat` postrouting masquerade on
`out0` (convention: outside iface `out0`, inside `in0`; callers wire veths).
`PortRestricted` = plain `masquerade`; `Symmetric` = `masquerade fully-random`.

Behavior proven by observed external source ports, not just rule
installation (`spike/natlab/tests/nat_behavior.rs`: one client UDP socket
bound to :6000 sends to two server addresses through the router; per-address
`udpsink` example binaries report the peer port they saw):

| Cell | Observed ports (dst1 / dst2) | Verdict |
|---|---|---|
| PortRestricted (`masquerade`) | 6000 / 6000 (equal, port-preserved) | endpoint-independent mapping ✓ |
| Symmetric (`fully-random`) run 1 | 29207 / 55524 (differ) | per-destination mapping ✓ |
| Symmetric (`fully-random`) run 2 | 62412 / 13809 (differ) | per-destination mapping ✓ |
| Symmetric (`fully-random`) run 3 | 45104 / 28754 (differ) | per-destination mapping ✓ |

**Risk that did NOT materialize:** the brief flagged that kernel SNAT
port-preservation might defeat `fully-random` (making the "symmetric" cell
endpoint-independent). On this kernel (`6.12.76-linuxkit`, aarch64,
nftables in the dev container) `masquerade fully-random` genuinely maps
per-destination — no fallback (`masquerade random` or explicit
per-destination `snat to :range` rules) was needed.

**CGNAT:** no dedicated `NatKind` — CGNAT is composed as two chained
`Symmetric` routers; the composition will be demonstrated in the later
hole-punch tests (Bet 4 matrix), not by a separate cell type.

**nft syntax finding:** the brief's one-line ruleset
(`table ip nat { chain post { ...; } }`) does not parse — nft requires a
newline (or standalone semicolon line) before closing braces; a bare `; } }`
fails with `syntax error, unexpected '}'`. The constructor emits the ruleset
with real newlines.

Canonical command (all 3 natlab tests green):
```
./dev.sh run "cd spike/natlab && cargo build --examples && cargo test -- --test-threads=1 --nocapture"
# test port_restricted_nat_is_endpoint_independent ... ok
# test symmetric_nat_maps_per_destination ... ok
# test veth_pair_pings ... ok
# test result: ok. 2 passed (nat_behavior) + 1 passed (veth_ping); 0 failed
```
