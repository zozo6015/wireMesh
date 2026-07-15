# Phase 0 Spike Report — go/no-go per bet

**Date:** 2026-07-15 · **Author:** Phase 0 spike (Task 15 synthesis)

This is the decision artifact the MVP planning cycle (spec §12, plan cycle 2 of 4)
starts from. It synthesizes the measured results in
[`phase0-results.md`](phase0-results.md) and the maintenance-health recommendation in
[`boringtun-assessment.md`](boringtun-assessment.md). **All numbers here are cited
from those docs — none are invented in this report.** The five bets' behavior tests
were all re-run green one last time as Step 2 of this task (see
[Final verification](#final-verification) at the end).

## Verdicts

| Bet | Result | Evidence |
|---|---|---|
| 1. boringtun embed + throughput | **go-with-caveats** | `spike/tunnel/tests/tunnel_ping.rs::wireguard_tunnel_pings_over_veth` (embed proven); `spike/tunnel/bench.sh` (~7.5–7.8 Mbit/s in-container cap, cause unresolved); [`boringtun-assessment.md`](boringtun-assessment.md) → adopt-as-is, **conditional on the G-2 cloud run** |
| 2. tc-BPF stateful ACL on tun | **go** | `spike/enforcer/enforcer/tests/enforce.rs` — 5/5 tests (attach-on-tun, default-deny+counters, atomic A/B flip under traffic, both-sides stateful reply, ICMP embedded-error pass/deny) |
| 3. QUIC datagram relay + WG-over-relay | **go** | `spike/relay/tests/bridge.rs::bridges_datagrams_and_rejects_certless_clients`; `spike/relay/tests/wg_over_relay.rs::wireguard_handshakes_and_pings_at_mtu_1280_over_relay` |
| 4. UDP observation + brokered punch | **go** | `spike/punch/tests/observe.rs::observation_reports_nat_mapping_not_local_addr`; `spike/punch/tests/punch.rs::{port_restricted_pair_punches, symmetric_pair_fails_to_punch}` |
| 5. NAT matrix harness | **go** | `spike/natlab/tests/nat_behavior.rs::{port_restricted_nat_is_endpoint_independent, symmetric_nat_maps_per_destination}` + cells consumed by Bet 4 |

**Overall: GO for MVP planning.** Four of five bets are unconditional go; Bet 1's
*embedding* claim is proven and its *throughput* claim is the single carried gate
(a manual cloud run that cannot execute in this environment). No bet produced a
result that blocks the design.

---

## Per-bet detail

### Bet 1 — boringtun embed + throughput → go-with-caveats

**What was proven.** boringtun 0.6.0 embedded as a library via
`boringtun::device::{DeviceConfig, DeviceHandle}`, configured externally over the
standard `wg` UAPI socket, brings up a working WireGuard tunnel between two netns and
carries an overlay ping (`spike/tunnel/tests/tunnel_ping.rs`). The brief's sketched
embedding API matched boringtun 0.6.0 **verbatim** — zero field-name drift
([assessment §Task 3 notes](boringtun-assessment.md)). Maintenance health is good:
repo not archived, default-branch commit 2026-06-15, repo push 2026-06-29, 32 open
PRs, tags at 0.7.1 (2026-05-01) — judge cadence by tags/commits, not the stale-since-
2022 Releases tab.

**Measured numbers** (from [`phase0-results.md` Bet 1](phase0-results.md), Apple M2,
Docker-Desktop/linuxkit aarch64, `nproc=8`, MTU 1280 — **indicative only, not a
production or G-2 number**):
- veth baseline, no tunnel: **~131 Gbit/s** (harness itself has no artificial bottleneck).
- boringtun tunnel, TCP forward/reverse: **~7.5–7.8 Mbit/s** both directions.
- UDP `-b 500M`: sender 0% send-side loss; receiver **~7.27 Mbit/s with 98% datagram
  loss (250169/254031 lost)**. Parallel TCP `-P 4` aggregates ~8.0 Mbit/s; TCP
  retransmits 7–10/run (rules out MSS/retransmit-storm).

**Surprises / risks.** The ~7.7 Mbit/s figure is a **fixed receive-side delivery cap**
independent of protocol, parallelism, and offered rate — the signature of a
receive-pipeline bottleneck (decrypt→TUN write, or an internal queue dropping), and
**inconsistent with pure shared-vCPU scheduling noise**. But the cause has **not been
isolated**: it may be a Docker-Desktop/linuxkit-on-Apple-Silicon artifact, or a genuine
boringtun receive-path property. This is a hypothesis, not a finding. Also carried: the
UAPI control socket is **mount-namespace-scoped, not network-namespace-scoped** — bit
the two-peer test lab (fixed in `natlab` via private mount ns), harmless to the
production one-gateway-per-mount-namespace model.

**Go/no-go.** **go-with-caveats.** Embedding is unconditionally proven. The throughput
claim is **explicitly unresolved and gated on the G-2 cloud run** (spec's ≥1 Gbps on a
4-vCPU cloud VM). Assessment recommendation: **adopt boringtun as-is (crates.io), do not
fork, do not escalate to a kernel-only spec change — conditional on that run.**

**MVP implications.** Keep boringtun-primary. **First action of the cloud run: rerun
`bench.sh` unmodified with `iperf3 -u -b 0` and inspect the Lost/Total datagrams column,
not just Mbit/s.** If the ~98% receive-side loss reproduces on non-virtualized hardware,
the bottleneck is boringtun's receive pipeline (not the env) and Bet 1 is at risk →
reopen the assessment and pursue a **vendored fork** to patch the receive path *before*
considering kernel-WireGuard-only (which is a spec change that drops the LXC/no-module
use case). `bench.sh` graduates as the reusable throughput harness.

### Bet 2 — tc-BPF stateful ACL on tun → go

**What was proven.** All five enforcer behaviors, `spike/enforcer/enforcer/tests/enforce.rs`,
5/5 green (kernel `6.12.76-linuxkit`, aya 0.14 via the TCX link API):
1. Attach `aeth_ingress`/`aeth_egress` on a real WireGuard tun (L3-only parse, byte 0 is
   the IP header, no ethernet) — `default_deny_drops_overlay_ping_and_counts`.
2. Default-deny + pinned counters — same test (`deny` counter ≥ 2 after attach).
3. First-match linear scan + **atomic A/B table flip under live traffic** —
   `rule_flip_under_traffic_never_transiently_denies`: `ping -i 0.2 -c 60` overlapped with
   **50 SIGHUP reloads at 100 ms**, **0% loss and deny-counter unchanged across all 3 runs**
   (read-once-`ACTIVE` gives every in-flight packet a consistent table view).
4. Stateful reply via egress-recorded flow table, enforcers on **both** gateways —
   `reply_traffic_passes_via_flow_table_with_enforcers_on_both_sides`: A's SYN-ACK passes
   with no matching rule, resolved by the flow table alone; A-side stats
   `allow:0, deny:0, flow_hit:938` prove the right reason.
5. ICMP embedded-error pass/deny (spec §5.3 / Cilium approach) —
   `icmp_error_for_recorded_flow_passes_unrelated_icmp_error_dropped`: frag-needed
   embedding a recorded flow bumps `icmp_err_pass` by **exactly 1**; unrecorded 4-tuple
   bumps `deny`.

**Measured numbers.** 5/5 green twice consecutively (~33 s/run); flip test 0% loss ×3;
Task 8 `flow_hit:938`; Task 9 exact-1 counter assertions.

**Surprises / risks.** (a) SIGHUP's default disposition is process-kill — the Task-6
scaffold had a bare `park()` loop, so the first `kill -HUP` killed the enforcer and
silently detached enforcement (false near-0%-loss for the wrong reason); fixed by
installing the `signal-hook` handler *before* the first `apply_rules`. (b) Docker
`/sys/fs/bpf` is plain sysfs not bpffs, and bpffs mounts don't cross `ip netns exec` — the
enforcer mounts bpffs itself and keys a `/tmp` map-id file; a real gateway needs the same
guarantees. (c) aya is **0.14 not the briefed 0.13** (API matched almost verbatim anyway).

**Carried design finding (deferred to a dedicated MVP fix task): ICMP-ECHO reverse-key
asymmetry.** Egress records echo as `{sport: id, dport: 0}`; ingress reverse lookup swaps
to `{sport: 0, dport: id}`, so inside-initiated echo *replies* don't match the flow table.
ICMP *errors* work (proven — disjoint type set, independent of the echo encoding); echo
return-path keying still needs a fix.

**Go/no-go.** **go.** eBPF-first enforcement (spec §1) is validated end-to-end on a real
tun.

**MVP implications.** The enforcer program structure (`enforcer-ebpf` kernel program,
`enforcer-common` `FlowKey`/`Rule`/counter indices, userspace `apply_rules` A/B flip)
carries straight into the gateway. Fold in the bpffs-mount and map-id-resolution logic as
gateway startup guarantees. Open a dedicated task for the ICMP-echo reverse-key fix.

### Bet 3 — QUIC datagram relay + WG-over-relay → go

**What was proven.** Bet 3's three claims (`spike/relay/tests/bridge.rs`), plus the
load-bearing end-to-end (`spike/relay/tests/wg_over_relay.rs`):
1. **Bridging:** `gw-A.send_to("gw-B", …)` arrives at `gw-B` as `(src="gw-A", …)` — the
   `[8B dest_id][payload]`→`[8B src_id][payload]` rewrite is correct e2e.
2. **max_datagram_size = `Some(1414)` ≥ 1320 required** (WG MTU 1280 + WG overhead 32 +
   8-byte relay id header), ~94 bytes headroom (loopback measurement).
3. **Mandatory mutual TLS:** `connect_no_cert` returns `Err` (`peer sent no certificates`);
   the rejection is asynchronous, so the test asserts on the aggregate `Result`.
4. **WG-over-relay e2e at MTU 1280** — real boringtun traffic handshakes and flows through
   the authenticated relay across a 3-netns lab where the two gateways have **no direct
   underlay link** (relay is the only path; confirmed: A's ping to B's underlay fails, and
   the relay logs both registrations every run).

**Measured numbers** (from [`phase0-results.md` Bet 3](phase0-results.md)):
- Handshake completes over the relay in **~1.09 s** both runs.
- **MTU boundary real both directions:** `ping -s 1232 -M do` (1260 on wire) succeeds;
  `-s 1400` (1428) fails outright — both held both runs.
- iperf3 through the relay: **~6.74 Mbit/s** (run 1) / **~8.11 Mbit/s** (run 2) sender —
  same container ceiling as Bet 1 (consistent, expected).

**Surprises / risks.** (a) `latest-handshakes` reported epoch value `1`, not a wall-clock
timestamp — boringtun's UAPI in this build may not report true wall-clock time; the
brief's bar is "non-zero" which it clears, and the handshake's effect is independently
proven. (b) **udpshim peer-learning chicken/egg** (a design property, not a bug): the
downlink can only deliver to whichever local address last sent — the test primes both
sides with concurrent background pings. (c) Registration was moved from a uni-stream to an
**acked bi-stream** to close a real race where `send_to` could fire before the relay's
registry insert.

**Go/no-go.** **go.** The relay is the proven fallback for the un-punchable NAT cases Bet 4
identifies.

**MVP implications.** The relay's mutual-TLS + datagram-bridge design carries over.
`udpshim` is a spike sketch — its bridge logic (point WireGuard's peer endpoint at a local
UDP socket, relay in/out) **moves into the gateway's tunnel manager**, not shipped as a
standalone binary. Re-measure `max_datagram_size` on a real WAN path (loopback's 1414 is
not representative of the WG-1280-constrained path the spec worries about).

### Bet 4 — UDP observation + brokered punch → go

**What was proven.** (a) A UDP-native observation endpoint reports the client's post-NAT
public mapping, never the private address (`spike/punch/tests/observe.rs`). (b) The Bet 4
punch matrix (`spike/punch/tests/punch.rs`), deterministic across 3 consecutive runs:

| Cell | Verdict |
|---|---|
| PortRestricted × PortRestricted | brokered simultaneous punch **works** (3/3, identical output) |
| Symmetric × Symmetric | pair does **not** punch (3/3) — the negative that justifies the relay |

**Right-reason check** (asserted, not eyeballed): each side's `PUNCHED` address is the
*peer router's public out0 address* (`198.51.100.130` seen by A, `198.51.100.2` seen by B) —
never loopback/private. In the symmetric cell each side observes a different random
external port per destination — per-destination mapping is exactly why punching fails.

**Measured numbers.** ~160 ms puncher-spawn-to-both-PUNCHED (manual e2e); full punch.rs
suite ~6.9 s (positive cell + symmetric's 5 s timeout burn).

**Surprises / risks (two real findings).**
1. **Self-punch bug (fixed in `puncher.rs`):** a `0.0.0.0:{port}` "local guess" candidate —
   Linux rewrites `sendto()` to `0.0.0.0` into `127.0.0.1`, so every puncher PINGed itself
   over loopback and instantly self-"punched" (`PUNCHED 127.0.0.1:6100`, masking the real
   outcome, making even the symmetric cell spuriously succeed). Fixed by registering only
   the observed post-NAT candidate + skipping unspecified/loopback in the PING loop; the
   positive test now asserts the peer's real public address, so this can't regress silently.
2. **Zero-latency conntrack poisoning → Sync design constraint (the important one).** With
   zero-latency veths, simultaneous punch through Linux-masquerade NATs fails
   deterministically: the peer's first PING arrives *before* the local side's first outbound
   crosses its own NAT, creating an `[UNREPLIED]` conntrack entry that poisons the masquerade
   source port for conntrack's 30 s UDP-unreplied timeout. Modeled correctly with
   `tc netem delay 20 ms` per internet-side link (40 ms one-way): **3/3 with delay, 0%
   without** — a modeled-physics fix, not a flakiness mask. **Design implication for Sync
   (spec §6.1): broker go-skew must stay below the inter-peer one-way latency**, or a
   Linux-NAT'd peer's mapping is poisoned for ~30 s; the production broker should send "go"
   as simultaneously as possible, and/or peers should tolerate/retry the poisoning window.

**Go/no-go.** **go.** Both the positive (punch) and negative (relay-justifying) cases are
proven for the right reason.

**MVP implications.** The `observe`/`whoami`/`broker`/`puncher` logic moves into the
gateway's connectivity manager. **Record the go-skew < one-way-latency constraint in the
Sync design (spec §6.1) before MVP planning.** The netem-delay lab fidelity requirement is
mandatory for any future punch test — zero-latency labs give false negatives.

### Bet 5 — NAT matrix harness → go

**What was proven.** `natlab` gained `NatKind::{PortRestricted, Symmetric}` and
`Lab::nat_router(name, kind)` (router ns, `ip_forward=1`, nftables masquerade on `out0`).
Behavior proven by **observed external source ports**, not just rule installation
(`spike/natlab/tests/nat_behavior.rs`):

| Cell | Observed ports (dst1 / dst2) | Verdict |
|---|---|---|
| PortRestricted (`masquerade`) | 6000 / 6000 (equal) | endpoint-independent mapping |
| Symmetric (`fully-random`), 3 runs | differ every run (e.g. 29207/55524) | per-destination mapping |

**Surprises / risks.** (a) The flagged risk that kernel SNAT port-preservation would defeat
`fully-random` (making "symmetric" endpoint-independent) **did not materialize** — no
fallback needed on this kernel. (b) nft one-line ruleset with `; } }` doesn't parse — needs
real newlines before closing braces (constructor emits them). (c) CGNAT is composed as two
chained `Symmetric` routers, not a first-class `NatKind` (YAGNI).

**Go/no-go.** **go.** The harness produces genuinely distinct NAT behaviors and asserts on
translated addresses.

**MVP implications.** **`natlab` graduates to the real integration-test harness** — it
already underpins Bets 1, 2, 3, 4. The private-mount-namespace fix (from Bet 1's UAPI
finding) and the netem-delay fidelity requirement (Bet 4) are part of that graduation. Add a
first-class CGNAT cell when the MVP needs it.

---

## Open risks carried into MVP

1. **G-2 cloud-VM benchmark still pending (Bet 1) — the top carried item.** ≥1 Gbps on a
   4-vCPU non-virtualized cloud VM has **not** been measured; it cannot run in this
   Docker-Desktop/Apple-Silicon environment. **First check on that run: `iperf3 -u -b 0`
   Lost/Total datagrams** — if the ~98% receive-side loss reproduces, boringtun's receive
   pipeline is the bottleneck and Bet 1's throughput claim is at risk. Blocks final
   validation of Bet 1, not MVP planning start.
2. **boringtun receive-side throughput cap unexplained** (~7.7 Mbit/s in-container). Could be
   env artifact or boringtun receive path. Mitigation path if real: vendored fork before any
   kernel-only spec change.
3. **ICMP-ECHO reverse-key asymmetry (Bet 2)** — inside-initiated echo replies don't match
   the flow table; needs a dedicated MVP fix task. (ICMP errors already work.)
4. **Sync go-skew constraint (Bet 4)** — go-skew must be < inter-peer one-way latency or a
   Linux-NAT'd peer's mapping is poisoned ~30 s. Must be designed into the broker/Sync.
5. **aya API churn** — pinned 0.14 (briefed 0.13); ≥6.6 kernels use the TCX link API (legacy
   `tc filter show` shows nothing — observe via `bpftool link show`). Track aya releases.
6. **max_datagram_size headroom re-measure (Bet 3)** — 1414 measured on loopback; re-measure
   on a real WG-1280-constrained WAN path before relying on the 94-byte margin.
7. **Docker/container BPF quirks (Bet 2)** — bpffs not mounted, mounts don't cross netns;
   the gateway must self-mount bpffs and resolve maps deterministically (the enforcer's
   `/tmp` map-id file is a spike workaround; production wants a cleaner scheme).

## Spec deltas discovered

Each becomes a spec edit before MVP planning:

1. **§6.1 Sync — add the go-skew < one-way-latency constraint** (Bet 4 finding 2). Currently
   unstated; the broker must send "go" as near-simultaneously as possible and/or peers must
   tolerate the ~30 s mapping-poisoning window. **This is a new hard requirement.**
2. **§5.3 ICMP handling — note the echo reverse-key asymmetry** as a known gap with a tracked
   fix task; the embedded-error path (already specced) is validated as-is.
3. **Data-plane note — record the UAPI-socket mount-namespace scoping** (Bet 1). Harmless to
   one-gateway-per-mount-namespace, but a design landmine if the gateway ever runs multiple
   same-named interfaces in one mount namespace — worth an explicit design note.
4. **§1 / enforcement — aya 0.14 + TCX link API** on ≥6.6 kernels (not the design's assumed
   version); a gateway must mount bpffs itself in container/Docker environments. Update any
   version/observability assumptions.
5. **No decision-record reversal.** Nothing in the spike proved a §1 decision wrong —
   eBPF-first enforcement, boringtun-primary, and the QUIC relay all validated. Bet 1's
   throughput is *unresolved*, not *disproven*; the boringtun-primary decision stands pending
   the G-2 run.

## What the MVP plan should reuse vs. rewrite

**Reuse (graduate largely intact):**
- **`natlab`** → the real integration-test harness. Already underpins all 5 bets; keep the
  private-mount-namespace fix and the netem-delay fidelity requirement.
- **`enforcer` program structure** → the gateway's data-plane enforcement: `enforcer-ebpf`
  kernel program, `enforcer-common` (`FlowKey`/`Rule`/counter indices), userspace A/B flip +
  SIGHUP reload, bpffs self-mount + map-id resolution.
- **`relay`** (mutual-TLS QUIC datagram bridge) → the gateway's relay path, largely as-is.
- **`punch`** `observe`/`whoami`/`broker`/`puncher` logic → the gateway's connectivity
  manager (with the self-punch fix and the go-skew constraint baked in).
- **`bench.sh`** → the reusable throughput harness for the pending G-2 cloud run.

**Rewrite / fold in (spike scaffolding, not shippable):**
- **`spike-tunnel`** is superseded by the real gateway binary — it was a throwaway UAPI-config
  driver around boringtun's `device` feature; the gateway embeds boringtun directly.
- **`udpshim`** logic **moves into the gateway's tunnel manager** — not a standalone binary
  (the brief itself flagged it as a sketch to clean during implementation).
- **`pktgen`** (crafted-ICMP injector) is a test-only tool — keep it in the test harness, not
  the gateway.
- The **`/tmp` map-id-file** map-resolution workaround wants a cleaner production scheme.

---

## Final verification

Step 2 of Task 15 — all five crates' behavior suites re-run one last time, for real, inside
the privileged Linux dev container. Tunnel release built first;
`SPIKE_TUNNEL_BIN=/work/spike/tunnel/target/release/spike-tunnel` exported for the
env-dependent suites; natlab examples (`udpsink`/`udpsend`) built before its behavior tests;
all suites serial (`cargo test -- --test-threads=1`). The enforcer is an aya workspace whose
`default-members` includes `enforcer`, so `cargo test` there runs the `enforce.rs`
integration suite (confirmed 5 tests ran).

Command:
```
./dev.sh run "cd /work/spike/tunnel && cargo build --release && \
  export SPIKE_TUNNEL_BIN=/work/spike/tunnel/target/release/spike-tunnel && \
  cd /work/spike/natlab && cargo build --examples && \
  for c in natlab tunnel enforcer punch relay; do \
    echo \"=== \$c ===\"; (cd /work/spike/\$c && cargo test -- --test-threads=1) || \
    { echo \"FAIL in \$c\"; exit 1; }; done; echo ALL_DONE"
```

Actual result — **all green, `ALL_DONE`, exit 0** (behavior/integration tests per crate;
crates also compile 0-test unit binaries which are omitted):

| Crate | Suite(s) | Result |
|---|---|---|
| natlab | `nat_behavior.rs` (2), `veth_ping.rs` (1) | **3 passed, 0 failed** |
| tunnel | `tunnel_ping.rs` (1) | **1 passed, 0 failed** |
| enforcer | `enforce.rs` (5) | **5 passed, 0 failed** (33.4 s) |
| punch | `observe.rs` (1), `punch.rs` (2) | **3 passed, 0 failed** |
| relay | `bridge.rs` (1), `wg_over_relay.rs` (1) | **2 passed, 0 failed** |

**Total: 14 behavior tests, 14 passed, 0 failed, 0 skipped, 0 flaky.** No suite failed or
was skipped. The CLAUDE.md "no done with failing/unrun tests" rule is satisfied.

> Note: the ~7.7 Mbit/s boringtun throughput cap (Bet 1) is **not** a test failure — the
> behavior tests assert connectivity/correctness, not a throughput floor. That number is the
> carried G-2 risk above, not a red suite.
