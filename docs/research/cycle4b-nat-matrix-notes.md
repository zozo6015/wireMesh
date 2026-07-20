# Cycle 4b — NAT-matrix conformance findings

Context: Task 11 (`crates/wiremesh-gateway/tests/nat_matrix.rs`), the cycle done-bar.
Two REAL `wiremesh-gateway` processes behind separate NATs, in-process controller
on the "internet" bridge, mandatory `tc netem delay 20ms` on each router `out0`.

## Finding 1 — a punched pair with ZERO data demand does not converge to Direct on keepalive alone

**Symptom (first run, before the fix).** The port-restricted pair (case 1/3/4)
never reached `path_state=direct`; both gateways flapped
`connecting -> disconnected -> connecting` on the path SM's 10s connect-timeout,
with `wg show latest-handshakes == 0` forever.

**Not a punch failure.** The evidence rules out the NAT/punch layer:

- gateway logs showed `punch confirmed peer=N endpoint=198.51.100.x:51820`;
- `wg show wg0` listed the correct peer, the correct NAT-mapped endpoint, and
  `persistent keepalive: every 15 seconds`;
- `conntrack -L` on BOTH routers showed an **`[ASSURED]` bidirectional UDP flow**
  `198.51.100.2 <-> 198.51.100.3` on sport/dport 51820 — i.e. the simultaneous
  punch opened both port-restricted mappings and packets were crossing both NATs.

So the mapping is open and mutually consistent; what never happens is the WG
**handshake initiation**.

**Root cause.** boringtun (like kernel WireGuard) initiates a handshake only on
(a) an outbound packet with no valid session, or (b) the persistent-keepalive
timer firing with no valid session — never on `set peer endpoint` alone. The 4b
path SM re-punches every time `Connecting` times out (10s), and each
`punch_and_apply` re-runs `uapi::apply` (`replace_peers`), which **resets the
peer's keepalive timer**. Because the re-punch cadence (~12s = 10s connect-timeout
+ backoff) is shorter than the 15s keepalive interval, the keepalive timer is
reset before it can ever fire. With no application traffic to supply outbound
demand either, boringtun sits idle and no handshake is ever sent — even though
the path is fully punched.

**Why the de-risk spike and 4a didn't hit this.**

- `spike/natpunch` configures boringtun's peer **once** (no path SM, no periodic
  re-apply), so its keepalive timer is free to fire and drive the first handshake.
- The 4a `mesh_milestone` asserts by **driving a workload TCP flow** in its
  `wait_until` loop; each SYN entering `wg0` is outbound demand that triggers the
  handshake immediately, well before any keepalive question arises.

**Resolution for the conformance test.** The done-bar for case 1 already requires
"pass workload traffic over the direct tunnel." Representative workload demand is
present in every real deployment, so the test drives the policy-permitted
tcp/8080 seg-a→seg-b flow *as* the convergence driver: the connect attempts
create the outbound tunnel demand that initiates the handshake over the punched
mapping, and the test then asserts `path_state=direct` + a real `wg show`
handshake + conntrack evidence on both NATs. This is not a weakened assertion —
every done-bar signal (direct path metric, real handshake, workload crossing,
NAT-crossing conntrack) is still checked; the change is only that the tunnel is
exercised the way a real one is (with traffic), matching 4a and the spike.

**Carry for a later cycle (owner decision needed).** Whether a gateway pair with
*no* application traffic should still converge to Direct purely on keepalive is a
design question about the re-punch cadence vs the keepalive interval. Options if
"idle convergence" is wanted: (i) don't `replace_peers`-reset a peer that is
already configured with the same endpoint (make `apply` idempotent so it doesn't
reset the keepalive timer); (ii) lengthen the connect-timeout / re-punch cadence
past the keepalive interval; or (iii) have the driver send a WG keepalive
directly after a confirmed punch. Not required for the 4b done-bar (which is
about punched connectivity + relay-needed verdict, both proven), so deferred.

## Finding 3 — case 3 (determinism) timing margin, and a real case-4 driver bug: `last_handshake_time` can advance with NO corresponding received byte

**Task 11 follow-up (this fix).** Two failures surfaced in `case3_direct_determinism`
and `case4_direct_then_degraded`; only the second was a real product bug.

**Case 3 — scrape-timing margin, not a bug.** `establish_direct`'s second phase
(waiting for both gateways' scraped `path_state=direct` *and* a real
`latest-handshakes > 0`) used a 10s bound. On a repeat run under container CPU
contention, the workload TCP flow crossed (proving the tunnel was actually up)
but the test's own separate `wg show wg0 latest-handshakes` round-trip
occasionally still read `0` for a few more seconds after `path_state` had
already flipped to `direct` — a benign settle-timing race between two
independent polls of the same underlying gateway process, not a convergence
failure. Widened the bound to 20s (still well inside the done-bar's ≤30s
convergence budget); no assertion was weakened, only given more real time to
observe the already-true condition. Confirmed deterministic across repeated
runs after the widen.

**Case 4 — a real driver bug, found via raw UAPI instrumentation.** Blocking
inbound WG (`nft ... udp dport 51820 drop` on gwA) never produced `Degraded`
within a very generous 65s bound (well past `DEGRADED_AFTER` = 45s). Diagnosis:
- `rx_bytes` on gwA was **provably frozen** (140 B, unchanged across dozens of
  samples) — the block genuinely works, no packet is reaching boringtun.
- Yet `wg show wg0 latest-handshakes` on gwA climbed by ~1 every real second,
  in lockstep with wall-clock time — confirmed down to the raw UAPI `get=1`
  response (`last_handshake_time_sec`/`_nsec`) queried directly against
  boringtun's control socket, bypassing the `wg` CLI entirely, so this is
  boringtun's own reported state, not a test-harness artifact.
- This environment's boringtun build evidently advances
  `last_handshake_time` on every driver tick for a peer that is repeatedly
  retrying an **unanswered** handshake (no reply ever arrives) — i.e. the
  timestamp is not gated on a completed, authenticated round-trip the way the
  UAPI's documented semantics imply.
- The gateway's path-tick driver (`run_path_ticks` in
  `crates/wiremesh-gateway/src/main.rs`) trusted every handshake-time advance
  unconditionally, calling `Path::on_handshake` (which refreshes
  `last_inbound`) on every tick — so `last_inbound` never went stale and
  `DEGRADED_AFTER` was unreachable for a peer that is, by every other measure
  (`rx_bytes`), completely dead.

**Fix (`main.rs`, `run_path_ticks`).** A handshake-time advance is now trusted
unconditionally only when it would drive a *real* recovery transition (peer
not already `Direct` — i.e. `Connecting`/`Degraded`/`Relayed` → `Direct`, which
is exactly a genuine completed handshake in every case the SM cares about).
Once **already** `Direct`, a handshake-time advance is only trusted when
corroborated by a same-tick `rx_bytes` increase; otherwise the driver falls
back to `rx_bytes`-only liveness (`on_authenticated_inbound`), same as before.
This preserves every existing behavior (idle-free convergence, keepalive-only
liveness keeping a healthy path `Direct`, real handshake recovery from
`Degraded`) while making the dead-path detection immune to a spurious
handshake-time advance with nothing behind it. Verified: gwA now reaches
`Degraded` (see `case4` log, `t≈44s`, matching `DEGRADED_AFTER=45s` within the
1s tick granularity), and the mesh-milestone (4a) and gateway unit-test suites
still pass unchanged.

## Finding 2 — symmetric pair reaches relay-needed cleanly (as designed)

The symmetric (`masquerade fully-random`) pair never confirms a punch (the
controller-observed candidate port ≠ the per-destination port the NAT assigns
toward the peer), so `punch_candidates` returns `None`, no handshake forms, and
the path SM parks in `Disconnected` (`relay-needed`, inert in 4b) after the 10s
connect-timeout, then oscillates `connecting<->disconnected` on backoff without
wedging. The test terminates deterministically on the first `disconnected`
sighting and additionally asserts no direct handshake ever completed. This is the
documented 4c relay hand-off point.
