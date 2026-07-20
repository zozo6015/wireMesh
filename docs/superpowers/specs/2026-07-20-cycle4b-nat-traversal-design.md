# WireMesh — Cycle 4b Design: NAT Traversal

> **Cycle 4 of 4**, sub-cycle **4b** (per the 4a decomposition, spec
> `2026-07-20-cycle4a-direct-gateway-design.md` §1). Authority: master spec
> `docs/superpowers/specs/2026-07-15-wiremesh-engineering-design.md` §6.1 (NAT
> traversal, MTU & relay failover) governs. Cycle 4a (direct-only gateway) is
> merged (PR #10). Relay transport is **4c**, not 4b.

## 1. Scope & the 4b/4c boundary

4b makes two gateways behind NATs form a **direct** WireGuard tunnel via
controller-brokered simultaneous hole punching, and makes a gateway that
*cannot* punch (symmetric/CGNAT) reach a correct **"relay-needed"** verdict — but
**4b does not build the relay transport**. The relay QUIC-datagram data path,
`wiremesh-relay` binary, and relay advertisement are **4c**.

**In scope (4b):**
1. **Same-socket punch** — send hole-punch packets from the gateway's WireGuard
   UDP source `ip:port` so the NAT mapping the punch opens is the one boringtun's
   handshake reuses (§3). Replaces 4a's routable-only `SO_REUSEPORT` observation
   sidecar with the punch mechanism, and keeps observation same-socket.
2. **Controller broker** — a new Sync directive that signals **both** gateways of
   a pair to punch at each other's candidates with bounded go-skew (§4).
3. **Multi-candidate model** — the controller stores a candidate *set* (observed
   public mapping + gateway-reported local addresses); the gateway reports its
   local addresses upward and iterates all candidates when punching (§5).
4. **Path state machine** — `Connecting → Direct / Degraded / Disconnected`, with
   the `Relayed` state and its transitions **wired but degenerate** until 4c
   supplies the relay transport (§6). Timers: keepalive 15s, Degraded at 45s,
   ≤30s convergence budget.
5. **NAT-matrix conformance** — netns punch tests with **mandatory `tc netem`
   latency** (§7), proving direct-punch success on port-restricted NAT and
   correct punch-failure→relay-needed on symmetric NAT.

**Deferred to 4c:** the relay data path (QUIC datagrams, `wiremesh-relay`, relay
advertisement over Sync, `Relayed`-state make-before-break). 4b's `Relayed`
target is a placeholder verdict, not a working transport.

## 2. Done bar

A netns NAT-matrix conformance suite (`wiremesh-testkit`, `--features netns`),
**with `tc netem delay 20ms` on every internet-side link** (mandatory — zero-
latency labs give false punch-failure, Phase-0 report Finding 2):

1. **Port-restricted NAT pair** — the controller brokers a simultaneous punch and
   the two gateways complete a **real WireGuard handshake and pass traffic over
   the direct tunnel** (`Connecting → Direct`), within the ≤30s convergence
   budget.
2. **Symmetric NAT pair** — the punch **fails for the right reason** (the observed
   mapping is per-destination, so the registered candidate is the wrong port);
   the gateway does not wedge, reaches a **`relay-needed`** verdict, and the path
   state machine leaves `Connecting` toward `Relayed`/`Disconnected` (no relay in
   4b, so it parks in a well-defined state, not a hang).
3. **Go-skew constraint honored** — the broker emits both "go" directives with
   skew below the modeled one-way latency; the test passes deterministically
   across runs (no conntrack-poisoning flakiness).
4. **Path state machine** — unit + netns coverage of the transitions and timers
   (Direct→Degraded after 45s silence, keepalive 15s, retry/backoff on
   Disconnected).

The G-2 throughput number stays deferred (4a). Relay-path (`Relayed`) traversal
is a **4c** done-bar item, explicitly not 4b's.

## 3. Same-socket punch — the central design decision (de-risk FIRST)

**Problem.** boringtun 0.6 binds and owns its WireGuard UDP socket internally and
exposes no raw-UDP inject/observe API, and its `DeviceConfig` cannot accept a
pre-bound fd. So the gateway cannot literally send from boringtun's socket. Yet
the punch must originate from the **same source `ip:port`** boringtun uses, or —
on any NAT — the mapping the punch opens differs from the one WireGuard needs.

**Key realization.** A NAT maps on `(src ip:port[, dst])`, **not on the socket
object**. A second socket bound to the WG listen port via `SO_REUSEPORT` presents
the *same* source `ip:port` to the NAT. So a punch it sends to a peer candidate
opens exactly the mapping boringtun's handshake to that same candidate will
reuse — on both endpoint-independent (port-restricted) *and* symmetric NATs (same
4-tuple → same mapping). The only hazard is **inbound delivery**: with two
`SO_REUSEPORT` sockets bound, the kernel load-balances inbound datagrams between
them, so boringtun could miss the peer's handshake.

**Decision — the transient punch socket.** For each punch attempt the gateway:
1. Opens a `SO_REUSEPORT` UDP socket on the WG listen port (as 4a's
   `reuseport_udp` already does).
2. On the broker's "go", blasts punch packets from it at every peer candidate for
   a bounded window (opening the NAT mapping/filter), tolerating/retrying across
   the ~30s conntrack-poisoning window (Phase-0 Finding 2).
3. **Closes the punch socket** as soon as the mapping is open (or the window
   ends), leaving only boringtun bound to the WG port — so the peer's WireGuard
   handshake, arriving at the now-open mapping keyed on `(ip:wg_port, peer)`, is
   delivered to boringtun's socket.
4. The gateway sets the peer's WG `endpoint=` (via UAPI) to the candidate the
   punch confirmed, so boringtun immediately drives its handshake over the open
   mapping.

**Observation** likewise uses a same-source-port socket (the transient
`SO_REUSEPORT` socket), correct for the observation→controller flow on endpoint-
independent NATs; on symmetric NATs the observed port is knowingly wrong for the
peer (that pair is a relay case, by design).

**This is the linchpin risk and is de-risked FIRST (plan Task 1):** a netns test
must prove a *real WireGuard handshake completes over a brokered punch through a
`netem`'d port-restricted NAT* using this transient-socket approach, before any
of the broker/state-machine/proto work is built on it. If it fails, that is a
genuine blocker to surface (fallback: direct-punch deferred, all NAT'd peers
relay-only in 4c) — do not build 4b on an unproven punch.

## 4. Controller broker — new Sync directive

**Gap (from context §5):** every existing Sync message is *declarative desired
state*; there is no imperative "punch now" signal, and the delta fan-out
self-*excludes* the subject gateway — the opposite of a pair directive that must
reach **both** members.

**Decision — a new `SyncMessage` body variant `PunchDirective`.** Proto:
```proto
message SyncMessage { oneof body {
  StateSnapshot snapshot = 1; Delta delta = 2; PunchDirective punch = 3;
} }
message PunchDirective {
  uint64 peer_gateway_id = 1;      // the peer to punch toward
  repeated string candidates = 2;  // that peer's candidate set (public + local)
  uint64 go_unix_ms = 3;           // synchronized fire time (see go-skew below)
}
```
The controller runs a **broker**: when both gateways of a pair are connected on
`Watch` and each has a candidate set, it emits a `PunchDirective` to **each**
gateway (carrying the *other's* candidates) — the two sends issued **back-to-back
in one tight critical section**, mirroring the spike `broker.rs`'s two
`write_all`s.

**Go-skew constraint (hard requirement, Phase-0 Finding 2):** broker go-skew must
stay below the inter-peer one-way latency or a Linux-NAT'd peer's mapping is
poisoned ~30s. Two levers, both used: (a) the broker emits both directives
back-to-back with no intervening await (µs-scale skew); (b) `go_unix_ms` gives a
near-future common fire instant so both punchers start on the same wall-clock
tick regardless of delivery jitter, and the puncher tolerates/retries across the
poisoning window. (Clock-sync is best-effort; the back-to-back send is the
primary guarantee, `go_unix_ms` the corroborating one.)

Routing: `PunchDirective` must reach both pair members, so it does **not** use the
`subject_gateway_id()` self-skip path (context §5); the broker targets each
member's `Watch` stream explicitly. Trigger: when a pair first has mutual
candidates, on a re-observation that changes a candidate, and on a periodic
retry while the pair is `Connecting`/`Degraded` and not yet `Direct`.

## 5. Multi-candidate model + local-address reporting

**Today:** the controller stores a single `gateway.candidate_endpoint` (last-
observed-wins), and the gateway consumes only `candidate_endpoints.first()`.
§6.1 requires candidates = *observed public mapping + local addresses* (plural).

**Decisions:**
- **DB candidate set.** Add a `gateway_candidate(gateway_id, endpoint, source,
  observed_at)` table (`source ∈ {observed, local}`), replacing the single-column
  last-observed model with a bounded set (observed public mapping kept as before;
  local addresses supplied by the gateway). `build_snapshot`/deltas emit the full
  set into the already-`repeated` `Peer.candidate_endpoints`.
- **Gateway reports local addresses.** Extend `ReportRequest` (today only
  `applied_version`) with `repeated string local_endpoints` — the gateway's own
  routable local `ip:wg_port` addresses (enumerated from its interfaces), so the
  controller can offer them as `local`-source candidates for LAN/hairpin/local
  reachability. Additive proto field.
- **Gateway iterates candidates.** `PeerState` keeps the full candidate list;
  the puncher blasts all candidates (as spike `puncher.rs` does), and the WG
  `endpoint=` is set to whichever candidate the punch/handshake confirms
  (preferring the one that produced authenticated inbound).

## 6. Path state machine (master §6.1)

New per-peer state machine in the gateway (`path.rs`), states
`Connecting / Direct / Degraded / Relayed / Disconnected`:
- `Connecting → Direct`: WG handshake completes over the brokered punch (boringtun
  reports a recent handshake for the peer, read via UAPI `get`).
- `Connecting → Relayed`: no handshake within 10s **and relay available** — in 4b
  relay is never available, so this is a **wired-but-inert** edge; the gateway
  records `relay-needed` and parks.
- `Connecting → Disconnected`: no handshake and no healthy relay → retry with
  backoff.
- `Direct → Degraded`: no authenticated inbound for 45s (keepalive 15s).
- `Degraded → Direct`: handshake recovers; `Degraded → Disconnected`: dies.
- `Relayed → Direct` (make-before-break) and `Relayed → Relayed` (re-path):
  **4c** — stubbed in 4b.
- `Disconnected → Connecting`: backoff retry, alarm metric.

The gateway reads boringtun's per-peer latest-handshake timestamp via the UAPI
`get=1` protocol (the read side of the writer 4a built) to drive
Direct/Degraded/handshake-recovers transitions. Metrics: per-peer path state +
transition counters exposed on the existing Prometheus endpoint.

## 7. Test harness — netem fidelity (mandatory)

The natlab/`netns.rs` NAT cells (`NatKind::{PortRestricted, Symmetric}`,
`nat_router`) exist but use **zero-latency veths**, which per Phase-0 Finding 2
give *false* punch-failure. 4b **must** add `tc netem delay 20ms` (≈40ms
one-way) on each internet-side link before any punch test — this is a mandatory
lab-fidelity requirement, not optional. Add a `netem`/latency knob to
`nat_router` (or the punch-lab builder) and document why. CGNAT stays composed as
two chained `Symmetric` routers (not a new `NatKind`) unless a test needs it.

## 8. Testing

- **Unit:** `PunchDirective` proto round-trip; path state-machine transitions +
  timers (injectable clock); candidate-set model; local-address enumeration.
- **Controller:** broker emits paired `PunchDirective`s back-to-back to both
  members with bounded skew; multi-candidate snapshot/delta; `ReportRequest.
  local_endpoints` stored as `local`-source candidates.
- **netns conformance (`--features netns`, netem):** (a) port-restricted →
  real WG handshake over direct punch (`Connecting→Direct`, ≤30s); (b) symmetric
  → punch fails, `relay-needed` verdict, no hang; (c) go-skew determinism (repeat
  runs); (d) Direct→Degraded after 45s silence.
- Per CLAUDE.md: tests authored / implemented / executed by three different
  agents; independent reviewer; all in the privileged container via `./dev.sh`.

## 9. Non-goals (4b)

The relay data path / `wiremesh-relay` / relay advertisement / `Relayed`
make-before-break (all 4c); key rotation (separate fast-follow); a boringtun fork
to expose its socket (rejected — the transient-socket approach avoids it); STUN
(master: no STUN in v1); IPv6; the measured G-2 number; a first-class CGNAT
`NatKind`; per-peer MTU raising (P1).

## 10. Scope-boundary decisions to confirm (owner)

Made autonomously; flag if any is wrong before the large build lands:
- **A. Transient `SO_REUSEPORT` punch socket** (§3) rather than a boringtun fork —
  de-risked first; fallback is direct-punch deferred, NAT'd peers relay-only.
- **B. `PunchDirective` as a new `SyncMessage` oneof variant** (§4) with a
  controller-side broker + `go_unix_ms`, rather than overloading a `Delta`.
- **C. 4b proves punch + path SM + `relay-needed` verdict; the relay transport
  and the `Relayed` working path are 4c** (§1) — so 4b's symmetric-NAT done-bar is
  "correctly determines relay is needed," not "traverses via relay."
