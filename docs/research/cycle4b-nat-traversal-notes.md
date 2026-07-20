# Cycle 4b — NAT traversal: notes & fast-follow carries

Cycle 4b made two gateways behind NATs form a **direct** WireGuard tunnel via
controller-brokered simultaneous hole punching, and made a gateway that
*cannot* punch (symmetric/CGNAT) reach a correct **relay-needed** verdict — the
relay transport itself stays **4c** (spec §1). This file records the design
decisions, the de-risk result, the proto changes, and the fast-follow carries
surfaced by per-task and whole-branch review, so 4c inherits them explicitly.

## What 4b delivered

- **Controller-brokered simultaneous hole punching.** A new `PunchDirective`
  `SyncMessage` variant (see below) that the controller's broker sends to
  **both** members of a NAT'd pair back-to-back in one critical section, with
  a `go_unix_ms` common fire instant — go-skew held below the modeled one-way
  latency (Phase-0 Finding 2: skew above that window poisons a Linux NAT
  mapping for ~30s).
- **The transient same-socket `SO_REUSEPORT` puncher** (`crates/wiremesh-
  gateway`) — opens a second `SO_REUSEPORT` socket on the WG listen port,
  blasts punch packets at every peer candidate, closes the socket once the
  mapping is open (or the window ends), then points boringtun's UAPI
  `endpoint=` at the confirmed candidate. Only one socket is ever bound to the
  WG port once punching finishes, so the peer's real WireGuard handshake is
  delivered to boringtun, not raced against the punch socket.
- **Multi-candidate model.** `gateway_candidate(gateway_id, endpoint, source,
  observed_at)` replaces the old single-column last-observed-wins column;
  `source ∈ {observed, local}` — the controller keeps the observed public
  mapping *and* the gateway's self-reported routable local addresses, and
  emits the full set into the already-`repeated` `Peer.candidate_endpoints`.
- **The `Connecting / Direct / Degraded / Relayed / Disconnected` path state
  machine** (`path.rs`), driven off the WG UAPI `get=1` read side (the read
  half of the writer 4a built): handshake completion drives `Connecting →
  Direct`; keepalive/rx-byte liveness holds `Direct`; 45s silence drops to
  `Degraded`; no handshake + no relay parks in `Disconnected`
  (`relay-needed`). `Relayed` and its make-before-break transitions are
  **wired but inert** — a placeholder verdict, not a working path (4c fills
  it).
- **NAT-matrix netns conformance** (`crates/wiremesh-gateway/tests/
  nat_matrix.rs`), two real `wiremesh-gateway` processes behind separate NATs
  with **mandatory `tc netem delay 20ms`** on every internet-side link — all
  4 done-bar cases pass: (1) port-restricted pair → real WG handshake over
  the brokered punch, workload traffic crosses, `path_state=direct`; (2)
  symmetric pair → punch fails for the right reason, clean `relay-needed`
  verdict, no hang; (3) go-skew determinism across repeat runs; (4)
  Direct→Degraded after 45s silence with inbound blocked.

## The de-risk

`spike/natpunch` (Task 1, run first, before any broker/proto/state-machine
work) proved the transient-socket approach actually works: a real WireGuard
handshake completes through a `netem`'d port-restricted NAT when the punch
and the WG traffic share the same source `ip:port` via `SO_REUSEPORT` — 4/4
de-risk runs. This is the load-bearing result the rest of 4b is built on
(spec §3); the fallback if it had failed was "direct-punch deferred, all
NAT'd peers relay-only in 4c."

## Proto changes

- `SyncMessage.body` gained a `PunchDirective punch = 3` oneof variant
  alongside `StateSnapshot`/`Delta`: `peer_gateway_id`, `candidates`
  (repeated), `go_unix_ms`. Routing does **not** go through the existing
  `subject_gateway_id()` self-skip path (every prior Sync message is
  declarative desired-state that self-excludes the subject); the broker
  explicitly targets both pair members' `Watch` streams.
- `ReportRequest` gained `repeated string local_endpoints` — additive field,
  the gateway's own enumerated routable local `ip:wg_port` addresses.
  **Semantic ratified in Task 8:** an empty `local_endpoints` list means
  "genuinely no local candidates" and **REPLACEs/clears** any stored local
  rows for that gateway (Task 4 shipped an empty-short-circuits-to-no-op
  behavior; Task 8 removed it) — a gateway must send its *complete* current
  local set on every report; omit the field entirely (don't send `[]`) if
  local-address enumeration itself failed, so a transient enumeration error
  can't wipe good candidates.

## Design decisions

- **Transient `SO_REUSEPORT` punch socket, not a boringtun fork** (spec §3,
  confirmed owner decision A). boringtun 0.6 owns its UDP socket internally
  with no raw inject/observe API and no pre-bound-fd `DeviceConfig`; a NAT
  maps on the `(src ip:port[, dst])` tuple, not the socket object, so a
  second same-port socket presents an identical mapping to the NAT without
  needing boringtun's cooperation.
- **`PunchDirective` as a new `SyncMessage` oneof + controller broker +
  `go_unix_ms`**, not an overloaded `Delta` (owner decision B) — the broker
  emits both directives back-to-back (µs-scale skew, the primary guarantee)
  with `go_unix_ms` as a corroborating near-future common instant (best-
  effort clock sync, secondary).
- **Multi-candidate DB model**: the observed-public slot is kept exactly as
  before; `gateway_candidate` rows with `source=local` are additive. The
  puncher iterates the full candidate list and blasts all of them; WG
  `endpoint=` is set to whichever candidate the punch/handshake confirms.
- **The 4b/4c boundary is deliberate and load-bearing**: 4b proves punch +
  path SM + a correct `relay-needed` verdict; the relay QUIC-datapath
  transport, the `wiremesh-relay` binary, relay advertisement over Sync, and
  the `Relayed` state's make-before-break are all **4c** (owner decision C).
  4b's symmetric-NAT done-bar is "correctly determines relay is needed," not
  "traverses via relay."

## Notable findings / fixes

- **The path-liveness bug (Task 10 + Task 11 case 4), see
  `docs/research/cycle4b-path-liveness-note.md` and the Finding-3 section of
  `docs/research/cycle4b-nat-matrix-notes.md` for full detail.** Two layered
  issues, both in `run_path_ticks` (`crates/wiremesh-gateway/src/main.rs`):
  (a) WireGuard only advances `last_handshake_time` on its own ~120s rekey
  cadence, not per-packet, so driving liveness off handshake-time alone made
  a perfectly healthy Direct path (living on 15s keepalives between rekeys)
  spuriously degrade — fixed by also treating a `rx_bytes` increase (from
  UAPI `get_peer_liveness`) as authenticated-inbound liveness; (b) this
  environment's boringtun build was then found to advance
  `last_handshake_time` on *every driver tick* for a peer endlessly retrying
  an unanswered handshake, even with `rx_bytes` provably frozen — so trusting
  every handshake-time advance unconditionally made the dead-path case
  (inbound WG blocked) never reach `Degraded` either. Final rule: a
  handshake-time advance is trusted unconditionally for a genuine *recovery*
  transition (not-yet-`Direct` → `Direct`); once already `Direct`, staying
  `Direct` requires `rx_bytes` corroboration on the same tick. Verified via
  raw UAPI `get=1` instrumentation bypassing the `wg` CLI, and confirmed
  against a case where the NAT mapping was open, `wg show` listed the correct
  peer/keepalive, and `conntrack -L` showed an `[ASSURED]` bidirectional
  flow on both routers — yet no handshake ever fired, because the re-punch
  cadence was resetting boringtun's keepalive timer faster than it could
  fire (see nat-matrix Finding 1; resolved for the conformance test by
  driving convergence with real workload traffic, matching how 4a's mesh
  milestone and the de-risk spike both already work).
- **The PONG-source guard** (`punch.rs`) — the punch responder now requires
  the PONG's source to be one of the candidates actually targeted
  (`targets.contains(&from)`) before accepting it, closing an off-path
  PONG-spoof window that existed before WG's own handshake authentication
  would have caught a forged endpoint.
- **`tc netem delay 20ms` is mandatory**, not optional, on every internet-
  side link in the NAT-matrix harness — a zero-latency lab gives false
  punch-failure (Phase-0 Finding 2); `nat_router`/the punch-lab builder grew
  a netem knob for this. `apply_netem` is a general, non-idempotent primitive
  (adds a qdisc, doesn't replace) — call it once per interface.

## Fast-follow carries (from the ledger; none merge-blocking)

1. **Broker lag-termination coverage (Minor 1, Task 5 whole-branch review).**
   After `delta_stream.merge(punch_stream)`, the `Watch` RPC currently ends
   only because tonic aborts on `Err`, not via stream self-end — correct
   today but untested. Add a comment at the merge point plus a lag test that
   asserts the stream terminates and the registry entry is removed.
2. **`DEGRADED_DEAD_AFTER` = 10s is an invented number** (Task 9), reused
   from `CONNECT_TIMEOUT` with no spec-mandated value; set deliberately
   against the master spec's ≤30s convergence budget (G-3) but worth
   revisiting with real-world data.
3. **`candidates_for` locals query not gated on `status='active'`** (Task 3)
   — latent, all current callers pre-filter; a one-line filter for a
   hardening pass.
4. **Dead pub API**: `get_latest_handshakes` / `handshake_times_from` /
   `candidate_endpoint_for_gateway` are now unused now that the driver uses
   `get_peer_liveness` (which folds both handshake-time and rx_bytes into a
   single UAPI round-trip) — harmless, but candidates for removal or an
   explicit "kept for epoch-ambiguity documentation" note.
5. **`periodic_attempts` not GC'd on disconnect** (Task 5) — self-heals,
   bounded by O(pairs), not a correctness issue.
6. **Idle-pair convergence question (nat-matrix Finding 1, owner decision
   needed)**: a punched pair with *zero* application traffic demand does not
   currently converge to Direct on keepalive alone, because the re-punch
   cadence (~12s) resets boringtun's keepalive timer faster than the 15s
   interval can fire a handshake. Not required for the 4b done-bar (every
   real deployment has traffic demand, and the conformance test exercises
   the tunnel the same way 4a and the de-risk spike do), but worth a design
   decision before assuming idle links self-heal: options are (i) make
   `apply` idempotent so it doesn't reset keepalive on an unchanged peer,
   (ii) lengthen the re-punch cadence past the keepalive interval, or (iii)
   send a keepalive directly after a confirmed punch.
7. **Relay advertisement stays empty in 4b** — `DesiredState.relays`
   replace-if-nonempty semantics (flagged as inert in the 4a notes) remain
   untouched; 4c is the first cycle to populate it.

## Next

Cycle 4c: the `wiremesh-relay` binary, gateway relay transport (QUIC
datagrams), relay advertisement over Sync, and `Relayed`-state make-before-
break — filling in the path state machine's wired-but-inert `Relayed` seam
this cycle left. Also still pending: the key-rotation fast-follow (carried
from 4a).
