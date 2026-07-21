# WireMesh — Cycle 4c Design: Relay Path

> **Cycle 4 of 4**, sub-cycle **4c** (final). Authority: master spec
> `docs/superpowers/specs/2026-07-15-wiremesh-engineering-design.md` §7 (Relay)
> + §6.1 relay-failover. Cycle 4a (direct gateway) merged; 4b (NAT traversal:
> brokered punch + path state machine) merged/merging. 4c is the guaranteed
> path — when direct/punch fails (symmetric/CGNAT), traffic flows via a relay.

## 1. Scope

Productionize the Phase-0 `spike/relay` (Bet 3, proven: mTLS-enforced QUIC
datagram bridge, WG-over-QUIC at MTU 1280 end-to-end) into:
1. **`wiremesh-relay` binary** — stateless QUIC-datagram bridge; in-memory
   `{gateway_id → QUIC connection}`; forwards `[dest_id][WG ciphertext]`
   datagrams between the two connections of a pair; mTLS against the fabric CA
   with an **offline revoked-serial denylist** check; persists identity
   (cert/key/CA/denylist, 0600) — fail-static.
2. **Relay enrollment** — reuse the gateway `Enroll` flow with `--kind relay`
   (already allowed by `enrollment_token.kind`); a relay registers its public
   endpoint (no segment/CIDRs); `certificate.subject_kind='relay'`.
3. **Relay advertisement over Sync** — the controller reads the `relay` DB
   table and advertises healthy relays in `StateSnapshot/Delta.relays`
   (today hardcoded empty); a health pipeline evicts an unhealthy relay from
   advertisements within 15s (R-3).
4. **Gateway relay transport** — the gateway holds one QUIC `Client` connection
   per advertised relay; boringtun's peer `endpoint=` is pointed at a **local
   relay-transport socket** that bridges local-UDP ↔ QUIC datagrams (the
   `udpshim` role, productionized), so the WG session/ciphertext is unchanged
   across a direct↔relay switch (no rekey; §6.1).
5. **Path-SM `Relayed` wiring** — feed real `relay_available` (from relay
   health) into `path::tick`; drive `Connecting/Degraded → Relayed`,
   `Relayed → Direct` (make-before-break background direct probe), and
   `Relayed → Relayed` re-path (≤15s) — filling the 4b inert stub.
6. **Relay conformance** — netns: two gateways whose **direct path is blocked**
   (symmetric NAT cell so the punch fails, per 4b) form a working tunnel **via
   the relay**; MTU-1280 boundary; make-before-break revert; ≤30s convergence.

## 2. Done bar

A netns conformance suite (`wiremesh-testkit`, `--features netns`, with the
mandatory `tc netem` from 4b):
1. **Relay-only pair** — two gateways behind **symmetric** NATs (direct punch
   fails, 4b's proven negative) reach a relay-needed verdict, open QUIC to an
   advertised relay, and pass **real workload traffic over the WG-over-QUIC
   relay path** (`path` state = `Relayed`), within the ≤30s convergence budget.
2. **Make-before-break** — when a direct path becomes available (e.g. a
   port-restricted pair that punches), a `Relayed` pair reverts to `Direct`
   via the background direct probe **without dropping the flow** (§6.1).
3. **Relay eviction / re-path** — an unhealthy relay is dropped from
   `relays` within 15s and the pair re-paths to the next advertised relay (or
   parks if none), driven by the gateway's QUIC-ping health report.
4. **mTLS + denylist** — a relay rejects a certless client and a client whose
   serial is on the pushed denylist, offline (no controller), at the TLS layer.
5. **MTU 1280** — the relay path carries the WG session at tun MTU 1280 (the
   `spike/relay` boundary assertion: 1232-byte inner ping succeeds, DF 1400
   fails).

## 3. `wiremesh-relay` binary (new crate `crates/wiremesh-relay`)

Graduate `spike/relay/src/{lib.rs,bin/relay.rs}`. Static binary (G-1).
- **QUIC server** via `quinn` + `rustls`: `server_config(certdir)` (relay
  cert/key + `WebPkiClientVerifier` over the fabric CA making client certs
  REQUIRED), ALPN `wiremesh-relay/0`, `transport_config` (30s idle, DPLPMTUD,
  1MiB datagram recv buffer). Reuse the spike's `transport_config`.
- **Registration + forwarding:** per accepted connection — mTLS handshake →
  `read_registration_id` (8-byte gateway id on the first bidi stream) → insert
  into the `Registry = Arc<Mutex<HashMap<[u8;8], Connection>>>` → `ack` → loop
  `read_datagram()` → `[8B dest_id][payload]` → look up dest → forward with
  `[8B src_id][payload]`; remove on disconnect. Reuse the spike's proven code.
- **Offline denylist (new — the 4c auth addition):** wrap the spike's
  `WebPkiClientVerifier` in a custom `rustls::server::ClientCertVerifier` that,
  after webpki chain validation, extracts the client cert serial and REJECTS if
  it's on the persisted denylist. The relay runs a **Sync client** (mTLS, its
  own relay cert) to receive `revoked_serials` deltas and persists the last set
  to `/var/lib/wiremesh/denylist.json` (0600) — fail-static (rejects revoked
  gateways even during a controller outage; §7/§3.2).
- **Identity/state store:** cert+key+CA+denylist at `/var/lib/wiremesh/` 0600;
  no session/flow state (stateless — restart re-established by gateways).
- **Health:** responds to QUIC ping (built into quinn keep-alive/ping); the
  gateway measures RTT/liveness and reports per-relay health upward.
- **Metrics/logs:** relay datagram throughput + active pairs (§8), structured
  JSON logs.

## 4. Relay enrollment (controller + trust)

Reuse the gateway `Enroll(token, csr, cidrs)` flow with a `relay`-kind token:
- **Generalize `Enroll`:** when the token's `kind='relay'`, skip the
  segment/CIDR resolution (`EnrollError::NoMatchingSegment` path) — a relay has
  no segment; instead accept the relay's **public endpoint** (add an
  `endpoint` field to `EnrollRequest`, used only for relays) and create a
  `relay` row + a `certificate` row with `subject_kind='relay'`. Add
  `Db::enroll_relay` (sibling of `enroll_gateway`) — inserts the `relay` row
  (name `relay-{secret_hash}`, endpoint, status `active`), records the cert.
- The relay's cert CN identifies it; it's signed by the fabric CA (90d TTL),
  same `CertificateIssuer::sign` path. `EnrollResponse` returns cert+CA (relay
  ignores `observe_key`/`gateway_id` or gets a relay_id).
- `fabricctl` gains a `relay enroll` path (or reuse the enrollment client with
  `--kind relay`). The existing `RegisterRelay` admin RPC (bookkeeping) is
  superseded/wired to the real relay row.

**Decision:** relay enrollment reuses the gateway flow (§3.1 "same flow"),
with the two gateway-specific assumptions (non-empty CIDRs; `gateway` row)
generalized behind the token kind. `EnrollRequest.endpoint` is an additive
proto field (empty for gateways).

## 5. Relay advertisement + health (controller Sync)

**Proto — upgrade `relays` to structured (safe: the field is always empty
today, no consumer):** change `StateSnapshot.relays` and `Delta.relays` from
`repeated string relays = 4` to `repeated RelayInfo relays = 4` where
`message RelayInfo { uint64 relay_id = 1; string endpoint = 2; }` (only healthy
relays are advertised, so status is implied by presence). Update
`DesiredState.relays` in the gateway to `Vec<RelayInfo>`-equivalent.

**Controller:**
- `build_snapshot` (and the delta builders) populate `relays` from the `relay`
  table WHERE `status='active'` (was hardcoded `Vec::new()` at
  `projection.rs:392`).
- **Health pipeline:** gateways report per-relay health via `Report`. Extend
  `ReportRequest` with `repeated RelayHealth { uint64 relay_id = 1; bool
  healthy = 2 }` (additive). The controller aggregates health; if a relay is
  reported unhealthy by (enough) gateways or its `last_seen` goes stale, flip
  `relay.status` and emit a `Delta` removing it from `relays` **within 15s**
  (R-3). A `ChangeEvent::RelaysChanged` maps to a delta carrying the current
  `relays` set.
- New relay enrollment → `ChangeEvent::RelayEnrolled` → delta adds it to
  `relays`.

## 6. Gateway relay transport (gateway crate)

Graduate `spike/relay/src/{lib.rs Client, bin/udpshim.rs}` into the gateway:
- **`relay.rs` (new):** a `RelayTransport` that, for an advertised relay, opens
  a QUIC `Client` connection (mTLS, the gateway's own cert, registering its
  gateway_id), binds a **local UDP socket** (`127.0.0.1:<relayport>`), and runs
  two pumps: uplink (local UDP → `client.send_to(peer_id, payload)`), downlink
  (`client.recv()` → local UDP to boringtun). boringtun's peer `endpoint=` is
  set to this local socket, so WG ciphertext rides the relay unchanged.
- **Path-SM driver wiring (extends 4b Task 10):** the per-peer tick driver now
  passes `relay_available = (an advertised+healthy relay exists AND a QUIC
  connection is up)`; on `PathAction::MarkRelayNeeded` / entering `Relayed`,
  point that peer's WG `endpoint=` at the local relay-transport socket;
  `Relayed → Direct` (make-before-break): keep a low-rate background direct
  punch/probe; when it completes a handshake, re-point `endpoint=` back to the
  direct candidate (no rekey — same WG session); `Relayed → Relayed`: on relay
  QUIC failure, re-connect to the next advertised relay within 15s.
- **Health reporting:** the gateway QUIC-pings its relay connections and reports
  `RelayHealth` in `Report`.
- **MTU:** the relay path already fits tun MTU 1280 with headroom (spike
  proved it); DPLPMTUD on the QUIC transport; if a relay path reports a limit
  below the required payload, lower that peer route's MTU + metric (§6.1, P1).

## 7. Conformance harness (netns)

Port `spike/relay/tests/wg_over_relay.rs`'s topology into `wiremesh-testkit`:
- Three-plus netns: a relay netns reachable by both gateways; two gateway netns
  whose **direct underlay path is blocked** (either the spike's route-blocking,
  or — better, integrating 4b — behind **symmetric** NAT cells so the punch
  genuinely fails). Assert (right-reason guard, from the spike) that the
  gateways have NO direct reachability, so a passing overlay flow proves the
  relay carried it.
- Real `wiremesh-relay` + real gateway relay transport (not the `udpshim`
  stand-in) + real controller advertising the relay. `tc netem` present.
- Cases per §2: relay-only pair flows; make-before-break revert; relay
  eviction/re-path; mTLS+denylist rejection; MTU 1280 boundary.

## 8. Decisions (owner — flag if wrong)

- **A. `relays` proto → structured `RelayInfo{relay_id, endpoint}`** (safe:
  field always empty today). Rather than keep bare endpoint strings — the
  gateway needs a stable relay_id for per-relay health reporting.
- **B. Relay enrollment reuses the gateway `Enroll` flow** with `kind=relay` +
  an additive `EnrollRequest.endpoint`; `Db::enroll_relay` sibling. Not a
  separate enrollment service.
- **C. Offline denylist at the relay** via a custom `ClientCertVerifier`
  wrapping webpki + a Sync client on the relay receiving `revoked_serials`.
- **D. Gateway relay transport = productionized `udpshim`** (local UDP socket
  boringtun points at ↔ QUIC datagrams), reusing the one-UDP-port property so
  direct↔relay switches don't rekey.
- **E. Done-bar's "direct blocked" = symmetric NAT cells** (integrating 4b's
  proven punch-failure) rather than a synthetic route block — proves the real
  end-to-end "punch fails → relay carries it" story.

## 9. Non-goals (4c)

Key rotation (separate fast-follow); multi-relay load balancing / relay
selection policy beyond "first healthy advertised" (P1); relay-to-relay
chaining; per-peer MTU raising (P1); IPv6; the measured G-2 throughput number.

## 10. Task decomposition (for the plan)

1. Proto: `RelayInfo`, `relays` → structured, `EnrollRequest.endpoint`,
   `ReportRequest.relay_health`.
2. `crates/wiremesh-relay` binary — QUIC bridge (graduate spike) + mTLS +
   registry/forwarding.
3. Relay offline denylist verifier + relay Sync client (receive revoked_serials,
   persist, reject at TLS).
4. Controller: relay enrollment (`enroll_relay`, generalize `Enroll`).
5. Controller: relay advertisement (`build_snapshot`/deltas from the relay
   table) + `RelaysChanged`/`RelayEnrolled` events.
6. Controller: relay health pipeline (Report.relay_health → status → evict
   within 15s).
7. Gateway relay transport (`relay.rs`: QUIC Client + local-UDP bridge).
8. Gateway path-SM relay wiring (real `relay_available`; Relayed endpoint
   switch; make-before-break; re-path) + health reporting.
9. testkit relay conformance harness (port spike topology + symmetric cell).
10. Relay netns conformance suite (the done-bar) + docs.
