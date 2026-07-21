# Cycle 4c — Relay path: wrap-up notes

Productionizes the Phase-0 `spike/relay` (Bet 3: mTLS QUIC-datagram bridge, WG-over-QUIC@1280)
and fills 4b's inert path-SM `Relayed` seam. Design: `docs/superpowers/specs/2026-07-20-cycle4c-relay-design.md`;
plan: `docs/superpowers/plans/2026-07-20-cycle4c-relay-plan.md`. Executed subagent-driven (separate
test-author / implementer / dedicated-runner / reviewer per task, per CLAUDE.md).

## What shipped (Tasks 1–10)
1. **Proto** — `RelayInfo{relay_id,endpoint}` + `RelayHealth{relay_id,healthy}`; `StateSnapshot/Delta.relays`
   → `repeated RelayInfo`; `ReportRequest.relay_health`; `EnrollRequest.endpoint`. Generated `RelayInfo`
   carries serde derives (build.rs `type_attribute`) for the gateway's fail-static `state.json`.
2. **`crates/wiremesh-relay`** — QUIC datagram bridge graduated from the spike: `server_config`
   (`WebPkiClientVerifier`, client certs REQUIRED, ALPN `wiremesh-relay/0`, 30s idle + DPLPMTUD + 1MiB
   datagram buf), 8-byte-id registration+ack, `[dest_id][payload]` forward with src-id prepend,
   remove-on-disconnect. Later made embeddable: `serve`/`spawn_server`, `test_certs`, `Client::connect_with_pems`,
   `Client::close`/`is_alive`.
3. **Offline revocation denylist** — a custom `rustls::ClientCertVerifier` wrapping webpki that rejects a
   client cert whose serial is on a persisted denylist (`x509-parser` raw_serial, DER leading-0x00
   normalized to the trust crate's 16-byte hex — **a review caught a revocation-bypass** in the first
   single-strip normalization for serials that genuinely begin with 0x00; fixed to reconstruct the full
   16-byte width). Relay Sync client folds `revoked_serials` (snapshot=replace, delta=union), persists
   `denylist.json` 0600, fail-static.
4. **Controller relay enrollment** — `Enroll` routes on a non-empty `EnrollRequest.endpoint` to a relay
   path: skips CIDRs, signs a relay cert, `Db::enroll_relay` (atomic single-use + `kind='relay'` check;
   relay row + `certificate.subject_kind='relay'`). Reviewer confirmed no token-reuse/kind-bypass.
5. **Relay advertisement** — `build_snapshot`/`delta_for_change` fill `relays` from `status='active'`
   rows; `ChangeEvent::RelaysChanged` (broadcast, subject_gateway_id=0); relay enrollment validates the
   endpoint as `SocketAddrV4` (IPv4-only) and emits the delta.
6. **Relay health pipeline** — `Report.relay_health` aggregated per-relay (healthy iff ≥1 gateway vouches);
   unhealthy → `status='inactive'` + `RelaysChanged` eviction, synchronous on the Report (≤15s). **A review
   caught a TOCTOU race** (read-decide-write across awaits) → fixed by holding a `tokio::sync::Mutex` across
   the whole relay-health block.
7. **Gateway relay transport** — `RelayTransport` (graduated `udpshim`): local UDP socket ↔ QUIC via
   `wiremesh_relay::Client`, two pumps, `is_healthy`; boringtun's peer `endpoint=` points at the local
   socket so WG ciphertext rides the relay unchanged.
8. **Path-SM relay wiring** — `PathAction::ProbeDirect` + real `Relayed` arm; `run_path_ticks` computes
   real `relay_available`, does a **rekey-free** endpoint switch to the relay socket, and reports
   `RelayHealth`. **A review caught a Critical multi-peer relay-id collision** (every peer registered at the
   relay under the same `gateway_id`) → fixed with a directional `relay_pair_id(my,peer)`; and an SLA carry
   (backoff never reset) → fixed.
9. **Relay netns conformance (done-bar case 1)** — `crates/wiremesh-gateway/tests/relay_matrix.rs`: two
   gateways behind **symmetric** NAT (direct punch provably fails), a real controller advertising a real
   in-process `wiremesh-relay`, mandatory `tc netem 20ms`. Proves the pair reaches `path=relayed`, endpoints
   are relay-local, a real WG handshake completes, and ICMP crosses the tunnel — with a right-reason
   no-direct-route guard and a never-`direct` honesty guard. RELIABLY green (5×).
   - **Found + fixed a genuine long-standing eBPF bug** (a known Phase-0 carry): the ICMP-echo reverse-flow
     key swapped sport/dport, but `ports_at` returns `(identifier,0)` for both request and reply, so echo
     replies missed the flow table and were default-denied. `relay_matrix` is the first netns test to
     exercise bidirectional ICMP. Cycle-3 conformance stays **22/22** (backends converge).
   - **Found + fixed a relay-starvation flake**: the make-before-break `ProbeDirect` fired every ~1s,
     keeping a transient `SO_REUSEPORT` punch socket on the WG port almost continuously; Linux's
     flow-to-socket rehash intermittently steered *relayed* inbound traffic into the punch socket. Fixed
     with a 20s `PROBE_DIRECT_INTERVAL` + grace period. See `cycle4c-relay-stability-note.md`.

## Done-bar coverage (spec §2)
- **Case 1 (relay-only symmetric pair flows over the relay):** ✅ `relay_matrix::case1_symmetric_pair_flows_over_relay` (reliably green).
- **Case 3 (relay eviction / re-path ≤15s):** `relay_matrix::case3_relay_eviction_repaths_to_second_relay` (Task 10).
- **Case 4 (mTLS + denylist rejection, offline):** ✅ covered by `wiremesh-relay/tests/denylist.rs` (certless + revoked-serial rejected with no controller) + `bridge.rs` (certless).
- **Case 5 (MTU 1280 boundary):** ✅ covered by `wiremesh-relay/tests/bridge.rs` (usable datagram ≥ 1320 = WG 1280 + overhead 32 + relay hdr 8, immediately and settled).
- **Case 2 (make-before-break Relayed→Direct revert):** **DEFERRED — fast-follow.** The direct-cutover
  detection is unreliable because WireGuard does not force a fresh noise handshake merely because the UAPI
  endpoint changed, so `on_handshake` may never fire after a repoint. Needs a forced rehandshake/keepalive.
  The relay path itself is stable and non-disruptive (case 1); the direct probe is gated + rate-limited so
  it never breaks a working relay. See `cycle4c-relay-stability-note.md`.

## Carries / fast-follows
- **Make-before-break Relayed→Direct cutover** (case 2) — force a WG rehandshake on repoint; add the netns case.
- **relay_pair_id** 32-bit → raw `[u8;8]`; **per-(gateway,relay) connection multiplexing** (one QUIC conn
  per peer today — correct via unique ids, but N connections).
- Relay endpoint `SocketAddrV4` only (IPv4 v1); admin `RegisterRelay` path still doesn't bump revision/emit
  a delta (superseded by enrollment); `(revision, active_relays)` not read atomically under one lock
  (narrow, inherited pattern); enrollment vs SyncSvc `RelaysChanged` emission not DRY'd (separate structs).

## Deployment
`wiremesh-relay` needs identity (cert/key/ca) at `/var/lib/wiremesh/` 0600 (from fabric-CA enrollment, `--kind relay`).
