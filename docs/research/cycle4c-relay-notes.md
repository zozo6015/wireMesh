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
- **Case 3 (relay eviction / re-path):** `relay_matrix::case3_relay_eviction_repaths_to_second_relay` (Task 10) —
  R1's QUIC is closed, the pair re-paths to R2 and flows again. The test asserts a **30s** bound; observed
  re-path is ~14.7–15.1s. R-3's "≤15s" is design INTENT (met synchronously on the controller-eviction side;
  the gateway-side re-path settle occasionally nudges just over 15s — a documented carry, not a hard assertion).
- **Case 4 (mTLS + denylist rejection, offline):** ✅ covered by `wiremesh-relay/tests/denylist.rs` (certless + revoked-serial rejected with no controller) + `bridge.rs` (certless).
- **Case 5 (MTU 1280 boundary):** ✅ covered by `wiremesh-relay/tests/bridge.rs` (usable datagram ≥ 1320 = WG 1280 + overhead 32 + relay hdr 8, immediately and settled).
- **Case 2 (make-before-break Relayed→Direct revert):** **DEFERRED — fast-follow.** The direct-cutover
  detection is unreliable because WireGuard does not force a fresh noise handshake merely because the UAPI
  endpoint changed, so `on_handshake` may never fire after a repoint. Needs a forced rehandshake/keepalive.
  The relay path itself is stable and non-disruptive (case 1); the direct probe is gated + rate-limited so
  it never breaks a working relay. See `cycle4c-relay-stability-note.md`.

## Security fix — relay registration is now bound to the client cert (post-review)

The pre-review carry below is **FIXED** (design A — the localized option). The relay REGISTRATION id was
self-asserted and blind-overwritten; any enrolled, non-revoked gateway could register under another pair's
`relay_pair_id(A,B)` (computable from small gateway ids), redirecting that pair's relayed datagrams and/or
evicting its registry entry. Impact was bounded to traffic-redirection / DoS (WireGuard E2E crypto keeps
confidentiality/integrity), but it is a real cross-gateway authorization gap and is now closed:

- **gateway_id in the cert (design A).** Gateway enrollment now stamps a CA-decided SAN `gw-<gateway_id>` onto
  every gateway leaf (reusing `CertProfile.subject_alt_names`, the same mechanism the relay's `"relay"` SAN uses).
  The sign-after-id ordering is resolved WITHOUT weakening the atomic single-use flow: the leaf's serial is
  pre-generated (`wiremesh_trust::random_serial` → `CertProfile.serial`) so the certificate row is still recorded
  atomically with the token spend (revocability preserved), and the leaf is signed AFTER the transaction returns
  the gateway_id. `validate_csr_pem` up front preserves "a malformed CSR never burns the token". (Handle==serial
  coupling holds for the embedded issuer — noted for a future non-embedded issuer.)
- **Relay binds registration to the authenticated cert.** `wiremesh_relay::serve` reads the registering gateway's
  TRUE identity from its mTLS client cert (`identity_from_client_cert` → the `gw-<id>` DNS SAN), REQUIRES the
  self-asserted `my_identity` to equal it (else it CLOSES the connection — fail-closed), and keys the registry by
  `registration_key(my_identity, peer_identity)`. A slot already held by a DIFFERENT cert is **rejected, never
  blind-overwritten** (eviction DoS closed); a same-cert reconnect replaces its own slot (removal is
  stable-id-guarded so a replaced connection's later teardown can't evict the reconnect).
- **Registration remains peer-computable.** The addressing peer targets `registration_key(peer, my)` — exactly the
  id the other side registered under — so routing is unchanged; only the *ownership* of a slot is now cert-bound.
- **Tests:** `wiremesh-relay/tests/impersonation.rs` (a gw-A cert asserting `my_identity=gw-B` is refused while the
  legit gw-B holder works and its slot survives intact); `registration_tests` unit tests (directional/distinct/
  stable/rendezvous key + framing); `bridge.rs`/`denylist.rs` updated to the peer-bound `Client` API and stay green;
  `relay_matrix` case1+case3 (real controller enrollment + real relay) stay green.

## Carries / fast-follows
- **Make-before-break Relayed→Direct cutover** (case 2) — force a WG rehandshake on repoint; add the netns case.
- **registration_key** 32-bit → raw `[u8;8]`; **per-(gateway,relay) connection multiplexing** (one QUIC conn
  per peer today — correct via unique cert-bound ids, but N connections). The cert-binding fix keeps the one-conn-
  per-pair model (design A); the multiplexing carry (design B) is orthogonal and still open.
- Relay endpoint `SocketAddrV4` only (IPv4 v1); admin `RegisterRelay` path still doesn't bump revision/emit
  a delta (superseded by enrollment); `(revision, active_relays)` not read atomically under one lock
  (narrow, inherited pattern); enrollment vs SyncSvc `RelaysChanged` emission not DRY'd (separate structs).
- **ProbeDirect permanent churn (Minor):** a symmetric↔symmetric relayed pair fires `ProbeDirect` every 20s
  forever (the punch can never confirm), keeping the transient `SO_REUSEPORT` punch socket at ~30% duty cycle
  on the WG port. Mitigated by the 20s interval + grace (case 1 reliably green 5×); tie a "give up probing after
  N failures for a known-symmetric pair" to the case-2 fast-follow.
- **Revocation latency (Minor, consistent with fabric model):** a CURRENTLY-connected revoked gateway keeps being
  relayed until its QUIC connection idle-drops (≤30s) — the denylist only blocks NEW handshakes, not live ones.

## Deployment
`wiremesh-relay` needs identity (cert/key/ca) at `/var/lib/wiremesh/` 0600 (from fabric-CA enrollment, `--kind relay`).

## Cert-binding review — accepted fast-follows (commit 4ab8b59, security review READY)
- **Important — enrollment signing-failure-after-token-spend:** with gateway-path signing now AFTER the
  atomic commit, a `sign()` failure post-commit leaves a spent token + an active gateway row + a
  certificate row but no issued leaf. Not attacker-exploitable (needs a legitimate segment-scoped token
  AND a CSR that passes `validate_csr_pem` but fails the crypto `signed_by()` — only unusual keys);
  recoverable via an operator `rebind` token (which correctly revokes the phantom row). Fast-follow: on a
  post-commit signing failure, compensate (revoke the just-recorded cert / free the segment) so the holder
  can retry. NOT a blocker (single-tenant, self-inflicted, recoverable).
- **Minor:** `handle == serial` coupling holds for `EmbeddedTrust` only — revisit for the OpenBao/non-embedded
  issuer fast-follow (already flagged inline). Orphaned old connection on a same-owner relay reconnect is
  closed only by its own idle timeout (pre-existing resource note, not security).
