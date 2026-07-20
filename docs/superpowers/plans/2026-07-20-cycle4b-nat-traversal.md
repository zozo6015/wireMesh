# Cycle 4b — NAT Traversal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]` checkboxes.

**Goal:** Two gateways behind NATs form a direct WireGuard tunnel via controller-brokered simultaneous hole punching; a gateway that cannot punch (symmetric/CGNAT) reaches a correct "relay-needed" verdict. Relay transport is 4c.

**Architecture:** New Sync `PunchDirective` (a broker signals both peers of a pair to punch at each other's candidates with bounded go-skew); controller multi-candidate model (observed public + gateway-reported local); gateway same-socket punch (transient `SO_REUSEPORT` socket on the WG port opens the NAT mapping boringtun reuses — **proven in `spike/natpunch`**) + a `Connecting/Direct/Degraded/Relayed/Disconnected` path state machine; netem-fidelity NAT-matrix conformance.

**Tech Stack:** Rust, tonic/prost, tokio, boringtun 0.6, rusqlite; netns + `tc netem` conformance via `wiremesh-testkit --features netns`.

## Global Constraints

- **Spec:** `docs/superpowers/specs/2026-07-20-cycle4b-nat-traversal-design.md` governs; master spec §6.1 governs conflicts.
- **De-risk reference:** `spike/natpunch/` (proven: transient-socket punch carries a real WG handshake through port-restricted NAT; symmetric fails correctly). Graduate its mechanics; do not re-invent.
- **`tc netem delay 20ms` on every internet-side link is MANDATORY** in any punch test (Phase-0 Finding 2 — zero-latency labs give false punch-failure). No punch conformance test may omit it.
- **Go-skew < inter-peer one-way latency** — the broker emits both `PunchDirective`s back-to-back in one critical section (no await between); `go_unix_ms` is the corroborating signal.
- **Same-socket, not boringtun fork:** punch from a `SO_REUSEPORT` socket on the WG listen port; NAT maps on `(src ip:port[,dst])` not the socket. In production boringtun is already bound to that port — the punch socket binds concurrently (SO_REUSEPORT) and is closed after punching so inbound handshakes land on boringtun.
- **4b/4c boundary:** 4b builds punch + path SM + `relay-needed` verdict. The `Relayed` state and its transitions are wired-but-inert (no relay transport until 4c). Do NOT build QUIC/relay here.
- **Timers:** keepalive 15s; Direct→Degraded after 45s no authenticated inbound; ≤30s convergence budget.
- **IPv4-only.** Env: macOS host, all builds/tests in the privileged container via `./dev.sh run "<cmd>"`; netns tests serial (`--test-threads=1`).
- **Agent separation (CLAUDE.md):** author/implement/execute tests via three different agents; independent reviewer.

## Task map

- **Task 1 — DONE** (de-risk `spike/natpunch`).
- Task 2: Proto — `PunchDirective` + `ReportRequest.local_endpoints`.
- Task 3: Controller — multi-candidate DB model.
- Task 4: Controller — store gateway-reported local endpoints (Report path).
- Task 5: Controller — the broker (paired `PunchDirective`, go-skew, triggers).
- Task 6: Harness — `tc netem` knob on `nat_router` (mandatory).
- Task 7: Gateway — same-socket observation + puncher (graduate natpunch).
- Task 8: Gateway — local-address enumeration + reporting; candidate iteration.
- Task 9: Gateway — path state machine + timers + metrics.
- Task 10: Gateway — wire punch + path SM into the boot loop (consume `PunchDirective`).
- Task 11: NAT-matrix netns conformance (the done-bar).
- Task 12: Docs + CLAUDE.md + tracker.

---

### Task 2: Proto — PunchDirective + Report local_endpoints

**Files:** Modify `proto/wiremesh/v1/sync.proto`; Test `crates/wiremesh-proto/tests/` (round-trip) or a controller unit test.

**Interfaces produced:**
```proto
message SyncMessage {
  oneof body { StateSnapshot snapshot = 1; Delta delta = 2; PunchDirective punch = 3; }
}
message PunchDirective {
  uint64 peer_gateway_id = 1;
  repeated string candidates = 2;   // the peer's candidate set (public + local)
  uint64 go_unix_ms = 3;            // synchronized fire instant (best-effort corroboration)
}
message ReportRequest { uint64 applied_version = 1; repeated string local_endpoints = 2; }
```

- [ ] Step 1: Add the `PunchDirective` message, the `punch = 3` oneof arm, and `ReportRequest.local_endpoints = 2` (additive field). Prost regenerates on build.
- [ ] Step 2: Write a round-trip test: build a `SyncMessage{ body: Some(Body::Punch(PunchDirective{...})) }`, prost-encode→decode, assert equality; and a `ReportRequest` with `local_endpoints` round-trips (empty vec = old behavior). Run `./dev.sh run "cargo test -p wiremesh-proto"` (or the controller test) → RED (field/variant absent) then GREEN.
- [ ] Step 3: Commit `feat(proto): PunchDirective SyncMessage variant + ReportRequest.local_endpoints`.

---

### Task 3: Controller — multi-candidate DB model

**Files:** Modify `crates/wiremesh-controller/src/db.rs` (schema + candidate accessors), `src/projection.rs` (emit the set), possibly `src/db_async.rs`. Test `crates/wiremesh-controller/tests/`.

**Context:** today a single `gateway.candidate_endpoint` column, surfaced via `candidate_endpoints: p.candidate_endpoint.into_iter().collect()` (projection.rs ~366). §6.1 needs candidates = observed public + local addresses (a set).

**Interfaces produced:**
- New table `gateway_candidate(gateway_id INTEGER, endpoint TEXT, source TEXT /* 'observed'|'local' */, observed_at TEXT, PRIMARY KEY(gateway_id, endpoint))`.
- `Db::set_observed_candidate(gateway_id, endpoint) -> Result<Option<u64>>` — upserts the single `observed`-source row (replacing any prior observed row for that gateway; last-observed-wins for the observed slot), returns new revision if changed (preserves the existing `set_candidate_endpoint` semantics for the observed value).
- `Db::set_local_candidates(gateway_id, &[String]) -> Result<Option<u64>>` — replaces the `local`-source rows for that gateway with the given set; returns new revision if the set changed.
- `Db::candidates_for(gateway_id) -> Result<Vec<String>>` — the full ordered set (observed first, then locals), deduped.

**Detail:** keep the migration additive/safe — create `gateway_candidate`; on the existing `candidate_endpoint` column, either migrate its value into an `observed` row at startup or keep the column as the observed slot and add the table only for locals. **Simplest safe path:** keep `gateway.candidate_endpoint` as the observed value (unchanged writer `set_candidate_endpoint`), add `gateway_candidate` ONLY for `local`-source rows, and have `candidates_for` = `[candidate_endpoint?] ++ local rows`. This avoids a data migration and preserves all Cycle-2/3 observed-endpoint behavior. Prefer this unless a reviewer objects.

- [ ] Step 1: Write failing tests: `candidates_for` returns observed + locals deduped; `set_local_candidates` replaces the local set and bumps revision only on change; an observed-only gateway (no locals) returns just its observed endpoint (back-compat).
- [ ] Step 2: Add the `gateway_candidate` table + the three accessors (keeping `set_candidate_endpoint`/`candidate_endpoint` as the observed slot).
- [ ] Step 3: Update `projection.rs::build_snapshot` and the `EndpointObserved`/`SegmentCidrsChanged` delta builders to emit `candidates_for(gw)` into `Peer.candidate_endpoints` (was the single value). Confirm existing snapshot/delta tests still pass (an observed-only gateway yields the same single-element list).
- [ ] Step 4: `./dev.sh run "cargo test -p wiremesh-controller -- --test-threads=1"` GREEN. Commit `feat(controller): multi-candidate model (observed + local)`.

---

### Task 4: Controller — store gateway-reported local endpoints

**Files:** Modify `crates/wiremesh-controller/src/services/sync.rs` (the `Report` handler). Test `crates/wiremesh-controller/tests/`.

**Context:** `Report(ReportRequest)` today only persists `applied_version` (sync.rs ~156-180). Task 2 added `local_endpoints`.

- [ ] Step 1: Failing test: a gateway calls `Report{applied_version, local_endpoints:["10.0.0.5:51820"]}`; assert `Db::candidates_for(gw)` now includes that local endpoint (source `local`), and a peer's snapshot lists it in `candidate_endpoints`.
- [ ] Step 2: In the `Report` handler, after persisting the version, call `Db::set_local_candidates(gateway_id, &req.local_endpoints)`; if it changed the set, publish a `ChangeEvent::EndpointObserved`-style delta (or a new `CandidatesChanged` event) so peers learn the locals without a reconnect. (Reuse the `EndpointObserved` event shape if it already carries the candidate list; otherwise add a minimal `ChangeEvent::CandidatesChanged { gateway_id, candidates, ... }` mapped to a `Peer` upsert delta.)
- [ ] Step 3: GREEN + full controller suite. Commit `feat(controller): store gateway-reported local endpoints as candidates`.

---

### Task 5: Controller — the broker (paired PunchDirective)

**Files:** Create `crates/wiremesh-controller/src/broker.rs`; modify `src/services/sync.rs` (deliver `PunchDirective` on the Watch stream to both members), `src/lib.rs` (wire the broker). Test `crates/wiremesh-controller/tests/broker.rs`.

**Context:** the Watch fan-out is per-connection and self-EXCLUDES the subject gateway (sync.rs ~126) — a pair directive must reach BOTH. Model the broker on `spike/punch/src/bin/broker.rs` (two back-to-back writes).

**Interfaces produced:**
- The broker tracks connected gateways' Watch senders (a registry `{gateway_id -> mpsc::Sender<SyncMessage>}` populated when a `Watch` stream opens, removed on close), separate from the broadcast-delta path.
- `Broker::maybe_punch(pair)` — when both gateways of a peer-pair are connected and each has ≥1 candidate, build `PunchDirective` for each (carrying the OTHER's `candidates_for`), stamp a common `go_unix_ms = now + PUNCH_LEAD_MS` (e.g. 300ms), and send both **back-to-back in one critical section** (no `.await` between the two `try_send`s). 
- Triggers: on both-connected + mutual-candidates; on a candidate change for either; and a periodic retry (e.g. every 5s) while the pair is not yet confirmed Direct (the controller doesn't know Direct state in 4b — so retry on a bounded schedule while both are connected and recently punched < N times, backing off).

**Detail — delivering on the Watch stream:** the `Watch` handler currently forwards snapshot + broadcast deltas. Add a per-connection `mpsc` channel the broker can push `SyncMessage{punch}` into; the Watch loop `select!`s over {broadcast deltas, broker punch channel, shutdown}. Register the sender in the broker keyed by the connection's authenticated `gateway_id`; deregister on stream end.

- [ ] Step 1: Failing test (`broker.rs`): two stub gateways open Watch; each reports a candidate; assert BOTH receive a `PunchDirective` naming the other's `gateway_id` + candidates, and the two directives' emission timestamps differ by < a small bound (skew). Use `TestController` + a way to read pushed `SyncMessage`s (extend `StubGateway` to surface received `PunchDirective`s — additive).
- [ ] Step 2: Implement `broker.rs` + the Watch-stream punch channel + registry; wire into `serve()`.
- [ ] Step 3: GREEN + full controller suite (no regression to snapshot/delta/self-skip behavior — the self-skip still applies to Deltas; PunchDirective uses the new explicit-target path). Commit `feat(controller): broker paired PunchDirective with bounded go-skew`.

---

### Task 6: Harness — tc netem knob on nat_router (MANDATORY)

**Files:** Modify `crates/wiremesh-testkit/src/netns.rs` (`nat_router` / a punch-lab builder). Test: exercised by Task 11; add a small assertion helper.

**Context:** `nat_router` uses zero-latency veths → false punch-failure (Finding 2). Must add `tc netem delay` on the internet-side link.

- [ ] Step 1: Add an additive `nat_router_delayed(name, kind, delay_ms)` (or a `delay_ms` param / builder option) that, after creating the router + masquerade, runs `tc qdisc add dev out0 root netem delay {delay_ms}ms` on the router's outside interface (and/or the peer side). Keep the existing `nat_router` signature intact (back-compat).
- [ ] Step 2: A helper `assert_netem_present(ns, iface)` that greps `tc qdisc show dev {iface}` for `netem`. Confirm existing enforcer/gateway netns tests (which use `nat_router` indirectly, if any) still compile.
- [ ] Step 3: Commit `test(testkit): tc netem latency on nat_router for punch fidelity`.

---

### Task 7: Gateway — same-socket observation + puncher

**Files:** Modify `crates/wiremesh-gateway/src/observe.rs`; create `crates/wiremesh-gateway/src/punch.rs`; modify `src/lib.rs`. Test: unit + a netns punch test (Task 11 covers end-to-end; here a focused one).

**Context:** graduate `spike/natpunch`'s observe + punch. 4a's `observe::report_once` already binds a `SO_REUSEPORT` socket on the WG port (`reuseport_udp`). Reuse it; add the punch.

**Interfaces produced:**
- `punch::punch_candidates(bind_port: u16, candidates: &[String], window: Duration) -> anyhow::Result<Option<SocketAddr>>` — opens a transient `SO_REUSEPORT` socket on `bind_port` (reuse `observe::reuseport_udp`), blasts `PING` at every non-loopback/non-unspecified candidate for `window` (tolerating/retrying across the conntrack-poisoning window), returns the first candidate that PONGs (the confirmed reachable peer address), or `None` on timeout. **Closes the socket on return** so boringtun (bound to the same port) receives the subsequent WG handshake. Model on `spike/natpunch` gateway bin.
- Keep `observe::report_once` (the observation half) — it already binds the same-port socket.

**Production nuance (from the de-risk report):** in production boringtun is ALREADY bound to `bind_port`; the punch socket binds concurrently via `SO_REUSEPORT`. Inbound during the punch window may hash to either socket — the puncher must only rely on its own PING/PONG for confirmation and MUST close promptly. The mapping reuse is conntrack-keyed (ASSURED ~120s), ordering-independent, so boringtun's later handshake reuses it. Verify this concurrent-bind behavior in the netns test.

- [ ] Step 1: Failing netns test (feature-gated): two gateway netns behind `nat_router_delayed(PortRestricted, 20)`, a broker/observe stand-in; each observes, then `punch::punch_candidates` at the peer's observed candidate; assert both return `Some(peer_addr)` (punch confirmed) — and assert netem present first. (This reuses spike/natpunch's proven flow; port it into the gateway crate's test.)
- [ ] Step 2: Implement `punch.rs` (graduate natpunch), reusing `observe::reuseport_udp`.
- [ ] Step 3: `./dev.sh run "cargo test -p wiremesh-gateway --test <punch_netns> --features netns-tests -- --test-threads=1"` GREEN. Commit `feat(gateway): same-socket hole puncher`.

---

### Task 8: Gateway — local-address enumeration + candidate iteration

**Files:** Modify `crates/wiremesh-gateway/src/observe.rs` or a new `netif.rs` (enumerate local addrs); `src/state.rs` (PeerState holds candidate LIST); `src/reconcile.rs` (endpoint = confirmed candidate); `src/main.rs` (Report carries local_endpoints). Tests: unit.

**Interfaces produced:**
- `netif::local_wg_endpoints(wg_port: u16) -> Vec<String>` — enumerate the host's routable (non-loopback, non-link-local) IPv4 addresses, format `ip:wg_port`. (Shell `ip -4 -o addr show` and parse, per repo shell-out convention, or use `nix`/`libc` getifaddrs — prefer the shell-out to match the repo.)
- `state::PeerState.candidates: Vec<String>` (replacing the single `candidate_endpoint: Option<String>`; keep a helper `.primary()` for the current WG `endpoint=` until punch confirms one).
- `reconcile::peer_configs` sets `endpoint` = the peer's confirmed candidate if known, else the first candidate (bootstrap).

- [ ] Step 1: Failing unit tests: `PeerState::from_proto` keeps ALL `candidate_endpoints` (not just `.first()`); `local_wg_endpoints` filters loopback/link-local and appends `:wg_port` (test with a parsed fixture of `ip -o addr` output — factor the parse into a pure fn `parse_ip_addr_output(&str, wg_port) -> Vec<String>` and test that).
- [ ] Step 2: Implement; thread `local_wg_endpoints` into the `Report` call in `main.rs` (send `local_endpoints`). Update `reconcile`/`state` to carry the list.
- [ ] Step 3: GREEN (lib). Commit `feat(gateway): enumerate + report local endpoints; carry candidate list`.

---

### Task 9: Gateway — path state machine + timers + metrics

**Files:** Create `crates/wiremesh-gateway/src/path.rs`; modify `src/metrics.rs`. Tests: unit (injectable clock).

**Interfaces produced:**
- `path::PathState` enum `Connecting | Direct | Degraded | Relayed | Disconnected`.
- `path::Path { state, last_handshake: Option<Instant>, last_inbound: Option<Instant>, connecting_since, backoff }` with `Path::on_handshake(now)`, `Path::on_authenticated_inbound(now)`, `Path::tick(now, relay_available: bool) -> Option<PathAction>` where `PathAction ∈ { StartPunch, MarkRelayNeeded, Retry }`. Transitions exactly per spec §6 (Connecting→Direct on handshake; →Relayed if no handshake in 10s && relay_available [4b: relay_available always false → →Disconnected/relay-needed]; Direct→Degraded at 45s no inbound; keepalive drives inbound; Disconnected→Connecting backoff).
- The driver reads boringtun's per-peer latest-handshake via UAPI `get=1` (add `uapi::get_latest_handshakes(ifname) -> Result<HashMap<pubkey, SystemTime>>` — the read side of 4a's writer). "Authenticated inbound" ≈ latest-handshake advancing OR rx bytes increasing (from UAPI `get`).
- `metrics.rs`: gauge `wiremesh_gateway_path_state{peer,state}` + counter `wiremesh_gateway_path_transitions_total{from,to}`.

- [ ] Step 1: Failing unit tests with an injectable clock: Connecting→Direct on handshake; Connecting→(relay-needed/Disconnected) after 10s no handshake with relay_available=false; Direct→Degraded after 45s no inbound; Degraded→Direct on handshake recover; Disconnected backoff increases. Assert `tick` returns the right `PathAction`.
- [ ] Step 2: Implement `path.rs` + `uapi::get_latest_handshakes` (parse the UAPI `get=1` response `public_key=...`/`last_handshake_time_sec=...`). Add metrics.
- [ ] Step 3: GREEN (lib). Commit `feat(gateway): per-peer path state machine + UAPI handshake read + metrics`.

---

### Task 10: Gateway — wire punch + path SM into the boot loop

**Files:** Modify `crates/wiremesh-gateway/src/main.rs` (+ `sync.rs` to surface `PunchDirective` from the Watch stream).

**Context:** `sync::next_desired` today handles `Snapshot`/`Delta`. Add `PunchDirective` handling: on receipt, run `punch::punch_candidates` (in `spawn_blocking`) at the directive's candidates around `go_unix_ms`, then set the peer's WG `endpoint=` to the confirmed candidate and drive the path SM. A per-peer `path::Path` map is `tick`ed on a timer; `StartPunch` re-requests/retries; the observation loop now reports `local_endpoints`.

- [ ] Step 1: Extend `sync::next_desired` (or add `sync::next_message`) to return a `SyncEvent` enum `{ State(DesiredState), Punch(PunchDirective) }` so the boot loop can act on punch directives. Unit test the punch-arm decoding.
- [ ] Step 2: In `run()`: maintain `HashMap<gateway_id, path::Path>`; on `Punch(d)`, at `go_unix_ms` run `punch::punch_candidates(wg_port, &d.candidates, window)` via `spawn_blocking`; on `Some(addr)` set that peer's endpoint (UAPI apply) and `path.on_handshake` once boringtun confirms; a periodic task `tick`s every ~1s reading UAPI handshakes → drives Direct/Degraded transitions + metrics. Relay actions record `relay-needed` (inert). Keep the fail-static + async discipline from 4a (no blocking in async without `spawn_blocking`, no lock across await).
- [ ] Step 3: `./dev.sh run "cargo build -p wiremesh-gateway"` + lib tests GREEN (end-to-end proven in Task 11). Commit `feat(gateway): consume PunchDirective + drive path state machine in boot loop`.

---

### Task 11: NAT-matrix netns conformance (the done-bar)

**Files:** Test `crates/wiremesh-gateway/tests/nat_matrix.rs` (feature `netns-tests`). Possibly small additive testkit helpers.

**Topology:** reuse the 4a mesh-milestone spawn pattern (real `wiremesh-gateway` processes) + `nat_router_delayed`. Controller in-process (`TestController::start_on` a routable underlay). Gateway-A behind NAT-A, Gateway-B behind NAT-B, both NAT outside interfaces on the internet segment with the controller; `tc netem delay 20ms` each side (assert present first).

**Asserted cases (done-bar):**
1. **Port-restricted pair → Direct:** the controller brokers the punch; both gateways complete a real WG handshake (each `wg show` latest-handshake recent) and a workload ping crosses the direct tunnel; path state reaches `Direct` within ≤30s. Confirm via conntrack on the NAT routers that traffic crossed the NATs (not a veth shortcut).
2. **Symmetric pair → relay-needed:** punch fails (no handshake), gateways reach `relay-needed`/park (metric `wiremesh_gateway_path_state{...,state="disconnected"|"relayed"}`), no hang; the run terminates deterministically.
3. **Go-skew determinism:** case 1 passes on repeat runs (≥2) with no conntrack-poisoning flake.
4. **Direct→Degraded:** after establishing Direct, stop keepalive/traffic and advance ~45s (or inject) → path SM reports `Degraded`.

Honesty: do NOT weaken; if the punch flakes, diagnose (wg show, conntrack, netem) — netem is mandatory. Separate agents author/run per CLAUDE.md.

- [ ] Step 1: Write the failing suite skeleton (topology + case-1 assertion). Run → RED.
- [ ] Steps 2-5: Fill cases 1-4; each committed as it goes green.
- [ ] Step 6: `./dev.sh run "cargo test -p wiremesh-gateway --test nat_matrix --features netns-tests -- --test-threads=1 --nocapture"` GREEN. Commit `test(gateway): 4b NAT-matrix conformance — direct punch, relay-needed, degraded`.

---

### Task 12: Docs + CLAUDE.md + tracker

**Files:** `docs/research/cycle4b-nat-notes.md` (decisions + carries), `CLAUDE.md` (project state → 4b done, next 4c), the progress tracker.

- [ ] Step 1: Write `cycle4b-nat-notes.md`: the transient-socket punch decision (+ de-risk evidence), the broker/go-skew design, multi-candidate model, path-SM, the netem-mandatory harness rule, and carries (e.g. same-socket precision limits, CGNAT as chained symmetric, relay is 4c).
- [ ] Step 2: Update `CLAUDE.md` "## Project state": Cycle 4b (NAT traversal) complete — brokered punch + path SM + relay-needed verdict; proto added `PunchDirective` + `ReportRequest.local_endpoints`; next Cycle 4c (relay). 
- [ ] Step 3: Commit `docs: Cycle 4b completion + NAT-traversal notes`.

## Self-review (coverage vs spec)
§3 same-socket punch → T7/T10 (+ de-risk T1). §4 broker/go-skew → T2/T5. §5 multi-candidate + local report → T2/T3/T4/T8. §6 path SM → T9/T10. §7 netem harness → T6. §2 done-bar → T11. §1 4b/4c boundary (Relayed inert) → T9/T10. ✔
