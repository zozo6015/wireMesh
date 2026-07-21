# Key-Rotation Fast-Follow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Per-gateway per-epoch WireGuard key rotation with make-before-break (zero-drop) cutover, on-demand or on a 30-day timer, reusing the 4b/4c path machinery so it works for direct and relayed gateways.

**Architecture:** Controller directs a gateway to mint a new-epoch key; the gateway stands up a **second boringtun `Device`** (new key, new UDP port; overlay IP on `lo`/dummy) alongside the old one, submits its real pubkey, and — once the new port's path is established via the existing 4b punch / 4c relay SM and its session handshakes — both ends `ip route replace` the overlay onto the new tun (both receive paths stay open → ~0 drop), ack, and the controller promotes `n+1→active` and retires `n`. Non-destructive on failure. The dual-Device / overlay-on-`lo` / route-flip mechanism is **proven** by `spike/keyrot` (commit `0ccfdb0`, `docs/research/keyrot-spike-note.md`).

**Tech Stack:** Rust; embedded boringtun 0.6 (in-process UAPI); tonic/prost gRPC; rusqlite; netns/tc-netem conformance via `wiremesh-testkit`.

## Global Constraints

- **Spec is authoritative:** `docs/superpowers/specs/2026-07-21-key-rotation-design.md`. Master §4.4's "second peer on one interface" model is WRONG (WG `allowed-ips` is peer-exclusive) — use the spike's **mechanism B** (two Devices during overlap, overlay IP on `lo`, route-flip cutover). Do NOT reintroduce the second-peer-on-one-interface approach.
- **Private keys are generated on the gateway and NEVER leave it** (master §4.4/D5). Only public keys transit the controller. `SubmitEpochKey` sends only the pubkey.
- **Make-before-break, non-destructive:** the old epoch keeps serving until the new session is PROVEN live (real handshake + `rx_bytes` corroboration, per `docs/research/cycle4b-path-liveness-note.md`). A rotation that can't complete leaves epoch `n` active everywhere with zero data-plane impact.
- **Host is macOS; ALL build/test runs in the Linux container** via `./dev.sh run "<cmd>"` from the worktree root. **Only ONE `./dev.sh` at a time** (concurrent container builds OOM). netns tests serial: `-- --test-threads=1 --nocapture`; `--features netns-tests` (gateway) / `--features netns` (testkit). `tc netem delay 20ms` MANDATORY on internet-side links wherever punch/NAT is involved (Phase-0 Finding 2).
- **Agent workflow (CLAUDE.md):** tests authored, implemented, and executed by three DIFFERENT agents; reviews by a fourth. No "done" with unrun/failing tests. Fix code, never weaken tests.
- **v1 is IPv4-only.** New UDP ports/endpoints are `SocketAddrV4`.
- **Reuse, don't reinvent:** `PunchDirective`/broker/`path.rs`/`punch.rs` (4b), `RelayTransport`/`relays_snapshot` atomic-read (4c), fail-static `state.json` (4a). Cite the exact symbol; do not re-implement.
- **Atomic (keys, revision) reads:** any controller emit of a key-set delta reads the key set and the revision under ONE lock (mirror `Db::relays_snapshot`, `crates/wiremesh-controller/src/db.rs`), so a rotation delta can never carry a stale key set tagged with a newer revision.

---

## File structure (what each unit owns)

- `proto/wiremesh/v1/sync.proto` — `RotateDirective` SyncMessage variant; `SubmitEpochKey` RPC + messages; `ReportRequest.epoch_acks`.
- `crates/wiremesh-controller/src/db.rs` — `rotate_key` (drop placeholder → sentinel), `set_epoch_pubkey`, `promote_epoch`/`retire_epoch`, `keys_snapshot` (atomic keys+revision), epoch-state queries.
- `crates/wiremesh-controller/src/services/sync.rs` — `SubmitEpochKey` handler; `Report` consumes `epoch_acks`; the promote/retire driver; `RotateDirective` emission on the addressed gateway's Watch stream.
- `crates/wiremesh-controller/src/services/admin.rs` — `rotate_key` handler wires the new flow (sentinel + directive, no placeholder advertise).
- `crates/wiremesh-controller/src/projection.rs` — advertise only real-keyed epochs; **preserve candidate_endpoints** in `KeyRotated` deltas; `RotateDirective` routing.
- `crates/wiremesh-controller/src/rotation.rs` (NEW) — the promote/retire state machine (pure, injectable-time) + the 30-day timer task.
- `crates/wiremesh-gateway/src/epochkeys.rs` (NEW) — multi-epoch key store: generate, persist to `state.json`, epoch-0 migration.
- `crates/wiremesh-gateway/src/tunnelset.rs` (NEW) — `EpochTunnel` manager: hold >1 boringtun `Device`, bring up/tear down per epoch; overlay IP on `lo`/dummy.
- `crates/wiremesh-gateway/src/state.rs` — `PeerState` retains full `keys: Vec<PeerKey>` (not just `active_pubkey_b64`).
- `crates/wiremesh-gateway/src/main.rs` — driver: `RotateDirective` handling, `SubmitEpochKey` call, per-peer second-Device reconcile, new-port path via the SM, route-flip cutover, `EpochAck` reporting.
- `crates/wiremesh-testkit/src/lib.rs` — rotation-under-load harness (generalize `spike/keyrot`), direct + relay topologies.
- `crates/wiremesh-gateway/tests/key_rotation.rs` (NEW) — netns done-bar.
- Docs: `docs/research/key-rotation-notes.md`, amend master §4.4, CLAUDE.md.

---

### Task 1: Proto — RotateDirective, SubmitEpochKey, EpochAck

**Files:**
- Modify: `proto/wiremesh/v1/sync.proto`
- Test: `crates/wiremesh-proto/tests/codegen.rs`

**Interfaces:**
- Produces: `SyncMessage.body` gains `RotateDirective rotate = 4` (numbers 1-3 taken by snapshot/delta/punch — verify and use the next free); `message RotateDirective { uint32 epoch = 1; }`. New RPC `rpc SubmitEpochKey(SubmitEpochKeyRequest) returns (SubmitEpochKeyResponse);` on `service Sync`; `message SubmitEpochKeyRequest { uint32 epoch = 1; string pubkey = 2; }`; `message SubmitEpochKeyResponse {}`. `ReportRequest` gains `repeated EpochAck epoch_acks = <next>;`; `message EpochAck { uint64 peer_gateway_id = 1; uint32 epoch = 2; bool live = 3; }`.

- [ ] **Step 1 (test-author): failing round-trip tests** in `codegen.rs` mirroring the existing prost round-trip style: encode→decode a `SyncMessage` carrying `RotateDirective{epoch:5}`; a `SubmitEpochKeyRequest{epoch:5,pubkey:"..."}`; a `ReportRequest` with two `EpochAck`s (one live, one not); assert every field survives.
- [ ] **Step 2: run — expect RED** (`RotateDirective`/`EpochAck`/`SubmitEpochKeyRequest` unresolved). `./dev.sh run "cargo test -p wiremesh-proto --no-run"` fails to compile.
- [ ] **Step 3 (implementer): add the proto messages/RPC/variant** as in Interfaces. Keep field numbers additive; `SyncMessage.body` oneof gets the new variant at the next free tag.
- [ ] **Step 4: ripple every `SyncMessage`/`ReportRequest` constructor** (gateway `sync.rs`, testkit, controller tests) with the new fields (`epoch_acks: vec![]`). `./dev.sh run "cargo test --workspace --no-run"` must compile.
- [ ] **Step 5: run — expect GREEN** `./dev.sh run "cargo test -p wiremesh-proto"`.
- [ ] **Step 6: commit** `feat(proto): RotateDirective + SubmitEpochKey + Report.epoch_acks (key-rotation Task 1)`.

### Task 2: Controller — real key material (sentinel + SubmitEpochKey fills it)

**Files:**
- Modify: `crates/wiremesh-controller/src/db.rs` (`rotate_key`, new `set_epoch_pubkey`), `db_async.rs`, `services/sync.rs` (`SubmitEpochKey` handler), `services/admin.rs` (`rotate_key` handler).
- Test: `crates/wiremesh-controller/tests/keys.rs` (extend) or new `tests/epoch_key_submit.rs`.

**Interfaces:**
- Consumes: proto `SubmitEpochKeyRequest` (Task 1).
- Produces: `Db::rotate_key` now inserts the pending row with pubkey `"awaiting-submission"` (sentinel; keeps `pubkey NOT NULL`). `Db::set_epoch_pubkey(gateway_id: i64, epoch: u32, pubkey: &str) -> Result<()>` (validates the row is `pending` + still sentinel; overwrites; bumps revision in-tx). Sync `SubmitEpochKey` handler: verify the caller's cert CN maps to `gateway_id`, call `set_epoch_pubkey`, then emit the (now real-keyed) `KeyRotated` delta.

- [ ] **Step 1 (test-author): failing test** — enroll a gateway; `Admin.RotateKey`; assert the new pending epoch's pubkey is `"awaiting-submission"` (via `debug_key_states`) AND that a peer's snapshot does NOT yet list the pending epoch (sentinel not advertised — needs Task 8's projection guard, so for THIS task assert only the DB sentinel + that `set_epoch_pubkey` overwrites it). Then call the gateway's `SubmitEpochKey(epoch, "REALKEY==")`, assert `debug_key_states` shows the real pubkey on that epoch, still `pending`.
- [ ] **Step 2: run — expect RED** (`rotate_key` still mints `placeholder-pubkey-…`; `set_epoch_pubkey`/`SubmitEpochKey` absent).
- [ ] **Step 3 (implementer): drop the placeholder** in `db.rs` `rotate_key` (`format!("placeholder-pubkey-gw{gateway_id}-epoch{new_epoch}")` → `"awaiting-submission".to_string()`); add `set_epoch_pubkey` (UPDATE gateway_key SET pubkey=?1 WHERE gateway_id=?2 AND epoch=?3 AND state='pending' AND pubkey='awaiting-submission'; error if 0 rows; bump_revision_tx). Expose via `db_async`. Add the `SubmitEpochKey` Sync handler (cert-CN check like `Report`'s `find_gateway_by_name`, then `set_epoch_pubkey`, then broadcast the real-keyed `KeyRotated`).
- [ ] **Step 4: run — expect GREEN** `./dev.sh run "cargo test -p wiremesh-controller --test epoch_key_submit -- --test-threads=1"`.
- [ ] **Step 5: full controller suite** `./dev.sh run "cargo test -p wiremesh-controller -- --test-threads=1"` — the existing `keys.rs` restart test must still pass (it asserts pending+active survive; the pubkey value changes from placeholder to sentinel — update that assertion in `keys.rs` to the sentinel, NOT a weakening).
- [ ] **Step 6: commit** `feat(controller): real epoch key via SubmitEpochKey (sentinel until submitted) (Task 2)`.

### Task 3: Controller — promote/retire state machine (ack-driven + grace)

**Files:**
- Create: `crates/wiremesh-controller/src/rotation.rs` (pure state machine, injectable `now`).
- Modify: `crates/wiremesh-controller/src/db.rs` (`promote_epoch`, `retire_epoch`, `keys_snapshot`, ack-tracking table or in-memory), `services/sync.rs` (consume `Report.epoch_acks` → feed the SM), `projection.rs`.
- Test: `crates/wiremesh-controller/tests/rotation.rs` (NEW) + unit tests in `rotation.rs`.

**Interfaces:**
- Consumes: `Report.epoch_acks` (Task 1); `Db::set_epoch_pubkey` (Task 2).
- Produces: `rotation::RotationSm` — pure logic: given a rotating gateway's peers, the set of acks received (per peer, per epoch), and `now`, decides `Promote(epoch)` / `Retire(old_epoch)` / `Wait` / `Abort(reason)`. Promote when a real-keyed pending epoch has a live ack from every currently-connected peer OR `GRACE_PROMOTE` (default 90s, `const`) elapsed with the epoch healthy; Retire the prior active epoch `RETIRE_GRACE` (default 30s) after promote. Abort (leave old active, drop pending) if no ack + `ABORT_AFTER` (default 300s). `Db::promote_epoch(gw,epoch)` (pending→active, prior active→retiring, one tx, bump revision), `Db::retire_epoch(gw,epoch)` (delete retiring row). `Db::keys_snapshot(gw) -> (Vec<PeerKey-ish>, revision)` under ONE lock.

- [ ] **Step 1 (test-author): unit tests in `rotation.rs`** — `promote_on_all_peers_ack` (2 peers ack epoch n+1 live → `Promote(n+1)`); `promote_on_grace_timeout` (no acks but `GRACE_PROMOTE` elapsed + healthy → `Promote`); `abort_when_no_ack` (`ABORT_AFTER` elapsed, no ack → `Abort`, old stays active); `retire_after_promote_grace`. Inject `Instant`s. AND an integration test in `tests/rotation.rs`: a StubGateway + 1 connected peer; RotateKey → SubmitEpochKey → the peer reports `epoch_acks=[{rotating_gw, n+1, live:true}]` → assert the controller promotes (a `KeyRotated` delta shows n+1 `active`, n `retiring` then absent).
- [ ] **Step 2: run — expect RED** (`rotation` module + `promote_epoch`/`retire_epoch`/`keys_snapshot` absent; `Report` ignores `epoch_acks`).
- [ ] **Step 3 (implementer): build `rotation::RotationSm`** (pure, the transitions above), `Db::promote_epoch`/`retire_epoch`/`keys_snapshot`, wire `Report`'s `epoch_acks` into a shared rotation-tracker on `SyncSvc` (a `tokio::sync::Mutex` held across the decide→DB-write→emit, mirroring the 4c `relay_health` TOCTOU fix), and emit `KeyRotated` deltas (candidate-preserving, atomic `keys_snapshot`) on each transition.
- [ ] **Step 4: run — expect GREEN** rotation unit + `tests/rotation.rs`.
- [ ] **Step 5: full controller suite** green.
- [ ] **Step 6: commit** `feat(controller): ack-driven promote/retire epoch state machine (Task 3)`.

### Task 4: Controller — 30-day rotation timer

**Files:** Modify `crates/wiremesh-controller/src/rotation.rs` (timer task), `Config` (interval), `lib.rs`/`serve` (spawn). Test: `tests/rotation.rs`.

**Interfaces:** Consumes `Db::rotate_key` (Task 2). Produces: a background task that, every `Config.rotation_interval` (default 30d), issues `RotateKey` for each `active` gateway NOT already mid-rotation (has a `pending`/`retiring` epoch). For tests, `Config.rotation_interval` is injectable (small).

- [ ] **Step 1 (test-author): failing test** — a `TestController` with `rotation_interval` set to ~1s; enroll 1 gateway; assert within a bounded wait a `pending` epoch appears (timer fired `RotateKey`); assert a gateway ALREADY mid-rotation is skipped (no second pending).
- [ ] **Step 2: run — expect RED** (no timer).
- [ ] **Step 3 (implementer): add the timer task** (spawned in `serve`; `tokio::time` interval; skip gateways with a non-active-only key set). Guard: injectable interval via `Config`.
- [ ] **Step 4: run — GREEN**; **Step 5: full controller suite**; **Step 6: commit** `feat(controller): 30-day rotation timer (Task 4)`.

### Task 5: Gateway — multi-epoch key store + state.json persistence

**Files:** Create `crates/wiremesh-gateway/src/epochkeys.rs`; modify `identity.rs` (epoch-0 migration), `state.rs`/persistence, `lib.rs` (module). Test: unit in `epochkeys.rs`.

**Interfaces:** Produces: `epochkeys::EpochKeys { epochs: Vec<EpochKey> }` where `EpochKey { epoch: u32, private_key_b64: String, pubkey_b64: String, state: String }`; `EpochKeys::generate_next(&mut self) -> &EpochKey` (X25519 via boringtun `StaticSecret`/`PublicKey`, next epoch = max+1, state `pending`); `load`/`persist` (0600 atomic, mirror `state.rs`); `EpochKeys::from_legacy(private_key_b64)` migrates 4a's single `wg_private_key_b64` into epoch-0 `active`. `active()`/`by_epoch()`/`promote(epoch)`/`retire(epoch)`.

- [ ] **Step 1 (test-author): unit tests** — `generate_next` yields a valid X25519 keypair (pubkey derivable from private), epoch = prior max+1, state pending; persist→load round-trips + file mode 0600; `from_legacy` produces one epoch-0 active entry whose pubkey matches the legacy key's derived pubkey; `promote`/`retire` transition states.
- [ ] **Step 2: run — expect RED** (`epochkeys` absent).
- [ ] **Step 3 (implementer): build `EpochKeys`** (reuse the `base64_pub_from_priv`/x25519 derivation already in `uapi.rs`; 0600 atomic write via `OpenOptionsExt`+rename like `state.rs`).
- [ ] **Step 4: GREEN** `./dev.sh run "cargo test -p wiremesh-gateway --lib epochkeys -- --test-threads=1"`.
- [ ] **Step 5: commit** `feat(gateway): multi-epoch key store + state.json persistence + epoch-0 migration (Task 5)`.

### Task 6: Gateway — EpochTunnel manager (two Devices; overlay IP on lo)

**Files:** Create `crates/wiremesh-gateway/src/tunnelset.rs`; modify `tunnel.rs`/`reconcile.rs`/`uapi.rs` as needed, `main.rs` (overlay IP → `lo`/dummy at boot). Test: unit + a focused netns bring-up-two-devices test (mirror `spike/keyrot`).

**Interfaces:** Consumes: `EpochKeys` (Task 5), the spike's proven mechanism (`spike/keyrot/src/main.rs`). Produces: `tunnelset::EpochTunnel` — holds a boringtun `Device` for one own-epoch (its key, a distinct UDP port, its own tun `wg-e<epoch>`); `TunnelSet` holds a map `epoch -> EpochTunnel`, `bring_up(epoch, key, port)`, `tear_down(epoch)`, `reconcile(epoch, peers)`. The overlay /32 lives on `lo`/dummy (moved off the tun) so both epoch tuns route to it — do this migration in `main.rs` boot (the spike keeps the overlay IP on `lo`). Ports: epoch e uses `base_wg_port + e` (documented; NAT path handled Task 8).

- [ ] **Step 1 (test-author): netns test** (`--features netns-tests`) porting the spike's two-Devices-one-gateway bring-up: stand up two `EpochTunnel`s (epochs 0 and 1, distinct ports/tuns) for one gateway with the overlay IP on `lo`; assert both devices report a live self-config (`wg show` on each tun) and the overlay IP is reachable via a route on either tun. + a unit test for `TunnelSet` map lifecycle (bring_up/tear_down).
- [ ] **Step 2: run — expect RED** (`tunnelset` absent).
- [ ] **Step 3 (implementer): build `TunnelSet`/`EpochTunnel`** graduating the spike's Device setup; move the overlay IP to `lo`/dummy at boot in `main.rs`; keep single-epoch behavior identical when only epoch-0 exists (4a mesh milestone must not regress).
- [ ] **Step 4: GREEN** (the netns bring-up test) + **Step 5: run 4a `mesh_milestone` + 4b `nat_matrix` + 4c `relay_matrix`** (`--features netns-tests`) to prove the overlay-IP-on-`lo` change didn't regress single-epoch. **Step 6: commit** `feat(gateway): EpochTunnel/TunnelSet — two Devices, overlay IP on lo (Task 6)`.

### Task 7: Gateway — peer multi-key handling (PeerState.keys + transient peer Device)

**Files:** Modify `crates/wiremesh-gateway/src/state.rs` (`PeerState.keys`), `reconcile.rs` (emit peer configs for pending epoch), `main.rs`. Test: unit in `state.rs`/`reconcile.rs`.

**Interfaces:** Consumes: `TunnelSet` (Task 6). Produces: `PeerState` retains `keys: Vec<PeerKey>` (drop the discard-all-but-active in `from_proto`); a helper `PeerState::pending_key()`/`active_key()`. `reconcile` emits, for a peer whose advertised key set has BOTH active + a real-keyed pending epoch, the config to stand up a transient second Device peering the rotating gateway's pending key (same allowed_ips) — mirroring the spike's peer side. When the peer returns to active-only, tear that transient Device down.

- [ ] **Step 1 (test-author): unit tests** — `PeerState::from_proto` now retains all `keys` (a peer with active+pending yields both); `reconcile` produces two peer-configs (active + pending) for a mid-rotation peer, one for an active-only peer; `pending_key()`/`active_key()` selectors.
- [ ] **Step 2: run — RED**.
- [ ] **Step 3 (implementer): retain `keys`** + the reconcile change + the transient-Device wiring (via `TunnelSet` on the peer side — a second Device for the rotating peer's pending key; note this is the PEER holding two of the ROTATING gateway's keys, per the spike).
- [ ] **Step 4: GREEN** (gateway `--lib`). **Step 5: 4a/4b/4c netns milestones green** (single-epoch peers unaffected). **Step 6: commit** `feat(gateway): PeerState multi-key + transient peer Device for pending epoch (Task 7)`.

### Task 8: Gateway — rotation driver (directive → mint → submit → path → cutover → ack) + projection guard

**Files:** Modify `crates/wiremesh-gateway/src/main.rs` (driver), `sync.rs` (`SubmitEpochKey` call + `epoch_acks` in Report), `crates/wiremesh-controller/src/projection.rs` (advertise only real-keyed epochs; preserve candidates). Test: driver unit (injectable) + the netns done-bar is Task 10.

**Interfaces:** Consumes: `RotateDirective`/`SubmitEpochKey`/`EpochAck` (Task 1), `EpochKeys` (5), `TunnelSet` (6), `PeerState.keys` (7), 4b path SM + `PunchDirective`/broker, 4c `RelayTransport`. Produces: on `RotateDirective(n+1)` → `EpochKeys::generate_next` → `TunnelSet::bring_up(n+1, key, base_port+n+1)` → `sync::submit_epoch_key(n+1, pubkey)`; the new port is driven through the EXISTING path SM (`run_path_ticks` treats the pending-epoch endpoint as a candidate — punch via broker / relay via `RelayTransport`); on a confirmed `Kb` handshake (real handshake + rx corroboration) → `ip route replace` the overlay onto the `wg-e<n+1>` tun → report `EpochAck{rotating_gw, n+1, live:true}`; on the controller retiring `n` (delta drops it) → `TunnelSet::tear_down(n)` + free the port. **Projection guard (controller):** `delta_for_change(KeyRotated)`/`build_snapshot` skip a `pending` epoch whose pubkey is still `"awaiting-submission"`, and MUST carry the peer's real `candidate_endpoints` (fix the current `Vec::new()` clobber at `projection.rs`).

- [ ] **Step 1 (test-author): injectable driver unit tests** — the rotation state on the gateway advances correctly given injected events (directive received → generates+brings up; handshake-confirmed → route-flip requested + ack emitted; retire delta → tear down). Assert the driver never route-flips before the `Kb` handshake is rx-corroborated (make-before-break). Do NOT netns here (Task 10). AND a controller unit test that `delta_for_change(KeyRotated)` preserves `candidate_endpoints` (not empty) and omits a sentinel-pubkey epoch.
- [ ] **Step 2: run — RED**.
- [ ] **Step 3 (implementer): wire the driver** (reusing `run_path_ticks`, the broker/punch, `RelayTransport`); the projection guard + candidate preservation.
- [ ] **Step 4: GREEN** (gateway `--lib` driver tests + controller projection test). **Step 5: 4a/4b/4c milestones + full controller suite green.** **Step 6: commit** `feat(gateway): rotation driver — directive/mint/submit/path/cutover/ack + projection guard (Task 8)`.

### Task 9: testkit — rotation-under-load conformance harness

**Files:** Modify `crates/wiremesh-testkit/src/lib.rs` (a `rotate_under_load` helper + topology helpers). Test: exercised by Task 10.

**Interfaces:** Produces: a testkit helper that, given a running netns mesh pair (direct OR symmetric/relay), starts a continuous ping flood (`ping -i 0.2` between the tun IPs), triggers `Admin.RotateKey` on one gateway, waits for the rotation to complete (new epoch active, old retired — observed via the gateway metrics/path-state + `debug_key_states`), stops the flood, and returns the packet-loss count + timing. Generalize `spike/keyrot`'s flood+assert into this reusable form; reuse the 4b symmetric-NAT cell + 4c relay spawn for the relayed topology.

- [ ] **Step 1 (test-author):** a smoke test in testkit that the `rotate_under_load` helper composes (compiles + drives a trivial no-op path) — or fold this task's proof directly into Task 10's cases (author decides; the helper is the deliverable).
- [ ] **Step 2-5: implementer builds the helper**; verified green as part of Task 10. **Commit** `feat(testkit): rotate-under-load conformance harness (direct + relay) (Task 9)`.

### Task 10: netns done-bar + docs

**Files:** Create `crates/wiremesh-gateway/tests/key_rotation.rs`; `docs/research/key-rotation-notes.md`; amend master §4.4 + CLAUDE.md.

**Interfaces:** Consumes: everything (Tasks 1-9) + the `rotate_under_load` helper.

- [ ] **Step 1 (test-author): the done-bar cases** (`--features netns-tests`, mandatory `tc netem`), from spec §2: (1) **direct rotation zero-drop** — directly-reachable pair, rotate under flood, assert ≤1-2 packet loss + old epoch retired + new active; (2) **relayed rotation zero-drop** — symmetric-NAT pair on the relay, rotate, new port establishes its relay path before cutover, assert ≤1-2 loss; (3) **non-destructive failure** — block the new session's handshake, assert old epoch stays active + zero drop + retry; (4) **crash-safety** — restart the controller mid-rotation (resumes from `gateway_key`) and the gateway (multi-epoch `state.json` survives). Right-reason guards throughout; no `#[ignore]`; run each ≥2× (flakiness gate).
- [ ] **Step 2: run — RED** (until the whole stack is wired).
- [ ] **Step 3 (implementer): make them pass** — iterate on any integration bug the netns surfaces (like 4c did); never weaken the tests.
- [ ] **Step 4: GREEN, run 2-3× for stability** + re-run 4a/4b/4c milestones + conformance 22/22 (no regression). **Step 5: docs** — `key-rotation-notes.md` (decisions, the §4.4 correction, measured drop, carries); amend master §4.4 to mechanism B; update CLAUDE.md project state. **Step 6: commit** `feat: key-rotation netns done-bar green + docs (Task 10)`.

## Done bar

Rotating a gateway's WG key under continuous traffic — **direct and relayed** — drops ~0 packets (≤ one handshake RTT), promotes the new epoch, and retires the old; a failed rotation is non-destructive; the state machine survives controller + gateway restarts. Cycle-3 conformance stays 22/22; 4a/4b/4c milestones unregressed.
