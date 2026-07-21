# Key-Rotation — subagent-driven progress ledger

Plan: docs/superpowers/plans/2026-07-21-key-rotation.md
Spec: docs/superpowers/specs/2026-07-21-key-rotation-design.md
Branch: worktree-key-rotation (off main 162ef70)
Baseline: 50fa06d (plan committed)

## Tasks
- [x] Task 1: proto — RotateDirective + SubmitEpochKey + Report.epoch_acks
- [x] Task 2: controller — real epoch key via SubmitEpochKey (sentinel)
- [x] Task 3: controller — ack-driven promote/retire state machine
- [x] Task 4: controller — 30-day rotation timer
- [x] Task 5: gateway — multi-epoch key store + state.json persistence
- [x] Task 6: gateway — EpochTunnel/TunnelSet (two Devices, overlay IP on lo)
- [x] Task 7: gateway — PeerState multi-key + transient peer Device
- [x] Task 8: gateway — rotation driver + projection guard
- [ ] Task 9: testkit — rotate-under-load harness
- [ ] Task 10: netns done-bar + docs

## Log
(baseline 50fa06d — build starting)

Task 1: complete (commits 2d406c8..cec0268, review clean — proto surface + ripple, 11/11 proto tests, workspace builds)
Task 2: complete (commits 975e88c..3bdb549, review clean — sentinel + SubmitEpochKey, cert-derived identity, atomic revision, DRY emit_key_rotated; epoch_key_submit 2/2, full controller suite green)
Task 3: complete (commit 68261d6 tests + this task's implementation commit — pure rotation::decide (5 ordered rules), Db::promote_epoch/retire_epoch/drop_pending_epoch/keys_snapshot, SyncSvc lazy-rebuild rotation tracker + drive_rotation wired into report's epoch_acks and submit_epoch_key, Broker::connected_gateway_ids, StubGateway::report_epoch_acks; rotation unit 8/8, rotation integration 1/1, full controller suite green, workspace builds)
Task 3: complete (commits 68261d6..53cadd8, review clean — pure decide SM 8/8, ack-driven promote integration 1/1, full controller suite green). CARRY→Task4: timer sweep must also retire orphaned `retiring` rows (crash in 30s promote-retire window has no pending row to rebuild a tracker) + fire grace/abort timeouts.
Task 4: complete (commits 593c63b..a72b4cf, review clean — timer + sweep; make-before-break & concurrency sound; rotation_timer 3/3, full controller suite green).
  Minor carries for final whole-branch review:
   - M1: sweep step-2 lazy-insert is redundant (drive_rotation_for rebuilds the tracker itself) — dead code, delete.
   - M2: orphaned-retiring check is per-gateway not per-epoch; a manual RotateKey racing into the crash window can leak the old retiring row (safe side: old key kept too long). Per-epoch tracker match closes it.
   - M3: initiate_due_rotations two-read TOCTOU (gateways_with_rotation_state + active_gateway_ids not atomic); negligible at 30d cadence.
   - M4: nit — RFC3339 format-err uses return (aborts tick) vs continue; all_keys_for_gateway read up to 3x/gateway/sweep.
Task 5: complete (commits 26253f5..0e7beb0, review found 1 CRITICAL — persist 0600 not enforced on pre-existing tmp inode (private-key file) — FIXED with unconditional chmod mirroring identity.rs::write_0600 + RED→GREEN regression test; epochkeys 7/7, gateway lib green, workspace builds).
Task 6: complete (commits e3fe666..46f8dc6, review clean — additive TunnelSet (no main.rs/overlay change; integration deferred to Task 8); tunnelset_netns 1/1, tunnel_netns non-regression 1/1, unit 1/1, build).
  FINDING (documented, ratified divergence): boringtun 0.6.0 UAPI get=1 reports own key as `own_public_key=<hex>` (non-standard) → real `wg show` can't display a boringtun device's own pubkey. See docs/research/keyrot-task6-uapi-pubkey-note.md. Test verifies self-pubkey via raw UAPI instead.
  Minor carry→Task8: bring_up leaks the tun if uapi::apply fails after Tunnel::up (no cleanup/insert); matters for rotation-retry. (mirrors pre-existing Tunnel::up gap.)
Task 7: complete (commits 7358aa2..a353b9a, review clean — PeerState.keys + active_key/pending_key (sentinel-skip) + pending_peer_configs with relative port offset (ep-ea), checked/panic-free; active_pubkey_b64 non-regression; gateway lib 68/68, netns-tests build compiles).
Task 8a (controller projection guard): complete (commits fa29d92..94f843a, review clean — sentinel-pending withheld at all 4 advertised-key sites (KeyRotated/EndpointObserved/SegmentCidrsChanged deltas + build_snapshot); KeyRotated preserves candidate_endpoints; keys.rs updated to new behavior per owner decision; projection_guard 2/2, full controller suite green).
  Minor carries→final review: no dedicated build_snapshot sentinel test (verified by reading); raw "awaiting-submission" literals in set_epoch_pubkey/promote_epoch/sync.rs:289 could use AWAITING_SUBMISSION_SENTINEL const.
Task 8b (gateway rotation SM + SyncEvent::Rotate): complete (commits 416824a..9664f48, review clean — pure Rotation SM, make-before-break STRUCTURALLY guaranteed (FlipRoutes only on rx_corroborated; no TearDown while Overlapping); SyncEvent::Rotate wired into classify; main.rs has a log-only placeholder arm (full I/O deferred to netns-integration). gateway lib 76/76.)
  Minor carry→T9/10: on_epoch_retired doesn't cross-check epoch vs tracked new_epoch — the integration caller must pass the correct OLD epoch.
Task 8 COMPLETE (8a controller projection guard + 8b gateway rotation SM). 8/10.
=== REMAINING: T9 (rotate-under-load testkit harness) + T10 (netns done-bar + wire the rotation SM into the live main loop). This is the netns integration — bring up 2nd Device, submit, path-liveness on new epoch, route-flip cutover, EpochAck reporting, tear down — proven by the 4 done-bar cases under tc netem. Expect real integration bugs (like 4b/4c). ===

=== Task 9/10 CASE 1 (direct rotation zero-drop) — GREEN (commit b41daa5, opus review) ===
Wired the full make-before-break choreography into the live gateway (Role A rotating + Role B peer), minimal epoch-aware boot refactor, controller broker now emits RotateDirective on sentinel-pending. TWO real bugs found+fixed (not test edits): (1) boringtun won't self-initiate the overlap handshake from keepalive → out-of-band probe; (2) ZERO-DROP KILLER: replace_peers rebuilt a fresh Tunn on every redundant apply → apply_wg0_if_changed change-guard (errs safe — encode_set injective, never skips a needed apply). Make-before-break STRUCTURALLY correct (flip only on rx-corroborated wg0e1 handshake). Done-bar: tx=11/rx=9 gap 2≤3. NON-REGRESSION ALL GREEN: gateway lib 76/76, full controller suite, mesh_milestone, nat_matrix 4/4, relay_matrix 2/2.

REQUIRED REMAINING WORK (feature NOT complete — case 1 of 4 + these):
  *** SECURITY (must-fix-before-ship) ***: enforcer NOT attached to wg0e<N> → post-rotation traffic UNFILTERED (default-deny bypass). Needs: attach enforcer to the new tun at bring-up + a conformance test that crosses a rotation with a DENY rule (case-1's allow-all-ICMP masks it).
  - Old-epoch Device teardown: wire on_epoch_retired(E) (pass the correct OLD epoch — Task-8b Minor) + TunnelSet::tear_down, so old key material is actually retired. Currently wg0 stays up forever.
  - Rotation failure recovery: handle_rotate moves SM to Overlapping before fallible work; a transient failure wedges rotation until process restart (no reset-to-Idle/abort path).
  - Remaining done-bar cases: 2 (relayed zero-drop), 3 (non-destructive failure), 4 (crash-safety). + testkit rotate-under-load harness (T9). + Role B multi-peer overlap.
  - Minors: send_epoch_ack per-tick mTLS connection churn (add backoff); set_rp_filter_loose global host change every boot; sentinel-literal→const cleanup.

=== SECURITY FIX DONE: enforcer-on-new-tun (commits 1fd0468 test, ade8742 fix, 193b019 fail-closed hardening) ===
The #1 must-fix is CLOSED. GatewayEnforcer now attached (with current policy) to each rotation tun (Role A wg0e<N> + Role B overlap tun) — attached BEFORE the peer-configuring uapi::apply, so a failed attach leaves a peer-less/session-incapable tun = FAIL-CLOSED, + teardown-on-error. New test `denied_flow_stays_denied_across_rotation` proves a DENY (tcp/9090) stays denied across a rotation (was leaking = default-deny bypass). Runner: security test PASS (tcp/9090 denied pre+post), zero-drop PASS (13/11 gap 2), lib 76/76, mesh_milestone PASS. opus review: SPEC ✅ no-window; hardening review: fail-closed ✅. Also fixed a pre-existing sync_client.rs report-arity + SyncEvent::Rotate ripple.

REMAINING (updated):
  - [DONE] enforcer-on-new-tun security fix (+ fail-closed hardening).
  - Old-epoch Device teardown (Rotation::TearDown arm still unused; wg0 stays up; also M-2: rotation_enforcers map never evicts — tie eviction to tear_down).
  - Rotation failure-recovery (transient error wedges SM in Overlapping — but note: handle_rotate NOW tears down the tun on enforcer-attach error; the SM-wedge on OTHER failures still stands).
  - NEW security-relevant follow-up (from enforcer review): policy UPDATES arriving mid-rotation only reach wg0's enforcer, NOT the overlap/new tun's — a policy TIGHTENING (new deny) during an overlap wouldn't reach the overlap tun until teardown. Track in the epoch-aware apply_state work (deny stays denied under a STABLE policy is proven; a mid-overlap tighten is the gap).
  - Done-bar cases 2 (relay zero-drop), 3 (non-destructive failure), 4 (crash-safety) + generalized rotate-under-load harness + Role-B multi-peer overlap.
  - Minors: zero-drop tolerance (gap≤3) fully consumed on short floods — watch; send_epoch_ack per-tick mTLS churn; set_rp_filter_loose global; sentinel→const cleanup.

=== OLD-EPOCH TEARDOWN — ARCHITECTURAL FINDING (investigated, NOT yet implemented) ===
Teardown is NOT a small wire-up — it is entangled with an epoch-aware data-plane refactor. Why:
- The case-1 wiring keeps the CONTROL plane on wg0: apply_state (main.rs:1188) applies WG PEERS + the ENFORCER always to boot's `tunnel`/`enforcer` (wg0); only ROUTES follow `active_tun` (wg0e<N> after cutover). Doc at main.rs:1184-1187 states this explicitly.
- So after cutover, traffic is on wg0e<N> (with its bring-up-time peers+enforcer) but peer/policy UPDATES still land on wg0. Tearing down wg0 → the next SyncEvent::State's `apply_state(...).await?` hits a dead device → Err → the run loop's `?` exits the process (4a fail-closed-on-apply-error). So teardown WITHOUT the refactor crashes the gateway on the next policy/peer change.
- Safe teardown REQUIRES apply_state to apply peers+enforcer to the ACTIVE epoch's Device+enforcer. That needs: (a) unify epoch-0's Device into TunnelSet (case-1 kept it as a separate `tunnel` to minimize regression) so `tunnels.get(active_epoch)` is uniform; (b) unify epoch-0's enforcer with rotation_enforcers — BUT the boot enforcer is Arc<Mutex> shared with the METRICS task (counters), while rotation_enforcers are plain non-Arc in the run task → non-trivial (metrics/enforcer sharing surgery); (c) apply_state selects the active Device+enforcer.
- This refactor ALSO closes the reviewer's "policy-updates-mid-rotation / post-cutover don't reach the active tun" security-relevant gap (bonus).
- The RETIRE SIGNAL itself needs NO proto change / controller signal: Role A can retire LOCALLY once every peer's session on the new tun (wg0e<N>) is rx-corroborated live for a keepalive grace (all peers have cut over → no peer needs the old key) → fire Rotation::on_epoch_retired(old_epoch) → TearDown → tunnels.tear_down(old) + rotation_enforcers.remove(old_tun). The pure SM + TearDown arm are already built (Task 8b).
CONCLUSION: teardown = the epoch-aware data-plane refactor (a+b+c above) + the local-liveness retire trigger + a done-bar assertion (wg0 gone after retire AND a policy-tighten post-cutover reaches the active tun). This is ~case-1 scale and architecturally invasive (touches the core apply path mesh/nat/relay depend on) → deserves a focused session with full non-regression, NOT a rushed end-of-session attempt. NEXT-SESSION TASK.
