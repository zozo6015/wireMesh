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
