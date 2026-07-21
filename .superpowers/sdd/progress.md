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
- [ ] Task 5: gateway — multi-epoch key store + state.json persistence
- [ ] Task 6: gateway — EpochTunnel/TunnelSet (two Devices, overlay IP on lo)
- [ ] Task 7: gateway — PeerState multi-key + transient peer Device
- [ ] Task 8: gateway — rotation driver + projection guard
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
