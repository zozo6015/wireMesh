# Key-Rotation — subagent-driven progress ledger

Plan: docs/superpowers/plans/2026-07-21-key-rotation.md
Spec: docs/superpowers/specs/2026-07-21-key-rotation-design.md
Branch: worktree-key-rotation (off main 162ef70)
Baseline: 50fa06d (plan committed)

## Tasks
- [x] Task 1: proto — RotateDirective + SubmitEpochKey + Report.epoch_acks
- [x] Task 2: controller — real epoch key via SubmitEpochKey (sentinel)
- [x] Task 3: controller — ack-driven promote/retire state machine
- [ ] Task 4: controller — 30-day rotation timer
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
