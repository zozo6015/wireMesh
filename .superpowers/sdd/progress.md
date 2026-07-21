# Key-Rotation — subagent-driven progress ledger

Plan: docs/superpowers/plans/2026-07-21-key-rotation.md
Spec: docs/superpowers/specs/2026-07-21-key-rotation-design.md
Branch: worktree-key-rotation (off main 162ef70)
Baseline: 50fa06d (plan committed)

## Tasks
- [ ] Task 1: proto — RotateDirective + SubmitEpochKey + Report.epoch_acks
- [ ] Task 2: controller — real epoch key via SubmitEpochKey (sentinel)
- [ ] Task 3: controller — ack-driven promote/retire state machine
- [ ] Task 4: controller — 30-day rotation timer
- [ ] Task 5: gateway — multi-epoch key store + state.json persistence
- [ ] Task 6: gateway — EpochTunnel/TunnelSet (two Devices, overlay IP on lo)
- [ ] Task 7: gateway — PeerState multi-key + transient peer Device
- [ ] Task 8: gateway — rotation driver + projection guard
- [ ] Task 9: testkit — rotate-under-load harness
- [ ] Task 10: netns done-bar + docs

## Log
(baseline 50fa06d — build starting)
