# Key rotation T2–T8 — plan verification against main, and the re-ordering it forced

**Date:** 2026-08-05. **Verified against:** `main` @ `6ec55dc` (includes PRs #43–#46).
**Why:** the B3 plan was ratified 2026-07-30 and re-verified once on the same day. Four
merges have landed since, three of them touching code this item depends on.

## THE HEADLINE: a deterministic fabric-wide outage is already shipped, on a timer

The plan files the `TunnelSet` epoch collision under "multi-peer overlap … concurrent
rotations untested". **It is not untested. It is broken, and the default configuration
triggers it.**

`initiate_due_rotations` (`services/sync.rs:640-688`) walks `db.active_gateway_ids()` —
**every active gateway, no per-gateway key-age filter** — and rotates each one that is not
already mid-rotation. It is driven by a single global `tokio::time::interval`
(`lib.rs:702`) whose default is **30 days** (`lib.rs:204-206`). So every gateway in the
fabric rotates in the same tick, N → N+1, in step.

Then, on each gateway, the two roles collide on **three axes at once**:

| | Role A (own new tun) | Role B (overlap toward the peer) |
|---|---|---|
| `TunnelSet` key | `n` (`main.rs:3692`) | `pending_epoch` (`main.rs:3794`) |
| ifname | `format!("{base}e{n}")` (`main.rs:3690`) | `format!("{base}e{pending_epoch}")` (`main.rs:3772`) |
| listen port | `base + (n - active)` (`:3688`) | `base + (pending - peer.active)` (`:3770`) |

`TunnelSet::bring_up` bails on a duplicate key (`tunnelset.rs:51-53`), and the `?` at
`main.rs:3794` sits inside `for peer in &ds.peers` (`:3760`) — so the first collision
**aborts the whole peer loop**, skipping every later peer, on every `State` event. The
caller only logs (`main.rs:985`).

Result: neither side forms an overlap, neither ever acks, neither Role A sees `any_live`,
so neither flips routes — while the controller grace-promotes at 90s and retires at 120s
regardless (rule 4, see §E of `key-rotation-teardown-notes.md`). **Both gateways of every
pair. First timer fire.**

### Jitter is NOT a mitigation (correcting the verification's own recommendation)

The verification proposed jittering the timer as a cheap immediate fix. It does not work,
because the collision is not fundamentally about *simultaneity* — it is that `TunnelSet` is
keyed by a bare epoch number that means **different things** for own-tuns and overlap-tuns.
Role A keys by *its own* epoch; Role B keys by the *peer's pending* epoch. Once the fabric
is in step, A sitting at active epoch 1 and B later rotating to pending epoch 1 makes A's
Role-B `bring_up(1, "wg0e1", base+1)` collide with **A's own active tun**. Staggering only
moves when it happens.

There is also **no config stopgap**: `rotation_interval` is hardcoded at `main.rs:77` and
not env-configurable. Restarting the controller resets the timer; that is the only
zero-code lever.

**Owner decision 2026-08-05: fix T3 properly, next.**

## The re-ordering

The plan's spine (T2 → T3 → T4 → T5) is wrong in one place and mis-sized in two.

T2's central deliverable is a *real-keyed abort*, which makes abort reachable **after** the
pending key has been fanned out to peers — the only case where Role-B overlaps exist. And
there is **no Role-B abort path at all** (new finding **F9**, below). So T2-before-T3 ships
a mechanism that aborts more often onto an implementation that leaks on every abort, on a
fabric where the collision guarantees zero acks.

Revised order:

1. **T3 first (L).** Three-axis de-collision, plus the Role-B abort/removal teardown (F9),
   plus F8's active-tun awareness, plus the `contains_key` re-rotation guard. The item's
   real blocker; everything else depends on it.
2. **T0 (S), a shared precursor** — the `PathCtx` → rotation-overlap handle. **Three
   independent verifications have now found this missing** (this item's T4, the proto
   block's cutover hard-skip, the relay mux's channels). One `Arc` field plus an accessor.
   Build once, outside all three.
3. **T2 (M→L).** Gateway `RotateAbort` transition and wire signal, the OD-4 threshold, ack
   re-delivery. Owns **case 3** as its red-first test. F2 belongs here.
4. **T4 (L).** Unchanged in shape. Consumes T0.
5. **T5 (S, was M).** Case 3 moved to T2, so this is the controller-restart half of case 4
   plus regression. Gate on the flake characterisation.
6. **T6 / T7 parallel.** T6 still gated behind the relay mux (item 3b, deferred). T7 picks
   up the testkit helper fix.
7. **T8 (S) anytime.** F4 fits here.

## OD-4 is a three-part task, not a predicate change

§E confirmed verbatim: `rotation.rs:104-106`, rule 4 promotes on `GRACE_PROMOTE` with no
ack predicate; rule 2 (`:70-79`) is the only abort path. `promote_epoch`
(`db.rs:1940-1958`) refuses a sentinel, so the promoted dead key is always a *real* one —
which is the point.

Rule 4 must stay in some form (it exists so an offline peer cannot block a rotation
forever), but OD-4 as written breaks four ways:

- **Acks are one-shot.** `main.rs:4296-4300` sets `done = true`; `:4275` filters `!b.done`.
  A **controller restart** rebuilds the tracker empty (`sync.rs:412`, `:574`, `:1223`) with
  a fresh `started_at`, and no peer ever re-acks — so a rotation that already succeeded on
  the data plane would abort 90s later.
- **F3 blocks acking entirely**, so on any affected fabric *every* rotation would abort.
- **Empty peer set** — a single-connected-gateway fabric could never rotate. Keep §E's
  `!expected_peers.is_empty()` conjunct; it is load-bearing.
- **PR #45 can reject the ack** (below) — transient, but now a veto input rather than an
  accelerator.

Threshold should be three-tier: `live_acks ≥ 1` → promote at 90s; zero acks with no
expected peers → promote at 90s; zero acks *with* expected peers → wait to a second,
longer deadline and then **Abort**, not promote. `ABORT_AFTER` (300s) is a defensible reuse.

**Prerequisites the plan does not budget:** ack re-delivery (periodic re-ack beats
persisting `live_acks` — no hot-path DB writes, no schema change, and it subsumes PR #45's
residual), and a **gateway-side abort**, which does not exist: `Rotation`
(`gateway/src/rotation.rs:61-95`) has no abort transition and `Overlapping` is terminal
until cutover, so a controller abort is invisible to Role A, which keeps kicking
`kick_overlap` forever (`main.rs:4226`) and refuses every future directive. T2 needs a wire
signal — `SyncMessage` oneof **field 5 is free**, just vacated when the proto block dropped
`CutoverProbe`. Coordinate before either claims it.

## F2/F3/F4/F8, re-graded — plus new F9

- **F2 — STILL OPEN, worse than recorded.** Traced end-to-end: directive epoch 1 → gateway
  mints 1, crashes → `send_rotate_if_pending` (`broker.rs:482-490`) re-issues
  `RotateDirective(1)` → the new process mints **epoch 2** (`epochkeys.rs:79`) but proceeds
  "on the directive epoch" (`main.rs:3680-3692`), bringing up `wg0e1` with the epoch-2 key
  and submitting it as epoch 1. Wire is self-consistent; **the store is not**. Cutover then
  promotes the *stale* epoch-1 entry (`main.rs:4198`), and `select_boot_key` boots a dead
  key. A guaranteed durable wedge on any crash-then-re-directive path. Make the epoch
  mismatch a hard error, or fix the mint to honour the directive epoch.
- **F3 — STILL OPEN, materially worse.** The three-axis collision above. Not scoped to the
  colliding peer: the `?` aborts the whole loop.
- **F4 — STILL OPEN, unchanged.** No boot-time scrub; a crash inside the retire grace
  leaves a `"retiring"` entry with its private key in `epoch_keys.json` permanently. Note
  the asymmetry: the **controller** grew exactly this cleanup (`sweep_rotations` step 3,
  `sync.rs:582-600`); the gateway did not. F4 is "mirror what the controller already does".
- **F8 — STILL OPEN**, and now a sub-case of F3 (both are "the overlap machinery assumes
  one tun namespace"), so fix together.
- **F9 — NEW: the abort path leaks Role-B state.** `maybe_collapse_role_b` only arms when
  the peer's active key **equals** the key we overlapped toward (`main.rs:3902-3906`). On an
  abort the peer's pending row is deleted and its active key is unchanged, so the predicate
  never matches: the overlap Device, its enforcer entry, its routes and its `wg0_pins`
  entry leak forever, the tick kicks a dead key every tick, and `contains_key`
  (`main.rs:3765`) blocks that peer from ever being overlapped again. **Not live today**
  only because abort is reachable solely via rule 2's no-real-key branch. **OD-4 makes it
  live.** T2 exit criterion.

## T3's premise — confirmed, one reference drifted

`contains_key` re-rotation skip is now `main.rs:3765` (was cited 2735). `wg0_pins` is
**RESHAPED**: it *is* cleared, at exactly one site (`main.rs:3908`, the T1 collapse slice).
Two leak paths remain — peer removed from the roster mid-overlap
(`main.rs:3894-3898`), and abort (F9). Re-grade from "never cleared" to "cleared only on
the happy collapse path".

## Interaction with today's merges

- **PR #43 vs T4 — holds structurally.** Only the *enforcer* half moved off the loop; the
  device path is still inline and `.await?`-fatal (`main.rs:932`). T4's three sites are now
  `main.rs:2225` / `3287` / `4152`. New: `apply_state` has an incremental `PureAdditions`
  path with a `device_header` compare (`:3304-3332`) — the offset builder must feed **both**
  it and the full path, or they diverge. Two facts for test authors: a rotation insert arms
  a fresh grace so the next policy install legitimately errors and bumps
  `policy_apply_failures_total` (a test asserting zero failures across a rotation would
  assert a falsehood); and ordering is now device → routes → policy(async), so
  `policy_tighten_after_rotation_reaches_active_tun` (`key_rotation.rs:812`) depends on a
  grace plus possible backoff rather than a synchronous apply.
- **PR #45 vs T2 — the residual is real, and OD-4 upgrades its severity.** Today a rejected
  ack is retried (`main.rs:4313` leaves `done = false`) and worst case falls back to rule 4.
  Under OD-4 the same rejection is a step toward *aborting*. **Do not carve `epoch_acks` out
  of the gate** — a stale-process ack is exactly as wrong as stale `peer_paths`. Give T2 the
  ack re-delivery it needs anyway; that subsumes the residual.
- **PR #45's `send_epoch_ack` fix — nothing in T2–T7 assumed the old shape, but the testkit
  still has it.** `StubGateway::report_epoch_acks` (`testkit/src/lib.rs:1245`) still sends
  `local_endpoints: vec![]`, i.e. the exact destructive shape fixed in the binary. Any
  controller-level rotation test acking through the stub will silently wipe that stub's
  candidates and publish the shrunk set. Fix in T7 before any rotation test relies on it.
  Also: `send_epoch_ack` reports `local_wg_endpoints(rot.base_wg_port)` and the observe loop
  captures `cfg.wg_listen_port` at boot — both **base-port-blind after a Role-A cutover**.
  That is the surviving form of finding B; the punch half is obsolete (the transient
  `SO_REUSEPORT` puncher was deleted), the candidate-advertisement half is T4's.
- **PR #46 vs T6 — the gate holds.** 3a is relay-side; the OD-3 gap is gateway-side and
  unchanged (`ensure_relay_transport` seeds from the **active** epoch, `main.rs:2413`), so a
  relayed peer's pending-epoch tun has no relay path during overlap. T6 stays last. New
  coupling: 3a is a lockstep upgrade, so T6's netns case needs all three components in step.

## T5's cases — case 3 belongs to T2

Existing (`tests/key_rotation.rs`, 5 tests, none ignored): case 1 is
`direct_rotation_is_zero_drop:432`; `rotation_survives_gateway_restart_on_new_epoch:1408`
is **half of case 4** (gateway restart; controller-restart half missing, though
`TestController::restart` exists and `rotation_timer.rs:154-161` already uses it).
**Case 3 is MISSING** — and it is the arbiter for §E/OD-4, not a T5 deliverable: "old epoch
stays active" is exactly what rule 4 violates. Written today it is RED for the right
reason. **Move it to T2 as its red-first test.**

The flake (`flake-direct-rotation-zero-drop.md`) sits at gap 2–3 of an allowed 3, and its
own conclusion is that full-suite load moves the number. Adding two netns-heavy cases to the
same serial file will push the margin to zero. Characterise before T5 — do **not** widen the
tolerance.

## Scope honesty — the residual is bigger than recorded

The epoch-0 private key survives in **two** files, not one: `state_dir/wg_private.key`
(`identity.rs:93`) and `identity.json`, which serializes `wg_private_key_b64`
(`identity.rs:22`, written at `:95`). Neither is rewritten after enrollment; the retire
scrub only touches `epoch_keys.json`.

So "forward secrecy on rotation" is true for live Devices and `epoch_keys.json`, and **false
on disk**. And the legacy fallback is load-bearing — `select_boot_key` (`epochkeys.rs:172-187`)
branch 2 needs the identity key, and `from_legacy` needs it on first rotation-aware boot —
so it cannot simply be deleted. **Do not attempt the full scrub in T2–T7**: close F4, state
the residual in release notes and in `select_boot_key`'s doc, and file identity-key
retirement separately, because it requires deciding what "the gateway's durable identity
key" means once rotation is real.

One residual closes for free: the controller's rule-4 promote is not reconciled into the
local store (`epochkeys.rs:164-171`), so a promoted-but-never-cut-over rotation boots the old
key. If a zero-ack rotation **aborts** instead of promoting, the divergence stops being
produced.

## Open owner decisions

| # | Decision | Recommendation |
|---|---|---|
| A | OD-4's `NO_ACK_ABORT` value | Reuse `ABORT_AFTER` (300s). Abort, not promote, and only when `!expected_peers.is_empty()` |
| B | Ack survival across controller restart | **Periodic re-ack**, not persisted `live_acks`. OD-4 cannot ship without one |
| C | Claim `SyncMessage` field 5 for `RotateAbort`? | Yes — just freed by the proto block. Confirm before either writes it |
| D | Jitter `initiate_due_rotations`? | **No** — see above, it does not mitigate. Fix the keying |
| E | T3's naming/port scheme within the 15-byte `validate_iface` budget | Needed before T3 starts. `wg0e{n}` is not extensible |
| F | The shared `PathCtx` rotation-overlap handle | **Standalone precursor PR.** Closes relay-mux decision I and proto-block decision 5 |
| G | The flake: characterise, or split the suite? | Characterise. Do not widen the tolerance |
| H | `StubGateway::report_epoch_acks`'s destructive empty `local_endpoints` | Fix in T7 before any rotation test depends on it |
