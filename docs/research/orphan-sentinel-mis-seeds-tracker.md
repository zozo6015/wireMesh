# An orphan sentinel row mis-seeds the rotation tracker

**Date:** 2026-08-26 · **Found by:** PR1's `rotation_wedge` done-bar, post-PR1b
**Status:** mechanism established; fix ruled (design Rev 1.42/1.42a); shipped in PR1c
**Evidence:** two deterministic `rotation_wedge` runs at `2372b18`, byte-identical

---

## Summary

A gateway-side rotation abort leaves an orphan `pending` row holding the
`awaiting-submission` sentinel. The controller does not know the rotation was abandoned, so
the row survives until its abort deadline. A second rotation started inside that window
creates a **second** `pending` row — and every tracker-seed site selected the pending row with
`.find(state == "pending")` over a snapshot ordered `epoch ASC`, i.e. **the orphan**.

The tracker therefore describes a rotation nobody is running. The live rotation's `EpochAck`
names a different epoch and is silently discarded; the live rotation's real key is never
examined, because `rotation::decide` only ever looks at `tracker.pending_epoch`.

**The rotation is not wedged — it is roughly 390 seconds late**, against a 120-second done-bar.
That distinction matters: a wedge needs a mechanism, a 390s stall needs only arithmetic, and
the two call for different fixes.

This is the **tracker** selector. `broker.rs::send_rotate_if_pending`'s **directive** selector
was a different `.find()` on the same row set, fixed one PR earlier (v0.10.4). Two selectors,
one row set, two bugs — see "Why this was not caught by the previous fix".

---

## What was measured

Both runs produced the identical end state:

```text
debug_key_states: [(0, <real>, "active"),
                   (1, "awaiting-submission", "pending"),
                   (2, <real>, "pending")]
```

* row 0 — the original key, still `active` **in the controller**
* row 1 — the orphan sentinel from the aborted rotation
* row 2 — the live rotation, real key submitted, stuck `pending`

Also measured, in both runs:

* `sent RotateDirective(epoch=1)` then `sent RotateDirective(epoch=2)` — the directive selector
  is correct; the gateway built epoch 2 and only epoch 2.
* `epoch ack sent` appears **exactly once**. Role B acks a rotation one time.
* **Zero** controller output mentioning tracker seeding — the whole area is unlogged.
* `retired epoch 0 — old Device torn down (key gone)` on the rotating gateway, while the
  controller's rows still show epoch 0 `active`.

---

## Mechanism

1. **Seed.** All three tracker-seed sites — `drive_rotation_for`, `sweep_rotations` step 2, and
   `seed_and_record_epoch_acks` — selected the pending row with `.find(state == "pending")`.
   `Db::all_keys_for_gateway` orders `epoch ASC`, so `.find` returns the **lowest** pending
   epoch: the orphan. The tracker is seeded `pending_epoch = 1`.
2. **The ack is eaten.** `seed_and_record_epoch_acks`'s record pass tests
   `ack.epoch == tracker.pending_epoch`. The live ack names 2, the tracker says 1, so the ack is
   dropped — with no `else`, no log, and no counter.
3. **The ack never comes back.** Role B sends one `EpochAck` per rotation from its cutover pass
   and then marks the entry `done`, which (per its own comment) *"permanently filters an entry
   out of `pending_b`"*. There is no re-ack path, and the steady-state report carries no
   `epoch_acks`. **The dropped ack is gone for good.**
4. **`decide` is never asked about the live epoch.** `pending_has_real_key` is computed only for
   `tracker.pending_epoch`. For the sentinel it is false, so `decide` rule 2 returns early —
   **rules 3 and 4 are unreachable, and the 90s grace promote never runs.** The tracker waits on
   `ABORT_AFTER`, not `GRACE_PROMOTE`. (This was mis-stated as a grace-promote path during
   triage; the constant that governs is the abort deadline.)
5. **Eventually it self-heals.** At `ABORT_AFTER` the tracker aborts, `Db::drop_pending_epoch`
   removes row 1 only, the tracker is dropped, the next drive re-seeds on row 2 — which has a
   real key — and rule 4's grace promotes it 90s later.

```text
t0        rotation 1 initiated; tracker seeded on epoch 1
t0+…      rotation 2 initiated; epoch 2 built, real key submitted; ack sent and DROPPED
t0+300s   ABORT_AFTER  -> Abort{1} -> row 1 dropped -> tracker removed
t0+300s   re-seed on epoch 2 (real key), started_at = now
t0+390s   GRACE_PROMOTE -> Promote{2}
```

**≈390s, measured from rotation 1's start** — because `ABORT_AFTER` runs off the stale tracker's
`started_at`, not off the live rotation. The done-bar polls 120s and would fail at any budget
under ~400s.

**The obvious response — widen the timeout — would have passed a broken system, and this is the
most transferable thing in this note.** At a budget above ~400s the *unfixed* code goes green:
the orphan aborts, the tracker re-seeds on the live epoch, and rule 4 promotes it **with zero
acks** via the recorded KNOWN HAZARD §E grace path. The rotation would then "succeed" onto a key
whose liveness nothing ever confirmed, the dropped ack would remain dropped, and the orphan-row
mis-seed would still be there waiting for the next abort. **The 120s budget was load-bearing by
accident**: it was short enough to expose a defect that a more generous one would have
concealed. Treat "the test just needs more time" as a hypothesis to disprove, not a fix.

---

## A second consequence: the fabric advertises a key the gateway has destroyed

The rotating gateway retires its old epoch on its **own** grace — every peer live on the new tun
for `RETIRE_GRACE` — which is independent of the controller's promote. Both runs show the
gateway logging `retired epoch 0 … (key gone)` while the controller still holds epoch 0
`active`.

For the whole stall window the roster advertises an epoch whose private key no longer exists on
that gateway. It did not break the test, because the only peer had already cut over. **The
exposure is a peer that has not**: anything enrolling, reconnecting, or re-reading the roster
inside the window receives an unusable key.

This is a data-plane consequence of what presents as a bookkeeping delay. The fix shortens the
window to approximately zero, but **nothing pins that it stays short**, and no assertion covers
it today. Filed as its own backlog item (Phase C) rather than fixed here: the exposure is real
but the remedy — coupling the two retire clocks, or refusing to advertise an epoch whose holder
has retired it — is a design question, not a selector change.

---

## Why this was not caught by the previous fix

`broker.rs::send_rotate_if_pending` had a `.find()` over the same rows and was fixed in v0.10.4
to take the newest row and direct it only if it is a sentinel. That fix is correct and is
working — the logs show exactly one directive per rotation, for the right epoch.

**It is a different question on the same data.** The broker asks *"is there a NEW rotation to
direct?"*; the tracker asks *"which pending row is the LIVE rotation?"*. The two need different
selectors, and fixing one says nothing about the other. Anyone auditing this area should expect
**per-consumer** selectors rather than one shared notion of "the pending row".

---

## The shape that looks right and is not

The obvious move is to reuse the broker's selector: take the max epoch over **all** rows, then
require it to be `pending`. It fixes the measured failure — and it introduces a worse one.

| rows | max-over-all-then-require-pending | max-over-pending (ruled) |
|---|---|---|
| `{0 active, 1 sentinel pending, 2 real pending}` | seeds 2 — correct | seeds 2 — correct |
| `{1 sentinel pending, 2 active}` *(after the rotation completes)* | top row is `active` → **seeds nothing** | seeds **1** |

In the second state the orphan is still there. Under max-over-all **no tracker is ever seeded
for it**, so `decide` is never asked, so `ABORT_AFTER` never fires, so `drop_pending_epoch` is
never called: **the row becomes permanent.** And `initiate_due_rotations` skips any gateway with
a `pending` or `retiring` row, so that gateway is **excluded from automatic rotation for good** —
the v0.7.2 class of silent self-disable, reintroduced.

The unfixed code is *slow but self-healing*. That shape would be *fast but leaky*: it turns a
latency bug into a durability bug, and the done-bar cannot tell the difference.

---

## The ruled fix

**Select the `pending` row with the maximum epoch.** One function, called at all three sites.

```rust
/// The LIVE rotation's pending row: the `pending` row with the highest epoch,
/// paired with the current `active` epoch if there is one.
fn select_live_pending(keys: &[GatewayKeyRow]) -> Option<(u32, Option<u32>)>
```

`GatewayKeyRow` is `crate::db::GatewayKeyRow` = `(i64, String, String)` — `(epoch, pubkey,
state)`. The return is `(pending_epoch, prior_active_epoch)`, which is exactly the inner tuple of
the `RotationSeed` alias, so the `report`-path seed vector needs no reshaping.

**Private, not `pub(crate)`, deliberately.** All three call sites are inside `services/sync.rs`,
and the in-module tests reach private items. Widening it would re-introduce, one PR later,
exactly what the review of the previous fix asked to remove from the sibling function hoisted
out of `report`.

**Three selection sites, five consumer positions — two at `drive_rotation_for`, two at
`sweep_rotations` step 2, one at the ack path. The function replaces the selection, never one
use of it.** At `drive_rotation_for` and `sweep_rotations` the selected value feeds both
`evict_decision` **and** the lazy seed; `seed_and_record_epoch_acks` feeds the seed **only** —
it has no `evict_decision` call, and it should not acquire one. (`evict_decision` has exactly
two production call sites; the rest are its unit tests.) Changing only the seed at the two
two-consumer sites would make the tracker and the staleness check disagree every tick — evict,
rebuild, `started_at` resets, and the grace never elapses. Same failure, subtler cause.

Stated as 2/2/1 rather than "two per site" deliberately: the shorthand invites an implementer
to go looking for the ack path's `evict_decision` and, not finding one, to add it.

**One value nearby is NOT selection-derived and must not be swept into this change:**
`drive_rotation_for`'s `pending_has_real_key` is computed from **`tracker.pending_epoch`**, not
from the selection. The selector change leaves it untouched — but it is downstream of the
mis-seed and is precisely how the orphan keeps `decide` pinned on rule 2, so it belongs in a
reader's mental model of the bug while staying outside the diff.

**Why it self-cleans.** After the live rotation promotes, the rows are `{1 sentinel pending,
2 active}` with no tracker. `Db::gateways_with_rotation_state` keeps that gateway in the sweep's
set (the orphan is `pending`); step 2 seeds on epoch 1; `evict_decision` keeps it (the selector
gives the same epoch to both consumers); rule 2 aborts at `ABORT_AFTER`; `drop_pending_epoch`
removes row 1 only. Final state `{2 active}`. **No change to `Db::rotate_key`** — the
alternative of deleting the orphan at rotation time would have made the only currently-safe key
path destructive.

**The collection clock starts at the re-seed**, so the orphan is collected after the live
rotation completes rather than competing with it.

**Seeding a tracker on a sentinel is deliberate and must not be optimised away.** It cannot
promote, and it is worth being exact about why, because the imprecise version invites a wrong
test: **`decide` rule 2 returns before rule 3 or 4 can propose a promote, so
`Db::promote_epoch` is never called on the sentinel path at all.** It is not that the CAS is
attempted and declines. (`promote_epoch` does independently gate on a real-keyed pending row,
which is defence in depth for a caller that reaches it by some other route — but nothing on
this path does.) A test asserting "`promote_epoch` returned `NoMatch`" here would fail, and
would read as a regression rather than a mis-specified assertion.

What the sentinel tracker is *for* is that it is the orphan's **only garbage collector**. The
selector's `{1 sentinel, 2 active}` case carries a failure message saying so.

---

## The diagnosability defect, which no selector fixes

The mismatch path in the ack record pass has no `else`: an ack naming an epoch the tracker does
not know is discarded silently. That is why this presented as *"the controller simply never
promotes"* with nothing in stderr, and why the diagnosis had to come from a database row dump.

PR1c adds one operator-phrased log line on that path, naming both epochs and both gateways, with
a test anchor. A counter is filed for Phase C. **No state change on that path**: removing the
tracker when an ack mismatches looks like a fix and is the documented `RETIRE_GRACE`-collapse
trap — a promoted tracker still owes a retire, and dropping it hands a live `retiring` row to the
grace-free orphan path.

---

## Carried forward

* Two selectors over one row set answer different questions. Audit per consumer.
* A test that only asserts the happy path cannot distinguish *slow* from *broken*; this one
  failed at 120s for a state that resolves at ~390s.
* An acknowledgement that is sent once is a fact worth knowing before designing anything that
  can drop it.
* The gateway's retire clock and the controller's promote clock are independent. Anything that
  delays promotion widens the window in which the roster advertises a destroyed key.


---

## What the falsification runs measured

Four sabotages against the fix, each one site (or, for the fourth, one *part* of one site),
each applied on a throwaway commit, run by the test-runner, reverted after.

| # | sabotage | SHA | RED |
|---|---|---|---|
| 1 | `drive_rotation_for`'s whole site → `.find()` (both consumers) | `cae7570` | `drive_seeds`, `sweep_step2`, `one_tick` |
| 2 | `sweep_rotations` step 2's whole site → `.find()` (both consumers) | `5c192f7` | `one_tick` |
| 3 | `seed_and_record_epoch_acks`' site → `.find()` (one consumer) | `7ef2689` | the ack test, on its seed assertion |
| 4 | **half-refactor**: seed on the selector, `drive`'s evict input on `.find()` | `7e73533` | `one_tick` |

### The three sites are not equally self-guarding

| site | reds its own test when reverted? | what actually guards it |
|---|---|---|
| `drive_rotation_for` | **yes** | its own seed test |
| `seed_and_record_epoch_acks` | **yes** | its own seed test |
| `sweep_rotations` step 2 | **NO** | `one_tick_…`'s identity stamps, alone |

The sweep site's own test stayed **green** under a full revert of that site (sabotage 2),
because step 2b calls `drive_rotation_for` for every gateway in step 1's set — after step 2,
off a fresher read — so the still-correct drive selector evicted the wrong seed and rebuilt it
on the right epoch inside the same iteration. The epoch is repaired; the identity stamps are
not.

The coupling is **asymmetric**, and neither run shows that alone: sabotage 1 propagated *into*
the sweep test (a defect that site does not own), while sabotage 2 was *masked* by drive (a
defect it does own). **`sweep_rotations` step 2's seed is therefore not independently
observable through a sweep pass** — anything that drives a sweep drives `drive_rotation_for`
after it, so a test that does not read the tracker between them is measuring the composition
of two sites.

### Two measurements about `one_tick_…` specifically

1. **A `pending_epoch`-only comparison would have produced ZERO reds under both sabotage 2 and
   sabotage 4.** In each, the tracker ends the tick holding the correct epoch. The identity
   stamps (`started_at` / `installed_at`) are the only thing standing between those two
   defects and complete silence.
2. **The sweep site's guarantee rests on `one_tick_…` alone**, and the full-sweep test is
   actively misleading about it: it reds for a defect it does not own (sabotage 1) and stays
   green for one it does (sabotage 2).

**So `one_tick_…` is the sole detector for two independent defects** — the sweep site's full
revert and the drive site's half-refactor. It is not redundant with the three per-site seed
tests; it is the only thing covering the cases they cannot see. Weakening it to compare epochs
rather than stamps silently removes both guards at once.

### Why the half-refactor is the shape worth remembering

Sabotage 4 is what a careful refactor lands in: the selection is moved to the shared function
at every seed site, and one consumer of that selection — the staleness input — is left behind.
Every per-site seed test passes, because every site really does seed the newest pending row.
The tracker is then evicted and rebuilt **on the same epoch** every tick, so only its clock
moves, and no grace can ever elapse. Three of the four tests are blind to it.
