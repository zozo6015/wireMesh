# A gateway-side abort leaves a sentinel row that steals the next directive

**Found:** 2026-08-26, by `crates/wiremesh-gateway/tests/rotation_wedge.rs` step (iv)
during Phase B's PR1 (B2, BACKLOG item 9) verification window.
**Status:** product defect, mechanism confirmed from source. Bounded (self-heals at
`ABORT_AFTER`), not permanent. **Fix RULED: (A′)** — direct a sentinel only if it is the
highest epoch of *all* rows (architect, Rev 1.40). **(A), "highest sentinel", was withdrawn
as unsafe** — see below: it does not merely rotate backwards, it can destroy a live key.
**Not** a harness artifact: the test is doing exactly what it says, and what it found is real.

## Summary

After B2, a rotation that fails gateway-side unwinds cleanly and the gateway returns to
`Idle`. The **controller's** `pending` row for that epoch does not go away — there is no
gateway→controller cancel RPC (engineering design §3.2 Piece 1b). It sits there carrying the
`awaiting-submission` sentinel until `ABORT_AFTER`.

While it sits there, **the next `Admin.RotateKey` directs the STALE epoch, not the one it
just created.** The new epoch *is* directed shortly afterwards — but by then the gateway is
mid-rotation on the stale one and correctly refuses a re-entrant directive, and nothing ever
retries. The rotation is lost between two individually-correct behaviours.

## Mechanism (measured from source, by symbol)

1. `db::Db::rotate_key` inserts the new epoch at `MAX(epoch) + 1` and emits
   `ChangeEvent::KeyRotated` carrying the gateway's **full** `(epoch, pubkey, state)` row
   set. It has no "is a rotation already pending?" guard — deliberately, since
   `Admin.RotateKey` is the operator's escape hatch.
2. `broker::Broker::send_rotate_if_pending` selects the epoch to direct with a
   **first-match** `find`:

   ```rust
   keys.iter().find(|(_, pubkey, state)| {
       state == "pending" && pubkey == AWAITING_SUBMISSION_SENTINEL
   })
   ```
3. `db::Db::all_keys_for_gateway`, which populates that row set, returns rows
   **`ORDER BY epoch` ascending**.
4. After an aborted rotation there are **two** sentinel `pending` rows — the orphan and the
   new one — so `find` returns the **lowest**, i.e. the orphan.
5. `ChangeEvent::KeyRotated` carries **no epoch field**, only the row set, so the broker has
   no way to know which epoch the event was raised for.

### The unstated invariant this breaks

`broker.rs`'s `KeyRotated` arm states C1 correctly — *"the directive fires exactly once, at
rotation start"* — but that is only true on an **unstated premise: at most one `pending` row
per gateway at a time.** Hold that premise and `find` is unambiguous, because there is only
ever one candidate. The orphan sentinel is precisely the state that violates it, and the
moment there are two candidates a first-match `find` silently starts answering a different
question ("the oldest un-submitted epoch") than the one the comment describes ("the epoch
this event is about"). **Name the invariant when fixing this**, whichever direction is
chosen: an unwritten premise is what let a correct-looking comment sit above code that stops
being correct the moment a second row exists.

Related, and now worth doing in one pass: the false *"the sweep/timer re-emits KeyRotated"*
claim has **four** sites, not the two design finding C1 recorded (all verified present):

| site | wording |
|---|---|
| `broker.rs::send_rotate_if_pending` doc | "sweep/timer re-emits KeyRotated on subsequent ticks" |
| `services/sync.rs::SyncSvc::submit_epoch_key` doc | "`Broker::send_rotate_if_pending` re-issues a `RotateDirective` for…" |
| `proto/wiremesh/v1/sync.proto`, `SubmitEpochKeyRequest` | "the controller re-issues a `RotateDirective` for the still-sentinel…" |
| `crates/wiremesh-controller/tests/epoch_key_submit.rs` rationale | "broker therefore re-issues the `RotateDirective`; the new process mints a…" |

**Disposition (v0.10.4 and PR6).** The first was corrected in v0.10.4. The other three were
re-checked against the code and **their mechanism names were already right** — each credits
`Broker::send_rotate_if_pending`, and repo-wide no text credits the *sweep* with re-issuing a
rotate directive. What was actually imprecise in all three was **causation**: they read as if
the gateway restart caused the re-issue. It does not. `send_rotate_if_pending` runs only from
`ChangeEvent::KeyRotated`, and reconnecting emits none (Watch registration goes to
`on_gateway_connected`, the punch path) — so the race needs a `KeyRotated` for that gateway
while the sentinel still stands. **The restart is the setup, not the trigger.** All three now
say so.

A rewrite claiming the re-issue does not happen at all was proposed during PR6 and
**withdrawn**: an independent premise check found `send_rotate_if_pending` fires on *every*
`KeyRotated` and re-issues *precisely because* the row is still the sentinel. The two-key race
this note describes is real.

The fourth is the one that matters most: it is a **test's stated rationale**, so the false
claim is not merely documented, it is load-bearing for why that test is believed to prove
what it proves.

**A fifth candidate was checked and REJECTED** — recorded because it looks like a match and
the next reader will find it too. `gateway/src/main.rs`'s `directive_punch_handoff` logs
*"dropping directive (broker re-emits on its sweep)"*, which reads like the same false
promise in a runtime, operator-facing string. It is **not** false: that line is on the
**punch** path, not the rotate path, and the broker really does have a periodic punch sweep
(`Broker::periodic_sweep`, trigger (c), `RETRY_INTERVAL` 5s). A dropped *punch* directive
genuinely does come back.

One caveat worth carrying if that line is ever revisited: the punch re-emit is **bounded**, by
`MAX_PERIODIC_ATTEMPTS` (5 consecutive periodic re-punches per pair, reset on any candidate
change or reconnect) and by `emit_pair`'s path-state skip. So the promise is real but not
unconditional. That is a much smaller observation than the four above, and it is the reason
this candidate is listed as rejected rather than quietly dropped: "re-emits on its sweep" is
true for punch and false for rotate, and only reading which directive the line sits on tells
them apart.

### The trigger is the first-match `find`; the KILL is the in-flight refusal

The gateway completes the epoch it was directed to — the stale one. What happens next is the
part that actually loses the rotation, and it is **not** "the new epoch is never directed".
It is directed, twice:

* completing the stale epoch produces two more `KeyRotated` events of its own — one from
  `Sync.SubmitEpochKey`, one from the promote arm of `drive_rotation_for`;
* at that moment the orphan is real-keyed, so it is no longer a sentinel and the **new** epoch
  is the only sentinel left — so `send_rotate_if_pending` correctly directs **it**, twice;
* but the gateway is by then `Overlapping`/`CutOver` on the stale epoch, so
  `Rotation::on_directive` **refuses** both, logging `ignoring RotateDirective(epoch=…) — a
  rotation is already in flight`;
* and per design finding C1 the directive fires once per event and nothing retries, so once
  the gateway returns to `Idle` no further `KeyRotated` is raised for the still-sentinel new
  epoch, and it is stranded until `ABORT_AFTER`.

**Every step in that chain is individually correct.** The first-match `find` is the only
outright defect; the re-entrancy refusal is exactly what `Rotation::on_directive` is *for*
(it is pinned by `duplicate_directive_while_rotating_is_ignored`), and fire-once delivery is
C1's deliberate design. The rotation is lost in the **composition**: a mis-targeted directive
puts the gateway busy precisely during the window in which the correctly-targeted ones arrive.

That distinction matters for the fix. Correcting the `find` removes the trigger, and with it
the whole chain — the gateway is `Idle` when the new epoch's directive arrives and takes it.
Nothing needs to change about re-entrancy or about fire-once delivery, and a fix aimed at
either of those would be treating a correct behaviour as the fault.

## Why B2 surfaced it rather than caused it

The defect predates B2. What B2 changed is **reachability**: before it, a rotation that
failed part-way left the gateway wedged off-`Idle`, so nobody ever got as far as a second
directive. B2 makes a clean abort the normal outcome of a failed rotation, which makes the
stale-sentinel window a routine state rather than an unreachable one.

This is the second time in Phase B that closing the wedge exposed something behind it; the
first was the epoch-numbering desync that `EpochKeys::generate_next_at` now handles
(engineering design §3.2 Piece 2c).

## Second-order consequences

1. **A `RotateKey` inside `ABORT_AFTER` of an aborted rotation rotates to the wrong epoch**,
   and orphans the epoch it just created.
2. **The fabric lags one rotation behind**: each subsequent `RotateKey` drives the *previous*
   orphan, since by then it is the lowest remaining sentinel.
3. **Timer-driven rotation is suppressed for that gateway while an orphan exists.**
   `services::sync::initiate_due_rotations` skips every id in
   `db::Db::gateways_with_rotation_state` (`state IN ('pending','retiring')`). One aborted
   rotation therefore disables the timer for that gateway for up to `ABORT_AFTER`. This is
   the consequence most relevant to the R13 decision to keep the timer off.
4. **It self-heals**, bounded by `ABORT_AFTER`: `drive_rotation_for`'s abort arm calls
   `drop_pending_epoch`, which deletes the orphan row. Nothing is permanently stuck.

## This makes `generate_next_at`'s replace branch load-bearing, not hardening

Rev 1.8 split `EpochKeys::generate_next_at`'s occupant guard by state: a `"pending"` occupant
at the requested epoch is **replaced** (stale key scrubbed, fresh material minted), while
`"active"`/`"retiring"` are refused. That branch was justified by a **crash** — a gateway
dying between the mint's `persist` and the unwind's scrub, then being re-directed at the same
epoch.

**The mechanism in this note reaches the same branch with no crash at all.** The controller
re-directs an epoch the gateway may still be holding locally as `pending` whenever the local
scrub did not happen — a failed `persist`, or a skipped step. So the branch is exercised in
**normal operation**, and its status upgrades from defensive hardening to load-bearing.

### Consequence for reading sabotage 2's result — do not misread it

B2's sabotage 2 removes `unwind_failed_rotation`'s step 4 (`discard_pending` + `persist`),
which is exactly "the local scrub was skipped". Its falsification target is
`rotation_wedge.rs` step **(iii)** — the orphan `"pending"` key survives in
`epoch_keys.json` — and the test stops there.

But had it continued, **the second rotation could well SUCCEED**, via precisely this replace
branch: the re-directed epoch finds a local `pending` occupant and replaces it. That must not
be read as "the scrub is unnecessary". The two properties are independent:

* step (iii) asks *was the orphan private key scrubbed from disk* — a **security** property;
* step (iv) asks *does the next rotation complete* — a **liveness** property.

The replace branch rescues liveness while leaving the security property broken, which is the
whole reason they are asserted separately. A reviewer who sees "sabotage 2 still completes a
rotation" and concludes step 4 is redundant would be drawing the exact wrong lesson.

## Candidate fixes — hypotheses, for the architect to rule

**The enabling condition is design finding C2**, and it should be stated before the options:
`services/admin.rs::rotate_key` has **no** mid-rotation guard, while
`services::sync::initiate_due_rotations` **does** (it skips every id in
`gateways_with_rotation_state`). So the timer can never produce a second concurrent sentinel
row — only `Admin.RotateKey` can, and only because that asymmetry is deliberate. Any fix that
removes the asymmetry is changing an intentional behaviour, not tidying an oversight.

Listed with the objection each has to answer; none is recommended here.

**A. Direct the highest sentinel instead of the first.** One line, at the `find`.
Objection: "newest" is a *proxy* for "the one just created", not the thing itself — right by
coincidence of `ORDER BY epoch`, and a future non-monotonic epoch source breaks it silently.
It also leaves the orphan undirected until `ABORT_AFTER`, when `drop_pending_epoch` removes
it — so consequence 3 (timer suppression) stands for that window.

**B. Carry the initiating epoch on `ChangeEvent::KeyRotated` and direct that.** Says what is
actually meant, and is the only option that makes the comment true rather than accidentally
satisfied. Objection: `emit_key_rotated` has **seven call sites** — measured, and one more
than design
finding C1's "six plus the sweep-orphan retire" phrasing suggests when read as six:
`services/admin.rs` (`Admin.RotateKey`), and in `services/sync.rs` the promote, retire and
abort arms of `drive_rotation_for`, the sweep-orphan retire, the rotation-timer initiate, and
`Sync.SubmitEpochKey`. They are **not uniform**: several raise the event for a reason that has
no "initiating epoch" at all — a retire and an abort are not initiations — so the field has to
be optional and **every one of the seven has to decide what it means**. That is where a
mechanical change stops being mechanical, and the count is the argument, not a detail.

**C. Give `Admin.RotateKey` the same guard `initiate_due_rotations` has.** Objection: beyond
C2, it has a **done-bar shape** consequence — with a guard, `RotateKey #2` in
`rotation_wedge.rs` would have to wait out `ABORT_AFTER` (**300s**) before it could be
accepted at all, so the netns done-bar's runtime and structure change materially. That is a
test-design decision, not just a controller one.

**D. Drop the orphan earlier than `ABORT_AFTER`, on a gateway-side signal.** Objection: no
such signal exists; inventing one is the gateway→controller cancel RPC that §3.2 Piece 1b
explicitly declines to add in Phase B.

**E. Have `Admin.RotateKey` drop the orphan sentinel (`Db::drop_pending_epoch`) before
inserting the new epoch.** Keeps the escape-hatch semantics C2 protects — the call still
always succeeds — while restoring the one-pending-row invariant the broker's comment assumes,
which makes A and B unnecessary. Objection: it makes `RotateKey` **supersede** an in-flight
rotation rather than stack alongside it. That is a real semantic change: an operator who
fires `RotateKey` twice in quick succession for a gateway that is legitimately mid-rotation
would silently lose the first, and the "in-flight" and "orphaned" cases are indistinguishable
from the controller's side without the very signal option D says does not exist.

## The harness assumption this invalidated — recorded as the test author's

`rotation_wedge.rs` step (iv) resolves its target epoch from **`RotateKeyResponse.epoch`**,
i.e. it assumes the directive that follows a `RotateKey` targets the epoch that call created.
**That assumption is false whenever an orphan sentinel exists — which, after a deliberate
abort, is always.** It was written before this mechanism was known and is wrong independently
of the product defect.

Consequences for whoever picks this up:
- If the product is fixed by any change that directs the newly created epoch — (A′) as
  ruled, or (B) — the test passes **as written**: the assumption becomes true.
- If it is not fixed, step (iv) must resolve its target from **what the controller actually
  directed**, not from the RPC response.

The test is not weakened either way. It asserted that the epoch advances after an unwound
rotation, and the epoch did not advance; that is a true report of a real defect. Only the
*label* it used for the expected epoch was wrong.

## Evidence

Confirmed 2026-08-26 by the qa-tester, from gwA's stderr captured mid-run into
`gw/target/qa-capture/`. **4 of 4 deterministic** at ~133s; `rotation_unwind` 3/3 and
`key_rotation` 7/7 green in the same window, so this is not a broadly sick tree.

The figures below are from qa's **complete** 285-line capture. An earlier partial reading of
the same run supported a stronger claim than the log does — see the pre-registration verdict
below, which records exactly which half survived.

| # | line | what it establishes |
|---|---|---|
| 12 | `ROTATION ABORTED — rotation to epoch 1 … after-enforcer-insert` | the injected fault fired, for epoch 1 |
| 13 | `state machine returned to Idle — the next RotateDirective will be honoured` | **the control: B2 worked** |
| 60 | `RotateDirective(epoch=1)` — from RotateKey #2's `KeyRotated` | **the defect**: the stale orphan is directed |
| 18 | `Role A minted epoch 1 on wg0e1:51821, submitted pubkey` | the gateway rotates to epoch **1** again |
| 62 / 63 | `RotateDirective(epoch=2)` ×2 — from submit(1)'s and promote(1)'s `KeyRotated` | the new epoch **is** directed, once it is the only sentinel |
| 196 / 199 | `ignoring RotateDirective(epoch=2) — a rotation is already in flight` ×2 | **the kill**: refused, correctly, because epoch 1 is mid-flight |
| 21 / 25 / 27 | cutover, grace, `retired epoch 0` | the stale rotation completes normally |

Line 13 is the control and should be read first: **B2 worked.** The state machine did return
to `Idle`, and the next directive *was* honoured. Line 60 is the defect — that directive
carried the wrong epoch. Lines 62/63 and 196/199 are the kill: the right directives arrived
while the gateway was busy with the wrong one, were refused for a correct reason, and were
never retried.

**Two absences, both pre-registered, both holding:**

* **`main.rs`'s "minted epoch {} != directive epoch {n}" warning did NOT fire.** The gateway
  mints at the directive epoch, so that warning firing would mean the two differed. Its
  silence is a positive measurement that **the directive the gateway acted on carried epoch
  1** — the controller's side of the mechanism, evidenced from the gateway's log without
  capturing the controller at all.
* **Zero `plan_tunnel` / `not available` / `reserved` lines.** This retires the competing
  hypothesis *by evidence* rather than by argument. `rotation_wedge.rs` step (iv) waits
  `tunnelset::QUARANTINE + 3s` before the second `RotateKey` specifically because a
  torn-down own-epoch tun holds the RESERVED port for 5s and `plan_tunnel` refuses rather
  than falling back — which would have produced a failure indistinguishable at the headline
  from this one. It did not happen: the wait did its job, and the quarantine is not a
  confounder here.

### The pre-registration — one half held, one half was refuted

This note's mechanism section was written **before** the capture existed, and predicted:

> controller: `sent RotateDirective(epoch=1)` **twice**, and **no** `…(epoch=2)`;
> gwA: the abort anchor once, then a *second* epoch-1 mint; **no** `Role A minted epoch 2`.

**Held:** the stale epoch-1 directive, the second epoch-1 mint, and the absence of any
epoch-2 mint. The trigger — first-match sentinel selection — is confirmed exactly as derived
from source.

**Refuted:** *"no `RotateDirective(epoch=2)`"*. Two were sent. The prediction was drawn from
a correct reading of `send_rotate_if_pending` plus an **incorrect assumption that no further
`KeyRotated` would be raised** — in fact completing the stale rotation raises two of its own,
and by then the new epoch is the only sentinel, so it is directed properly. The rotation is
lost to the in-flight refusal, not to an absent directive.

Recorded rather than quietly corrected, because the refuted half is the more interesting
finding: the original prediction described a single defect, and the log shows a **composition
of one defect and two correct behaviours**. A note that had only been rewritten to match the
evidence would have lost that.

## Ruling — direction (A′) (architect, Rev 1.40)

**RULED: (A′) — direct a sentinel only if it is the highest epoch of ALL rows**
(architect, Rev 1.40). **(A), "highest sentinel", was proposed first and withdrawn as
unsafe.**

### Why (A) is not merely insufficient but destructive

Once the gateway completes the stale epoch, that epoch is real-keyed and drops out of the
sentinel set, leaving the orphan situation **inverted**: if the *newer* epoch is the one
real-keyed first, the only remaining sentinel is the **older** one, and "highest sentinel"
selects it. A now-`Idle` gateway is then directed to rotate to an epoch *below* its current
active one.

"Rotates backwards" understates the consequence. **`Db::promote_epoch`'s demote step carries
no epoch predicate:**

```sql
UPDATE gateway_key SET state = 'retiring' WHERE gateway_id = ?1 AND state = 'active'
```

It demotes whatever is `active`, whichever epoch that is. So the backwards rotation would
promote the *older* epoch and demote the **newer, live** one to `"retiring"` — after which
the ordinary retire path **deletes** it. Plain (A) therefore converts a stranded-rotation bug
into **destruction of a real, in-use key**, which is categorically worse than the defect it
was meant to fix.

(A′) closes it by requiring the sentinel to be the highest epoch of **all** rows, not merely
the highest among sentinels — "direct only the newest epoch that exists, and only if it is
still awaiting submission". A stale sentinel with any higher row above it is never directed
at all; it simply expires at `ABORT_AFTER`.

Note the shape of the correction, because it recurs: **(A) was right about which candidate to
prefer and wrong about the set to prefer it within** — a selection predicate evaluated over a
set whose composition nobody had stated. That is the *same class of error* as the original
defect this note is about, arrived at independently while fixing it. The lesson is not "check
selection predicates"; it is that a predicate and the set it ranges over have to be specified
**together**, and neither `send_rotate_if_pending`'s `find` nor `promote_epoch`'s demote
states its set.

The objection this note raised against (A) — that *newest* is only a proxy for *the one just
created* — is answered by an invariant rather than by coincidence: epochs are allocated
`MAX(epoch) + 1` (`Db::rotate_key`), so within a gateway's row set the highest sentinel **is**
the most recently created one. (A) is therefore correct for as long as that allocation holds,
and a future non-monotonic epoch source would have to revisit it — which is worth a comment at
the `find`, since that is exactly the premise this whole defect came from going unstated.

**(E) — have `Admin.RotateKey` drop the orphan before inserting — was rejected as
destructive.** The controller cannot distinguish an *orphaned* sentinel from a *legitimately
in-flight* one; that is the same missing signal option (D) needs. So (E) would sometimes
delete a live rotation's pending row, and the project's standing rule is to fail toward the
non-destructive branch when the two cases are indistinguishable. This is the same shape as
`evict_decision`'s `None`-means-keep and the four recorded `RETIRE_GRACE`-collapse routes:
the destructive option is the one that looks like a simplification.

### What (A)/(A′) does NOT fix — and it is consequence 3

Either version directs the **new** epoch, which is the point; under (A′) the orphan is
explicitly never directed at all. But both leave the **orphan present**,
so the orphan `pending` row still sits there until `ABORT_AFTER` — and
`initiate_due_rotations` still skips every gateway in `gateways_with_rotation_state`. So
**consequence 3, timer suppression for up to 300s after any aborted rotation, survives this
fix.**

That is deliberate, not an oversight: closing it needs either (E)'s destructive drop or (C)'s
guard on `Admin.RotateKey`, and both change intentional behaviour (C2). **Filed for Phase C,
together with C2's guard**, and called out here because it bears directly on the R13 decision
to keep the rotation timer off — an operator re-enabling the timer should know that one
aborted rotation quietly disables it for that gateway for five minutes.
