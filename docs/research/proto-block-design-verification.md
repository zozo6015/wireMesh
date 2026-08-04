# Proto block (B5+B7 cutover, B9 X-6) — design verification against main

**Date:** 2026-08-04. **Verified against:** `main` @ `801955e` (pre-PR-#43), with the
item-1 branch read separately where noted.
**Why:** the B5+B7 and B9 designs in `backlog-program-notes.md` were ratified 2026-07-30.
Six PRs landed after. A prior verification of the B3 key-rotation design found that of its
five assumptions, one still held, one had been reshaped, one had got worse, one had grown a
new leak, and one was missing entirely. This is the same exercise for the proto block, done
before writing code rather than after.

## Field numbering — ALL STILL FREE

Re-checked on current main despite the proto having moved (`relay_infos=8`, `epoch_acks=4`,
`peer_paths=5`, `peer_paths_snapshot=6` all landed after the designs were written):

| Message | Used | Design wants | Verdict |
|---|---|---|---|
| `WatchRequest` (sync.proto:9) | *empty* | 1 session_generation, 2 client_version, 3 max_ir_schema | free |
| `ReportRequest` | 1-6 | 7 session_generation | free |
| `PunchDirective` | 1-3 | 4 peer_session_generation | free |
| `SyncMessage` oneof | 1-4 | 5 CutoverProbe | free — **but see decision 2** |
| `StateSnapshot` | 1-8 | 9 controller_version, 10 min_supported_version | free |
| `GatewayInfo` (admin.proto:66) | 1-5 | 6, 7 | free |
| `EnrollRequest` (enrollment.proto:13) | 1-5 | 6 | free |

`StateSnapshot` field 4 is a deliberately deprecated `repeated string` kept after a
wire-type hazard. **Never reuse it.**

## The premise that was already obsolete when the design was written

The Cycle-4c fast-follow is recorded as blocked on: *"WireGuard doesn't force a fresh noise
handshake on a UAPI endpoint change, so reliable direct-cutover detection needs a forced
rehandshake."*

That was no longer true at the time of writing. `set_peer_endpoint` →
`apply_peer_endpoint_scoped` → `uapi::set_one_peer` is literally `encode_remove_peer` then
`encode_add_peers`, and `uapi.rs:193-197` states the consequence: the re-created peer starts
with **no noise session** and the caller must nudge boringtun. The relay install is not an
exception — `ensure_relay_transport` calls `set_peer_endpoint(..., true)` and then
`poke_peer_overlay` *precisely because* the scoped re-add left the peer sessionless.

So the forced-rehandshake mechanism **already exists and is the default**. The real blockers
are the make-before-break refusals and the total absence of any rollback (below).
CLAUDE.md's "rekey-free endpoint switch to the relay socket" was corrected in PR #43.

## A. B5+B7 — cutover and session generation

### 1. The cutover seam — RESHAPED (moved down, not away)

The `ProbeDirect` no-op is where the design expects (`main.rs:2553-2563`, emitted by
`path.rs:346-365` at 20s intervals). What changed is underneath it. Two hard refusals now
sit between that arm and the device:

- `punch_and_apply`'s loop-head guard (`main.rs:1560-1585`) returns unless the path is
  `Connecting` **and** not relay-pointed. A `Relayed` peer fails both conjuncts.
- `set_peer_endpoint`'s atomic-commit guard (`main.rs:1844-1857`) returns `Ok(false)`
  **without touching the device** for `is_relay == false` unless `Connecting` and not
  relay-pointed.

So the executor cannot reuse either as they stand. The `EndpointOwner` tri-state must be
threaded through **three** places, not one: those two plus `run_path_ticks`'s corroboration
gate (`main.rs:2505-2542`), which routes a corroborated handshake to
`on_authenticated_inbound` instead of `on_handshake` whenever `relay_pointed` — i.e. the
cutover's own success signal is suppressed by the flag the probe must clear.

**Not budgeted for in the design:**
- **There is no rollback anywhere today.** `punch_and_apply` on `Exhausted`
  (`main.rs:1643-1651`) logs and returns, leaving WG pointed at the last dead candidate. The
  design's "≤6s gap then roll back" is entirely new code. It must also restore the
  `live_endpoints` pin (`main.rs:1867`) to the relay socket, or the next `apply_state`
  rebuild resurrects the direct endpoint and silently kills the relay path.
- **A rollback is a SECOND session reset of the relay leg.** A failed cutover costs two
  rekeys, not one, and the relay handshake has to re-complete. Not in the ≤6s budget.
- `apply_peer_endpoint_scoped`'s change-guard (`main.rs:1956-1961`) skips the write if the
  peer block already matches `applied_peers`. The rollback re-point must not be
  short-circuited into a no-op leaving the device on the direct candidate. Worth a pinned
  test.
- Gap arithmetic: `PER_CANDIDATE_PUNCH_TIMEOUT` 5s + `PUNCH_POLL_INTERVAL` 500ms ≈ 5.5s from
  commit to detectable failure. ≤6s works for one candidate only if the executor bypasses
  `MAX_PUNCH_DELAY` (the 5s go-skew sleep, `main.rs:1468-1477`) or counts it outside the gap
  — legitimately outside, since the endpoint is not moved until after it, but state it.

### 2. Rotation hard-skip — MISSING a signal

`PathCtx` has `wg0_pins` and `active` but **no handle to `RotationShared`/`Rotation`**.
Role-B overlap is detectable via `wg0_pins.contains_key(&gid)`; **Role-A overlap (this
gateway rotating) is not observable from `PathCtx` at all.** Needs a shared field or an
`AtomicBool`.

### 3. The controller sweep — SUPERSEDED by owner decision

No duplication with v0.3.0's brokering (`emit_pair`'s settled skip at `broker.rs:593-595`
rejects exactly the pairs a cutover targets, so a sweep would be its complement and must not
route through `emit_pair`). The state it needs already exists (`peer_path_states`,
`broker.rs:160`).

**But the blind spot is decisive:** `transition_crosses_settled_boundary`
(`path.rs:145-148`) returns `false` for `Relayed → Direct`, because round 4 deliberately
excluded within-settled moves to avoid report chatter (`path.rs:138-141`). So a successful
cutover produces **no prompt report**, the controller keeps believing the pair is relayed,
and a sweep burns its budget re-probing a solved problem. The one edge a sweep most needs is
the one round 4 optimised away.

**OWNER DECISION (2026-08-04): drive the cutover GATEWAY-LOCAL. `CutoverProbe` is dropped
from the proto entirely.** The gateway already has the peer's candidates in `DesiredState`;
the only thing the controller adds is go-time synchronisation, which matters far less for a
cutover (one side punching into an already-open port-restricted mapping) than for a cold
punch. This also removes the need for a second sweep timer — `MAX_PERIODIC_ATTEMPTS` 5 at
`RETRY_INTERVAL` 5s (`broker.rs:113,116`) does not fit a 60s exponential cadence anyway.

### 4. Session generation — the fix HOLDS, the race's grading is NOW WRONG

The race is still present and documented at `broker.rs:193-206`: a delayed pre-restart
Report, being `snapshot == true`, REPLACEs the fresh empty state written by
`on_gateway_connected`'s `clear_reported_states` (`broker.rs:423`). A per-boot nonce closes
it cleanly — the controller has the authenticated `gw.id` at Watch-open (`sync.rs:585`) and
`report` (`sync.rs:840`) can reject a mismatch synchronously with no DB hop.

**What is wrong is the comment's own bounding argument.** It says impact is bounded because
*"the gateway's own tick-driven `StartPunch` recovery is directive-independent."* The
authoritative case-4 run **falsified exactly that** — it is why round 4 exists.
`path.rs:130-140` records: *"both sides otherwise punching on unsynchronized self-timers
(idle-timeout detection + backoff drift), which a port-restricted pair can never land."*

So a stale snapshot that re-settles a restarted gateway's pair suppresses the synchronized
directives, and the fallback the comment relies on is known not to work for the common NAT
pairing. **Re-grade from "valid but deferred, bounded" to a real availability bug**, and
correct `broker.rs:196-203` as part of the work. Round 4 also *widened* the window: reports
are now event-driven and prompt (`main.rs:2661-2666`, 2s debounce).

**Scope correction:** the generation must gate the **whole** `Report` handler, not just
`peer_paths`. `sync.rs:878-899` also runs `set_applied_version` and `set_local_candidates`
off the same stale request — and `local_endpoints` is the *original* instance of this race
per `broker.rs:203-204`.

### 5. Netns done-bars — case 2 COLLIDES with an existing assertion

- **Case 2 (relayed→direct ≤90s)** — the scenario exists as `relay_matrix.rs` case 4
  (`case4_relay_leg_death_unwedges_direct_punch`, line 1475), but its **phase 2 asserts the
  opposite**: `relay_matrix.rs:1543-1560` panics if either side leaves `relayed` during a 5s
  settle after `unblock_direct`, with *"a healthy relay path must not be disturbed before its
  leg dies."* Today it stays green only by the 20s `PROBE_DIRECT_INTERVAL` grace — a timing
  coincidence, not a basis. **Must be reconciled deliberately**, as a modification to case 4
  rather than a pure addition.
- **Case 6 (roam-wedge, healthy relay)** — this *is* case 4; re-verify under the cutover
  rather than adding a case.
- **Case 5 (rollback + give-up, symmetric)** — fits `relay_matrix.rs` case 1, but that case
  tolerates ≤1 `DEFER_NEEDLE` line (`:1096-1112`) and asserts the pair never reaches
  `direct`. The executor must log a *different* line, and case 1's flowing-ping assertions
  must survive up to 5 × ~6s gaps. Budget it.
- **Case 7 (restart asymmetry ≤30s)** — **needs new harness.** `GwProc` has `kill()`
  (`relay_matrix.rs:465-467`) but no respawn, and no test reuses a statedir across a process
  boundary. `convergence_matrix.rs:736` (late-joining gateway) is the closest pattern.
  **Strongly consider proving it in `crates/wiremesh-controller/tests/broker_pathstate.rs`
  instead** — that suite already drives real Watch streams and Reports against a
  `TestController` and would pin the generation-reject semantics far more cheaply.

## B. B9 / X-6 version negotiation

### 6. "Schema-2 IR crashes the gateway" — WAS true, now REDUNDANT, replaced by worse

Chain: `PolicyIR::from_json` (`wiremesh-policy/src/ir.rs:85-94`) bails on `schema != 1`; its
only production caller is `GatewayEnforcer::apply_if_changed` (`enforce.rs:34`).

On pre-#43 main that was reached from `apply_state` (`main.rs:3030`) whose sole steady-state
caller is the sync loop at `main.rs:648-656` (`.await?`) inside `async fn run` — so it
propagated out of the process. The finding was correct; only the line number had drifted.

**After PR #43** the decode sits inside the worker's non-fatal path: logged, counted on
`wiremesh_gateway_policy_apply_failures_total`, retried with backoff. The sync loop's only
interaction is `policy_apply.publish(ds.clone())` — not async, returns `()`, no `?`. The old
policy stays live because `from_json` fails *before* `inner.apply`.

**X-6 Task 2 as written is redundant. Do not delete it — RE-SCOPE it**, because #43
introduced two consequences the design never considered. One is already fixed there (an
undecodable IR was being persisted and replayed on every fail-static boot — see
`FailStaticWriter`). The other remains: **a first-boot schema mismatch is now a silent
blackhole rather than a crash.** A gateway booting against a too-new controller with no prior
good policy attaches its default-deny enforcer and drops all fabric traffic while looking
healthy to systemd/Kubernetes. That raises the value of X-6's **Watch-open
`FailedPrecondition` gate and enroll-time gate** — they become the only things preventing it,
where the crash was at least loud.

Rotation-path callers are already non-fatal (`main.rs:3356`, `:3459`), so there is no second
fatal site.

### 7. The rest of X-6 — LARGELY HOLDS, two gaps

- **`apply_fabric` transaction — HOLDS.** `db.rs:815-823` spans every segment mutation, the
  fresh `read_all_segment_defs_tx`, the compile and the policy-version write. An apply-time
  gate slots in cleanly.
- **DB schema room — HOLDS.** `PRAGMA user_version` is 3; `run_migrations` (`db.rs:637-675`)
  is a straight ladder and `SCHEMA_V2` (`db.rs:215-217`) is the exact precedent for
  `ALTER TABLE gateway ADD COLUMN version TEXT NOT NULL DEFAULT ''` /
  `max_ir_schema INTEGER NOT NULL DEFAULT 0` as `SCHEMA_V4`. Those defaults land exactly on
  the design's legacy semantics. Add the `user_version == 4` assertion to `tests/db.rs`.
- **Watch-open gate — HOLDS.** `SyncSvc::watch` (`sync.rs:811-838`) resolves the gateway from
  the cert CN before dispatching, so a `FailedPrecondition` return is a two-line insert.
- **No version plumbing exists at all.** `env!("CARGO_PKG_VERSION")` appears only in
  `cli.rs:47` and `cli.rs:65` for `--version`. All greenfield.
- **GAP — the operator turns an enroll rejection into a silent hang.**
  `wiremesh-operator/src/controllers/gateway.rs:641` requeues every 15s while not enrolled
  (B11 item 8 already flagged mint churn there). A version-rejecting `Enroll` becomes a
  permanent 15s retry with no operator-visible cause unless surfaced into the CR status.
  Needs a `Condition` naming the mismatch, or it is an unexplained hang on the one deployment
  path with no human at the console.
- **GAP — `--min-supported-version` is described as "emergency lower-only" but nothing in the
  controller is lower-only-enforceable today.** No config-validation ratchet precedent. Say
  where the ratchet lives (boot-time compare against the compiled floor).

## Open owner decisions

| # | Decision | Status |
|---|---|---|
| 1 | Case 4 phase 2 vs case 2 — reconcile deliberately, do not let the 20s-vs-5s coincidence decide | OPEN |
| 2 | Cutover driver: controller sweep vs gateway-local | **DECIDED: gateway-local, CutoverProbe dropped** |
| 3 | Does a failed cutover's rollback rekey count against the ≤6s gap budget? | OPEN |
| 4 | Re-grade the `on_report` race to an availability bug; gate the WHOLE Report handler | **DECIDED: yes to both** |
| 5 | Rotation-overlap signal — add a shared handle, or Role-B-only + document the Role-A hole | OPEN |
| 6 | X-6 must follow the policy-apply worker | **RESOLVED: PR #43 merged 2026-08-04** |
| 7 | Exclude an un-decodable `policy_ir` from `state.json` | **RESOLVED: shipped in PR #43** |
| 8 | Operator-visible surface for an enroll-time version rejection | OPEN |
