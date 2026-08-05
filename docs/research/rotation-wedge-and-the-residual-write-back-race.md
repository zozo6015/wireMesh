# Two findings from the review of the F1/F3/F4/F6 fixes

**Reviewed:** 2026-08-05, by an agent that wrote none of the code, scoped to `5a5f644..dfbd8e3`.
**Verdict:** the four fixes are sound and the branch is net-positive on every axis. These two
are what it found *residual*, recorded before merge rather than after.

## R2 — F4's accepted leak also costs the gateway its ability to rotate, permanently

**This is worse than `53c20c3`'s commit message says, and the difference matters.**

That message characterised the withheld retire as "a bounded and recoverable leak" — one
Device, one enforcer, a lingering old key. Two consequences were missing:

1. **The gateway never rotates again.** `Rotation::on_directive` is honoured **only from
   `Idle`** (`rotation.rs:62-73`), and `handle_rotate` logs-and-returns otherwise
   (`main.rs:3747-3754`). A rotation parked in `CutOver` because the watch set is
   permanently empty means **every subsequent `RotateDirective` is silently dropped for the
   life of the process.**
2. **The old private key is never scrubbed.** `service_retire` is what calls
   `EpochKeys::retire` + `persist`. It never runs, so the retired key stays in
   `epoch_keys.json` — *the security half of the rotation never happens*. A restart does
   not fix it: `select_boot_key` promotes, it does not retire.

Reachable: a two-gateway fabric where the peer is decommissioned after this gateway has cut
over. `ds.peers` loses it permanently → every entry becomes `Gone` → the watch set is empty
forever.

For completeness, and **pre-existing rather than introduced here**: a gateway with *zero*
peers cannot complete a rotation at all — `any_live` over an empty set is false, so it
wedges in `Overlapping` and equally never rotates again.

**The chosen direction is still right.** A wrong retire destroys a key live peers depend on;
that is an outage. Withholding it is the safe side. What was wrong was the *description*,
and the fact that a state this consequential was announced by a single `eprintln!` on a loop
that runs five times a second. The warning now names all three consequences explicitly
(`main.rs:4699`). It still deserves a metric rather than a log line — folded into the
F2/F5 observability work, which already needs a channel out of the non-`Send` run task.

## R2b — the same wedge, reached by an ordinary transient error (found by CodeRabbit)

`main.rs:3747` advances the phase to `Overlapping` via `on_directive`, and *then*
`handle_rotate` does fallible work: `plan_tunnel(...)?`, `tunnels.bring_up(...)?`, the
enforcer attach, `uapi::apply`, `submit_epoch_key`. **Any `?` returning `Err` leaves the
phase non-`Idle` with no reset path** — the only transition back to `Idle` is
`rotation.rs:94`, after a completed retire. So the gateway lands in exactly R2's dead end:
every subsequent `RotateDirective` silently ignored for the life of the process, old key
never scrubbed.

**This is far more reachable than R2.** R2 needs a peer decommissioned mid-rotation; this
needs one transient failure — a `bring_up` that loses a name race, an enforcer attach
refused on a restricted host, a `submit_epoch_key` that hits a closed channel.

Not fixed here on purpose. A correct reset must **unwind partial setup**: by the time
`submit_epoch_key` fails, the tun may be up, the enforcer attached and the epoch key
persisted, so a bare `phase = Idle` would leak all three and the next directive's
`bring_up` would bail "already has a tunnel up" — trading a wedge for a different wedge.
That is real work with its own test, and adding a fifth fix with unwind semantics to this
branch is how the four bugs above got written.

Latent in production today, because automatic rotation is disabled fabric-wide.

## R1 — the F1 gate protects the map mutation, but not the route write derived from it

`main.rs:4790` (gate ends) → `:4806` (`place_peer_routes`).

The verdict block releases the `role_b` lock, and `place_peer_routes` then programs routes
from `b.new_tun` / `b.built_at_own_epoch` taken from the **clone**, outside any gate.

Interleaving: the gate returns `Apply` and sets `cut_over = true` on entry E1
(`wg0o0`, epoch 5); the lock is released; the run thread does `maybe_start_role_b` →
`Restart` → `retire_stale_overlap` removes E1, re-derives routes onto the active tun,
tears `wg0o0` down, and brings E2 up on `wg0o1`; the tick thread resumes and calls
`place_peer_routes` with `Some(("wg0o0", claim{cut_over: true}))`. With
`built_at_own_epoch == active_epoch`, `route_owner` returns `OverlapTun`, so the peer's
CIDRs are `ip route replace`d onto a Device that is being deleted — and the kernel flushes
them when the link goes.

Recovery is slow: `apply_state` programs from `reconcile::route_diff`, a **delta**, so an
unchanged roster re-adds nothing. The CIDRs stay blackholed until E2's own Role-B cutover
proves live.

**Severity relative to F1: down roughly two orders of magnitude, not eliminated.** The
window is now milliseconds — `place_peer_routes` shells out to `ip` per CIDR and the two run
on different OS threads — where F1's was the hundreds of milliseconds of a fresh mTLS
channel.

Fix shape, which needs no change to the tick: have `retire_stale_overlap` **re-assert the
routes after `tear_down`** rather than only before it. Then it wins the race
unconditionally.

The same structural gap exists at the collapse arm (`:4940` → `:4950`) and at the Role-A
cutover's per-peer `role_b` read (`:4553` → `:4558`), but in both the racing and stale
outcomes agree (`ActiveTun`), so they are benign.

## Minor, recorded so they are not rediscovered

- **R6.** `MAX_QUARANTINE`'s doc (`tunnelset.rs:113-122`) claims "at least 32 slots and 32
  ports are always allocatable no matter how hard the gateway churns". True only while live
  rotation tuns number ≤ 32; the actual guarantee is "quarantine can never consume more
  than half the window".
- **R7.** `QUARANTINE` is 5s but `send_epoch_ack` carries a 10s connect timeout, so an
  ifname can be recycled while a write-back naming it is still in flight. The
  `pending_epoch` axis still discriminates, so this is not exploitable — but `53c20c3`'s
  "F1 is now guarded twice" holds only for awaits shorter than `QUARANTINE`.
- **R8.** F3's fix is a no-op when the `Gone` peer is the *last* one: with F4's guard the
  stall simply moves from "watching a key the device lacks" to "empty watch set". The
  improvement is real for the multi-peer case, which is the shipped shape.
- **R3.** `overlap_write_back`'s 9 tests exercise a pure six-line `match`. The parts of the
  F1 fix that could plausibly be wrong — capture before the awaits, evaluation under the
  same guard as the mutation, three call sites choosing skip vs continue, and R1's route
  write — have no coverage. The file says so itself.

## What the review confirmed, so it is not re-litigated

- All three deferred `role_b` write-backs are gated, with check and mutation inside one
  guard scope, and `taken` captured *before* the awaits.
- `Replaced` vs `Vanished` are used correctly, and `continue` is safe at each site:
  `retire_stale_overlap` is the only concurrent remover and it cleans the route claim, the
  pin, the Device and the enforcer, so an abandoned pass strands nothing.
- The quarantine is bounded, ordered correctly for oldest-first eviction, and `bring_up`'s
  three-axis retain cannot double-report a live resource. `MAX_ROTATION_TUNS` is still a
  hard error — `plan_port` uses `checked_add`, so an overflowing window truncates.
- No lock-order inversion and no guard held across an `.await`.
- `post_cutover_key_iff_device_config_pinned_keeps_the_peer` is genuine, not tautological:
  it re-derives the selection independently, so a change to the writer's precedence would
  fail it.
- The `#[ignore]` weakens nothing — doc comment plus attribute only.
- **The four F6 netns tests HAVE been run green** (4 passed, 7.58s), contrary to what
  `301cdc2`'s message says, and R4's skip note did **not** print, so the `MAX_QUARANTINE`
  eviction path was genuinely exercised rather than skipped.
