# Key-rotation old-epoch teardown — known limitations (Step 2/3)

Status: the epoch-aware device unification + old-epoch teardown is implemented and
proven by `crates/wiremesh-gateway/tests/key_rotation.rs::old_epoch_device_is_torn_down_after_rotation`
(commit `a538967`): after a Role-A gateway rotates and every peer is rx-corroborated
live on the new tun for `RETIRE_GRACE` (= `2 * ROTATION_KEEPALIVE`), the old epoch's
boringtun `Device` is torn down (`TunnelSet::tear_down`, dropping the old private key
from memory before the `ip link del`) and its enforcer evicted. Make-before-break is
preserved (teardown only from `CutOver`, only after full-peer grace; the OLD epoch is
retired, never the live one). Full non-regression green (lib 76, key_rotation 4/4,
mesh_milestone, nat_matrix 4/4, relay_matrix 2/2).

The following are KNOWN LIMITATIONS in scenarios the done-bar does NOT exercise. None
is a regression; each is a focused fast-follow. Recorded per the cycle's
documented-limitation discipline (cf. the one-way-UDP divergence and the boringtun
`own_public_key` finding).

## A. (TOP must-fix) Post-cutover DEVICE churn applies base-port peer endpoints to the offset-port tun
The new tun is brought up (`handle_rotate`) with `reconcile::device_config_at_port` —
peer endpoints rewritten to the OFFSET port. But the active-tun apply path
(`apply_state`, `set_peer_endpoint`, the cutover change-guard seed) recomputes
`reconcile::device_config_pinned`, whose peer endpoints come from `primary_endpoint()`
= the peer's BASE port. The change-guard seed at cutover masks this for the UNCHANGED
config (the byte-identical recompute is a no-op, so the live offset-port session is not
disturbed). But a LEGITIMATE post-cutover device change — a peer CIDR add/remove, an
`EndpointObserved` candidate change, or a punch/relay `set_peer_endpoint` — recomputes a
DIFFERENT `device_config_pinned` and DOES apply, pushing BASE-port peer endpoints onto
the live OFFSET-port tun → the WG session silently black-holes (no crash, no assertion).
The done-bar's post-teardown change is policy-only (the enforcer loop, correctly reaching
the active tun via Step 1), so it never triggers this.
FIX: thread the offset-port endpoint rewrite through the active-tun apply path — the
apply sites must build peer configs with the active epoch's port offset (like
`device_config_at_port`/`pending_peer_configs` do), not `device_config_pinned` (base
port). Needs a post-cutover endpoint/CIDR-change test. Until then: post-cutover device/peer
churn on a rotated gateway is UNSUPPORTED.

## B. Post-rotation NAT re-punch binds the wrong port
`PathCtx` uses a fixed `base_wg_port` for the SO_REUSEPORT punch socket (correct: binding
the active/offset port would let the punch socket steal the live new-tun's inbound
datagrams — the real regression this fix avoided; non-regressive for no-rotation since
base == active, nat_matrix green). But post-cutover the live session is on the OFFSET
port while the punch binds the BASE (idle/retired) port, so a Degraded NAT'd peer that
needs a re-punch AFTER a rotation opens a hole on the wrong port and can't restore the
direct path. Rotation × NAT-repunch is untested and unhandled; relay is the fallback.
Acceptable edge case for now; fix alongside A (the active-port punch needs the same
active-tun awareness).

## C. Retirement is process-local; a reboot resurrects the retired epoch — FIXED for locally-cut-over rotations (Backlog 3 Task 1)
**STATUS: fixed by Backlog 3 Task 1 for rotations whose LOCAL cutover ran** (the store
records local promote/retire transitions only). **Known residuals, still open:**
(i) the controller's Rule-4 ack-less grace-promote is NOT reconciled down into the
store — a rotation whose new-epoch session never established locally but was
grace-promoted controller-side leaves the store pending-only, so a reboot falls back
to the legacy key, which post-promote no peer advertises (the original black hole,
surviving in that corner; T2 territory — see `select_boot_key`'s KNOWN RESIDUAL doc).
(ii) The retire scrub destroys key material in `epoch_keys.json` ONLY: the epoch-0
private key remains on disk in `identity.json`/`wg_private.key` (enrollment identity is
never rewritten), and deleting `epoch_keys.json` re-arms the legacy fallback to boot it
(absent file → fallback by design; corrupt file → fail-loud at load). Test-author note:
`tests/epoch_boot_key.rs`'s header (lines ~20-29) frames the selector as fixing the
Rule-4 grace-promote reboot — stale per (i); the selector only fixes the
locally-cut-over case. The lifecycle is now
wired and durable: the Role-A FlipRoutes cutover arm (`run_rotation_ticks`, main.rs)
drives `EpochKeys::promote(new)` + `persist` the moment the data plane flips, and
`service_retire` drives `EpochKeys::retire(old)` + `persist` alongside the Device
teardown — `retire` REMOVES the entry, so the retired private key is scrubbed from
`epoch_keys.json`'s bytes, not left dormant. Boot now selects its key via
`EpochKeys::select_boot_key` (store's ACTIVE epoch wins; legacy `Identity` key only as
fallback when no active entry exists), always on the base tun/port per OD-1. Evidence:
`crates/wiremesh-gateway/src/epochkeys.rs` (`select_boot_key` + module doc),
`crates/wiremesh-gateway/tests/epoch_boot_key.rs` (selector contract),
`crates/wiremesh-gateway/tests/epoch_persistence.rs` (promote/retire persistence +
raw-bytes scrub), and `crates/wiremesh-gateway/tests/key_rotation.rs`
`rotation_survives_gateway_restart_on_new_epoch` (SIGKILL + restart boots the promoted
key, retired priv absent from disk, traffic reconverges, OD-1 re-normalization).
Original finding kept below for the record:
`EpochKeys::promote()`/`retire()` are never called in `main.rs` (only `generate_next()`),
and boot ALWAYS brings up epoch 0 from `id.wg_private_key_b64` (hardcoded epoch 0),
independent of the persisted store. So after a rotation the store still reads
`epoch 0 = active, epoch 1 = pending` (diverged from the live Devices), and after a
rotation + REBOOT the gateway comes back on the RETIRED epoch-0 key as its live device.
The Step-2/3 security goal ("old private key gone from any LIVE Device") is met for the
RUNNING process — and robustly (the boringtun Device is dropped before the best-effort
`ip link del`, so even an `ip link del` failure doesn't leave the key live). But the
retirement is NOT durable: it is process-local until rotation PERSISTENCE lands
(`EpochKeys::promote/retire` wired at cutover/retire + the boot identity swapped to the
active epoch's key + the controller-side promote reconciled with the boot key). Track as
a fast-follow; qualify the security claim as "process-local until rotation persistence."

## D. (Minor) Role-B post-cutover CIDR churn routes via wg0 — PARTIALLY FIXED (Backlog 3 Task 1 slice)
Role B deliberately never flips `active` (it isn't rotating its own key; flipping would
mis-apply its `wg0` pin) — correct. Consequence: a NEW CIDR added to an already-rotated
peer on the Role-B side, post-cutover, routes via `wg0` (active) rather than the overlap
tun; a removed CIDR's `del_route(cidr, wg0)` no-ops and can leak the route on the overlap
tun. Existing peer CIDRs ARE explicitly flipped onto the overlap tun at cutover, so this
is a narrow untested churn scenario. Low impact; fold into the multi-peer overlap work.

**Backlog 3 Task 1 shipped the minimal Role-B COLLAPSE (reverse make-before-break),
the core slice of the ratified plan's Task 3.** The un-collapsed overlap was the fatal
half of this finding: after the peer's rotation completed, the surviving gateway kept
routes + a frozen offset-port endpoint on `wg0e<N>` forever while stale `wg0` held the
peer's retired key — so a peer that later rebooted onto the base port (item C's fix, OD-1)
could never re-reach it (base-port punch confirms on the unrouted device). Now:
`maybe_collapse_role_b` (main.rs, State arm, BEFORE `apply_state`) detects the peer's
retire delta (roster collapses to active-only on the very key the overlap targeted),
unpins `wg0_pins[gid]` so that same apply rekeys `wg0` to the peer's new key, and arms
the collapse; the rotation tick then waits for a live rx-corroborated `wg0` session
toward the new key, flips routes back `wg0e<N>` -> `wg0`, and signals
`service_role_b_collapse` (run task) to tear the overlap Device down + evict its
enforcer + drop the `role_b` entry. The overlap is never torn down before `wg0` is
proven live. Runtime arbiter: `rotation_survives_gateway_restart_on_new_epoch`
(key_rotation.rs) — post-reboot traffic reconvergence requires the collapse.

**Remaining — named follow-ups:**
- **(F2)** [T2 territory] `promote(epoch)` promotes by EPOCH NUMBER, so after a
  crash + re-directive an orphaned stale `"pending"` entry at that number can be the one
  promoted instead of the freshly minted key. Mechanics: promote by minted key identity
  (or purge stale pendings at mint time).
- **(F3)** [T3 per-peer keying — PRIORITIZED] boot-epoch tunnel keying: a rebooted-once
  gateway's BASE tun sits in `TunnelSet`/`enforcers` under key 1, so a peer rotating to
  pending epoch 1 collides — `maybe_start_role_b`'s `bring_up` bails on EVERY State
  event and the overlap never forms. Same root as our-own-rotation epoch-N collisions.
- **(F4)** [small dedicated task] a crash inside the local retire grace orphans the old
  epoch's `"retiring"` entry — with its private key — in `epoch_keys.json` forever
  (nothing retires it post-reboot). Mechanics: mirror the controller's boot-time orphan
  cleanup — scrub non-active leftovers at load/boot.
- **(F8)** [T3] the collapse pass hardcodes `rot.base_tun` as the watch/flip target — if
  our OWN rotation cut over concurrently (active tun now `wg0e<N>`), the collapse
  watches/routes the wrong device and wedges. Needs active-tun awareness.

**Remaining — unnamed (full Task 3):** (1) re-rotation of the same peer while an overlap
exists is skipped by `maybe_start_role_b`'s `contains_key` guard (and a collapse-armed
entry blocks a fresh overlap until it completes); (2) multi-peer overlap (one
single-purpose Device per rotating peer; concurrent rotations untested); (3) the collapse
cannot COMPLETE while the rotated peer stays on its offset port (its base port has no WG
listener post-retire — pairs with findings A/B; the overlap keeps carrying traffic until
the peer re-normalizes, e.g. reboots, so nothing breaks — it just defers); (4) a peer
REMOVED from the roster mid-overlap leaks its overlap Device/routes (no collapse trigger
fires); (5) the original post-cutover CIDR-churn note above still stands for the
overlap's lifetime.

## E. A wrong-but-real epoch key does NOT fail safe — rule 4 promotes it anyway (found 2026-08-04)

Found while assessing whether `Sync.SubmitEpochKey` needed the Sync session-generation
gate (Backlog item 2). The *submission* race is now closed there; **this half is not, and
belongs to the key-rotation item.**

`rotation::decide` (rotation.rs:55-110) has no path that rejects a real key nobody can use:

- **Rule 2** refuses to promote a pending epoch still holding the `awaiting-submission`
  sentinel, and past `ABORT_AFTER` it aborts. This is the ONLY abort path — its own
  comment at rotation.rs:89-92 says so: *"abort is only reachable via rule 2's no-real-key
  branch."*
- **Rule 3** promotes early once every expected peer has acked live.
- **Rule 4** promotes on the `GRACE_PROMOTE` timeout **regardless of ack state**.

So the ack signal is an accelerator, never a veto. If the controller ends up advertising a
real pubkey that the gateway is not actually serving on that epoch's tun, no peer can
establish a session, no peer can ack — and rule 4 promotes it to `active` at 90s anyway.
The rotation completes "successfully" onto a key that cannot carry traffic, and the prior
active epoch is subsequently retired. That is a wedged gateway, reached without any
component reporting an error.

How the controller could come to advertise such a key (the shape that led here, now closed
on the Sync side): `Db::set_epoch_pubkey` (db.rs:1903-1908) is a compare-and-swap onto the
sentinel, first writer wins. With a submission in flight across a gateway restart,
`Broker::send_rotate_if_pending` (broker.rs:482-502) re-issues a `RotateDirective` for the
still-sentinel epoch; the new process mints a *different* key (`EpochKeys::generate_next`
allocates `max(epoch)+1`, epochkeys.rs:79) but submits it under the *directive* epoch —
there is even a WARNING log for that mismatch at main.rs:3680-3686 — so two different
pubkeys race for one epoch and the pre-restart one usually lands first. Session generation
now rejects the stale submission, so this particular producer is gone.

**Why it still matters:** the CAS race was one producer, not the only one. Rule 4's
unconditional promote means *any* future path that installs a key the gateway is not
serving degrades from "rotation stalls and aborts" to "rotation promotes a dead key". The
fail-safe is missing, not merely unused.

FIX (key-rotation item, not scoped here): rule 4 should not promote with **zero** live
acks when `expected_peers` is non-empty — that state is indistinguishable from "the key we
advertised is unusable". Options: abort instead of promoting when `live_acks.is_empty() &&
!expected_peers.is_empty()` at the grace deadline; or keep promoting but only after a
longer no-ack deadline, so a genuinely quiet-but-correct fabric still converges. Note the
tension rule 4 exists to resolve — a peer that is simply offline must not block a rotation
forever — so the fix is a threshold question, not a straight inversion. Needs a decision
plus a `decide()` unit case (the module is pure and injectable-`now`, so it is cheap to
pin).

---
## Concrete implementation plan for Fast-follow A (worked out 2026-07-22, ready for a fresh session)
Exact code sites (main.rs / reconcile.rs on branch worktree-key-rotation @ a530c33):
1. `reconcile.rs`: add `pub fn device_config_pinned_offset(ds, private_key_b64, listen_port, keepalive_secs, pinned_pubkeys, port_offset: u16) -> DeviceConfig` — identical to `device_config_pinned` (reconcile.rs:76) EXCEPT each peer's `endpoint` is the peer's `primary_endpoint()` with its port SHIFTED by `port_offset` (parse `ip:port` via rsplit_once(':'), `port.checked_add(port_offset)`, skip peer on malformed/overflow). When `port_offset == 0` this is byte-identical to `device_config_pinned` (a peer at `ip:51820` → `ip:51820`) → NON-REGRESSIVE BY CONSTRUCTION. (Mirrors the relative-offset logic already in `pending_peer_configs`.)
2. `main.rs` `ActiveTunInfo` (struct at ~main.rs:94): add field `port_offset: u16`. Set it: boot (~main.rs:171) `port_offset: 0`; cutover (~main.rs:1859, the `*rot.active.lock() = ActiveTunInfo{...}` in run_rotation_ticks Role-A FlipRoutes) `port_offset: new_port - rot.base_wg_port` (the same `offset` already computed in handle_rotate; recompute as `a_new_port.saturating_sub(rot.base_wg_port)`); test-ctx (~main.rs:1983) `port_offset: 0`.
3. Replace the 3 active-tun `reconcile::device_config_pinned(...)` calls with `device_config_pinned_offset(..., active_port_offset)`, reading `port_offset` from the `active` lock alongside ifname/priv_key/wg_port: `set_peer_endpoint` (~main.rs:825), `apply_state` (~main.rs:1317), and the cutover SEED (~main.rs:1850). The seed MUST use the same offset so its fingerprint matches what apply_state/set_peer_endpoint will recompute (keeps the no-op-on-unchanged property) while a real change now applies OFFSET-port endpoints.
NON-REGRESSION: every non-rotation gateway keeps `active.port_offset == 0` → identical to today (nat/relay/mesh green by construction). NAT'd peers post-rotation remain Finding B (the relative offset is wrong behind NAT) — still unsupported, still documented.
TEST (Finding-A repro): `post_rotation_device_change_keeps_session_alive` — direct mesh + netem; rotate gwA to completion; then `h.apply(fabric_v2)` adding a 2nd CIDR to seg-b (changes gwA's peer allowed_ips → a device re-apply); assert the ORIGINAL wlA→wlB flow (ICMP + tcp/8080) STILL crosses. RED without the fix (base-port endpoints black-hole the offset-port session); GREEN with it. Verify + full non-regression (nat/relay the gate) as in the Step-2 brief.
