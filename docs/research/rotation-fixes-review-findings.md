# Independent review of the three in-step rotation fixes

**Reviewed:** 2026-08-05, by an agent that wrote none of the code.
**Scope:** commits `dc3d0bb` (tun/port de-collision), `451115c` (live-enforcer gauge),
`a5e9fb6` (`route_owner`), `5a5f644` (`new_epoch_watch_keys`).

The reviewer worked without a compiler (no cargo on the host, did not enter the container)
and said so.

## Confirmed sound

- **`TunnelId` + the `e`/`o` namespace split is structural, not probabilistic.**
  `plan_ifname` cannot produce the same name for an `Own` and an `Overlap` for any input.
  `plan_port` allocates against `tunnels.plans()`, which includes the boot tun, and the
  boot port is excluded *structurally* by starting at offset 1 rather than by a check that
  could be forgotten. Every unwind path (attach-fail, `apply_if_changed`-fail,
  `uapi::apply`-fail, `service_retire`, `service_role_b_collapse`, `retire_stale_overlap`)
  either removes the enforcer entry or never inserted one.
- **`5a5f644`'s "pre-cutover is bit-for-bit unchanged" claim is TRUE.** Verified against
  `rotation.rs:370-372`: `wanted`, `any_live` and `all_live` are literally the same sets as
  before, order preserved. The one delta — `phase` now read *before* `read_live_peers()`
  rather than after — was traced through all three writers of `phase` and is not
  observable, because `role_a` is `None` on both sides of the windows that would matter and
  `handle_rotate` sets `phase` before `role_a`. **The cutover timing is unchanged.**
- **`route_owner` is total** and could not be made to name a dead device given a
  self-consistent `role_b` entry, except via F1.
- **No lock-order inversion and no `std` guard held across an `.await`.** The only nestings
  anywhere are `desired → wg0_pins → live_endpoints` and `role_b → wg0_pins`; nothing takes
  either pair in the opposite order.

## Findings

### F1 — HIGH. Epoch-unqualified Role-B write-backs, made racy by our own `Restart` path

The rotation tick clones `pending_b`, `.await`s `read_live_peers` and `send_epoch_ack` (a
fresh mTLS channel, hundreds of ms), then writes back via `role_b.lock().get_mut(&aid)` —
keyed on peer id ONLY, never on `pending_epoch` or `new_tun`.

Before `dc3d0bb` this was safe: the sync loop's `contains_key(&gid)` guard meant an entry
was never replaced while it existed. `RoleBDecision::Restart` removes and re-inserts, which
destroys that invariant. **We introduced this.**

Consequences when the entry is swapped mid-`await`: `done = true` lands on the *new* epoch's
entry, permanently filtering it out of `pending_b` so it never gets its cutover or ack;
`cut_over = true` lands on an entry whose session was never observed, and `place_peer_routes`
then points a peer's CIDRs at a Device with no live session — a direct make-before-break
violation. The collapse arm has the same shape and is worse: it removes the *new* entry and
tears down the *old* id, orphaning a live Device+enforcer that nothing will ever collapse,
after which `bring_up` bails "already has a tunnel up" forever.

**Status: being fixed.** Every write-back becomes epoch-qualified via a pure helper in
`rotation.rs`, testable in isolation.

### F3 — MEDIUM. `new_epoch_watch_keys` re-enters the stall through its fallback

`device_config_pinned` drops a peer entirely when there is no pin and `active_pubkey_b64`
is `None`. `new_epoch_watch_keys` instead falls back to the snapshot for BOTH "no key
selected" and "key won't decode". In the former case it watches a key the device provably
does not hold → `all_live` false every tick → the old Device and enforcer are never torn
down. That is exactly what `5a5f644` was written to prevent, re-entered one branch over.

Latent today — the reviewer could not prove the controller ever emits a peer with keys but
no `active` row (`projection.rs:44-46` only withholds the awaiting-submission pending row).
Fixed anyway, because it is the precise drift the function exists to make impossible.

**Status: being fixed.** `None` ⇒ `Gone`; snapshot fallback kept only for an undecodable
`Some`.

### F4 — MEDIUM-LOW. `all_live` vacuously true when the watch set empties

Post-cutover, peers that left `rot.desired` become `Gone` and are filtered out; an empty
`wanted` makes `.all(...)` vacuously true and the retire fires. Newly reachable, since
pre-fix `a.peers` was fixed at directive time and could not shrink.

Genuinely ambiguous: if the peers really left, retiring is correct and safe; if
`rot.desired` is transiently truncated, retiring destroys a key live peers still need.

**Status: being fixed, direction to be recorded with the change.**

### F6 — LOW mechanically, but it makes F1 deterministic

`plan_ifname` hands back the lowest free slot, so on the `Restart` path a new Device is
created on the *same ifname* microseconds after the old `Tunnel` dropped, with no await
between. `Tunnel::up` waits for the UAPI socket to *appear* — a not-yet-unlinked socket
from the dropped Device satisfies that instantly. And `tear_down` only logs an `ip link del`
failure, so the next allocation deterministically picks a name that is still occupied.

**Status: being fixed.** Monotonic or quarantined slot allocation.

## Deferred, with reasons

### F2 — MEDIUM. The gauge cannot express the alert it was written for

`map.len()` is the right source, but a *displacing* insert leaves `len()` unchanged. The
real signal is "N tuns, N−1 enforcers", and N is not exported — there is no
`live_tunnels` gauge. The doc at `metrics.rs:158` names an alert an operator cannot
actually write against this scrape. It works in the netns test only because the test counts
interfaces itself.

Also: `live_enforcers` is computed at `main.rs:736` but the same closure then does
`per_tun.push(e.counters()?)`, so any enforcer error turns the whole body into
`# error collecting counters` — losing the "always emitted" property exactly when something
is wrong.

**Deferred** because exporting `live_tunnels` needs a channel out of the run task
(`tunnels` is non-`Send`), which is a structural change to the same run loop the endpoint/
port fix will rework. Do it with that work, not before it. The `?`-in-closure issue is
independent and small — fix it whenever the metrics file is next touched.

### F5 — LOW. `MAX_ROTATION_TUNS = 64` is an undocumented fabric-size ceiling

A rotating gateway holds one own tun plus one overlap per peer, and `initiate_due_rotations`
rotates everyone at once, so a fabric of 65+ gateways exhausts both windows on every
rotation. The failure is a per-peer `eprintln!` + `continue` — no metric, no report to the
controller — and affected peers then take the rule-4 grace-promote onto a key that was
never established. The comment justifies 64 as "far beyond any plausible fan-out", which is
true per-*rotation* but not per-*fabric* under the in-step design.

**Deferred** to the same work as F2 (both are observability of rotation limits), but the
bound should be documented as fabric-size-dependent regardless.

## The reviewer's closing point, which matters most

F3 and all of `5a5f644` are **gated on the unfixed endpoint/port bug**. The apply that
rekeys a rotated peer on the new tun is `device_config_pinned`, which rebuilds endpoints at
the BASE port — so the same apply that makes the watch key correct destroys the offset-port
session the watch is looking for. In the field `all_live` may still never come true and the
old epoch may still never retire, for a *different* reason than the one `5a5f644` fixed.

See [`rotation-endpoint-and-port-model-is-broken.md`](rotation-endpoint-and-port-model-is-broken.md).
