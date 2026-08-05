# In-step rotation: the two cutovers fight over the peer route

**Found:** 2026-08-05, by the T3 done-bar (`in_step_rotation_of_both_gateways_stands_up_own_and_overlap_tuns`).
**Status:** **FIXED** by `a5e9fb6` (`rotation::route_owner` — ownership derived once rather
than written by whichever cutover finishes last). Verified 2026-08-05: the in-step run then
showed `routes on wg0e1 (ActiveTun)` on both gateways, where it had previously shown
`wg0o0`. Option 2 below is what was built. Originally: deterministic, reproduced on two
independent clean-tree runs.
**Not** a regression in T3 — T3's de-collision is verified working; this is downstream.

## What T3 fixed, and what it did not

T3 fixed the collision: both gateways now stand up their own new-epoch tun **and** an
overlap toward the rotating peer at the same epoch number, with all three enforcers
attached, and traffic flows across the overlap. Observed peak on both sides in one sample:

    paired_peak = ({lo, und, seg0, wg0, wg0e1, wg0o0}, 3)   # 2 extra links, 3 enforcers
    TRAFFIC PASS: transmitted=17 received=15 (gap 2 <= 6)

**But the settled state after both rotations complete has no connectivity.** The case fails
at its post-rotation ICMP check, not at the T3 assertion.

> **Read the rest of this note as historical evidence, not as the current failure.**
> `a5e9fb6` fixed the arbitration: routes now land on `wg0e1 (ActiveTun)` on both gateways,
> where the dumps below show `wg0o0`. The case still fails, but for a *different and
> unrelated* reason — the post-cutover endpoint dials the peer's base port while the peer
> listens on an offset port. See
> [`rotation-endpoint-and-port-model-is-broken.md`](rotation-endpoint-and-port-model-is-broken.md).

## Mechanism (as observed BEFORE `a5e9fb6` — historical)

Both gateways end with the peer route on the **Role-B overlap** device rather than on their
own new-epoch tun:

    gwA: 10.10.2.0/24 dev wg0o0 scope link
    gwB: 10.10.1.0/24 dev wg0o0 scope link

The stderr ordering is identical and symmetric on both gateways:

    Role A minted epoch 1 on wg0e1:51821
    Role B overlap Device up on wg0o0:51822 toward peer 2 epoch 1
    Role A cutover — routes flipped onto wg0e1 (epoch 1)
    Role B collapse armed for peer 2 … wg0 unpinned, awaiting live base-tun session
    Role B cutover — peer 2 epoch 1 live; routes on wg0o0, epoch ack sent   <-- clobbers Role A

The Role-B cutover runs *after* the Role-A cutover and re-points the peer's CIDRs at the
overlap device. `wg0` also still carries the peer's retired epoch-0 key, and neither
`wg0e1` nor `wg0o0` shows a completed handshake in the failing state.

**Why it was never seen:** in a one-sided rotation only ONE of the two cutovers ever runs,
so their ordering could not matter. In-step rotation is what `initiate_due_rotations`
produces by default (every active gateway, one tick, one global 30-day timer), and nothing
in the suite constructed it until now. Exactly the same blind spot that hid the collision
itself.

## Consequence for the 2026-08-31 outage

**T3 alone does not fix it.** It converts "neither side overlaps, both wedge" into "both
sides overlap, traffic flows during the window, then the peer route is stranded on a device
that is about to be torn down". Both are fabric-wide outages on the first timer fire. The
in-step scenario needs this fixed too before the timer can be trusted.

The mitigations from the plan verification still apply in part: jitter does not help (this
is ordering between two cutovers, not simultaneity of their starts). **The "`rotation_interval`
is hardcoded, so a controller restart is the only zero-code lever" claim is obsolete as of
v0.7.0** — `WIREMESH_ROTATION_INTERVAL=off` now disables the timer outright, and it is set
on the live controller.

## What to look at

The two cutover paths and what each believes it owns:

- Role A's cutover flips the peer's CIDRs onto the new active tun and moves
  `ActiveTunInfo`.
- Role B's cutover (the collapse path) re-points that same peer's CIDRs at the overlap
  device it built, because in the one-sided case that IS where the peer's traffic should go.

Both are individually correct. They need an arbitration rule for the case where the *same
peer* is both "the peer I built an overlap toward" and "a peer whose route my own cutover
just moved". Candidates, unassessed:

1. Role B's cutover writes the peer route only if the peer's CIDRs currently point at the
   base tun — i.e. never overwrite a Role-A cutover's decision.
2. Route ownership becomes explicit (which tun a given peer's CIDRs belong on is derived
   once from active-epoch + overlap state, rather than written by whichever path finishes
   last).
3. Role B's collapse completes before Role A's cutover is allowed to flip, serialising the
   two — likely the most invasive, and it lengthens the overlap window.

Option 2 is the shape that removes the class rather than the instance, and it is close to
what F8 ("Role B has no active-tun awareness") already asks for — so these should probably
be fixed together.

## Evidence

`crates/wiremesh-gateway/tests/key_rotation.rs::in_step_rotation_of_both_gateways_stands_up_own_and_overlap_tuns`
fails at its post-rotation ICMP assertion. The T3 assertion and the traffic-during-overlap
assertion both PASS, which is what localises the fault to the settled state. The case's
sampling summary and the route dumps above are printed on failure.
