# The Role-A cutover gate is fabric-wide, but the action it gates is per-peer

**Found:** 2026-08-05, while fixing the third in-step rotation bug.
**Status:** open, deliberately NOT fixed on `fix/key-rotation-t2-t7`.
**Needs ≥3 gateways to bite.** Every test in the suite today uses a pair, so nothing
covers it and nothing regresses if it is left alone.

## The shape

Role A's cutover is gated on `any_live` — *some* peer has a live session on the new
epoch's tun — and then places routes for **every** peer:

```
if any_live {
    for peer in peers {
        place_peer_routes(peer, active_tun)
    }
}
```

With two gateways `any_live` and `all_live` are the same predicate, so the gate is exactly
right and the loop body is trivially correct. With three or more, one peer completing its
handshake on the new tun moves *all* peers' CIDRs onto a device the others have no session
on. Their traffic blackholes until they individually complete — which they will, because
the peer set was written to that device and the keepalive keeps initiating, but the window
is unbounded by anything in the code and is as long as the slowest peer's handshake.

`all_live` would be the wrong correction: one unreachable peer would then hold the whole
cutover hostage indefinitely, which is worse than a bounded per-peer stall. The gate is
fabric-wide because it was written for a decision that genuinely is fabric-wide (is this
tun usable at all), and it got reused for one that is not.

## Why it is cheap to fix later

`place_peer_routes` is already per-peer as of `a5e9fb6` — the route-ownership fix made it
so for unrelated reasons. Gating each peer's placement on that peer's own liveness is a
two-line change: keep `any_live` as the "the tun works" precondition, and add the peer's
own liveness as the per-peer condition inside the loop.

The reason to do it *later* rather than now is that it is unobservable without a
three-gateway harness, and this branch has no such harness. Fixing an unobservable bug is
how the last three bugs on this branch got shipped in the first place. **Build the
three-gateway case first, watch it fail, then fix it** — that is T7 (harness + multi-peer)
in the item-5 task list, and this note is its first concrete done-bar.

## Relationship to the in-step bugs

Independent of all four. The in-step bugs are about two gateways rotating simultaneously;
this is about one gateway rotating with several peers, whether or not they rotate. They
share only the observation that has now held five times on this branch: **a predicate
written for one question gets reused for a neighbouring question it does not answer**
(`base_tun` vs the active tun, a directive-time key snapshot vs the current key, `any_live`
vs this peer's liveness).

See [`key-rotation-plan-verification.md`](key-rotation-plan-verification.md) and
[`in-step-rotation-cutover-arbitration.md`](in-step-rotation-cutover-arbitration.md).
