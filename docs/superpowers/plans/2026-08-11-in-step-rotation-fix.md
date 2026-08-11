# Plan: fix the in-step rotation blocker (backlog item 3)

**Status:** designed, NOT implemented. Read `docs/research/in-step-rotation-rebaselined.md`
first — it carries the verified mechanism this plan is built on.

## The framing that was tested and REFUTED

A candidate framing held that the defect was *supplying* an endpoint where
`device_config_at_port` deliberately supplies `None` ("receive-and-roam, never dial"), and
that the fix was to stop clobbering a correct roamed value.

**Half right, and the actionable half is wrong.** Verified against the code:

- `maybe_start_role_b` brings the overlap up with `a.priv_key` — our CURRENT active key,
  i.e. **epoch-0** pre-cutover — and records `a.epoch` as `built_at_own_epoch`.
- The collapse gate reads `read_live_peers(&active_ifname, once(b.peer_pending_hex))` — it
  watches the ACTIVE tun for the **peer's epoch-1** key. The Role-A retire gate wants the
  same key via `new_epoch_watch_keys`.

So both gates require an **epoch1 ↔ epoch1** session. Our `wg0e1` peers the peer's epoch-0
key until the collapse-unpin rekeys it — **that rekey is correct and necessary, not a bug**.
Once both sides rekey, neither `wg0e1` has an endpoint and *no third party can send to
either*: the only remaining sender, the peer's overlap, runs a key our `wg0e1` no longer
holds. Roaming requires an inbound authenticated packet and there is no source for one.

**Leaving `endpoint: None` there parks both gates forever — a silent wedge, not a
diagnosable outage.** An endpoint at that site is mandatory.

## The distinction that explains why one-sided is green

> **One-sided: the base-port endpoint is EVENTUALLY correct. In-step: it is NEVER correct.**

One-sided — our `wg0` dials `peer:51820`, wrong while the peer sits on its offset port, but
the peer's retire is gated on *our overlap's* session, which is live. The peer retires,
`renormalize_active_listen_port` moves its key back to base, and our unchanged dial starts
working. Convergence by waiting.

In-step — the peer's retire is gated on the very session we cannot address. Circular.

That is stronger than "the recompute is currently a no-op", and it is why the one-sided
suite is green while this deadlocks.

## Recommended: Shape A + D, gated; defer C

**Gate for both:** `b.built_at_own_epoch != rot.active.epoch` — the same discriminator
`rotation::route_owner` already uses. It means our overlap and our active tun run DIFFERENT
private keys, so exactly one of ours matches the peer's key set at any instant. When they
are equal (every one-sided case) the new path is a literal no-op **by construction**.

**A — the rotation dial.** At the collapse arm, at the same moment `wg0_pins[gid]` is
removed, set `live_endpoints[gid] = own_tun_endpoint(peer.primary_endpoint())` — the peer's
`candidate_port + OWN_TUN_PORT_OFFSET`, where its active key lives between its cutover and
its retire. `maybe_collapse_role_b` runs immediately before `apply_state` on the same event,
so the very apply that performs the rekey carries the right endpoint. All three renderers
read that one map, so they agree by construction. No builder signature changes.

Deliberately NOT cleared at collapse completion: by then the pin equals the live session's
endpoint. It is superseded naturally — the read-through overwrites it once `Direct`; after
both retires the peer's keepalives arrive from base and boringtun roams. If the session
never comes up, `DEGRADED_AFTER` (45s) clears it and candidate-chasing recovery resumes.

**D — handshake kick during the collapse.** Our first init after the rekey is dropped if the
peer has not yet rekeyed; boringtun retries on `REKEY_TIMEOUT` ~5s, which at the flood's
`-i 0.2` is ~25 packets against a **≤6** allowance. Nothing currently kicks the active tun
during a collapse, on a rationale ("routes may still point at the overlap") that is FALSE
in the in-step case where our own cutover already won the routes. Gate identically.

**C — scoped rekey instead of `replace_peers` — DEFERRED.** `replace_peers` resets every
peer's session; with N peers that is N-1 innocent resets per rotation. But it is
**aggravating, not causal**, alone it turns nothing green, and **no test in the tree can
observe it** (both netns rotation topologies have exactly one peer). There is also a
recorded landmine: an early scoped remove+re-add prototype was rejected on evidence.
Defer behind a multi-peer test.

**Extract, do not restate:** `pending_peer_configs` already computes this exact endpoint.
Pull out `reconcile::own_tun_endpoint(candidate)`; two readers, one definition — the same
argument v0.7.2 used for the constant. An agreement test pins them together.

## Test strategy — unit first, netns last

Netns-first is wrong: ~2 min serial, and the file also holds
`direct_rotation_is_zero_drop`, which fails ~42% under host load.

1. **Pure unit** (new `tests/collapse_dial.rs`, following the one-file-per-decision
   precedent of `role_b_decisions.rs`): stranded overlap -> `Some(ip:base+1)`; **equal
   epochs -> `None`** (the one-sided non-regression, and the assertion that fails first if
   the predicate is later "simplified"); malformed/`u16::MAX` candidate -> `None`, no panic;
   and an **agreement test** that `collapse_dial` and `pending_peer_configs` emit an
   identical string for the same candidate — this is what stops the two derivations drifting
   apart again.
2. **Cheap netns regression** before the done bar: the one-sided suite plus
   `scoped_peer_apply`, `convergence_matrix`, `keepalive_emission`. One red
   `direct_rotation_is_zero_drop` is NOT evidence — interleaved A/B against `451e8ae` first.
3. **The done bar:** `in_step_rotation_of_both_gateways_stands_up_own_and_overlap_tuns
   --ignored --features netns-tests` (without the feature the binary compiles to ZERO tests
   and prints a false green). At least three runs, and read the log for the REASON —
   `wg0e1`'s endpoint must be `:51821` with a non-zero handshake. **A green run still
   showing `:51820` passed for the wrong reason.**

4. **Post-SETTLE reachability — PART OF THE DONE BAR, not a follow-up.** Ping after BOTH
   sides have renormalized, i.e. after the enforcer gauge returns to 1 on each.

   This was originally scoped as a separate follow-up. That was wrong, and a review caught
   it: the plan names the post-retire mutual pin as its sharpest availability risk AND
   states that this check is the only assertion that detects it. Deferring it means **the
   done bar can go green while both gateways are unreachable in steady state** — the exact
   failure the fix exists to prevent, merely relocated past the assertion window. A 45s
   degrade-and-recover path is not a substitute for proving steady-state reachability.

   Make it deterministic rather than hoping for the interleaving: drive the two
   renormalizations close together (or assert directly on the post-settle peer endpoint of
   each side, which is checkable without racing). If a deterministic near-simultaneous
   renormalize cannot be forced, assert the endpoints AND ping, and say in the test which
   part is timing-dependent.

## Risks

The enumerated regression surface is contained because the builder signature does not change
and the gate makes the new path a literal no-op for every peer in every existing test.

**The one to watch (now covered by done-bar tier 4, above):** after BOTH sides retire, both may be pinned at the other's `:51821`
while both listen on `:51820` — a mutual black hole. Mitigated by an existing detail:
`renormalize_active_listen_port` pokes every peer right after moving the port, and the first
side to renormalize pokes while the other is still on `:51821`. Residual risk only if that
poke is lost AND the renormalizations are near-simultaneous; recovery is then the 45s
degrade -> candidate chase. **This is the sharpest unmeasured claim in the design.**

## Open, and what would settle each

1. Whether the traffic assertion holds without D — reasoned from `REKEY_TIMEOUT`, not
   observed. *Settled by:* the done bar with and without the kick; the delta is the answer.
2. Whether `built_at_own_epoch != active.epoch` actually held in the failing runs — the
   load-bearing predicate, inferred from ordering rather than observed. *Settled by:* log
   both values at the arm (do this regardless) and grep the two captured runs.
3. The promote skew between gateways. *Settled by:* one re-run — `dump_diag` already dumps
   every device since `5b42f6b`.
4. Whether the controller drops the peer's `retiring` row before or after the peer's local
   renormalize. Deliberately NOT built on as a signal because of this uncertainty.
5. Socket-leak interaction — dissolved by the clobber explanation, but 3 sockets on `:51821`
   were measured. If a green run shows a handshake landing on a device the UAPI layer does
   not report, item 26 re-enters this blocker.

**The single claim most worth falsifying before implementation:** that the epoch1↔epoch1
session has no possible dialer other than these two devices. Everything else follows from it.
