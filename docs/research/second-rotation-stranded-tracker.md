# Every rotation after the first promotes late, and its ack is discarded

**Found:** 2026-08-06, by the rotate-twice done-bar built for a *different* bug.
**Status:** open. **Pre-existing controller bug — not introduced by the port-authority
branch** (`git diff 68f96e5..a64c7fd --stat` touches only gateway files).
**Second-rotation-only**, which is why nothing has ever hit it: no test had rotated twice.

## What happens

A `RotationTracker` from rotation 1 is stranded with `promoted_at = Some`, and **no code
path can drive it**:

- `sweep_rotations` step 2 only drives a gateway with a **`pending`** row
  (`services/sync.rs:557`) — after a promote there is none.
- step 3's orphan retire is explicitly skipped when a tracker exists (`sync.rs:603-608`).
- `report` only drives when `epoch_acks` is non-empty (`sync.rs:1201`), and the gateway
  sends an ack exactly **once** per Role-B cutover before latching it off
  (`gateway/src/main.rs:4768-4835`, `:5288-5295`). No more acks are coming.
- `submit_epoch_key` only fires on a new rotation.

So epoch 0 stays `retiring` and the tracker lives indefinitely. When rotation 2 arrives,
`sync.rs:561` reuses it (`if !guard.contains_key(&gateway_id)`), `drive_rotation_for`
rebuilds `RotationState` from `tracker.pending_epoch = 1` with `promoted_at = Some`
(`sync.rs:436-444`), and `rotation::decide`'s **rule 1** (`rotation.rs:58-64`) short-circuits
— it never looks at `pending_epoch` again, returning only `Retire` or `Wait`.

Two consequences, both fatal:

1. **gwB's epoch-2 ack is silently discarded.** It arrives while the stale tracker is
   installed, so `sync.rs:1208` skips the lazy rebuild and `sync.rs:1233` tests
   `ack.epoch (2) == tracker.pending_epoch (1)` → false → never recorded. gwB does not
   re-ack. **Rule 3's immediate ack-promote is structurally unreachable on every second
   rotation.**
2. **The 90s grace clock starts 30–40s late** — at `RotateKey#2 + RETIRE_GRACE (30s) +
   ≤5s sweep granularity`. Promotion lands near `RotateKey#2 + 125s`.

## The fingerprint

The failing run's final state is `[(1, active), (2, pending)]` — **epoch 0 is gone.**
Nothing could have deleted it before `RotateKey #2` (see the four blocked paths above), so
its deletion happened *during* rotation 2.

> **Wording corrected 2026-08-06.** This first said epoch 0's deletion "is the stale tracker
> being **evicted**". Nothing evicts it in the current code — `sync.rs:561` *reuses* it.
> Epoch 0 is deleted by that reused tracker firing rule 1's
> `Retire{ prior_active_epoch = 0 }`, whose handler then calls `rotations.remove`. The
> distinction is load-bearing for the timing claim, and it **supports** it: rule 1 `Wait`s
> until `RETIRE_GRACE` elapses from *rotation 1's* promote, then retires and self-removes,
> and only the following tick builds the epoch-2 tracker — which is exactly the
> "30s + ≤5s sweep granularity" delay.

## Production impact

**Every rotation after the first promotes ~30–40s late with zero ack acceleration**, and
the window in which peers still hold a key the rotating gateway has already destroyed grows
to match. Latent today only because automatic rotation is disabled fabric-wide.

## Why the gateway destroying a live key is not itself the bug

The gateway leads by design, and the split is stated in the code. Gateway-side
`RETIRE_GRACE` is `2 × ROTATION_KEEPALIVE` = **6s** (`main.rs:352`), decided purely on local
rx-corroborated liveness with no controller input (`main.rs:5128-5144`). The controller's
clocks are 90s/30s. `main.rs:5046-5053` says the two clocks are "unrelated"; `rotation.rs:14-18`
says grace-promote "only advances controller bookkeeping" because make-before-break is
enforced gateway-side.

So the gateway is the authority on its own data plane. **But the port-authority branch makes
that divergence both more reachable and larger:** piece 1 exists precisely to make
`service_retire` fire in cases where it previously wedged, and piece 2 hangs the listen-port
renormalization off it. The ordering is not ours; some of its visibility is.

The genuinely dangerous coupling runs the other way, and is also pre-existing: gwB's
`maybe_collapse_role_b` gates on the **controller roster** (`main.rs:4655-4663`), so a
stalled controller pins gwB's base tun to a key gwA has already scrubbed — which is exactly
the observed 120s flap.

## The flap is a symptom, not a cause

`direct → degraded → disconnected → connecting`, ending "no candidate confirmed", follows
from the promotion failure: with epoch 1 still `active` in the roster, gwB's base tun keeps
peering gwA by the epoch-1 key gwA destroyed, so no handshake is possible on that tun ever.

**Renormalization is ruled out** as the cause:
- The gateway has *always* advertised locals at the **configured base port**
  (`main.rs:937`, `:1079`, `:4827`), never the offset port — renormalization moves reality
  *toward* what was already advertised, so there is no candidate for it to invalidate.
- The overlap `wg0o1 → 10.9.0.1:51820` works across the same moved port (403 B rx / 287 B tx).
  Only the entry keyed by the dead epoch-1 key is dead.
- `set_listen_port` leaves `endpoint.addr` intact, and renormalization pokes each peer so
  boringtun roams immediately.

Incidentally explained: `gwB: wg0 peer 08bb4f… endpoint=10.10.1.1:51820` is gwA's *retired*
epoch-1 key, parked on a **segment** address because `netif::parse_ip_addr_output` reports
every usable IPv4 unfiltered and the candidate cycler stopped there. Address wrong, port
right — correct post-renormalization.

## The port fix is unaffected

Both sides derive the port from the base plus one shared constant with **no controller input
on the path**: `plan_port` takes the reserved `base + OWN_TUN_PORT_OFFSET` with no fallback
(`tunnelset.rs:144`, `:205-208`); `pending_peer_configs` imports the same constant
(`reconcile.rs:4`, `:79`). Neither consumes `promote_epoch`'s output. `{51820, 51821}`
matching on both sides is pieces 1+2+3 composing as designed.

## Smallest fix that validates the mechanism

In `drive_rotation_for` (`sync.rs:398`) and `sweep_rotations` step 2 (`sync.rs:561`), evict a
tracker whose `pending_epoch` disagrees with the DB's current `pending` row before using it:

```rust
if rotations.get(&gid).is_some_and(|t| Some(t.pending_epoch) != db_pending_epoch) {
    rotations.remove(&gid);
}
```

Rotation 2's tracker — and gwB's ack — then land immediately, and rule 3 promotes within
seconds.

> **Predicate correction, found while implementing.** The sketch above uses plain
> inequality. **That is wrong and would be a silent regression.** It also evicts on the
> stranded-post-promote state itself (live tracker, *no* pending row) — a tracker that still
> owes a `Retire`. Evicting there hands the retire to sweep step 3's orphan path, which
> deletes **immediately with no grace**, collapsing `RETIRE_GRACE` from 30s to ~0 and
> shrinking the make-before-break window on every normal rotation. The predicate must be
> **"the DB has a pending epoch AND it disagrees"**.

**This does not close the underlying hole:** a promoted rotation's retire is never driven,
because no path exists for "gateway has a `retiring` row *and* a live tracker". The sweep
should drive `decide` for that state too. The eviction is the minimal change that turns the
done-bar green if the hypothesis holds; the sweep gap is the real fix.


## What the sweep gap actually costs (traced while implementing the fix)

After the eviction, rotation 1's promote still strands a tracker nothing drives to its
`Retire`, and epoch 0's `retiring` row still survives step 3 (`has_tracker` → `continue`).
Its lifetime becomes "until the next rotation completes" — rotation 2's promote returns
`Retire{ prior_active_epoch = 1 }`, deletes epoch **1**, calls `rotations.remove`, and only
then can the following tick orphan-retire epoch 0.

That matters more than bookkeeping: **`routes.rs:48` feeds every key row — `retiring`
included — into the peer roster** (`PeerRoute::keys`). So for that whole span, peers hold a
Device for a key the rotating gateway has already destroyed. On a fabric that rotates once
and then idles, that is forever.

## Residual race the fix deliberately does not cover

The `report` ack path has its own lazy rebuild (~`sync.rs:1244`) with the same
`if !rotations.contains_key` shape and no eviction, so an ack arriving between `RotateKey #2`
and the first eviction would still be discarded. It is closed by **ordering, not luck**:
`submit_epoch_key` calls `drive_rotation` (~`:1327`), and a peer cannot have a live session
with — hence cannot ack — an epoch whose real key has not been submitted yet, so site 1
always evicts first. Adding the check there would cost an unconditional
`all_keys_for_gateway` per ack rather than only on a tracker miss.


## Line references in this document are stale — use symbol names

**Noted 2026-08-06** (CodeRabbit, PR #51). The `sync.rs:NNN` citations throughout were
written against the pre-fix file and the code has since moved under them — `sync.rs:557` now
lands before `sweep_rotations` rather than on its pending branch, `sync.rs:603-608` lands
inside the new eviction comment, and `sync.rs:398` is part of the pending-epoch derivation
rather than the eviction predicate. The same applies to the citations at lines 21-25, 43-50,
107-109 and 148-154 of this file.

The mechanisms described are unchanged and still correct; only the coordinates rotted.
Navigate by SYMBOL, not by line:

| What the text calls out | Find it by |
|---|---|
| "step 2 only drives a gateway with a pending row" | `sweep_rotations`, its pending-epoch branch |
| "step 3's orphan retire is skipped when a tracker exists" | `sweep_rotations`, the `has_tracker` guard |
| "`report` only drives when `epoch_acks` is non-empty" | `report`, the `epoch_acks` guard |
| "the eviction predicate" | `drive_rotation_for`, the `db_pending_epoch` comparison |
| "rule 1 short-circuits" | `rotation::decide` |
| "every key row, `retiring` included, feeds the roster" | `routes.rs`, `PeerRoute::keys` |

Lesson worth keeping beyond this file: **a research note that cites line numbers starts
decaying the moment the fix it describes is written**, because the fix moves the very lines
it cites. Cite symbols.
