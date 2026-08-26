# B8 relay-mux design — verification against main, and the re-scope it forced

**Date:** 2026-08-04. **Verified against:** `main` @ `4669194` (includes PRs #43, #44).
**Why:** the B8 design in `backlog-program-notes.md` was ratified 2026-07-30. Two prior
verifications on this program each found substantial drift; this one inverted the item's
priority.

## Headline

The design's justification chain was *the width bug is a permanent fail-closed outage →
therefore fold the fix into a mux wire break → and interest sets must come along to avoid
a regression*. **The first and third links are both false.** The conclusions mostly
survive — mux is worth building, interest sets should ship, channels do subsume
key-rotation's OD-3 — but the priority ordering rested on the first link.

Meanwhile two problems that ARE live in production today were found, neither needing the
wire break. **Owner decision 2026-08-04: ship those first as a patch; decide the mux
separately.**

## 1. The width bug — real, but self-healing, not permanent

`crates/wiremesh-relay/src/lib.rs:65-79`. `SHA-256(len(my) || my || peer)`, first **4**
bytes, hex-expanded to 8 ASCII bytes → a 32-bit space. `lib.rs:58-62` already admits it.

Birthday arithmetic checks out (n=50 → 0.0699%; n=200 → 16.84%), but the model is
worst-case in three stacked ways the design did not state: it counts *all* ordered pairs
(only relayed pairs register); the registry is **per relay process** (`lib.rs:531`), so
two keys only conflict if registered on the same relay at the same time; and `lib.rs:61`
already scopes the guarantee to v1's ≤50-segment scale, where it is 0.07%.

**"Permanent" is wrong — three escapes exist:**
1. The winner's teardown frees the slot (`remove_if_owner`, `lib.rs:510-518`; called from
   `teardown_relay_transport`, `main.rs:2458-2467`). Real semantics are **mutually
   exclusive occupancy**, not death.
2. Multi-relay round-robin: `main.rs:2363-2369` advances the cursor on every attempt, so
   with R≥2 the loser lands elsewhere. Only R=1 is sticky.
3. Re-enrollment mints a new `gateway_id` (`db.rs:1488`) hence a new SAN
   (`enrollment.rs:367`) hence a new key.

**Which pair loses is not deterministic** — `lib.rs:583-598` rejects whoever registers
*second*, and that depends on boot order.

**A silent variant the design missed.** The rejection only fires when
`existing.owner != cert_identity`. A **same-owner** collision — `K(A,B)` vs `K(A,D)` —
falls through to `reg.insert` (`lib.rs:602`) and silently REPLACES. Since the gateway
discards the src header (`relay.rs:198` — `let (_src, data)`), B's datagrams get written
to D's local socket and boringtun roams B's endpoint onto D's leg. Total cross-wiring, no
log. ~1/(n−1) of the collision mass, but it is the only silent branch.

(Also: the design says the rejection is "gRPC code 3". `lib.rs:595` is a **QUIC**
application error code. Cosmetic, but it suggests the text was written from a summary.)

**Consequence.** Re-grade to *a probabilistic, self-healing mutual-exclusion fault, sticky
only on single-relay fabrics, with a silent same-owner variant*. The width fix is ~5 lines
on its own — `digest[..8]` raw instead of `hex(digest[..4])`, keeping the header at 8
bytes — and was originally listed as a **separate, orthogonal** carry in
`cycle4c-relay-notes.md:99`. Note the relay recomputes the key itself (`lib.rs:578`), so
it is NOT derivation-oblivious: relay and both gateways must agree. But nothing about
framing, MTU, headers or demux moves.

## 2. LIVE HOLE — any enrolled gateway can inject into any pair's relay slot

`lib.rs:636-649` forwards to whatever `dest` is on the wire, with no check that it belongs
to the sender's pair. Identities are `gw-<rowid>` (`enrollment.rs:367`) — trivially
enumerable. So any enrolled, non-revoked gateway can compute `K(A,B)` and inject.

**The "consent property" the design said interest sets must preserve does not exist.**
Only the receive side is enforced (a slot `K(A,B)` can only be *created* by the holder of
the `gw-A` cert, `lib.rs:452-476, 569-576`). The send side is unenforced. This is the same
class as the gap `cycle4c-relay-notes.md:71-75` closed for registration while leaving
forwarding untouched.

WireGuard E2E holds, so this is DoS/reachability rather than confidentiality — but it is
live on every deployed fabric.

**~3-line fix, no ALPN, no proto, no gateway change:** in `serve`'s datagram loop the relay
already holds this connection's `(my_identity, peer_identity)`. The only legal `dest` is
`registration_key(peer_identity, my_identity)` — exactly what `Client::finish_connect`
computes at `lib.rs:356`. Reject anything else.

**What mux actually changes here** (once the hole is closed): not spoofing — under mux the
receiver must demux on the src header, which the relay stamps from the authenticated cert,
so unknown-src traffic is dropped cheaply. That is *better* than today. What degrades is
(a) blast radius — injected traffic contends on the one shared connection's flow-control
credit and 1 MiB datagram buffer (`lib.rs:177`) — and (b) reachability: holding any relay
connection makes a gateway datagram-reachable from every enrolled gateway.

## 3. LIVE GAP — a peer that leaves the relay pins the path in `Relayed` forever

The design says `NO_ROUTE` "replaces per-pair idle death". **There is no per-pair idle
death.** The 30s `max_idle_timeout` (`lib.rs:169-179`, no `keep_alive_interval`) is
*connection*-scoped, and `sever_relay` in `relay_matrix.rs:720-728` blackholes the relay's
own /32 — so the `TimedOut` branch this codebase pins is "lost reachability to the relay",
not "lost a peer".

With the relay reachable the connection should never idle out: `LIVENESS_PROBE_INTERVAL`
is 20s (`main.rs:305`) and fires for `Relayed` peers (`main.rs:2942-2950`). And
`Path::tick`'s `Relayed` arm (`path.rs:346-383`) has **no liveness requirement at all** —
it stays `Relayed` while `relay_available`, which is just connection health
(`main.rs:2717`).

So the case `main.rs:3048-3053` calls "the production shape — the peer restarted, punched
direct, and LEFT the relay" is **structurally undetectable today**: our connection stays
healthy, the relay logs `unknown dest` per datagram (`lib.rs:648`), and the path sits
pinned indefinitely. The v0.3.1 wedge self-heal covers connection death and leaked pins,
not peer absence.

`NO_ROUTE` is therefore a **new capability closing a live gap**, not parity — a stronger
argument for mux than the one written, and its netns case tests something real.

Three integration hazards the design does not budget:
1. `relay_available` must become **per-peer route presence**, or the `Relayed` arm can
   never emit `RelayDied` under mux (the shared connection is always healthy).
2. `NO_ROUTE` is only observable when we transmit, so detection latency is bounded below
   by our send cadence (today the 20s probe). That dependency is what makes "faster than
   30s" true.
3. `to_relay_died` (`main.rs:3010-3059`) calls `teardown_relay_transport` →
   `transport.close()`, which under a shared connection severs every other peer. It also
   reads `death_reason()` before teardown; under mux that returns `None` and falls into
   the `None => {}` arm — the correct punch-window default, but only by accident.

## 4. The stale-pin sweep — not an audit item; two hard requirements

Predicate, collect phase (`main.rs:2924-2930`): `!RelayDied && state != Relayed &&
!healthy_relay[gid] && relay_pointed[gid]`. Act phase (`main.rs:3080-3093`): re-check,
then `teardown_relay_transport` + clear the pin. It exists to close the leak at
`main.rs:2903-2920` (a late `ensure_relay_transport` re-pins after cleanup; `RelayDied` is
emitted only from the `Relayed` arm, `path.rs:381`, so it can never re-fire and every
`StartPunch` defers forever — the production wedge).

**Under a shared connection both phases break, in opposite directions:**
- **Collect, false negative:** `healthy_relay[gid]` becomes "shared conn alive" = true for
  every peer, so the third conjunct never holds and **the sweep silently stops firing** —
  for exactly the leak it was built to catch.
- **Act, fabric-wide outage:** teardown closes the connection, severing every other peer.

Requirements, not an audit: (i) the liveness conjunct must become per-peer route presence
— the same signal `NO_ROUTE` feeds, so build it once; (ii) split teardown into
`drop_peer_route(gid)` and `close_shared_conn(relay_id)`, and the sweep may only call the
former. Add a netns case running the sweep on one peer while another keeps flowing over
the same relay; N1-N5 has no such case.

Related pure win: `relay_health_snapshot` (`main.rs:1466-1474`) OR-folds per-peer
transports into per-relay health. Under mux that becomes trivially correct — a deletion,
not a port.

## 5. Sequencing (B8 before key-rotation T6) — holds

Neither merge today touched the relay path. The OD-3 gap is real and visible: during
overlap the gateway runs two tuns on two ports (`main.rs:3656`, `:3738`) but `PathCtx`
holds a single `ActiveTunInfo` (`main.rs:1189`) whose `wg_port` flips only at cutover
(`main.rs:4080`), and `ensure_relay_transport` seeds from the **active** epoch
(`main.rs:2400`) — so a relayed peer's pending-epoch tun has no relay path at all.

Two pickups: the missing `PathCtx` → rotation-overlap handle is the **same** precursor the
proto-block verification found for B5/B7 — build it once. And "channel = rotation epoch"
is under-specified in three ways: **width** (`epoch` is `uint32` on the wire,
`sync.proto:28,33,37`; a 2-byte channel truncates), **whose epoch** (per-gateway and
independent; A→B must select B's tun and the reply A's), and **the forwarded header is
never specified** — today the relay rewrites to `[8B src_key][payload]`
(`lib.rs:641-643`) and the gateway throws src away (`relay.rs:198`). Under mux the return
header carries the entire demux. Load-bearing and unwritten.

## 6. The `/0` deprecation window — the anchor does not exist

The design pins the `/0` horizon to "one minor per the B9/X-6 skew window". X-6 does not
exist and is deferred — and **even if it shipped it would be the wrong instrument**: X-6
tracks *gateway* versions at the **controller**, while the entity that must decide is the
**relay**, which has no Sync-borne knowledge of gateway versions, and a version does not
say which ALPN was negotiated.

Dual-offer itself needs nothing. **(Superseded by v0.10.3: the duplicated literals are gone.)**
`tls.alpn_protocols` now reads from one exported list, `wiremesh_relay::{ALPN_V0,
ALPN_SUPPORTED}` — **grep those symbols for the referents rather than counting sites**, since
every site count and line citation this note carried has since rotted. The list keeps its
shape so `/1` is a one-line addition. Only the horizon was tied to X-6.

**Defensible replacement:** a per-ALPN session counter logged at registration
(`lib.rs:616-620` already logs every registration; the relay has zero metrics today —
`src/bin/relay.rs` is 115 lines of `eprintln!`), and an empirical rule: `/0` may be removed
one minor after the relay has observed zero `/0` registrations fleet-wide for a stated
window. This removes B8's only dependency on the deferred proto block.

## Owner decisions

| # | Decision | Status |
|---|---|---|
| A | Unfold the width fix from the mux break | **DECIDED: yes — ship separately** |
| B | Ship the `/0` dest-pinning check now as a patch | **DECIDED: yes** |
| C | Re-motivate interest sets as a fix, not parity | adopted (affects the netns case) |
| D | Netns case pinning peer-departure RED against `/0` first | **DONE in 3a** — the TEST shipped (`case5`, `#[ignore]`d and failing). The GAP IS STILL OPEN; the fix belongs to 3b |
| E | Split `teardown_relay_transport` per-peer vs per-connection | hard requirement if mux proceeds |
| F | Channel semantics: truncated epoch, or opaque tunnel-instance id | OPEN |
| G | Specify the forwarded (relay→gateway) header | OPEN — load-bearing |
| H | Relay-observed ALPN counter as the `/0` horizon | OPEN, recommended |
| I | Shared precursor: `PathCtx` → rotation-overlap handle (also B5/B7) | OPEN |
| J | Per-relay connect dedup + relay-choice cursor | OPEN — `try_start_relay_connect` keys on `gid` (`main.rs:1449-1455`) and `relay_next_idx` is per-peer (`main.rs:2363-2369`), so an eviction fan-out spawns N connections to N relays, defeating mux exactly when it matters. "Reconnect ONCE" has no mechanism behind it today. |

---

# Addendum, 2026-08-05: what item 3a shipped, and what writing case5 revealed

## Shipped in 3a (branch `fix/relay-injection-and-pairid`)

1. **Cross-pair injection closed.** `serve` now computes the one legal dest after
   registration and drops anything else. Drop, never close: closing buys nothing against
   an attacker who can reconnect, and a QUIC handshake plus registration costs the *relay*
   far more than the compare that dropped the datagram — an amplification the attacker
   would choose. Against a *bug* (a version-skewed gateway during the lockstep window
   below) dropping leaves a static greppable failure where closing would be a fleet-wide
   reconnect storm.
2. **Key widened 32 → 64 bits.** Raw `digest[..8]`; header size unchanged.
3. **`register_decision` extracted** as a pure public function, with `RegEntry` gaining
   `peer` so the relay can finally tell a reconnect from a collision. Owner mismatch
   rejects *first and unconditionally* — the peer half is attacker-chosen and must never
   upgrade a rejection into a replace.
4. **All four per-datagram log branches bounded** by a `DatagramDropLog` type. Three were
   unbounded; the fourth (runt datagrams) logged *nothing at all*, so malformed traffic was
   invisible. Per-branch limiters, not shared, so a loud injector cannot suppress the
   `unknown dest` line operators grep during a lockstep upgrade.

**This is a LOCKSTEP upgrade.** Wire format is otherwise untouched — same 8-byte header
both directions, same registration framing and ack, same ALPN, same MTU floor, no proto or
gateway change — but relay and both gateways recompute the derivation independently, so a
version split means the pair silently never rendezvouses (old relay: `unknown dest`; new
relay: dropped as cross-pair; gateway: nothing). Relay and both gateways of any relayed
pair must move together. The dest check and collision rejection are relay-side only.

## The width bug is ADVERSARIAL, which §1 above understated

§1 re-graded the collision from "permanent fail-closed outage" to "self-healing mutual
exclusion" and that is correct **for accidents**. Writing the tests surfaced the other
half: **`peer_identity` is not cert-bound.** `serve` enforces `my_identity ==
cert_identity` (explicit SECURITY comment, `lib.rs:566-576`) and never checks the peer
half — it is free-form wire input.

So an attacker holding *any* valid gateway cert can brute-force a string `P` with
`registration_key("gw-C", P) == registration_key("gw-A", "gw-B")` — a 32-bit target
preimage, ~4.3e9 single-block SHA-256, minutes on a laptop. Then `gw-C` registers
`(gw-C, P)`, occupies A's slot, and:

- A's own registration is **rejected** (`existing.owner != cert_identity`, close code 3)
  for as long as C holds the connection;
- B's datagrams addressed to `K(A,B)` are **delivered to C**.

WireGuard E2E holds, so no confidentiality break — but it is a targeted, attacker-chosen
DoS plus interception of a chosen pair's relay leg, by one compromised enrolled gateway.
At 64 bits the search is ~1.8e19. The old doc comment's "collision-safe at v1's
≤50-segment scale" was true for accidents and false adversarially; both failure modes are
now separated in the code.

## The peer-departure wedge is SELF-PERPETUATING (new, and it strengthens 3b's case)

§3 established that a peer leaving the relay is undetectable. Writing `case5` established
something worse: **the pair cannot recover by any path on its own.**

A peer can only leave the relay by reaching `Direct`. A punch needs both sides. And the
survivor discards every punch — including controller-brokered directives — while
`relay_pointed` holds (`directive_should_punch(Some(Relayed), true) == false`). So the
survivor's pin is precisely what prevents the peer from producing the event that would
clear it. It is circular, and no amount of waiting resolves it.

This also made the *graceful* departure unreachable in the netns harness, because the bug
blocks the very transition the test would need. `case5` therefore has the peer **lose** the
relay (blackholed in its router only) instead. That differs in the peer's own experience
and in ~30s of registration-reap latency, and in **nothing the survivor can observe** —
relay healthy, our connection healthy, peer's route gone. Exactly the input set `NO_ROUTE`
would act on. Reproducing a graceful departure needs a production seam (on-demand
per-peer relay teardown) that does not exist.

`case5` is committed `#[ignore]`d and failing, with a right-reason guard set that panics on
premise failures *before* the verdict so a harness fault cannot masquerade as the finding.
Verified: it fails on the verdict, at the documented site, with all eight premises
satisfied. Un-ignore when `healthy_relay`'s check (`main.rs:2731`) stops meaning "the QUIC
connection is alive" and starts meaning "this peer is reachable through this relay" —
§3 hazard 1, which §4's stale-pin sweep needs identically, so build it once.

## Decisions closed by 3a

| # | Was | Now |
|---|---|---|
| A | Unfold the width fix from the mux break | **DONE** — shipped standalone |
| B | Ship the `/0` dest-pinning check as a patch | **DONE** |
| D | Netns case pinning peer-departure red against `/0` | **DONE** — `case5`, `#[ignore]`d |

E, F, G, H, I, J remain open and belong to 3b.


## Addendum 2: two things the analysis above left implicit

### Mixed-version rollout for the width change (was unstated)

"Lockstep" needs an order, or an operator will pick one and pick wrong. The derivation is
recomputed independently by three parties, and a relayed pair needs all three in agreement,
so:

1. **Relays first, one at a time.** A restarted relay drops its registry; both gateways of
   every pair using it re-register on their next `MarkRelayNeeded`. Between the restart and
   the gateway upgrades, pairs on that relay cannot rendezvous — old gateways compute the
   old key, the new relay computes the new one and drops it as cross-pair. Expect the
   dest-pinning counter to climb during the window; that is the fix working, not a fault.
2. **Then gateways**, in any order. A pair recovers the moment its *second* member is
   upgraded — not the first.
3. **Multi-relay fabrics degrade more gracefully**: `relay_next_idx` rotates per attempt
   (`main.rs:2363-2369`), so a pair that fails on an upgraded relay tries the next one, and
   an un-upgraded relay still serves un-upgraded pairs.

The window is bounded by how long a pair tolerates no relay path, not by the upgrade
itself. On a single-relay fabric with symmetric NAT, that window is a hard outage for
affected pairs — schedule accordingly. There is no compatibility shim and deliberately so:
a dual-derivation relay would have to accept BOTH keys, which re-opens the 32-bit slot to
an attacker for as long as it is supported.

### The `/0` observation horizon is not fleet-complete

The proposed rule — remove `/0` once a relay has observed zero `/0` registrations for a
window — is sound per relay and **unsound across a fleet**. A relay only ever sees the
gateways that chose it, and `relay_next_idx` means a gateway may not touch a given relay
for a long time; a pair that only ever relays through R1 is invisible to R2's counter. So
"R2 saw no `/0`" is not evidence that no `/0` gateway exists.

Two ways to make it whole, neither requiring X-6:
- **Aggregate across all relays** and additionally require that every enrolled gateway has
  been *seen at all* in the window — a gateway absent from every relay's counter is
  unobserved, not upgraded.
- Or invert it: have the relay report its per-ALPN counts to the controller (it already
  holds a Sync connection for the denylist), so the controller can compare observed
  gateways against its own roster. That is the only place the full roster exists.

Until one of those is built, treat the per-relay counter as a *necessary but not
sufficient* signal, and pair it with a calendar horizon stated in release notes.
