# The decided endpoint/port fix shape was wrong — corrected plan

**Verified:** 2026-08-06, read-only pass against `main` @ `68f96e5`, including boringtun
0.6.0's own source.
**Supersedes** the "Fix shapes" section of
[`rotation-endpoint-and-port-model-is-broken.md`](rotation-endpoint-and-port-model-is-broken.md).
That note's *diagnosis* stands; its *prescription* does not.

## The headline

**The decided shape does not close either bug, and part (1) placed where the doc puts it
makes things worse.**

The missing invariant is not "one port authority". It is that **a gateway's active key
permanently leaves the base port at the first cutover and never comes back except by
reboot** (OD-1, `main.rs:463-467`). Until that is repaired, every port formula — old, new,
or authoritative — is guessing at a moving target.

**Bugs 4 and 5 are not two bugs. They are one invariant violated twice**, so they cannot be
fixed independently: anti-clobber alone leaves the gateway parked on `base+1` and bug 5
fires on the next rotation exactly as before.

## Why part (1), at the cutover, is actively harmful

The plan said: at the Role-A cutover, seed `live_endpoints[gid]` from boringtun's
ground-truth `endpoint=`. Traced at HEAD:

1. `handle_rotate` brings up `wg0e1` and writes peers via `device_config_at_port`
   (`main.rs:3831-3833`) at `peerIP:ourNewPort` — a target the peer's active key is not on.
2. The cutover gate `any_live` (`main.rs:4497-4498`) needs `latest_handshake.is_some() &&
   rx_bytes > 0` (`main.rs:4350`). The only thing that can produce that is **the peer's
   Role-B overlap** dialing us (`pending_peer_configs`, `main.rs:3949`), which on rotation
   0→1 happens to hit `wg0e1`. Our device roams the peer onto the overlap's source port.
3. So at `FlipRoutes` the device's `endpoint=` for a live peer is
   `peerIP:<the peer's wg0o<slot> port>` — real, correct *now*, and **destroyed when that
   peer's Role-B collapse tears the overlap down** (`main.rs:4967`).

Seeding from it writes a transient, doomed socket into the map `device_config_pinned`
*prefers over the candidate* (`reconcile.rs:131-137`). Today that slot is empty, so
post-collapse the peer is dialed at the base candidate — **correct** in the one-sided case.
The proposal replaces a correct value with a dead one, recoverable only via the ~45s
Degraded path (`main.rs:3042-3044`).

And for peers *not* live at cutover (`any_live`, not `all_live`) there is nothing roamed to
read at all — it returns `device_config_at_port`'s guess. **Wrong in both directions.**

The moment that actually clobbers is not the cutover. It is the **collapse-arm apply**:
`maybe_collapse_role_b` unpins (`main.rs:4258`) *before* `apply_state` in the same event
(`main.rs:980-992`), the key change forces `NeedsFullApply` (`main.rs:3234-3236`), and
`replace_peers=true` both rewrites the endpoint to base and destroys the roamed session
(`uapi.rs:254-268`).

## Confirmed buildable

- **boringtun's `get=1` really does emit a roamed `endpoint=`.** From its source:
  `api_get` writes `endpoint={}` from `p.endpoint().addr`, and `register_udp_handler` calls
  `p.set_endpoint(addr)` on every successfully-decapsulated datagram — so the value is
  roamed *and authenticated*. Note the design doc's cited evidence was weaker than claimed:
  `scoped_peer_apply.rs` only ever reads back a **configured** endpoint, and
  `uapi.rs:634-653` is a hand-written fixture. The source is the evidence.
  - Caveat to carry: boringtun issue **#489, "Don't roam peer endpoint on cookie replies"**,
    is open. A bad roam is transient today; pinning it durably would amplify it.
- **Parsing is trivial**; the cost is that `PeerGetInfo` and the public `PeerLiveness` lose
  `Copy`, so `main.rs:2791`'s `.copied()` and friends become `.cloned()`. ~1 hour.
- **No proto change is required** — *provided* renormalization lands. boringtun's `api_set`
  handles `listen_port` by rebinding the socket; it calls `peer.shutdown_endpoint()` but
  **does not reset noise sessions** the way `set_key` does, and both boringtun
  (`set_reuse_address(true)`) and the observe socket (`observe.rs:86`) set `SO_REUSEADDR`.
  Without renormalization the peer's real port *must* cross the wire
  (`PeerKey.listen_port`), and the estimate changes materially.

## The corrected plan — three ordered pieces, all required

1. **Anti-clobber, as continuous read-through — not a one-shot seed.** Extend the path
   tick's existing `get_peer_liveness` fetch (`main.rs:2679`, already once/second on the
   active tun) to also carry `endpoint`, and refresh `live_endpoints[gid]` from the device
   for peers in `Direct`/`Relayed`. This preserves "live peers keep their endpoint, dead
   peers chase candidates", subsumes both `set_peer_endpoint` writers, and covers rotation
   for free. **Prerequisite for step 2** — see the deadlock below.
2. **Renormalize the listen port to base at retire.** After `service_retire` drops the old
   Device, UAPI-`set` `listen_port=<base>` on the survivor, update `ActiveTunInfo.wg_port`,
   **re-seed the change-guard in the same step** (else the next `apply_state` sees a header
   mismatch, `main.rs:3265-3270`, and does a destructive full apply), and **rebuild live
   relay transports** (their forward target is frozen — see below).
3. **Split the port ranges.** `Own` tuns take a reserved `base+1`; overlaps free-list
   `base+2..`. `plan_port` (`tunnelset.rs:251-255`) is one lowest-free scan over a shared
   range today. With (2) holding, a peer's in-flight new-epoch tun is *always*
   `candidate_port + 1`, epoch-independent — so `pending_peer_configs`'s epoch-delta
   formula is **deleted**, and `device_config_at_port` stops rewriting the port at all.
   Role A's new tun is documented as **receive-and-roam**, which is what it actually is.

Plus the **rotate-twice test**, and realistically the **R2b wedge reset**.

> **Note from building piece 2:** bug 5's arithmetic partially resolves itself once
> renormalization lands — rotation 1→2 plans `Own{2}` at `base+1` (the survivor is back at
> `base`, so the free-list's lowest free is `base+1`), and the peer's `pending_peer_configs`
> computes `active_port + (2-1)` = `base+1`. They agree. **But only if no overlap grabbed
> `base+1` first**, which is precisely the coincidence piece 3's reserved range makes
> structural. Nobody should read the arithmetic working here as piece 3 being optional.

### The deadlock that orders 1 before 2

The collapse-arm apply kills the roamed session → `all_live` never holds → `service_retire`
never fires → renormalization never happens. So (1) is not an alternative to (2); it is
what makes (2) reachable at all. The original doc's "(1) and (2) compose" framing hides a
hard ordering.

### Why the wedge must be fixed before or with this

`on_directive` is honoured only from `Idle`, reachable only via `on_epoch_retired` from
`CutOver`, which requires `service_retire`. Today a wedge leaks a Device and an unscrubbed
key.

> **CORRECTED 2026-08-06.** This note originally claimed renormalization makes a wedge
> *worse* — "a wedge also leaves the gateway permanently unaddressable at its advertised
> port". **That is wrong.** A cutover already leaves the gateway off its base port, wedge
> or not; a wedge simply means renormalization never runs, so a wedged gateway is exactly
> as unaddressable as it is today. Piece 2 does not raise the **cost** of a wedge — it
> raises the **value of fixing one**, because task #20 becomes the difference between
> getting the cure and not. The conclusion (fix the wedge) stands; the argument for it
> was bad.

## Relay finding — real, but this note had the mechanism wrong

> **CORRECTED 2026-08-06 while building piece 2.** The claim below — that the forward
> target is *"fixed for the transport's life"* — **is wrong**, and getting it wrong would
> have bought an expensive fix for a cheap problem.
>
> `RelayTransport`'s uplink pump rewrites `last_seen` on **every** datagram;
> `local_peer_hint` is only a seed. So the exposure is not "until the ~45s Degraded
> rebuild" but "until boringtun's next outbound datagram through the relay socket" —
> at most one keepalive, ≤25s. Still real: inbound relayed datagrams in that window hit a
> port with no socket.
>
> That makes **rebuilding the transports the wrong fix.** It would cost a QUIC reconnect,
> a fresh local socket, a `set_one_peer` remove + re-add and a forced rehandshake *per
> relayed peer* — to close a window that closes itself. `set_local_peer` overwrites
> `last_seen` in place: no QUIC, no WireGuard, no rehandshake. Applied at **both**
> port-moving sites, since the Role-A cutover has the identical bug today.
>
> One thing this note also missed: renormalization moves **our own source port**, so each
> peer keeps sending to the old one until it authenticates a datagram from the new one and
> roams. Unprompted that is up to 25s. Piece 2 pokes each peer so boringtun emits
> immediately.

*Original text, kept for the record:*

`RelayTransport::start` is handed `127.0.0.1:<ctx.active.wg_port>` as its forward target
(`main.rs:2440-2449`), **fixed for the transport's life**. A Role-A cutover changes
`active.wg_port` (`main.rs:4601-4613`), so every existing relay transport keeps writing
inbound WG datagrams to the *old* port — the old device, holding the old private key, which
cannot decrypt what the peer now sends. **Relayed peers black-hole across every rotation**,
recovering only via the ~45s Degraded → relay-rebuild cycle. Renormalizing the port has the
same effect and needs the same handling.

Consistent with the recorded "relayed rotation unimplemented — `pending_peer_configs`
direct-only" (`backlog-program-notes.md:43`, finding E), but the mechanism — a frozen
forward target — was written down nowhere.

Related: for a `Relayed` peer, `live_endpoints[gid]` is a **loopback** address. Any new
endpoint-override map must lose to that or the relay path breaks. Read-through gets this
right for free; the doc's part (2) left the precedence unspecified.

## Regression surface is larger than recorded

Seven direct `device_config_pinned` call sites, not six — the doc missed
**`tests/epoch_watch_keys.rs:312`**, which pins `new_epoch_watch_keys` against
`device_config_pinned`'s *actual output*.

> **CORRECTED 2026-08-06 while building piece 3.** This note claimed
> `pending_peer_configs_builds_offset_endpoint` (`:274`) and
> `pending_peer_configs_offset_survives_nonzero_active_epoch` (`:321`) "encode the wrong
> formula", and framed it as a collision between *tests must always pass* and *never
> arrange the tests to match the code*. **Both claims are wrong. There is no collision.**
>
> Both tests use `pending == active + 1`, where the epoch-delta formula and
> `candidate_port + 1` produce the **same answer**. They never discriminated between the
> two models, so they pass unchanged after the formula is deleted.
>
> The real problem is worse than the one I described: **they pin the exact coincidence that
> hid bug 5** — the `k → k+1` case where two unrelated functions happen to agree. And
> `..._offset_survives_nonzero_active_epoch` is now actively misleading, because it names an
> epoch-independence-via-delta property that no longer exists and **would pass against an
> implementation with the bug restored.**
>
> Remedy: replace them with a `pending == active + 2` case whose expected port is still
> `candidate + 1`, plus one pinning that an overlap can never be planned onto
> `base + OWN_TUN_PORT_OFFSET`. Rewrite because they test the wrong thing — not, as this
> note originally said, delete because they encode a falsehood.

The one test that genuinely breaks is
`rotation_slot_quarantine.rs::a_truncated_port_window_allocates_only_what_fits`: it
allocates three overlaps at base `u16::MAX-3`, and reserving `base+1` costs exactly one
overlap port. Unavoidable by construction.

## No smaller safe step exists

Ruled out: refusing a directive unless `active.wg_port == base` (rotation #1 in-step is
*already* broken empirically, so this doesn't make re-enabling safe); shipping anti-clobber
alone (leaves manual rotation one-way, needing a reboot to renormalize); advertising the
offset port (already rejected — `candidates_for` puts the observed endpoint first
unconditionally, and a fresh UDP socket has no punched NAT mapping).

Anything less than the three pieces is "rotation is manual and each use costs a reboot",
which is a legitimate owner choice but is **not** "safe to re-enable the timer".

## Line-cite drift in the superseded doc

Against `68f96e5`: the Role-A cutover seed is `main.rs:4567-4597` (doc: 4528-4574); the
Role-B collapse liveness read is `main.rs:4913-4915` (doc: 4784-4788); the collapse unpin is
`main.rs:4258` (doc: 4252). Also, on rotation 1→2 the device the peer's overlap dials at
`base+1` is our **active** epoch-1 tun, not the "retiring" one — the conclusion (MAC1
mismatch, dropped) is unchanged.


## Found while building piece 3 — two things this plan never mentioned

**`candidate_port + 1` inherits a NAT hazard, and the plan's framing hides it.**
`primary_endpoint()` is `candidates.first()`, i.e. the controller-*observed public*
endpoint. Behind a port-translating NAT that is a mapping for G's **base-port socket**, and
`+1` on it is meaningless. This is **not a regression** — `active_port + delta` had the
identical defect, and rotation behind NAT is already unsupported because the offset port is
never observed, reported or punched, so nothing can reach it regardless. But "epoch-
independent, both sides agree" is only true on the un-translated path, and the plan should
say so rather than implying generality.

**Role A's `kick_overlap` is now provably inert and still runs.** With
`device_config_at_port` emitting `endpoint: None`, Role A's new tun cannot send, so the
kick costs up to `1s × peers` of `ping -W1` per rotation tick for the whole overlap window
and briefly routes a `/32` of the peer's segment onto a device that cannot answer. Left in
place with a comment saying it is inert **by design** and must not be "repaired" by
guessing another port. The real options are to delete the Role-A arm's kick, or to make
Role A's new tun addressable properly — which means the peer telling us where its overlap
is, i.e. a proto change.

**And one limitation that survives all three pieces unchanged:** piece 1's transient-
overlap pin. Post-cutover the roamed endpoint written into `live_endpoints` is the peer's
*overlap* socket, which dies at that peer's Role-B collapse, leaving up to 45s of Degraded.
Pieces 2 and 3 neither worsen nor fix it; this note previously implied they might.
