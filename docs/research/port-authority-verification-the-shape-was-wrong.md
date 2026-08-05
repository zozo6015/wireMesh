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

### The deadlock that orders 1 before 2

The collapse-arm apply kills the roamed session → `all_live` never holds → `service_retire`
never fires → renormalization never happens. So (1) is not an alternative to (2); it is
what makes (2) reachable at all. The original doc's "(1) and (2) compose" framing hides a
hard ordering.

### Why the wedge must be fixed before or with this

`on_directive` is honoured only from `Idle`, reachable only via `on_epoch_retired` from
`CutOver`, which requires `service_retire`. Today a wedge leaks a Device and an unscrubbed
key. **If renormalization hangs off retire, a wedge also leaves the gateway permanently
unaddressable at its advertised port** — and R2b makes that reachable from one transient
error in `handle_rotate`.

## New finding — relay black-holes on every rotation

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

And a collision worth naming: `reconcile.rs`'s `pending_peer_configs_builds_offset_endpoint`
(`:274`) and `pending_peer_configs_offset_survives_nonzero_active_epoch` (`:321`) **encode
the wrong formula**. "Tests must always pass" and "never arrange the tests to match the
code" collide here, and the resolution is that **the formula is the bug**, so the tests
encoding it must be deleted rather than kept green. Flagged explicitly so nobody reads that
as weakening a test to fit an implementation.

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
