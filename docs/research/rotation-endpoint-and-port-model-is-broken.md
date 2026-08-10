# Rotation's endpoint and port model: nothing can address a rotated gateway

**Found:** 2026-08-05. Bug 4 predicted by an implementer, confirmed empirically by the
in-step done-bar run at `5a5f644`. Bug 5 found by the independent verification pass that
was checking bug 4.
**Status:** bug 4 open; **bug 5 FIXED in v0.7.2** (the port authority), which deleted
`pending_peer_configs`' `candidate_port + OWN_TUN_PORT_OFFSET` epoch-delta formula — the
mechanism analysed below — and made the device the one authority on the endpoint. Its done
bar, `second_rotation_of_same_gateway_keeps_traffic_flowing`, is committed and not
`#[ignore]`d. The bug-5 analysis below is kept as the record of what was wrong.

## Bug 4 — after a Role-A cutover, nothing durable can address the active tun

### Confirmed by direct observation

From the failing in-step run at `5a5f644` (routes correct, arbitration fixed):

    gwA wg0e1:  listening port: 51821
      peer: Vw1kzmBnxFWjGTgjPI2SG6HMvulxcOIeesgSBTWUjSw=   <- gwB's epoch-1 key
      endpoint: 10.9.0.2:51820                              <- gwB's BASE port
      (no "latest handshake" line)

gwB listens for epoch-1 on 51821. gwA sends epoch-1 handshakes to 51820 — gwB's `wg0`,
holding the epoch-0 private key, which cannot validate them. Symmetric on the other side.
Routes are on `wg0e1` and ping demand exists, so this is not the route bug: it is the
endpoint.

### Mechanism

`device_config_pinned` (`reconcile.rs:116-147`) selects a peer endpoint from exactly two
sources, at lines 131-137: `live_endpoints`, else `p.primary_endpoint()`. **Neither can
ever carry an offset port.**

- `primary_endpoint()` is `candidates.first()` (`state.rs:80-82`), and the controller
  orders candidates observed-first unconditionally (`db.rs:2932-2962`). The observed value
  is the public mapping of the observe socket, bound to `cfg.wg_listen_port` for the
  process's whole life and never rebound on rotation (`main.rs:629`, `observe.rs:56-60`).
- `live_endpoints` is written only at `main.rs:2233`, from punch candidates (roster,
  base port) or the relay socket. Never an offset port.

The tree already states this as an invariant it relies on: `main.rs:463-467` (OD-1, "peers
hold base-port candidates for us") and `key_rotation.rs:1734-1736`.

So the *only* things that ever produce an offset port are two transient writers that both
**guess**:

- `device_config_at_port` (`reconcile.rs:166-187`) retargets peers at **our own** new port,
  on the explicit assumption that "the peer's own new-epoch Device listens on the identical
  offset port" (`reconcile.rs:161-163`).
- `pending_peer_configs` (`reconcile.rs:44-52`) computes `active_port + (pending - active)`
  — base plus epoch delta.

**These two models are mutually incompatible**, and T3's planner made both unfounded:
`plan_port` allocates the lowest free port in `base+1..=base+64` (`tunnelset.rs:203-207`),
a free-list, not a function of the epoch. The in-step log shows them diverging on the very
first rotation — own tun at `:51821`, overlap at `:51822`.

### Why the one-sided path survives it

Not because it is correct — by accident of the guard. The Role-A cutover seeds the new
tun's change-guard with `device_config_pinned`'s output (`main.rs:4528-4574`), i.e. with an
endpoint the device does not hold. In a one-sided rotation there is no Role-B pin, so every
later recompute renders identically, takes the `Unchanged` arm (`main.rs:3350-3355`), and
never rewrites the device. The wrong endpoint sits inertly in the guard while the device
keeps the value boringtun roamed onto it.

In-step rotation breaks the accident: the collapse-arm unpin (`main.rs:4252`, running
before `apply_state` in the same State event, `main.rs:980-992`) changes the peer's key,
which forces `classify_peer_delta` down the "peer removed" branch → `NeedsFullApply`
(`main.rs:3226-3236`), so a real `uapi::apply` lands and rewrites the endpoint to the base
port. `replace_peers=true` is session-destructive with this boringtun
(`uapi.rs:254-268`), so the roamed state that had been holding it together is discarded too.

### The real invariant being violated

Everything durable in the fabric — observed candidate, reported locals, punch candidates,
`live_endpoints` — is base-port by construction. The design's stated recovery from a
divergent port is **reboot** (OD-1). That is not a mechanism; it is the absence of one.

### Sizing (2026-08-10): it is a deadlock, not a slow convergence

The post-rotation reachability wait was widened from 20s to 90s to find out whether the
pair heals once a grace expires. **It does not.** `test result: FAILED ... finished in
97.54s`, and it failed on the *first* direction (wlA → wlB), so the reverse direction was
never measured — do not read this as a symmetric result. After 90s `wg0e1` was still on
51821 with no handshake, `wg0` was still up, and `wg0o0` had never collapsed.

The two halves gate each other:

- `wg0e1` cannot become live: it dials the peer at `:51820`, where the peer's epoch-0 key
  still sits.
- `retire_ready` is assigned **only inside the `if all_live` branch** of
  `run_rotation_ticks`, and `all_live` requires every peer rx-corroborated live *on the new
  tun*.
- `service_retire` is what tears down the old device and calls
  `renormalize_active_listen_port` to move the active key back to the base port.

So the retire that would make `wg0e1` addressable is gated on `wg0e1` already being live.
Neither side can advance the other, and nothing else moves the port. The relevant clock is
the gateway's `RETIRE_GRACE = 2 * ROTATION_KEEPALIVE` (6s), not the controller's
`rotation::RETIRE_GRACE` (30s) — but neither ever starts, because the gate never opens.

**Blast radius: it churns, it does not settle.** Both gateways log a permanent
`direct → degraded → disconnected → connecting` cycle, with the controller brokering a
punch directive roughly every 5s, indefinitely. On a real fabric that is every gateway at
once, forever, until someone restarts them — so in-step rotation costs control-plane load
as well as data-plane reachability.

### The trap: do not fix this at the cutover gate

The obvious fix is to tighten the cutover gate — stop `any_live` from flipping routes onto
a tun that cannot carry them. **Do not.** A stricter gate parks the phase in `Overlapping`,
and `Rotation::on_directive` is honoured only from `Idle` with **no exit from
`Overlapping`**: `on_epoch_retired` returns to `Idle` only from `CutOver`. That trades
today's churning-but-diagnosable outage for a silent permanent wedge in which every later
directive is ignored and the old key is never scrubbed — strictly worse, and invisible.

**Fix the endpoint the cutover writes, not the gate that lets it happen.**

## Bug 5 — the SECOND rotation cannot complete

**No test has ever rotated twice.** Every case in `key_rotation.rs` goes 0→1 once from a
clean tree, which is why this has never been seen.

A gateway never returns to the base port after a cutover — `rot.base_wg_port` and
`rot.base_tun` stay at the configured values (`main.rs:854-855`) and only a reboot
re-normalizes (OD-1). So on rotation 1→2:

- `plan_tunnel(Own{2}, "wg0", 51820, …)` sees `Own{1}` live at 51821 and allocates **51822**.
- Our new tun dials the peer at `peer:51822` (`device_config_at_port` — our own port).
- The peer's overlap dials us at `base + (2-1)` = **51821** (`pending_peer_configs`) —
  our *retiring* epoch-1 tun.

Neither side's configured endpoint reaches a device holding the matching key, and unlike
rotation 0→1 there is no correctly-dialing side to roam from. **Rotation 1→2 cannot
complete.** On a 30-day timer that is a fabric-wide outage on the *second* fire — hidden
behind, and not fixed by, any fix for the first.

### A one-sided consequence, in currently-green code

The Role-B collapse waits for an rx-corroborated session on the ACTIVE tun toward the
peer's new key (`main.rs:4784-4788`). The active tun's peer entry points at the peer's base
port, which after the peer's retire is nothing. So **the collapse can never complete after
any Role-A cutover, one-sided included** — the overlap Device, its enforcer and its routes
leak permanently. This is the F9 leak shape, reachable on the green path, and it is
visible only because the in-step done-bar added the settle-to-1 gauge assertion
(`key_rotation.rs:2226-2255`).

## The mitigation already shipped

**Automatic rotation is disabled fabric-wide, so neither bug can fire unattended.**
`WIREMESH_ROTATION_INTERVAL=off` landed in **v0.7.0** (PR #47) and is set on the live px
controller as of 2026-08-05, which defused a scheduled outage due 2026-08-31. Do **not**
re-enable the timer until the single port authority below exists and a rotate-twice test is
green — re-enabling it is what makes both bugs live.

## Fix shapes

Two candidates were proposed and **both should be rejected**:

**(a) Advertise the active tun's port in `local_endpoints`.** Cannot work.
`candidates_for` puts the controller-observed endpoint first unconditionally
(`db.rs:2941-2946`) and `primary_endpoint()` takes `.first()`, so advertising locals never
moves the selected endpoint. Changing the observed candidate means rebinding the observe
socket, which is pinned for process life. `set_local_candidates` is a full REPLACE
(`db.rs:2982`), so swapping base→offset mid-rotation deletes the base-port candidates the
live old epoch and the punch ladder still need. And the Report → roster → fan-out
round-trip races a collapse-arm firing on the same promote. Under real NAT it is inert
anyway: the new-epoch device is a new UDP socket with no punched mapping, so
`public_ip:offset` is undialable — already flagged unsolved in `keyrot-spike-note.md`.

**(b) Teach `device_config_pinned` the offset the way `pending_peer_configs` does.** No
source of truth exists at the moment it is needed. The collapse arms exactly when
`peer.pending_key().is_some()` goes false (`main.rs:4243-4245`), so there is no pending
epoch and the delta is undefined — the formula degenerates to the base port. And the
formula is already wrong by construction post-T3, since ports come from a free-list.

**The shape to build instead** — remove the divergence rather than repair the guess:

1. **Ground-truth endpoint feedback.** boringtun's `get=1` response carries a per-peer
   `endpoint=` reflecting the *roamed* value — the fixture at `uapi.rs:634-640` shows it and
   `tests/scoped_peer_apply.rs:122-146` already parses it off a live device.
   `parse_get_response` (`uapi.rs:344-372`) currently drops the line. Extract it, and at the
   Role-A cutover seed `live_endpoints[gid]` from what the tun is *actually* using before
   computing the guard seed. Every later recompute then reproduces reality and the guard
   stops lying.
2. **One port authority.** Give `RoleA` an explicit per-peer endpoint-override map that
   `device_config_pinned` consults (a third pin, beside `pinned_pubkeys` and
   `live_endpoints`), and have `handle_rotate` build the new tun *through the same builder*
   — so there is exactly one renderer for that device and no apply can diverge from it.
   This is the same "no call site can drift" argument `device_config_pinned`'s own doc
   already makes (`reconcile.rs:112-115`). Reconcile `device_config_at_port` and
   `pending_peer_configs` against that authority or the next rotation shape breaks again.

(1) is smaller and self-correcting; (2) removes the class. They compose.

**And add a test that rotates twice.** Bug 5 is invisible without it.

## Regression surface

The one-sided path works *because* the recompute is a no-op. Any change to what
`device_config_pinned` emits changes those bytes and can turn a permanent no-op into a real
apply. At risk:

- `tests/apply_make_before_break.rs` — six direct `device_config_pinned` call sites
  (122, 147, 172, 192, 212, 237).
- `tests/keepalive_emission.rs:166-175` — pins the builder's output shape.
- `reconcile.rs:246-335` unit tests (`pending_peer_configs_*`).
- `tests/key_rotation.rs` one-sided cases at 434, 626, 814, 1021, 1410 — all green, all
  traverse the seed/guard path.
- `tests/scoped_peer_apply.rs`, `convergence_matrix.rs`, `nat_matrix.rs`,
  `relay_matrix.rs` — all reach `device_config_pinned` via `set_peer_endpoint`
  (`main.rs:2251`), so an endpoint-source change touches steady-state punch and relay too.
- `rotation::new_epoch_watch_keys` (`rotation.rs:381-386`) mirrors the *key* selection; an
  endpoint change leaves it alone but a refactor of the selection will drift it.

## Note on the evidence

The "no handshake despite a 25s keepalive" inference does **not** discriminate on its own.
The tree contradicts itself on whether boringtun initiates from keepalive alone —
`main.rs:4280-4293` says it does not (which is why the handshake kick exists),
`cycle4b-nat-matrix-notes.md:25-27` says it does. The inference is sound *here* only
because the `5a5f644` run has routes on `wg0e1` and live ping demand, so outbound demand
existed and still produced no handshake. On the earlier pre-arbitration run, where routes
were on `wg0o0`, a route explanation covered the same observation. Bugs 4 and 5 stand on
code and on the endpoint dump regardless.
