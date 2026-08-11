# In-step rotation, re-baselined on HEAD (2026-08-10)

**Measured:** 2026-08-10, HEAD `349c16e`, two consecutive runs.
**Test:** `in_step_rotation_of_both_gateways_stands_up_own_and_overlap_tuns`
(`crates/wiremesh-gateway/tests/key_rotation.rs:2049`), still `#[ignore]`d.
**Result:** still RED, same assertion — but **the mechanism in
`rotation-endpoint-and-port-model-is-broken.md` is STALE.** Read this before that.

    ./dev.sh run "cargo test -p wiremesh-gateway --test key_rotation \
      --features netns-tests in_step_rotation_of_both_gateways_stands_up_own_and_overlap_tuns \
      -- --ignored --test-threads=1 --nocapture"

**The `--features netns-tests` flag is mandatory.** The whole file is
`#![cfg(feature = "netns-tests")]`, so without it the binary compiles to ZERO tests and
prints `0 passed; 0 failed; 0 filtered out` — a false green.

## What is no longer true

The `#[ignore]` attribute describes a permanent deadlock with both sides churning
`direct → degraded → disconnected → connecting` forever, measured at 90s with no recovery.
Three of those claims do not survive re-measurement:

- **No churn.** Each gateway logs exactly ONE transition — `connecting -> direct` — and
  then nothing. No degraded, no disconnected, no re-connecting, either side, either run.
- **Rotation is not deadlocked; it COMPLETES.** Both gateways reach terminal state
  (`epoch 0 retiring`, `epoch 1 active`), both cutovers finish, and the Role-B epoch ack is
  sent. The state machine is fine.
- **The 90s figure is unreachable from this test.** Its post-rotation gate is
  `wait_until(Duration::from_secs(20), ..)` (`key_rotation.rs:2274`). Both runs failed in
  ~28s wall clock. The 90s number came from some other measurement and should not be cited
  as this test's evidence.

Also passing, and worth knowing: the **T3 assertion passes** (four rotation devices across
the pair, every one with its enforcer attached), and **traffic survives the rotation** —
`17 transmitted, 15 received` through both cutovers, inside the ≤6 gap bar. Only the
SETTLED post-rotation state is broken.

## The live mechanism

The gateway's own log states the defect:

    Role B cutover — peer 2 epoch 1 live on wg0o0; routes on wg0e1 (ActiveTun), epoch ack sent

**The live session is on `wg0o0`. The routes were installed on `wg0e1`. And `wg0e1` never
handshakes** — `wg show wg0e1` has no `latest handshake:` line at all, on either side, in
either run, while its `allowed ips` and route are in place:

    10.10.2.0/24 dev wg0e1 scope link

## The actual defect: `wg0e1`'s peer endpoint is programmed to the wrong port, RACILY

Each gateway's epoch-1 key lives on its own `wg0e1`, **listening on 51821**. So for gwB's
`wg0e1` to handshake it must dial `10.9.0.1:51821`. Observed:

| run | gwB `wg0e1` peer endpoint | what is actually there |
|---|---|---|
| 1 | `10.9.0.1:51820` | `wg0` — the peer's OLD epoch-0 key |
| 2 | `10.9.0.1:51822` | `wg0o0` — the peer's overlap tun |

**Two different wrong ports across two runs, never the correct 51821.** This is not a fixed
off-by-one — the endpoint selection is nondeterministic between runs. Any fix that assumes a
constant delta is fixing the wrong thing.

## Where a gate IS stuck (but not the one the old note names)

`wg0o0` has NOT collapsed. The collapse is armed and parked:

    Role B collapse armed for peer 2 (rotation complete; roster active-only on the new key)
    — wg0 unpinned, awaiting a live session on the ACTIVE tun before tearing wg0o0 down

So the stuck gate is the **Role-B collapse** waiting for a live session on `wg0e1` — not the
retire/base-port deadlock the old note describes. The distinction matters: the pair is **one
correct endpoint away from working**, with a healthy session already sitting unused on
`wg0o0`.

## The shipped ground-truth fix does not appear to fire here

PR #51 (2026-08-06) added a continuous read-through of the device's real per-peer endpoint on
the ~1s path tick. **No per-tick read-back lines appear in these logs** — the only endpoint
lines are `observed endpoint …:51820` (observe path) and `punch confirmed peer=2
endpoint=…:51820`. Nothing renormalizes `wg0e1`'s peer endpoint.

Hypothesis worth testing first, from reading rather than measurement: the read-through only
pins for peers the path SM judges `Direct` or `Relayed`, and `to_record` deletes the pin on
`Degraded`. Here the pair reaches `direct` on the BASE tun and `wg0e1` is never the device
the path SM is judging — so the feedback may be firing on the wrong device entirely, rather
than not firing at all.

## Diagnostic gap found while measuring

`dump_diag` hardcodes `wg show wg0` and `wg show wg0e1` only (`key_rotation.rs:409-410`).
**`wg0o0` is never dumped**, so its peer/endpoint/handshake state is known only from the
gateway's own log claim, never from independent device output. Widen it before diagnosing
further — the overlap tun is now the device carrying the live session.

## One unexplained observation, not diagnosed

`wg0` reports `latest handshake: 56 years, 235 days ago` (a zeroed timestamp) while
`transfer: 1.37 KiB received, 1.37 KiB sent` is nonzero. Resembles the boringtun
handshake-time quirk recorded in `cycle4b-path-liveness-note.md`. Flagged, not investigated.

## What this changes

The problem is **narrower and more tractable** than "permanent deadlock". The rotation
machinery works; traffic survives; the state machine terminates. What is broken is a single
programmed endpoint on one device, chosen nondeterministically wrong. Start there — and do
NOT start from the old note's mechanism, which describes a pre-PR-#51 world.

---

# Instrumented re-run (2026-08-11) — the overlap tun already has the right answer

Re-ran on `test/rotation-diag-overlap-tun` after widening `dump_diag` (`5b42f6b`) to dump
every device plus `ss -4 -lunp`. Still red, same assertion. But the device state now answers
the open question. The LAYOUT was **symmetric within this run** — both gateways showed the
identical device/endpoint/handshake shape. The endpoint SELECTION remains **nondeterministic
across runs** (see below). Two runs cannot establish the absence of a race, and nothing here
should be read as having done so.

## Measured

Both gateways, identical shape:

| device | listens | peer endpoint | latest handshake | transfer |
|---|---|---|---|---|
| `wg0o0` (Role-B overlap) | 51822 | `10.9.0.x:51821` **correct** | **24 s** | 84/84 (gwA), 168/84 (gwB) |
| `wg0e1` (own new epoch) | 51821 | `10.9.0.x:51820` **wrong** | **0 — never** | **0/0** |
| `wg0` (base, epoch 0) | 51820 | `10.9.0.x:51820` | 26 s | 1654/1654 |

**`wg0o0` and `wg0e1` are configured with the SAME peer public key and DIFFERENT
endpoints.** The overlap tun points at the peer's epoch-1 port (`:51821`) and is live. The
own-epoch tun points at the peer's BASE port (`:51820`), where the peer's epoch-0 key sits,
and has never completed a handshake. Routes are on `wg0e1` — the dead one.

So the correct endpoint is **already computed and already on the box**, one device away from
where it is needed. This is not a missing value; it is a value that one builder derives
correctly and another does not.

Yesterday's run saw `:51822` on one side; today both sides show `:51820`. So the specific
wrong value is not stable across runs, and no fix should be designed against a fixed offset.
What IS consistent across both runs is which device is wrong: **`wg0e1`'s endpoint is always
WRONG and `wg0o0`'s is always RIGHT.** The wrongness is stable even though the wrong value is
not — that is the actionable part.

## Socket counts, from `ss -4 -lunp` (new evidence)

gwA: **2 sockets on :51820, 3 on :51821, 2 on :51822.** This is the leak recorded
in backlog item 26 / `socket-leak-on-rebind.md`, observed live here.

## An inference, explicitly NOT measured

There is a contradiction worth chasing. gwA's `wg0o0` records a completed handshake with the
peer, and the peer's endpoint for that session is `10.9.0.2:51821`. On gwB, the device
holding the matching epoch-1 private key and listening on 51821 is `wg0e1` — **yet gwB's
`wg0e1` reports handshake 0 and zero bytes.** Something on gwB:51821 answered a handshake
that `wg0e1` did not record.

Hypothesis: one of the **three** sockets bound to :51821 is a leaked socket from an earlier
apply that still holds the epoch-1 key, and it — not the live `wg0e1` device — is servicing
those packets. Item 26 was downgraded on the reasoning that "newest-bound wins
deterministically"; that argument says which socket wins, not that the winner is the one the
device layer is reading.

**This is reasoning from device state, not a measurement.** It would be confirmed by
correlating the fds in `ss -4 -lunp` with the boringtun instance that owns each device.

## Where to look first

The fix is likely to make `wg0e1`'s peer endpoint come from wherever `wg0o0`'s comes from,
rather than computing it again. Compare the two builders: whatever produces the overlap
device's peer config gets `:51821` right, and whatever produces the own-epoch device's peer
config does not. That comparison is a much smaller question than "what should the endpoint
be".

If the leaked-socket hypothesis also holds, item 26 stops being cosmetic and becomes part of
this blocker.

---

# MECHANISM FOUND (2026-08-11) — a clobber apply, not a builder divergence

Traced read-only against `main` at `0218b57`; every claim below was verified against the
code, not doc comments.

**It is not a builder divergence.** `wg0e1`'s endpoint is not *computed* wrong — it is
*inherited* from the base-tun world by a rebuild that also destroys the session.

## The three endpoint derivations (verified)

| builder | builds | endpoint | value |
|---|---|---|---|
| `pending_peer_configs` (`reconcile.rs:89-95`) | `wg0o0` overlap | `candidate_port + OWN_TUN_PORT_OFFSET` | **`:51821` correct** |
| `device_config_at_port` (`reconcile.rs:246-252`) | `wg0e1` **at creation** | **`endpoint: None`** — *"receive-and-roam, never dial"* | none |
| `device_config_pinned` (`reconcile.rs:174-180`) | the ACTIVE tun | `live_endpoints[gid]` else `primary_endpoint()` | **both base-port** |

`pending_peer_configs` is the ONLY builder that knows it is dialling a rotation-epoch
device. `device_config_pinned` takes `listen_port` as a parameter but derives the peer
endpoint from `(candidates, live_endpoints)` — a per-PEER map, not a per-DEVICE one. It has
no notion of which device it is building for.

`primary_endpoint()` is `candidates.first()`, and every candidate is base-port by
construction: the observe socket is bound to `cfg.wg_listen_port` for process life, and
reported locals are always `netif::local_wg_endpoints(cfg.wg_listen_port)`. **`:51821` cannot
enter the candidate list at all.**

## The trigger: the Role-B collapse unpin forces a `replace_peers`

`maybe_collapse_role_b` does `rot.wg0_pins.lock().unwrap().remove(aid)` (`main.rs:4719`)
immediately before `apply_state` on the same `State` event. Its own doc comment
(`main.rs:4682-4687`) states the consequence:

> unpin `wg0_pins[gid]`, so the apply rebuilds `wg0`'s entry for this peer with its NEW
> active key … **the key change defeats both the change-guard and the pure-addition
> incremental path, so a full rebuild is guaranteed by that very apply**

**That comment says `wg0`. `apply_state` resolves `a.ifname` — the ACTIVE tun
(`main.rs:3495-3497`) — which after our own Role-A cutover is `wg0e1`.** A load-bearing
prose error: the sentence was written for a world where our own cutover had not happened.

Forced chain:
1. peer promotes → `pending_key()` becomes `None`, `active_pubkey_b64` becomes epoch-1
2. unpin → `device_config_pinned` emits the peer under the **epoch-1** key; `wg0e1` holds it
   under **epoch-0** (what `device_config_at_port` installed)
3. `classify_peer_delta` → key present-then-absent → `NeedsFullApply`
4. `uapi::apply` with `replace_peers=true` → boringtun `clear_peers()` → **every peer's
   `Tunn` and byte counters rebuilt from zero**, new block carrying
   `endpoint = live_endpoints[gid] = :51820`

## This dissolves the "unexplained" observation — no leaked socket needed

The earlier inference that a leaked socket on `:51821` was servicing handshakes is
**unsupported**. The real explanation: `wg0o0`'s private key is our epoch-0 key, and the
peer's `wg0e1` peer-set was built from our epoch-0 pubkey — so `wg0o0 → peer:51821`
handshakes for real (the 84/84). Then the peer's own collapse-unpin apply `clear_peers()`-es
its `wg0e1`, **zeroing exactly the record we went looking for.** Symmetric both sides.

The socket leak (item 26) is real but is NOT required to explain this shape.

## And it explains the nondeterminism without any race in port arithmetic

The candidate list can only ever yield `:51820`, so the variation comes entirely from
`live_endpoints`: whether a roamed endpoint got captured by the read-through **before** the
clobber apply fired. `:51822` = the peer's overlap source port, roamed-to and read back;
`:51820` = the stale punch pin, never displaced. Same bug, two arrival orders — a race in
TIME, not in the port formula.

## The read-through: right device, wrong side of the clobber

**Refuted:** the hypothesis that `wg0e1` is never the judged device. `run_path_ticks` re-reads
the active ifname every tick (`main.rs:2738`), so after the cutover it IS polling `wg0e1`.

**Confirmed, but a different gap:** the read-through is keyed by the peer's currently
advertised active pubkey (`main.rs:2856-2867`). After the peer promotes, `hex` flips to
epoch-1 while `wg0e1` still holds epoch-0 until the clobber → `liveness.get(&hex)` is `None`
→ the SM receives no evidence at all. That is why there are no read-through lines and no
degrade churn.

**Decisive:** the read-through can only echo back what the device already has. It has no
mechanism to PRODUCE `:51821`, because nothing ever wrote it. Post-clobber it will read
`:51820` off the device and pin it into `live_endpoints` — **cementing the wrong value as
durable state.** Amplifier, not corrector.

## Checked and NOT the cause

- No surviving epoch-delta formula. `OWN_TUN_PORT_OFFSET` appears only in `tunnelset.rs`
  (the allocator/reservation) and `reconcile.rs:92`. v0.7.2's deletion was complete.
- `device_config_at_port` emitting a wrong endpoint — it emits `None`.
- Candidate-list ordering — cannot yield anything but base-port.
- The punch path writing post-cutover — it yields without touching the device when the path
  is `Direct`. It IS the origin of the stale `:51820` pin, written pre-cutover on the base tun.
- The Role-B collapse gate as root cause — it is stuck, but downstream: it waits on liveness
  the clobber *it triggered* made unreachable. Cause and symptom are the same apply.

## One line

`pending_peer_configs` gets `:51821` because it is the only builder that knows it is
dialling a rotation-epoch device. `wg0e1` gets `:51820` because after the Role-A cutover it
becomes "the active tun" and is rebuilt by the device-agnostic `device_config_pinned`, whose
two endpoint sources both describe the peer's BASE port — and that rebuild is FORCED by the
Role-B collapse unpin, whose `replace_peers` also destroys the session `wg0o0`'s counters
prove really existed.
