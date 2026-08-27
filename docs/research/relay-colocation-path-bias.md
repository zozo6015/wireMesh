# Relay colocation biases a pair to `relayed` permanently

**Date:** 2026-08-27 · **Where:** the live fabric (v0.11.1 rollout) · **Status:**
observed, root-caused from logs, reproduced twice, workaround verified twice.

## The finding

A peer pair in which **one endpoint hosts the relay** is structurally biased
to park on `relayed` after a disruption and not return to `direct` on its
own: whenever the loopback relay leg re-establishes before the direct punch
completes — the common case, and the outcome in three of the four disruptions
observed — make-before-break then defers the punch indefinitely. The punch
can still occasionally win the race (it did once, when the relay session
itself had to re-establish), but nothing *converges* the pair back to
`direct`; `relayed` is an absorbing state until the relay leg dies. The
mechanism:

1. Both gateways lose the pair's path (restart, roster churn, anything).
2. Both race the recovery: the controller brokers a punch, and the path
   machine simultaneously tries the relay fallback.
3. For the gateway colocated with the relay, its relay leg is
   **loopback-fast** — same machine, no network — so the relay path
   establishes in milliseconds, while the punch needs the broker's
   paired `go` plus probe round-trips (seconds).
4. The relay path wins, the state machine reaches `Relayed`, and
   make-before-break then **defers the direct punch forever**, by design:

   ```
   wiremesh-gateway: peer=5 now relayed via relay=1 (127.0.0.1:54762)
   wiremesh-gateway: peer=5 path no longer connecting; deferring direct punch
       (make-before-break, relay path kept flowing)
   wiremesh-gateway: peer=5 endpoint read-through: pinning 127.0.0.1:54762
       (the endpoint the device is actually using)
   wiremesh-gateway: path peer=5 connecting -> relayed
   ```

On the live fabric this is the zolab↔fi pair (the relay runs on fi,
`95.217.118.177:4443`). Observed twice on 2026-08-27, once after the zolab
pod restart during the v0.11.1 rollout and once after a deliberate fi gateway
restart; each time the pair sat stably `relayed` for 15+ minutes with zero
transitions while every other pair went `direct`.

## What does NOT fix it, and what does

- **Restarting either gateway does not fix it.** The restart just reruns the
  race, and the relay leg wins again (verified: restarting fi's gateway
  re-landed the pair on `relayed` within seconds).
- **Restarting the relay fixes it within ~60s.** Killing the relay leg is
  exactly the case-4 unwedge: both sides lose `Relayed`, fall to
  `disconnected`, the deferred punch finally runs, and the pair lands
  `direct` (verified twice; both sides logged `connecting -> direct`).

The cost of the parked state is small — for a colocated pair the "detour" is
the same machine, so the overhead is QUIC encapsulation only — but the path
state is misleading (`relayed` reads as "NAT defeated us", which is false) and
the pair silently depends on the relay process staying up.

## Why this matters for the fast-follows

- **Make-before-break `Relayed→Direct` cutover** (the Cycle-4c fast-follow):
  this finding upgrades it from "nice to have" to the only real fix for a
  structural bias — without it, *any* colocated pair converges to `relayed`
  as its permanent steady state after its first disruption. The cutover
  design should treat "relay leg is loopback/colocated" as the expected
  common case, not an edge.
- **Backlog item 45** (`case4_relay_leg_death_unwedges_direct_punch`
  bimodality): the live fabric independently confirms the case-4 mechanism —
  relay-leg death is what unwedges the punch — and shows the *inverse* is a
  stable trap in production, not just a test-bench transition.
- **Ops guidance until the cutover ships** (also recorded in the operator's
  runbook memory): if a colocated pair must be `direct`, restart the *relay*,
  not a gateway.

## Evidence trail

- zolab gw logs, 2026-08-27 ~15:55–16:10 EEST: the deferring loop above,
  stable across 15 min with punch directives firing every 5s and no path
  transitions.
- fi gateway restart at ~16:05 EEST: pair re-landed `relayed` (fi side went
  `connecting -> relayed` at 15:08:37 fi-local time), confirming
  gateway-restart-does-not-fix.
- `systemctl restart wiremesh-relay` on fi at ~16:20 EEST: zolab logged
  `connecting -> direct`, fi logged `disconnected -> direct` within ~60s;
  repeated later the same day after the BBR init-container rollout with the
  same result (that time the pair happened to win the race and went
  `direct` without intervention — the bias is a race, so a fast punch can
  still occasionally win when the relay session itself needs re-establishing).
