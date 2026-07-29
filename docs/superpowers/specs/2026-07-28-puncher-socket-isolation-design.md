# Puncher-socket isolation — design

**Status:** approved (brainstorm 2026-07-28). **Branch:** `fix/puncher-socket-isolation`.
**Authority:** this design sits under the engineering design + PRD (CLAUDE.md
document map). **Problem source:** `docs/research/ops-finding-multi-gateway-convergence.md`
§3 "punch-socket starvation", confirmed on the all-v0.1.2 zolab/FI/px production
mesh — with every gateway on v0.1.2 and the path state machine stable, NO pair
achieves a direct path (not even home↔FI, both dialable), all fall back to a
non-functional relay.

## Problem

The gateway hole-puncher opens a transient `SO_REUSEPORT` UDP socket on the
SAME port as boringtun's WireGuard listen socket (`:51820`) — necessary so the
punch's outbound packet opens the NAT mapping the WG data plane then uses. But
`SO_REUSEPORT` makes the kernel hash *inbound* datagrams across every socket in
the group, so a peer's WireGuard handshake can be delivered to the puncher
socket and dropped instead of reaching boringtun. Held open near-continuously
under a permanently-un-punchable peer's retries, this starves established and
establishing peers' sessions (handshake→0, rx frozen). boringtun owns its UDP
socket internally (`DeviceHandle::new`), configured only via the UAPI writer —
the gateway cannot inject into or demux boringtun's socket without a second
socket, which is the whole problem.

## Chosen approach (B): boringtun-endpoint-driven punch — no separate socket

The punch exists only to send an outbound UDP packet from `:51820` toward a
peer candidate, opening the NAT mapping. boringtun ALREADY does exactly that:
given a peer endpoint and no valid session, it sends handshake initiations from
`:51820`. So we delete the separate puncher socket and let boringtun's own
handshake traffic be the punch.

### Flow (replaces the reuseport-probe flow)

1. Controller broker is UNCHANGED — `PunchDirective` (candidate list +
   simultaneous "go" within one one-way latency, Phase-0 Finding 2) still
   coordinates both peers.
2. At "go", the gateway sets the boringtun peer's endpoint to the first
   candidate via the UAPI writer. boringtun emits a handshake initiation from
   `:51820` to that endpoint → opens the NAT mapping; the peer does the same
   toward us; the initiations cross.
3. Success = a real WG handshake, detected by the existing T2 rx-corroborated
   liveness (`path.rs`, `run_path_ticks`).
4. No handshake within a per-candidate timeout → set the endpoint to the next
   candidate; repeat (SEQUENTIAL trial — accepted trade-off vs today's parallel
   probe).
5. Candidates exhausted with no handshake → existing `Relayed` fallback,
   UNCHANGED.

### Why the timing is safe for punchable NATs

For a port-restricted NAT (the punchable case, endpoint-independent mapping +
address/port-restricted filtering), once our boringtun has sent any outbound to
the peer's endpoint, our NAT admits inbound FROM that endpoint. So the crossing
tolerance is the conntrack UDP window (tens of seconds) — comfortably within
boringtun's ~5s handshake-retry cadence, so precise sub-latency go-skew is NOT
required here. Symmetric/address-dependent NATs never punched anyway and go to
relay (unchanged). **The one risk to prove: boringtun must emit its handshake
init promptly enough on endpoint-set — de-risked by the spike before any
gateway change.**

## De-risk spike RESULT (2026-07-29): GO-WITH-NUDGE — approach B works

`spike/natpunch2` ran **4/4 green** (after hardening its own wedging harness:
`wg show` UAPI reads can deadlock, so the spike uses ground-truth ping as the
authoritative liveness signal). **Boringtun-endpoint-driven punching reliably
completes a direct WG handshake through a port-restricted NAT with NO separate
`SO_REUSEPORT` socket** — the core premise is proven. Two findings the
productionization MUST incorporate:

1. **The prompt-init NUDGE is required.** boringtun 0.6.0 emits handshake inits
   only on its persistent-keepalive tick (measured ~26s at keepalive=25, ~6s at
   keepalive=5) — setting the peer endpoint via UAPI does NOT trigger an
   immediate init, so a punch would otherwise take ~26s to establish. The
   productionized path must NUDGE boringtun to init promptly right after setting
   the endpoint at the broker "go", WITHOUT adding a competing socket. The
   clean nudge: **write a packet through the `wg0` tun toward the peer's overlay
   IP** (boringtun sees "data to send, no session" → initiates the handshake
   immediately) — the standard WireGuard "ping to trigger handshake" technique,
   which uses the tun, not a UDP socket. (Do NOT rely on lowering
   persistent_keepalive as the nudge — it changes keepalive semantics and is
   still tick-bounded.)
2. **Avoid the two-step peer-config panic.** A real gateway bug the spike hit:
   configuring a peer in two steps (add, then modify) panics boringtun 0.6.0's
   `update_peer` ("Modifying existing peers is not yet supported"). The
   endpoint-driven punch must set the peer's endpoint in a way that does not
   trigger an in-place modify of an existing boringtun peer — configure the
   endpoint atomically with the peer, or via the make-before-break/incremental
   apply already in the gateway (v0.1.2), never a modify.

## De-risk spike (gates the productionization)

`spike/natpunch2` — a standalone crate (no root workspace, per the spike
convention), following `spike/natpunch`'s harness:

- Two netns "gateways", each behind a port-restricted NAT (`natlab`/testkit
  primitives), mandatory `tc netem` latency, a minimal broker sending a
  coordinated "go".
- At "go", each side sets a REAL boringtun peer's endpoint to the other's
  observed candidate — NO `SO_REUSEPORT` socket anywhere — and asserts a real
  WG handshake completes (direct path) reliably (bar: 4/4 runs, matching
  natpunch).
- Answered (spike RESULT above): boringtun does NOT emit an init promptly on an
  endpoint-set — it waits for its ~26s persistent-keepalive tick — so a nudge IS
  required. The productionization uses the tun-based nudge (write a packet toward
  the peer overlay IP → boringtun inits immediately), WITHOUT reintroducing a
  competing socket. See "spike RESULT: GO-WITH-NUDGE".
- Records its result in `docs/research/` (go/no-go + runs), like every spike.

## Scope

- **Removed:** `crates/wiremesh-gateway/src/punch.rs`'s `SO_REUSEPORT` puncher
  socket + parallel-probe loop (the §3 source). Its `reuseport_udp` use goes;
  `punch.rs` either shrinks to the candidate-trial driver or is folded into the
  path-SM driver.
- **Changed:** `path.rs` / `run_path_ticks` `Connecting` handling → sequential
  candidate-trial driven off handshake detection (set endpoint → await liveness
  → next candidate → relay). `punch_backoff` STAYS and now bounds
  candidate-trial attempts (its contract is unchanged; the thing it counts is
  now "trials", not "reuseport probes").
- **Kept unchanged:** the controller broker, `PunchDirective` + go coordination,
  the relay fallback, the T2 rx-corroborated liveness, the make-before-break /
  incremental-add apply.
- **Explicitly OUT OF SCOPE (follow-up):** `observe.rs`'s brief `SO_REUSEPORT`
  socket for the controller address-echo. It is transient (not the
  near-continuous §3 culprit) and genuinely needs its own socket to receive a
  non-WG reply. Narrowing this cycle to the confirmed punch-socket bug; noted
  as a candidate follow-up in the research doc.

## Done-bar

1. `spike/natpunch2` green (4/4) — proves the mechanism BEFORE any gateway edit.
2. The two `#[ignore]`d `crates/wiremesh-gateway/tests/convergence_matrix.rs`
   tests UN-IGNORED and passing (make-before-break session continuity +
   keepalive-hold under a permanently-blocked peer — satisfied because no
   puncher exists to steal established sessions). If either still can't pass,
   that is a real finding, recorded, not weakened.
3. `nat_matrix` 4/4 (regression gate — brokered punch → Direct must still work),
   plus `relay_matrix` 2/2 and `mesh_milestone`.

## Release

Behavior fix → patch bump **v0.1.2 → v0.1.3** per the release-every-fix rule.

## Execution

Spike first (de-risk), then per-task test-author / implementer / dedicated
runner / reviewer (CLAUDE.md agent workflow); CodeRabbit before push. All
builds/tests in the Linux dev container; network tests serial.
