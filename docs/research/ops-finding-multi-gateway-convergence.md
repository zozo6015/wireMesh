# Ops finding: 3-gateway mesh fails to converge — NAT-blocked peer destabilizes the whole fabric

**Date:** 2026-07-27/28 (first real 3-segment production deployment: zolab k8s
gateway `home`, bare-metal FI `aether`, bare-metal px `aether-dev`).
**Status:** OPEN — needs a dedicated hardening cycle with a netns conformance
suite reproducing this exact topology.

## Topology

- `home` (gw id 7, operator pod, hostNetwork on WiFi leg 10.0.125.12): behind
  consumer NAT (AmpliFi Alien); UDP 51820 forward added mid-incident.
- `aether` (gw id 5, FI host, true public IP): fully dialable. Also hosts the
  `wiremesh-relay` (deployed mid-incident, see below).
- `aether-dev` (gw id 6, px): behind NAT that DROPS unsolicited inbound to its
  observed mapping (proven: manual UDP from px→home:51820 while tcpdumping at
  home — zero arrivals; FI's packets to px:51820 never counted rx by px's wg).

## Observed failure cascade (each step evidenced in the session)

1. **Two-gateway mesh (home↔FI) worked**: direct path, real traffic (~100ms).
2. **Enrolling the third gateway (px) regressed the WORKING pair**: peer-set
   re-application reset established endpoints to static candidates (FI's
   `home` endpoint reverted to `79.119.133.77:51820`, then-undialable), and
   home↔FI never re-formed on its own. A newcomer must not break existing
   tunnels — make-before-break applies to peer-set updates too.
3. **Punch-retry storm**: px's pair with home can never complete inbound, so
   punch directives cycle every few seconds indefinitely. While punching, the
   transient same-socket `SO_REUSEPORT` punchers plausibly steal inbound WG
   packets on :51820 (the exact starvation hazard flagged in the 4c notes) —
   observed as "initiations arrive (rx grows) but are never answered" on
   MULTIPLE gateways (FI rx from px grew 16→33KB with ~0 tx back; handshake
   responses missing until fresh restarts).
4. **`last_handshake_time` false-advance** (the cycle-4b liveness caveat)
   observed live on FI (handshake 13-70s "ago" with rx_bytes=0 sustained) —
   and gw-home's path SM reported `direct` while its peer's rx stayed 0, so
   path-liveness accepted a dead tunnel. The liveness rule needs to require
   corroborating rx, not just handshake+any-rx-once.
5. **No WireGuard `persistent_keepalive` is set** — px's NAT mapping expires
   when a tunnel idles; the working px↔home path died ~20 min after forming,
   then sawtoothed (works after handshake → NAT forgets → 45s silence →
   Degraded → punch storm → occasionally re-forms). Standard WG answer: 25s
   persistent keepalive at least for peers whose observed!=local mapping.
6. **State visibility gap**: the gateway logs only path transitions; there is
   no `wiremesh_gateway` metric for per-peer rx/tx deltas or last-handshake,
   which made every diagnosis require UAPI spelunking via debug containers.

## Relay deployment (mid-incident) — worked, with two findings

`wiremesh-relay` v0.1.1 deployed on the FI host per docs/install.md:
- **Finding A (packaging bug):** the .deb's unit runs `User=wiremesh`, but
  `wiremesh-relay-enroll` (documented as sudo) writes root-owned 0600 files,
  and the documented `--certdir /var/lib/wiremesh` collides with the
  GATEWAY's root-only state dir when both run on one host. Service crash-loops
  on `Permission denied` until the identity is moved to a dedicated dir
  (`/var/lib/wiremesh-relay`, chown wiremesh:wiremesh). Packaging should use
  separate StateDirectory + a matching enroll default, or chown on enroll.
- **Finding B:** the relay's revocation Sync watch is rejected by the
  controller: `PermissionDenied: client certificate's CN does not match any
  enrolled gateway` — the Sync service does not authorize relay certs, so the
  offline denylist never updates post-enrollment. (Compounds the relay
  keepalive gap already listed in ops-finding-sync-half-open-stream.md.)
- Within seconds of start, px registered a relay pair (`owner=gw-6 peer=gw-5`
  from its real source) — advertisement + gateway pickup works.

## Suggested fast-follows (priority order)

1. `persistent_keepalive` (~25s) on peers — cheapest, kills the sawtooth for
   NAT-ed gateways and keeps punch-created mappings warm.
2. Punch back-off: a pair that repeatedly fails N punches should back off to
   slow retries (and prefer relay when available) instead of a永-storm.
3. Make-before-break peer-set updates: never reset an ESTABLISHED tunnel's
   endpoint when re-applying peers; only add/remove.
4. Path-liveness: require rx-delta corroboration before reporting `direct`
   (re-open the cycle-4b note's rule with this evidence).
5. Per-peer rx/tx/handshake metrics.
6. Relay packaging (Finding A) + relay Sync authorization (Finding B).
7. Netns conformance case: 3 gateways, one inbound-blocked NAT, relay
   present — assert full convergence and no regression of the working pair
   when the third enrolls.

## Also hit today (operator, second occurrence)

`kubectl rollout restart` of the gateway deployment destroyed the emptyDir
identity → enroll crash-loop on the spent single-use token; manual repair
(scale 0, drain, delete token Secret, nudge). PVC-backed identity and/or
auto-rebind-on-orphan remains the fix (tracked in the operator follow-ups).

## Client-side note (not a product bug)

A Twingate client on an operator workstation intercepts overlapping resource
CIDRs ahead of the mesh static routes — mesh-vs-ZTNA-client route shadowing is
worth a docs paragraph.
