# Ops finding: 3-gateway mesh fails to converge — NAT-blocked peer destabilizes the whole fabric

**Date observed:** night of 2026-07-27, continuing past midnight into
2026-07-28 (a single session — the first real 3-segment production deployment:
zolab k8s gateway `home`, bare-metal FI `aether`, bare-metal px `aether-dev`).
**Status:** PARTIALLY RESOLVED (2026-07-28). The mesh-convergence fix cycle
(branch `fix/mesh-convergence`) delivered T1–T7 (see "Suggested fast-follows"
below, each now marked with its landed/carried state). The deeper punch-socket
starvation root cause remains OPEN — carried to a dedicated puncher-socket
isolation cycle, with the two `#[ignore]`d `convergence_matrix` tests as its
executable done-bar.

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

## Deeper root cause the T8 done-bar proved (2026-07-28): punch-socket starvation is a SEPARATE bug from the attempt-count storm

The §3 fix (T3 punch back-off) bounds how OFTEN a permanently-undialable
pair may punch — and the netns done-bar's anti-storm pin confirms it holds
(attempt COUNT toward a blocked pair stays bounded over a fixed window). But
the T8 done-bar surfaced that bounding the count is **not sufficient**: the
harm §3 hinted at ("transient SO_REUSEPORT punchers plausibly steal inbound
WG packets on :51820") is real and independent of attempt frequency.

**Mechanism (proved under netns):** every punch attempt — even one the
back-off admits — opens a transient same-port `SO_REUSEPORT` socket on the
gateway's SHARED WireGuard listen port (:51820). While that puncher is open,
inbound WireGuard datagrams on :51820 destined for an *already-established,
unrelated* peer can be delivered to the puncher socket instead of boringtun,
so that established peer's inbound liveness (keepalives/data) is starved.

**Observable in the done-bar (clean netns run, 2026-07-28):** with gateway C
permanently un-punchable (its NAT drops peer-sourced inbound UDP) both A and
B keep issuing bounded punch attempts toward C; each attempt opens a
transient puncher on that gateway's own :51820. At ~t+8.6s after C enrolls,
gwA's and gwB's path SMs still both report the A↔B peer `direct` and the A↔B
WG **endpoints are intact** (the endpoint-preserving add-only apply, commit
0302d2c, prevents the endpoint clobber of §2 item 2) — yet the ESTABLISHED
A↔B WG **session** has reset (`latest handshake` back to 0/never, rx frozen
near zero), so a FRESH workload connection opened across the window cannot
complete its handshake and times out. The observed fact is:
**make-before-break at the ENDPOINT level is necessary but not sufficient —
under a concurrent punch storm toward a permanently-blocked newcomer, the
established pair still loses its live session for several seconds.** The
primary cause is the punch-socket starvation above (C-directed punchers on
gwA/gwB :51820 stealing the A↔B rehandshake response); a secondary
contributor to disambiguate during the fix is whether adding C also triggers
a session-rebuilding apply on the A↔B peer despite the add-only path being
taken for the endpoint — but both point at the same architectural fix
(§ "Fix direction" below).

Note this refines (does not match) the earlier hand-diagnosis that "on-demand
A↔B data keeps crossing while only the path SM flaps": in the netns repro the
session reset does interrupt fresh data-plane connections, not merely the
liveness SM — a long-lived flow may tolerate the gap better than the
fresh-connection probe the done-bar uses, but the session reset is real.

**Why T1/T2/T3 don't cover it:** T1 (persistent keepalive) keeps the mapping
warm but cannot help if the keepalive's inbound reply is stolen before it
reaches boringtun; T2 (rx-liveness) then *correctly* reports the path as not
live (rx really did stall) — the SM flap is a true negative, not a false one;
T3 bounds attempt count but each admitted attempt still opens the thieving
socket; T4 preserves the endpoint but not, under this contention, the live
session. The defect is architectural: **the puncher must not share or steal
the WG listen socket** (and the reconcile path must not rebuild an
established peer's session when a newcomer is added).

**Fix direction (next cycle):** give the puncher a DEDICATED socket / keep it
off the WG listen port so a punch in flight can never intercept an
established peer's inbound WG traffic; alternatively (or additionally)
resolve the boringtun live `remove_peer`+re-add relay-session bug that
blocked the surgical single-peer endpoint-update alternative (see
`crates/wiremesh-gateway/src/main.rs::set_peer_endpoint`'s caveat), which
would let the reconcile path avoid full-device re-applies that compound the
contention window.

**Done-bar for it — BOTH tests in
`crates/wiremesh-gateway/tests/convergence_matrix.rs` are `#[ignore]`d
against this root cause** (assertions preserved intact and un-weakened as the
next cycle's executable spec; un-ignore both once the puncher is off the
shared WG port):

- `t8_convergence_incident_lifecycle` (assertions 1–3): assertions 1 (A↔B
  direct) and 2 (C settles relayed, bounded punch attempts) PASS; assertion 3
  (make-before-break session continuity) is blocked — adding C while C
  punch-storms its blocked pairs resets the established A↔B session (above),
  so the fresh-connection continuity probe fails ~t+8.6s after C's enrollment
  even though endpoints/path-state are preserved.
- `t8_keepalive_holds_path_state_under_punch_contention` (assertion 4): path
  state must hold through a 90s idle and post-idle traffic must flow without a
  re-punch cycle — blocked by the same session reset/starvation.

Both go green once the session-preservation gap is closed. What the done-bar
PROVED, concisely: (a) endpoint-level make-before-break works (endpoints and
path_state preserved — verified live) but is insufficient; (b) under a
permanently-blocked newcomer's punch storm, established peers' WG SESSIONS
reset (handshake→0, rx frozen) even with the add-only apply, so BOTH A3 and
A4 fail; (c) root cause = the transient SO_REUSEPORT punch socket on the
shared :51820 stealing other peers' inbound; (d) fix = a dedicated puncher
socket / stop sharing the WG listen port (and/or resolve the boringtun
remove+re-add relay-session bug).

## Relay deployment (mid-incident) — worked, with two findings

`wiremesh-relay` v0.1.1 deployed on the FI host per docs/install.md:
- **Finding A (packaging bug) — RESOLVED (T7, this cycle):** the .deb's unit
  ran `User=wiremesh`, but `wiremesh-relay-enroll` (documented as sudo) writes
  root-owned 0600 files, and the documented `--certdir /var/lib/wiremesh`
  collided with the GATEWAY's root-only state dir when both run on one host —
  the service crash-looped on `Permission denied`. Fixed: dedicated
  `StateDirectory=/var/lib/wiremesh-relay` in the unit + `relay.env`/docs
  default, a `postinstall-relay.sh`, and chown-when-root in the enroll binary.
- **Finding B — RESOLVED (T6, this cycle):** the relay's revocation Sync watch
  was rejected by the controller (`PermissionDenied: client certificate's CN
  does not match any enrolled gateway`) because the Sync service authorized
  only gateway certs, so the offline denylist never updated post-enrollment.
  Fixed: the controller now authorizes enrolled relay certs on a
  revocation-scoped watch (`watch_relay`, revoked_serials only, no
  peers/policy, structurally out of the punch broker). (The relay Sync
  channel's own keepalive gap remains tracked in
  ops-finding-sync-half-open-stream.md.)
- Within seconds of start, px registered a relay pair (`owner=gw-6 peer=gw-5`
  from its real source) — advertisement + gateway pickup works.

## Suggested fast-follows (priority order)

1. `persistent_keepalive` (~25s) on peers — cheapest, kills the sawtooth for
   NAT-ed gateways and keeps punch-created mappings warm.
2. Punch back-off: a pair that repeatedly fails N punches should back off to
   slow retries (and prefer relay when available) instead of a storm.
   **(DONE as T3 — bounds attempt COUNT. But see "Deeper root cause the T8
   done-bar proved" above: bounding count is not enough; the puncher must ALSO
   stop sharing/stealing the WG listen socket. That part is CARRIED to the
   next cycle.)**
3. Make-before-break peer-set updates: never reset an ESTABLISHED tunnel's
   endpoint when re-applying peers; only add/remove. **(DONE as T4 +
   incremental add-only apply — endpoint level. NOTE: proven necessary but
   NOT sufficient — session-level continuity under punch contention is the
   carried punch-socket item above.)**
4. Path-liveness: require rx-delta corroboration before reporting `direct`
   (re-open the cycle-4b note's rule with this evidence). **(DONE as T2; the
   boringtun elapsed-vs-absolute handshake-timestamp bug was the real cause —
   see "boringtun" note.)**
5. Per-peer rx/tx/handshake metrics. **(DONE as T5.)**
6. Relay packaging (Finding A) + relay Sync authorization (Finding B).
   **(DONE as T7 + T6.)**
7. Netns conformance case: 3 gateways, one inbound-blocked NAT, relay
   present — assert full convergence and no regression of the working pair
   when the third enrolls.

## Security follow-up (surfaced during T6 review — separate, cross-cutting)

`Admin.RevokeCert` sets `certificate.revoked_at` and bumps the revision (so the
serial enters the data-plane `revoked_serials` denylist), but it does NOT sever
an already-open control-plane `Sync.Watch`: neither `find_gateway_by_name` nor
`find_relay_by_name` joins to `certificate.revoked_at` — gateway/relay watch
authorization gates on ROW status (`active`, and drain/rebind flip it), not on
cert revocation. So a cert revoked WITHOUT a drain/rebind keeps its holder's
control-plane watch open (for a gateway: full topology + policy; for a relay:
the revoked_serials denylist only). The relay path (T6) is deliberately
CONSISTENT with the gateway path here — guarding only the relay watch would
protect the low-sensitivity surface while leaving the high-sensitivity gateway
watch open, which is backwards. The real de-authorization control today is
data-plane (peers/relay reject the revoked serial). If control-plane watches
should reject revoked certs, that is a UNIFORM change across `watch_gateway` +
`watch_relay` (thread the leaf serial from `peer_identity()`, add a shared
`revoked_at IS NULL` check) — a distinct security-hardening item with its own
test surface (it would contradict the current `rebind.rs` expectation that
revocation surfaces via the denylist, not the watch gate). NOT done in this
cycle; recommended if revocation is meant to cut active control-plane access.

## Also hit today (operator, second occurrence)

`kubectl rollout restart` of the gateway deployment destroyed the emptyDir
identity → enroll crash-loop on the spent single-use token; manual repair
(scale 0, drain, delete token Secret, nudge). PVC-backed identity and/or
auto-rebind-on-orphan remains the fix (tracked in the operator follow-ups).

## Client-side note (not a product bug)

A Twingate client on an operator workstation intercepts overlapping resource
CIDRs ahead of the mesh static routes — mesh-vs-ZTNA-client route shadowing is
worth a docs paragraph.

## Puncher-socket-isolation productionization (2026-07-29): test-coverage note

The §3 fix (endpoint-driven punch + prompt-init nudge, no `SO_REUSEPORT` punch
socket) removed `crates/wiremesh-gateway/src/punch.rs`'s `punch_candidates` and
its `observe::reuseport_udp` use. The old `tests/punch_netns.rs` — which drove
two `SO_REUSEPORT` sockets through a port-restricted NAT and confirmed a punch
via a `PING`/`PONG` exchange — tested a mechanism that no longer exists, so it
was **removed** (not ported): the punch is now boringtun's own handshake, which
requires a full boringtun device and is exercised end-to-end by
`tests/nat_matrix.rs` (brokered punch → real WG handshake → `Direct` through a
port-restricted NAT), `tests/mesh_milestone.rs`, and the un-ignored
`tests/convergence_matrix.rs` done-bar. The new pure surfaces
(`nudge_target`/`nudge_peer`/`CandidateTrial`) are unit-pinned by
`tests/punch_endpoint_driven.rs`. Net coverage is preserved and strengthened.
