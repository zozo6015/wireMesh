# Mesh-convergence hardening — fix cycle plan

**Source of truth:** `docs/research/ops-finding-multi-gateway-convergence.md`
(2026-07-27 live 3-segment deployment failure cascade, evidence-backed).
**Branch:** `fix/mesh-convergence`. **Release:** ships as v0.1.2 (patch — all
fixes, no new surface) per the release-every-fix rule.

Execution per CLAUDE.md: separate test-author / implementer / dedicated
test-runner / reviewer agents per task; all builds/tests in the dev container
(`./dev.sh run`); network tests serial; CodeRabbit before push.

## Tasks (priority order from the finding)

- **T1 — WireGuard persistent keepalive.** Set `persistent_keepalive_interval`
  (25s) on every peer the gateway configures via UAPI. Rationale: NAT-ed peers'
  mappings expire on idle → sawtooth (finding §5). Always-on for v1 (tiny
  overhead, no config knob yet). Scope: the UAPI device-config writer + its
  emission tests.

- **T2 — Path-liveness requires rx corroboration.** `path.rs` may not report
  `Direct` (nor stay in it) without an rx_bytes delta accompanying the
  handshake evidence within the liveness window; a handshake-time advance with
  flat rx is NOT liveness (boringtun false-advance, finding §4 — observed
  live: FI handshake "28s ago" with rx=0 while gw-home claimed direct).
  Scope: path.rs state machine + its transition tests.

- **T3 — Punch back-off.** A peer pair whose punches fail N consecutive times
  (start N=3) backs off exponentially (base 30s, cap 5min, jitter) instead of
  re-punching on every directive; a successful punch or fresh candidate set
  resets the counter. While backed off, directives for that pair are skipped
  (log once per state change, not per directive). Rationale: finding §3 —
  permanently-undialable peer produced an indefinite punch storm with
  collateral SO_REUSEPORT interference. Scope: gateway punch driver in
  main.rs (extract testable pure decision state if needed).

- **T4 — Make-before-break peer-set application.** Re-applying desired state
  must not clobber an ESTABLISHED peer's live endpoint back to a static
  candidate: diff peers; only add/remove peers or update keys/allowed-ips;
  never rewrite the endpoint of a peer whose tunnel currently shows liveness
  (post-T2 definition). Rationale: finding §2 — px's enrollment reset FI's
  established home endpoint and broke a working pair. Scope: the desired-state
  apply/reconcile path.

- **T5 — Per-peer observability.** Metrics: per-peer `rx_bytes`, `tx_bytes`,
  `last_handshake_age_seconds` gauges (labels: peer id), sourced from the same
  UAPI fetch the path SM uses. Rationale: finding §6 — every diagnosis tonight
  required UAPI spelunking via debug containers.

- **T6 — Controller authorizes relay certs on the revocation watch.** The
  relay's `Sync.Watch` is rejected (`client certificate's CN does not match
  any enrolled gateway`) so its offline denylist never updates (finding
  "Relay Finding B" — security-relevant staleness). Authorize enrolled RELAY
  identities for the revocation-bearing watch (scoped: relays must not
  receive gateway desired-state). Scope: controller sync service authz +
  a testkit case (relay cert watch succeeds, sees revoked_serials, does NOT
  see gateway state).

- **T7 — Relay packaging fix.** The .deb unit runs `User=wiremesh` but
  documented enroll writes root-owned files into the GATEWAY's root-only
  state dir (`/var/lib/wiremesh`) — crash-loop on shared hosts (finding
  "Relay Finding A"). Fix: dedicated `/var/lib/wiremesh-relay` default in
  unit (StateDirectory) + relay.env template + docs/install.md, and
  `wiremesh-relay-enroll` chowns to the service user when run as root (or
  clearly errors). Scope: deploy/packages + enroll binary UX.

- **T8 — Done-bar: netns convergence conformance.** New testkit case
  reproducing the incident topology: three gateways (A public, B behind
  port-restricted NAT with inbound forward, C behind inbound-DROP NAT), relay
  available. Assertions: (1) A↔B direct; (2) C's pairs settle (relay or
  direct) without punch-storming — punch attempts for a blocked pair bounded
  over an interval; (3) enrolling C does NOT break an established A↔B pair
  (traffic flows continuously across the peer-set update); (4) idle 90s, then
  traffic still flows A↔B and to C (keepalive holds mappings). Mandatory
  netem latency per harness convention.

## Sequencing

T1 → T2 → T5 (each small, distinct modules) → T3 → T4 (both touch the boot
loop; sequential) → T6, T7 (independent) → T8 last (validates the lot).
Non-regression gate after each task: gateway suite + mesh_milestone
(`--features netns-tests`); full nat_matrix/relay_matrix before the PR.
