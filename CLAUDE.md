# WireMesh

Open-source (Apache-2.0), fully self-hosted, cloud-agnostic zero-trust L3/L4 network
fabric in Rust. Connects network *segments* (VPCs, VLANs, subnets) via one gateway per
segment — WireGuard data plane, default-deny L4 policy, no agents on workloads.
The project ships binaries and docs, never hosted infrastructure.

## Document map (authority order)

1. `docs/superpowers/specs/2026-07-15-wiremesh-engineering-design.md` — **approved
   engineering design**; its §1 decision record and §11 amendments supersede the PRD
   where they conflict (eBPF-first enforcement, per-gateway key epochs, single-tenant
   controller, no SaaS).
2. `docs/PRD.md` — product requirements (v0.1, pending v0.2 fold-in of spec §11).
3. `docs/superpowers/plans/2026-07-15-phase0-spike.md` — current implementation plan
   (Phase 0: 5 de-risk bets, 15 tasks).

## Project state

Phase 0 spike, Cycle 2 (controller core), Cycle 3 (policy pipeline), Cycle 4a
(direct-only gateway), Cycle 4b (NAT traversal), and Cycle 4c (relay path) are
complete. Cycle 3
delivered the DSL →
canonical-JSON IR compiler (`wiremesh-policy`), the controller wiring that
compiles/versions policy and streams real `policy_ir` over Sync (+ `fabricctl
policy show|status`), and the `wiremesh-enforcer` library with **both**
enforcement backends — eBPF (tc-BPF, LPM-bitset first-match, map-in-map
atomic generations, stateful flow table, sampled deny ring buffer) and the
nftables fallback — proven behaviorally equivalent by a netns conformance
packet-suite (`wiremesh-testkit`, `--features netns`). One ratified backend
divergence is documented (one-way UDP live-flow survival; owner decision
2026-07-18, see `docs/research/cycle3-policy-notes.md`).

Cycle 4a delivered the real `wiremesh-gateway` binary: mTLS Sync client, an
in-process WireGuard UAPI writer driving embedded boringtun, enforcer wiring
(eBPF/nftables, version-gated apply), fail-static `state.json` boot, SO_REUSEPORT
endpoint observation, tun MTU 1280 + nft MSS clamp, and Prometheus metrics. The
full-mesh netns milestone (`crates/wiremesh-gateway/tests/mesh_milestone.rs`)
passes all four done-bar assertions — allowed traffic, denied+counter,
fail-static (controller-independent), policy-update — with two real gateway
processes. **Scope decisions this cycle:** key rotation DEFERRED to a
fast-follow (4a ships static single-epoch keys); a proto change was made —
`EnrollRequest` gained `wg_pubkey` so gateways register their real WireGuard
public key at enrollment (epoch-0 baseline), since the Cycle-2/3 controller
only stored placeholder keys; an additive controller `Config.bind_ip`
(default `127.0.0.1`) was added for the netns milestone; the G-2 throughput
number is DEFERRED to a cloud 4-vCPU run (bench built and smoke-tested,
not measured — see `crates/wiremesh-gateway/bench.md` and
`docs/research/phase0-results.md`).

Cycle 4b delivered controller-brokered simultaneous hole punching: a new
`PunchDirective` `SyncMessage` variant with a controller broker that sends
both pair members' directives back-to-back (go-skew held below one-way
latency, per Phase-0 Finding 2), the gateway's transient same-socket
`SO_REUSEPORT` puncher (de-risked first by `spike/natpunch`, 4/4 runs, before
any broker/state-machine work was built on it), a multi-candidate model
(observed public mapping + gateway-reported local addresses via the new
`ReportRequest.local_endpoints` field, empty-list-clears semantics), and the
`Connecting/Direct/Degraded/Relayed/Disconnected` path state machine
(`path.rs`) driven off the WG UAPI read side. NAT-matrix netns conformance
(`crates/wiremesh-gateway/tests/nat_matrix.rs`, mandatory `tc netem delay
20ms`) passes all 4 done-bar cases: port-restricted→Direct with a real WG
handshake, symmetric→clean relay-needed verdict, go-skew determinism, and
Direct→Degraded after 45s silence. **Relay transport is explicitly out of
scope** — `Relayed` is wired but inert (a placeholder verdict, not a working
path); that's Cycle 4c. A path-liveness product bug (boringtun's
`last_handshake_time` can advance with no corroborating `rx_bytes` for a
peer retrying an unanswered handshake) was found and fixed during
conformance — see `docs/research/cycle4b-path-liveness-note.md` and
`docs/research/cycle4b-nat-traversal-notes.md`.

Cycle 4c delivered the relay path (productionizing the Phase-0 `spike/relay`
Bet-3 mTLS QUIC-datagram bridge and filling 4b's inert `Relayed` seam): the
`wiremesh-relay` binary (QUIC datagram bridge, mandatory mTLS, an offline
revocation denylist), controller relay enrollment (`Enroll --kind relay`) +
advertisement (`RelaysChanged` deltas) + a health/eviction pipeline (≤15s), a
`RelayInfo`/`RelayHealth` proto surface, and the gateway `RelayTransport`
(local UDP ↔ QUIC) wired into the path state machine with a **rekey-free**
endpoint switch to the relay socket. The netns done-bar
(`crates/wiremesh-gateway/tests/relay_matrix.rs`) proves a **symmetric-NAT
pair whose direct punch fails flows real WG traffic over the relay** (`path =
relayed`, relay-local endpoints, never `direct`) — reliably green; relay
eviction/re-path is `case3`. Denylist (offline certless + revoked rejection)
and the MTU-1280 datagram floor are covered by
`wiremesh-relay/tests/{denylist,bridge}.rs`. **A genuine long-standing eBPF
bug was found+fixed** (the ICMP-echo reverse-flow key asymmetry, a known
Phase-0 carry — echo replies missed the flow table; Cycle-3 conformance stays
22/22). See `docs/research/cycle4c-relay-notes.md` +
`cycle4c-relay-stability-note.md`. **Scope:** the make-before-break
`Relayed→Direct` cutover (done-bar case 2) is a documented **fast-follow** —
WireGuard doesn't force a fresh noise handshake on a UAPI endpoint change, so
reliable direct-cutover detection needs a forced rehandshake; the relay path
itself is stable and the direct probe is rate-limited so it never disrupts it.

**Deployment notes:** the nftables enforcer backend requires
`conntrack-tools` on the gateway host (`flush_flows` uses `conntrack -F`);
the gateway binary itself requires `iproute2` and `nftables` on the host
(route/link programming and the MSS clamp shell out to `ip`/`nft`). The
`wiremesh-relay` binary needs its identity (cert/key/ca, from fabric-CA
enrollment with `--kind relay`) at `/var/lib/wiremesh/` — the certificate,
private-key, and CA identity files EACH require mode 0600 individually (not
just the containing directory).

Next action: the Cycle-4c fast-follows (make-before-break direct cutover;
`relay_pair_id` width + per-relay connection multiplexing) and the
key-rotation fast-follow (carried from 4a). Also pending: Cycle 2b fast-follow
(OpenBao provider driver). Update this section as phases complete.

## Agent workflow rules

- **Tests are written by a different agent than the one that writes the code under
  test.** Dispatch separate subagents for test authoring and implementation.
- **Reviews are done by a different agent than the one that wrote the code.** Never
  review your own artifacts inline; dispatch independent reviewer subagents.
- **Tests are executed by a dedicated agent — neither the agent that wrote the code
  nor the agent that wrote the tests.** Whoever has a stake in a green run must not
  be the one that runs it and reports the result. Dispatch a separate agent to run
  the suite and relay the raw output, per superpowers:test-driven-development
  (and superpowers:subagent-driven-development for the per-task flow).
- **Tests must ALWAYS pass before declaring a goal reached.** No "done" claims with
  failing, skipped, or unrun tests — show the passing output.
- **When tests fail, fix the code — never arrange the tests to match the code.**
  Weakening assertions, widening tolerances, or deleting cases to get green is
  prohibited. (In this spike specifically, a "failing" behavior test may be a real
  finding about the design — investigate and record it in `docs/research/` before
  touching anything.)

## Execution rules (from the plan — non-obvious)

- Host is macOS; **all code/tests run inside the privileged Linux container** via
  `./dev.sh {build|shell|run <cmd>}` (exists after Phase 0 Task 1). tun/eBPF/netns/
  nftables do not work on the host.
- Network tests are serial: `cargo test -- --test-threads=1 --nocapture`.
- Each `spike/*` crate is standalone — no root cargo workspace (the aya template
  ships its own workspace and must not be nested).
- v1 is IPv4-only; measured numbers go in `docs/research/phase0-results.md`, never
  just the terminal.
