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

Phase 0 spike, Cycle 2 (controller core), and Cycle 3 (policy pipeline) are
complete. Cycle 3 delivered the DSL → canonical-JSON IR compiler
(`wiremesh-policy`), the controller wiring that compiles/versions policy and
streams real `policy_ir` over Sync (+ `fabricctl policy show|status`), and the
`wiremesh-enforcer` library with **both** enforcement backends — eBPF
(tc-BPF, LPM-bitset first-match, map-in-map atomic generations, stateful flow
table, sampled deny ring buffer) and the nftables fallback — proven
behaviorally equivalent by a netns conformance packet-suite
(`wiremesh-testkit`, `--features netns`). One ratified backend divergence is
documented (one-way UDP live-flow survival; owner decision 2026-07-18, see
`docs/research/cycle3-policy-notes.md`). **Deployment note:** the nftables
backend requires `conntrack-tools` on the gateway host (`flush_flows` uses
`conntrack -F`).

Next action is Cycle 4 (gateway transport + relay: real `wiremesh-gateway`
binary consuming `wiremesh-enforcer`, NAT traversal, relay path). Also pending:
Cycle 2b fast-follow (OpenBao provider driver). Update this section as phases
complete.

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
