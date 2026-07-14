# AetherLink

Open-source (Apache-2.0), fully self-hosted, cloud-agnostic zero-trust L3/L4 network
fabric in Rust. Connects network *segments* (VPCs, VLANs, subnets) via one gateway per
segment — WireGuard data plane, default-deny L4 policy, no agents on workloads.
The project ships binaries and docs, never hosted infrastructure.

## Document map (authority order)

1. `docs/superpowers/specs/2026-07-15-aetherlink-engineering-design.md` — **approved
   engineering design**; its §1 decision record and §11 amendments supersede the PRD
   where they conflict (eBPF-first enforcement, per-gateway key epochs, single-tenant
   controller, no SaaS).
2. `docs/PRD.md` — product requirements (v0.1, pending v0.2 fold-in of spec §11).
3. `docs/superpowers/plans/2026-07-15-phase0-spike.md` — current implementation plan
   (Phase 0: 5 de-risk bets, 15 tasks).

## Project state

Pre-code: docs only. Next action is Phase 0 Task 1 (dev container). Update this
section as phases complete.

## Agent workflow rules

- **Tests are written by a different agent than the one that writes the code under
  test.** Dispatch separate subagents for test authoring and implementation.
- **Reviews are done by a different agent than the one that wrote the code.** Never
  review your own artifacts inline; dispatch independent reviewer subagents.
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
