# Puncher-socket isolation — productionization plan

**Design:** `docs/superpowers/specs/2026-07-28-puncher-socket-isolation-design.md`
(approach B, spike verdict **GO-WITH-NUDGE 4/4**). **Branch:**
`fix/puncher-socket-isolation`. **Release:** patch (connectivity fix).

The spike proved boringtun-endpoint-driven punching completes a direct
handshake through a port-restricted NAT with NO separate `SO_REUSEPORT`
socket — eliminating the finding-§3 punch-socket starvation. Two spike
findings are load-bearing and MUST be built in (see spec §"spike RESULT"):
the prompt-init NUDGE, and avoiding the two-step peer-config boringtun panic.

## Tasks

- **T1 — Remove the reuseport puncher.** Delete `punch.rs`'s `SO_REUSEPORT`
  punch socket + parallel-probe loop (`crates/wiremesh-gateway/src/punch.rs`,
  `observe::reuseport_udp` use for punching). Keep `observe.rs`'s reuseport
  socket for the controller address-echo (out of scope, transient — spec).

- **T2 — Endpoint-driven punch with prompt-init nudge.** At the broker "go"
  (`PunchDirective`, unchanged), the gateway sets the boringtun peer's endpoint
  to the current candidate via the existing UAPI writer (using the
  make-before-break / incremental apply from v0.1.2 so it NEVER triggers a
  boringtun `update_peer` in-place modify — the spike's panic), then NUDGES
  boringtun to init immediately: write a packet through the `wg0` tun toward
  the peer's overlay IP (boringtun: "data to send, no session" → handshake
  init now, not ~26s later). No competing socket. Detect success via the
  existing T2 rx-corroborated liveness (`path.rs`).

- **T3 — Sequential candidate trial.** No handshake within a per-candidate
  timeout → set the endpoint to the next candidate + nudge; repeat.
  `punch_backoff` (v0.1.2) still bounds trials. Exhausted → existing `Relayed`
  fallback (unchanged). Wire into `run_path_ticks` replacing the reuseport
  probe path.

- **T4 — Done-bar: un-ignore the convergence tests.** Un-`#[ignore]` the two
  `crates/wiremesh-gateway/tests/convergence_matrix.rs` tests
  (`t8_convergence_incident_lifecycle` = A1-3, and
  `t8_keepalive_holds_path_state_under_punch_contention` = A4). They must now
  PASS — with no puncher socket stealing sessions, a blocked newcomer no longer
  starves established peers (A3 make-before-break session continuity, A4
  keepalive-hold under contention). If either still fails, that is a real
  finding — record it, do not weaken.

## Non-regression

- `nat_matrix` 4/4 (brokered punch → Direct must still work via the new
  endpoint-driven path), `relay_matrix` 2/2, `mesh_milestone`, the full gateway
  suite. The nudge must not break the existing direct-punch cases.

## Notes / risks

- The nudge packet: prefer writing to the tun fd the gateway already manages
  (or an equivalent that makes boringtun initiate) — keep it minimal and
  well-documented (spike finding). It must fire once per endpoint-set, not
  spam.
- Symmetric NAT still can't punch → relay (unchanged). This fix targets the
  punchable cases that were failing purely due to socket starvation (e.g. the
  zolab home↔FI pair that should be direct).

## Execution

Per-task test-author / implementer / dedicated runner / reviewer; CodeRabbit
via the coderabbit skill before push; then push → PR → CI → merge → tag →
release → re-validate on the zolab mesh (does home↔FI now go Direct?).
