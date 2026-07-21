# Cycle 4c Task 9 — relay-path stability debug note (`relay_matrix.rs` case 1 flake)

## Symptom

`case1_symmetric_pair_flows_over_relay` (both gateways behind symmetric NAT,
direct punch impossible by NAT-kind construction, relay is the only working
path) was flaky: the overlay ping never crossed the relayed tunnel, and both
gateways' stderr logs showed the path state repeatedly churning
`connecting -> relayed -> ... -> disconnected -> connecting`, alongside a
flood of `"punch already in flight; skipping"` and, on the observation loop,
intermittent `"observe failed: no observation reply"`.

## Root cause

`Path::tick`'s `Relayed` arm (`crates/wiremesh-gateway/src/path.rs`) returned
`PathAction::ProbeDirect` on **every** call while the relay stayed available —
i.e. roughly every `PATH_TICK_PERIOD` (~1s), with no rate limiting at all.
`run_path_ticks` (`main.rs`) turns that action into a spawned
`punch_and_apply`, which runs the transient same-port `SO_REUSEPORT` puncher
(`punch::punch_candidates`) for `PUNCH_WINDOW` (6s). Since the punch window
outlives a tick, in steady state a fresh `ProbeDirect` request landed on
almost every tick while the previous punch was still running, was rejected by
`PathCtx::try_start_punch`'s dedup guard (the "punch already in flight;
skipping" log line), and was immediately retried the instant that guard
released — so the punch socket was open, or about to reopen, essentially the
entire time the peer was `Relayed`.

That socket is the actual disruptor: `punch::punch_candidates` binds
`0.0.0.0:<wg_listen_port>` with `SO_REUSEPORT`, sharing the WG listen port
with boringtun's own socket. Separately, `main.rs::ensure_relay_transport`
points a relayed peer's `RelayTransport` downlink at
`127.0.0.1:<wg_listen_port>` (the `local_peer_hint` passed to
`RelayTransport::start`) — i.e. the relay's locally-forwarded WireGuard
datagrams are delivered to the exact same port the transient punch socket is
bound on via `SO_REUSEPORT`. Linux distributes `SO_REUSEPORT`-group traffic
per flow using a hash that gets recomputed whenever the reuseport group's
membership changes (a socket joining or leaving), so opening/closing the
punch socket on this near-continuous cadence could — and empirically did —
reassign the relay's inbound flow to the (short-lived, punch-purpose-only)
socket instead of boringtun's, silently dropping the punch socket's `PING`/
`PONG`-only reader would just ignore whatever it got. Net effect: an
otherwise perfectly healthy relay path stopped delivering WireGuard traffic
to boringtun for as long as the punch churn continued, so no handshake ever
completed and the ping never crossed. (The same reuseport-group churn is a
plausible contributor to the observation loop's intermittent "no
observation reply" — `observe::report_once` also binds a transient
`SO_REUSEPORT` socket on the same port, briefly, every `OBSERVE_PERIOD`.)

## Fix

`path.rs`: added `PROBE_DIRECT_INTERVAL` (20s) and a new `Path` field
`relayed_probe_last`. Entering `Relayed` (from either `Connecting` or
`Degraded`) now starts a full grace period before the *first* probe of that
`Relayed` spell; thereafter `ProbeDirect` fires at most once per
`PROBE_DIRECT_INTERVAL`, not every tick. This both gives a freshly-relayed
path a long, undisturbed window to actually establish traffic flow, and
drops the punch socket's on-the-wire duty cycle to roughly `PUNCH_WINDOW /
PROBE_DIRECT_INTERVAL` (~30%) in steady state, with long clean gaps in
between.

`main.rs`: no change was needed to `punch_and_apply`/`set_peer_endpoint`
itself — they already only repoint the WG endpoint on a CONFIRMED punch
result, never unconditionally, so the "clobbering the endpoint via
reconcile" hypothesis considered up front was ruled out by inspection (a
symmetric-NAT punch essentially never confirms, matching `nat_matrix.rs`'s
`case2_symmetric_relay_needed`). Also added: pruning of `PathCtx::
relay_pointed`/`relay_next_idx` and closing+removing stale `relay_transports`
entries for any peer no longer present in the latest desired state, to avoid
unbounded growth (minor review carry, unrelated to the flake itself).

## Scope note

This fix makes the RELAY path stable and reliable for a pair whose NAT kind
makes direct recovery genuinely impossible (this test's scenario) — it does
not change (and does not need to change) the actual `Relayed -> Direct`
cutover logic itself, which was already gated correctly on a real confirmed
punch. Validating that a live make-before-break cutover reliably completes
for a NAT pairing where the punch *can* succeed is out of scope for this
task; see `crates/wiremesh-gateway/tests/nat_matrix.rs` for the existing
direct-punch-succeeds coverage (4b) and the Cycle 4c fast-follow list for any
further relay<->direct cutover conformance work.

## Verification

- `path.rs` unit tests: `relayed_grants_a_full_grace_period_before_the_first_probe`
  and `relayed_probes_direct_at_a_low_bounded_rate` (new), plus the existing
  `relayed_repaths_to_disconnected_when_relay_lost` /
  `relayed_recovers_to_direct_on_handshake` (unaffected, still pass).
- `cargo test -p wiremesh-gateway --test relay_matrix --features netns-tests
  -- --test-threads=1 --nocapture`, run 3x to confirm the fix isn't itself
  flaky, plus a `nat_matrix.rs` regression run — see the Task 9 debug report
  for the actual runs.
