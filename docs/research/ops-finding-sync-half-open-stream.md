# Ops finding: gateway Sync stream goes silently half-open (no keepalive) — gateway runs fail-static believing it's connected

**Date:** 2026-07-27 (zolab live deployment, while onboarding the first
off-cluster gateway).
**Status:** gateway-side fix LANDED 2026-07-27 (keepalive on the Sync
channel, with hostname support + per-reconnect DNS re-resolution); the relay
Sync client and controller-side keepalive mirrors LANDED 2026-07-30
(Backlog 2 — see below).

## Symptom

`gw-home` (in-cluster, hostNetwork, enrolled 2026-07-23, gateway_id=3) sat at
`applied_version=1` in the controller roster while the controller advanced the
compiled policy through at least two newer versions (segment CIDR replace +
two new policy blocks via `Apply`). The gateway's own metrics agreed
(`wiremesh_gateway_applied_policy_version 1`). Its logs showed **only** the
observe loop (`observed endpoint …` every tick) — none of the reconnect paths
ever fired (`sync stream closed; reconnecting`, `sync error: …`,
`controller unreachable: …`), i.e. the gateway believed its Sync stream was
healthy for ~3+ days.

## Evidence the stream was gone

`ss -tn` inside the controller pod's netns (ephemeral debug container): **zero
established TCP connections on 9500** (sync) — while the gateway process was
alive, logging observe ticks, and never reconnecting. Classic half-open: the
TCP path (gateway hostNetwork → ClusterIP → kube-proxy conntrack → pod) died
at some point after enrollment; the FIN/RST never reached the gateway, whose
`Streaming<SyncMessage>` read blocks forever.

## Root cause (code)

`crates/wiremesh-gateway/src/sync.rs::connect` builds the tonic channel with
TLS only — **no `http2_keep_alive_interval`, no `keep_alive_timeout`, no
`tcp_keepalive`**. A long-lived `Sync.Watch` stream that receives no pushes is
completely silent on the wire, so a dropped NAT/conntrack entry (or any
middlebox timeout — exactly the path an off-cluster gateway on the internet
will traverse) is undetectable. The observe UDP loop keeps logging (separate
socket), which masks the failure.

Consequences while half-open:
- policy updates never arrive (stale enforcement — the fabric admin sees
  `Apply` succeed but a gateway silently never converges);
- `PunchDirective`/`RotateDirective` never arrive (NAT traversal + key
  rotation dead for that gateway);
- the controller ack/roster shows the stale `applied_version`, which is the
  one visible breadcrumb.

This is far worse for the remote/off-cluster gateway case (Cycle-4 target
topology): home-router NAT table entries for idle TCP are commonly minutes,
not days.

## Remediation used (ops)

In-place gateway **container** restart (`kill 1` in the gateway container —
NOT a pod delete, which would destroy the emptyDir identity per the known
operator limitation). On boot the gateway comes up fail-static from
`state.json`, redials Sync, and converges to the latest policy version.

## Suggested fix (fast-follow)

**Gateway side: LANDED 2026-07-27** in `sync.rs::connect` —
`SYNC_KEEPALIVE_INTERVAL = 15s` (`http2_keep_alive_interval`, with
`keep_alive_while_idle(true)` since the Watch stream is exactly the idle
case), `SYNC_KEEPALIVE_TIMEOUT = 10s` (`keep_alive_timeout`), plus
`SYNC_CONNECT_TIMEOUT = 10s` on the dial itself. A dead link now surfaces as
a stream error within ~25s worst case, and the reconnect it triggers
re-resolves DNS (hostname support landed in the same change — see
`operator-remote-deployment-notes.md` Finding 3), so a rotated DDNS address
heals too.

**Both mirrors: LANDED 2026-07-30 (Backlog 2):**

- **Controller side**: `http2_keepalive_interval/timeout` on the Sync
  listener's server builder
  (`wiremesh-controller/src/lib.rs::serve()` —
  `SYNC_HTTP2_KEEPALIVE_INTERVAL/TIMEOUT`, the same 15s/10s), so the
  controller also detects a dead client and reaps its Watch stream instead
  of holding the half-open roster entry until a Report that never comes.
  Sync listener only — the Admin (UDS + loopback TCP) and Enrollment
  surfaces carry short unary RPCs with nothing to go silently half-open.
- **Relay Sync client** (`wiremesh-relay/src/lib.rs::run_sync`): had the
  identical bug — TLS-only channel, no keepalive, no `connect_timeout`, and
  a fixed `SocketAddr` target. Its Watch stream carries only
  `revoked_serials`, so the failure mode was a **security** one: a half-open
  relay silently enforces a stale revocation denylist — a certificate revoked
  after the stream went dead keeps being accepted by that relay until it
  restarts (the offline-persisted denylist only covers what arrived before
  the stream died). Now mirrors the gateway exactly: the same 15s/10s/10s
  figures (`wiremesh_relay::SYNC_KEEPALIVE_INTERVAL/SYNC_KEEPALIVE_TIMEOUT/
  SYNC_CONNECT_TIMEOUT`, `keep_alive_while_idle`), a `host:port` target
  resolved inside every `run_sync` call (per-dial DNS re-resolution), and
  the gateway's boot-time `validate_host_port` on the bin's `--controller`
  flag, so an IPv6 or typo'd IPv4-shaped literal exits non-zero at boot —
  same posture as `--controller-sync`. The shared pieces — the bounded
  resolver, the boot-time validation, and the CANONICAL keepalive constants
  from which all three crates now derive their figures (so the client and
  server sides can't drift apart) — were extracted to `wiremesh-enroll` and
  are re-exported under the original gateway/relay paths. Pinned by
  `wiremesh-relay/tests/{sync_hostname,sync_keepalive}.rs` and
  `wiremesh-controller/tests/sync_server_keepalive.rs`.

**Still open (follow-up):**

- Consider also alerting on roster `applied_version` lag (controller side),
  which is what actually exposed this.
- **Sync session generation**: per-boot nonce in Watch+Report so a delayed
  pre-restart Report can't restore stale
  `peer_paths`/`local_endpoints`/`relay_health` after reconnect (see
  `Broker::on_report`'s known-race note).
