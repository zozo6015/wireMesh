# Remote / behind-NAT deployment findings (controller reachability, observe-UDP, gateway hostname)

**Date:** 2026-07-22 (K8s operator design discussion).
**Status:** OPEN — three deployment findings to fold into the reconciler phase.
Surfaced working through a concrete topology: a home Raspberry-Pi cluster
behind an ISP DDNS name (dynamic public IP, port-forwarded / fronted by Envoy
Gateway), with gateways on remote networks.

## Background: the reachability model

The control plane is **gateway → controller, outbound only**. Gateways never
need inbound reachability; the one component that must accept inbound is the
**controller** (or a reachable LB/ingress in front of it). A relay does NOT
help here — it brokers gateway↔gateway *data* traffic, not the control plane.
Enroll and Sync always go directly gateway→controller.

The controller's TLS is **hostname-agnostic by design**: the server leaf's SAN
is a constant `127.0.0.1` (`wiremesh-trust`/controller `lib.rs:445`) and every
client verifies with `domain_name("127.0.0.1")` regardless of the dialed
address (`gateway/src/sync.rs:35`; the controller comment at `lib.rs:115`
spells this out). Trust is anchored in the pinned private CA + mTLS, not public
PKI hostname validation. **Consequence:** a dynamic IP behind DDNS is
transparent to TLS — no cert regeneration, no DDNS name in the cert. Any L4
transport (port-forward, LB, Envoy passthrough) that delivers bytes to the
controller works.

---

## Finding 1 — the controller Service needs a reachability knob (default ClusterIP is wrong for remote gateways)

For remote gateways to reach the controller, its three control-plane ports
must be externally reachable:

| Port | Proto | Purpose |
|------|-------|---------|
| enroll-tcp (`WIREMESH_TCP_PORT`)      | TCP | `Enrollment.Enroll` (server-TLS) |
| sync-tcp (`WIREMESH_SYNC_TCP_PORT`)   | TCP | Sync stream (**mTLS**) |
| observe-udp (`WIREMESH_OBSERVE_UDP_PORT`) | UDP | endpoint observation |

`workloads::controller_service` currently emits a default (ClusterIP) Service
exposing these three — fine in-cluster, but remote gateways can't reach a
ClusterIP. **Action (gateway/controller reconciler):** the `WiremeshController`
CRD should carry a service-exposure choice (`ClusterIP` | `LoadBalancer` |
`NodePort`, plus an optional external hostname/address the operator writes into
gateway configs). Home/DDNS setups use `LoadBalancer` (MetalLB) or `NodePort`
behind a router port-forward.

**Envoy Gateway / ingress:** works **only as L4 passthrough**, never TLS
termination — the Sync mTLS client cert must reach the controller intact
(that's how the controller identifies/authorizes each gateway), and enroll
verifies the controller's own CA-signed cert. Terminating TLS breaks both. Use
per-port `TCPRoute` (passthrough) for enroll-tcp + sync-tcp; this also sidesteps
the odd SNI (clients send the literal `127.0.0.1`), which SNI/`TLSRoute` routing
would otherwise have to match. Envoy earns nothing WireMesh-specific on
passthrough traffic — a plain LB/NodePort is simpler unless Envoy is already the
house ingress.

## Finding 2 — observe-UDP requires client-source preservation (SNAT silently forces relay-always)

The observe channel exists so the controller learns each gateway's **real
public IP:port** by reading the **source address of the UDP probe as it
arrives** (`observe.rs` echoes the sender's `ip:port`). That observed mapping is
the candidate peers hole-punch toward (Phase-0 Bet 4 / Cycle 4b).

If anything in the ingress path **SNATs** the observe packet, the controller
records the proxy's address instead of the gateway's public mapping. Culprits:
a stock k8s Service (`externalTrafficPolicy: Cluster` SNATs to the node IP) and
a UDP proxy (Envoy `UDPRoute` rewrites source unless run in
transparent/original-source mode — not the default). Router DNAT preserves
source.

**Failure mode is silent and misleading:** enrollment and Sync still succeed, so
the mesh *comes up* — but every observed candidate is wrong, so hole-punching
fails and **every pair falls back to the relay.** A working-but-always-relayed
mesh that throws away NAT traversal, with no error to point at.

**Action:** give observe-UDP a **source-preserving path** —
`externalTrafficPolicy: Local` on the Service (preserves client IP), or a
`hostPort`/NodePort straight to the controller; if routing observe through Envoy
`UDPRoute`, verify it preserves the client source (transparent mode) and don't
use it otherwise. **Scope + caveat:** `externalTrafficPolicy` is only valid on
externally-exposed Service types (`LoadBalancer`/`NodePort`) — it does nothing
for a `ClusterIP` (there is no external hop to SNAT), so the reconciler should
set `Local` **only when it selects `LoadBalancer`/`NodePort`** (Finding 1's
exposure knob), not unconditionally. Note `Local` also drops packets on nodes
with no local backend pod and skips cross-node load-balancing — fine for the
single-replica controller here, but that's why it's not a blanket default. The
observe port specifically needs it (or a `hostPort`); enroll/sync-tcp don't
care (no source-derived candidate). **Verification:** after a remote gateway
connects, confirm the controller's observed endpoint for it is the gateway's
real public `ip:port`, not the node/proxy address.

## Finding 3 — the gateway can't take the controller as a hostname for Sync/observe (breaks dynamic-IP DDNS)

**Status (2026-07-27): fast-follow LANDED** — `--controller-sync`/`--observe`
now take `host:port` with a hostname (syntax-only validation at parse, so
fail-static boot never needs DNS), `sync::connect` re-resolves DNS on every
reconnect and the observe loop re-resolves every tick (the DDNS pickup paths),
and the Sync channel gained HTTP/2 keepalive so a dead link actually surfaces
and triggers that re-resolving reconnect (see
`ops-finding-sync-half-open-stream.md`). `domain_name("127.0.0.1")` unchanged.

The analysis below is the original pre-fix finding, kept verbatim for the
record — its present-tense statements ("you must bake a resolved IP…",
"should land…") no longer apply:

The gateway's `--controller-sync` and `--observe` flags parse straight into a
`std::net::SocketAddr` (`gateway/src/config.rs:38-39`;
`sync::connect(sync_addr: SocketAddr, ...)`), which is **numeric IP:port only**
— `"home.ddns.net:9500".parse::<SocketAddr>()` fails. Only the enroll path
(`wiremesh-enroll`, a `&str` handed to tonic) accepts a hostname.

**Consequence for dynamic-IP DDNS:** you must bake a resolved IP into the
control-plane flags, so when the ISP rotates the public IP the gateway's Sync
config is stale and it **cannot reconnect until restarted with the new IP**.
(The data plane survives via fail-static in the meantime, but the control plane
stays down.) There is no DNS re-resolution today because the address is a fixed
`SocketAddr`, not a name.

**Action (fast-follow, small + contained):** accept a **hostname** for
`--controller-sync` / `--observe` (keep them as `String`, resolve at connect
time) and **re-resolve DNS on each reconnect**, so a dynamic IP is picked up
automatically. Localized to `config.rs` (type change) and the connect paths in
`sync.rs`/observe; no protocol change; does not touch the pinned-SNI TLS
(`domain_name` stays `127.0.0.1`). **This should land before the gateway
reconciler** — otherwise the `WiremeshGateway` reconciler can only ever emit IP
literals for the controller endpoint, and DDNS deployments can't be hands-off.

---

## Summary for the reconciler phase

1. `WiremeshController` CRD: service-exposure knob (`ClusterIP`/`LoadBalancer`/
   `NodePort` + external address); document Envoy = L4 passthrough only.
2. Controller Service: default `externalTrafficPolicy: Local` (observe-UDP
   source preservation); document the relay-always failure mode.
3. Gateway (fast-follow, before its reconciler): hostname + re-resolve for
   `--controller-sync`/`--observe`.
