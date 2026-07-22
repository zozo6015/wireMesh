# Finding: the operator can't reach the controller Admin API as designed (loopback-only Admin TCP)

**Date:** 2026-07-22 (K8s operator, building Task 4 workload builders).
**Status:** OPEN — architecture decision needed before the reconcilers (Tasks 5-8). Does NOT block the pure workload builders.

## The gap

The operator design is a "thin front-end over the controller Admin API": the
operator mints an admin bearer token at bootstrap and then drives
`Apply` / `MintToken` / `RegisterRelay` / `Drain` over the Admin **TCP**
listener. But the controller **deliberately binds the Admin TCP listener
loopback-only, regardless of `bind_ip`** (`crates/wiremesh-controller/src/lib.rs:120`):

> *"the Admin TCP listener (`admin_tcp_port`) is plaintext gRPC with a bearer
> token as its only security boundary, so it always binds loopback-only
> regardless of this field ... exposing it on a routable interface would make
> the bearer token interceptable/replayable on the wire."*

The UDS (`/run/wiremesh/controller.sock`, implicit-admin) is **pod-local**.

So a **separate-pod operator has no channel to the Admin API**: TCP is
loopback-only, UDS is not reachable across pods. Exposing Admin TCP on the
ClusterIP Service (as the plan's `controller_service_exposes_admin_tcp` test
assumes) would ship exactly the plaintext-bearer-on-the-wire vulnerability the
controller explicitly guards against.

## Options (no controller change unless noted)

1. **Co-locate an admin-exec sidecar in the controller pod** that shares the
   UDS emptyDir, and have the operator drive admin ops by running `fabricctl`
   in that sidecar (kube `exec` subresource) — or the operator itself execs
   `fabricctl` into the controller container per op. Works today; clunky
   (exec per operation, needs `pods/exec` RBAC).
2. **Add a routable mTLS Admin listener to the controller** (client-cert
   auth, not plaintext bearer) that the operator dials with an issued cert.
   Cleanest operator UX; **is a controller change** (violates the "no
   controller change" scope the operator design set).
3. **Run the operator's admin calls from inside the controller pod** — i.e.
   fold the reconciler's admin-driving half into a controller-pod sidecar,
   and keep only the CRD watch/status in the standalone operator. Splits the
   operator; awkward but no controller change and no exec.

## Impact on Task 4 (workload builders)

The builders themselves are unaffected — they define the controller / gateway
/ relay Deployments, PVC, and Service, none of which depend on how the
operator later talks to the controller. **Deviation taken now:** the
`controller_service` builder exposes `enroll-tcp` (the Enrollment RPC),
`sync-tcp`, and `observe-udp` — the ports gateways/relays legitimately dial —
but **NOT** `admin-tcp`, honoring the controller's loopback-only posture. This
diverges from the operator plan's `controller_service_exposes_admin_tcp` test;
the plan predates this finding. The admin channel is resolved in the reconciler
phase per one of the options above (owner decision).

## Recommendation

Option 1 (admin-exec sidecar sharing the UDS) is the least-invasive path that
needs no controller change and no plaintext bearer on the wire. Confirm with
the owner before building the WiremeshController reconciler (Task 5), since it
determines the controller pod shape and the operator's RBAC (`pods/exec`).
