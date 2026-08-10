# WireMesh Kubernetes Operator

Deploy and run a WireMesh zero-trust fabric declaratively on Kubernetes. You
`kubectl apply` a few custom resources; the operator brings up the controller,
deploys gateways/relays, and keeps the segment/policy config reconciled.

> **Status:** the operator has been **validated end-to-end on a real cluster**
> (k3s/arm64: operator deploys the controller, a gateway enrolls through the
> in-cluster Service and its data plane comes up Running). Controller,
> gateway, **and relay** identities are all persisted on per-instance PVCs, so
> pod restarts/reschedules no longer wedge on a spent enrollment token.
> By design, the **controller + fabric (segments/policy)** path needs no extra
> setup; **gateways/relays** additionally require the CA bundle published (see
> [CA bundle](#ca-bundle)).

## Architecture

The operator is a thin front-end over the unchanged `wiremesh-controller`,
which stays the source of truth. It (a) owns Kubernetes workloads and (b)
reconciles config CRDs into the controller's Admin API.

Because the controller's Admin TCP listener binds **loopback-only** by design
(plaintext bearer), the operator does **not** dial it over the network.
Instead the controller pod runs an **admin-exec sidecar** (the operator image,
idle) that shares the controller's Unix socket; the operator `kube exec`s
`operator-admin` into it and reaches the controller over the pod-local
**implicit-admin UDS** — no admin token anywhere.

```
WiremeshController CR ─▶ operator ─▶ controller Deployment + PVC + Service
WiremeshSegment/Policy ─▶ operator ─(exec over UDS)▶ controller Apply(fabric)
WiremeshGateway CR    ─▶ operator ─▶ mint token → Secret → privileged hostNetwork gateway pod
WiremeshRelay CR      ─▶ operator ─▶ mint token → Secret → relay pod
```

## Prerequisites

- Kubernetes ≥ 1.28 (the admin-exec sidecar uses standard `pods/exec`).
- A default StorageClass (for the controller/gateway/relay identity PVCs) — or
  set `spec.storageClass` on the respective CRs.
- The `wiremesh-*` images reachable from the cluster. The defaults point at
  `ghcr.io/zozo6015/*`; mirror them to any registry and override the image
  registry/owner (Helm `image.registry`/`image.owner`, or a kustomize `images:`
  block) if you don't pull from GHCR.
- For **gateways**: nodes where a privileged, `hostNetwork` pod with
  `/dev/net/tun` can run, and the CA bundle published (below).
- Optional: **cert-manager** (recommended for the CA — see below).

## Install

Two supported paths — pick one. Plain manifests / kustomize is the default.

### A. Manifests + kustomize

```sh
# Installs CRDs + namespace + RBAC + the operator Deployment.
kubectl apply -k deploy/operator/
```

Or, without kustomize, apply in order:

```sh
kubectl apply -f deploy/operator/crds/wiremesh-crds.yaml
kubectl apply -f deploy/operator/namespace.yaml
kubectl apply -f deploy/operator/rbac.yaml
kubectl apply -f deploy/operator/deployment.yaml
```

Pin images by editing the `images:` block in `deploy/operator/kustomization.yaml`.

### B. Helm

```sh
helm install wiremesh deploy/helm/wiremesh-operator/ \
  --namespace wiremesh --create-namespace \
  --set image.tag=v0.1.0
```

The chart ships the CRDs in its `crds/` directory. **Helm installs CRDs on
first install but never upgrades or deletes them** — on a chart upgrade,
re-apply the CRDs yourself (`kubectl apply -f deploy/operator/crds/…`) if the
schema changed.

## Bring up a fabric

```sh
kubectl apply -f deploy/operator/examples/01-controller.yaml   # control plane
kubectl wait --for=jsonpath='{.status.ready}'=true wiremeshcontroller/wiremesh-controller --timeout=180s

kubectl apply -f deploy/operator/examples/02-fabric.yaml        # segments + policy
# Watch each segment reach status.applied=true:
kubectl get wiremeshsegments \
  -o custom-columns=NAME:.metadata.name,APPLIED:.status.applied,MSG:.status.message

# Gateways need the CA bundle published first (see below).
kubectl apply -f deploy/operator/examples/03-gateway.yaml
kubectl get wiremeshgateways \
  -o custom-columns=NAME:.metadata.name,ENROLLED:.status.enrolled,ID:.status.gatewayId,PATH:.status.pathState
```

## CRD reference (configuration options)

All five CRDs are **cluster-scoped**, group `wiremesh.io/v1alpha1`. The
controller is single-tenant — one `WiremeshController` per cluster.

### WiremeshController (`wmctrl`)

| field | default | purpose |
|-------|---------|---------|
| `image` | `ghcr.io/zozo6015/wiremesh-controller:latest` | controller image |
| `storageSize` | `1Gi` | data PVC size (DB + CA + secrets) |
| `storageClass` | cluster default | data PVC storage class |
| `syncTcpPort` | `9500` | Sync (mTLS) listener |
| `observeUdpPort` | `9600` | endpoint observation listener |
| `adminTcpPort` | `9443` | loopback-only admin (NOT exposed on the Service) |

Status: `ready`, `adminEndpoint` (the sync-tcp Service DNS), `conditions`
(`Ready` and `ScaledDown` — both always emitted, `True` or `False`, so a
consumer never has to read absence as false; see [Scaling to zero](#scaling-to-zero)).

### WiremeshSegment (`wmseg`)

| field | purpose |
|-------|---------|
| `segmentName` | fabric segment name |
| `cidrs` | list of IPv4 CIDRs in the segment |

### WiremeshPolicy (`wmpol`)

| field | purpose |
|-------|---------|
| `from` / `to` | source / destination segment names |
| `rules[].allow.proto` | `tcp` \| `udp` \| `icmp` |
| `rules[].allow.ports` | ports (omit for icmp / all) |

Default-deny: only what a policy allows passes.

### WiremeshGateway (`wmgw`)

| field | default | purpose |
|-------|---------|---------|
| `segmentRef` | — | the `WiremeshSegment` (by `.metadata.name`) this gateway fronts |
| `nodeName` / `nodeSelector` | — | pin the hostNetwork pod to a node |
| `wgPort` | `51820` | WireGuard listen port |
| `tun` | `wg0` | tun interface name |
| `image` | `…/wiremesh-gateway:latest` | gateway image |
| `storageSize` | `128Mi` | identity PVC (`<name>-gateway-data`) size |
| `storageClass` | cluster default | identity PVC storage class |
| `observeEndpoint` | controller Service ClusterIP | override for the gateway's `--observe` target (`host:port`, DNS ok). Use when kube-proxy SNATs the ClusterIP UDP path (poisoning the observed public mapping) — point at a source-preserving UDP LB instead |
| `syncEndpoint` | controller Service ClusterIP | override for `--controller-sync` (`host:port`, DNS ok) — controllers reached through an external LB / DDNS name |
| `metricsBind` | `0.0.0.0:9090` | override for the gateway's `--metrics` Prometheus bind address (`ip:port`, IPv4 **or** IPv6 literal, no DNS names). Use to bind loopback-only (`127.0.0.1:9090`), move the port, or go dual-stack (`[::]:9090`) |

All three fields are validated when the CR is reconciled and **fail closed** — a
malformed value is reported on the CR instead of rolling out a CrashLooping pod.
The rules differ by field, and they are **not** the same rule:

| | `observeEndpoint` / `syncEndpoint` | `metricsBind` |
|---|---|---|
| what it is | a **dial** target the gateway connects *out* to | a **local socket** the gateway binds |
| validator | `workloads::validate_dial_target` | `workloads::validate_bind_target` |
| DNS names | **allowed** (re-resolved at connect time) | **rejected** |
| IPv6 literals | **rejected** | **accepted** |
| port `0` | **rejected** | **accepted** (OS-assigned) |

The divergence is deliberate, and it follows from what the binary itself does
with each value. The two dial targets go through the gateway's
`validate_host_port`, which is IPv4-only end to end in v1 and for which an
unreachable target (port `0`) is never useful, while a hostname is exactly what
a DDNS controller needs. `--metrics` is parsed by the binary as a literal
`std::net::SocketAddr` and nothing more: a hostname there would be accepted by
the CRD only to CrashLoopBackOff at boot, and IPv6 / port `0` are both
legitimate bind addresses the binary already takes. `validate_bind_target` is
therefore exactly "parses as `SocketAddr`" — neither stricter nor looser than
the binary it guards. **Do not "restore consistency" by tightening `metricsBind`
to match the dial rule** (owner decision, 2026-08-10): stricter strands a
legitimate `[::]:9090`, looser ships a CrashLoopBackOff.

The enroll init-container always uses the in-cluster enroll endpoint — none of
the `observeEndpoint` / `syncEndpoint` / `metricsBind` overrides ever affect
enrollment.

Editing the referenced segment's **CIDRs** after enrollment automatically mints
a **rebind token** (a `kind: rebind` token whose authorization scope is the
segment id — the one token type allowed to replace a segment's already-active
gateway) and refreshes the token Secret; the Secret also records the CIDR set
it was minted against, compared as a set on later passes. Without this, a later
re-enroll would be rejected both on the stale CIDR binding and on the
one-gateway-per-segment invariant. The CIDR change also rolls the pod
(`Recreate`), since the CIDRs are part of the enroll init-container's args.
**Latency:** the gateway reconciler does not watch `WiremeshSegment`, so a CIDR
edit is picked up on the CR's next requeue — **up to 300s** for an enrolled
gateway. Force it sooner by touching the `WiremeshGateway` CR (adding a
`.watches` mapping from Segment → dependent Gateways is the tracked follow-up).

Status: `enrolled`, `gatewayId`, `pathState`, `conditions` (`Enrolled` and
`ScaledDown` — both always emitted, `True` or `False`; see
[Scaling to zero](#scaling-to-zero)) — reported from the
segment's **active** roster row (stale drained/replaced rows are ignored).
Because that row is active-filtered, `pathState` is effectively degenerate
today: it mirrors the roster status, which is `active` whenever a row is found
and absent otherwise — it does **not** surface the data-plane
`Direct`/`Relayed`/`Degraded` path state.

### WiremeshRelay (`wmrelay`)

| field | default | purpose |
|-------|---------|---------|
| `endpoint` | — | the relay's public IPv4 `ip:port` (advertised to gateways) |
| `nodeName` | — | pin the relay pod |
| `image` | `…/wiremesh-relay:latest` | relay image |
| `storageSize` | `128Mi` | identity PVC (`<name>-relay-data`) size |
| `storageClass` | cluster default | identity PVC storage class |

## Scaling to zero

The operator no longer force-applies `replicas: 1`, so **`kubectl scale
--replicas=0` now sticks** on all three workloads — the controller, a gateway
and a relay Deployment:

```bash
kubectl scale deployment/wiremesh-controller --replicas=0 -n wiremesh
kubectl scale deployment/gw-home-gateway    --replicas=0 -n wiremesh
```

This is the **supported way to take a workload down for maintenance**. Scale
back up and the operator picks it back up through its Deployment watch — no CR
edit, no re-enrollment. (Only an explicit `replicas: 0` counts: an *omitted*
`spec.replicas` is defaulted to 1 by the apiserver and means "up", which is the
steady state now that the operator leaves the field alone.)

**How each kind reports it.** `WiremeshController` and `WiremeshGateway` gain a
typed **`ScaledDown` condition** (`status: True`, reason `ReplicasZero`; when up
it is `status: False`, reason `ReplicasNonZero`):

```bash
kubectl get wiremeshgateways -o custom-columns=\
NAME:.metadata.name,\
SCALEDDOWN:'.status.conditions[?(@.type=="ScaledDown")].status'
```

`WiremeshRelay` signals it **only through `status.message`** — the string
`"relay scaled down (0 replicas)"`, alongside `applied: false`. Its status type
(`WiremeshResourceStatus`) has no `conditions` field, and that type is shared
verbatim with `WiremeshSegment` and `WiremeshPolicy`. A human reading `kubectl
describe` sees it fine, but it is **not machine-selectable** — nothing can match
on it without string-comparing the message.

**Operational trap — read this before you scale anything down.** A deliberately
scaled-down workload is *not* Ready, and it never will be until someone scales
it back up. `WiremeshController.status.ready` goes `false` (reason `ScaledDown`,
not `WaitingForController`) and `WiremeshRelay.status.applied` goes `false`. So:

- **`kubectl wait --for=condition=Ready` will block until timeout**, and any
  "not ready for N minutes" alert **will fire and never clear**.
- Exclude `ScaledDown=True` from readiness alerting on the controller and
  gateways. The reason/message strings distinguish "deliberately off" from
  "trying and failing" precisely so a rule can tell them apart — that
  distinction only helps if the rule actually consults it.
- The relay has no condition to exclude on. Suppress it by name during planned
  maintenance, or match the `status.message` string.

**Gateways specifically:** `Enrolled` stays **`True`** while scaled down, and
that is deliberate. The roster row is real and the certificates are valid;
there is simply no pod. Both conditions are true at once — enrolled, and not
running — and reading them together is the point. Do not treat `Enrolled: True`
alone as proof of a live data plane; the `ScaledDown` message spells this out
("the enrollment is still valid, but no gateway pod is running and this segment
carries no traffic").

## CA bundle

Gateways and relays must trust the controller's CA to enroll. The operator
mounts a Secret named **`wiremesh-controller-ca`** (key `tls.crt`) into their
enroll init-container as `--ca`.

**Recommended — cert-manager.** Have cert-manager issue the WireMesh CA, and
use the *same* Secret for the controller (as its signing CA) and for the
gateway/relay trust anchor:

```yaml
apiVersion: cert-manager.io/v1
kind: Issuer
metadata: { name: wiremesh-selfsigned, namespace: wiremesh }
spec: { selfSigned: {} }
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: { name: wiremesh-controller-ca, namespace: wiremesh }
spec:
  isCA: true
  commonName: wiremesh-ca
  secretName: wiremesh-controller-ca        # -> Secret used by controller + gw/relay
  duration: 87600h                          # 10y (a stable mesh root)
  privateKey: { algorithm: ECDSA, size: 256 }
  issuerRef: { name: wiremesh-selfsigned, kind: Issuer }
```

This produces the `wiremesh-controller-ca` Secret (`tls.crt`/`tls.key`). See
`docs/research/operator-remote-deployment-notes.md` for how the controller
consumes it (mounting `tls.crt`/`tls.key` as `ca.pem`/`ca.key` into its data
dir; `wiremesh-trust` uses a provided CA instead of self-generating).

**Without cert-manager**, the CA Secret is optional: the controller
self-generates its CA on first boot (the `ca-seed` init-container no-ops when the
Secret is absent, and does **not** overwrite an existing CA on later restarts).
For gateways/relays to trust that self-generated CA, publish its cert
(`/var/lib/wiremesh/ca.pem`) into the `wiremesh-controller-ca` Secret under key
**`tls.crt`** — the same key gateways/relays project to their `ca.pem` trust
anchor.

## Client routing (out of band)

WireMesh has no agents on workloads. Devices on a segment reach the mesh by
routing the *other* segments' CIDRs to their gateway's node/LAN IP — a static
route, DHCP option 121, or making the gateway node the default router. **The
operator cannot set routes on your workloads**; this is a per-network step.

For remote/behind-NAT and dynamic-IP (DDNS) controller reachability, see
`docs/research/operator-remote-deployment-notes.md`.

## External connectivity via the Gateway API

Gateways and relays **inside this cluster** reach the controller by its ClusterIP
— the operator wires that automatically, and you need nothing here. Gateways or
relays running on **other networks** connect *inbound* to the controller, so it
must be exposed through an ingress. WireMesh ships Kubernetes **Gateway API**
routes for that, so you can front the controller with any Gateway API
implementation (Envoy Gateway, etc.).

The controller listens on these ports (the operator sets `WIREMESH_BIND_IP=0.0.0.0`
so the Service routes to them). **Configure one Gateway listener per row:**

| Purpose | Backend Service port | Listener protocol | TLS handling | Route kind |
|---------|----------------------|-------------------|--------------|------------|
| Enrollment RPC | `9400` | `TCP` | **passthrough** — do NOT terminate | `TCPRoute` |
| Sync (mTLS) | `9500` | `TCP` | **passthrough** — do NOT terminate | `TCPRoute` |
| Endpoint observation | `9600` | `UDP` | n/a | `UDPRoute` |

> The admin port (`9443`) is **never** exposed — it is forced loopback-only and
> is not in this table by design.

There is **no HTTPRoute**: enroll/sync are gRPC-over-TLS that must be passed
through (the Sync mTLS *client* cert has to reach the controller), so they are L4
TCP, not terminatable HTTP. The *external* listener port can be anything you
like; only the *backend* port must match the table.

**1. Add listeners to your Gateway** (`gateway.networking.k8s.io/v1`), one per
port above — `protocol: TCP` for enroll/sync, `protocol: UDP` for observe. Name
them so the routes can target them by `sectionName` (defaults: `wiremesh-enroll`,
`wiremesh-sync`, `wiremesh-observe`).

**2. Create the routes** — either enable them in Helm:

```sh
helm upgrade wiremesh-operator deploy/helm/wiremesh-operator \
  --set gatewayApi.enabled=true \
  --set gatewayApi.gateway.name=<your-gateway> \
  --set gatewayApi.gateway.namespace=<your-gateway-ns>
```

or apply the standalone manifests (edit the `parentRefs` first). They carry no
`metadata.namespace`, so apply them **into the controller's namespace** (default
`wiremesh`) — the `backendRef` resolves the Service in the route's own namespace:
`kubectl -n <controller-namespace> apply -f deploy/operator/gateway-api/routes.yaml`.
Full walkthrough + a sample `Gateway`:
[`deploy/operator/gateway-api/README.md`](../deploy/operator/gateway-api/README.md).

**Gateway API version.** The shipped routes are `gateway.networking.k8s.io/v1`
`TCPRoute`/`UDPRoute`, which require the **Gateway API v1.6+ CRDs** (where these
kinds graduated to `v1`) and a controller that serves them (Envoy Gateway
**v1.6+**). On older clusters (Gateway API < v1.6, which serve these kinds only
under `v1alpha2`), change the three route files' `apiVersion` to
`gateway.networking.k8s.io/v1alpha2` before applying — the `kind`/`spec` are
otherwise identical. Confirm what your cluster serves with
`kubectl get crd tcproutes.gateway.networking.k8s.io -o jsonpath='{.spec.versions[*].name}'`.

**Caveats (both critical):**

- **TLS passthrough, never termination.** A Gateway that terminates TLS breaks
  enrollment (wrong CA) and Sync (the mTLS client cert dies at the proxy). Plain
  `TCPRoute` on a `protocol: TCP` listener passes the bytes through untouched.
- **observe-UDP source preservation.** The controller learns each remote
  gateway's public `ip:port` from the *source* of its observe packet and uses it
  for hole-punching. A UDP proxy that SNATs (Envoy `UDPRoute` does, by default)
  masks that source → NAT traversal silently degrades to **relay-always**. If your
  UDP path can't preserve the client source, expose observe-udp another way (a
  source-preserving `LoadBalancer`/`NodePort` with `externalTrafficPolicy: Local`,
  or a `hostPort`) or accept relay-always for off-cluster pairs. Details:
  `docs/research/operator-remote-deployment-notes.md` (Finding 2).

## Limitations

- **Restart durability: fixed.** Controller, gateway, and relay identities are
  all persisted on per-instance PVCs (`<name>-data`, `<name>-gateway-data`,
  `<name>-relay-data`); both enroll init-containers are idempotent (they skip
  when a complete identity is already on the volume, so a restart never
  re-redeems the spent single-use token); and the token mint is keyed off
  whether the identity is durably persisted. (Gateway PVC identity was
  validated on a live cluster; the relay PVC + idempotent relay enroll ship
  with this round.) All three Deployments use the `Recreate` strategy — an RWO
  PVC must never surge a second pod.
- **Segment-CIDR edits are not watched:** the gateway reconciler watches its own
  CR (and its Deployment/PVC), not `WiremeshSegment`, so an automatic rebind can
  lag a CIDR edit by up to the 300s requeue. Follow-up: a `.watches` mapping
  from Segment → the Gateways referencing it.
- **`status.pathState` is degenerate:** it reports the controller roster status
  of the segment's active row (so, in practice, `active`), not the data-plane
  `Direct`/`Relayed`/`Degraded` path state.
- **Teardown order:** delete dependent CRs (`WiremeshGateway`,
  `WiremeshSegment`, …) **before** the `WiremeshController` CR so their
  finalizers can drain/deregister through the controller. If the controller is
  already gone (e.g. `kubectl delete -f all.yaml` in one shot), the finalizers
  do **not** wedge in `Terminating`: they log a warning naming the skipped
  cleanup (gateway drain / segment delete) and complete — any surviving
  controller elsewhere then needs a manual `fabricctl` cleanup.
- One-gateway-per-segment is a design invariant; running two `WiremeshGateway`
  CRs against one segment disables the automatic stale-id adoption drain (the
  operator will never risk draining a live peer).
- The `Relayed → Direct` make-before-break cutover and relay multiplexing are
  data-plane fast-follows (see the project CLAUDE.md).

## Troubleshooting

- `kubectl -n wiremesh logs deploy/wiremesh-operator` — reconcile logs.
- `WiremeshController` stuck not-ready → check the controller pod + its PVC bound.
- `WiremeshSegment` not `applied` → the operator can't reach the controller
  Admin: confirm the `admin-exec` sidecar is Running in the controller pod and
  the operator has `pods/exec` RBAC.
- Gateway enroll init-container failing → the `wiremesh-controller-ca` Secret is
  missing or wrong (see [CA bundle](#ca-bundle)).
