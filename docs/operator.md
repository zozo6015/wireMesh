# WireMesh Kubernetes Operator

Deploy and run a WireMesh zero-trust fabric declaratively on Kubernetes. You
`kubectl apply` a few custom resources; the operator brings up the controller,
deploys gateways/relays, and keeps the segment/policy config reconciled.

> **Status:** the operator's reconcilers, the admin transport, and the install
> artifacts are complete and **unit-tested**; the reconcile loops, the exec
> transport, and these manifests **compile and pass unit tests but have not yet
> been validated end-to-end on a live cluster** — that is the current next step.
> By design, the **controller + fabric (segments/policy)** path needs no extra
> setup; **gateways/relays** additionally require the CA bundle published (see
> [CA bundle](#ca-bundle)) and, for restart durability, PVC-backed state (see
> [Limitations](#limitations)).

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
- A default StorageClass (for the controller PVC) — or set `spec.storageClass`.
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

Status: `ready`, `adminEndpoint` (the sync-tcp Service DNS), `conditions`.

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

Status: `enrolled`, `gatewayId`, `pathState`, `conditions`.

### WiremeshRelay (`wmrelay`)
| field | purpose |
|-------|---------|
| `endpoint` | the relay's public IPv4 `ip:port` (advertised to gateways) |
| `nodeName` | pin the relay pod |
| `image` | relay image |

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

**Without cert-manager**, the controller self-generates its CA on first boot;
publish it to the `wiremesh-controller-ca` Secret (extract `/var/lib/wiremesh/ca.pem`).

## Client routing (out of band)

WireMesh has no agents on workloads. Devices on a segment reach the mesh by
routing the *other* segments' CIDRs to their gateway's node/LAN IP — a static
route, DHCP option 121, or making the gateway node the default router. **The
operator cannot set routes on your workloads**; this is a per-network step.

For remote/behind-NAT and dynamic-IP (DDNS) controller reachability, see
`docs/research/operator-remote-deployment-notes.md`.

## Limitations

- **Gateway restart durability:** gateway identity currently lives in an
  `emptyDir`, so a gateway pod restart loses its identity and its single-use
  enrollment token is already spent. Treat gateway pods as non-restartable for
  now; PVC-backed gateway state is the tracked fix.
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
