# External connectivity via the Kubernetes Gateway API

Gateways and relays on **other networks** reach the WireMesh control plane by
connecting *inbound* to the controller. In-cluster gateway pods use the
controller's ClusterIP directly; **off-cluster** ones need the controller
exposed through an ingress. This directory provides the Gateway API routes for
that, so you can front the controller with any Gateway API implementation
(you run **Envoy Gateway**).

> This is only for **remote/off-cluster** gateways and relays. If every gateway
> pod is in-cluster, you don't need any of this — the operator already wires them
> to the controller ClusterIP.

## The external ports

The controller listens on these (the operator sets `WIREMESH_BIND_IP=0.0.0.0` so
the Service can route to them). Configure **one Gateway listener per row**:

| Purpose | Backend Service port | Listener protocol | TLS handling | Route kind |
|---------|----------------------|-------------------|--------------|------------|
| Enrollment RPC | `9400` | `TCP` | **passthrough** (do NOT terminate) | `TCPRoute` |
| Sync (mTLS) | `9500` | `TCP` | **passthrough** (do NOT terminate) | `TCPRoute` |
| Endpoint observation | `9600` | `UDP` | n/a | `UDPRoute` |

The *external* (listener) port can be anything you like; the *backend* port must
be the one above. There is **no HTTPRoute** — enroll/sync are gRPC-over-TLS that
must be passed through (the sync mTLS client cert must reach the controller), so
they are L4 TCP, not terminatable HTTP.

## 1. Add listeners to your Gateway

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: wiremesh          # <- referenced by routes.yaml parentRefs.name
  namespace: envoy-gateway-system
spec:
  gatewayClassName: eg    # your Envoy Gateway GatewayClass
  listeners:
    - name: wiremesh-enroll      # <- routes.yaml sectionName
      protocol: TCP
      port: 9400               # external port (your choice)
      allowedRoutes: { namespaces: { from: All } }
    - name: wiremesh-sync
      protocol: TCP
      port: 9500
      allowedRoutes: { namespaces: { from: All } }
    - name: wiremesh-observe
      protocol: UDP
      port: 9600
      allowedRoutes: { namespaces: { from: All } }
```

Envoy Gateway needs its `TCPRoute`/`UDPRoute` support enabled (they're
Gateway API v1alpha2). The Gateway's address (LoadBalancer IP / node) + these
ports are what a remote gateway points its `--controller-sync` / enroll at.

## 2. Apply the routes

Edit `routes.yaml` — set `parentRefs` (your Gateway name/namespace + the
`sectionName` listener names above), and the `backendRefs.name` if your
`WiremeshController` CR isn't named `wiremesh-controller` — then:

```sh
kubectl apply -f deploy/operator/gateway-api/routes.yaml
```

(Or enable them via the Helm chart: `--set gatewayApi.enabled=true` +
`gatewayApi.gateway.name/namespace`.)

## Caveats

- **TLS passthrough, never termination.** The Gateway must forward the TCP bytes
  untouched — terminating TLS breaks enrollment (wrong CA) and Sync (the mTLS
  client cert dies at the proxy). Plain `TCPRoute` (no TLS config on the
  listener) does this.
- **observe-UDP source preservation.** The controller learns each remote
  gateway's public `ip:port` from the *source* of the observe packet, and uses it
  for hole-punching. A UDP proxy that SNATs (most, by default) masks that source
  → NAT traversal silently degrades to relay-always. If your Gateway's UDP path
  doesn't preserve the client source, expose observe-udp another way (a
  source-preserving `LoadBalancer`/`NodePort` with `externalTrafficPolicy:
  Local`) or accept relay-always for off-cluster pairs. See
  `docs/research/operator-remote-deployment-notes.md`.
- The controller's TLS is **hostname-agnostic** (constant SNI, pinned private
  CA), so a dynamic public IP behind DDNS is fine — no cert changes on IP change.
