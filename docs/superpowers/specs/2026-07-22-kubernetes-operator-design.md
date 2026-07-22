# WireMesh Kubernetes Operator — design

Status: approved shape (owner decisions 2026-07-22): **full-scope** operator (deploys
the controller *and* manages gateway/relay lifecycle *and* the fabric config), **separate
CRDs**, **Rust + `kube-rs`**. Build is a separate agent-driven cycle (subagent budget for
the design session was spent). Complements the merged container images
(ghcr.io/zozo6015/wiremesh-*) and the release-distribution spec.

## 0. Amendments (2026-07-22, post-implementation — these SUPERSEDE the body where they conflict)

Discovered while implementing Tasks 1–4 (PR #16) and ratified with the owner. Detail
lives in `docs/research/`.

1. **Admin transport is NOT routable TCP.** The controller's Admin TCP listener binds
   **loopback-only by design** (plaintext bearer). The operator therefore drives admin ops
   (`Apply`/`MintToken`/`RegisterRelay`/`Drain`) by `exec`-ing `fabricctl --socket <uds>` in a
   controller-pod **admin-exec sidecar** sharing the UDS — NOT the TCP `FabricAdmin` client
   (which is kept only for local/out-of-cluster + tests). The controller `Service` exposes
   enroll-tcp + sync-tcp + observe-udp, **never admin-tcp.** See
   `operator-admin-channel-gap.md`. (Fixes body §2/§5 "Admin TCP" mentions.)
2. **RBAC:** the operator ServiceAccount needs `pods/exec` (create) + `pods` (get/list) for
   that sidecar transport, on top of the CRD + `deployments/services/pvc/secrets` perms.
3. **Gateway identity must persist across pod replacement.** The gateway loads a
   pre-provisioned `Identity` at boot; an `emptyDir` state volume is lost on restart, forcing a
   re-enroll (and a fresh single-use token). Use a **PVC** for the gateway `--state-dir` (and
   the relay `certdir`), OR have the reconciler re-mint + re-enroll on restart. The Task-4
   builders currently emit `emptyDir` — the gateway reconciler must switch this to a PVC.
4. **Controller reachability + hostname contract (for remote/DDNS gateways).** `WiremeshController`
   needs a Service-exposure knob (`ClusterIP`/`LoadBalancer`/`NodePort` + external address);
   observe-udp needs client-source preservation (`externalTrafficPolicy: Local` on the exposed
   Service only); and the gateway's `--controller-sync`/`--observe` must accept a **hostname +
   re-resolve** (a small gateway fast-follow) **before** the gateway reconciler, or it can only
   emit IP literals. See `operator-remote-deployment-notes.md`.
5. **Enrollment client** (the token→identity bootstrap the body assumes) is **built** —
   `wiremesh-enroll` + `wiremesh-gateway enroll` + `wiremesh-relay-enroll`. See
   `operator-enrollment-client-gap.md`.

## 1. Goal
Make a WireMesh fabric fully declarative on Kubernetes: `kubectl apply` a set of CRDs and
the operator brings up the control plane, deploys the data-plane gateways/relays, and keeps
the fabric config (segments + policy) reconciled — GitOps-friendly, no `fabricctl` scripting.

## 2. Architecture — thin operator over the existing controller
The operator does **not** reimplement the control plane. The `wiremesh-controller` stays the
single source of truth (embedded CA, sqlite, enrollment, Sync projection, policy compile).
The operator is a **declarative front-end** that:
- deploys/owns the controller (+ gateways/relays) as Kubernetes workloads, and
- reconciles fabric-config CRDs into the controller via its **Admin API** — chiefly
  `Apply(fabric_yaml)` (compile DSL→IR, version, apply idempotently in ONE tx; the exact call
  `fabricctl apply -f` already makes), plus `MintToken`/`RegisterRelay`/`DeleteSegment`/
  `Drain`/`RotateKey`.

New crate `wiremesh-operator` (Rust, `kube-rs` + `controller-runtime`-style reconcilers),
reusing `wiremesh-proto`'s generated Admin gRPC client. One image
`ghcr.io/zozo6015/wiremesh-operator`.

## 3. CRDs (cluster-scoped; the controller is single-tenant)
### `WiremeshController` (singleton — the root)
Spec: `image`, `storage` (PVC size/class for DB+CA+secrets), `adminTcpPort`,
`syncTcpPort`, `observeUdpPort`, `bindIP`, `rotationInterval?`, `resources?`. The operator
reconciles: a controller `Deployment` (1 replica), a `PVC` (`/var/lib/wiremesh`), a
`Service` (Sync + Admin TCP + observe UDP), and the **admin-token bootstrap** (§5). Status:
`ready`, `adminEndpoint`, `caFingerprint`, `observedVersion`, conditions.

### `WiremeshSegment`
Spec: `name`, `cidrs: [CIDR]`. Status: `applied`, `appliedVersion`, `gatewayCount`.
Aggregated (with all other Segments + Policies) into the fabric YAML → `Apply`.

### `WiremeshPolicy`
Spec: `from` (segment), `to` (segment), `rules: [{allow:{proto,ports}}]` — the fabric DSL
`policy:` block. Status: `applied`, `appliedVersion`. Aggregated into the fabric YAML.

### `WiremeshGateway`
Spec: `segmentRef` (a WiremeshSegment), `placement` (nodeSelector/nodeName + `hostNetwork:true`
REQUIRED), `wgPort?`, `tun?`, `image?`, `resources?`. Reconcile: `MintToken` bound to the
segment's CIDRs (once) → store token in a `Secret` → deploy the **privileged hostNetwork**
gateway workload (Deployment, 1 replica; §6) mounting the token Secret + a state
volume/PVC. Status: `enrolled`, `gatewayId`, `pathState`, conditions. On delete → `Drain`
the gateway + remove the workload.

### `WiremeshRelay`
Spec: `endpoint` (public reachable ip:port), `placement`, `image?`. Reconcile:
`RegisterRelay(endpoint)` → identity Secret (relay enrolls with `--kind relay`) → deploy the
relay workload. Status: `registered`, `relayId`, `healthy`.

## 4. Reconciliation model
- **Ordering.** `WiremeshController` reconciles first and must reach `ready` (admin token in
  its Secret) before any config/gateway/relay reconcile proceeds; those requeue-with-backoff
  until the controller is ready. CRD `conditions` surface the wait.
- **Fabric aggregate (Segments + Policies).** Because `Apply` is **whole-fabric and
  transactional**, the operator renders the fabric YAML from the FULL set of `WiremeshSegment`
  + `WiremeshPolicy` objects on every relevant change and calls `Apply` once; the returned
  `ApplyDiff`/policy version is written to each object's status. Idempotent (a no-op re-apply
  is a clean zero-diff). A single "fabric" reconciler owns this aggregate to avoid races —
  Segment/Policy events enqueue one fabric-reconcile key.
- **Deletes.** `Apply` today is create/update (Cycle-2 carry "apply -f is create-only").
  So a deleted `WiremeshSegment` → the operator calls `DeleteSegment` explicitly (finalizer
  on the CRD ensures the controller-side delete happens before the CRD is removed); policy is
  whole-replaced by the next `Apply`. (If `Apply` grows full create/update/delete semantics —
  the D-C2-4 follow-up — the operator simplifies to render-and-Apply only.)
- **Gateways/relays** reconcile independently (mint/register + workload), keyed by their CRD.

## 5. Bootstrap — how the operator authenticates to the controller it deploys
The controller Admin API is: **UDS = implicit-admin (no token)**, **TCP = bearer-token**
(tokens minted by `MintApiToken`, which itself needs admin). Chosen bootstrap (NO controller
change): the operator adds an **init container** to the controller pod that opens the pod-local
**UDS** (implicit admin) and `MintApiToken`s a dedicated operator token, writing it to a K8s
`Secret`; the operator then drives the **TCP Admin API** with that token (and records identity
in audit). Alternative (small controller enhancement, cleaner/decoupled): a
`WIREMESH_INITIAL_ADMIN_TOKEN` env the controller registers as a valid admin token at boot —
the operator generates it, provisions it to the controller Secret + uses it. MVP = the
init-container-UDS-mint approach; the env approach is a noted follow-up.

## 6. Gateway workload (the privileged, LAN-reachable data plane)
Per the earlier design discussion, a gateway must be **on the workload LAN and privileged**:
`hostNetwork: true` (so it has a real node/LAN IP, not a cluster-internal pod IP),
`securityContext.privileged: true` (or `capabilities.add: [NET_ADMIN, BPF, NET_RAW]`),
`/dev/net/tun` (hostPath or device plugin), and `NET_ADMIN` for `ip`/`nft`/`conntrack` +
eBPF tc. One active gateway per segment (a Deployment, 1 replica, pinned via placement); HA
(a standby / VIP) is a follow-up. The operator emits the gateway args
(`--controller-sync <svc>`, `--wg-port`, `--tun`, `--state-dir`, `--metrics`) and mounts the
enrollment-token Secret; the gateway self-enrolls (epoch-0 baseline) on first boot. **Client
routing is out-of-band** (workloads must route mesh CIDRs to the gateway's LAN IP — static
route / DHCP-121 / gateway-as-router); the operator documents this, it can't set routes on
external devices.

## 7. RBAC & packaging
Operator ServiceAccount + ClusterRole: manage `Deployments`/`Services`/`Secrets`/`PVC`/
`ConfigMaps` (+ the gateway's privileged `PodSecurity`/SCC exception), and full CRUD on the
five CRDs + their `status`/`finalizers`. Shipped as: the CRD manifests, the operator
Deployment + RBAC, and a **Helm chart** (`deploy/helm/wiremesh-operator`) that installs the
CRDs + operator; the operator then materializes everything else from CRs.

## 8. Key design decisions / open points
- Aggregate-Apply for Segments+Policy (one fabric reconciler) — chosen to match `Apply`'s
  whole-fabric transaction; avoids partial-fabric races.
- Delete handling via finalizers + `DeleteSegment` until `Apply` gains delete semantics.
- Bootstrap = init-container UDS mint (no controller change); env-token = follow-up.
- Gateway HA (standby/VIP) and multi-CIDR segments = follow-ups.
- Controller singleton (single-tenant) — cluster-scoped CRDs; multi-fabric is out of scope.
- Does the operator manage relay identity 0600 files? Yes — via the relay Secret + the
  container's per-file mode (as the container-image deployment note requires).

## 9. Task decomposition (build cycle)
1. `wiremesh-operator` crate scaffold (kube-rs, main, healthz, leader-election) + image + CI.
2. CRD Rust types (`kube::CustomResource`) for the 5 kinds + generated CRD YAML.
3. `WiremeshController` reconciler: Deployment+PVC+Service + init-container admin-token bootstrap → Secret; status ready.
4. Admin client wiring: connect to the controller TCP Admin with the bootstrap token; reusable `AdminClient`.
5. Fabric reconciler: aggregate Segments+Policies → render fabric YAML → `Apply`; status/version; finalizer `DeleteSegment` on removal.
6. `WiremeshGateway` reconciler: `MintToken` → Secret → privileged hostNetwork Deployment; status via `ListGateways`; `Drain` on delete.
7. `WiremeshRelay` reconciler: `RegisterRelay` → identity Secret → relay Deployment; status via `ListRelays`.
8. RBAC + Helm chart (CRDs + operator) + PodSecurity/SCC for the privileged gateway.
9. E2E in `kind`/`k3s` (netns/eBPF work in kind's kernel): apply CRs → controller up → gateway enrolls → a cross-segment flow passes, default-deny holds; delete CRs → clean teardown.
10. Docs: install (Helm), the client-routing requirement, examples; CLAUDE.md + README.

## 10. Constraints / prerequisites
- eBPF/tun/nftables need a real Linux kernel — E2E runs in `kind`/`k3s` (works; the CI netns
  suites already prove the enforcer/gateway in-kernel). Managed clusters must allow privileged
  hostNetwork pods + `/dev/net/tun` for gateways.
- The operator needs cluster-admin-ish RBAC (it creates privileged workloads).
- No new secrets required for the operator itself (unlike the release-signing work); it mints
  what it needs via the controller UDS.
