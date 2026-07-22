# WireMesh Kubernetes Operator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Rust/`kube-rs` operator that makes a WireMesh fabric fully declarative on Kubernetes — five CRDs reconciled into the existing controller's Admin API, with the operator owning the controller/gateway/relay workloads.

**Architecture:** A thin front-end over the unchanged `wiremesh-controller` (which stays the source of truth). The operator (a) owns Kubernetes workloads (controller Deployment+PVC+Service, privileged `hostNetwork` gateways, relays) and (b) reconciles fabric-config CRDs into the controller via its Admin gRPC API — chiefly `Apply(fabric_yaml)` (the call `fabricctl apply -f` makes). It reuses `wiremesh-proto`'s generated Admin client. Pure render/build logic is unit-tested; reconcilers are proven by a `kind` e2e.

**Tech Stack:** Rust, `kube` (kube-rs) + `k8s-openapi`, `tokio`, `tonic` (reusing `wiremesh-proto`), `serde`/`serde_yaml`, `schemars` (CRD schema); `kind`/`k3s` for e2e.

## Global Constraints
- **Spec is authoritative:** `docs/superpowers/specs/2026-07-22-kubernetes-operator-design.md`.
- **Do NOT modify the controller** for the MVP. The operator drives the EXISTING Admin API. (The `WIREMESH_INITIAL_ADMIN_TOKEN` env is a noted follow-up, NOT this plan.)
- **Controller is single-tenant** → all five CRDs are **cluster-scoped**, group `wiremesh.io`, version `v1alpha1`.
- **Admin API reuse:** the controller Admin service (`proto/wiremesh/v1/admin.proto`, generated in `wiremesh-proto`) exposes `Apply(ApplyRequest{fabric_yaml}) -> ApplyDiff`, `CreateSegment`, `DeleteSegment`, `MintToken(MintTokenRequest{kind,bound_cidrs,rebind_segment_id}) -> MintTokenResponse{token}`, `ListGateways`, `RegisterRelay(RegisterRelayRequest{endpoint}) -> Relay`, `ListRelays`, `MintApiToken(MintApiTokenRequest{name,role}) -> {token}`, `Drain`, `RotateKey`, `GetPolicy`. The TCP admin listener requires a bearer token; the UDS listener is implicit-admin.
- **Fabric YAML shape** (the `Apply` input; see `crates/wiremesh-controller/src/apply.rs`): `segments: [{name, cidrs: [..]}]` + optional `policy:` (the `wiremesh-policy` DSL: a list of `{from, to, rules: [{allow: {proto, ports: [..]}}]}`).
- **Gateway workload MUST be** `hostNetwork: true` + privileged (`NET_ADMIN`+`BPF`+`NET_RAW` or `privileged:true`) + `/dev/net/tun` — it loads eBPF, creates the tun, programs `ip`/`nft`. Uses the merged `ghcr.io/zozo6015/wiremesh-gateway` image. One active gateway per segment.
- **Images:** controller/gateway/relay use the merged `ghcr.io/zozo6015/wiremesh-{controller,gateway,relay}`; the operator publishes a new `ghcr.io/zozo6015/wiremesh-operator`.
- **Build discipline:** Rust builds/unit-tests run in the container via `./dev.sh run "<cmd>"` from the repo root, FOREGROUND, one at a time. The `wiremesh-operator` crate is a NEW workspace member. The **e2e needs a real kernel** — run it in `kind` (the CI netns suites already prove eBPF/tun work in-kernel); it is NOT a `./dev.sh` unit test.
- **Agent workflow (CLAUDE.md):** test-author, implementer, dedicated-runner, reviewer are DIFFERENT agents per task. No "done" with unrun/failing tests. Fix code, never weaken tests.

---

## File structure (what each unit owns)
- `crates/wiremesh-operator/Cargo.toml` — new workspace member (kube, k8s-openapi, schemars, serde, serde_yaml, tokio, tonic, wiremesh-proto, anyhow, thiserror, tracing).
- `crates/wiremesh-operator/src/crd.rs` — the 5 `#[derive(CustomResource)]` types + their Spec/Status structs.
- `crates/wiremesh-operator/src/fabric.rs` — PURE: aggregate `Segment`+`Policy` objects → fabric YAML string.
- `crates/wiremesh-operator/src/workloads.rs` — PURE builders: controller Deployment/PVC/Service, gateway Deployment (privileged hostNetwork), relay Deployment, the bootstrap init-container + Secret.
- `crates/wiremesh-operator/src/admin.rs` — Admin gRPC client wrapper (connect w/ bearer token; `apply`, `mint_token`, `register_relay`, `delete_segment`, `list_gateways`, `drain`).
- `crates/wiremesh-operator/src/controllers/{controller,fabric,gateway,relay}.rs` — the reconcilers.
- `crates/wiremesh-operator/src/main.rs` — operator entrypoint: install/verify CRDs, start the reconcilers, healthz, leader-election.
- `deploy/operator/crds/*.yaml` — generated CRD manifests.
- `deploy/helm/wiremesh-operator/` — Helm chart (CRDs + operator Deployment + RBAC + gateway PodSecurity/SCC).
- `deploy/docker/Dockerfile` — add a `wiremesh-operator` runtime target (mirror controller).
- `.github/workflows/container-images.yml` — add `wiremesh-operator` to the image matrix.
- `crates/wiremesh-operator/tests/e2e.rs` — `kind` end-to-end (feature-gated `e2e`).

---

### Task 1: Crate scaffold + operator entrypoint + image
**Files:** Create `crates/wiremesh-operator/{Cargo.toml,src/main.rs,src/lib.rs}`; Modify root `Cargo.toml` (add member), `deploy/docker/Dockerfile` (operator target), `.github/workflows/container-images.yml` (matrix). Test: `crates/wiremesh-operator/src/main.rs` unit (`healthz` returns 200).

**Interfaces:** Produces: a runnable `wiremesh-operator` binary that serves `/healthz` on `:8080` and logs "operator started"; `wiremesh_operator` lib crate.

- [ ] **Step 1 (test-author): failing test** in `main.rs` `#[cfg(test)] mod tests`: `async fn healthz_ok()` — call the `healthz()` handler, assert it returns HTTP 200 body `"ok"`.
- [ ] **Step 2: run — RED** `./dev.sh run "cargo test -p wiremesh-operator --no-run"` (crate/handler absent → fails).
- [ ] **Step 3 (implementer): scaffold** — add `crates/wiremesh-operator` to root `Cargo.toml` `[workspace] members`; `Cargo.toml` deps: `kube = { version = "0.95", features = ["runtime","derive","client"] }`, `k8s-openapi = { version = "0.23", features = ["latest"] }`, `schemars = "0.8"`, `serde`/`serde_json`/`serde_yaml`, `tokio` (workspace), `tonic`/`prost` (workspace), `wiremesh-proto = { path = "../wiremesh-proto" }`, `anyhow`, `thiserror`, `tracing`, `tracing-subscriber`, `futures`. `main.rs`: `tokio::main` that inits tracing, serves a minimal `healthz` (a tiny hyper/axum handler or a `TcpListener` returning `HTTP/1.1 200 OK\r\n\r\nok`), and logs. Add the `wiremesh-operator` runtime target to `deploy/docker/Dockerfile` (mirror the `controller` stage: debian-slim, ca-certs, non-root, `COPY --from=builder /out/wiremesh-operator`) and to the builder's `cp` list; add `{component: operator, image: wiremesh-operator}` to the workflow matrix.
- [ ] **Step 4: GREEN** `./dev.sh run "cargo test -p wiremesh-operator"` + `./dev.sh run "cargo build --workspace"`.
- [ ] **Step 5: commit** `feat(operator): crate scaffold + entrypoint + image target (Task 1)`.

### Task 2: CRD types
**Files:** Create `crates/wiremesh-operator/src/crd.rs`; Modify `lib.rs` (`pub mod crd;`); Create `crates/wiremesh-operator/src/bin/crdgen.rs` (emits CRD YAML). Test: unit in `crd.rs`.

**Interfaces:** Produces (exact — later tasks depend on these):
```rust
// group "wiremesh.io", version "v1alpha1", all Kind = cluster-scoped (no namespaced).
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(group="wiremesh.io", version="v1alpha1", kind="WiremeshController", status="WiremeshControllerStatus")]
pub struct WiremeshControllerSpec { pub image: Option<String>, pub storage_class: Option<String>, pub storage_size: Option<String>, pub admin_tcp_port: Option<u16>, pub sync_tcp_port: Option<u16>, pub observe_udp_port: Option<u16> }
pub struct WiremeshControllerStatus { pub ready: bool, pub admin_endpoint: Option<String>, pub observed_version: Option<u64>, pub conditions: Vec<Condition> }

#[kube(group="wiremesh.io", version="v1alpha1", kind="WiremeshSegment", status="WiremeshResourceStatus")]
pub struct WiremeshSegmentSpec { pub segment_name: String, pub cidrs: Vec<String> }

#[kube(group="wiremesh.io", version="v1alpha1", kind="WiremeshPolicy", status="WiremeshResourceStatus")]
pub struct WiremeshPolicySpec { pub from: String, pub to: String, pub rules: Vec<PolicyRule> }
pub struct PolicyRule { pub allow: AllowRule }  pub struct AllowRule { pub proto: String, pub ports: Vec<u16> }

#[kube(group="wiremesh.io", version="v1alpha1", kind="WiremeshGateway", status="WiremeshGatewayStatus")]
pub struct WiremeshGatewaySpec { pub segment_ref: String, pub node_name: Option<String>, pub node_selector: Option<BTreeMap<String,String>>, pub wg_port: Option<u16>, pub tun: Option<String>, pub image: Option<String> }
pub struct WiremeshGatewayStatus { pub enrolled: bool, pub gateway_id: Option<u64>, pub path_state: Option<String>, pub conditions: Vec<Condition> }

#[kube(group="wiremesh.io", version="v1alpha1", kind="WiremeshRelay", status="WiremeshResourceStatus")]
pub struct WiremeshRelaySpec { pub endpoint: String, pub node_name: Option<String>, pub image: Option<String> }

pub struct WiremeshResourceStatus { pub applied: bool, pub applied_version: Option<u64>, pub message: Option<String> }
pub struct Condition { pub r#type: String, pub status: String, pub reason: String, pub message: String }
```

- [ ] **Step 1 (test-author): failing tests** in `crd.rs` `#[cfg(test)] mod tests`: `crd_yaml_roundtrips` — build a `WiremeshSegment` (`WiremeshSegment::new("aws", WiremeshSegmentSpec{segment_name:"aws".into(),cidrs:vec!["10.10.1.0/24".into()]})`), serialize to YAML + parse back, assert `spec.cidrs == ["10.10.1.0/24"]`; `crd_derive_compiles_all_five` — construct one of each Kind (compile-proof). And `crdgen_emits_five_crds`: call the crdgen fn (Task step 3) and assert it returns 5 CRD docs whose `spec.names.kind` are the five kinds and `spec.scope == "Cluster"`.
- [ ] **Step 2: run — RED** `./dev.sh run "cargo test -p wiremesh-operator crd --no-run"`.
- [ ] **Step 3 (implementer): the 5 CRD types** exactly as the Interfaces block; add `pub fn all_crds() -> Vec<CustomResourceDefinition>` returning `WiremeshController::crd()` … for all five, forcing `.spec.scope = "Cluster"`. `bin/crdgen.rs` prints `serde_yaml` of `all_crds()` (`---`-joined) to stdout.
- [ ] **Step 4: GREEN** the crd tests. Generate the manifests: `./dev.sh run "cargo run -p wiremesh-operator --bin crdgen" > deploy/operator/crds/wiremesh-crds.yaml` and commit that file too.
- [ ] **Step 5: commit** `feat(operator): 5 cluster-scoped CRDs + crdgen (Task 2)`.

### Task 3: Admin client wrapper
**Files:** Create `crates/wiremesh-operator/src/admin.rs`; Modify `lib.rs`. Test: unit (request builders) in `admin.rs`; live calls are exercised by the e2e (Task 9).

**Interfaces:** Consumes: `wiremesh_proto::v1::admin_client::AdminClient` (generated). Produces:
```rust
pub struct FabricAdmin { /* tonic channel + bearer token interceptor */ }
impl FabricAdmin {
    pub async fn connect(admin_tcp_addr: &str, bearer_token: &str) -> anyhow::Result<Self>;
    pub async fn apply(&mut self, fabric_yaml: &str) -> anyhow::Result<ApplyDiff>;
    pub async fn mint_gateway_token(&mut self, bound_cidrs: &[String]) -> anyhow::Result<String>; // MintToken{kind:"gateway",bound_cidrs,rebind_segment_id:0}
    pub async fn register_relay(&mut self, endpoint: &str) -> anyhow::Result<u64>; // returns relay_id
    pub async fn delete_segment(&mut self, name: &str) -> anyhow::Result<()>;
    pub async fn list_gateways(&mut self) -> anyhow::Result<Vec<GatewayRow>>; // (id, segment_name, status)
    pub async fn drain(&mut self, gateway_id: u64) -> anyhow::Result<()>;
}
```
- [ ] **Step 1 (test-author): failing unit test** — `bearer_interceptor_sets_authorization`: build the interceptor with token "T", apply it to a `tonic::Request`, assert the `authorization` metadata == `"Bearer T"`. (Reuse the exact header form `crates/fabricctl` / `wiremesh-testkit`'s `BearerCredential` uses — grep for it.)
- [ ] **Step 2: run — RED**.
- [ ] **Step 3 (implementer): `FabricAdmin`** — a `tonic::service::Interceptor` that injects `authorization: Bearer <token>`; `connect` builds a `Channel` to `http://<admin_tcp_addr>` (plaintext gRPC — the admin TCP listener is bearer-auth over plaintext, see `Config::admin_tcp_port` doc) wrapped with the interceptor; the methods map to the generated `AdminClient` calls (build the exact request messages per the Global-Constraints Admin API list).
- [ ] **Step 4: GREEN** the interceptor test + `./dev.sh run "cargo build -p wiremesh-operator"`.
- [ ] **Step 5: commit** `feat(operator): Admin gRPC client wrapper (bearer) (Task 3)`.

### Task 4: Pure builders — fabric YAML + workload specs + bootstrap
**Files:** Create `crates/wiremesh-operator/src/{fabric.rs,workloads.rs}`; Modify `lib.rs`. Test: unit in both.

**Interfaces:** Produces:
```rust
// fabric.rs
pub fn render_fabric_yaml(segments: &[WiremeshSegmentSpec], policies: &[WiremeshPolicySpec]) -> String;
// workloads.rs — all return k8s-openapi types
pub fn controller_deployment(name:&str, spec:&WiremeshControllerSpec) -> Deployment;   // 1 replica, PVC mount /var/lib/wiremesh, ports, + bootstrap init container
pub fn controller_pvc(name:&str, spec:&WiremeshControllerSpec) -> PersistentVolumeClaim;
pub fn controller_service(name:&str, spec:&WiremeshControllerSpec) -> Service;          // admin-tcp + sync-tcp + observe-udp
pub fn bootstrap_init_container(admin_uds:&str, out_secret:&str) -> Container;          // mints an operator token over the UDS, writes to the token Secret via kubectl-less API (see Task 5 note)
pub fn gateway_deployment(gw:&WiremeshGateway, controller_sync:&str, token_secret:&str) -> Deployment; // hostNetwork+privileged+/dev/net/tun
pub fn relay_deployment(r:&WiremeshRelay, identity_secret:&str) -> Deployment;
```
- [ ] **Step 1 (test-author): failing unit tests.** `fabric.rs`: `renders_segments_and_policy` — two segments + one allow-policy → assert the YAML parses (`serde_yaml::from_str::<serde_yaml::Value>`) and contains the segment names + a `policy:` with the allow rule; `renders_segments_only_when_no_policy` — omits the `policy:` key when policies empty (matches `apply.rs`'s optional policy). `workloads.rs`: `gateway_is_privileged_hostnetwork` — `gateway_deployment(...)` has `spec.template.spec.host_network == Some(true)`, a container `security_context.privileged == Some(true)`, a `/dev/net/tun` volume/device, and mounts the token secret; `controller_deployment_has_pvc_and_bootstrap_init` — the controller Deployment mounts the PVC at `/var/lib/wiremesh` and has an init container named `admin-token-bootstrap`; `controller_service_exposes_admin_tcp` — the Service has a port named `admin-tcp`.
- [ ] **Step 2: run — RED**.
- [ ] **Step 3 (implementer): the builders.** `render_fabric_yaml`: build a `serde_yaml::Value`/typed struct mirroring `apply.rs`'s `Fabric{segments, policy?}` and the `wiremesh-policy` DSL, serialize. Workload builders: standard `k8s-openapi` `Deployment`/`Service`/`PVC`/`Container` construction per the Global Constraints (gateway = hostNetwork+privileged+tun+token-secret+the gateway args; controller = PVC + the bootstrap init container + ports; relay = identity secret + `--kind relay` args). Use the merged ghcr images as defaults.
- [ ] **Step 4: GREEN** both unit suites.
- [ ] **Step 5: commit** `feat(operator): pure fabric-YAML + workload/bootstrap builders (Task 4)`.

### Task 5: WiremeshController reconciler + admin-token bootstrap
**Files:** Create `crates/wiremesh-operator/src/controllers/controller.rs`; Modify `main.rs` (start it). Test: the bootstrap logic unit-testable where pure; the reconcile is proven by the e2e (Task 9).

**Interfaces:** Consumes: `workloads::{controller_deployment,controller_pvc,controller_service,bootstrap_init_container}`, `crd::WiremeshController`. Produces: a `kube::runtime::Controller` reconcile fn that, for a `WiremeshController`, server-side-applies the PVC+Service+Deployment (owner-referenced), waits for the Deployment available AND the token Secret populated, then sets `status.ready=true` + `status.admin_endpoint` (the Service DNS `admin-tcp` addr). The bootstrap init container runs a tiny shell that, via the pod-local UDS, calls the controller's `MintApiToken` (using `grpcurl`? NO — keep it Rust: a small `operator-bootstrap` subcommand of the operator image that opens the UDS + `MintApiToken` + writes the token to the Secret via the K8s API). Add `operator-bootstrap` as a `bin`/subcommand.

- [ ] **Step 1 (test-author): unit test** for the one pure piece: `admin_endpoint_from_service("wiremesh-controller", 6443) == "wiremesh-controller.<ns>.svc:6443"` (a helper `admin_endpoint(name, ns, port)`). The reconcile itself is e2e-tested (Task 9) — do NOT mock the whole apiserver here.
- [ ] **Step 2: run — RED**.
- [ ] **Step 3 (implementer):** the reconciler (SSA of the three objects with owner refs + finalizer; requeue until ready; status). The `operator-bootstrap` subcommand: connect to the UDS (implicit-admin), `MintApiToken{name:"operator", role:"admin"}`, write `{token}` into the named Secret via the in-cluster K8s client. `bootstrap_init_container` runs `wiremesh-operator operator-bootstrap --uds /var/run/wiremesh/admin.sock --secret <name>` with the shared UDS volume + a ServiceAccount that can write the Secret.
- [ ] **Step 4: GREEN** the helper unit test + `cargo build`.
- [ ] **Step 5: commit** `feat(operator): WiremeshController reconciler + UDS admin-token bootstrap (Task 5)`.

### Task 6: Fabric reconciler (Segments + Policies → Apply)
**Files:** Create `crates/wiremesh-operator/src/controllers/fabric.rs`; Modify `main.rs`. Test: `render` reuse is unit-tested in Task 4; the aggregate + Apply flow is e2e-tested (Task 9).

**Interfaces:** Consumes: `fabric::render_fabric_yaml`, `admin::FabricAdmin`, `crd::{WiremeshSegment,WiremeshPolicy}`. Produces: ONE fabric reconciler that, on ANY Segment/Policy change (both watched; both enqueue the SAME fixed reconcile key), lists ALL `WiremeshSegment` + `WiremeshPolicy`, renders one fabric YAML, calls `FabricAdmin::apply`, and writes the returned `policy_version`/diff into each object's status. A **finalizer** on `WiremeshSegment` calls `FabricAdmin::delete_segment(name)` before allowing deletion (since `Apply` is create/update-only). Requeues until the controller is `ready`.

- [ ] **Step 1 (test-author): unit test** — `enqueue_key_is_constant`: the mapper for Segment/Policy events returns the same singleton `ObjectRef` (so all fabric changes coalesce to one reconcile, avoiding races). (The full apply is e2e.)
- [ ] **Step 2: run — RED**.
- [ ] **Step 3 (implementer):** the fabric reconciler (aggregate → render → apply → status), the constant-key coalescing, and the `WiremeshSegment` finalizer that `delete_segment`s on removal.
- [ ] **Step 4: GREEN** the unit test + `cargo build`.
- [ ] **Step 5: commit** `feat(operator): fabric reconciler — aggregate Segments+Policy → Apply + delete finalizer (Task 6)`.

### Task 7: WiremeshGateway reconciler
**Files:** Create `crates/wiremesh-operator/src/controllers/gateway.rs`; Modify `main.rs`. Test: token-Secret idempotence unit; deploy + enroll is e2e (Task 9).

**Interfaces:** Consumes: `admin::FabricAdmin::{mint_gateway_token,list_gateways,drain}`, `workloads::gateway_deployment`, `crd::{WiremeshGateway,WiremeshSegment}`. Produces: a reconciler that resolves the `segment_ref` → its CIDRs, mints an enrollment token ONCE (guarded: only if the token Secret doesn't already exist), stores it in a `Secret`, SSA-applies the privileged hostNetwork gateway Deployment (owner-ref'd), and sets `status.enrolled`/`gateway_id` from `list_gateways`. Finalizer: `drain(gateway_id)` + delete the workload on CRD removal.

- [ ] **Step 1 (test-author): unit test** — `token_secret_name(gw) == format!("wiremesh-gw-{}-token", gw.name)` and `mint is skipped when the secret exists` (a pure guard fn `needs_token(existing_secret: Option<&Secret>) -> bool`).
- [ ] **Step 2: run — RED**.
- [ ] **Step 3 (implementer):** the gateway reconciler + the mint-once guard + the `drain` finalizer.
- [ ] **Step 4: GREEN** the unit test + `cargo build`.
- [ ] **Step 5: commit** `feat(operator): WiremeshGateway reconciler — mint token + privileged hostNetwork deploy + drain (Task 7)`.

### Task 8: WiremeshRelay reconciler
**Files:** Create `crates/wiremesh-operator/src/controllers/relay.rs`; Modify `main.rs`. Test: unit for the naming/guard; deploy is e2e.

**Interfaces:** Consumes: `admin::FabricAdmin::register_relay`, `workloads::relay_deployment`, `crd::WiremeshRelay`. Produces: a reconciler that `register_relay(endpoint)` once → identity Secret → SSA the relay Deployment → status `registered`/`relay_id`.

- [ ] **Step 1 (test-author): unit test** — `relay_secret_name(r) == format!("wiremesh-relay-{}-identity", r.name)` + `needs_register(existing_secret) -> bool` guard.
- [ ] **Step 2: run — RED**. **Step 3 (implementer):** the relay reconciler + register-once guard. **Step 4: GREEN** unit + build. **Step 5: commit** `feat(operator): WiremeshRelay reconciler (Task 8)`.

### Task 9: RBAC + Helm chart + kind e2e (the real proof)
**Files:** Create `deploy/helm/wiremesh-operator/{Chart.yaml,values.yaml,templates/*.yaml}` (CRDs, operator Deployment, ServiceAccount+ClusterRole+Binding, gateway PodSecurity/SCC exemption); Create `crates/wiremesh-operator/tests/e2e.rs` (feature `e2e`); Create `deploy/operator/e2e/kind.sh` (spin up kind, load images, run). Test: the e2e IS the test.

**Interfaces:** Consumes: everything. The e2e is the done-bar.

- [ ] **Step 1 (test-author): the e2e** (`#![cfg(feature="e2e")]`, `crates/wiremesh-operator/tests/e2e.rs`): assumes a `kind` cluster with the operator + CRDs installed and the four ghcr images loaded. It: applies a `WiremeshController` CR → waits `status.ready`; applies two `WiremeshSegment`s + one `WiremeshPolicy` → waits both segments `status.applied` with a non-zero version; applies two `WiremeshGateway`s (one per segment, pinned to two kind nodes, hostNetwork) → waits both `status.enrolled`; asserts (via `kubectl exec` into a probe pod on each segment / the gateway metrics) that a **policy-permitted cross-segment flow passes AND a denied flow is dropped** (mirror `mesh_milestone.rs`'s allowed/denied assertions); then deletes the CRs and asserts clean teardown (gateways drained, workloads gone). `kind.sh` builds+loads the images, `helm install`s the chart, and runs `cargo test -p wiremesh-operator --features e2e -- --nocapture`.
- [ ] **Step 2: run — RED** (no operator deployed yet / reconcilers incomplete → the e2e fails at `status.ready` or the flow assertion). Capture.
- [ ] **Step 3 (implementer): the Helm chart + RBAC** (ClusterRole: CRUD on the 5 CRDs+status+finalizers, and Deployments/Services/Secrets/PVCs; the privileged-pod exemption for gateways) and any reconciler fixes the e2e surfaces. Iterate on real cluster bugs; a "failing" behavior may be a real finding → record in `docs/research/` before adapting.
- [ ] **Step 4: GREEN** — the full e2e passes in kind (run 2× for stability). Also confirm `./dev.sh run "cargo test -p wiremesh-operator"` (the unit tests, no `e2e` feature) stays green and `cargo build --workspace` is clean.
- [ ] **Step 5: commit** `feat(operator): Helm chart + RBAC + kind e2e green (Task 9)`.

### Task 10: Docs
**Files:** Create `docs/operator.md` (install via Helm; the CRD reference; the **client-routing requirement** — workloads must route mesh CIDRs to the gateway's LAN IP; a full example fabric); Modify `README.md` (operator quickstart), `CLAUDE.md` (project state: operator shipped). Test: none (docs).
- [ ] **Step 1:** write `docs/operator.md` with a copy-pasteable example (WiremeshController + 2 Segments + 1 Policy + 2 Gateways) and the routing caveat.
- [ ] **Step 2:** README quickstart + CLAUDE.md state update. **Step 3: commit** `docs(operator): install + CRD reference + routing model (Task 10)`.

## Done bar
`helm install` the operator, `kubectl apply` a WiremeshController + Segments + Policy + Gateways, and a policy-enforced cross-segment mesh comes up with no `fabricctl` scripting; the kind e2e proves allowed+denied flows and clean teardown; unit suites + `cargo build --workspace` green; the controller was not modified.
