# WireMesh backlog

**As of `v0.7.5` (2026-08-07).** 24 open items. Every one has a verified mechanism —
these are not guesses, and where a claim was checked and turned out wrong, that is
recorded too.

Ordered by what to pick up first. Items marked **READY** have a designed and verified
fix shape and can go straight to test-authoring.

> **Before starting anything here, read [Recurring traps](#recurring-traps) at the
> bottom.** Four of them have already caught someone, and three are in this backlog's
> own subject matter.

---

## Do these first

### 1. READY &mdash; Unvalidated `local_endpoints` breaks every gateway's device apply

**Fabric-wide availability defect, reachable from one gateway.**

`SyncSvc::report` passes `req.local_endpoints` to `Db::set_local_candidates` with **no
validation at all** &mdash; no parse, no `SocketAddrV4` check, no element cap &mdash;
and re-advertises the strings verbatim to every other gateway.

Downstream, `encode_set` loops all peers with `push_peer_block(..)?`, so **one
malformed endpoint on one peer fails the entire device encode**. Gateway A (observe UDP
blocked &mdash; exactly the NAT case the fabric exists for) reports a malformed local
endpoint, it becomes A's `candidates[0]`, and **every other gateway's whole `wg0` apply
fails**.

That is not a stalled convergence, it is an exit. `apply_state` calls
`uapi::encode_set(&dev).context(..)?` *before* the `match delta`, so no incremental path
avoids it; the `?` unwinds out of `async fn run(cfg: GatewayConfig)` past both loops, and
`main` ends in `rt.block_on(run(cfg))` &mdash; so **the gateway process exits non-zero, on
every peer simultaneously**. Boot goes through the same call
(`apply_state(None, ds, ..).await?`), so a persisted bad candidate blocks restart too: a
crash-loop, not a degradation. The one mitigating detail is ordering &mdash;
`fail_static.save(..)` runs *after* `apply_state`, so the dying path never persists the
poison.

Reachability is precise. `set_local_candidates` **sorts**, and `candidates_for` pushes the
observed endpoint first, so a malformed entry reaches `candidates[0]` exactly when
`gateway.candidate_endpoint` is NULL &mdash; the observe-blocked NAT case &mdash; and
enrollment never seeds it. The sort also means an attacker picks index 0 with a
low-sorting string. A stock gateway cannot emit garbage: `netif::local_wg_endpoints`
formats from an already-parsed `Ipv4Addr`. The threat is a compromised or version-skewed
gateway holding a valid fabric-CA cert, which is squarely inside the zero-trust model.

The tell: the controller *does* validate relay endpoints as `SocketAddrV4` at both
registration paths, and gets the observed endpoint's IPv4-ness free from the socket
type. The one source that is genuinely remote-supplied and free-form is the unchecked
one.

**Fix, two layers.** Validate at controller ingress in `SyncSvc::report` &mdash; filter
with a log rather than a hard reject, so a partially-garbage report does not cost the
gateway its whole candidate set &mdash; plus an element-count bound. There is **no cap
anywhere today**: `sync.proto` declares `repeated string local_endpoints = 2;`
unconstrained and nothing overrides `max_decoding_message_size`, so the ceiling is tonic's
4MB default (~200k strings), fanned out into every peer's snapshot and delta and deduped
by an O(n²) `contains()` in `candidates_for`. Then filter `PeerState::candidates` on
ingest in `PeerState::from_proto`: that site covers `peer_configs`,
`device_config_pinned` and `pending_peer_configs` at once, and makes item 16 unreachable
by construction. **Do not add per-builder checks.**

`from_proto` is private and dominates those three consumers, but it is **not** the only
gateway-side ingress. Two escapes:

- `DesiredState::load` is `serde_json::from_slice` over `state.json`, and
  `PeerState.candidates` is a `pub` field with `#[serde(default)]`, so deserialization
  rebuilds `candidates` without going through `from_proto`. This is the path that turns
  one bad apply into a gateway that cannot boot, so the fix must cover it &mdash; either
  filter across `load`/`from_snapshot`/`apply_delta` as a set, or make `candidates`
  private behind a validating constructor.
- `PunchDirective.candidates` is a separate ingress: the controller's `Broker` reads the
  same `Db::candidates_for` strings and ships them, and the gateway consumes them in the
  `SyncEvent::Punch(d)` arm without ever building a `PeerState`. It is safe today only
  because `punch::CandidateTrial::new` filters. **Controller ingress is what covers this
  path &mdash; `from_proto` is not**, so do not later delete the controller-side check as
  redundant.

Separately worth deciding, but **not** to be smuggled in with a validation fix: whether
`encode_set` should skip a malformed peer rather than failing the whole device apply.
That is a fail-open/fail-closed call and deserves its own decision &mdash; and the exit
path above raises its stakes, since what it decides is whether a malformed peer
crash-loops the gateway, not whether the fabric converges. Still right to defer; not
decided here.

**Item 1 closes one of three fatal validators, not all three.** The siblings &mdash;
`Peer.keys[].pubkey` and `Peer.allowed_ips` &mdash; are filed as items 23 and 24, **out of
scope for item 1's branch** by owner decision. Item 23 is HIGH and remotely reachable
today. Do not read a green item 1 as closing the family.

Tests: all pure, no netns. Nothing covers this today.

### 2. READY &mdash; Operator CRD surface (three items remain, one minor release &mdash; 2c shipped in PR #59)

**Ship these together.** Every CRD change costs users a mandatory manual re-apply
(Helm never upgrades CRDs), so splitting them means two re-applies for no reason.

**2a. No CRD field for `WIREMESH_ROTATION_INTERVAL`.** The key appears nowhere in
`wiremesh-operator` or `deploy/`, and `.force()` is on both apply paths
(`controllers::apply`, `controllers::apply_deployment`). **Not an empty list:**
`controller_deployment` emits `env: Some(vec![..])` with **seven** entries
(`WIREMESH_DATA_DIR`, `WIREMESH_TCP_PORT`, `WIREMESH_SYNC_TCP_PORT`,
`WIREMESH_SOCKET_PATH`, `WIREMESH_ADMIN_TCP_PORT`, `WIREMESH_OBSERVE_UDP_PORT`,
`WIREMESH_BIND_IP`) &mdash; the change is a conditional eighth push, not populating a
`vec![]` (the fn's own doc comment says "six" and is stale too).

> **Not true, and do not "fix" it:** hand-edits do *not* revert.
> `io.k8s.api.core.v1.Container.env` carries `x-kubernetes-list-type: map` with
> `list-map-keys: [name]` (and the matching `patch-merge-key`/`patch-strategy: merge`), so
> `.force()` asserts ownership **per key**. The operator never names this one, so
> `kubectl set env` survives every reconcile. (This is per-key &mdash; `WIREMESH_BIND_IP` *is* clobbered, because the
> operator names it. Read off a live v1.34 schema while `k8s-openapi` is pinned to
> `v1_30`; these markers have been stable on `env` since ~1.19.)

**But note there may be no live instance of this.** The control plane moved off zolab k8s
to the px Debian host on 2026-08-01, where the controller runs as a **systemd unit, not a
Deployment** &mdash; so there may currently be no operator-managed controller anywhere, and
the rotation mitigation on the real fabric is an env var on a systemd unit, not an SSA
question. The doctrine above holds for operator-managed clusters; it is not presently
protecting a live edit.

**The trap:** emitting the key **with a default** makes the operator *own* it, and then
`.force()` really would overwrite a human's `off` &mdash; silently re-enabling rotation
on exactly the clusters that had mitigated it. **Emit only when `Some`.** The precedent to
copy is the `Option` spec fields' `#[serde(default, skip_serializing_if = "Option::is_none")]`,
pinned by `override_fields_serialize_camel_case_and_omit_when_unset` in
`crates/wiremesh-operator/tests/gateway_endpoint_overrides.rs` (which also covers
legacy-CR deserialization); `scheduler_aware_node_selector`'s omit-when-unset is real but
less close.

**A second trap, from the opposite direction:** once set and then *removed* from the CR,
SSA **deletes** the env entry and the controller boots on the 30-day default. Removing a
field re-enables rotation. Inherent to SSA; document it loudly on the field.

Validation: a CRD `pattern` **cannot** express the grammar (it cannot reject `0s`, or
`>3650d`, or a `u64` overflow, and must *accept* whitespace-trimmed forms). So
`parse_rotation_interval` has to be shared code. **Put it in `wiremesh-enroll` and create
no new crate** &mdash; that is where the shared resolver and keepalive constants already
live, and the operator already carries tonic + prost + wiremesh-proto, so it gains only
`rcgen`. (An earlier version of this item asked for "a leaf crate depending only on
`anyhow`" *and* cited `wiremesh-enroll` as the precedent; those contradict &mdash;
`wiremesh-enroll` depends on tonic, rcgen, tokio and wiremesh-proto. The dependency
constraint was the wrong half to keep.) Do **not** depend on `wiremesh-controller` (no
`[features]`, pulls rusqlite, tonic, prost, x509-parser, serde_yaml, rcgen and more). And
do **not** follow the counter-precedent: `workloads::validate_dial_target` is a documented
hand-duplicate of the gateway's `config::validate_host_port`, but duplicating a *grammar*
is worse than duplicating a check &mdash; a drift means the operator accepts a value the
controller rejects at boot, i.e. CrashLoopBackOff.

> **DESCOPED from 2a's first commit (owner decision 2026-08-10) &mdash; filed as item 29.**
> The CRD field and the conditional env emission shipped without the
> `parse_rotation_interval` relocation or any reconciler pre-apply check. Rationale:
> `wiremesh-operator` has no production dependency on `wiremesh-enroll` or
> `wiremesh-controller` today, so the validation needs a new dependency edge &mdash; a
> structural change that does not belong inside a field addition. The stakes also differ
> from the `validate_dial_target` precedent this section cites: a bad dial target **burns a
> single-use enrollment token** (destructive, unrecoverable), whereas a bad rotation
> interval crash-loops the controller pod (visible, recoverable). Still worth doing; not
> worth coupling.

**2b. `args` and `replicas` are force-clobbered with no override.** Upstream
`Container.args` is `x-kubernetes-list-type: atomic` (as is `Container.command`, which the
enroll init-containers set), so unlike `env` there is **no per-element survival** &mdash;
hand-added flags are wiped wholesale and the gateway's `--metrics 0.0.0.0:9090` is
unchangeable. `replicas: Some(1)` is force-set on
all three workloads, so `kubectl scale --replicas=0` reverts *immediately*. There **is**
one documented workaround &mdash; scale the *operator* to 0 first
(`docs/runbooks/controller-migration-to-fi.md`, "Field notes &mdash; px migration,
2026-08-01", item 1) &mdash; which stops all reconciliation and is independent live
evidence that the force-clobber really happens. Short of that or deleting the CR and
firing the drain finalizer, there is no per-workload way to take a gateway down for
maintenance.

- Add one typed `metricsBind` field. **Do NOT add `extraArgs`** &mdash; the gateway's arg
  parser is last-wins, so an appended list could silently override `--state-dir`,
  destroying PVC identity and forcing a re-enroll against a *spent single-use token*.
- **Do NOT reuse `validate_dial_target`** for a bind address: it accepts DNS names (which
  the gateway rejects at boot), rejects port `0` (legitimate for a bind addr, and the
  binary's own default), and rejects `[::]:9090` and every other IPv6 form &mdash; so
  `metricsBind` inherits an IPv4-only bind constraint whichever validator is written.
- The two **enroll init-container** arg lists must stay non-overridable &mdash; they are
  bound to CIDRs the enrollment token is cryptographically committed to. **This is not
  already covered:** `enroll_init_container_is_never_overridden`
  (`crates/wiremesh-operator/tests/gateway_endpoint_overrides.rs`) is one test pinning one
  element of one list, the gateway enroll container's `--controller`. Nothing pins
  `--cidr`, `--token-file` or `--state-dir`, and nothing pins the relay's
  `wiremesh-relay-enroll` args at all. Closing that gap is part of this work.
- For `replicas`: **omit unconditionally, no CRD field.** A field would still be
  force-applied (moving the knob, not fixing it), and it advertises capability that does
  not exist (hostNetwork, fixed WG port, RWO PVC, `Recreate` chosen so a second pod never
  surges). **But omitting breaks two readiness computations** &mdash;
  `controllers::controller::reconcile` (`status.ready`, the `Ready` condition,
  `reason: WaitingForController`, 10s requeue) and `controllers::relay::reconcile`
  (`status.applied`, `"relay pod starting"`, 15s requeue) are the only two that read
  `available_replicas` &mdash; so a `ScaledDown` condition must ship in the same change,
  **on `WiremeshController` and `WiremeshRelay` only**. The gateway's readiness is
  roster-based: `controllers::gateway::apply_gateway` computes `enrolled =
  seg_row.is_some()` from the controller's gateway roster, emits an `Enrolled` condition,
  and requeues `if enrolled {300} else {15}` &mdash; it never reads Deployment status. So
  the very workload this item wants scalable needs zero condition work. One-time upgrade
  effect, confirmed by the upstream schema (`DeploymentSpec.replicas` is a nullable int32,
  *"a pointer to distinguish between explicit zero and not specified. Defaults to 1"*): SSA
  releases the field, the API-server defaulter re-sets 1, and any currently-scaled-to-0
  Deployment comes back up once.
- **Unfiled gap this surfaces:** because gateway readiness never reads the Deployment, a
  gateway scaled to 0 keeps reporting `Enrolled: True` off a still-active roster row
  &mdash; the CR silently misreports a dead data plane. Shipping "you may now scale a
  gateway to 0" ships that misreport with it.

**2c. RESOLVED &mdash; Helm CRD bundle had drifted.** Fixed in PR #59 (commit `77ca6f7`):
`render_crd_yaml()` was extracted out of `bin/crdgen.rs` into `crd.rs`, `crdgen.rs` is now a
one-line wrapper over it, `crates/wiremesh-operator/tests/crd_manifest_freshness.rs`
byte-compares both `deploy/operator/crds/wiremesh-crds.yaml` and
`deploy/helm/wiremesh-operator/crds/wiremesh-crds.yaml` against it (2 tests, both green), and
the Helm bundle was regenerated &mdash; the two files are byte-identical again. Kept below as
a **historical regression guard**: the failure mode is subtle enough that whoever next
touches either CRD file should still learn it.

Three hunks, four missing properties, all removals from the Helm copy and nothing else:
`WiremeshGateway.spec.observeEndpoint`, `WiremeshGateway.spec.syncEndpoint`, and the unfiled
`WiremeshRelay.spec.storageClass` / `WiremeshRelay.spec.storageSize`.

Root cause was exact, and it was **one missed commit**: `crd.rs` and
`deploy/operator/crds/wiremesh-crds.yaml` share identical commit histories (`a694f04`,
`4ffa006`, `f345cae`, `c7a4814`); the Helm copy had the first three and was missing exactly
`c7a4814` ("wip(operator): hardening round", 2026-07-31). Structurally, `crdgen` printed to
stdout only &mdash; no `build.rs`, no Makefile/CI/justfile reference &mdash; and the only
related test, `crd::tests::crdgen_emits_five_cluster_scoped_crds`, counted kinds and asserted
scope while never opening either YAML.

The broken path was a **first-time `helm install`** (unknown fields are *pruned*, not
rejected; documented upgraders apply the fresh copy). The runbook casualty was worse than
filed: `docs/runbooks/controller-migration-to-fi.md` §6.3 "gw-home (the payoff)" patches
`observeEndpoint`/`syncEndpoint`, both absent from the Helm bundle, and with no
`x-kubernetes-preserve-unknown-fields` a structural-schema apiserver **prunes them silently
while `kubectl` still prints `patched`** &mdash; the pod is never re-rolled, the section's own
success check fails with no error anywhere, and the documented rollback silently no-ops too.
**This is the part to remember even with the bundle fixed:** a structural CRD schema does not
reject an unknown field, it prunes it, so a `kubectl patch` printing `patched` is never
evidence anything actually changed.

Fix shape that landed: extract the render into a shared `pub fn render_crd_yaml()` so
`crdgen` and the test exercise the same code path, regenerate both files from it, then assert
byte equality against **both** in ordinary `cargo test` &mdash; no cluster, no CI change. Two
physical files stayed (a chart must be self-contained); patching the YAML alone would only
have guaranteed a fifth drift.

Two unpinned assumptions carry forward, now load-bearing precisely because
`crd_manifest_freshness.rs` byte-compares the bundles &mdash; either one changing silently
rewrites both YAML files, and this test is what would catch it: document order is
deterministic only because `all_crds()` returns an explicit `vec![..]`, and property order is
alphabetical only because `schemars` is built without `preserve_order`.

**2d. Relay `--controller` has no CRD override.** Derived from the in-cluster ClusterIP.
Since the control plane moved to the px host, an in-cluster relay cannot be pointed at it
&mdash; the identical failure that gave the gateway `syncEndpoint`. Same shape as
`WiremeshGatewaySpec::sync_endpoint`, four pieces: the field plus serde attrs in `crd.rs`;
validation in the reconciler via `validate_dial_target` (correct here &mdash; this *is* a
dial target) returning `Error::Admin`, **before any mint/PVC/Deployment side effect**, the
way `apply_gateway`'s loop over `[("observeEndpoint",..),("syncEndpoint",..)]` does;
`..as_deref().unwrap_or(controller_sync)` in the builder; tests alongside
`gateway_endpoint_overrides.rs`. **One asymmetry:** `relay_deployment` returns
`anyhow::Result` and already fails closed on a bad `endpoint` *inside the builder*, so the
validation must go in the reconciler or the relay ends up with two validation sites.

**Sizing and order.** Total CRD-visible surface is **3 new spec properties across 3 of the
5 kinds** (`WiremeshController.spec.rotationInterval`, `WiremeshGateway.spec.metricsBind`,
`WiremeshRelay.spec.controllerEndpoint`) plus the **4 existing properties restored** to the
Helm bundle. **No status schema change** &mdash; `ScaledDown` is a new *value* of the
existing `conditions[].type` string. All additive `Option` + `skip_serializing_if`, so no
`v1alpha2`, no conversion webhook, no storage migration, and legacy CRs still deserialize:
**minor bump**, with the mandatory manual CRD re-apply called out in the release notes.

**Build order: 2d → 2a → 2b, as commits inside the one minor.** 2c shipped first (PR #59,
commit `77ca6f7`) for the reason the original order gave it priority: pure regeneration plus
a test, zero design risk, the only live casualty &mdash; and every later sub-item adds a field
that must land in *both* files, so the freshness test it added now guards the rest from a
fresh chance to drift a fifth time. That rationale does not transfer to what leads next: 2d
is first among the remaining three because it is mechanical, a proven shape, not because of
the drift guard. 2a second (only the crate decision left), 2b last &mdash; it still carries
the one real design question, now a third smaller.

---

## Rotation

**`WIREMESH_ROTATION_INTERVAL=off` is set on the px controller and must stay set.**
Manual `fabricctl` rotation works. Rotation is now *repeatable* &mdash; a gateway can
rotate more than once (v0.7.2) and no longer falls out of the timer after one round
(v0.7.3) &mdash; but one blocker remains.

### 3. The in-step case &mdash; THE LAST BLOCKER

The controller rotates every active gateway in one tick off one timer, so the fabric
rotates **in step**. Committed `#[ignore]`d as RED-by-design in
`crates/wiremesh-gateway/tests/key_rotation.rs`. **Un-ignoring it is the bar.** This is
exactly what the timer does, which is why `off` stays until it is green.

### 4. T7 &mdash; three-gateway rotation harness + per-peer cutover gate

The in-step case is a multi-gateway problem and **there is no harness for it**. That is
why it went unnoticed until a done-bar forced it. Likely a prerequisite for item 3.

### 5. `Retire{0}` permanent wedge

`prior_active_epoch` is `.unwrap_or(0)` when the snapshot has no `active` row, at
**three** sites &mdash; `drive_rotation_for`, `sweep_rotations` step 2, and **`report`'s
batched seed loop** (a fix that misses the third leaves it reachable via the ack path).
The tracker promotes, rule 1 then yields `Retire{0}` forever, the CAS matches nothing
forever, and `evict_decision`'s `None`-means-keep makes it an unconditional keep with no
`pending`/`retiring` row for the sweep to find. Permanent.

Fix: type `prior_active_epoch` as `Option<u32>` and teach rule 1 to skip a retire with
nothing to retire. **Do not** paper over it by removing the tracker on row-absent &mdash;
that is trap #2 below, in a new place.

### 6. Rotation observability (F2/F5) &mdash; deferred review findings

### 7. `kick_overlap` is provably inert after v0.7.2's piece 3

Delete it, or make the tun addressable. Currently dead code that looks live.

### 8. Piece 1's read-through aborts the first retire grace after every cutover

A delay, not a failure &mdash; but it happens every time.

### 9. Rotation wedge &mdash; three routes in

`on_directive` is honoured only from `Idle`, so anything parking the phase off-`Idle`
means the gateway silently ignores every later directive **and** never scrubs the old
key. Most reachable via `handle_rotate` advancing the phase then doing fallible work.

### 10. `rotation_timer` setup-race flake

Tests race the timer against setup.

### 11. Socket leak on rebind &mdash; DOWNGRADED, not a blocker

Recorded because the leak is real and someone will rediscover it. boringtun registers its
epoll event against a `try_clone()` but clears by the *original's* fd, so old sockets stay
bound. Observed: four sockets on the reserved port at the rotation-2 peak, two holding the
**retiring epoch's key**; the gateway leaks even before any rotation.

**It does not cause a failure.** Linux head-inserts into the port hash and
`udp4_lib_lookup2` uses a strict `>`, so newest-bound wins deterministically &mdash; and
the leaked socket could not be made to win even warm and CPU-pinned (20 sends x 5 trials).
What remains is an undocumented kernel dependency plus an **unbounded fd leak** (2 per
`open_listen_socket`, per rotation *and* per full apply). Evidence and three candidate
fixes: `docs/research/socket-leak-on-rebind.md`.

---

## Gateway / data plane

### 12. Fabric routes carry no `src`

The gateway host itself cannot reach the fabric.

### 13. R1 &mdash; the F1 gate does not cover the route write derived from the stale clone

### 14. `endpoint_commit_gen` is one-sided, not the seqlock its doc claims

Bumped once *before* the device write, so the covered case is "commit lands entirely after
the tick's read". The uncovered one: the tick snapshots the bumped generation, observes the
*old* endpoint, passes the equality check, and writes it over the fresh pin. Self-heals next
tick. Needs a bump before **and** after, with the tick requiring unchanged *and* even.

### 15. Blocking UAPI write inside the `endpoint_commit` section

`tunnels.set_listen_port` is a synchronous round-trip on a runtime worker, inside a lock
that gates the endpoint-install path. Every sibling UAPI write uses `spawn_blocking`.
Suspected contributor to the zero-drop flake &mdash; but **note the constraint**: failures
also fire at the *minimum* flood window, so "the rotation got slower" is not a complete
mechanism.

### 16. Remaining IPv4-validation gap

Largely subsumed by item 1. Two of the three originally-filed sites are **closed as safe**
(the observed endpoint is only a log line; the relay dial target is triple-guarded). The
third is `pending_peer_configs`' `rsplit_once(':')` string surgery &mdash; real, but the
least important of its family, and fixed for free by item 1's `PeerState::from_proto` filter.

---

## Platform / design

### 17. `WIREMESH_INIT_CA` &mdash; explicit first-boot CA opt-in

### 18. `ReportRequest` conflates a snapshot and a sparse event

### 19. Relay mux `/1` wire break

Deferred with **6 open owner decisions**. The 32-bit `registration_key` makes collisions
deterministic and permanent (~17% at 200 gateways), so this is a correctness fix, not an
optimization.

### 20. LAN-side route propagation

Fabric CIDRs are unreachable from non-gateway hosts. Assume the operator may not control
the LAN router.

### 21. No HA for a segment gateway

Single node = single point of failure. The gateway's identity is on a node-local RWO PVC,
so cross-node failover is explicitly out of scope as built. On a cluster with a node
autoscaler this is *worse* than a single box: the node can be reclaimed and the pod cannot
reschedule.

### 22. Two source comments claim a `kind` e2e harness proves the reconcile loops

**It does not exist.** No kind config, no script, no workflow, no test that creates a
cluster. The operator's real automated coverage is pure-builder only; end-to-end validation
has been manual. This is a false assurance sitting exactly where someone looks before
deciding how much to test a change &mdash; same class as the `--help` text corrected in
v0.7.4.

Either correct the comments, or build the harness. The operator crate has no
aya/boringtun/netns dependency, so unlike the rest of the workspace it *could* run kind on a
plain runner.

---

## Ingress validation &mdash; item 1's siblings

Filed 2026-08-10 from an independent audit of `push_peer_block`, and **out of scope for
item 1's branch** by owner decision. Numbered here to keep the file's numbers ascending;
**item 23 is HIGH and belongs with "Do these first" by priority.**

Item 1 fixes one of **three** fatal validators in `wiremesh_gateway::uapi::push_peer_block`
(`crates/wiremesh-gateway/src/uapi.rs:134-143`): `validate_ipv4_endpoint(ep)?` (item 1),
`key_b64_to_hex(&p.public_key_b64)?` (item 23) and `validate_ipv4_cidr(cidr)?` (item 24).
All three `?` land identically, on item 1's own exit path &mdash; `push_peer_block` →
`encode_set` (`uapi.rs:154-164`) → `apply_state`'s `uapi::encode_set(&dev).context(..)?`
(`main.rs:3536`) → unwinds out of `run()` → process exit. **Both** `apply_state` call sites
propagate rather than catch: `main.rs:994` (Sync event loop) and `main.rs:613` (fail-static
boot). So item 1's whole rationale &mdash; fabric-wide crash, then an unbootable gateway
with the controller out of the loop &mdash; transfers verbatim.

Line numbers are as of `fix/validate-local-endpoints`; per the last trap below, trust the
symbols over the numbers.

### 23. HIGH &mdash; `Peer.keys[].pubkey` is item 1's bug on a sibling field

**Remotely reachable today.** `key_b64_to_hex` (`uapi.rs:47-54`) errors on non-base64, or
on a decode that is not exactly 32 bytes.

Both doors are open. **Gateway side:** `reconcile::peer_configs`
(`crates/wiremesh-gateway/src/reconcile.rs:22`) does `let public_key_b64 =
p.active_pubkey_b64.clone()?` &mdash; that `?` filters `None` **only**, never an
undecodable key; `PeerState::from_proto` (`state.rs:112-118`) copies `pubkey_b64:
k.pubkey.clone()` with no filter. **Controller side, unvalidated at both ingress points:**
`EnrollRequest.wg_pubkey` reaches `services/enrollment.rs:321`, which passes
`req.wg_pubkey.clone()` straight into `enroll_gateway` (the only inspection anywhere is an
`is_empty()` branch choosing a placeholder); `SubmitEpochKey.pubkey` reaches
`services/sync.rs:2003`, which calls `self.db.set_epoch_pubkey(gw.id, epoch, req.pubkey)`
with no decode and no length check &mdash; the only gate before it is
`check_session_generation`.

Failure scenario: a compromised or version-skewed gateway holding a valid fabric-CA cert
enrolls with `wg_pubkey = "!!!"` (or any base64 decoding to ≠32 bytes). The controller
stores it and advertises it to every peer. Every other gateway's next `apply_state` returns
`Err("WG key must be 32 bytes, got 2")` and the process exits &mdash; **every peer at
once**. Fail-static then persists it into `state.json`, so it also blocks boot.

**Fix shape** (record only, not implemented): the gateway already owns the right primitive.
`uapi::pubkey_b64_to_hex` (`uapi.rs:67-73`) is `Option`-shaped and is already used
correctly by `rotation::role_b_decisions` and the path ticks (`main.rs:2857`) to answer
exactly "is this peer's advertised key usable at all?". `reconcile::peer_configs` simply
never calls it. **Gateway half:** filter at the same door item 1 opened. **Controller
half:** validate at `enroll` and at `SubmitEpochKey`, mirroring the existing relay-endpoint
precedent at `services/enrollment.rs:121` &mdash; that precedent exists and was never
applied to pubkeys.

### 24. MEDIUM &mdash; `Peer.allowed_ips` is unfiltered at both doors

`state.rs:126` is `allowed_ips: p.allowed_ips.clone()`, no filter, and the field
(`state.rs:66`) carries **no serde attribute**, so the `state.json` half is unguarded too
&mdash; contrast `candidates`, which item 1 gives a `deserialize_with`. `validate_ipv4_cidr`
(`uapi.rs:110-123`) rejects a non-CIDR / non-IPv4 / prefix>32 entry with the same fatal `?`.

Lower than item 23 **only** because the value is not gateway-controlled: it comes from
`db.cidrs_for_segment(gw.segment_id)` (`routes.rs:47`), operator-defined and validated at
insert via the `OverlapError` path. But the `state.json` half of item 1's argument applies
in full &mdash; a corrupted, hand-edited or older-format `state.json` carrying
`allowed_ips: ["garbage"]` is an unbootable gateway, with no controller in the loop to
correct it.

**Open design question, to be answered in writing before either item is built:** if the
invariant is "`PeerState` cannot hold anything `encode_set` would reject", items 23 and 24
are both in scope. If it is the narrower "only the gateway-reported field", then item 23 is
**still** in scope (`wg_pubkey` is gateway-reported) and item 24 is not. Nobody has stated
which.

### 25. LOW &mdash; the controller filter is ingest-only; legacy `gateway_candidate` rows are never revalidated

`usable_local_candidates` runs only in `SyncSvc::report` (`services/sync.rs:1727`), and
`Db::set_local_candidates` is a full REPLACE (`db.rs:3098-3140`) &mdash; so an **actively
reporting** gateway self-heals on its next report. A gateway that is offline, has stopped
reporting, or is de-rostered keeps whatever rows it wrote before the fix shipped, and
`candidates_for` (`db.rs:3048-3080`) still serves them into both `Peer.candidate_endpoints`
(`routes.rs:52`) and `PunchDirective.candidates` (`broker.rs:687-694`). No
migration/backfill exists; `SCHEMA_V3` puts a `CHECK` on `source` but none on `endpoint`.

Non-fatal, because the new gateway-side filter absorbs it &mdash; hygiene, not a live crash
path. **Worth a line in item 1's commit message** so nobody later assumes the store is
clean.

---

### 29. MEDIUM &mdash; `rotationInterval` has no admission-time validation

Descoped from 2a's first commit. The CRD field accepts any string; nothing validates it
until `wiremesh-controller` parses it at boot, so a typo (`"30 days"`, `"0ff"`) is accepted
by the apiserver and surfaces as a controller **CrashLoopBackOff** with the real reason
buried in pod logs. `controllers/controller.rs::reconcile()` has zero validation calls of
any kind today.

The blocker is structural, not conceptual: `wiremesh-operator` depends on neither
`wiremesh-enroll` nor `wiremesh-controller` in production (`wiremesh-testkit` pulls the
latter as a dev-dependency only). The backlog's own 2a section argues `parse_rotation_interval`
should move to `wiremesh-enroll` and be shared &mdash; and explicitly rejects the
`workloads::validate_dial_target` hand-duplicate counter-precedent, because duplicating a
GRAMMAR means the operator accepts what the controller rejects at boot, which is the exact
CrashLoopBackOff this item is about.

Two routes, and the cheap one may be enough: **(a)** a `schemars` pattern/format constraint
on the field so the apiserver rejects garbage at admission with no Rust dependency at all
&mdash; check whether the grammar is regex-expressible before assuming it is not; or **(b)**
relocate `parse_rotation_interval` into `wiremesh-enroll`, add that dependency, and validate
in `reconcile()` before any PVC/Service/Deployment side effect, mirroring
`controllers/gateway.rs`'s existing `validate_dial_target` call site (`Error::Admin`,
fail-closed, before any mutation).

Severity is MEDIUM not HIGH because the failure is loud and recoverable &mdash; `kubectl edit`
fixes it. Contrast the gateway's dial-target precedent, where the same class of mistake burns
a single-use enrollment token.

---

### 28. MINOR (deferred) &mdash; `candidates_for`'s read filter covers shape but not SIZE

`Db::candidates_for`'s read-side filter (PR #59 follow-up) drops malformed entries but does
**not** enforce `MAX_LOCAL_CANDIDATES`. The justification for the read filter &mdash; a row
written by a pre-fix binary sits in the table forever &mdash; applies verbatim to the cap,
which shipped in the same commit (`77ca6f7`). So a row set written while a pre-cap binary
was running is still returned in full: every row passes
`is_usable_candidate_endpoint` individually, and the `Vec::contains` dedup pays its O(n²)
cost against the whole oversized set on every projection build, for every peer. Peers are
NOT exposed to the size (the gateway's `partition_dialable` caps at 64); the controller's
own quadratic work is.

**Do not "fix" this with a `LIMIT` in the SQL.** Two reasons, both checked: a hardcoded
numeric limit in `db.rs` is a second copy of `MAX_LOCAL_CANDIDATES` free to drift from the
real one &mdash; precisely the defect class this branch spent its length eliminating &mdash;
and `LIMIT` over `ORDER BY endpoint` truncates *alphabetically*, not to "the 32 the gateway
most recently reported", so it is a silent behaviour change rather than a bound.

The real fix: relocate `MAX_LOCAL_CANDIDATES` out of `services::sync` to sit beside
`is_usable_candidate_endpoint` (or into a module both can depend on), then enforce it on the
read path. Importing it into `db.rs` as-is would invert the layering the read filter's own
doc comment relies on (`services::sync` depends on `db`, never the reverse). Documented
honestly in `candidates_for`'s doc comment in the meantime.

---

### 27. MINOR (deferred) &mdash; the drop log's sample DELIMITERS are unasserted

`state::partition_dialable` pushes samples as `format!("{:?}", &c[..end])`, which supplies
both the escaping and the surrounding quotes. The G3 tests assert the ESCAPING
(`an_injection_payload_is_escaped_in_the_log_not_emitted_raw`) but nothing asserts the
QUOTES are present. Found during G3's red-green verification (2026-08-10): the
`{:?}`&rarr;`{}` probe removed both properties at once, and only one of them failed a test.

Consequence is cosmetic-to-mildly-misleading, not a vulnerability: a payload containing no
newline but carrying punctuation that mimics this message's own suffix would render
undelimited, so a reader could misjudge where the attacker-controlled span ends. The sharp
case &mdash; newline injection forging a second log record &mdash; IS covered and is
red-verified.

Fix if taken: one assertion that a rendered sample starts and ends with `"`. Deliberately
deferred rather than dismissed &mdash; it did not warrant another implement-and-test cycle
at the end of the item-1 branch.

---

### 26. LOW &mdash; candidate endpoints are parse-checked but never reachability-checked

`validate_ipv4_endpoint` is a pure PARSE check, so `10.0.0.5:0`, `0.0.0.0:51820`,
`127.0.0.1:51820`, `169.254.1.1:51820`, `224.0.0.1:51820` and `255.255.255.255:65535` all
pass. The item-1 filters are defined as "agrees with that function", so a compromised or
version-skewed gateway can report any of them and have the controller store and
re-advertise it to every peer. `127.0.0.1:51820` written into a peer's UAPI points that
peer at itself. Pinned as characterization by
`uapi::tests::validate_ipv4_endpoint_is_parse_only_so_undialable_addresses_are_accepted_today`.

Severity is a rung below item 1: these PARSE, so they do not kill the process &mdash; they
silently poison a direct path. Note the honest producer is already stricter
(`netif::is_usable_ipv4` refuses loopback/link-local/unspecified), as is
`punch::CandidateTrial::new`, so only a misbehaving gateway can emit one.

**Trap &mdash; do NOT implement this by tightening `validate_ipv4_endpoint`.** An automated
review (CodeRabbit, 2026-08-10) proposed precisely that, and it would break the relay data
path FATALLY. `relay::RelayTransport::connect` binds `127.0.0.1:0` (`relay.rs:130`) and the
Cycle-4c endpoint switch points the relayed peer at that `local_addr()`, so a loopback peer
endpoint is the normal production shape of a relayed path. Rejecting it there returns `Err`
from `push_peer_block`, which unwinds through `encode_set`/`apply_state` out of `run()` and
ENDS THE PROCESS &mdash; taking down every gateway that ever fails over to a relay.

The fix, if taken, belongs in the item-1 FILTERS
(`services::sync::usable_local_candidates`, `state::partition_dialable`) where a rejected
entry is dropped harmlessly. That makes the filters strictly stricter than the validator
&mdash; the safe direction &mdash; and `tests/predicate_equality.rs` must then assert
CONTAINMENT (filter ⊆ validator) rather than equality.

---

## Recurring traps

Read these before touching rotation. Each has already caught someone.

### `RETIRE_GRACE` collapsing to ~0 &mdash; four independent routes, all disguised as simplifications

1. **Plain inequality in `evict_decision`** &mdash; `db_pending == None` must mean *keep*.
   Pinned by three unit tests whose failure messages say why.
2. **Removing a tracker on any error** &mdash; a transient DB error is indistinguishable from
   a CAS bail at the call site. Pinned by comments at both `Err` arms.
3. **Adding grace to the step-3 orphan path** &mdash; tempting when a two-row convergence test
   fails. It must stay grace-free; the path is only reachable when no tracker exists.
4. **A write-back trusting its own precondition** &mdash; v0.7.5's own first attempt. The guard
   checked in-memory `promoted_at`, but the promoter commits to SQLite *before* re-taking the
   lock, so the value cannot have changed yet.

**The generalisation:** when a decision's safety rests on a precondition and the lock is
*released* between decision and action, that precondition is stale by construction. Durable
state is the only thing that survives the gap.

### Fixing an error can hide the test that proves your bug

Making a boot-time panic total the obvious way (saturating arithmetic) turns four tests green
**vacuously** &mdash; including the one demonstrating the regression under test. On a young
clock the panic was the *good* outcome. Always ask what a fix does to your coverage, not just
to the crash.

### One red run is not a regression

`direct_rotation_is_zero_drop` fails **~42% under host load**. Run an interleaved A/B against
the parent commit before believing your change broke something &mdash; when this was done, the
control lost 3&ndash;2. Do **not** widen the tolerance. See
`docs/research/flake-direct-rotation-zero-drop.md`.

### Trace the consumer, not the container

"X appears in the roster" says nothing until you find the code that *reads* X. A consequence
was once asserted across four documents on the strength of a data structure's contents; nothing
read them.

### The punch path is safe by type accident, and nothing pins it

`PunchDirective.candidates` never reaches the UAPI &mdash; but not because anything checks
it. `punch::CandidateTrial::new` (`crates/wiremesh-gateway/src/punch.rs:169-180`) parses
each string to `SocketAddr` and drops what does not parse (it is in fact *stricter* than
`is_dialable_endpoint`: it also drops loopback and `0.0.0.0`), and `set_peer_endpoint`
(`main.rs:2219-2225`) takes a typed `SocketAddr`, so whatever reaches the UAPI has been
re-serialized canonically. **Change either signature to `&str` and the hole reopens with no
test failing.** This is why item 1 keeps the controller-side check as well.

### A half-check reads as a check &mdash; `pending_peer_configs`

`reconcile::pending_peer_configs` (`reconcile.rs:76-82`) does `rsplit_once(':')` plus a
`u16` parse on the port. `"abc:123"` survives that and then dies at the fatal validator
&mdash; the check is shaped like protection and provides none (this is item 16). Item 1's
door filter makes it unreachable. **Removing the door filter reopens it**, so do not later
retire the door on the grounds that this site "already parses".

### Cite symbols, not line numbers

Line numbers in this repo's research notes rot constantly &mdash; implementing the fix a note
argues for moves the very lines it cites.
