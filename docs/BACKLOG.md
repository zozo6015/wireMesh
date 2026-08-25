# WireMesh backlog

**As of `v0.9.0` (2026-08-10), plus item 32 filed 2026-08-12.** 25 open items of 32
numbered. Every one has a verified mechanism &mdash; these are not guesses, and where a
claim was checked and turned out wrong, that is recorded too.

Seven are fully resolved and kept below as historical notes &mdash; **1, 2 (all four
sub-items), 16, 22, 24, 25 and 30**. Item **23 is partially resolved** and still counted
open: its fatal, remotely-reachable half shipped, one named controller door did not. A
closed item keeps its mechanism and its lesson, so **do not read a `RESOLVED` heading as
an invitation to delete the item.** Re-audited against the code at `d4a0a55` on
2026-08-11 &mdash; an item that reads as open but is actually done has already put this
project two dispatches away from implementing the same fix twice.

Ordered by what to pick up first. Items marked **READY** had a designed and verified fix
shape and could go straight to test-authoring &mdash; both of them (1 and 2) have since
shipped, so nothing carries that marker right now. **Item 3 is what leads.**

> **Before starting anything here, read [Recurring traps](#recurring-traps) at the
> bottom.** Four of them have already caught someone, and three are in this backlog's
> own subject matter.

---

## Do these first

**Both items in this section have shipped** (item 1 in v0.7.6, item 2's last sub-item in
v0.9.0). What leads next is not here &mdash; it is **item 9**, the rotation wedge, now
the only thing gating an armed rotation timer anywhere. (Item 3, the in-step blocker that
used to lead here, was FIXED in v0.9.1.) Items 1 and 2 stay in place, and stay first,
because every later item's reasoning cites theirs.

### 1. RESOLVED &mdash; Unvalidated `local_endpoints` breaks every gateway's device apply

**Shipped in v0.7.6 (PR #59, commits `77ca6f7` + `8fcde64`), both layers as prescribed.**
Controller ingress: `services::sync::usable_local_candidates` (`sync.rs:108`) filters
`req.local_endpoints` entry-by-entry against the shared
`db::is_usable_candidate_endpoint` predicate (`db.rs:491`) and bounds the set at
`MAX_LOCAL_CANDIDATES = 32` (`sync.rs:70`) &mdash; filtering with a log, not rejecting the
RPC, and called at `sync.rs:1729` **before** `set_local_candidates` persists anything.
Gateway ingress: `PeerState::from_proto` routes `candidates` through `retain_dialable`
(`state.rs:411`), and the `state.json` escape the item singles out as load-bearing is
closed at the field &mdash; `#[serde(default, deserialize_with = "deserialize_dialable_candidates")]`
on `PeerState::candidates` (`state.rs:85`), so `DesiredState::load`'s bare
`serde_json::from_slice` cannot rebuild an unfiltered set. The `PunchDirective` path is
covered by the controller-side check exactly as the item insists; **it is still not
redundant.** Covered by `wiremesh-controller/tests/report_local_endpoints_validation.rs`,
`tests/candidate_cap_gateway_relation.rs`, `wiremesh-gateway/tests/candidate_ingest_validation.rs`,
`tests/uapi_endpoint_validation.rs` and `tests/predicate_equality.rs` (which pins the
two predicates' agreement as a contract).

Deliberately **not** taken, and still undecided: whether `encode_set` should skip a
malformed peer rather than failing the whole device apply. That fail-open/fail-closed call
was flagged below as not-to-be-smuggled-in, and it wasn't.

The sibling validators are items 23 and 24, both since addressed &mdash; see their
headings for what actually shipped and, for 23, what did not. Kept below as a
**historical note**: the crash mechanism it traces (`push_peer_block` &rarr; `encode_set`
&rarr; `apply_state`'s `?` &rarr; process exit, on every peer at once, then an unbootable
gateway) is cited verbatim by items 16, 23, 24, 25, 26 and 28, and it is the reasoning to
reuse the next time a remote-supplied string reaches the UAPI.

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

### 2. RESOLVED &mdash; Operator CRD surface (all four sub-items shipped)

**Complete as of v0.9.0.** 2c in v0.7.6 (PR #59), 2a and 2d in v0.8.0 (PR #61), 2b in
v0.9.0 (PR #65) &mdash; so the "ship these together" advice was **not** followed, and the
cost it predicted was real: three CRD-bearing releases, three mandatory manual
`kubectl apply` re-applies rather than one. Worth remembering, not worth re-litigating.

All three new spec properties are on the CRDs (`crd.rs`):
`WiremeshControllerSpec::rotation_interval` (`crd.rs:75`),
`WiremeshGatewaySpec::metrics_bind` (`crd.rs:194`),
`WiremeshRelaySpec::controller_endpoint` &mdash; each `Option` +
`skip_serializing_if = "Option::is_none"` as prescribed, and both YAML bundles are
regenerated and pinned byte-for-byte by `tests/crd_manifest_freshness.rs`.

Two residuals were filed rather than fixed, and both are still open: **item 29**
(`rotationInterval` has no admission-time validation, descoped from 2a) and **item 31**
(`WiremeshRelay` cannot carry a typed `ScaledDown` condition). Read each sub-item below
for what shipped versus what its analysis prescribed &mdash; **2a's shipped shape is the
inverse of the one this section argues for**, deliberately and for a good reason.

**Ship these together.** Every CRD change costs users a mandatory manual re-apply
(Helm never upgrades CRDs), so splitting them means two re-applies for no reason.

**2a. RESOLVED &mdash; no CRD field for `WIREMESH_ROTATION_INTERVAL`.** Shipped in v0.8.0
(PR #61, commits `b8ae23a`, `0be1aea`, `b96d8ed`), pinned by
`crates/wiremesh-operator/tests/controller_rotation_interval.rs` (8 tests).

> **What shipped is the INVERSE of the emission rule this sub-item argues for, and that
> is deliberate.** The text below says **"Emit only when `Some`"**, on the reasoning that
> emitting the key with a default makes the operator *own* it under `.force()` and would
> silently overwrite a human's `off`. What `workloads.rs:485` actually does is emit it
> **unconditionally**: `env("WIREMESH_ROTATION_INTERVAL", spec.rotation_interval.as_deref().unwrap_or("off"))`.
> The trap the paragraph identifies is real; the fix inverts its own conclusion by
> choosing a *safe* default rather than no default. `off` is the mitigation value, so
> operator ownership now pins rotation OFF instead of re-enabling it, and the **"second
> trap, from the opposite direction"** &mdash; removing the field from the CR re-enabling
> rotation on the 30-day default &mdash; is defused by the same stroke: unset means `off`,
> not `30d`. Read the analysis below for the SSA mechanics, which are unchanged and
> correct; do not read its emission prescription as describing the code.

The original finding: the key appears nowhere in
`wiremesh-operator` or `deploy/`, and `.force()` is on both apply paths
(`controllers::apply`, `controllers::apply_deployment`). **Not an empty list:**
`controller_deployment` emits `env: Some(vec![..])` with **seven** entries
(`WIREMESH_DATA_DIR`, `WIREMESH_TCP_PORT`, `WIREMESH_SYNC_TCP_PORT`,
`WIREMESH_SOCKET_PATH`, `WIREMESH_ADMIN_TCP_PORT`, `WIREMESH_OBSERVE_UDP_PORT`,
`WIREMESH_BIND_IP`) &mdash; the change is a conditional eighth push, not populating a
`vec![]` (the fn's own doc comment says "six" and is stale too).

> **HISTORICAL (pre-v0.8.0), and its conclusion is now INVERTED &mdash; do not act on
> it.** As written, correcting an earlier claim: hand-edits do *not* revert.
> `io.k8s.api.core.v1.Container.env` carries `x-kubernetes-list-type: map` with
> `list-map-keys: [name]` (and the matching `patch-merge-key`/`patch-strategy: merge`), so
> `.force()` asserts ownership **per key**; the operator never named this one, so
> `kubectl set env` survived every reconcile &mdash; unlike `WIREMESH_BIND_IP`, which *was*
> clobbered because the operator names it.
>
> **The SSA mechanics are still exactly right; only the premise died.** v0.8.0 made
> `workloads.rs:488` emit `WIREMESH_ROTATION_INTERVAL` unconditionally, and both apply
> paths force (`controllers/mod.rs:212,225`), so the operator owns that entry like any
> other: **`kubectl set env` on this key IS reverted on the next reconcile.** Set
> `spec.rotationInterval` on the CR instead. (Schema read off a live v1.34 while
> `k8s-openapi` is pinned to `v1_30`; these markers have been stable on `env` since
> ~1.19.)

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

**A second trap, from the opposite direction** &mdash; **defused; see the banner above.**
As written: once set and then *removed* from the CR, SSA **deletes** the env entry and
the controller boots on the 30-day default, so removing a field re-enables rotation.
Neither half survives. The operator emits the key unconditionally, so removing the field
yields `off` rather than deleting the entry &mdash; and the controller has no 30-day
default any more, so even a deleted entry resolves to "no timer".

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

**2b. RESOLVED &mdash; `args` and `replicas` were force-clobbered with no override.**
Shipped in v0.9.0 (PR #65, commit `7d80233`), all four pieces, and the AMENDED note below
is the accurate account of where the condition work landed. `metricsBind` is a typed
`Option<String>` (`crd.rs:194`) consumed at `workloads.rs:714`
(`.unwrap_or("0.0.0.0:9090")`) and validated in the reconciler by a purpose-written
`validate_bind_target` &mdash; **not** `validate_dial_target`, exactly as this sub-item
demands (`controllers/gateway.rs:304-320`, `Error::Admin`). No `extraArgs` was added.
`replicas` is released rather than force-set, via a single `released_replicas()` helper
called by all three workload builders (`workloads.rs:153`, `557`, `798`, `993`) whose doc
comment carries the four-scenario SSA ownership-transfer analysis. Readiness moved to the
shared pure `workload_readiness` (item 30). Tests:
`tests/gateway_metrics_bind_override.rs` (11), `tests/replicas_omitted_scaledown_condition.rs`
(7), and `tests/enroll_init_container_arg_pinning.rs` (6) &mdash; which closes the gap this
sub-item names precisely, pinning `--cidr`, `--token-file` and `--state-dir` plus the
relay's `wiremesh-relay-enroll` args, not just the one gateway `--controller` element the
pre-existing test covered.

The original finding: upstream
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

> **AMENDED 2026-08-10 &mdash; the condition work landed on a different pair of kinds.**
> The `replicas` bullet above says the `ScaledDown` condition goes **on `WiremeshController`
> and `WiremeshRelay` only** and that the gateway needs none. What shipped is typed
> `ScaledDown` conditions on **`WiremeshController` and `WiremeshGateway`**, with
> **`WiremeshRelay` signalling the same state through `status.message`**. Two corrections,
> in opposite directions:
>
> - **The gateway was added to scope.** The reasoning above about gateway *readiness* is
>   correct and unchanged &mdash; `apply_gateway` still never reads the gateway Deployment's
>   status, so its roster-based `Enrolled` computation needed no rework. What it did not
>   anticipate is the consequence its own "Unfiled gap" bullet then spells out: a gateway
>   scaled to 0 keeps reporting `Enrolled: True`, the CR claiming a live data plane that is
>   dead. Fixing that misreport **is** condition work, so the gateway got a `ScaledDown`
>   condition alongside `Enrolled` &mdash; `Enrolled` deliberately unchanged in meaning, so
>   the CR states both true things at once.
> - **The relay could not take a condition at all.** `WiremeshResourceStatus` has no
>   `conditions` field and is shared verbatim with Segment and Policy, so widening it would
>   change three CRDs' schemas to serve one consumer. The relay signals scale-down through
>   `applied=false` plus a distinct `message` instead; the residual (legible to a human, not
>   machine-selectable) is filed as **item 31**.
>
> The shared decision is the pure `controllers::workload_readiness(desired, available)`,
> extracted in the same change &mdash; see **item 30**.

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

**2d. RESOLVED &mdash; relay `--controller` had no CRD override.** Shipped in v0.8.0
(PR #61, commit `b65ef57`), all four pieces and the asymmetry handled as prescribed: the
field plus serde attrs in `crd.rs`, validation in the **reconciler** &mdash;
`controllers/relay.rs:101-105`, a `validate_dial_target` call inside the same
`for (field, value)` loop shape `apply_gateway` uses, returning `Error::Admin` before any
mint/PVC/Deployment side effect, so `relay_deployment`'s own fail-closed check does not
become a second validation site &mdash; the `as_deref().unwrap_or(..)` in the builder, and
`tests/relay_controller_endpoint_override.rs` (5 tests) alongside
`gateway_endpoint_overrides.rs`.

The original finding: derived from the in-cluster ClusterIP.
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

**Automatic rotation is off everywhere, and that is now the DEFAULT rather than an
override.** An absent `WIREMESH_ROTATION_INTERVAL` means no timer at all, so the px
controller's explicit `off` is one instance of the default &mdash; it should stay, but it
is no longer the thing doing the work. Rotation on demand works as the Admin `RotateKey`
RPC, but nothing wraps it &mdash; see item 33. Rotation is now
*repeatable* &mdash; a gateway can rotate more than once (v0.7.2) and no longer falls out
of the timer after one round (v0.7.3) &mdash; and the in-step blocker below is fixed.
**What still gates arming a timer anywhere is item 9, the rotation wedge.**

### 3. RESOLVED &mdash; the in-step case

**Fixed in v0.9.1** (commit `b452597`, "address the peer's reserved own-tun port at the
collapse"). The controller rotates every active gateway in one tick off one timer, so the
fabric rotates **in step**. Its done bar
(`in_step_rotation_of_both_gateways_stands_up_own_and_overlap_tuns` in
`crates/wiremesh-gateway/tests/key_rotation.rs`) was committed `#[ignore]`d as
RED-by-design from 2026-08-05; that work landed and the `#[ignore]` came off. Nothing in
that file is `#[ignore]`d today. This item no longer holds the timer &mdash; item 9 does.

### 4. T7 &mdash; three-gateway rotation harness + per-peer cutover gate

The in-step case is a multi-gateway problem and **there is no harness for it**. That is
why it went unnoticed until a done-bar forced it. Likely a prerequisite for item 3.

### 5. RESOLVED &mdash; `Retire{0}` permanent wedge

**Fixed in PR2 (S3).** `prior_active_epoch` is now `Option<u32>` end to end &mdash;
`rotation::RotationState::prior_active_epoch` and
`services::sync::RotationTracker::prior_active_epoch` &mdash; and the `.unwrap_or(0)`
coercion is gone from **all three** tracker-seed sites: the rebuild-if-absent block in
`services::sync::drive_rotation_for`, step 2 of `services::sync::sweep_rotations`, and the
batched seed loop now living in `services::sync::seed_and_record_epoch_acks` (hoisted out
of `SyncSvc::report` so the third site is reachable from a test at all &mdash;
`peer_identity` needs a `TlsConnectInfo` with no public constructor). `rotation::decide`
rule 1 yields the new `rotation::RotationDecision::Finished` when a promoted tracker has
no prior active epoch, which `drive_rotation_for` maps to `TrackerEffect::Finished` with
**no DB call**, so the tracker clears instead of failing a CAS on every tick forever.

`Finished` is returned **regardless of elapsed time**: `RETIRE_GRACE` buys
make-before-break time for peers still finishing a handshake on the prior key, and with no
prior key there is nothing for a grace to protect.

**Not fixed by removing the tracker on row-absent** &mdash; that was the explicitly
forbidden shape (trap #2 in a new place). The `Retire`/`CasOutcome::NoMatch` arm still
keeps its tracker, `evict_decision`'s `None`-means-keep is untouched, and the unrelated
`.unwrap_or(0)` in `SyncSvc::recorded_session_generation` (a session-generation nonce) was
deliberately left alone.

This was **hardening, not a timer gate**: the entry state is unreachable from any current
mutation path and arises only for a key-row set with no `active` row, which
`Db::rotate_key` deliberately tolerates. Item 9 is the only code gate on the timer.

### 6. Rotation observability (F2/F5) &mdash; deferred review findings

### 7. `kick_overlap` &mdash; the "provably inert" verdict is STALE. DO NOT DELETE IT.

As originally written: inert after v0.7.2's piece 3, so delete it or make the tun
addressable. **Acting on that today would break the in-step done bar.** Commit `b452597`
(v0.9.1) made the Role-B collapse call site at
`crates/wiremesh-gateway/src/main.rs:5505` load-bearing: the collapse unpin forces a
rekey, our handshake init then races the peer's identical rekey, and a dropped init costs
boringtun a ~5s `REKEY_TIMEOUT` &mdash; long enough to blow the done bar's packet-gap
allowance. Kicking each tick until the session comes up is what closes that window. The
other two call sites (`main.rs:5232`, `:5328`) have not been re-examined; if anything is
left of this item it is scoped to those, not to the function.

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

### 16. RESOLVED &mdash; remaining IPv4-validation gap

**Closed by item 1 shipping in v0.7.6 (PR #59), exactly as this item predicted &mdash; no
code of its own.** `reconcile::pending_peer_configs` still does the `rsplit_once(':')`
string surgery (`reconcile.rs:90`), and that is fine: the string it operates on comes from
`p.primary_endpoint()`, i.e. `PeerState::candidates[0]`, which is now filtered at **both**
gateway doors (`retain_dialable` in `from_proto`, `deserialize_dialable_candidates` on the
`state.json` field). The half-check is unreachable rather than removed. **The trap this
creates is already recorded** &mdash; see "A half-check reads as a check" at the bottom:
retiring the door filter on the grounds that this site "already parses" reopens item 16
with no test failing.

Kept as a historical note. The two other originally-filed sites were **closed as safe**
(the observed endpoint is only a log line; the relay dial target is triple-guarded). The
third is `pending_peer_configs`' `rsplit_once(':')` string surgery &mdash; real, but the
least important of its family, and fixed for free by item 1's `PeerState::from_proto` filter.

---

## Platform / design

### 17. `WIREMESH_INIT_CA` &mdash; explicit first-boot CA opt-in

### 18. `ReportRequest` conflates a snapshot and a sparse event

### 19. Relay mux `/1` wire break

Deferred with **6 open owner decisions**. **Its stated correctness justification is
dead:** the 32-bit `registration_key` collision argument (deterministic and permanent,
~17% at 200 gateways) was fixed in v0.6.0 by commit `94e8b98`, which widened the key to
the full 64 bits &mdash; `wiremesh_relay::registration_key` now returns `digest[..8]` raw.
The item may still have other drivers, but that collision is not one of them;
re-establish the driver before scheduling it.

**D2 (ALPN) &mdash; SETTLED in Phase B, owner ruling 2026-08-25. v1.0 speaks
`wiremesh-relay/0` ONLY, on both sides.** The shipped client offers `/0` only; the relay
accepts `/0` only. Rationale, recorded because it is what a future change must re-answer:
**a client that offers a protocol must be able to speak it.** A v1.0 client cannot speak
`/1`, so against a *future* mux relay a dual-offer would negotiate `/1` and then speak
`/0` framing &mdash; the same defect as accepting `/1`, with the roles reversed. And the
accept side was never safe to open: `/1`'s framing is not a defined wire while owner
decisions **F** (channel semantics) and **G** (the relay&rarr;gateway return header,
recorded *"OPEN &mdash; load-bearing"*) remain open in
`docs/research/relay-mux-design-verification.md`.

What shipped (`wiremesh_relay::{ALPN_V0, ALPN_SUPPORTED}`):

* **One constant set.** The four hand-copied `b"wiremesh-relay/0"` literals &mdash;
  `server_config`, `server_config_with_denylist`, `build_client_endpoint`, and
  `tests/dest_pinning.rs::raw_client_endpoint` &mdash; now consume one exported list.
  `ALPN_SUPPORTED` has exactly one member in v1.0 but **stays a list**, so adding `/1`
  later is a one-line change at one site. (`relay-mux-design-verification.md` says the
  ALPN literal lives in "three places"; it was **four** &mdash; the test replica counts.)
* **Negotiated-ALPN readback** via `quinn::Connection::handshake_data()` on both sides
  (`Client::negotiated_alpn`, and the relay's per-session read), previously called
  nowhere in the repo.
* **Decision H's deprecation anchor:** a per-ALPN cumulative session counter on the
  relay, surfaced in the registration log line as `alpn="…" alpn_sessions=N`. A counter
  and a log line, **not** a metrics endpoint &mdash; the relay has no metrics surface at
  all, and building one is item S4. It counts *accepted registrations*, so a rejected
  connection never reaches it, and re-registrations do count. Recorded limitation: a
  per-relay count is necessary but **not fleet-complete**, because `relay_next_idx`
  round-robins, so a pair that only ever uses R1 is invisible to R2.
* **Connect-failure distinguishability.** `wiremesh_relay::RelayConnectFailure`
  (`AlpnMismatch` / `PeerRejectedCredentials(alert)` / `Unreachable` / `Other`) is
  classified at **every** fallible step of `Client::finish_connect` on the raw error,
  before `.context()` erases the type &mdash; because the rejection does **not** reliably
  surface at the handshake step: `tests/bridge.rs`'s header records that a certless
  client's `endpoint.connect(...).await` returns **Ok**, with the failure manifesting at
  the registration-ack read. Paired with `relay_connect_backoff::RelayConnectBackoff`,
  which replaced `ensure_relay_transport`'s bare `eprintln!`-and-return: an unusable
  relay used to be retried every tick forever, indistinguishably. Permanent causes back
  off from the first failure, transient ones after three.

**Two follow-ups from PR5's review, both narrow:**

* `ensure_relay_transport`'s unparseable-endpoint arm records `Err(Other)` &mdash;
  **review-verified (PR5 CodeRabbit), not test-pinned**; pin it when a controller-side
  `RelayInfo` fixture exists that can feed a malformed `endpoint` through a real Sync
  stream.
* A `RelaysChanged` delta that alters relay R's endpoint should **clear the `(gid, R)`
  back-off entry** &mdash; the accumulated failure history is about a string that no
  longer exists, and the key `(gid, relay_id)` survives the correction. Needs a decision
  on which `RelayInfo` fields count as "changed" for this purpose.

The `/1` mux wire itself remains deferred on decisions F and G. **Follow-up filed:** the
relay's application-level registration rejections (identity mismatch, id in use, id
collision) close the connection *after* a successful TLS handshake, so they classify as
`Other` rather than a named variant &mdash; a `RelayRejected { code, reason }` variant
would name them, at the cost of widening the enum past D2's four-cause bar.

### 20. LAN-side route propagation

Fabric CIDRs are unreachable from non-gateway hosts. Assume the operator may not control
the LAN router.

### 21. No HA for a segment gateway

Single node = single point of failure. The gateway's identity is on a node-local RWO PVC,
so cross-node failover is explicitly out of scope as built. On a cluster with a node
autoscaler this is *worse* than a single box: the node can be reclaimed and the pod cannot
reschedule.

### 22. RESOLVED &mdash; Two source comments claimed a `kind` e2e harness proves the reconcile loops

**Confirmed exactly two, both corrected (doc comments only, no code/behaviour change):**
`crates/wiremesh-operator/src/controllers/mod.rs` (the module's "Validation status"
paragraph) and `crates/wiremesh-operator/tests/finalizer_best_effort.rs` (its "Wiring"
section). A full sweep of `crates/wiremesh-operator/src/` and `crates/wiremesh-operator/tests/`
for every plausible wording (`e2e`, `kind`, `Task 9`, `cluster-tested`, `proven by`, `covered
by`, `integration harness`) plus a repo-wide search for any `kind`/e2e CI config or script
turned up nothing else claiming automated cluster coverage. Two other hits looked similar but
are accurate and were left alone: `workloads.rs`/`controllers/gateway.rs`'s `zolab e2e` bug
comments record real bugs found during *manual* testing (true history, not a false claim about
automation), and `tests/reconcile_guards.rs` correctly says its property "cannot be proven by a
unit test" and calls it REVIEW-VERIFIED instead of claiming an e2e proves it.

Both comments now state plainly: the pure helpers/builders **are** unit-tested in-container;
the reconcile loops (apiserver I/O, finalizers, requeue) are **not** covered by any automated
test anywhere in this repo — they compile, and their only validation to date has been MANUAL,
against real clusters. The `kind` e2e harness remains pointed at as intended-but-unbuilt (plan
Task 9) rather than deleted, so the gap stays visible instead of reverting to silence. This was
a false assurance sitting exactly where someone looks before deciding how much to test a
change &mdash; same class as the `--help` text corrected in v0.7.4.

Building the harness itself remains open and unfiled as future work &mdash; the operator crate
has no aya/boringtun/netns dependency, so unlike the rest of the workspace it *could* run kind
on a plain runner.

---

### 32. LOW &mdash; the operator Helm chart is never stamped, because nothing publishes it

Filed 2026-08-12 on the version-stamping branch, where the fix was **written and then
deliberately removed**. `deploy/helm/wiremesh-operator/Chart.yaml` is committed at
`version: 0.1.0` / `appVersion: "0.1.0"` &mdash; unchanged across every tagged release to
date &mdash; and no script or workflow rewrites either key.

Stamping it in `scripts/set-version.sh` alongside the crate manifests was implemented,
reviewed, and cut. It is **inert**: nothing packages or publishes the chart. All three
workflow files were checked &mdash; there is no `helm package`, no chart repo, no index;
`release.yml` attaches tarballs, `.deb`/`.rpm`, `.msi` and `.pkg` and nothing else. A
CI-side stamp therefore lives and dies inside the job, and anyone installing from a git
checkout still gets `0.1.0`. It was not free, either: the block hard-failed if the chart
moved or its keys were renamed, and because `set-version.sh` runs in every build job of
BOTH workflows, that failure would have taken down jobs with no interest in the chart at
all &mdash; including `release.yml`'s Windows job, which builds only `fabricctl`.

The crate half &mdash; the actual defect, five crates including the previously-missing
`wiremesh-operator`, plus `container-images.yml` finally calling the script &mdash; shipped
on that branch and is pinned by `crates/wiremesh-operator/tests/release_version_stamping.rs`
(5 tests). That file's doc comment points here and says not to re-add a chart assertion
without the publishing half.

Fixing this properly means deciding a **distribution channel first**: an attached
`helm package` tarball per release (cheap, no hosting, but `helm repo add` does not work),
or a real chart repo with an `index.yaml` (gh-pages or OCI on ghcr.io &mdash; the registry
is already in use). Stamping is a two-line follow-on once that is chosen; choosing is the
work.

**Settle this at the same time**, because publishing a chart makes it user-visible: the
chart defaults `image.tag: "latest"` (`values.yaml:12`), while `container-images.yml`
pushes `latest` on every push to `main`
(`type=raw,value=latest,enable={{is_default_branch}}`, plus `pullPolicy: Always`). So a
default `helm install` today tracks **main**, not a release. `values.yaml` recommends
pinning in a comment, but the default is what most people run. The obvious pairing is to
default `image.tag` to `""` and have `_helpers.tpl` fall back to `.Chart.AppVersion` &mdash;
which only becomes correct once the chart is stamped AND published, which is why the two
halves belong in one piece of work. Note this also makes the stamp load-bearing: today
`_helpers.tpl` never reads `.Chart.AppVersion`, so a stale `appVersion` is metadata rot
(what `helm list` reports); after such a change it would decide which image runs.

### 33. `fabricctl` does not expose `RotateKey`, so on-demand rotation has no operator interface

Filed 2026-08-13, on the branch that corrected the docs claiming otherwise. `docs/install.md`,
`deploy/packages/env/controller.env`, `README.md` and this file all told operators that manual
rotation via `fabricctl` "works and is the supported path". **There is no such command.**
`grep -rni rotate crates/fabricctl/` returns zero hits, and the complete subcommand set
(`crates/fabricctl/src/main.rs`, `enum Command`) is Segment, Gateway, Relay, Token, Audit,
Apply, Policy, EnrollToken.

The RPC itself is real and works &mdash; `proto/wiremesh/v1/admin.proto` (`rpc RotateKey`),
handler `AdminSvc::rotate_key` in `crates/wiremesh-controller/src/services/admin.rs` &mdash; but
it has **no production caller anywhere**. Its only callers in the tree are in
`crates/wiremesh-gateway/tests/key_rotation.rs`. So the sole way to rotate a key on demand is
to hand-roll a gRPC call, which also means obtaining `gateway_id` (`RotateKeyRequest` takes the
numeric id, not a name) out of band.

**Why this is more than a missing convenience.** v0.9.2 made automatic rotation off-by-default
everywhere, and justified that partly by pointing at manual rotation as the safe alternative.
An operator who believes a key is compromised reaches for `fabricctl` and finds nothing &mdash;
at exactly the moment improvisation is most expensive. A mitigation that requires writing a
gRPC client is not an operator-usable mitigation. This also compounds item 9: the wedge is what
gates arming the timer, and this is what makes the recommended substitute impractical.

The transport half is already solved and needs no new work: `fabricctl` dials the Admin service
over either `--socket <path>` (UDS, implicit admin) or `--token <bearer> --addr <host:port>`
(bearer-gated TCP), and every existing subcommand rides that. Adding `fabricctl key rotate` is
a subcommand plus an `AdminAuthClient::rotate_key` call &mdash; small, and worth doing before
anyone is asked to rely on the path. Resolving a gateway **name** to its id (the ergonomics
`gateway list` already implies) is the only real design question. Note both routes are
host-local: the Admin TCP listener binds `127.0.0.1` unconditionally and deliberately ignores
`Config::bind_ip` (`crates/wiremesh-controller/src/lib.rs`, the Admin TCP listener bind), since
a bearer token on plaintext gRPC would be interceptable on a routable interface. A CLI does not
change that, and should not.

The specs have said `fabricctl key rotate` since the design was ratified
(`docs/superpowers/specs/2026-07-21-key-rotation-design.md`,
`2026-07-15-wiremesh-engineering-design.md` OQ3/D5) &mdash; the CLI was designed and simply
never built, and the docs then described the design as if it had shipped.

---

## Ingress validation &mdash; item 1's siblings

Filed 2026-08-10 from an independent audit of `push_peer_block`, and **out of scope for
item 1's branch** by owner decision. Numbered here to keep the file's numbers ascending.

> **Status as of v0.8.0 (PR #62, commit `f4a9c87`): item 24 is RESOLVED and item 23 is
> PARTIALLY resolved.** All three fatal validators are now unreachable from the gateway
> side, so the fabric-wide crash-and-cannot-boot mechanism this section describes is
> closed. **Item 23 is no longer HIGH and no longer "remotely reachable today"** &mdash;
> item 1's closing paragraph still says it is, and that sentence is stale (left in place
> because item 1 is preserved as a historical note). One named controller door remains
> unvalidated; see item 23 for exactly which and why.

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

### 23. LOW (residual) &mdash; `Peer.keys[].pubkey` is item 1's bug on a sibling field

> **PARTIALLY RESOLVED in v0.8.0 (PR #62, commit `f4a9c87`). Downgraded HIGH &rarr; LOW.
> Do not implement this from scratch &mdash; read what shipped first.**
>
> **Shipped &mdash; the fatal half.** Gateway side, both doors, mirroring item 1:
> `PeerState::from_proto` filters `active_pubkey_b64` through `uapi::pubkey_b64_to_hex`
> (`state.rs:388-393`), and `#[serde(default, deserialize_with = "deserialize_valid_active_pubkey")]`
> (`state.rs:42`) covers the `state.json` path. An undecodable ACTIVE key drops the whole
> peer &mdash; a deliberately different shape from item 24's per-entry filtering, because
> `PeerConfig.public_key_b64` is a `String`, not an `Option`, so there is no keyless WG
> block to emit. Controller side, the `Enroll` door: `services/enrollment.rs:266-272`
> rejects a non-empty `wg_pubkey` that is not base64-of-32-bytes with
> `Status::invalid_argument`, **before any DB write**, so a rejected attempt does not
> consume the single-use token. Empty stays legal &mdash; it is the cycle-2 placeholder
> branch. Tests: `wiremesh-gateway/tests/peer_key_and_allowedips_validation.rs` (13) and
> `wiremesh-controller/tests/enroll_wg_pubkey_validation.rs` (2).
>
> **Not shipped &mdash; the `SubmitEpochKey` door.** `services/sync.rs:2003` still calls
> `self.db.set_epoch_pubkey(gw.id, epoch, req.pubkey)` with no decode and no length check;
> `check_session_generation` remains the only gate before it, and `set_epoch_pubkey` is a
> CAS over the sentinel, not a validator. Deferred on purpose: roughly eight already-green
> rotation tests across `epoch_key_submit.rs`, `rotation.rs`, `rotation_disabled.rs` and
> others submit placeholder pubkeys (`"REALKEY=="`, `"NO-WATCH-KEY=="`) and assert success,
> so validating this path turns them red, and rotation is this project's most delicate
> subsystem. **That fixture rot is itself a finding**: those literals encode keys that
> could never work in production.
>
> **Why LOW, not HIGH.** The gateway-side filter closes the crash-loop regardless of which
> controller path admitted the key, so what remains costs defence-in-depth, not the fix.
> The controller is still the only choke point between "what a gateway claims" and "what
> every peer is told", which is why the residual is worth closing &mdash; alongside the
> fixture cleanup, not before it.
>
> **A mechanism correction, load-bearing for whoever finishes this.** The fix shape below
> says to filter at "the same door item 1 opened". That is right for `active_pubkey_b64`
> and **wrong for `keys[]`**, which is filtered at the `pending_peer_configs` BUILDER
> instead (`reconcile.rs:76-89`). `rotation::decide_role_b` must distinguish
> `RoleBDecision::Unusable { pending_epoch }` (pending key present, undecodable) from
> `Skip` (no pending key at all), and it reads the `keys` vec to do it &mdash; dropping a
> bad-keyed entry at ingest collapses those two into `Skip` and silently changes rotation
> behaviour. Rationale and a hypothesis that was checked and found WRONG are recorded in
> `docs/research/gateway-key-filter-placement.md`.

The original finding, kept as the historical record. `key_b64_to_hex` (`uapi.rs:47-54`)
errors on non-base64, or
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

### 24. RESOLVED &mdash; `Peer.allowed_ips` was unfiltered at both doors

**Shipped in v0.8.0 (PR #62, commit `f4a9c87`), both doors.** `PeerState::from_proto` now
routes `allowed_ips` through `retain_valid_cidrs` (`state.rs:418`), and the unguarded
`state.json` half this item calls out &mdash; the field carried **no serde attribute at
all** &mdash; is closed by `#[serde(deserialize_with = "deserialize_valid_cidrs")]`
(`state.rs:102`). Filtering is per-ENTRY and never drops the peer, which survives with
whatever CIDRs remain: `allowed_ips` is a list like `candidates`, not a required scalar
like `active_pubkey_b64`. Covered by
`crates/wiremesh-gateway/tests/peer_key_and_allowedips_validation.rs` (13 tests, shared
with item 23's gateway half).

**The open design question below is answered, by what shipped.** The invariant taken is
the broad one &mdash; "`PeerState` cannot hold anything `encode_set` would reject" &mdash;
so item 24 was in scope alongside item 23 rather than being ruled out as
not-gateway-reported. Kept as a historical note.

The original finding: `state.rs:126` was `allowed_ips: p.allowed_ips.clone()`, no filter,
and the field
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

### 25. RESOLVED &mdash; the controller filter was ingest-only; legacy `gateway_candidate` rows were never revalidated

**Shipped in v0.7.6 (PR #59, commit `8fcde64`) &mdash; the same branch's follow-up, as a
read-side filter rather than a migration.** `Db::candidates_for` now passes **both** the
observed slot and every local row through `is_usable_candidate_endpoint` before returning,
dropping bad ENTRIES and never erroring the call, so a row written by a pre-fix binary is
never served into `Peer.candidate_endpoints` (`routes.rs`) or `PunchDirective.candidates`
(`broker.rs`) no matter how long it sits in the table. That is why no backfill was needed
&mdash; the rows may persist, but nothing reads them out. Pinned by
`crates/wiremesh-controller/tests/candidates.rs`, which added
`a_persisted_pre_filter_local_row_with_a_non_ipv4_endpoint_is_not_returned`,
`valid_sibling_local_rows_survive_when_a_bad_row_is_also_present` and
`a_gateway_whose_local_rows_are_all_invalid_yields_an_empty_list_not_an_error`.

**One half was deliberately left, and it is filed separately: the read filter covers SHAPE
but not SIZE.** A pre-cap row set is still returned in full, paying the `Vec::contains`
dedup's O(n²) cost on every projection build. That is **item 28**, which also records why
a SQL `LIMIT` is the wrong fix. Kept as a historical note.

The original finding: `usable_local_candidates` runs only in `SyncSvc::report`
(`services/sync.rs:1727`), and
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

### 31. LOW &mdash; `WiremeshRelay`/`Segment`/`Policy` status carries no `conditions`

Found while implementing 2b piece 4 (2026-08-10). `WiremeshResourceStatus` (`crd.rs:26-33`) has
only `applied`, `applied_version` and `message`, and it is **shared by three kinds** &mdash;
Relay, Segment and Policy. Only `WiremeshControllerStatus` (`crd.rs:88`) and
`WiremeshGatewayStatus` (`crd.rs:207`) carry `conditions: Vec<Condition>`.

Consequence, concretely: 2b's `ScaledDown` signal lands as a typed condition on the controller
and the gateway, but on the relay it can only be an `applied=false` plus a distinct `message`
string. That is legible to a human running `kubectl describe` and it does fix the real defect
(scaled-down stops being indistinguishable from starting), but it is **not machine-readable**
&mdash; nothing can select on it, and no standard tooling understands it the way it understands
a condition.

Deliberately NOT fixed in 2b: adding `conditions` to the shared type changes the status schema of
THREE CRDs to serve one consumer, and leaves Segment and Policy carrying a field they never
populate. Two shapes if taken: widen the shared type anyway (simple, but the schema change hits
all three), or give `WiremeshRelay` its own status type (precise, more code). Either is another
mandatory CRD re-apply, so it should ride along with the next CRD-surface change rather than
alone.

---

### 30. RESOLVED &mdash; readiness truth tables are inline in async reconcilers, so untestable

**Filed and fixed the same day (2026-08-10), on 2b's own branch.** The extraction this item
proposes is exactly what shipped: `controllers::workload_readiness(desired, available)` is now a
pure `pub fn` returning `Available` / `ScaledDown` / `Starting`, with
`controllers::deployment_readiness` as the thin live-Deployment wrapper, and all three reconcilers
(`controller`, `relay`, `apply_gateway`) call it instead of computing readiness inline. The truth
table is pinned by `crates/wiremesh-operator/tests/workload_readiness_truth_table.rs` (7 tests),
including the two cases the item singles out &mdash; explicit `Some(0)` is the *only* scale-down
(an omitted `spec.replicas` means "up"), and `Some(0)` is checked BEFORE the available count so a
mid-scale-down pod still counted available cannot flip the report to `Available` for a pass.

Kept below as a **historical note**, because both halves generalise: the diagnosis (a truth table
living inline in an async reconciler, in a crate with no fake apiserver, is a code-review invariant
with no test behind it) and the remedy (extract the decision as a pure function &mdash; the shape
`gateway.rs` already uses for `should_mint_token`, `identity_persisted`, `needs_rebind` and
`adoption_needs_stale_drain`). Reach for it the next time a reconcile grows a decision worth
pinning.

`controllers::controller::reconcile` and `controllers::relay::reconcile` compute readiness inline
from `available_replicas`, and `apply_gateway` builds its `Enrolled` condition inline. None is a
pure function, and this crate has no fake apiserver &mdash; so 2b's `ScaledDown` truth table
(desired `Some(0)` vs absent/`Some(n>0)`, crossed with available) shipped as a **code-review
invariant with no automated test**.

The fix shape is already precedented in the same file: `controllers/gateway.rs` extracts
`should_mint_token`, `identity_persisted`, `needs_rebind` and `adoption_needs_stale_drain` as free
`pub fn`s precisely so they can be unit-tested. Extracting a `workload_readiness(desired, available)`
would make the whole table mechanically pinnable the same way, with no behaviour change.

Worth doing before anything else touches readiness &mdash; the untested half is exactly where a
future edit would silently regress a deliberately-scaled-down workload back into a 10s hot requeue
loop.

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
