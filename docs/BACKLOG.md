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
malformed endpoint on one peer fails the entire device encode**, and `apply_state(..)?`
propagates the error out of the Sync loop. Gateway A (observe UDP blocked &mdash;
exactly the NAT case the fabric exists for) reports a malformed local endpoint, it
becomes A's `candidates[0]`, and **every other gateway's whole `wg0` apply fails**.
Fail-static keeps existing tunnels up, but the fabric stops converging.

The tell: the controller *does* validate relay endpoints as `SocketAddrV4` at both
registration paths, and gets the observed endpoint's IPv4-ness free from the socket
type. The one source that is genuinely remote-supplied and free-form is the unchecked
one.

**Fix, two layers.** Validate at controller ingress in `SyncSvc::report` &mdash; filter
with a log rather than a hard reject, so a partially-garbage report does not cost the
gateway its whole candidate set &mdash; plus an element-count bound. Then filter
`PeerState::candidates` on ingest in `PeerState::from_proto`: that single gateway-side
site covers `peer_configs`, `device_config_pinned` and `pending_peer_configs` at once,
and makes item 14 unreachable by construction. **Do not add per-builder checks.**

Separately worth deciding, but **not** to be smuggled in with a validation fix: whether
`encode_set` should skip a malformed peer rather than failing the whole device apply.
That is a fail-open/fail-closed call and deserves its own decision.

Tests: all pure, no netns. Nothing covers this today.

### 2. READY &mdash; Operator CRD surface (four items, one minor release)

**Ship these together.** Every CRD change costs users a mandatory manual re-apply
(Helm never upgrades CRDs), so splitting them means two re-applies for no reason.

**2a. No CRD field for `WIREMESH_ROTATION_INTERVAL`.** `controller_deployment` hardcodes
the controller's env as a literal `vec![]`.

> **Not true, and do not "fix" it:** hand-edits do *not* revert. A container's `env` is
> a server-side-apply list-map keyed by `name`, so `.force()` only overrides keys the
> applier names. The operator never names this one, so `kubectl set env` survives every
> reconcile. (This is per-key &mdash; `WIREMESH_BIND_IP` *is* clobbered, because the
> operator names it.)

**The trap:** emitting the key **with a default** makes the operator *own* it, and then
`.force()` really would overwrite a human's `off` &mdash; silently re-enabling rotation
on exactly the clusters that had mitigated it. **Emit only when `Some`**, matching the
`scheduler_aware_node_selector` omit-when-unset precedent.

**A second trap, from the opposite direction:** once set and then *removed* from the CR,
SSA **deletes** the env entry and the controller boots on the 30-day default. Removing a
field re-enables rotation. Inherent to SSA; document it loudly on the field.

Validation: a CRD `pattern` **cannot** express the grammar (it cannot reject `0s`, or
`>3650d`, or a `u64` overflow, and must *accept* whitespace-trimmed forms). Lift
`parse_rotation_interval` into a leaf crate depending only on `anyhow` and re-export it
&mdash; in-repo precedent is `wiremesh-enroll` holding the shared resolver and keepalive
constants. Do **not** depend on `wiremesh-controller` (no `[features]`, pulls SQLite,
rcgen, x509-parser).

**2b. `args` and `replicas` are force-clobbered with no override.** `args` is
`x-kubernetes-list-type: atomic`, so hand-added flags are wiped; the gateway's
`--metrics 0.0.0.0:9090` is unchangeable. `replicas: Some(1)` is force-set on all three
workloads, so `kubectl scale --replicas=0` reverts *immediately* &mdash; **no supported
way to take a gateway down for maintenance** short of deleting the CR and firing the
drain finalizer.

- Add one typed `metricsBind` field. **Do NOT add `extraArgs`** &mdash; the gateway's arg
  parser is last-wins, so an appended list could silently override `--state-dir`,
  destroying PVC identity and forcing a re-enroll against a *spent single-use token*.
- **Do NOT reuse `validate_dial_target`** for a bind address: it accepts DNS names (which
  the gateway rejects at boot) and rejects port `0` (legitimate for a bind addr, and the
  binary's own default).
- The two **enroll init-container** arg lists must stay non-overridable &mdash; they are
  bound to CIDRs the enrollment token is cryptographically committed to, and a test
  already pins this.
- For `replicas`: **omit unconditionally, no CRD field.** A field would still be
  force-applied (moving the knob, not fixing it), and it advertises capability that does
  not exist (hostNetwork, fixed WG port, RWO PVC, `Recreate` chosen so a second pod never
  surges). **But omitting breaks three readiness computations** &mdash; a permanently-False
  `Ready` with a misleading reason plus a 10s/15s requeue loop &mdash; so a `ScaledDown`
  condition must ship in the same change. One-time upgrade effect: SSA releases the field
  and the defaulter re-sets 1, so any currently-scaled-to-0 Deployment comes back up once.

**2c. Helm CRD bundle has drifted.** Three hunks, not the two originally filed:
`observeEndpoint`, `syncEndpoint`, and **relay `storageClass`/`storageSize`** (unfiled).
Root cause is structural &mdash; `crdgen` prints to stdout only, there is no build
integration, and the Helm copy is hand-mirrored and missed the commit that added all
three. The broken path is a **first-time `helm install`** (unknown fields are *pruned*,
not rejected; documented upgraders apply the fresh copy). Concrete casualty: the
`observeEndpoint`/`syncEndpoint` patch in `docs/runbooks/controller-migration-to-fi.md`
**cannot work on a Helm-installed cluster**.

Fix: regenerate, then add a Rust freshness test asserting byte equality against **both**
files &mdash; runs in ordinary `cargo test`, no cluster, no CI change. Keep two physical
files (a chart must be self-contained). Patching the YAML alone guarantees a fourth drift.

**2d. Relay `--controller` has no CRD override.** Derived from the in-cluster ClusterIP.
Since the control plane moved to the px host, an in-cluster relay cannot be pointed at it
&mdash; the identical failure that gave the gateway `syncEndpoint`. Same shape:
`controllerEndpoint: Option<String>`, omit-when-unset, `validate_dial_target` (correct
here &mdash; this *is* a dial target), fail-closed before the deployment apply.

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

### Cite symbols, not line numbers

Line numbers in this repo's research notes rot constantly &mdash; implementing the fix a note
argues for moves the very lines it cites.
