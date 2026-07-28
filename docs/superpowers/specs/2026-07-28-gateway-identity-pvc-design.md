# PVC-backed gateway identity + idempotent enroll — design

**Status:** approved 2026-07-28. **Branch:** `feat/gateway-identity-pvc`.
**Motivation:** the operator-deployed gateway keeps its identity
(`identity.json`, `wg_private.key`, `epoch_keys.json`, `state.json`) in an
**emptyDir**, so ANY pod recreation — image upgrade, reschedule, node reboot —
destroys it. The enroll init-container then re-runs `wiremesh-gateway enroll`
against a spent single-use token and crash-loops, forcing the manual
drain → delete-token-Secret → re-mint → new-id dance (hit ≥3× in production).
This is an availability bug, not just an upgrade annoyance: a node outage
currently forces a gateway re-enrollment.

## Fix — two independent changes

### 1. Persist the identity on a small per-gateway PVC (operator)

- New `gateway_pvc(name, spec) -> PersistentVolumeClaim`, mirroring the existing
  `controller_pvc` (`crates/wiremesh-operator/src/workloads.rs`): RWO, small
  default (**128Mi** — the state is KB; huge margin), `storageClassName` and
  size overridable from the `WiremeshGateway` CR (add optional
  `storageClass` / `storageSize` fields to the CRD + spec type, matching
  `WiremeshController`'s existing fields + `crdgen`).
- The gateway Deployment's `state` volume changes from `EmptyDirVolumeSource`
  to a `PersistentVolumeClaimVolumeSource` referencing `<name>-gateway-data`
  (kind-specific name, so it never collides with the controller PVC's
  `<name>-data`).
- The gateway RECONCILER creates/owns the PVC (owner-ref, so it's GC'd with the
  CR — same pattern as the controller reconciler owning `controller_pvc`).
  Verify the operator RBAC already covers PVC create (the controller path does).
- Node-pinning note: the gateway is node-pinned, but the operator MUST NOT set
  `spec.nodeName` directly once the pod mounts a PVC. Default storage classes
  (k3s `local-path`, most NFS/CSI) are `WaitForFirstConsumer`, which binds a PVC
  only after the SCHEDULER places the consuming pod; a direct `nodeName` bypasses
  the scheduler, so the WFC PVC never binds and the pod hangs `Pending` forever
  (observed live: `gw-home` on `zolab-worker1`). Instead the operator folds the
  CR's `nodeName` into a `kubernetes.io/hostname` nodeSelector (an explicit CR
  `nodeSelector` is preserved; an explicit hostname key wins) — same node pin,
  but the scheduler places the pod so the WFC PVC binds. True cross-node failover
  is explicitly OUT OF SCOPE (a node-local RWO PVC still binds on one node; real
  failover needs networked storage + routing follow — a separate, larger effort).

### 2. Idempotent enroll (gateway binary)

- `wiremesh-gateway enroll` (`crates/wiremesh-gateway/src/enroll.rs`): BEFORE
  redeeming the token, check `--state-dir` for a parseable, structurally complete
  existing identity (the same `Identity::load` the runtime uses at boot — a
  structural JSON load, NOT cryptographic cert/key validation). If it loads
  successfully, **skip enrollment**: log `wiremesh-gateway: already enrolled
  (identity present in <state-dir>), skipping` and exit 0. A missing or malformed
  identity falls through to enrollment as today; a read that fails with any other
  IO error (EACCES/EIO) must PROPAGATE (do not treat it as absent and redeem the
  token).
- This makes the init-container safe to run on EVERY boot: first boot enrolls
  into the fresh PVC; every later boot finds the persisted identity and skips.
- Idempotency belongs IN the enroll command (not a shell guard in the
  init-container) so it is robust for the k8s init-container, systemd, and
  manual invocation alike — no `/bin/sh -c`, consistent with the existing
  no-shell init-container design.
- Edge case (documented, not handled specially): if an operator changes the
  gateway's bound segment/CIDRs, the persisted identity is now stale; forcing a
  fresh enroll requires clearing the PVC (or a future rebind flow). Out of
  scope here — the common path (same gateway, same segment) is what this fixes.

## One-time adoption cost

The FIRST rollout to the PVC version starts with an empty PVC (the current
identity is in the ephemeral emptyDir and cannot be migrated), so gw-home
re-enrolls ONCE (new id). After that, its identity is durable and no pod
recreation ever re-enrolls again. Call this out in the PR/release notes.

**Adoption is automatic as of v0.2.2 (hands-off, no manual step).** The v0.2.1
e2e on zolab found the transition was NOT actually hands-off — the old gateway
id (enrolled from the now-gone emptyDir) stays `active` in the roster, so the
new pod's plain-token enroll is rejected until the old id is drained. v0.2.2
makes the operator DETECT adoption and DRAIN the stale gateway id itself, which
frees the segment so the plain-token enroll is no longer rejected (the fresh
token is minted independently because the freshly created PVC makes
`identity_persisted` false → `should_mint_token` true); the new pod then enrolls
into the freed segment automatically.

The drain is guarded by the COMPLETE condition — it occurs ONLY when BOTH hold:
(1) the gateway PVC is freshly created this reconcile (`existing_pvc.is_none()`)
AND (2) this CR is the SOLE `WiremeshGateway` for the segment. Guard (2) is
required because the controller roster matches a gateway to its segment by NAME
only, so if a second `WiremeshGateway` targets the same segment the "active"
roster id could be that peer's LIVE gateway — draining it would be an outage;
the operator counts the `WiremeshGateway` CRs referencing the segment and drains
only when the count is 1. The CR-list query is issued only on the fresh-PVC path
(skipped in steady state), and it FAILS SAFE: if the list query errors, the
operator treats this CR as NOT the sole gateway and does NOT drain (a missed
drain is a manual cleanup; a wrong drain kills a live peer). In steady state
(PVC already present, own id legitimately active) the operator never drains a
healthy gateway. See `docs/research/ops-finding-pvc-adoption-migration.md`
(`adoption_needs_stale_drain`, and the companion `Recreate`-strategy
`rollingUpdate` fix).

## Scope

- **Changed:** `workloads.rs` (gateway volume emptyDir→PVC + `gateway_pvc`),
  the gateway reconciler (own the PVC), the `WiremeshGateway` CRD + spec
  (`storageClass`/`storageSize`) + `crdgen` regen, `enroll.rs` (idempotent
  skip). Helm/kustomize CRD manifests regenerated.
- **Unchanged:** the enrollment protocol, token minting, the drain-on-CR-delete
  finalizer (still drains the id; the owned PVC is GC'd with the CR), the
  gateway run/data path.
- **Out of scope:** cross-node failover / networked storage; the bound-segment
  change/rebind flow; the bare-metal (systemd) gateway already persists to
  `/var/lib/wiremesh` on disk, but it ALSO benefits from idempotent enroll
  (a restart no longer needs a fresh token) — that's a free win, keep it.

## Done-bar / tests

- **operator unit tests**: `gateway_pvc` shape (RWO, size, name); the gateway
  Deployment mounts the PVC (not emptyDir); the reconciler emits/owns the PVC;
  CRD carries `storageClass`/`storageSize` with the 128Mi default.
- **enroll idempotency test**: `wiremesh-gateway enroll` with a pre-existing
  valid identity in `--state-dir` skips (exit 0, no controller call, identity
  untouched); with no identity it enrolls as before (existing enroll_cmd
  coverage stays green). A stub/injected controller confirms "no enroll RPC
  issued when identity present".
- Full workspace green; operator lib + `enroll_cmd` suites; no regression to the
  netns gateway suites (they don't use the operator, but run mesh_milestone as
  a guard since enroll.rs changed).

## Release

Availability fix → patch bump per the release-every-fix rule. Shipped in two
steps: the PVC-backed identity + idempotent enroll feature released as **v0.2.1**;
the hands-off *adoption* automation (detect + drain the stale id) described in the
"One-time adoption cost" section released as **v0.2.2**.

## Execution

Per-task test-author / implementer / dedicated runner / reviewer (CLAUDE.md
agent workflow); CodeRabbit before push. Dev container for builds/tests.
