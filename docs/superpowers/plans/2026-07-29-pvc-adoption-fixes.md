# v0.2.2 — PVC-adoption fixes plan

**Source of truth:** `docs/research/ops-finding-pvc-adoption-migration.md` (two
bugs the v0.2.1 e2e caught on zolab; the steady-state feature is validated and
works). **Branch:** `fix/pvc-adoption`. **Release:** patch **v0.2.2**.

Both bugs are in the ONE-TIME adoption transition (emptyDir→PVC), operator-side.

## T1 — `strategy: Recreate` apply must clear the defaulter's `rollingUpdate`

Applying `strategy.type: Recreate` over an existing RollingUpdate Deployment
422s: `spec.strategy.rollingUpdate: Forbidden ... when type is 'Recreate'`.
A typed `rolling_update: None` serializes to OMITTED (not null), so SSA leaves
the API-server-defaulter's `rollingUpdate` block in place → the merged object
has both → rejected. Affects both `gateway_deployment` and
`controller_deployment` on upgrade-in-place.

**Fix:** ensure the applied Deployment explicitly sets
`strategy.rollingUpdate = null` so SSA removes it. Options for the implementer,
pick the cleanest that fits the existing apply path
(`crates/wiremesh-operator/src/controllers/*` + `workloads.rs`):
- Build the strategy in the apply body as `serde_json::Value` with
  `{"type":"Recreate","rollingUpdate":null}` (a null, not an omitted field); or
- Post-process the serialized Deployment JSON to insert `rollingUpdate: null`
  under `spec.strategy` before the `Patch::Apply`; or
- A targeted merge-patch that nulls `spec.strategy.rollingUpdate` in the same
  reconcile before/with the apply.
Keep the typed builders returning `type: Recreate`; the null-injection is at
the apply boundary. Must be idempotent (re-applying a Deployment already at
`Recreate` with no `rollingUpdate` is a no-op, not a churn).

**Done-bar:** a test proving the applied body carries `strategy.rollingUpdate:
null` (or its equivalent) for both gateway and controller. If the apply path is
side-effect-only, pin the pure "build apply body" surface. (Cluster-level
apply-over-existing can't be unit-tested; the pure body-shape pin + the e2e
re-run is the coverage.)

## T2 — adoption must free the segment (drain old gateway) + get a fresh token

When the pod is recreated onto a fresh empty PVC, the OLD gateway id (enrolled
from the now-gone emptyDir) is still `active` in the roster, so the new pod's
plain-token enroll is rejected: `AlreadyExists: segment already has an active
gateway; use a rebind token`. And `identity_persisted = pvc_exists AND
gateway_active` is `true` during adoption (fresh PVC + old id active) →
`should_mint_token` is `false` → no fresh token minted. Adoption stalls in
`Init:Error`.

**Fix (chosen):** the operator DETECTS adoption and drains the stale gateway so
the segment is free and a fresh token is minted. Precisely — in the gateway
reconciler, when the identity is NOT persisted on the current PVC but the
roster has an active gateway for this segment that is NOT this deployment's
current pod (i.e. a stale/adopted id), the operator should:
1. drain that stale gateway id (frees the segment), which flips
   `gateway_active` → false → `identity_persisted` false → mints a fresh token;
2. proceed with the deployment so the new pod enrolls into the freed segment.

CAUTION: this must fire ONLY on genuine adoption (identity absent on a fresh
PVC), NEVER in steady state (where the PVC has the identity, enroll skips, and
the active roster id is legitimately this gateway). Distinguishing "stale id to
drain" from "our own current id" is the crux — options for the implementer to
evaluate: (a) drain only when the PVC is freshly created (pvc_needs_create was
true this reconcile) AND a roster id is active for the segment; (b) track the
enrolled id in the CR status and drain a roster id that differs from it; (c) if
neither is safe, mint a REBIND token (bound to the segment id) for the adoption
enroll instead of draining. Prefer the SAFEST option that cannot drain a
healthy steady-state gateway. Report the approach chosen with its safety
argument.

**Done-bar:** a test pinning the adoption decision (fresh PVC + stale active
roster id → drain/rebind; steady-state PVC-has-identity + own active id → NO
drain). Update the design doc's "automatic one-time re-enroll" claim to match
the real behavior.

## Non-regression + validation

- operator suite green (existing PVC/enroll/pinning/should_mint_token tests).
- After merge/release: re-run the zolab e2e — this time adoption should be
  hands-off (no manual strategy patch, no manual drain). But since gw-home is
  ALREADY on PVC (id 9), a fresh adoption test needs a gateway still on
  emptyDir (aether/px are bare-metal, not operator-managed) — so the e2e
  re-validation is via a scratch operator-managed gateway OR by reverting a
  test gateway to emptyDir. Note this in the PR; the unit done-bars carry the
  correctness, the earlier zolab e2e already proved steady-state.

## Execution

Per-task test-author / implementer / dedicated runner / reviewer; CodeRabbit
via the coderabbit skill before push; then push → PR → CI → merge → tag v0.2.2.
