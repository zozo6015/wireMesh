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
gateway_active` — where `pvc_exists` is the pre-reconcile `existing_pvc.is_some()`
snapshot — is `true` during adoption (fresh PVC + old id active) →
`should_mint_token` is `false` → no fresh token minted. Adoption stalls in
`Init:Error`.

The chosen fix does NOT mint a rebind token: on the fresh-PVC path
`existing_pvc.is_none()` makes `pvc_exists` false → `identity_persisted` false →
`should_mint_token` true, so a PLAIN token is minted, and the stale-id drain (below)
frees the segment so that plain-token enroll is accepted.

**Fix (chosen + implemented):** the operator DETECTS adoption and drains the
stale gateway so the segment is freed and the new pod's plain-token enroll is no
longer rejected. Precisely — in the gateway reconciler the operator drains a
stale active roster id ONLY when ALL of the following hold:
1. the gateway PVC is **freshly created** this reconcile
   (`existing_pvc.is_none()`) — genuine adoption, no persisted identity; AND
2. this CR is the **sole `WiremeshGateway` for the segment** — the operator
   lists the `WiremeshGateway` CRs and counts those referencing this segment
   (`segment_ref`); the drain is allowed only when the count is 1; AND
3. a roster id is active for the segment that is not this CR's own id (on the
   fresh-PVC path own-id is `None`, so any active id qualifies).

It then drains that stale id (freeing the segment) and proceeds with the
deployment so the new pod enrolls into the freed segment. NOTE: the drain does
NOT flip `gateway_active` within the reconcile (that snapshot is read before the
drain and not re-read); the fresh token is minted because the freshly created
PVC makes `identity_persisted` false → `should_mint_token` true.

Guard 2 is load-bearing because the controller roster matches a gateway to its
segment by **NAME only**: with two CRs on one segment, the "active" id could be
a healthy peer's LIVE gateway, and draining it would be an outage. The CR-list
query runs ONLY on the fresh-PVC path (skipped in steady state to avoid an API
call every reconcile) and **fails safe**: on a list-query error the operator
treats this CR as NOT sole → does NOT drain (a missed drain is a manual cleanup;
a wrong drain kills a live peer).

CAUTION: this fires ONLY on genuine adoption (fresh PVC + sole gateway), NEVER
in steady state (where the PVC has the identity, enroll skips, and the active
roster id is legitimately this gateway). Options considered: (a) drain only when
the PVC is freshly created AND a roster id is active — CHOSEN, hardened with the
sole-gateway guard; (b) track the enrolled id in CR status and drain a differing
roster id — rejected (during adoption status still holds the stale id); (c) mint
a REBIND token — deferred. The chosen path cannot drain a healthy steady-state
gateway, and the sole-gateway guard also protects a healthy peer sharing the
segment.

**Done-bar:** a test pinning the adoption decision (fresh PVC + stale active
roster id → drain the stale id, then the new pod enrolls with a freshly minted
PLAIN token; steady-state PVC-has-identity + own active id → NO drain, no mint —
enroll is skipped). No rebind-token minting is involved. Update the design doc's
"automatic one-time re-enroll" claim to match the real behavior.

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
