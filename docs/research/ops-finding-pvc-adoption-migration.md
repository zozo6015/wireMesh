# Ops finding: gateway PVC-identity ADOPTION path (two bugs the v0.2.1 e2e caught)

**Date:** 2026-07-28/29 (v0.2.1 end-to-end validation on the zolab k3s cluster).
**Status:** OPEN — two operator bugs in the emptyDir→PVC *adoption* transition,
targeted for **v0.2.2**. The STEADY-STATE feature (identity persists across pod
recreation; enroll skips) is VALIDATED and works — see below.

## What v0.2.1 shipped and what the e2e proved GREEN

v0.2.1 (PR #31) persists the gateway identity on a per-gateway PVC
(`<name>-gateway-data`) and makes `wiremesh-gateway enroll` idempotent. The
core e2e passed on zolab:

- The operator created `gw-home-gateway-data` (RWO 128Mi, local-path). The
  **scheduler-aware pinning fix works**: `nodeName` folded into a
  `kubernetes.io/hostname` nodeSelector let the scheduler place the pod, which
  bound the WaitForFirstConsumer PVC (a direct `nodeName` would have left it
  Pending).
- gw-home migrated and enrolled as **id 9**, PVC-backed.
- **The proof:** deleting the gw-home pod → the replacement booted with the
  PVC re-attached, the enroll init logged `already enrolled (identity present
  in /var/lib/wiremesh), skipping`, and the roster stayed **id 9** — NO
  re-enrollment, NO new id, NO drain/re-mint dance. The whole point of the
  feature.

## Bug 1 — `strategy: Recreate` apply 422s over an existing RollingUpdate Deployment

The operator now sets `strategy.type: Recreate` (`rolling_update: None`) on the
gateway + controller Deployments. But an EXISTING Deployment on the cluster was
created with the default RollingUpdate strategy, whose `rollingUpdate` block is
owned by the API-server DEFAULTER (not the operator's field manager). A
server-side apply that omits `rollingUpdate` leaves the defaulter's block in
place, so the merged object has `type: Recreate` AND `rollingUpdate` →
Kubernetes rejects it:

```
Deployment.apps "gw-home" is invalid: spec.strategy.rollingUpdate:
Forbidden: may not be specified when strategy `type` is 'Recreate'
```

The reconcile loops on this 422 and never applies the new pod spec. The unit
test only asserts the DESIRED spec has `type: Recreate`; it can't catch the
apply-over-existing conflict — only the cluster did.

**Fix (v0.2.2):** the operator must explicitly CLEAR `strategy.rollingUpdate`
when applying `Recreate` — e.g. build the apply body as JSON with
`"strategy": {"type": "Recreate", "rollingUpdate": null}` (a typed
`rolling_update: None` serializes to *omitted*, not null, so SSA won't remove
the defaulter's field). Applies to both `gateway_deployment` and
`controller_deployment`. **Manual unblock used in the e2e:** `kubectl patch
deploy <d> --type=json` removing `/spec/strategy/rollingUpdate` and setting
`/spec/strategy/type=Recreate` on gw-home and wiremesh-controller.

## Bug 2 — adoption doesn't drain the old active gateway; enroll rejected

The design claimed adoption "re-enrolls ONCE automatically." It does NOT: when
the pod is recreated onto a fresh empty PVC, the OLD gateway id (enrolled from
the now-gone emptyDir) is STILL `active` in the controller roster. A plain
enrollment token can't enroll into an occupied segment:

```
status: AlreadyExists, "segment already has an active gateway; use a rebind
token to replace it"
```

Compounding it, `identity_persisted = pvc_exists AND gateway_active` is `true`
during adoption (the fresh PVC exists AND the old id is active), so
`should_mint_token` is `false` — no fresh token is minted either. So adoption
stalls in `Init:Error` until the old id is drained.

**Fix (v0.2.2) — options:** (a) the operator DRAINS the old active gateway for
the segment when the identity is not persisted (adoption detection), then mints
a fresh token and lets the new pod enroll; or (b) the operator mints a REBIND
token (bound to the segment id) for the adoption enroll instead of a plain one;
or (c) at minimum, document the one-time manual drain in the release notes and
DON'T claim it's automatic. Option (a) is the cleanest "no manual step" fix but
must be careful to drain only during a genuine adoption (identity absent), not
in steady state. **Manual unblock used in the e2e:** `operator-admin drain
--id <old>` → `gateway_active` flips false → operator mints a fresh token →
the new pod enrolls into the freed segment (became id 9). After that, the
steady-state feature works perfectly.

## Net

The v0.2.1 feature is correct and validated for its purpose (steady-state pod
recreation no longer re-enrolls). The ADOPTION transition (one-time,
emptyDir→PVC) needs the two operator fixes above before it is hands-off; until
v0.2.2, adopting a gateway requires the two manual steps used here (patch the
strategy, drain the old id). The design doc's "automatic one-time re-enroll"
wording is corrected by this note.
