# Finding: no production enrollment client blocks the operator's gateway/relay workloads

**Date:** 2026-07-22 (during K8s operator build, Task 4).
**Status:** OPEN — scope decision required before Tasks 7 (gateway) / 8 (relay) workloads.

## What the operator needs

The operator design assumes it can stand up a **gateway** and a **relay** as
Kubernetes workloads. Both binaries boot by loading a *pre-provisioned
identity* from their state/cert dir:

- `wiremesh-gateway`: `Identity::load(state_dir)` reads
  `identity.json` + `wg_private.key` (`crates/wiremesh-gateway/src/identity.rs`).
  The doc comment says verbatim: *"Pre-provisioned gateway identity (Cycle 4a
  assumes enrollment already ran — see spec §7-A)."*
- `wiremesh-relay`: `relay <bind> [certdir]` reads `ca.pem` + `relay.pem`/key
  from `certdir` (`crates/wiremesh-relay/src/bin/relay.rs`).

So for a pod to boot, an **init container must first turn an enrollment token
into those on-disk identity files** (the classic token → CSR → cert flow).

## The gap

There is **no shipped binary or CLI that performs client-side enrollment.**

- `fabricctl` has NO `enroll` subcommand (its `Command` enum is
  Segment/Gateway/Relay/Token/Audit/Apply/Policy — `crates/fabricctl/src/main.rs`).
- The controller's `MintToken{kind}` RPC mints the enrollment token, and the
  `Enrollment.Enroll` RPC issues the cert — but the **only** code that drives
  the client half (generate CSR, call `Enroll`, write identity to disk) is
  `wiremesh-testkit`'s `StubGateway::enroll_inner`
  (`crates/wiremesh-testkit/src/lib.rs:651`), a **test-only** helper.
- That helper also writes a **different layout** than the gateway reads: it
  emits `cert.pem` / `ca_bundle.pem` / `key.pem`, whereas
  `Identity::load` wants a single `identity.json` (with `gateway_id`,
  `observe_key`, `wg_private_key_b64`) plus `wg_private.key`. So it is not
  even a drop-in provisioner today.

Net: the operator can mint a gateway/relay enrollment token (via the Admin
`MintToken` RPC) and drop it in a Secret, but **nothing in the shipped
binaries consumes that token to produce a bootable identity.** This is a
pre-existing product gap (spec §7-A deferred gateway enrollment; Cycle 4a
explicitly assumed identity is pre-provisioned), surfaced now because the
operator is the first consumer that needs it end-to-end.

## What is NOT blocked (fully implementable today)

- **Controller lifecycle** (WiremeshController → Deployment + PVC + Service).
  The operator's *own* admin bootstrap works: `MintApiToken{name, role}` RPC
  over the implicit-admin UDS → operator bearer token into a Secret.
- **Fabric** (WiremeshSegment + WiremeshPolicy → `Apply(fabric_yaml)`), fully
  real: the fabric envelope (`segments:` + optional `policy:` DSL) and the
  `Apply` RPC both exist and are idempotent.
- **Relay registration** (`RegisterRelay{name, endpoint}`) — the control-plane
  record. Only the relay *workload's* identity is blocked, not its registration.

## Options

**A. Build a production enroll helper first (recommended).** Promote the
testkit CSR→Enroll→write-identity logic into a shippable subcommand
(`wiremesh-gateway enroll --token … --controller … --state-dir …`, and the
relay equivalent) that writes the exact on-disk layout each binary loads. One
focused crate change (its own test-author/implementer/runner cycle), after
which the operator's gateway/relay init-containers are real and the kind e2e
can actually boot a gateway. This is the thing that makes the operator able
to stand up gateways at all.

**B. Ship the operator for controller + fabric + relay-registration now**, and
treat gateway/relay *workload* identity provisioning as a documented
fast-follow gated on (A). The WiremeshGateway/WiremeshRelay CRDs + reconcilers
land (mint token, register), but stop short of a bootable pod.

## Recommendation

Do **A** as a small prerequisite, then resume the operator plan — otherwise
the operator's headline capability (deploy a gateway) can't actually work,
and Tasks 7/8 would be built around a non-existent init step.
