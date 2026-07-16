# WireMesh — Cycle 2 Design: Controller Core

> **Plan cycle 2 of 4** (per the master engineering design §12). This document
> elaborates the master spec's controller sections into an implementable design;
> it does not restate them. Authority: the master spec
> (`docs/superpowers/specs/2026-07-15-wiremesh-engineering-design.md`, esp. §3
> trust, §4 controller, §4.2 API surface) governs where this conflicts. Cycle 3
> is the policy pipeline; cycle 4 is gateway transport + relay.

## 1. Scope & done bar

**In scope (the single-tenant control plane):** embedded-SQLite data model (§4.1),
embedded fabric CA + enrollment/rebind trust flow (§3.1–3.2), the Enrollment /
Sync / Admin gRPC services plus the UDP observation endpoint (§4.2, §6.1
controller side), WireGuard key-epoch lifecycle *bookkeeping* (§4.4), full-mesh
route computation (§4.3), audit log (§4.5), the pluggable `SecretStore` /
`CertificateIssuer` provider seams with the embedded default (§3.4), the proto +
trait definitions (§12 artifact 2), and `fabricctl` including declarative
`apply -f` (C-6).

**Done bar — end-to-end against a stub gateway.** A real controller a non-enforcing
stub gateway can enroll into (token → CSR → cert), open a Sync stream, receive a
full desired-state snapshot + deltas, ack revisions, and survive a controller
restart/restore with its existing cert (no re-enrollment, C-7). Policy IR and the
real data-plane gateway are stubbed; the trust + Sync loop is proven live.

**Out of scope (later cycles):** the DSL→IR policy compiler and enforcement
backends (cycle 3); the real gateway/relay binaries, the data-plane half of key
rotation, and the brokered-hole-punch choreography (cycle 4); the OpenBao and
cloud provider drivers (fast-follow / P1).

## 2. Decisions

- **D-C2-1 — Build strategy: contract-first, then vertical slice.** Lock the shared
  contracts (proto, trust traits, DB schema) first; stand up the thinnest live
  enroll→sync→fail-static path against a stub gateway; then thicken each service to
  full spec. De-risks the integration early.
- **D-C2-2 — Stack (grounded in Phase 0):** `tonic` + `prost` (gRPC), `rustls 0.23`
  (mTLS), `rcgen 0.13` (embedded CA), `rusqlite` (embedded DB) behind a small
  blocking-pool wrapper so synchronous DB calls never block the tonic executor.
  Migrations via `PRAGMA user_version` + embedded ordered SQL steps — no external
  migration tool, preserving the single-binary/no-dependency promise.
- **D-C2-3 — Provider seams: traits + embedded default now, OpenBao fast-follow.**
  The `SecretStore` / `CertificateIssuer` traits are real and the embedded default
  is wired through them; the OpenBao reference driver + its containerized
  conformance suite are a tight fast-follow (cycle 2b).
- **D-C2-4 — `fabricctl` including declarative `apply -f`.** Full imperative CRUD +
  the server-side diff/idempotence engine for everything except policy semantics.
- **D-C2-5 — `apply -f`: policy stanzas stubbed.** The diff engine fully handles
  segments/CIDRs/gateways/relays/tokens; policy blocks are accepted and stored as
  `source_yaml` but compiled by a stub emitting **empty IR v0**. The real
  DSL→IR compiler (cycle 3) drops in behind the same call site.
- **D-C2-6 — UDP observation: controller side only.** Build + unit/synthetic-test the
  endpoint (authenticated probe → echo observed source addr → surface into the
  projection's candidate endpoints). The brokered-hole-punch choreography and the
  Phase 0 **go-skew < one-way-latency** constraint (master-spec delta 1) are
  designed-for here but proven end-to-end in cycle 4 (they need real gateways).
- **D-C2-7 — Key rotation: controller bookkeeping only.** Prove the
  `GATEWAY_KEY(gateway_id, epoch, state)` state machine + `RotateKey` signaling
  against a stub that acks transitions; the data-plane half (second WG listener,
  atomic allowed-ips repoint) is cycle 4.

## 3. Workspace & crate structure

Unlike the Phase 0 spike (standalone crates, no workspace — forced by the aya
template), the product uses one cargo workspace so the wire contract and trust
traits are shared, never copied.

```
Cargo.toml                    # workspace root
proto/                        # .proto sources: enrollment, sync, admin
crates/
  wiremesh-proto/             # tonic/prost codegen (build.rs) — THE wire contract.
                              #   Sync StateSnapshot/Delta types live here so the
                              #   cycle-4 gateway deserializes byte-identical messages.
  wiremesh-trust/             # SecretStore + CertificateIssuer traits (§3.4) + the
                              #   embedded default impl (rcgen CA on 0600 disk;
                              #   secrets in SQLite/files). Future OpenBao/AWS/GCP/
                              #   Azure drivers become sibling crates.
  wiremesh-controller/        # the binary. Modules:
                              #     db          rusqlite + migrations + overlap guard
                              #     projection  revisioned per-gateway desired state
                              #     services    enrollment / sync / admin (tonic)
                              #     routes      full-mesh computation
                              #     keys        epoch lifecycle bookkeeping
                              #     audit       append-only log + query
                              #     observe     UDP observation endpoint
  fabricctl/                  # CLI: Admin client over bearer-token TCP or the Unix
                              #   socket; imperative CRUD + declarative apply -f.
  wiremesh-testkit/           # stub gateway + integration harness (the done-bar proof)
```

**Structural invariant:** the Sync `StateSnapshot` / `Delta` message types are
proto-defined in `wiremesh-proto`, not hand-rolled in the controller — cycle 4's
real gateway must consume identical types.

## 4. Data model & migrations

Schema is master-spec §4.1 verbatim (SEGMENT, CIDR, GATEWAY, GATEWAY_KEY,
TUNNEL_PAIR, RELAY, CERTIFICATE, ENROLLMENT_TOKEN, POLICY_VERSION/RULE/STATUS,
API_TOKEN, AUDIT_LOG). Implementation specifics:

- Migrations run in a transaction at startup, keyed on `PRAGMA user_version`; `v1`
  creates the whole schema.
- **CIDR-overlap invariant (C-2)** is enforced in exactly one place: an insert guard
  that checks against all registered CIDRs *inside* the enrollment/apply
  transaction, with rebind tokens exempting their own segment's rows. The reject
  names the conflicting segment.
- `POLICY_VERSION.compiled_ir` caches compiler output for identical re-serving after
  restart; in cycle 2 the compiler is the empty-IR-v0 stub.
- All DB access is synchronous `rusqlite` behind a blocking pool.

## 5. Trust: CA, enrollment, rebind, lifecycle

- The embedded CA (rcgen) is created at first startup; its private key is a separate
  `/var/lib/wiremesh/ca.key` (0600), never in SQLite. Both CA and secret storage go
  through the `wiremesh-trust` seam; the embedded default is one impl.
- **`Enrollment.Enroll`** (TLS, no client cert yet): enrollee presents token + CSR +
  declared CIDRs. Controller validates the token (hash match, unexpired, unused,
  kind), runs the overlap check, signs a 90-day client cert via
  `CertificateIssuer::sign`, records it in `CERTIFICATE` with the opaque
  `issuer_handle`, marks the token used, audit-logs. WireGuard keypairs are
  gateway-generated; only pubkeys transit.
- **Rebind tokens** exempt their bound segment's CIDR rows from the overlap check so
  a replacement gateway isn't rejected as a self-overlap.
- **Lifecycle:** 90-day certs, renewal at 50% via a re-sign path against the same
  subject; revocation writes `revoked_at` and pushes the serial onto the denylist
  carried in every Sync snapshot (authoritative, offline-verifiable).

## 6. Services & the Sync projection engine

Three tonic services on one TCP port + the Unix socket exposing Admin only.

- **Projection:** per connected gateway, a **revisioned desired-state view** — peer
  public keys by epoch + candidate endpoints, allowed-ips (peer segment CIDRs),
  relay list, compiled policy IR + version, revoked serials. Built from the DB on
  connect, updated incrementally on any mutating Admin op.
- **`Sync.Watch`** (server-streaming, mTLS): full `StateSnapshot` on connect, then
  `Delta`s, each carrying a monotonic revision. A mutation recomputes affected
  gateways' projections and fans deltas over per-connection broadcast channels.
- **`Sync.Report`** (unary, upstream): gateways ack the applied policy revision →
  feeds `fabricctl policy status` (C-4) and the publish→ack propagation-latency
  metric (5s p99, C-3).
- **`Admin`** (unary CRUD): driven by `fabricctl`; also exposed on the Unix socket.

## 7. fabricctl & the declarative-apply boundary

- **Auth:** bearer token (named, revocable, role `admin` / `read-only`) over TCP, or
  the Unix socket (`/run/wiremesh/controller.sock`, 0700) as implicit admin /
  break-glass.
- **Imperative:** create/list/drain segments & gateways, mint/revoke enrollment +
  API tokens, audit query, gateway/sync status.
- **Declarative `apply -f fabric.yaml`** (C-6): server-side diff against current
  state; idempotent (identical apply → empty diff, zero mutations, zero audit).
  **Boundary (D-C2-5):** full diff for segments/CIDRs/gateways/relays/tokens; policy
  stanzas stored as `source_yaml` and compiled by the empty-IR-v0 stub. `apply -f`
  is otherwise real and complete.

## 8. Controller mechanics

- **Key-epoch lifecycle (§4.4, D-C2-7):** the `GATEWAY_KEY(gateway_id, epoch, state)`
  state machine (pending→active→retiring) and make-before-break *bookkeeping* —
  controller drives `RotateKey`, tracks per-gateway epoch state so a mid-rotation
  restart resumes from the snapshot, emits peer updates. Data-plane half is cycle 4.
- **Route computation (§4.3):** full mesh — each gateway's peer set is the other
  N−1; add/remove segment → delta to all; drain (G-7) → withdrawal + ack-wait (5s
  timeout) → remove + revoke cert.
- **Audit log (§4.5):** every mutating Admin op + lifecycle event appends
  `{ts, actor, action, entity, diff_json}`; actor is the token name, `unix-socket`,
  or `system`.
- **UDP observation endpoint (§6.1, D-C2-6):** authenticated UDP probe → echo
  observed source addr → surface into the projection's candidate endpoints;
  unit/synthetic-tested here. Brokered-punch choreography + go-skew constraint
  proven in cycle 4.

## 9. Provider seams (§3.4, D-C2-3)

The `SecretStore` (get/put/watch, versioned) and `CertificateIssuer`
(trust_bundle / sign→IssuedCert+IssuerHandle / revoke) traits per the master spec,
with the embedded default wired through them (rcgen CA on disk; secrets in
SQLite/files). Manager-driven rotation, min-TTL refusal, and the manager-outage
contract are honored by the embedded impl trivially (it never goes down
independently). The OpenBao reference driver + its containerized conformance suite
(issuance, renewal-follows-TTL incl. min-TTL refusal, external-rotation hot-swap,
CRL→denylist, manager-outage mode) are the cycle-2b fast-follow.

## 10. Stub gateway & testing

- **Stub gateway (`wiremesh-testkit`):** enroll → open Sync → persist snapshot to
  disk → `Report` acked revisions → survive controller restart with its existing
  cert. Non-enforcing (no eBPF) — the controller's counterparty, reused across
  tests.
- **Test layers (relevant subset of §9):** golden tests for enrollment/rebind/
  overlap logic; property tests for CIDR-overlap and route-computation invariants;
  an **integration harness** running the full vertical slice (enroll, delta on 2nd
  gateway, controller-kill-and-restore resync, drain, revocation→denylist); and the
  **provider-conformance suite against the embedded default** (issuance,
  renewal-follows-TTL incl. min-TTL refusal, revocation→denylist). Per CLAUDE.md:
  separate test-author and implementer agents; tests green before any done-claim.

## 11. Build phases (feeds the implementation plan)

1. **Contract-first** — `proto/` (Enrollment/Sync/Admin + StateSnapshot/Delta),
   `wiremesh-trust` traits, SQLite schema + migrations, `wiremesh-proto` codegen.
   Contracts compile and are reviewed; nothing runs yet.
2. **Vertical slice** — the §1 done-bar path live end-to-end against the stub gateway
   (embedded CA, minimal Admin, Sync snapshot+delta, fail-static/restore).
3. **Thicken** — rebind, key-epoch rotation bookkeeping, route deltas on drain, full
   `fabricctl` incl. `apply -f`, audit query/export, UDP observation endpoint,
   revocation/denylist, provider-conformance suite (embedded).

## 12. Deferred / carried forward

- **Cycle 2b (fast-follow):** OpenBao `SecretStore`/`CertificateIssuer` driver +
  containerized provider-conformance suite.
- **Cycle 3:** DSL→IR policy compiler + enforcement backends behind the stub's call
  site; real `apply -f` policy semantics.
- **Cycle 4:** real gateway/relay binaries; data-plane key rotation; brokered-punch
  choreography that must honor the **go-skew < one-way-latency** constraint
  (master-spec delta 1) — the controller's Sync signal for it is designed here,
  proven there.

## 13. Next artifact

An implementation plan (via the writing-plans skill) structured on the three build
phases of §11, each task carrying the CLAUDE.md agent-workflow rules.
