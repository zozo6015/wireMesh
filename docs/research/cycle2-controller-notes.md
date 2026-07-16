# Cycle 2 (Controller Core) — Wrap-up Notes

Branch: `worktree-cycle2-controller`, base `28f9a49`, HEAD at wrap-up `7ef68e2`
(this doc's own commit lands on top). Plan: `docs/superpowers/plans/2026-07-16-controller-core.md`.
Ledger: `.superpowers/sdd/progress.md` (18 tasks, all complete, every review
approved — clean or clean-after-fix, none shipped with an open finding).

## Done bar reached

Design §1's done bar — *"a real controller a non-enforcing stub gateway can
enroll into (token → CSR → cert), open a Sync stream, receive a full
desired-state snapshot + deltas, ack revisions, and survive a controller
restart/restore with its existing cert (no re-enrollment, C-7)"* — is **proven**,
not just asserted. Load-bearing tests:

- `crates/wiremesh-controller/tests/enroll.rs` — token → CSR → 90-day client
  cert issuance, single-use atomicity, bound-CIDR enforcement (2 tests).
- `crates/wiremesh-controller/tests/sync_snapshot.rs` /
  `tests/sync_delta.rs` — mTLS `Sync.Watch` full snapshot on connect, then a
  live `Delta` on a second gateway's enrollment, keyed by monotonic DB-backed
  revision (2 tests).
- `crates/wiremesh-controller/tests/fail_static.rs` — controller restart on the
  same data dir (new ports, same DB/CA), stub gateway reconnects with its
  **existing** enroll-time cert via `dial_sync`, no re-enrollment path taken —
  this is C-7 (1 test, independently reproduced 5x per Task 9's review).

### Step 1 evidence — full workspace suite, run for real

```
./dev.sh run "cd /work && timeout 500 cargo test --workspace -- --test-threads=1 ..."
```

Result: **34 tests, 0 failed, 0 ignored, 0 skipped**, across every crate:

| Crate / suite | Tests |
|---|---|
| fabricctl `tests/cli.rs` | 1 |
| wiremesh-controller `tests/admin.rs` | 1 |
| wiremesh-controller `tests/admin_auth.rs` | 4 |
| wiremesh-controller `tests/apply.rs` | 1 |
| wiremesh-controller `tests/db.rs` | 5 |
| wiremesh-controller `tests/drain.rs` | 1 |
| wiremesh-controller `tests/enroll.rs` | 2 |
| wiremesh-controller `tests/fail_static.rs` | 1 |
| wiremesh-controller `tests/keys.rs` | 1 |
| wiremesh-controller `tests/observe.rs` | 2 |
| wiremesh-controller `tests/rebind.rs` | 3 |
| wiremesh-controller `tests/revoke_audit.rs` | 1 |
| wiremesh-controller `tests/sync_delta.rs` | 1 |
| wiremesh-controller `tests/sync_snapshot.rs` | 1 |
| wiremesh-proto `tests/codegen.rs` | 1 |
| wiremesh-testkit `tests/stub_enroll.rs` | 2 |
| wiremesh-trust `tests/conformance.rs` | 1 |
| wiremesh-trust `tests/embedded.rs` | 5 |
| **Total** | **34** |

This is one more than the 33 the ledger recorded at Task 16 — expected, since
Task 17 added the 1-test provider-conformance suite afterward. All lib-only
crate targets report `0 passed; 0 failed` (no unit tests, integration tests
carry the suite) — not a gap, by design (§10). No `FAILED`, no `error` lines
anywhere in the run.

## What was built

- **Workspace** (`crates/`, 5 members): `wiremesh-proto`, `wiremesh-trust`,
  `wiremesh-controller` (bin), `fabricctl` (bin), `wiremesh-testkit` — one
  cargo workspace (unlike the Phase 0 standalone-crate spikes), so the wire
  contract and trust traits are shared, not copied (§3).
- **Proto wire contract** (`wiremesh-proto`): Enrollment/Sync/Admin services,
  `StateSnapshot`/`Delta`/`Peer` message types byte-exact via `tonic`+`prost`
  codegen; the cycle-4 gateway will consume these unchanged.
- **Embedded trust**: `CertificateIssuer`/`SecretStore` traits (§3.4/§9) +
  `EmbeddedTrust` (rcgen 0.13 CA, 0600 `ca.key` never in SQLite, CA-controlled
  leaf identity from CSR pubkey only, CA reload across restart). Generic
  provider-conformance suite (issuance chain, TTL-follows-90d, min-TTL refusal,
  idempotent revoke, SecretStore roundtrip+monotonic version) — parameterized
  so the cycle-2b OpenBao driver plugs into the same test surface.
- **SQLite data model**: full §4.1 schema (13 tables) via `PRAGMA user_version`
  migrations, transactional CIDR-overlap guard (rebind exempts its own
  segment), append-only audit log, and a DB-backed persistent monotonic
  `state_revision` (survives restart — this closed a landmine flagged at
  Tasks 8/9).
- **Enrollment**: single-use atomic token→CSR→cert (one txn: check+mark-used+
  cert-record+gateway-insert), bound-CIDR enforcement, rebind tokens (replace
  an active gateway, revoke its prior cert, enforce declared-segment scope,
  reject occupied segments with `AlreadyExists`).
- **mTLS Sync projection**: dedicated listener, client-auth required
  (certless → rejected at handshake), peer identity from the TLS leaf CN (not
  spoofable), full snapshot on connect + broadcast-fanned `Delta`s on every
  mutation (enroll, rotate, drain, revoke), `Report` persists
  `applied_version`.
- **Key-epoch rotation bookkeeping** (§4.4, D-C2-7): `RotateKey` admin RPC,
  pending/active/retiring state machine, survives restart; data-plane half
  (ack→active/retiring→remove-n, real pubkeys) is cycle 4.
- **Drain** (G-7): one-txn revoke+remove+audit+broadcast; withdraws the
  gateway from peers' projections.
- **Full Admin CRUD + fabricctl + auth**: segments/gateways/relays/tokens/
  audit query, TCP admin listener (plaintext, bearer-token sole boundary) +
  Unix socket (implicit admin), fail-closed `tower::Layer` classifying
  read-only vs admin-only by method path (unknown method → admin-only, not
  read-only).
- **Declarative `apply -f`** (D-C2-4/D-C2-5): structural idempotence (identical
  apply → rollback before any audit/mutation write), cross-segment overlap
  invariant preserved within one apply, policy stanzas stubbed
  (`compile_policy` → empty IR v0).
- **UDP observation endpoint** (§6.1, D-C2-6): per-gateway keyed-MAC probe,
  authenticated echo + candidate-endpoint projection update; explicitly a
  cycle-2 stand-in (see Spec deltas below).
- **Revocation denylist + audit query/export**: `RevokeCert` → sentinel
  `ChangeEvent` reaching all open streams → `revoked_serials` in every
  snapshot/delta; `fabricctl audit export` (JSON lines).

## Tech / API-drift findings (real, from the ledger)

- **tonic 0.12 Unix-socket serving**: server side needs
  `UnixListenerStream` + `serve_with_incoming_shutdown`; client side needs
  `hyper_util::rt::TokioIo` + a `tower::service_fn` connector — none of this
  is the naive TCP-only tonic quickstart path (Task 4).
- **Admin auth must be a `tower::Layer`, not a tonic `Interceptor`** — the
  interceptor strips the URI needed to classify method paths for the
  fail-closed read-only/admin-only split (Task 13).
- **rusqlite**: `Mutex<Connection>` needed for shared `&mut` transaction
  access; `time` crate needs `features = ["formatting"]`; `user_version` must
  be set *inside* the DDL transaction — it's part of the SQLite file header
  and participates in the transaction's atomicity (Task 3).
- **Shutdown-hangs-on-open-stream deadlock**: `RunningController::shutdown()`
  hung on open `Sync.Watch` streams across restart (tonic's graceful shutdown
  waits for in-flight streams to end, but a live Watch stream never ends on
  its own). Fixed by bounding each of the 3 join handles with a
  `SHUTDOWN_GRACE=500ms` timeout then `.abort()`ing — `spawn_blocking` DB
  transactions still run to completion regardless of abort, no corruption
  (Task 11).
- **The ALWAYS-timeout-wrap-cargo-test lesson**: an earlier unbounded
  `cargo test` run cost ~15 minutes wall-clock hung on the above deadlock
  before it was fixed. Every subsequent run (and this wrap-up's Step 1) uses
  `timeout 500 cargo test ...` inside `./dev.sh run`.
- **`protobuf-compiler` must be in the dev image** — `prost-build` shells out
  to `protoc`; added to `dev/Dockerfile` at Task 1.
- **`serde_json`'s transitive `zmij` float-formatter crate** flagged as a
  possible phantom/supply-chain finding at Task 16 review, then refuted by
  re-running the full suite (33/33 green at the time) — it is the real
  serde_json float formatter in this ecosystem, present since Task 1's
  `Cargo.lock`. Recorded here so it isn't re-litigated as new information in
  cycle 3/4.

## Carried findings (Minors)

Every Minor below shipped with reviewer approval (none blocking); grouped by
area for the whole-branch final review to triage:

- **Proto / codegen (T1):** codegen test is an in-memory oneof check, not a
  byte-level encode/decode round-trip; no `[workspace.package]` shared edition.
- **Trust (T2, T17):** blocking sync fs I/O inside async bodies (acceptable at
  embedded scale); `secret_path` traversal-safety is an implicit invariant, no
  comment; temp-file orphan possible on rename failure; no exact-24h min-TTL
  boundary test.
- **Data model (T3):** same-call self-overlap check names the new segment
  itself in the conflict message; non-workspace `time` dependency version; no
  CIDR index (full scan on the overlap guard).
- **Admin/harness (T4, T13):** no direct unit test for `bound_cidrs`
  round-trip; `create_segment` insert+audit not one txn; hex-not-base64 secret
  encoding (doc said base64); FK-violation maps to `internal` not
  `invalid_argument`; `serve()` startup DB/CA open is blocking (one-time cost);
  audit actor hardcoded `"unix-socket"` for TCP bearer mutations (loses token
  identity in the audit trail); `DeleteSegment` error mapping via fragile
  DB-error substring match; testkit teardown signals-not-awaits before tempdir
  removal (benign under serial tests).
- **Enrollment/rebind (T5, T6, T10):** CSR is cryptographically verified
  *before* token validation (wasted work / DoS-amplification on a bad token);
  hand-rolled hex duplicated between admin and enrollment modules;
  `NoMatchingSegment` leaves the token unspent (probe-able); stub gateway CSR
  CN is a fixed `"stub-gw"` (collision risk under concurrent stub-CN
  assertions); `cert_serial` guard checks length only, not direct equality
  against the controller's recorded serial; replaced gateway's old cert is
  still TLS-valid at the Sync handshake (no CRL/OCSP check there — the
  zero-trust gap called out below); `BoundCidrMismatch` reused for the
  rebind-wrong-segment case (a distinct variant would aid audit reading); no
  mint-time check that a rebind token carries a non-zero `rebind_segment_id`.
- **Sync/projection (T7, T8):** `build_snapshot` reads revision then peers in
  separate transactions (revision can transiently lag data — benign, but
  deltas should snapshot both in one read-txn or explicitly tolerate
  revision≤data); no revocation check on a *connecting* gateway's own cert at
  Sync handshake (the same zero-trust gap as above, called out twice
  independently); `Status::internal` leaks raw error strings to clients;
  `gateway.name` has no UNIQUE constraint; `Report` has no dedicated test
  (deferred — `ListGateways` exposing `applied_version` made it observable
  later); `CreateSegment` doesn't publish a `ChangeEvent` (a segment created
  while a gateway is mid-watch produces no live delta for it); `applied_version`
  does a u64→i64 cast.
- **Keys/drain (T11, T12):** dead code `Db::active_keys_for_gateway` (no
  callers); `GatewayEnrolled` delta omits the new gateway's own epoch-0 key
  (self-heals on next snapshot); a narrow window where an aborted-mid-flight
  `RotateKey` persists to the DB but its delta isn't broadcast (peers pick it
  up on reconnect); no observable intermediate `'draining'` status
  (active→removed happens in one transaction); repeat `Drain` on an
  already-removed gateway still audits+broadcasts (redundant, not harmful); a
  drained gateway's own open Sync stream isn't proactively closed (it learns
  of its removal only on reconnect).
- **Apply/observe/audit (T14, T15, T16):** duplicate segment name within one
  YAML batch surfaces a raw UNIQUE constraint error (safe — the tx rolls back
  — but ugly); the inline audit-in-transaction pattern needs a why-comment to
  stop a future "simplify" pass from reintroducing the `Db::audit`
  Mutex-reentrancy deadlock it was written to avoid; observation's keyed-SHA256
  is a documented HMAC stand-in, not textbook HMAC; last-observed-wins
  candidate endpoint has no staleness tracking; `mac_eq` is only
  constant-time-*ish*; a bad-MAC flood costs one indexed DB lookup each (minor
  DoS surface); re-revoking an already-revoked serial still audits+broadcasts
  (only the `revoked_at` column is truly idempotent); no not-found/double-revoke
  test; no `fabricctl` surface for `RevokeCert`; `AuditQueryRequest`'s wire
  shape exposes only `action`, not `actor`/`entity` (the DB layer supports
  both, the RPC doesn't yet).

## Hand-offs to later cycles

- **Cycle 2b (fast-follow):** OpenBao `SecretStore`/`CertificateIssuer`
  driver + its containerized conformance arm. The conformance suite
  (`crates/wiremesh-trust/tests/conformance.rs`) is already generic over both
  traits and parameterized so the OpenBao impl runs the identical test list
  the embedded default does (issuance chain, TTL-follows-90d + min-TTL
  refusal, idempotent revoke, SecretStore roundtrip+monotonic version) — plus
  the containerized-only cases (external-rotation hot-swap, CRL→denylist,
  manager-outage mode) noted in design §9.
- **Cycle 3 (policy):** the real DSL→IR compiler behind the stubbed
  `compile_policy` call site (currently returns empty IR v0 unconditionally);
  real `apply -f` policy semantics. **Also carry forward D-C2-4's unmet
  scope**: design D-C2-4 asked for "full" `apply -f`, but cycle 2's diff
  engine is **create-only** for update/delete/relay-apply (Task 14's
  documented carve-out) — segments/CIDRs/gateways/relays/tokens diffing needs
  to be finished to genuinely close D-C2-4, not just the policy stanza.
- **Cycle 4 (gateway/relay):** a real gateway binary consuming
  `wiremesh-proto` byte-identical types; data-plane key rotation
  (ack→active/retiring→remove-n with real WireGuard pubkeys, replacing the
  bookkeeping-only epoch state machine built here); the brokered-punch
  choreography honoring the go-skew < one-way-latency constraint (master-spec
  delta 1) — the controller's Sync signal for it is designed, not yet proven
  live; the observation probe needs real **anti-replay** (nonce/timestamp +
  WG-socket binding — the cycle-2 44-byte keyed-MAC stand-in is replayable by
  design, documented as such in Task 15); and the revoked/replaced gateway's
  own cert is still TLS-valid at the Sync handshake today (no CRL check at
  that point) — cycle 4 (or an earlier hardening pass) must decide and
  implement the enforcement point.

## Spec deltas discovered

- **Admin TCP is plaintext-bearer, loopback-bound** — the design's §7 "bearer
  token over TCP" reads as if TLS were assumed; Task 13 implemented it as
  documented-plaintext with the 127.0.0.1 bind and the bearer token as the
  *sole* boundary. Worth an explicit spec sentence so a future reader doesn't
  assume TLS is present on the admin TCP path.
- **Shutdown is abort-based past a grace window, not purely graceful** — the
  design doesn't mention this; `RunningController::shutdown()` bounds each of
  its 3 join handles to 500ms then force-aborts. This is safe (DB txns still
  complete under `spawn_blocking`) but is a real behavior the design should
  record, since cycle 4's real gateway will observe mid-flight stream
  termination on controller restart.
- **Min-TTL of 24h is enforced in the embedded issuer** (Task 17: `bail!`
  before CSR parse if `ttl < 24h`, boundary-inclusive at exactly 24h) — this
  is a concrete parameter the design's "min-TTL refusal" language didn't
  pin down a value for; worth folding the number into §9 so the OpenBao
  driver (cycle 2b) enforces the same floor.

## Report

Full detail (doc structure, actual tally, self-review) filed at
`.superpowers/sdd/task-18-report.md`.
