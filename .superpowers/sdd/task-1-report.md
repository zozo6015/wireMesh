# Task 1 — Test Author Report (key-rotation, wiremesh-proto)

## Status: DONE (RED confirmed)

## Commit
`2d406c8` — "test(proto): failing roundtrips for RotateDirective/SubmitEpochKey/epoch_acks (key-rotation Task 1)"

## Tests added (crates/wiremesh-proto/tests/codegen.rs)

Added `RotateDirective, SubmitEpochKeyRequest, EpochAck` to the existing
`use wiremesh_proto::v1::{...}` import block, then appended three new tests
at the end of the file, matching the file's existing genuine
encode_to_vec() → decode() → assert-against-decoded style:

1. `rotate_directive_message_roundtrips` — builds
   `SyncMessage { body: Some(Body::Rotate(RotateDirective { epoch: 5 })) }`,
   encodes, decodes, matches `Body::Rotate(r)` and asserts `r.epoch == 5`.

2. `submit_epoch_key_request_roundtrips` — builds
   `SubmitEpochKeyRequest { epoch: 5, pubkey: "REALKEY==".into() }`, encodes,
   decodes, asserts full equality against the original.

3. `report_request_epoch_acks_roundtrips` — builds a `ReportRequest` with
   `epoch_acks: vec![EpochAck{peer_gateway_id:1,epoch:6,live:true},
   EpochAck{peer_gateway_id:2,epoch:6,live:false}]` (other fields set as in
   the existing `report_request_relay_health_roundtrips` test), encodes,
   decodes, asserts `len == 2` and every field of both acks; also asserts an
   empty `epoch_acks: vec![]` ReportRequest still roundtrips cleanly
   (additive-field / old-client behavior), mirroring the existing
   `report_request_local_endpoints_roundtrips` pattern.

No existing test was modified, weakened, or deleted. The pre-existing
fully-specified `ReportRequest {...}` literals elsewhere in the file were
left untouched (not given `epoch_acks`), per instructions — the implementer
will ripple that field into them.

## RED verification

Command run (foreground, in-container):
`./dev.sh run "cargo test -p wiremesh-proto --no-run"`

Compile failed as expected, with exactly the errors that prove the new
proto surface doesn't exist yet:

```
error[E0432]: unresolved imports `wiremesh_proto::v1::RotateDirective`, `wiremesh_proto::v1::SubmitEpochKeyRequest`, `wiremesh_proto::v1::EpochAck`
 --> crates/wiremesh-proto/tests/codegen.rs:5:51
  |
5 |     RelayInfo, RelayHealth, Delta, EnrollRequest, RotateDirective, SubmitEpochKeyRequest,
  |                                                   ^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^^^^ no `SubmitEpochKeyRequest` in `v1`
  |                                                   |
  |                                                   no `RotateDirective` in `v1`
6 |     EpochAck,
  |     ^^^^^^^^ no `EpochAck` in `v1`

error[E0599]: no variant, associated function, or constant named `Rotate` found for enum `Body` in the current scope
   --> crates/wiremesh-proto/tests/codegen.rs:232:46
    |
232 |     let msg = SyncMessage { body: Some(Body::Rotate(rotate.clone())) };
    |                                              ^^^^^^ variant, associated function, or constant not found in `Body`

error[E0599]: no variant, associated function, or constant named `Rotate` found for enum `Body` in the current scope
   --> crates/wiremesh-proto/tests/codegen.rs:238:20
    |
238 |         Some(Body::Rotate(r)) => assert_eq!(r.epoch, 5),
    |                    ^^^^^^ variant, associated function, or constant not found in `Body`

error[E0560]: struct `ReportRequest` has no field named `epoch_acks`
   --> crates/wiremesh-proto/tests/codegen.rs:267:9
    |
267 |         epoch_acks: vec![
    |         ^^^^^^^^^^ `ReportRequest` does not have this field
    |
    = note: all struct fields are already assigned

error[E0609]: no field `epoch_acks` on type `ReportRequest`
   --> crates/wiremesh-proto/tests/codegen.rs:276:24
    |
276 |     assert_eq!(decoded.epoch_acks.len(), 2);
    |                        ^^^^^^^^^^ unknown field
    |
    = note: available fields are: `applied_version`, `local_endpoints`, `relay_health`

[... additional epoch_acks field-not-found errors on lines 277-282, 290 ...]

error: could not compile `wiremesh-proto` (test "codegen") due to 12 previous errors
```

12 total compile errors, all directly attributable to the missing proto
surface (RotateDirective, SubmitEpochKeyRequest, EpochAck, Body::Rotate,
ReportRequest.epoch_acks). No unrelated failures.

## Concerns

None. The proto surface requested (`SyncMessage.body` oneof variant 4,
`RotateDirective`, `SubmitEpochKeyRequest`/`SubmitEpochKeyResponse`,
`ReportRequest.epoch_acks` field 4, `EpochAck`) is fully specified by the
task; no ambiguity encountered. Note `Peer` already has a `PeerKey { epoch,
pubkey, state }` message (from a prior cycle) — the implementer may want to
reuse/relate that shape for epoch tracking, but that's outside this task's
scope (proto-only wire roundtrips) and no test here depends on it.

---

# Task 1 — Implementer Report (key-rotation, proto surface + ripple)

## Status: DONE

## Proto diff summary (`proto/wiremesh/v1/sync.proto`)

Additive only — no existing field number or wire type changed.

1. `service Sync` gained a third rpc:
   `rpc SubmitEpochKey(SubmitEpochKeyRequest) returns (SubmitEpochKeyResponse);`
2. `SyncMessage.body` oneof gained a fourth variant:
   `RotateDirective rotate = 4;` (1=snapshot, 2=delta, 3=punch, 4=rotate —
   unchanged numbers for the existing three).
3. New `message RotateDirective { uint32 epoch = 1; }` — controller→gateway,
   sent to the addressed gateway's own Watch stream (explicit addressing,
   like `PunchDirective`), telling it to mint the given new epoch's key and
   begin make-before-break rotation.
4. New `message SubmitEpochKeyRequest { uint32 epoch = 1; string pubkey = 2; }`
   and `message SubmitEpochKeyResponse {}` — gateway→controller, submits the
   real WG public key generated for `epoch` (private key never leaves the
   gateway).
5. `ReportRequest` gained `repeated EpochAck epoch_acks = 4;` (next free
   number after `relay_health = 3`) — gateway→controller liveness acks for
   peers' pending epochs during rotation. New
   `message EpochAck { uint64 peer_gateway_id = 1; uint32 epoch = 2; bool live = 3; }`.

## Files rippled (workspace compile fixes)

- `crates/wiremesh-proto/tests/codegen.rs` — added `epoch_acks: vec![]` to the
  two *pre-existing* `ReportRequest` literals (`report_request_local_endpoints_roundtrips`'s
  `with_endpoints`/`no_endpoints`, and `report_request_relay_health_roundtrips`'s
  `report`) that predate the new field. The three NEW tests written by the
  test-author agent (RotateDirective/SubmitEpochKeyRequest/epoch_acks) were
  left completely untouched — no test logic was edited.
- `crates/fabricctl/tests/cli.rs` — added `epoch_acks: vec![]` to the
  `ReportRequest` literal in the Sync.Report smoke test.
- `crates/wiremesh-testkit/tests/end_to_end_policy.rs` — same, one
  `ReportRequest` literal.
- `crates/wiremesh-testkit/src/lib.rs` — added `epoch_acks: vec![]` to both
  `ReportRequest` constructors (`report()` and `report_with_relay_health()`).
- `crates/wiremesh-gateway/src/sync.rs`:
  - `report()`'s `ReportRequest { .. }` struct literal gained
    `epoch_acks: vec![]`.
  - `classify()`'s match over `sync_message::Body` was non-exhaustive against
    the new `Body::Rotate` variant (no wildcard arm); added a minimal arm
    that returns `Err(anyhow!("RotateDirective handling is not yet
    implemented (key-rotation Task 2+)"))` rather than silently dropping the
    directive. No rotation logic implemented — deferred to a later task.
- `crates/wiremesh-controller/src/services/sync.rs` — the generated `Sync`
  server trait gained a `submit_epoch_key` method; added a minimal stub impl
  on `SyncSvc` returning `Status::unimplemented("SubmitEpochKey lands in
  Task 2")`. Import list extended with
  `SubmitEpochKeyRequest`/`SubmitEpochKeyResponse`.

Audited, no change needed (already had a catch-all `other => panic!(...)` or
`_ => ...` arm, so the new `Body::Rotate` variant doesn't break exhaustiveness):
every other `match ... .body { ... }` site in
`crates/wiremesh-relay/src/lib.rs`,
`crates/wiremesh-controller/tests/{keys,policy_pipeline,rebind,revoke_audit,relay_health,sync_relays,wg_pubkey_enrollment,drain,fail_static,report_local_endpoints,sync_delta,sync_snapshot,observe}.rs`,
and `crates/wiremesh-testkit/{src/lib.rs,tests/end_to_end_policy.rs}`.
`crates/wiremesh-controller/src/broker.rs` and `services/sync.rs`'s existing
`Body::Snapshot`/`Body::Delta` *construction* sites (not matches) needed no
change. `EnrollRequest` (in `enrollment.proto`) already had `wg_pubkey` and
`endpoint` fields from prior cycles — no change needed there.

## `wiremesh-proto` test output — 11/11 passing

Command: `./dev.sh run "cargo test -p wiremesh-proto -- --test-threads=1 --nocapture"`

```
running 11 tests
test delta_relay_infos_roundtrips_relay_info ... ok
test delta_relays_updated_roundtrips_true_and_false ... ok
test enroll_request_endpoint_roundtrips ... ok
test punch_directive_message_roundtrips ... ok
test report_request_epoch_acks_roundtrips ... ok
test report_request_local_endpoints_roundtrips ... ok
test report_request_relay_health_roundtrips ... ok
test rotate_directive_message_roundtrips ... ok
test snapshot_message_roundtrips ... ok
test state_snapshot_relay_infos_roundtrips_multiple_relay_infos ... ok
test submit_epoch_key_request_roundtrips ... ok

test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

## Workspace build result — exit code 0

Command: `./dev.sh run "cargo build --workspace"`

Tail of output:

```
   Compiling fabricctl v0.1.0 (/work/crates/fabricctl)
   Compiling wiremesh-enforcer-common v0.1.0 (/work/crates/wiremesh-enforcer-ebpf/common)
   Compiling rusqlite v0.32.1
   Compiling boringtun v0.6.0
   Compiling wiremesh-controller v0.1.0 (/work/crates/wiremesh-controller)
   Compiling wiremesh-testkit v0.1.0 (/work/crates/wiremesh-testkit)
   Compiling wiremesh-gateway v0.1.0 (/work/crates/wiremesh-gateway)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 2m 15s
```

No compiler errors anywhere in the workspace (the `wiremesh-enforcer`
eBPF-program build.rs also completed, in its own release profile, as part of
this same graph — unrelated warnings from that build script, no errors).

## Commit

`feat(proto): RotateDirective + SubmitEpochKey + Report.epoch_acks
(key-rotation Task 1)` — see `git log -1` in the worktree for the SHA.
