# WireMesh Controller Core (Cycle 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the WireMesh single-tenant controller to the "end-to-end against a stub gateway" done bar — a stub gateway can enroll (token → CSR → cert), open a Sync stream, receive a desired-state snapshot + deltas, ack revisions, and survive a controller restart with its existing cert.

**Architecture:** One cargo workspace. `wiremesh-proto` holds the gRPC wire contract (Enrollment/Sync/Admin + the `StateSnapshot`/`Delta` types the cycle-4 gateway will reuse). `wiremesh-trust` holds the `SecretStore`/`CertificateIssuer` provider seams + an embedded default (rcgen CA on disk, secrets in SQLite/files). `wiremesh-controller` is the binary (rusqlite data model, a revisioned per-gateway projection, three tonic services, route computation, key-epoch bookkeeping, audit, UDP observation). `fabricctl` is the admin CLI. `wiremesh-testkit` holds the stub gateway + integration harness. Built contract-first, then a thin vertical slice, then thickened.

**Tech Stack:** Rust stable, `tonic` + `prost` (gRPC, codegen via `build.rs`), `rustls 0.23` (mTLS, validated in Phase 0), `rcgen 0.13` (embedded CA, validated in Phase 0), `rusqlite` (embedded SQLite, `bundled` feature) behind a blocking-pool wrapper, `tokio`, `clap` (fabricctl), `serde`/`serde_yaml`/`serde_json`.

## Global Constraints

- **Design:** `docs/superpowers/specs/2026-07-16-controller-core-design.md`; master spec `docs/superpowers/specs/2026-07-15-wiremesh-engineering-design.md` (§3 trust, §4 controller) governs conflicts.
- **Build/test environment:** the `wiremesh-dev` container via `./dev.sh run "<cmd>"` from the repo root — the host has no Rust toolchain; the container ships stable Rust 1.97. Cycle 2 is pure userspace (no tun/eBPF/netns), so it does not *need* privilege — but `dev.sh` currently always passes `--privileged` for both `shell` and `run` (a broader default than cycle-2 requires; later phases needing tun/eBPF/netns do rely on it, so narrowing `dev.sh` itself is out of this cycle's scope, not a claim that the extra privilege is harmless). The suite is `./dev.sh run "cargo test --workspace"`; tests are not serial unless a task says so.
- **One cargo workspace** rooted at repo root; crates under `crates/`, proto sources under `proto/`. (This is a real product workspace — distinct from the Phase 0 spike's deliberately-standalone `spike/*` crates, which stay as-is.)
- **The wire contract lives in `wiremesh-proto`.** `StateSnapshot`/`Delta`/all RPC messages are proto-defined there so the cycle-4 gateway consumes byte-identical types. Never hand-roll these in the controller.
- **CA private key never enters SQLite** — it is a separate `0600` file (`<data-dir>/ca.key`). Secrets and key material on disk are `0600`. WireGuard/CA private keys, tokens, and secrets never serialize into logs.
- **v1 is IPv4-only** — CIDRs are validated IPv4 (`ipnet::Ipv4Net`).
- **CIDR-overlap invariant (C-2)** is enforced in exactly one DB helper, inside the mutating transaction; rejects name the conflicting segment.
- **Tests are written by a different agent than the code under test; reviews by a different agent than the author** (WireMesh CLAUDE.md). The stub gateway and integration harness in `wiremesh-testkit` are neutral test infrastructure (they are *not* the code under test — the controller is), so an implementer may build them; the controller-behavior tests that use them are test-author work.
- **Tests must pass before any done-claim; fix code, never bend tests.**
- Commit after every green test cycle. Commit messages end with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- **API-drift note:** `tonic`/`rusqlite` exact APIs were **not** validated in Phase 0 (only rustls/rcgen/quinn were). Where a code block below hits a `tonic`/`rusqlite`/`prost` API that has drifted, adapting it against the current crate docs **is expected implementation work** (as aya/boringtun drift was in Phase 0) — fix against docs, keep the behavior the test asserts, and record any notable friction in the task report.

## File Structure (end state)

```
Cargo.toml                                  # [workspace] members
proto/
  wiremesh/v1/enrollment.proto              # Enroll
  wiremesh/v1/sync.proto                    # Watch (stream), Report, StateSnapshot, Delta
  wiremesh/v1/admin.proto                   # CRUD: segments, gateways, relays, tokens, policy, audit, drain
crates/
  wiremesh-proto/{Cargo.toml,build.rs,src/lib.rs}
  wiremesh-trust/{Cargo.toml,src/lib.rs}    # traits + embedded default (CA, secret store)
  wiremesh-controller/
    Cargo.toml
    src/main.rs                             # wire-up: open DB, load/create CA, serve TCP+UDS+UDP
    src/db.rs                               # rusqlite pool, migrations, schema, overlap guard, audit-append
    src/projection.rs                       # revisioned per-gateway desired state; snapshot/delta build
    src/services/enrollment.rs
    src/services/sync.rs
    src/services/admin.rs
    src/routes.rs                           # full-mesh peer computation
    src/keys.rs                             # GATEWAY_KEY epoch state machine
    src/observe.rs                          # UDP observation endpoint
    src/apply.rs                            # declarative apply -f diff engine
  fabricctl/{Cargo.toml,src/main.rs}        # clap CLI over Admin (bearer/UDS)
  wiremesh-testkit/{Cargo.toml,src/lib.rs} # stub gateway + harness helpers
```

---

## PHASE 1 — Contract-first

### Task 1: Workspace + `wiremesh-proto` (wire contract)

**Files:**
- Create: `Cargo.toml` (workspace)
- Create: `proto/wiremesh/v1/enrollment.proto`, `proto/wiremesh/v1/sync.proto`, `proto/wiremesh/v1/admin.proto`
- Create: `crates/wiremesh-proto/{Cargo.toml,build.rs,src/lib.rs}`
- Test: `crates/wiremesh-proto/tests/codegen.rs`

**Interfaces:**
- Produces: the `wiremesh_proto` crate re-exporting generated modules `wiremesh.v1` types: `EnrollRequest{token, csr_pem, cidrs}`, `EnrollResponse{cert_pem, ca_bundle_pem}`; `WatchRequest{}`, `SyncMessage{oneof{StateSnapshot, Delta}}`, `StateSnapshot{revision, self_cert_pem, peers[], routes[], relays[], policy_ir, policy_version, revoked_serials[]}`, `Delta{revision, ...}`, `ReportRequest{applied_version}`; Admin messages `CreateSegmentRequest`, `MintTokenRequest`, etc. Later tasks import these as `use wiremesh_proto::v1::*`.

- [ ] **Step 1: Workspace manifest**

```toml
# Cargo.toml (repo root)
[workspace]
resolver = "2"
members = ["crates/wiremesh-proto", "crates/wiremesh-trust", "crates/wiremesh-controller", "crates/fabricctl", "crates/wiremesh-testkit"]

[workspace.dependencies]
tokio = { version = "1", features = ["full"] }
tonic = { version = "0.12", features = ["tls"] }
prost = "0.13"
rustls = "0.23"
rcgen = "0.13"
rusqlite = { version = "0.32", features = ["bundled"] }
anyhow = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
ipnet = "2"
```

(Create empty `src/lib.rs` + minimal `Cargo.toml` for the other four members so the workspace resolves; they are filled by later tasks. `wiremesh-proto/Cargo.toml` depends on `tonic`, `prost`; `[build-dependencies] tonic-build = "0.12"`.)

- [ ] **Step 2: Write the `.proto` contract**

```proto
// proto/wiremesh/v1/sync.proto
syntax = "proto3";
package wiremesh.v1;

service Sync {
  rpc Watch(WatchRequest) returns (stream SyncMessage);
  rpc Report(ReportRequest) returns (ReportResponse);
}
message WatchRequest {}
message SyncMessage { oneof body { StateSnapshot snapshot = 1; Delta delta = 2; } }
message PeerKey { uint32 epoch = 1; string pubkey = 2; string state = 3; } // pending|active|retiring
message Peer {
  uint64 gateway_id = 1;
  string segment_name = 2;
  repeated PeerKey keys = 3;
  repeated string candidate_endpoints = 4;
  repeated string allowed_ips = 5;      // peer segment CIDRs
}
message StateSnapshot {
  uint64 revision = 1;
  string self_cert_pem = 2;
  repeated Peer peers = 3;
  repeated string relays = 4;
  bytes policy_ir = 5;                    // empty IR v0 in cycle 2
  uint64 policy_version = 6;
  repeated string revoked_serials = 7;
}
message Delta { uint64 revision = 1; repeated Peer upserted_peers = 2; repeated uint64 removed_peer_ids = 3; repeated string relays = 4; bytes policy_ir = 5; uint64 policy_version = 6; repeated string revoked_serials = 7; }
message ReportRequest { uint64 applied_version = 1; }
message ReportResponse {}
```

```proto
// proto/wiremesh/v1/enrollment.proto
syntax = "proto3";
package wiremesh.v1;
service Enrollment { rpc Enroll(EnrollRequest) returns (EnrollResponse); }
message EnrollRequest { string token = 1; string csr_pem = 2; repeated string cidrs = 3; }
message EnrollResponse { string cert_pem = 1; string ca_bundle_pem = 2; }
```

```proto
// proto/wiremesh/v1/admin.proto  (cycle-2 subset; grown in Task 13/14)
syntax = "proto3";
package wiremesh.v1;
service Admin {
  rpc CreateSegment(CreateSegmentRequest) returns (Segment);
  rpc MintToken(MintTokenRequest) returns (MintTokenResponse);
  rpc ListGateways(ListGatewaysRequest) returns (ListGatewaysResponse);
}
message CreateSegmentRequest { string name = 1; repeated string cidrs = 2; }
message Segment { uint64 id = 1; string name = 2; repeated string cidrs = 3; }
message MintTokenRequest { string kind = 1; repeated string bound_cidrs = 2; uint64 rebind_segment_id = 3; }
message MintTokenResponse { string token = 1; }   // wiremesh://host/#tok...@sha256:...
message ListGatewaysRequest {}
message ListGatewaysResponse { repeated GatewayInfo gateways = 1; }
message GatewayInfo { uint64 id = 1; string name = 2; string segment = 3; string status = 4; uint64 applied_version = 5; }
```

- [ ] **Step 3: Codegen `build.rs` + lib re-export**

```rust
// crates/wiremesh-proto/build.rs
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure().build_server(true).build_client(true).compile_protos(
        &["../../proto/wiremesh/v1/enrollment.proto",
          "../../proto/wiremesh/v1/sync.proto",
          "../../proto/wiremesh/v1/admin.proto"],
        &["../../proto"],
    )?;
    Ok(())
}
```

```rust
// crates/wiremesh-proto/src/lib.rs
pub mod v1 { tonic::include_proto!("wiremesh.v1"); }
```

- [ ] **Step 4: Write the failing test**

```rust
// crates/wiremesh-proto/tests/codegen.rs
use wiremesh_proto::v1::{StateSnapshot, Peer, sync_message::Body, SyncMessage};

#[test]
fn snapshot_message_roundtrips() {
    let snap = StateSnapshot { revision: 7, self_cert_pem: "PEM".into(),
        peers: vec![Peer { gateway_id: 2, segment_name: "aws".into(), ..Default::default() }],
        relays: vec!["r1:4443".into()], policy_ir: vec![], policy_version: 0,
        revoked_serials: vec![] };
    let msg = SyncMessage { body: Some(Body::Snapshot(snap.clone())) };
    // prost messages derive PartialEq + Clone; assert the oneof carries the snapshot
    match msg.body { Some(Body::Snapshot(s)) => assert_eq!(s.revision, 7), _ => panic!("wrong body") };
    assert_eq!(snap.peers[0].gateway_id, 2);
}
```

- [ ] **Step 5: Run to fail, then build codegen to green**

Run: `cargo test -p wiremesh-proto`
Expected first: FAIL (crate/types absent) → after Steps 1–3, PASS. (If `tonic-build`'s method name differs, e.g. `compile()` vs `compile_protos()`, adapt against `tonic-build` docs — that IS the work.)

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml proto crates/wiremesh-proto crates/*/Cargo.toml crates/*/src/lib.rs
git commit -m "feat(controller): workspace + wiremesh-proto wire contract"
```

---

### Task 2: `wiremesh-trust` — provider seams + embedded default

**Files:**
- Create: `crates/wiremesh-trust/{Cargo.toml,src/lib.rs}`
- Test: `crates/wiremesh-trust/tests/embedded.rs`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `trait CertificateIssuer` (async, object-safe): `async fn trust_bundle(&self) -> Result<String /*PEM, ≥1 roots*/>`; `async fn sign(&self, csr_pem: &str, profile: CertProfile) -> Result<IssuedCert>`; `async fn revoke(&self, handle: &IssuerHandle) -> Result<()>`.
  - `trait SecretStore` (async): `async fn get(&self, key: &str) -> Result<Option<Versioned>>`; `async fn put(&self, key: &str, value: Vec<u8>) -> Result<u64 /*version*/>`.
  - `struct IssuedCert { cert_pem: String, serial: String, not_after: OffsetDateTime, handle: IssuerHandle }`; `struct CertProfile { subject_cn: String, ttl: Duration }`; `type IssuerHandle = String` (opaque).
  - `struct EmbeddedTrust` with `EmbeddedTrust::open(data_dir: &Path) -> Result<Self>` — creates/loads the CA (`<data_dir>/ca.key` 0600, `<data_dir>/ca.pem`), implements both traits. Secrets go to `<data_dir>/secrets/<key>` (0600).

- [ ] **Step 1: Write the failing test**

```rust
// crates/wiremesh-trust/tests/embedded.rs
use wiremesh_trust::{EmbeddedTrust, CertificateIssuer, CertProfile};
use std::time::Duration;

#[tokio::test]
async fn embedded_ca_signs_a_csr_that_chains_to_the_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let trust = EmbeddedTrust::open(dir.path()).unwrap();
    // a gateway generates its own keypair + CSR (rcgen)
    let kp = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
    params.distinguished_name.push(rcgen::DnType::CommonName, "gw-aws");
    let csr = params.serialize_request(&kp).unwrap().pem().unwrap();

    let issued = trust.sign(&csr, CertProfile { subject_cn: "gw-aws".into(), ttl: Duration::from_secs(90*24*3600) }).await.unwrap();
    assert!(issued.cert_pem.contains("BEGIN CERTIFICATE"));
    assert!(!issued.serial.is_empty());

    // the leaf verifies against the trust bundle
    let bundle = trust.trust_bundle().await.unwrap();
    assert!(verify_chains(&issued.cert_pem, &bundle), "leaf must chain to CA bundle");
    // CA private key must NOT be inside the bundle
    assert!(!bundle.contains("PRIVATE KEY"));
    // CA key file is 0600
    let mode = std::fs::metadata(dir.path().join("ca.key")).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "ca.key must be 0600");
}
```

(Helper `verify_chains` uses `rustls`/`webpki` to validate; the test author writes it. `use std::os::unix::fs::PermissionsExt;`)

- [ ] **Step 2: Run to fail**

Run: `cargo test -p wiremesh-trust`
Expected: FAIL (crate absent).

- [ ] **Step 3: Implement embedded default**

```rust
// crates/wiremesh-trust/src/lib.rs  (sketch — adapt rcgen 0.13 API, validated in Phase 0)
use anyhow::Result; use std::path::Path; use std::time::Duration;
use async_trait::async_trait;

pub type IssuerHandle = String;
pub struct IssuedCert { pub cert_pem: String, pub serial: String, pub not_after: time::OffsetDateTime, pub handle: IssuerHandle }
pub struct CertProfile { pub subject_cn: String, pub ttl: Duration }
pub struct Versioned { pub version: u64, pub value: Vec<u8> }

#[async_trait] pub trait CertificateIssuer: Send + Sync {
    async fn trust_bundle(&self) -> Result<String>;
    async fn sign(&self, csr_pem: &str, profile: CertProfile) -> Result<IssuedCert>;
    async fn revoke(&self, handle: &IssuerHandle) -> Result<()>;
}
#[async_trait] pub trait SecretStore: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<Versioned>>;
    async fn put(&self, key: &str, value: Vec<u8>) -> Result<u64>;
}

pub struct EmbeddedTrust { data_dir: std::path::PathBuf, ca_pem: String, ca_key_pem: String }
impl EmbeddedTrust {
    pub fn open(data_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let (ca_pem, ca_key_pem) = load_or_create_ca(data_dir)?;   // rcgen self-signed CA; write ca.pem + ca.key(0600)
        Ok(Self { data_dir: data_dir.into(), ca_pem, ca_key_pem })
    }
}
// impl CertificateIssuer: sign() parses the CSR (rcgen CertificateSigningRequestParams::from_pem),
//   signs it with the CA keypair for profile.ttl, returns leaf PEM + a serial + not_after + handle=serial.
// impl SecretStore: get/put read/write <data_dir>/secrets/<key> (0600) with a sidecar version counter.
```

(Add deps: `async-trait`, `rcgen`, `time`, `anyhow`, and `tempfile`+`rustls`/`webpki` as dev-deps. `load_or_create_ca` + the trait impls are the implementer's work; the CSR-signing path mirrors Phase 0's `spike/relay/src/bin/mkcerts.rs`.)

- [ ] **Step 4: Run to green, then commit**

Run: `cargo test -p wiremesh-trust` → PASS.
```bash
git add crates/wiremesh-trust && git commit -m "feat(controller): trust seams + embedded CA/secret default"
```

---

### Task 3: `db` module — rusqlite, migrations, schema v1, overlap guard, audit-append

**Files:**
- Create: `crates/wiremesh-controller/Cargo.toml`, `crates/wiremesh-controller/src/db.rs`, `crates/wiremesh-controller/src/lib.rs` (re-export `db`)
- Test: `crates/wiremesh-controller/tests/db.rs`

**Interfaces:**
- Produces:
  - `struct Db` with `Db::open(path: &Path) -> Result<Db>` (runs migrations), `Db::open_memory()`.
  - `fn insert_segment(&self, name: &str, cidrs: &[Ipv4Net]) -> Result<i64>` — runs the overlap check inside the txn; on overlap returns `Err(OverlapError { conflicting_segment })`.
  - `fn audit(&self, actor: &str, action: &str, entity: &str, diff_json: &str) -> Result<()>`.
  - Schema = master-spec §4.1 (all tables). Migrations keyed on `PRAGMA user_version` (0 → 1 creates all).
  - All calls are synchronous rusqlite; a later task wraps them for async.

- [ ] **Step 1: Write the failing test**

```rust
// crates/wiremesh-controller/tests/db.rs
use wiremesh_controller::db::{Db, OverlapError};
use ipnet::Ipv4Net; use std::str::FromStr;

#[test]
fn migration_is_idempotent_and_sets_user_version() {
    let db = Db::open_memory().unwrap();
    assert_eq!(db.user_version().unwrap(), 1);
    db.run_migrations().unwrap(); // second run is a no-op
    assert_eq!(db.user_version().unwrap(), 1);
}

#[test]
fn overlapping_cidr_is_rejected_naming_the_conflict() {
    let db = Db::open_memory().unwrap();
    db.insert_segment("aws", &[Ipv4Net::from_str("10.0.0.0/16").unwrap()]).unwrap();
    let err = db.insert_segment("gcp", &[Ipv4Net::from_str("10.0.5.0/24").unwrap()]).unwrap_err();
    let overlap = err.downcast::<OverlapError>().unwrap();
    assert_eq!(overlap.conflicting_segment, "aws");
    // non-overlapping is accepted
    db.insert_segment("lab", &[Ipv4Net::from_str("192.168.0.0/24").unwrap()]).unwrap();
}

#[test]
fn audit_row_is_appended() {
    let db = Db::open_memory().unwrap();
    db.audit("token:ci", "create", "segment/aws", r#"{"name":"aws"}"#).unwrap();
    assert_eq!(db.count_audit().unwrap(), 1);
}
```

- [ ] **Step 2: Run to fail**

Run: `cargo test -p wiremesh-controller --test db`
Expected: FAIL (module absent).

- [ ] **Step 3: Implement `db.rs`**

Implement `Db` over `rusqlite::Connection`. `run_migrations()` reads `PRAGMA user_version`; if `< 1`, executes the schema DDL (all §4.1 tables) in a transaction and sets `PRAGMA user_version = 1`. `insert_segment` opens a transaction, inserts the segment row, then for each CIDR checks overlap against every existing `cidr` row (parse both as `Ipv4Net`, overlap = one contains the other's network or they intersect: `a.contains(&b.network()) || b.contains(&a.network())`), and on conflict rolls back and returns `OverlapError{conflicting_segment}` (via `anyhow::Error`). `audit` inserts into `audit_log`. IPv4 only — reject non-IPv4 CIDR strings.

- [ ] **Step 4: Run to green, then commit**

Run: `cargo test -p wiremesh-controller --test db` → PASS (3 tests).
```bash
git add crates/wiremesh-controller && git commit -m "feat(controller): sqlite schema, migrations, CIDR overlap guard, audit"
```

---

## PHASE 2 — Vertical slice

### Task 4: `Admin` service (minimal) + Unix socket + async DB wrapper

**Files:**
- Create: `crates/wiremesh-controller/src/db_async.rs` (blocking-pool wrapper), `crates/wiremesh-controller/src/services/admin.rs`, `crates/wiremesh-controller/src/services/mod.rs`
- Modify: `crates/wiremesh-controller/src/main.rs` (serve Admin on a Unix socket)
- Test: `crates/wiremesh-controller/tests/admin.rs`

**Interfaces:**
- Consumes: `db::Db`, `wiremesh_proto::v1::admin_server::{Admin, AdminServer}`, `CreateSegmentRequest`, `MintTokenRequest`.
- Produces: `AdminSvc` implementing `CreateSegment` (persists segment+CIDRs, audits) and `MintToken` (generates a token secret, stores its sha256 hash + kind + bound_cidrs in `enrollment_token`, returns the `wiremesh://…#tok_…@sha256:<root-fp>` string). Server bound on a Unix socket at `<run-dir>/controller.sock` (0700 dir). Also `DbHandle` — an async wrapper running `Db` calls on `tokio::task::spawn_blocking` behind a `Mutex<Db>` (single connection is fine for cycle-2 volume).

- [ ] **Step 1: Write the failing test**

```rust
// crates/wiremesh-controller/tests/admin.rs
// Spins the Admin service on a Unix socket in a tempdir; connects a tonic client over UDS.
use wiremesh_proto::v1::{admin_client::AdminClient, CreateSegmentRequest, MintTokenRequest};

#[tokio::test]
async fn create_segment_and_mint_token_over_uds() {
    let h = wiremesh_testkit::TestController::start().await; // Task 8 provides this; here a local helper
    let mut admin = h.admin_client().await;
    let seg = admin.create_segment(CreateSegmentRequest { name: "aws".into(), cidrs: vec!["10.0.0.0/16".into()] })
        .await.unwrap().into_inner();
    assert_eq!(seg.name, "aws");
    let tok = admin.mint_token(MintTokenRequest { kind: "gateway".into(), bound_cidrs: vec!["10.0.0.0/16".into()], rebind_segment_id: 0 })
        .await.unwrap().into_inner();
    assert!(tok.token.starts_with("wiremesh://"));
    assert!(tok.token.contains("@sha256:"));
}
```

- [ ] **Step 2: Run to fail** — `cargo test -p wiremesh-controller --test admin` → FAIL (svc/harness absent).

- [ ] **Step 3: Implement** the async DB wrapper, `AdminSvc`, and Unix-socket serving in `main.rs` (`tonic` over a `UnixListener`; see tonic UDS example — adapt against docs). `MintToken` generates 32 random bytes → base64 secret → store `sha256(secret)`; the returned token embeds the secret and the CA root fingerprint. A minimal `TestController` harness helper may live inline in the test until Task 8 formalizes it in `wiremesh-testkit`.

- [ ] **Step 4: Run to green** → PASS. **Step 5: Commit** `feat(controller): admin CreateSegment/MintToken over unix socket`.

---

### Task 5: `Enrollment` service — token → CSR → cert

**Files:**
- Create: `crates/wiremesh-controller/src/services/enrollment.rs`
- Modify: `main.rs` (serve Enrollment on the TCP port, server-TLS only), `src/services/mod.rs`
- Test: `crates/wiremesh-controller/tests/enroll.rs`

**Interfaces:**
- Consumes: `db::Db` (token lookup + cert record), `wiremesh_trust::CertificateIssuer`, `EnrollRequest`, `EnrollResponse`.
- Produces: `EnrollmentSvc` implementing `Enroll` — validates the token (sha256 of presented secret matches a stored, unexpired, unused row of the right kind), runs the CIDR overlap check for the declared CIDRs (rebind tokens exempt their segment — Task 10), signs a 90-day cert via `CertificateIssuer::sign`, records it in `certificate` with the opaque `issuer_handle`, marks the token `used_at`, audits, and returns `{cert_pem, ca_bundle_pem}`. Enforces single-use atomically in one transaction.

- [ ] **Step 1: Write the failing test**

```rust
// crates/wiremesh-controller/tests/enroll.rs
use wiremesh_proto::v1::{enrollment_client::EnrollmentClient, EnrollRequest, admin_client::AdminClient, CreateSegmentRequest, MintTokenRequest};

#[tokio::test]
async fn enroll_issues_cert_then_token_is_single_use() {
    let h = wiremesh_testkit::TestController::start().await;
    let mut admin = h.admin_client().await;
    admin.create_segment(CreateSegmentRequest { name: "aws".into(), cidrs: vec!["10.0.0.0/16".into()] }).await.unwrap();
    let tok = admin.mint_token(MintTokenRequest { kind: "gateway".into(), bound_cidrs: vec!["10.0.0.0/16".into()], rebind_segment_id: 0 }).await.unwrap().into_inner().token;

    let (csr, _kp) = wiremesh_testkit::gen_csr("gw-aws");
    let mut enr = h.enrollment_client().await;
    let resp = enr.enroll(EnrollRequest { token: tok.clone(), csr_pem: csr.clone(), cidrs: vec!["10.0.0.0/16".into()] }).await.unwrap().into_inner();
    assert!(resp.cert_pem.contains("BEGIN CERTIFICATE"));
    assert!(resp.ca_bundle_pem.contains("BEGIN CERTIFICATE"));

    // token is now spent — a second enroll fails
    let err = enr.enroll(EnrollRequest { token: tok, csr_pem: csr, cidrs: vec!["10.0.0.0/16".into()] }).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}
```

- [ ] **Step 2: Run to fail** → FAIL. **Step 3: Implement** `EnrollmentSvc` + serve on TCP with server TLS (rustls; the Enrollment port presents the relay/controller server cert, no client cert required — mTLS begins at Sync). **Step 4: green.** **Step 5: Commit** `feat(controller): enrollment issues single-use certs`.

---

### Task 6: Stub gateway — enroll (`wiremesh-testkit`)

**Files:**
- Create: `crates/wiremesh-testkit/{Cargo.toml,src/lib.rs}` (`TestController`, `gen_csr`, `StubGateway`)
- Test: `crates/wiremesh-testkit/tests/stub_enroll.rs`

**Interfaces:**
- Produces:
  - `TestController::start() -> TestController` — boots a controller (temp data-dir, embedded trust, random TCP port + UDS), exposing `.admin_client()`, `.enrollment_client()`, `.sync_endpoint()`, `.data_dir()`, `.restart()`.
  - `gen_csr(cn: &str) -> (String /*csr pem*/, rcgen::KeyPair)`.
  - `StubGateway::enroll(controller: &TestController, token: &str, cidrs: &[&str]) -> StubGateway` — enrolls, holds its cert + key + CA bundle, persists them under a temp state dir.

- [ ] **Step 1: Write the failing test**

```rust
// crates/wiremesh-testkit/tests/stub_enroll.rs
#[tokio::test]
async fn stub_gateway_enrolls_and_holds_a_cert() {
    let h = wiremesh_testkit::TestController::start().await;
    let mut admin = h.admin_client().await;
    admin.create_segment(wiremesh_proto::v1::CreateSegmentRequest { name: "aws".into(), cidrs: vec!["10.0.0.0/16".into()] }).await.unwrap();
    let tok = admin.mint_token(wiremesh_proto::v1::MintTokenRequest { kind: "gateway".into(), bound_cidrs: vec!["10.0.0.0/16".into()], rebind_segment_id: 0 }).await.unwrap().into_inner().token;
    let gw = wiremesh_testkit::StubGateway::enroll(&h, &tok, &["10.0.0.0/16"]).await.unwrap();
    assert!(gw.cert_pem().contains("BEGIN CERTIFICATE"));
    assert!(gw.ca_bundle_pem().contains("BEGIN CERTIFICATE"));
}
```

- [ ] **Step 2: Run to fail** → FAIL. **Step 3: Implement** `TestController` (wraps the controller wire-up from `main.rs` as a library entrypoint `wiremesh_controller::serve(config) -> Handle` so tests boot it in-process — refactor `main.rs` to call a `lib` `run()` ), `gen_csr`, and `StubGateway::enroll`. **Step 4: green.** **Step 5: Commit** `feat(testkit): controller test harness + stub gateway enrollment`.

---

### Task 7: Projection + `Sync.Watch` snapshot (mTLS)

**Files:**
- Create: `crates/wiremesh-controller/src/projection.rs`, `crates/wiremesh-controller/src/routes.rs`, `crates/wiremesh-controller/src/services/sync.rs`
- Modify: `main.rs` (serve Sync on the TCP port with **mTLS: client cert required, chaining to the CA**)
- Test: `crates/wiremesh-controller/tests/sync_snapshot.rs`

**Interfaces:**
- Consumes: `db::Db`, trust bundle, the enrolled client cert (mTLS identifies the gateway).
- Produces: `fn build_snapshot(db, gateway_id) -> StateSnapshot` — peers = full-mesh over *other* gateways (Task with `routes::peers_of`), allowed-ips = each peer segment's CIDRs, relays list, `policy_ir = vec![]` (empty v0), `policy_version = 0`, revoked serials from `certificate WHERE revoked_at NOT NULL`, monotonic `revision`. `SyncSvc::watch` streams the snapshot on connect. `StubGateway::open_sync(&self) -> impl Stream<Item=SyncMessage>` added to testkit.

- [ ] **Step 1: Write the failing test**

```rust
// crates/wiremesh-controller/tests/sync_snapshot.rs
#[tokio::test]
async fn single_gateway_receives_a_full_snapshot() {
    let h = wiremesh_testkit::TestController::start().await;
    let gw = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await; // helper: create seg+token+enroll
    let mut stream = gw.open_sync().await;
    let msg = stream.next().await.unwrap().unwrap();
    let snap = match msg.body { Some(wiremesh_proto::v1::sync_message::Body::Snapshot(s)) => s, _ => panic!("expected snapshot") };
    assert_eq!(snap.policy_version, 0);
    assert!(snap.peers.is_empty(), "only gateway -> no peers");
    assert!(!snap.self_cert_pem.is_empty());
    assert!(snap.revision >= 1);
}
```

- [ ] **Step 2: Run to fail** → FAIL. **Step 3: Implement** projection/routes/sync + mTLS Sync server (`tonic` `ServerTlsConfig` with `client_ca_root` = CA bundle; extract the peer cert CN → gateway identity — adapt against tonic TLS-peer-identity docs). **Step 4: green.** **Step 5: Commit** `feat(controller): sync projection + mTLS snapshot stream`.

---

### Task 8: `Sync` deltas + `Report` acks (2nd gateway → delta)

**Files:**
- Modify: `crates/wiremesh-controller/src/projection.rs` (delta fan-out via per-connection `tokio::sync::broadcast`), `src/services/sync.rs` (implement `Report`), `src/services/admin.rs` (mutations publish deltas)
- Test: `crates/wiremesh-controller/tests/sync_delta.rs`

**Interfaces:**
- Produces: on any projection-affecting mutation, connected gateways receive a `Delta` with new revision; `Report{applied_version}` records `policy_status` and updates `gateway.applied_version`. `revision` is monotonic per gateway.

- [ ] **Step 1: Write the failing test**

```rust
// crates/wiremesh-controller/tests/sync_delta.rs
#[tokio::test]
async fn second_gateway_triggers_a_delta_to_the_first() {
    let h = wiremesh_testkit::TestController::start().await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    let mut a_stream = a.open_sync().await;
    let _snap_a = a_stream.next().await.unwrap().unwrap(); // initial snapshot

    // enrolling a 2nd gateway must push a delta to A adding B as a peer
    let _b = wiremesh_testkit::enroll_one(&h, "gcp", "10.1.0.0/16").await;
    let msg = tokio::time::timeout(std::time::Duration::from_secs(3), a_stream.next()).await.unwrap().unwrap().unwrap();
    let delta = match msg.body { Some(wiremesh_proto::v1::sync_message::Body::Delta(d)) => d, _ => panic!("expected delta") };
    assert_eq!(delta.upserted_peers.len(), 1);
    assert_eq!(delta.upserted_peers[0].segment_name, "gcp");
    assert!(delta.revision > _snap_a_revision(&_snap_a));
}
```

- [ ] **Step 2: Run to fail** → FAIL. **Step 3: Implement** broadcast fan-out + `Report`. **Step 4: green.** **Step 5: Commit** `feat(controller): sync deltas on mutation + report acks`.

---

### Task 9: Fail-static / restore integration test

**Files:**
- Modify: `crates/wiremesh-testkit/src/lib.rs` (`StubGateway::persist_state`, `reconnect`; `TestController::restart` reopens the *same* data-dir)
- Test: `crates/wiremesh-controller/tests/fail_static.rs`

**Interfaces:**
- Produces: proof of C-7 — after a controller restart against the same SQLite + CA key dir, an already-enrolled gateway reconnects **with its existing cert** and resyncs by revision, no re-enrollment.

- [ ] **Step 1: Write the failing test**

```rust
// crates/wiremesh-controller/tests/fail_static.rs
#[tokio::test]
async fn gateway_resyncs_after_controller_restart_without_reenrolling() {
    let mut h = wiremesh_testkit::TestController::start().await;
    let gw = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    { let mut s = gw.open_sync().await; let _ = s.next().await.unwrap().unwrap(); }   // got snapshot
    gw.persist_state();                          // gateway writes its bundle to disk (fail-static)

    h.restart().await;                           // same data-dir + ca.key; controller comes back up

    // reconnect with the SAME cert — must succeed (no re-enroll) and yield a fresh snapshot
    let mut s2 = gw.reconnect(&h).await.unwrap();
    let msg = s2.next().await.unwrap().unwrap();
    assert!(matches!(msg.body, Some(wiremesh_proto::v1::sync_message::Body::Snapshot(_))));
}
```

- [ ] **Step 2: Run to fail** → FAIL. **Step 3: Implement** persistence/reconnect + `restart`. **Step 4: green — the vertical slice is now proven.** **Step 5: Commit** `test(controller): fail-static restore — resync without re-enrollment`.

---

## PHASE 3 — Thicken

### Task 10: Rebind tokens (gateway replacement)

**Files:** Modify `src/services/enrollment.rs`, `src/db.rs` (overlap exemption for rebind segment), `src/services/admin.rs` (mint `kind=rebind`). Test: `crates/wiremesh-controller/tests/rebind.rs`.

**Interfaces:** Produces: a `rebind` token bound to an existing `segment_id` enrolls a replacement gateway **without** tripping the self-overlap check, and revokes the replaced gateway's old cert (pushing its serial onto the denylist).

- [ ] **Step 1: Failing test**

```rust
// tests/rebind.rs
#[tokio::test]
async fn rebind_replaces_gateway_without_overlap_and_revokes_old_cert() {
    let h = wiremesh_testkit::TestController::start().await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await; // original gateway for segment aws
    let old_serial = a.cert_serial();
    let seg_id = a.segment_id();
    let mut admin = h.admin_client().await;
    let tok = admin.mint_token(wiremesh_proto::v1::MintTokenRequest { kind: "rebind".into(), bound_cidrs: vec![], rebind_segment_id: seg_id }).await.unwrap().into_inner().token;
    // replacement enrolls with the SAME segment CIDRs — must NOT be rejected as overlap
    let b = wiremesh_testkit::StubGateway::enroll(&h, &tok, &["10.0.0.0/16"]).await.unwrap();
    assert_ne!(b.cert_serial(), old_serial);
    // old cert serial is now on the revoked denylist (visible in a fresh snapshot)
    let mut s = b.open_sync().await; let snap = expect_snapshot(s.next().await);
    assert!(snap.revoked_serials.contains(&old_serial));
}
```

- [ ] **Steps 2–5:** run-fail → implement (rebind branch exempts `rebind_segment_id`'s CIDR rows; revoke old cert via `CertificateIssuer::revoke` + `revoked_at`) → green → commit `feat(controller): rebind tokens replace a gateway and revoke the old cert`.

---

### Task 11: Key-epoch lifecycle bookkeeping

**Files:** Create `src/keys.rs`; modify `src/services/admin.rs` (a `RotateKey` admin op), `src/projection.rs` (emit peer key states), testkit stub acks epoch transitions. Test: `crates/wiremesh-controller/tests/keys.rs`.

**Interfaces:** Produces: `RotateKey(gateway_id)` inserts a `pending` `GATEWAY_KEY(epoch=n+1)`, deltas peers with the new pubkey in `pending`; the stub gateway acks n+1 in use → controller marks n+1 `active`, n `retiring`, then removes n. A controller restart mid-rotation resumes state from the DB snapshot.

- [ ] **Step 1: Failing test**

```rust
// tests/keys.rs
#[tokio::test]
async fn key_rotation_advances_epoch_states_and_survives_restart() {
    let mut h = wiremesh_testkit::TestController::start().await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    let b = wiremesh_testkit::enroll_one(&h, "gcp", "10.1.0.0/16").await; // peer that observes A's keys
    let mut b_stream = b.open_sync().await; let _ = b_stream.next().await; // snapshot

    h.admin_client().await.rotate_key(wiremesh_proto::v1::RotateKeyRequest { gateway_id: a.id() }).await.unwrap();
    // B sees A gain a pending epoch key
    let d = expect_delta(b_stream.next().await);
    let a_peer = d.upserted_peers.iter().find(|p| p.gateway_id == a.id()).unwrap();
    assert!(a_peer.keys.iter().any(|k| k.state == "pending"));

    // restart mid-rotation: the pending epoch is still present (resumed from DB)
    h.restart().await;
    let states = h.debug_key_states(a.id()).await; // testkit reads GATEWAY_KEY via admin/debug
    assert!(states.iter().any(|(_, st)| st == "pending"));
}
```

(Requires adding `RotateKey` to `admin.proto` — grow the proto in this task.)

- [ ] **Steps 2–5:** run-fail → implement the state machine → green → commit `feat(controller): per-gateway key-epoch rotation bookkeeping`.

---

### Task 12: Drain + route withdrawal (G-7)

**Files:** Modify `src/services/admin.rs` (`Drain`), `src/routes.rs`/`src/projection.rs` (withdraw peer, ack-wait 5s). Test: `crates/wiremesh-controller/tests/drain.rs`.

**Interfaces:** Produces: `Drain(gateway_id)` marks it `draining`, deltas a `removed_peer_ids` withdrawal to every peer, waits for acks (or 5s), then removes the gateway and revokes its cert.

- [ ] **Step 1: Failing test**

```rust
// tests/drain.rs
#[tokio::test]
async fn drain_withdraws_the_gateway_from_its_peers() {
    let h = wiremesh_testkit::TestController::start().await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    let b = wiremesh_testkit::enroll_one(&h, "gcp", "10.1.0.0/16").await;
    let mut a_stream = a.open_sync().await; let _ = a_stream.next().await; // snapshot (has B as peer)
    h.admin_client().await.drain(wiremesh_proto::v1::DrainRequest { gateway_id: b.id() }).await.unwrap();
    let d = expect_delta(a_stream.next().await);
    assert!(d.removed_peer_ids.contains(&b.id()));
    // B's gateway row is gone and its cert revoked
    assert!(!h.gateway_exists(b.id()).await);
}
```

- [ ] **Steps 2–5:** run-fail → implement → green → commit `feat(controller): drain withdraws routes and revokes the gateway`.

---

### Task 13: Full Admin CRUD + `fabricctl` imperative CLI + auth

**Files:** Grow `admin.proto` (list/get/delete segments; relays register/list; API-token mint/revoke; audit query; policy status); implement in `src/services/admin.rs`; add bearer-token auth interceptor (`API_TOKEN` role `admin`/`read-only`) on the TCP Admin port (UDS stays implicit-admin). Create `crates/fabricctl/{Cargo.toml,src/main.rs}`. Test: `crates/fabricctl/tests/cli.rs` + `crates/wiremesh-controller/tests/admin_auth.rs`.

**Interfaces:** Produces: `fabricctl` (clap) subcommands `segment {create,list,rm}`, `gateway {list,drain}`, `relay {register,list}`, `token {mint,revoke}`, `audit query`, `status`; connects via `--token <bearer>` over TCP or `--socket` over UDS. A `read-only` token is rejected on mutations.

- [ ] **Step 1: Failing tests**

```rust
// crates/wiremesh-controller/tests/admin_auth.rs
#[tokio::test]
async fn read_only_token_cannot_mutate() {
    let h = wiremesh_testkit::TestController::start().await;
    let ro = h.mint_api_token("read-only").await;
    let mut admin = h.admin_client_with_bearer(&ro).await;
    let err = admin.create_segment(wiremesh_proto::v1::CreateSegmentRequest { name: "x".into(), cidrs: vec!["10.9.0.0/24".into()] }).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}
```

```rust
// crates/fabricctl/tests/cli.rs — drive the built binary against a TestController's UDS
#[tokio::test]
async fn fabricctl_creates_and_lists_segments_over_uds() {
    let h = wiremesh_testkit::TestController::start().await;
    let out = run_fabricctl(&["--socket", h.socket_path(), "segment", "create", "aws", "--cidr", "10.0.0.0/16"]).await;
    assert!(out.status.success());
    let list = run_fabricctl(&["--socket", h.socket_path(), "segment", "list"]).await;
    assert!(String::from_utf8_lossy(&list.stdout).contains("aws"));
}
```

- [ ] **Steps 2–5:** run-fail → implement CLI + auth interceptor → green → commit `feat(controller): full admin CRUD + fabricctl CLI + bearer/uds auth`.

---

### Task 14: Declarative `apply -f` (diff/idempotence; policy stub)

**Files:** Create `src/apply.rs`; grow `admin.proto` (`Apply(fabric_yaml) -> ApplyDiff`); `fabricctl apply -f`. Test: `crates/wiremesh-controller/tests/apply.rs`.

**Interfaces:** Produces: `Apply` parses `fabric.yaml` (segments/CIDRs/relays/tokens), diffs against current state, applies creates/updates/deletes in one transaction, returns the diff; a second identical apply yields an **empty diff, zero mutations, zero audit rows**. Policy stanzas are stored as `source_yaml` and compiled by the **empty-IR-v0 stub** (`compile_policy(yaml) -> vec![]`, `version+1` only if the yaml changed).

- [ ] **Step 1: Failing test**

```rust
// tests/apply.rs
const FABRIC: &str = r#"
segments:
  - name: aws
    cidrs: ["10.0.0.0/16"]
  - name: gcp
    cidrs: ["10.1.0.0/16"]
"#;
#[tokio::test]
async fn apply_is_idempotent() {
    let h = wiremesh_testkit::TestController::start().await;
    let d1 = h.apply(FABRIC).await;
    assert_eq!(d1.created_segments, 2);
    let audits_after_first = h.count_audit().await;
    let d2 = h.apply(FABRIC).await;  // identical
    assert_eq!(d2.created_segments, 0);
    assert!(d2.is_empty(), "second apply must be a no-op");
    assert_eq!(h.count_audit().await, audits_after_first, "no audit rows on empty apply");
}
```

- [ ] **Steps 2–5:** run-fail → implement diff engine + policy stub → green → commit `feat(controller): declarative apply -f with idempotent diff (policy stubbed)`.

---

### Task 15: UDP observation endpoint (controller side)

**Files:** Create `src/observe.rs`; modify `main.rs` (bind the UDP endpoint), `src/projection.rs` (surface observed endpoint into a gateway's candidate list). Test: `crates/wiremesh-controller/tests/observe.rs`.

**Interfaces:** Produces: an authenticated UDP endpoint that, on a probe carrying a gateway's identity token/HMAC, echoes the observed `ip:port` and records it as that gateway's candidate endpoint (surfaced in peers' snapshots). Auth binds the probe to an enrolled gateway (shared secret derived at enrollment — a cycle-2 stand-in for the real WG-socket probe).

- [ ] **Step 1: Failing test**

```rust
// tests/observe.rs — send a probe from a UDP socket; assert the echoed observed addr and its appearance as a candidate
#[tokio::test]
async fn observation_echoes_source_and_populates_candidate() {
    let h = wiremesh_testkit::TestController::start().await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    let b = wiremesh_testkit::enroll_one(&h, "gcp", "10.1.0.0/16").await;
    let observed = a.probe_observe(h.observe_addr()).await.unwrap();  // sends AOBS+auth, returns echoed ip:port
    assert!(observed.starts_with("127.0.0.1:"));
    // B's snapshot now lists A's observed candidate
    let mut s = b.open_sync().await; let snap = expect_snapshot(s.next().await);
    let a_peer = snap.peers.iter().find(|p| p.gateway_id == a.id());
    // (peer appears once B reconnects post-observation; test may re-open the stream)
    assert!(a_peer.map_or(false, |p| p.candidate_endpoints.iter().any(|c| c == &observed)));
}
```

- [ ] **Steps 2–5:** run-fail → implement (reuse the Phase 0 `spike/punch` observe logic pattern) → green → commit `feat(controller): udp observation endpoint feeds candidate endpoints`.

---

### Task 16: Revocation → denylist + audit query/export

**Files:** Modify `src/services/admin.rs` (`RevokeCert`, `AuditQuery`), `src/projection.rs` (revoked serials already in snapshot — assert push-on-revoke), `fabricctl` (`audit export`). Test: `crates/wiremesh-controller/tests/revoke_audit.rs`.

**Interfaces:** Produces: revoking a cert pushes its serial into every connected gateway's next delta's `revoked_serials`; `AuditQuery` filters by actor/entity/time; `fabricctl audit export` streams JSON lines.

- [ ] **Step 1: Failing test**

```rust
// tests/revoke_audit.rs
#[tokio::test]
async fn revoke_pushes_serial_to_connected_gateways_and_audits() {
    let h = wiremesh_testkit::TestController::start().await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    let victim = wiremesh_testkit::enroll_one(&h, "gcp", "10.1.0.0/16").await;
    let mut a_stream = a.open_sync().await; let _ = a_stream.next().await;
    h.admin_client().await.revoke_cert(wiremesh_proto::v1::RevokeCertRequest { serial: victim.cert_serial() }).await.unwrap();
    let d = expect_delta(a_stream.next().await);
    assert!(d.revoked_serials.contains(&victim.cert_serial()));
    let rows = h.audit_query("revoke").await;
    assert!(rows.iter().any(|r| r.action == "revoke"));
}
```

- [ ] **Steps 2–5:** run-fail → implement → green → commit `feat(controller): cert revocation denylist push + audit query/export`.

---

### Task 17: Provider-conformance suite (embedded default)

**Files:** Create `crates/wiremesh-trust/tests/conformance.rs` (parameterized over a provider; cycle 2 runs the embedded impl only; the OpenBao arm is the fast-follow). No controller changes expected.

**Interfaces:** Produces: the reusable conformance suite each `SecretStore`/`CertificateIssuer` backend must pass — the embedded default must pass all cycle-2-applicable cases.

- [ ] **Step 1: Failing tests**

```rust
// crates/wiremesh-trust/tests/conformance.rs
async fn run_conformance<C: CertificateIssuer + SecretStore>(p: &C) {
    // 1. issuance: sign a CSR -> leaf chains to trust_bundle
    // 2. renewal-follows-TTL: sign with ttl=90d -> not_after ~ now+90d; a min-TTL below 24h is REFUSED
    // 3. revoke(handle) succeeds and is idempotent
    // 4. SecretStore put/get roundtrip with monotonically increasing version
}
#[tokio::test]
async fn embedded_default_passes_conformance() {
    let dir = tempfile::tempdir().unwrap();
    let p = wiremesh_trust::EmbeddedTrust::open(dir.path()).unwrap();
    run_conformance(&p).await;
}
```

- [ ] **Step 2: Run to fail** (min-TTL refusal not yet implemented) → **Step 3: implement** min-TTL refusal (< 24h) in `EmbeddedTrust::sign` and any missing conformance behavior → **Step 4: green** → **Step 5: Commit** `test(trust): provider conformance suite (embedded default passes)`.

---

### Task 18: Cycle-2 wrap-up — full-suite gate + status doc

**Files:** Create `docs/research/cycle2-controller-notes.md` (API-drift findings from tonic/rusqlite, decisions realized, what cycle-2b/3/4 inherit). No new product code.

- [ ] **Step 1: Full suite green**

Run: `cargo test --workspace`
Expected: all crates' suites PASS (0 failed, 0 skipped). Record the per-crate tally.

- [ ] **Step 2: Write the notes doc** — the done bar reached (link the `fail_static` + `sync_delta` tests as evidence), tonic/rusqlite friction encountered, and the hand-offs: cycle-2b (OpenBao provider + its conformance arm), cycle-3 (real DSL→IR compiler behind the stub call site; real `apply -f` policy semantics), cycle-4 (real gateway consuming `wiremesh-proto`; data-plane key rotation; brokered-punch honoring the go-skew constraint).

- [ ] **Step 3: Commit** `docs(controller): cycle 2 wrap-up notes + full-suite gate`.

---

## Self-Review Notes (author-run)

- **Spec coverage:** every design §1 in-scope item maps to a task — data model/migrations/overlap (T3), CA/enrollment (T2/T5), rebind (T10), Enrollment/Sync/Admin services (T4/T5/T7/T8/T13), Sync projection + snapshot/delta + acks (T7/T8), key-epoch bookkeeping (T11), route computation + drain (T7/T12), audit (T3 append, T16 query/export), provider seams + embedded default (T2, T17), proto + trait defs (T1, T2), fabricctl incl. apply -f (T13/T14), UDP observation controller-side (T15). Done-bar end-to-end proven at T9. The three scope boundaries (D-C2-5/6/7) are honored: policy stubbed in T14, observation controller-only in T15, key rotation bookkeeping-only in T11.
- **Deliberate deferrals (not gaps):** OpenBao provider + its conformance arm (cycle 2b, T17 leaves the seam parameterized); real policy compiler + real `apply -f` policy semantics (cycle 3); real gateway, data-plane key rotation, brokered-punch/go-skew proof (cycle 4).
- **Known soft spots:** `tonic`/`rusqlite` API specifics in code blocks may drift (unvalidated in Phase 0) — Tasks 1/4/7 flag "adapt against docs" as expected work, mirroring Phase 0's aya/boringtun framing. mTLS peer-identity extraction (T7) and UDS serving (T4) are the two tonic areas most likely to need doc-checking. The UDP observation auth (T15) is a cycle-2 stand-in for the real WG-socket probe (cycle 4 replaces it).
- **Type consistency:** the `wiremesh_proto::v1` message/type names (`StateSnapshot`, `Delta`, `Peer`, `SyncMessage::Body`, `EnrollRequest/Response`, admin messages) are defined once in T1 and used verbatim in T4–T16; `wiremesh_trust` trait/type names (`CertificateIssuer`, `SecretStore`, `IssuedCert`, `CertProfile`, `EmbeddedTrust`) defined in T2 and reused in T5/T17; the testkit surface (`TestController`, `StubGateway`, `enroll_one`, `gen_csr`, `expect_snapshot`/`expect_delta`) is introduced in T6–T9 and reused throughout Phase 3.
