//! Cycle-4c Task 4: relay enrollment via `Enrollment.Enroll`.
//!
//! Mirrors `tests/enroll.rs`'s harness exactly (same `TestController`,
//! `admin_client()`/`mint_token`, `wiremesh_testkit::gen_csr`,
//! `enrollment_client()`) but exercises the NEW relay path: a `kind =
//! "relay"` enrollment token redeemed with `EnrollRequest.endpoint` set
//! (instead of `cidrs`) must skip segment/CIDR resolution entirely, sign
//! the CSR the same way a gateway's is signed, and record a `relay` DB row
//! (endpoint, status `active`) plus a `certificate` row with
//! `subject_kind = 'relay'` — see
//! `/private/tmp/claude-501/-Users-zozo-k8s-aetherLink/2dddbea1-f462-4b3b-8979-ec20bb29a8b1/scratchpad/task4-design-notes.md`
//! for the full design this test suite is written against.
//!
//! None of `Db::enroll_relay`, the handler's endpoint-routed relay branch,
//! or the `subject_kind = 'relay'` cert recording exist yet as of this
//! writing — every test below is expected RED: relay enrollment currently
//! either fails outright (the handler unconditionally requires non-empty
//! `cidrs`, which a relay never declares) or, if that guard were bypassed,
//! would silently fall through the GATEWAY path and create no relay row at
//! all.
//!
//! DB inspection deliberately reads the `certificate`/`relay` tables via a
//! raw second `rusqlite::Connection` to the controller's on-disk
//! `controller.db` (same "open a second connection to the same file"
//! pattern `TestController::gateway_exists`/`tests/report_local_endpoints.rs`
//! already use through the `Db` wrapper) rather than adding a new `Db`
//! accessor — `Db::enroll_relay` and any DB-side reads it needs are the
//! IMPLEMENTER's surface to design, not this test suite's.
use rusqlite::Connection;
use wiremesh_proto::v1::{CreateSegmentRequest, EnrollRequest, MintTokenRequest};

/// Parses `pem`'s X.509 serial number, normalized to the controller's
/// canonical 32-lowercase-hex-char (16-byte) form. Duplicates the
/// width-normalization `wiremesh_testkit::StubGateway::cert_serial` performs
/// (that logic is unit-tested there — see
/// `wiremesh-testkit/src/lib.rs::normalize_serial_to_16_bytes`'s tests)
/// rather than depending on it: that helper is private to `testkit`, and a
/// controller-side certificate-row assertion belongs in this crate's own
/// tests, not behind a new cross-crate export minted just for this.
fn cert_serial_hex(pem: &str) -> String {
    let (_, parsed) =
        x509_parser::pem::parse_x509_pem(pem.as_bytes()).expect("parsing cert_pem as PEM");
    let cert = parsed
        .parse_x509()
        .expect("parsing cert_pem's DER as X.509");
    let raw = cert.raw_serial();
    let stripped: &[u8] = match raw {
        [0x00, rest @ ..] if rest.len() == 16 => rest,
        _ => raw,
    };
    assert!(
        stripped.len() <= 16,
        "cert serial implausibly long ({} bytes after sign-pad strip): {stripped:02x?}",
        stripped.len()
    );
    let mut buf = [0u8; 16];
    buf[16 - stripped.len()..].copy_from_slice(stripped);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Total `relay` row count, read off `db_path` via a fresh raw sqlite
/// connection (see the module doc comment for why this bypasses `Db`).
fn count_relay_rows(db_path: &std::path::Path) -> i64 {
    let conn = Connection::open(db_path).expect("opening controller.db for relay-count inspection");
    conn.query_row("SELECT COUNT(*) FROM relay", [], |row| row.get(0))
        .expect("counting relay rows")
}

/// Every `relay` row as `(id, name, endpoint, status)`, ordered by id —
/// same shape as `Db::list_relays` (deliberately not reused; see module doc
/// comment).
fn list_relay_rows(db_path: &std::path::Path) -> Vec<(i64, String, String, String)> {
    let conn = Connection::open(db_path).expect("opening controller.db for relay-row inspection");
    let mut stmt = conn
        .prepare("SELECT id, name, endpoint, status FROM relay ORDER BY id")
        .expect("preparing relay SELECT");
    stmt.query_map([], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
    })
    .expect("querying relay rows")
    .collect::<rusqlite::Result<Vec<_>>>()
    .expect("collecting relay rows")
}

/// The single `certificate` row with `subject_kind = 'relay'`, as `(serial,
/// subject_kind)` — `None` if no such row exists. A fresh `TestController`
/// per test means at most one relay certificate is ever recorded across
/// these tests, so "the" row (rather than "a" row) is unambiguous.
fn find_relay_certificate_row(db_path: &std::path::Path) -> Option<(String, String)> {
    let conn = Connection::open(db_path).expect("opening controller.db for certificate inspection");
    conn.query_row(
        "SELECT serial, subject_kind FROM certificate WHERE subject_kind = 'relay'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .ok()
}

/// A relay-kind enrollment token, redeemed with `EnrollRequest.endpoint` set
/// and `cidrs` empty (the relay path per the Task-4 design), must succeed
/// with a CA-signed cert and must record BOTH a new, active `relay` DB row
/// carrying the declared endpoint AND a `certificate` row tagged
/// `subject_kind = 'relay'` whose serial matches the actually-issued cert.
#[tokio::test]
async fn relay_enrollment_issues_ca_signed_cert_and_creates_active_relay_row() {
    let h = wiremesh_testkit::TestController::start().await;
    let mut admin = h.admin_client().await;

    let tok = admin
        .mint_token(MintTokenRequest {
            kind: "relay".into(),
            bound_cidrs: vec![],
            rebind_segment_id: 0,
        })
        .await
        .unwrap()
        .into_inner()
        .token;

    let (csr, _kp) = wiremesh_testkit::gen_csr("relay-1");
    let mut enr = h.enrollment_client().await;

    let endpoint = "203.0.113.9:51820";
    let resp = enr
        .enroll(EnrollRequest {
            token: tok,
            csr_pem: csr,
            cidrs: vec![],
            wg_pubkey: String::new(),
            endpoint: endpoint.to_string(),
        })
        .await
        .expect("a relay-kind token with a non-empty endpoint must enroll successfully")
        .into_inner();

    assert!(
        resp.cert_pem.contains("BEGIN CERTIFICATE"),
        "cert_pem must be a PEM certificate, got: {}",
        resp.cert_pem
    );
    assert!(
        resp.ca_bundle_pem.contains("BEGIN CERTIFICATE"),
        "ca_bundle_pem must be a PEM certificate, got: {}",
        resp.ca_bundle_pem
    );

    let issued_serial = cert_serial_hex(&resp.cert_pem);

    let db_path = h.data_dir().join("controller.db");
    let relays = tokio::task::spawn_blocking({
        let db_path = db_path.clone();
        move || list_relay_rows(&db_path)
    })
    .await
    .expect("blocking relay-row inspection task panicked");

    assert_eq!(
        relays.len(),
        1,
        "exactly one relay row must exist after a single relay enrollment, got: {relays:?}"
    );
    let (_, name, db_endpoint, status) = &relays[0];
    assert_eq!(
        db_endpoint, endpoint,
        "relay row's endpoint must match the endpoint declared at enrollment"
    );
    assert_eq!(
        status, "active",
        "a freshly enrolled relay row must have status 'active', got {status:?}"
    );
    assert!(
        name.starts_with("relay-"),
        "relay name should be derived as relay-<secret_hash>, got {name:?}"
    );

    let cert_row = tokio::task::spawn_blocking(move || find_relay_certificate_row(&db_path))
        .await
        .expect("blocking certificate-row inspection task panicked");
    let (db_serial, subject_kind) = cert_row
        .expect("a certificate row with subject_kind = 'relay' must exist after relay enrollment");
    assert_eq!(subject_kind, "relay");
    assert_eq!(
        db_serial.to_lowercase(),
        issued_serial,
        "the certificate row's serial must match the serial actually issued in cert_pem"
    );
}

/// Security property: a GATEWAY-kind token must not be redeemable on the
/// relay path. Declaring a non-empty `endpoint` (which selects the relay
/// path) with a gateway-kind token must be rejected outright, and — the
/// part a merely-failing RPC call doesn't by itself prove — must leave NO
/// relay row behind. Exact status code is left unspecified (only that it's
/// an error), since the important contract is the rejection + the absence
/// of a side effect, not which `tonic::Code` names the rejection.
#[tokio::test]
async fn gateway_token_cannot_enroll_a_relay() {
    let h = wiremesh_testkit::TestController::start().await;
    let mut admin = h.admin_client().await;

    let tok = admin
        .mint_token(MintTokenRequest {
            kind: "gateway".into(),
            bound_cidrs: vec!["10.0.0.0/16".into()],
            rebind_segment_id: 0,
        })
        .await
        .unwrap()
        .into_inner()
        .token;

    let (csr, _kp) = wiremesh_testkit::gen_csr("relay-x");
    let mut enr = h.enrollment_client().await;

    enr.enroll(EnrollRequest {
        token: tok,
        csr_pem: csr,
        cidrs: vec![],
        wg_pubkey: String::new(),
        endpoint: "203.0.113.9:51820".to_string(),
    })
    .await
    .expect_err(
        "a gateway-kind token must not be able to enroll a relay via the endpoint-routed path",
    );

    let db_path = h.data_dir().join("controller.db");
    let relay_count = tokio::task::spawn_blocking(move || count_relay_rows(&db_path))
        .await
        .expect("blocking relay-count task panicked");
    assert_eq!(
        relay_count, 0,
        "a rejected relay enrollment attempt via a gateway-kind token must not create any relay row"
    );
}

/// Regression: an ordinary gateway enrollment (gateway-kind token,
/// non-empty `cidrs`, EMPTY `endpoint`) must be entirely unaffected by the
/// new relay path — it still enrolls a gateway (segment/CIDR resolution
/// intact) and must NOT create any relay row.
#[tokio::test]
async fn gateway_enrollment_unaffected() {
    let h = wiremesh_testkit::TestController::start().await;
    let mut admin = h.admin_client().await;

    admin
        .create_segment(CreateSegmentRequest {
            name: "aws".into(),
            cidrs: vec!["10.0.0.0/16".into()],
        })
        .await
        .unwrap();

    let tok = admin
        .mint_token(MintTokenRequest {
            kind: "gateway".into(),
            bound_cidrs: vec!["10.0.0.0/16".into()],
            rebind_segment_id: 0,
        })
        .await
        .unwrap()
        .into_inner()
        .token;

    let (csr, _kp) = wiremesh_testkit::gen_csr("gw-aws");
    let mut enr = h.enrollment_client().await;

    let resp = enr
        .enroll(EnrollRequest {
            token: tok,
            csr_pem: csr,
            cidrs: vec!["10.0.0.0/16".into()],
            wg_pubkey: String::new(),
            endpoint: String::new(),
        })
        .await
        .expect("a plain gateway enrollment (empty endpoint) must be unaffected by the relay path")
        .into_inner();

    assert!(
        resp.cert_pem.contains("BEGIN CERTIFICATE"),
        "cert_pem must be a PEM certificate, got: {}",
        resp.cert_pem
    );
    assert!(
        h.gateway_exists(resp.gateway_id).await,
        "gateway row {} must exist after ordinary gateway enrollment",
        resp.gateway_id
    );

    let db_path = h.data_dir().join("controller.db");
    let relay_count = tokio::task::spawn_blocking(move || count_relay_rows(&db_path))
        .await
        .expect("blocking relay-count task panicked");
    assert_eq!(
        relay_count, 0,
        "an ordinary gateway enrollment must not create any relay row"
    );
}
