//! Task 6 (RED): drives `StubGateway::enroll` — the not-yet-implemented
//! testkit helper that wraps a full CSR-generate + `Enrollment.Enroll` round
//! trip behind a single call, mirroring what a real gateway does at
//! bootstrap. This is intentionally a thin end-to-end assertion (cert +
//! CA bundle come back as PEM certificates); the token-scoping and
//! single-use semantics it rides on top of are already covered by
//! `wiremesh-controller/tests/enroll.rs`.
use wiremesh_proto::v1::{CreateSegmentRequest, MintTokenRequest};

#[tokio::test]
async fn stub_gateway_enrolls_and_holds_a_cert() {
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

    let gw = wiremesh_testkit::StubGateway::enroll(&h, &tok, &["10.0.0.0/16"])
        .await
        .unwrap();

    assert!(
        gw.cert_pem().contains("BEGIN CERTIFICATE"),
        "cert_pem must be a PEM certificate, got: {}",
        gw.cert_pem()
    );
    assert!(
        gw.ca_bundle_pem().contains("BEGIN CERTIFICATE"),
        "ca_bundle_pem must be a PEM certificate, got: {}",
        gw.ca_bundle_pem()
    );
}

/// Regression guard for a padded-DER serial bug: x509-parser's `raw_serial()`
/// returns the *DER-encoded* INTEGER contents, which — per the ASN.1
/// positive-integer rule — prepends a `0x00` pad byte whenever the serial's
/// leading byte has its MSB set. The controller records a fixed 16-byte
/// serial, so a correct `cert_serial()` is ALWAYS 32 lowercase-hex chars; the
/// padded-DER bug yields 34 (a spurious leading `"00"`) for the ~50% of random
/// serials whose top byte is >= 0x80, which would flake the serial
/// comparisons in later tasks (T7/T9/T16). Assert exactly 32 hex chars.
#[tokio::test]
async fn stub_gateway_cert_serial_is_16_hex_bytes() {
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

    let gw = wiremesh_testkit::StubGateway::enroll(&h, &tok, &["10.0.0.0/16"])
        .await
        .unwrap();

    let serial = gw.cert_serial().unwrap();
    assert!(
        serial
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "cert_serial() must be lowercase hex only, got: {serial:?}"
    );
    assert_eq!(
        serial.len(),
        32,
        "cert_serial() must be exactly 32 hex chars (16 raw bytes) to match the \
         controller's recorded serial; 34 chars means a spurious leading \"00\" \
         from returning the padded DER-encoded serial. got {} chars: {serial:?}",
        serial.len()
    );
}
