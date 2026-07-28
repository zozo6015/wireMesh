//! Idempotent enroll (design 2026-07-28, §2): `wiremesh-gateway enroll` with a
//! parseable, structurally-complete pre-existing identity in `--state-dir` must
//! SKIP enrollment — issue NO enrollment RPC and exit success, leaving the
//! existing identity byte-for-byte untouched. This is what makes the K8s
//! init-container safe to run on EVERY boot once the identity lives on a PVC:
//! first boot enrolls into the fresh PVC; every later boot finds the persisted
//! identity and skips.
//!
//! NOTE ON "valid": the skip criterion is exactly what `Identity::load` accepts
//! — a structural JSON parse of `identity.json`. It does NOT validate the
//! embedded cert/key cryptographically or check expiry. The implementer should
//! word enroll.rs accordingly ("a parseable/structurally-complete identity",
//! not "a VALID identity") so the guarantee is not overstated. This test only
//! sets up a parseable identity, so no assertion depends on crypto validity.
//!
//! REQUIRED SURFACE FROM THE IMPLEMENTER: before generating the WG keypair /
//! reading the CA / dialing the controller, `run_enroll` must
//! `Identity::load(&args.state_dir)` and, if it succeeds, log
//! `wiremesh-gateway: already enrolled (identity present in <state-dir>),
//! skipping` and return `Ok(())` WITHOUT contacting the controller. The
//! "no identity present" path (see `enroll_cmd.rs`) must stay unchanged.
//!
//! The `run_enroll` signature stays `async fn(EnrollArgs) -> anyhow::Result<()>`
//! (no new return type needed) — the skip is observable behaviorally: it is
//! proven here by pointing `--controller` at an address with no listener, so a
//! correct idempotent enroll returns Ok (never dials) while the current
//! always-dials code returns Err (connection refused).

use wiremesh_gateway::enroll::{run_enroll, EnrollArgs};
use wiremesh_gateway::identity::Identity;

#[tokio::test]
async fn enroll_skips_when_valid_identity_present_and_issues_no_rpc() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");

    // A parseable, loadable identity already on disk (as if a prior boot enrolled
    // it into the PVC). "Loadable" == accepted by `Identity::load` (structural
    // JSON parse); no cryptographic validation is implied.
    let existing = Identity {
        cert_pem: "-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----".into(),
        key_pem: "-----BEGIN PRIVATE KEY-----\nBB\n-----END PRIVATE KEY-----".into(),
        ca_bundle_pem: "-----BEGIN CERTIFICATE-----\nCC\n-----END CERTIFICATE-----".into(),
        gateway_id: 7,
        observe_key: "cafef00d".into(),
        wg_private_key_b64: "cHJpdmtleQ==".into(),
    };
    existing.store(&state_dir).unwrap();
    let before = std::fs::read(state_dir.join("identity.json")).unwrap();

    // A CA file that exists, so that even if the skip check runs AFTER the CA
    // read the read still succeeds and the ONLY operation left that could fail is
    // the controller dial — which a correct idempotent enroll must never perform.
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, "-----BEGIN CERTIFICATE-----\nCC\n-----END CERTIFICATE-----").unwrap();

    // Point the controller at an address with no listener. If enroll dialed the
    // controller this returns Err (connection refused); a correct idempotent
    // enroll never dials, so it returns Ok purely from the on-disk identity.
    let res = run_enroll(EnrollArgs {
        token: "wiremesh://unused-token".into(),
        controller: "127.0.0.1:1".into(),
        ca_path,
        state_dir: state_dir.clone(),
        cidrs: vec!["10.0.0.0/16".into()],
    })
    .await;

    assert!(
        res.is_ok(),
        "enroll must SKIP (exit 0) when a parseable identity is already present, without \
         dialing the controller; got {res:?}"
    );

    // The existing identity must be left byte-for-byte untouched — not
    // re-enrolled, not re-keyed.
    let after = std::fs::read(state_dir.join("identity.json")).unwrap();
    assert_eq!(before, after, "existing identity must be left untouched on skip");
    let reloaded = Identity::load(&state_dir).expect("identity still loadable after skip");
    assert_eq!(reloaded.gateway_id, 7, "gateway_id must be unchanged");
    assert_eq!(
        reloaded.wg_private_key_b64, "cHJpdmtleQ==",
        "WG private key must be unchanged (no fresh keypair generated)"
    );
}
