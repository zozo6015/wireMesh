//! (Backlog item 23, controller half) `EnrollRequest.wg_pubkey` reaches
//! `services/enrollment.rs`'s gateway path (`req.wg_pubkey.clone()` straight
//! into `Db::enroll_gateway`) with no base64 or length check — the only
//! inspection anywhere is an `is_empty()` branch choosing the cycle-2
//! placeholder (`db.rs`'s `baseline_pubkey`). Whatever a caller sends lands
//! as the gateway's `GATEWAY_KEY.pubkey` and is advertised to every peer
//! verbatim (`wg_pubkey_enrollment.rs` proves the "threaded through
//! verbatim" half of that).
//!
//! # Why this is remotely reachable, not just a persistence nicety
//!
//! `PeerState::from_proto` copies an advertised key straight through (see
//! `crates/wiremesh-gateway/tests/peer_key_and_allowedips_validation.rs`,
//! this backlog item's gateway half). A compromised-but-certificate-holding
//! gateway enrolling with `wg_pubkey = "!!!"` (or any base64 decoding to
//! != 32 bytes) gets that value advertised to every peer; each peer's next
//! `apply_state` -> `encode_set` -> `key_b64_to_hex` fails, and the `Err`
//! unwinds out of `run()` and exits the process — for every peer that
//! gateway has, at once. The controller is the ONLY place that can stop this
//! before it is a fabric-wide incident, since it is the sole choke point
//! between "what a gateway claims" and "what every peer is told".
//!
//! # The precedent this mirrors
//!
//! `EnrollmentSvc::enroll`'s relay path already does exactly this shape for
//! `req.endpoint` (`services/enrollment.rs`, the Cycle-4c Task 5 comment):
//! reject up front, before signing or touching the DB, with
//! `Status::invalid_argument`, so a malformed value can never be enrolled or
//! advertised. This suite asks for the mirror-image check on the gateway
//! path's `wg_pubkey`, which the same comment names as "never applied to
//! pubkeys".
//!
//! # What is deliberately NOT covered here
//!
//! `services/sync.rs`'s `SubmitEpochKey` (`req.pubkey` into
//! `Db::set_epoch_pubkey` with no decode and no length check) is the other
//! controller-side door the backlog names for item 23. It is NOT exercised
//! in this file — see the report accompanying this change for why: at the
//! time of writing, at least eight already-green tests across
//! `epoch_key_submit.rs`, `rotation.rs`, `rotation_disabled.rs`,
//! `rotation_timer.rs`, `projection_guard.rs`, and
//! `rotation_retire_drive.rs` submit short, non-32-byte, and in several
//! cases non-base64-alphabet placeholder strings (`"REALKEY=="`,
//! `"FRESH-POST-RESTART-KEY=="`, etc.) as epoch pubkeys and assert
//! `Sync.SubmitEpochKey` SUCCEEDS. Applying `key_b64_to_hex`-shaped
//! validation there as a drive-by would turn those into new, unrelated
//! failures — a scope decision for whoever lands that half, not something a
//! test-only change should force silently.
//!
//! # Why token-not-consumed is asserted, not just the rejection
//!
//! `Enrollment` tokens are single-use (`Db::enroll_gateway` marks the token
//! spent atomically with recording the cert/gateway). If a bad `wg_pubkey`
//! consumed the token before being rejected, the caller's only recovery
//! would be minting an entirely new token — for a mistake that has nothing
//! to do with the token itself. The relay-endpoint precedent this mirrors
//! validates before ANY DB interaction for exactly this reason, and these
//! tests pin that the gateway path does too.

use wiremesh_proto::v1::EnrollRequest;
use wiremesh_testkit::gen_csr;

/// Not base64 at all — `key_b64_to_hex`'s (`crates/wiremesh-gateway/src/uapi.rs`)
/// first failure mode, mirrored here as the reference predicate for what the
/// controller must also refuse to store.
const BOGUS_NOT_B64: &str = "!!! not base64 !!!";
/// Valid base64, decodes to 5 bytes, not 32 — the second failure mode. A
/// check that only asks "does this parse as base64" would miss this one.
const BOGUS_WRONG_LEN: &str = "SGVsbG8=";
/// base64 of 32 bytes of 0x22 — a validly-shaped key, for the "token
/// survives a rejection and can still be redeemed" half of each test.
const VALID_32_BYTE_KEY: &str = "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=";

/// Mints a fresh single-use `gateway` token bound to `cidr` under a
/// fresh segment — the same setup `wiremesh_testkit::enroll_one` does, but
/// exposing the raw token/cidr instead of redeeming it immediately, so a
/// test can attempt (and re-attempt) `Enrollment.Enroll` itself.
async fn mint_gateway_token(h: &wiremesh_testkit::TestController, segment_name: &str, cidr: &str) -> String {
    let mut admin = h.admin_client().await;
    admin
        .create_segment(wiremesh_proto::v1::CreateSegmentRequest {
            name: segment_name.to_string(),
            cidrs: vec![cidr.to_string()],
        })
        .await
        .expect("creating segment");
    admin
        .mint_token(wiremesh_proto::v1::MintTokenRequest {
            kind: "gateway".to_string(),
            bound_cidrs: vec![cidr.to_string()],
            rebind_segment_id: 0,
        })
        .await
        .expect("minting gateway token")
        .into_inner()
        .token
}

#[tokio::test]
async fn enroll_with_a_non_base64_wg_pubkey_is_rejected_and_does_not_consume_the_token() {
    let h = wiremesh_testkit::TestController::start().await;
    let token = mint_gateway_token(&h, "aws", "10.0.0.0/16").await;
    let mut enr = h.enrollment_client().await;

    let (bad_csr, _kp1) = gen_csr("stub-gw");
    let status = enr
        .enroll(EnrollRequest {
            token: token.clone(),
            csr_pem: bad_csr,
            cidrs: vec!["10.0.0.0/16".to_string()],
            wg_pubkey: BOGUS_NOT_B64.to_string(),
            endpoint: String::new(),
        })
        .await
        .expect_err(
            "Enrollment.Enroll with a non-base64 wg_pubkey must be REJECTED. TODAY \
             `req.wg_pubkey.clone()` reaches `Db::enroll_gateway` with no decode and no \
             length check at all, so this call currently SUCCEEDS and stores the garbage \
             verbatim — which every peer's gateway then advertises and dies on.",
        );
    assert_eq!(
        status.code(),
        tonic::Code::InvalidArgument,
        "expected InvalidArgument (the same status the relay-endpoint precedent at \
         services/enrollment.rs uses for a malformed `endpoint`), got: {status:?}"
    );

    // The token must still be usable: a caller who mistyped the pubkey gets
    // exactly one more chance with the SAME token, not a fresh mint.
    let (good_csr, _kp2) = gen_csr("stub-gw");
    let resp = enr
        .enroll(EnrollRequest {
            token,
            csr_pem: good_csr,
            cidrs: vec!["10.0.0.0/16".to_string()],
            wg_pubkey: VALID_32_BYTE_KEY.to_string(),
            endpoint: String::new(),
        })
        .await
        .expect(
            "retrying the SAME token with a valid wg_pubkey must succeed — a rejected \
             enroll attempt must not have already spent the single-use token",
        );
    assert!(resp.into_inner().gateway_id > 0, "expected a real gateway_id to be assigned");
}

#[tokio::test]
async fn enroll_with_a_wrong_length_wg_pubkey_is_rejected_and_does_not_consume_the_token() {
    let h = wiremesh_testkit::TestController::start().await;
    let token = mint_gateway_token(&h, "aws", "10.1.0.0/16").await;
    let mut enr = h.enrollment_client().await;

    let (bad_csr, _kp1) = gen_csr("stub-gw");
    let status = enr
        .enroll(EnrollRequest {
            token: token.clone(),
            csr_pem: bad_csr,
            cidrs: vec!["10.1.0.0/16".to_string()],
            wg_pubkey: BOGUS_WRONG_LEN.to_string(),
            endpoint: String::new(),
        })
        .await
        .expect_err(
            "Enrollment.Enroll with a wg_pubkey that IS valid base64 but decodes to the \
             wrong length (5 bytes, not 32) must also be rejected — a check that only \
             validates the base64 alphabet and not the decoded length would miss exactly \
             this input.",
        );
    assert_eq!(status.code(), tonic::Code::InvalidArgument, "got: {status:?}");

    let (good_csr, _kp2) = gen_csr("stub-gw");
    enr.enroll(EnrollRequest {
        token,
        csr_pem: good_csr,
        cidrs: vec!["10.1.0.0/16".to_string()],
        wg_pubkey: VALID_32_BYTE_KEY.to_string(),
        endpoint: String::new(),
    })
    .await
    .expect("retrying the same token with a valid wg_pubkey must succeed");
}
