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
//! reading the CA / dialing the controller, `run_enroll` must classify the
//! on-disk identity into THREE outcomes (not the current `Identity::load(..).is_ok()`
//! two-way test, which mis-classifies EACCES/EIO as "absent"):
//!   * loads OK                → skip (log the "already enrolled" line, return Ok(()))
//!   * NotFound OR JSON parse  → proceed to the real enrollment (unchanged)
//!   * any other io::ErrorKind → PROPAGATE the error (return Err; do NOT enroll)
//! Suggested seam: `Identity::probe(state_dir) -> anyhow::Result<bool>` returning
//! Ok(true)=present, Ok(false)=absent/malformed, Err=other IO failure — the enroll
//! guard matches on that. The "no identity present" path (see `enroll_cmd.rs`)
//! must stay unchanged.
//!
//! The `run_enroll` signature stays `async fn(EnrollArgs) -> anyhow::Result<()>`
//! (no new return type needed) — the skip is observable behaviorally: it is
//! proven here by pointing `--controller` at an address with no listener, so a
//! correct idempotent enroll returns Ok (never dials) while the current
//! always-dials code returns Err (connection refused).

use wiremesh_gateway::enroll::{run_enroll, EnrollArgs};
use wiremesh_gateway::identity::Identity;
use wiremesh_proto::v1::{CreateSegmentRequest, MintTokenRequest};

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
    std::fs::write(
        &ca_path,
        "-----BEGIN CERTIFICATE-----\nCC\n-----END CERTIFICATE-----",
    )
    .unwrap();

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
    assert_eq!(
        before, after,
        "existing identity must be left untouched on skip"
    );
    let reloaded = Identity::load(&state_dir).expect("identity still loadable after skip");
    assert_eq!(reloaded.gateway_id, 7, "gateway_id must be unchanged");
    assert_eq!(
        reloaded.wg_private_key_b64, "cHJpdmtleQ==",
        "WG private key must be unchanged (no fresh keypair generated)"
    );
}

/// Mint a fresh gateway token bound to `10.0.0.0/16` against a live test controller.
async fn mint_gateway_token(h: &wiremesh_testkit::TestController) -> String {
    let mut admin = h.admin_client().await;
    admin
        .create_segment(CreateSegmentRequest {
            name: "aws".into(),
            cidrs: vec!["10.0.0.0/16".into()],
        })
        .await
        .unwrap();
    admin
        .mint_token(MintTokenRequest {
            kind: "gateway".into(),
            bound_cidrs: vec!["10.0.0.0/16".into()],
            rebind_segment_id: 0,
        })
        .await
        .unwrap()
        .into_inner()
        .token
}

#[tokio::test]
async fn enroll_propagates_non_notfound_io_error_and_leaves_token_unspent() {
    // CORRECTNESS (CodeRabbit finding): the idempotency skip may only fall through
    // to enrollment when the identity is MISSING (NotFound) or MALFORMED (parse
    // error). A read that fails with a DIFFERENT io error (EACCES / EIO / EISDIR)
    // must PROPAGATE — treating it as "absent" would redeem the single-use token
    // and potentially wipe an identity that actually exists but is momentarily
    // unreadable.
    let h = wiremesh_testkit::TestController::start().await;
    let token = mint_gateway_token(&h).await;

    let dir = tempfile::tempdir().unwrap();
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, h.ca_bundle_pem()).unwrap();

    // Force a NON-NotFound io error from the identity read: make identity.json a
    // DIRECTORY, so `fs::read` fails with EISDIR. This is a structural error root
    // cannot bypass (unlike a permission bit), so it is deterministic inside the
    // privileged container.
    let bad_dir = dir.path().join("bad-state");
    std::fs::create_dir_all(bad_dir.join("identity.json")).unwrap();

    let res1 = run_enroll(EnrollArgs {
        token: token.clone(),
        controller: h.tcp_addr().to_string(),
        ca_path: ca_path.clone(),
        state_dir: bad_dir.clone(),
        cidrs: vec!["10.0.0.0/16".into()],
    })
    .await;
    assert!(
        res1.is_err(),
        "a non-NotFound IO error while probing the existing identity must propagate as Err"
    );

    // Proof the errored run did NOT redeem the token: a clean enroll with the SAME
    // token into a fresh dir must still succeed. On the buggy path, the first run
    // treated EISDIR as "absent", dialed the controller and SPENT the single-use
    // token (before failing at store), so this second enroll would be rejected.
    let good_dir = dir.path().join("good-state");
    let res2 = run_enroll(EnrollArgs {
        token,
        controller: h.tcp_addr().to_string(),
        ca_path,
        state_dir: good_dir.clone(),
        cidrs: vec!["10.0.0.0/16".into()],
    })
    .await;
    assert!(
        res2.is_ok(),
        "the single-use token must stay unspent when the first run hit an IO error; got {res2:?}"
    );
    assert!(
        Identity::load(&good_dir).is_ok(),
        "the clean enroll wrote a loadable identity"
    );
}

#[tokio::test]
async fn enroll_proceeds_when_identity_is_malformed_json() {
    // The complementary branch: a structurally-broken identity.json (JSON parse
    // error) is classified like a MISSING identity — enroll falls through and
    // (re)enrolls. This must stay true alongside the IO-error propagation above.
    let h = wiremesh_testkit::TestController::start().await;
    let token = mint_gateway_token(&h).await;

    let dir = tempfile::tempdir().unwrap();
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, h.ca_bundle_pem()).unwrap();
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&state_dir).unwrap();
    // Not valid JSON → a parse error, not an IO error.
    std::fs::write(state_dir.join("identity.json"), b"{ this is not valid json").unwrap();

    let res = run_enroll(EnrollArgs {
        token,
        controller: h.tcp_addr().to_string(),
        ca_path,
        state_dir: state_dir.clone(),
        cidrs: vec!["10.0.0.0/16".into()],
    })
    .await;
    assert!(
        res.is_ok(),
        "a malformed identity.json must fall through to enrollment; got {res:?}"
    );
    let id = Identity::load(&state_dir)
        .expect("enroll overwrote the malformed identity with a valid one");
    assert!(id.gateway_id > 0, "controller assigned a gateway_id");
}
