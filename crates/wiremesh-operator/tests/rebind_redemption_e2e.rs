//! FAILING test (test-author, operator review round) — CRITICAL, part (b): an
//! END-TO-END REDEMPTION of an OPERATOR-MINTED rebind token.
//!
//! The reviewer's key point: nothing anywhere redeems a token the OPERATOR
//! minted. `crates/wiremesh-controller/tests/rebind.rs` proves the CONTROLLER's
//! rebind works — but it hand-writes the request (`kind: "rebind"`), so it
//! cannot catch the operator encoding `kind: "gateway"` instead. Unit shape
//! pins (`rebind_token_encoding.rs`) catch the encoding but not the redemption
//! semantics. This test closes the loop: it drives the operator's OWN
//! `FabricAdmin::mint_gateway_rebind_token` against a real `TestController`,
//! then REDEEMS the resulting token with a replacement gateway and asserts the
//! segment's active gateway is REPLACED — not rejected.
//!
//! Placement: in the OPERATOR crate (not the controller's tests), because the
//! code under test is the operator's mint encoding — the controller is only the
//! oracle. This needs a dev-dependency the implementer must add (dev-only, no
//! cycle: `wiremesh-testkit` depends on `wiremesh-controller`, which does not
//! depend on the operator):
//!
//! ```toml
//! [dev-dependencies]
//! wiremesh-testkit = { path = "../wiremesh-testkit" }   # default features (no netns)
//! ```
//!
//! Expected failure TODAY: `StubGateway::enroll` returns
//! `AlreadyExists`/`SegmentAlreadyBound` — the operator's `kind: "gateway"`
//! token takes the occupancy arm (db.rs:1454-1466) instead of the rebind arm.
//! After the fix it must succeed and replace the incumbent.

use wiremesh_operator::admin::FabricAdmin;

#[tokio::test]
async fn operator_minted_rebind_token_replaces_the_segments_active_gateway() {
    let h = wiremesh_testkit::TestController::start().await;

    // An incumbent gateway owns segment "aws" — the segment is now OCCUPIED,
    // which is exactly the state an ordinary `gateway` token cannot enroll into.
    let incumbent = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    let old_serial = incumbent.cert_serial().expect("incumbent cert serial");
    let old_id = incumbent.id();
    let seg_id = incumbent.segment_id();

    // Mint through the OPERATOR's own admin client (its real gRPC path, bearer
    // auth, against the controller's Admin TCP listener) — NOT a hand-written
    // MintTokenRequest. This is what makes the test catch the wrong `kind`.
    let bearer = h.mint_api_token("admin").await;
    let mut admin = FabricAdmin::connect(&h.admin_tcp_addr().to_string(), &bearer)
        .await
        .expect("operator FabricAdmin must connect to the controller's Admin TCP listener");
    let token = admin
        .mint_gateway_rebind_token(seg_id)
        .await
        .expect("operator rebind mint must succeed");

    // Redeem it: a REPLACEMENT gateway declaring the SAME CIDRs the segment
    // already owns. THE load-bearing assertion — today the operator's
    // kind="gateway" token is refused here with SegmentAlreadyBound.
    let replacement = wiremesh_testkit::StubGateway::enroll(&h, &token, &["10.0.0.0/16"])
        .await
        .expect(
            "an OPERATOR-minted rebind token must be redeemable on its own occupied \
             segment (it must be minted with kind=\"rebind\"; a kind=\"gateway\" token \
             is rejected here with SegmentAlreadyBound)",
        );

    // Replacement, not duplication: a freshly issued cert...
    let new_serial = replacement.cert_serial().expect("replacement cert serial");
    assert_ne!(
        new_serial, old_serial,
        "the replacement gateway must receive a freshly issued cert distinct from the incumbent's"
    );
    assert_ne!(
        replacement.id(),
        old_id,
        "the replacement is a distinct gateway id"
    );

    // ...and the roster shows the incumbent REPLACED, with exactly one active
    // gateway left on the segment (the one-gateway-per-segment invariant holds).
    // Read back through the operator's own list_gateways for symmetry.
    let roster = admin
        .list_gateways()
        .await
        .expect("listing the gateway roster");
    let active: Vec<_> = roster
        .iter()
        .filter(|g| g.segment == "aws" && g.status == "active")
        .collect();
    assert_eq!(
        active.len(),
        1,
        "exactly one ACTIVE gateway must remain on the segment after a rebind; roster: {roster:?}"
    );
    assert_eq!(
        active[0].id,
        replacement.id(),
        "the surviving active gateway must be the REPLACEMENT, not the incumbent"
    );
    assert!(
        roster
            .iter()
            .any(|g| g.id == old_id && g.status != "active"),
        "the incumbent must be left non-active (replaced), proving a REPLACEMENT rather \
         than a second active gateway; roster: {roster:?}"
    );
}
