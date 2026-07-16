//! Task 13's failing test: the TCP Admin port (grown alongside the UDS one
//! for `fabricctl`'s `--token` transport) must enforce a bearer-token auth
//! interceptor that respects `API_TOKEN.role` — `admin` may mutate,
//! `read-only` may only read. The UDS listener stays implicit-admin (no
//! token needed there; that's what every earlier Admin test still drives via
//! `TestController::admin_client()`), so this test is the first to exercise
//! Admin over TCP at all.
//!
//! Mints a `read-only`-role API token via the (not-yet-existing)
//! `TestController::mint_api_token`, connects an `AdminClient` to the TCP
//! Admin port with that token attached as a bearer credential via the
//! (not-yet-existing) `TestController::admin_client_with_bearer`, and calls
//! `CreateSegment` (a mutation) — that must be rejected with
//! `tonic::Code::PermissionDenied`, not silently succeed or fail some other
//! way (e.g. `Unauthenticated`, which would mean the interceptor isn't
//! distinguishing "no/bad credential" from "valid credential, wrong role").
//!
//! As a positive control, an `admin`-role token's `CreateSegment` call over
//! the same TCP+bearer path must succeed — proving the interceptor actually
//! admits legitimate mutations rather than the test passing by accident
//! (e.g. every TCP mutation being rejected regardless of role).
//!
//! None of this exists yet: `TestController::mint_api_token` and
//! `TestController::admin_client_with_bearer` don't exist, so today this file
//! does not even COMPILE — that's the expected RED state for this step. The
//! implementer adds both (plus growing `admin.proto` with a token-mint RPC,
//! the bearer-auth `tonic::service::Interceptor` on the TCP Admin listener,
//! and the `fabricctl`-facing `Admin.MintApiToken`/role-check wiring in
//! `src/services/admin.rs`) to turn this green.
use wiremesh_proto::v1::{CreateSegmentRequest, ListSegmentsRequest};

#[tokio::test]
async fn read_only_token_cannot_mutate() {
    let h = wiremesh_testkit::TestController::start().await;

    let ro = h.mint_api_token("read-only").await;
    let mut admin = h.admin_client_with_bearer(&ro).await;

    let err = admin
        .create_segment(CreateSegmentRequest {
            name: "x".into(),
            cidrs: vec!["10.9.0.0/24".into()],
        })
        .await
        .expect_err("a read-only-role bearer token must not be allowed to CreateSegment");

    assert_eq!(
        err.code(),
        tonic::Code::PermissionDenied,
        "expected PermissionDenied for a read-only token's mutation attempt, got: {err:?}"
    );
}

#[tokio::test]
async fn admin_token_can_mutate() {
    let h = wiremesh_testkit::TestController::start().await;

    let admin_token = h.mint_api_token("admin").await;
    let mut admin = h.admin_client_with_bearer(&admin_token).await;

    let seg = admin
        .create_segment(CreateSegmentRequest {
            name: "y".into(),
            cidrs: vec!["10.10.0.0/24".into()],
        })
        .await
        .expect("an admin-role bearer token must be allowed to CreateSegment")
        .into_inner();

    assert_eq!(seg.name, "y");
}

/// A `read-only`-role token must still be allowed to READ — the interceptor
/// gates mutations by role, it doesn't blanket-deny read-only tokens. Proves
/// the fail-closed classifier the implementer is adding doesn't over-block
/// (a bug where "not admin" → deny everything would fail here even though
/// `read_only_token_cannot_mutate` still passed).
#[tokio::test]
async fn read_only_token_can_list() {
    let h = wiremesh_testkit::TestController::start().await;

    let ro = h.mint_api_token("read-only").await;
    let mut admin = h.admin_client_with_bearer(&ro).await;

    // A non-mutating RPC over the same TCP+bearer path must succeed.
    admin
        .list_segments(ListSegmentsRequest {})
        .await
        .expect("a read-only-role bearer token must be allowed to ListSegments (a read)");
}

/// A caller presenting an INVALID credential on the TCP Admin port must be
/// rejected `Unauthenticated` (distinct from `PermissionDenied`, which is
/// "valid credential, insufficient role"). The interceptor can't resolve
/// this obviously-invalid bearer token to any `api_token` row.
#[tokio::test]
async fn no_token_is_unauthenticated() {
    let h = wiremesh_testkit::TestController::start().await;

    let mut admin = h
        .admin_client_with_bearer("this-is-not-a-real-api-token")
        .await;

    let err = admin
        .list_segments(ListSegmentsRequest {})
        .await
        .expect_err("an invalid/absent bearer token must be rejected, not served");

    assert_eq!(
        err.code(),
        tonic::Code::Unauthenticated,
        "expected Unauthenticated for a request with no valid bearer token, got: {err:?}"
    );
}

/// A caller presenting NO `authorization` header AT ALL on the TCP Admin
/// port must ALSO be rejected `Unauthenticated` — this is the genuinely
/// absent-header branch of `wiremesh_controller::auth`'s middleware
/// (`extract_bearer` returning `None`), distinct from the invalid-token
/// case above (where a header IS present, just unresolvable). Both must
/// converge on the same `Unauthenticated` status, but only this test
/// actually exercises the missing-header code path.
#[tokio::test]
async fn missing_bearer_header_is_unauthenticated() {
    let h = wiremesh_testkit::TestController::start().await;

    let mut admin = h.admin_client_tcp_no_auth().await;

    let err = admin
        .list_segments(ListSegmentsRequest {})
        .await
        .expect_err("a request with no authorization header at all must be rejected, not served");

    assert_eq!(
        err.code(),
        tonic::Code::Unauthenticated,
        "expected Unauthenticated for a request with no bearer header at all, got: {err:?}"
    );
}
