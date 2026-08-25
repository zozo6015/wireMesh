//! Cycle-4c CodeRabbit round 3 (Major): `Admin.RegisterRelay` must reject
//! non-IPv4 endpoints.
//!
//! `AdminSvc::register_relay` (`crates/wiremesh-controller/src/services/admin.rs`)
//! currently only checks that `endpoint` is non-empty before persisting +
//! advertising it (see the `req.endpoint.is_empty()` guard right below the
//! `req.name.is_empty()` one). v1 is IPv4-only end to end, and the sibling
//! ENROLLMENT relay path already enforces this — see
//! `tests/relay_enroll.rs`/`tests/sync_relays.rs::relay_enrollment_rejects_malformed_endpoint`,
//! which pins that a malformed `endpoint` must be rejected by
//! `Enrollment.Enroll` and must leave no relay row behind. The admin surface
//! is a second way to add a relay (see
//! `sync_relays.rs::register_relay_pushes_relay_infos_delta_to_connected_gateway`)
//! and has no equivalent guard yet, so it currently accepts (and advertises)
//! an IPv6 endpoint like `"[::1]:4443"` or outright garbage like
//! `"not-an-address"`.
//!
//! This suite pins the fix: `register_relay` must reject any endpoint that
//! does not parse as `std::net::SocketAddrV4`, mirroring the enrollment path,
//! while continuing to accept a well-formed IPv4 `ip:port` endpoint.
//!
//! RED as of this writing: both the IPv6 and malformed cases currently
//! SUCCEED (creating a relay row each) instead of being rejected, so the
//! "rejected + no row created" assertions below fail; only the final
//! valid-IPv4-still-succeeds assertion currently passes.
use wiremesh_proto::v1::{ListRelaysRequest, RegisterRelayRequest};

/// `Admin.RegisterRelay` must reject an endpoint that isn't a well-formed
/// IPv4 `ip:port` (an IPv6 form, and a wholly malformed string), while a
/// genuinely valid IPv4 endpoint must still succeed and be persisted. Only
/// the valid call may leave a relay row behind.
#[tokio::test]
async fn admin_register_relay_rejects_non_ipv4_endpoint() {
    let h = wiremesh_testkit::TestController::start().await;
    let mut admin = h.admin_client().await;

    // An IPv6 endpoint must be rejected outright.
    admin
        .register_relay(RegisterRelayRequest {
            name: "relay-ipv6-rejected".into(),
            endpoint: "[::1]:4443".into(),
        })
        .await
        .expect_err("Admin.RegisterRelay must reject an IPv6 endpoint — v1 is IPv4-only");

    // A wholly malformed endpoint must also be rejected outright.
    admin
        .register_relay(RegisterRelayRequest {
            name: "relay-malformed-rejected".into(),
            endpoint: "not-an-address".into(),
        })
        .await
        .expect_err("Admin.RegisterRelay must reject a malformed (non ip:port) endpoint");

    // Neither rejected call may have left a relay row behind.
    let after_rejections = admin
        .list_relays(ListRelaysRequest {})
        .await
        .expect("Admin.ListRelays")
        .into_inner();
    assert_eq!(
        after_rejections.relays.len(),
        0,
        "no relay row may exist after two rejected (non-IPv4) RegisterRelay calls, got: {:?}",
        after_rejections.relays
    );

    // A genuinely valid IPv4 endpoint must still succeed — the fix must not
    // over-reject valid input.
    let valid_endpoint = "203.0.113.9:51820";
    let registered = admin
        .register_relay(RegisterRelayRequest {
            name: "relay-valid-ipv4".into(),
            endpoint: valid_endpoint.into(),
        })
        .await
        .expect("Admin.RegisterRelay must accept a well-formed IPv4 ip:port endpoint")
        .into_inner();
    assert_eq!(
        registered.endpoint, valid_endpoint,
        "the registered relay's endpoint must echo back the valid IPv4 endpoint supplied"
    );

    let after_valid = admin
        .list_relays(ListRelaysRequest {})
        .await
        .expect("Admin.ListRelays")
        .into_inner();
    assert_eq!(
        after_valid.relays.len(),
        1,
        "exactly one relay row must exist after the single valid IPv4 RegisterRelay call, got: {:?}",
        after_valid.relays
    );
    assert_eq!(
        after_valid.relays[0].endpoint, valid_endpoint,
        "the persisted relay row's endpoint must match the valid IPv4 endpoint that was registered"
    );
}
