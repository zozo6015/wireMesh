//! FAILING tests (test-author, operator review round) — CRITICAL: the operator
//! mints REBIND tokens with the WRONG `kind`. **compile-RED** until the pinned
//! pure surfaces exist.
//!
//! # The bug (all three layers)
//!
//! The controller keys rebind SOLELY off the token's `kind`:
//!   * `db.rs:1330` — `let is_rebind = kind == "rebind";`
//!   * `rebind_segment_id` is read ONLY inside that `is_rebind` arm
//!     (db.rs:1402-1410); a non-rebind token's stored segment id is dead data.
//!   * a `kind == "gateway"` token redeemed against an OCCUPIED segment takes
//!     the `else` arm and is rejected with `SegmentAlreadyBound`
//!     (db.rs:1454-1466).
//!
//! The operator sends `kind = "gateway"` on every rebind mint, on BOTH
//! transports:
//!   * gRPC — `admin.rs` `mint_gateway_rebind_token` → `self.mint_token("gateway", ..)`;
//!   * exec — `admin_exec.rs` → argv `["mint-token", "--kind", "gateway",
//!     "--rebind-segment-id", "<id>"]`, and `operator_admin.rs` passes `--kind`
//!     through to `MintTokenRequest.kind` verbatim.
//! So EVERY operator-issued rebind is a plain gateway token: the CIDR-change
//! rebind path (gateway.rs:415-455) can never replace the segment's active
//! gateway — the redemption is refused and the gateway stays wedged.
//!
//! # Sanctioned encoding (pinned by `crates/wiremesh-controller/tests/rebind.rs:40-44`)
//!
//! ```ignore
//! MintTokenRequest { kind: "rebind", bound_cidrs: vec![], rebind_segment_id: seg_id }
//! ```
//! `bound_cidrs` MUST be empty: for a rebind token the controller skips the
//! bound-CIDR scope check entirely (db.rs' `if !is_rebind` block) and scopes
//! authorization by segment id alone — carrying CIDRs there is dead, misleading
//! data that diverges from the one sanctioned encoding.
//!
//! # Pinned implementer surfaces (the request construction is inline today —
//! extract it so ONE definition feeds both transports and this test)
//!
//! ```ignore
//! // wiremesh_operator::admin
//! /// The token `kind` the controller keys rebind off (db.rs:1330). NOT "gateway".
//! pub const REBIND_TOKEN_KIND: &str = "rebind";
//! /// The exact MintTokenRequest an operator rebind mint must send.
//! pub fn rebind_mint_request(rebind_segment_id: u64) -> MintTokenRequest;
//!
//! // wiremesh_operator::admin_exec
//! /// The exec-transport argv for the same mint (operator-admin flags).
//! pub fn rebind_mint_args(rebind_segment_id: u64) -> Vec<String>;
//! ```
//! Both `FabricAdmin::mint_gateway_rebind_token` and
//! `AdminExec::mint_gateway_rebind_token` must be re-signatured to
//! `(rebind_segment_id: u64)` — the `cidrs` parameter DROPS (a rebind carries
//! no CIDR binding). Call site to update: `controllers/gateway.rs:438`.

use wiremesh_operator::admin::{rebind_mint_request, REBIND_TOKEN_KIND};
use wiremesh_operator::admin_exec::{rebind_mint_args, AdminExec};

#[test]
fn rebind_kind_constant_is_the_controllers_rebind_kind() {
    // db.rs:1330 `is_rebind = kind == "rebind"` — any other value silently
    // degrades to an ordinary gateway token.
    assert_eq!(
        REBIND_TOKEN_KIND, "rebind",
        "the controller keys rebind off kind == \"rebind\"; \"gateway\" makes the \
         token an ordinary one that SegmentAlreadyBound will reject"
    );
}

#[test]
fn rebind_mint_request_carries_rebind_kind_empty_cidrs_and_segment_id() {
    let req = rebind_mint_request(42);
    assert_eq!(
        req.kind, "rebind",
        "kind MUST be \"rebind\" (this is the whole bug: the operator sends \"gateway\")"
    );
    assert!(
        req.bound_cidrs.is_empty(),
        "a rebind token carries NO bound CIDRs — its scope is the segment id \
         (the controller skips the bound-CIDR check for rebind); got {:?}",
        req.bound_cidrs
    );
    assert_eq!(
        req.rebind_segment_id, 42,
        "the segment id must reach the wire — it is what the controller matches \
         against the resolved segment at redemption (db.rs:1402-1410)"
    );
}

#[test]
fn rebind_mint_request_matches_the_sanctioned_controller_test_encoding() {
    // Byte-for-byte the request `crates/wiremesh-controller/tests/rebind.rs:40-44`
    // proves works end-to-end. Constructed independently here so a change to
    // either side breaks this pin.
    let sanctioned = wiremesh_proto::v1::MintTokenRequest {
        kind: "rebind".into(),
        bound_cidrs: vec![],
        rebind_segment_id: 7,
    };
    let ours = rebind_mint_request(7);
    assert_eq!(ours.kind, sanctioned.kind);
    assert_eq!(ours.bound_cidrs, sanctioned.bound_cidrs);
    assert_eq!(ours.rebind_segment_id, sanctioned.rebind_segment_id);
}

#[test]
fn exec_transport_rebind_args_use_rebind_kind_and_no_cidrs() {
    // The exec transport must encode the SAME thing as the gRPC one:
    // `operator_admin.rs` forwards `--kind` verbatim into MintTokenRequest.kind,
    // so `--kind gateway` there is the identical bug on the production path.
    let args = rebind_mint_args(42);
    let pos = |flag: &str| args.iter().position(|a| a == flag);

    assert_eq!(
        args.first().map(String::as_str),
        Some("mint-token"),
        "op is mint-token: {args:?}"
    );
    let k = pos("--kind").expect("argv must carry --kind");
    assert_eq!(
        args.get(k + 1).map(String::as_str),
        Some("rebind"),
        "--kind must be rebind, NOT gateway: {args:?}"
    );
    let r = pos("--rebind-segment-id").expect("argv must carry --rebind-segment-id");
    assert_eq!(
        args.get(r + 1).map(String::as_str),
        Some("42"),
        "--rebind-segment-id must carry the segment id: {args:?}"
    );
    assert!(
        pos("--cidr").is_none(),
        "a rebind mint must pass NO --cidr flags (bound_cidrs is empty): {args:?}"
    );
}

/// Compile-pin: both transports' rebind mints take the segment id ALONE — the
/// `cidrs` parameter is dropped, so no caller can reintroduce a CIDR binding.
/// Never called; its compilation IS the assertion.
#[allow(dead_code)]
async fn _pin_rebind_mint_signatures(
    exec: &AdminExec,
    grpc: &mut wiremesh_operator::admin::FabricAdmin,
) -> anyhow::Result<(String, String)> {
    let a = exec.mint_gateway_rebind_token(7).await?;
    let b = grpc.mint_gateway_rebind_token(7).await?;
    Ok((a, b))
}
