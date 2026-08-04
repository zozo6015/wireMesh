//! Enrollment-token **kind** enforcement at both enrollment boundaries.
//!
//! `enrollment_token.kind` is constrained to `('gateway','relay','rebind')`
//! by the schema (`db.rs`'s `SCHEMA_V1`), and two independent boundaries
//! filter on it:
//!
//!   - the GATEWAY boundary — `Db::enroll_gateway`'s token SELECT carries
//!     `AND kind IN ('gateway', 'rebind')`, and derives
//!     `is_rebind = kind == "rebind"` from the row it matched;
//!   - the RELAY boundary — `Db::enroll_relay`'s token SELECT carries
//!     `AND kind = 'relay'`.
//!
//! Both filters are load-bearing SECURITY checks (a relay token must not be
//! redeemable into a gateway identity that gets a fabric peer slot and a
//! policy feed, and a gateway/rebind token must not be redeemable into a
//! relay identity whose leaf carries the CA-decided SAN `relay`), and until
//! this file neither was pinned by a negative test — flagged in review as
//! "no negative test pins the new controller rebind-kind rejection".
//!
//! **Layer.** These tests drive the real `Enrollment.Enroll` gRPC surface
//! via `wiremesh_testkit::TestController`, not `Db` directly. The filter
//! itself lives in `Db`, but `Db` is not a public API of this crate's test
//! target the way the RPC is, and — more importantly — the property worth
//! pinning is the END-TO-END one: what a caller presenting a wrong-kind
//! token actually observes (which `tonic::Code`, with which message) and
//! what the controller is left holding afterwards. A `Db`-level test would
//! pin the SELECT but say nothing about the handler's error mapping or its
//! non-disclosure posture. This also matches the harness every neighbouring
//! enrollment test already uses (`tests/enroll.rs`, `tests/rebind.rs`,
//! `tests/relay_enroll.rs`).
//!
//! **Observables, not logs.** Each rejection asserts three things: the exact
//! `tonic` status; that the status is BYTE-IDENTICAL to what a plain
//! wrong-secret token gets at the same boundary (the documented
//! non-disclosure posture — a distinguishable "wrong kind" error would be a
//! free oracle for probing token kinds); and a full DB footprint of zero —
//! no `gateway` row, no `relay` row, no `certificate` row, and crucially no
//! SPENT enrollment token. That last one matters on its own: a rejected
//! enroll must not burn the single-use token, so an operator who fat-fingers
//! the boundary can still redeem the token correctly.
//!
//! DB inspection uses a raw second `rusqlite::Connection` onto the
//! controller's on-disk `controller.db`, the same pattern
//! `tests/relay_enroll.rs` established (and for the same reason: these are
//! assertions about raw rows, not about a `Db` accessor anyone needs in
//! production).
use std::path::{Path, PathBuf};

use rusqlite::Connection;
use wiremesh_proto::v1::{CreateSegmentRequest, EnrollRequest, MintTokenRequest};

/// Everything a *successful* enrollment of either kind would leave behind,
/// read in one shot so a rejection can be asserted against a single
/// all-zero value with a readable diff on failure.
///
/// `spent_tokens` counts `enrollment_token` rows with `used_at` set — the
/// single-use token must survive a rejected attempt unspent (both
/// `enroll_gateway` and `enroll_relay` roll their transaction back before
/// the `UPDATE ... SET used_at` on an `InvalidToken`).
#[derive(Debug, PartialEq, Eq)]
struct Footprint {
    gateways: i64,
    relays: i64,
    certificates: i64,
    spent_tokens: i64,
}

impl Footprint {
    /// The footprint of a controller on which nothing has successfully
    /// enrolled: no identity rows, no issued-and-recorded cert, no burnt
    /// token.
    const NOTHING: Footprint = Footprint {
        gateways: 0,
        relays: 0,
        certificates: 0,
        spent_tokens: 0,
    };
}

fn read_footprint(db_path: &Path) -> Footprint {
    let conn = Connection::open(db_path).expect("opening controller.db for footprint inspection");
    let count = |sql: &str| -> i64 {
        conn.query_row(sql, [], |row| row.get(0))
            .unwrap_or_else(|e| panic!("counting rows for {sql:?}: {e}"))
    };
    Footprint {
        gateways: count("SELECT COUNT(*) FROM gateway"),
        relays: count("SELECT COUNT(*) FROM relay"),
        // Only `enroll_gateway`/`enroll_relay` ever INSERT into
        // `certificate` (the controller's self-generated CA does not), so a
        // total count of 0 is an exact "no leaf was issued AND recorded".
        certificates: count("SELECT COUNT(*) FROM certificate"),
        spent_tokens: count("SELECT COUNT(*) FROM enrollment_token WHERE used_at IS NOT NULL"),
    }
}

/// `read_footprint` off the controller's live DB file, from async context.
async fn footprint(h: &wiremesh_testkit::TestController) -> Footprint {
    let db_path: PathBuf = h.data_dir().join("controller.db");
    tokio::task::spawn_blocking(move || read_footprint(&db_path))
        .await
        .expect("blocking footprint-inspection task panicked")
}

/// Every `gateway` row as `(id, status)`, ordered by id.
fn gateway_statuses(db_path: &Path) -> Vec<(i64, String)> {
    let conn = Connection::open(db_path).expect("opening controller.db for gateway inspection");
    let mut stmt = conn
        .prepare("SELECT id, status FROM gateway ORDER BY id")
        .expect("preparing gateway SELECT");
    stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("querying gateway rows")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("collecting gateway rows")
}

/// Every `certificate` row as `(serial, revoked_at)` — `revoked_at` is
/// `None` while the cert is still live.
fn certificate_revocations(db_path: &Path) -> Vec<(String, Option<String>)> {
    let conn = Connection::open(db_path).expect("opening controller.db for certificate inspection");
    let mut stmt = conn
        .prepare("SELECT serial, revoked_at FROM certificate ORDER BY serial")
        .expect("preparing certificate SELECT");
    stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("querying certificate rows")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("collecting certificate rows")
}

/// The same `wiremesh://host/#tok_<secret>@sha256:<fp>` URL with its secret
/// replaced by an all-zero hex string of identical length: still perfectly
/// well-FORMED (so it clears `parse_token_secret`/`hex_decode` and actually
/// reaches the DB's token lookup), but its sha256 matches no stored
/// `secret_hash`. This is the "wrong secret" baseline every wrong-KIND
/// rejection below is compared against — the controller must not let the
/// two be told apart.
fn with_bogus_secret(token: &str) -> String {
    let (prefix, rest) = token
        .split_once("#tok_")
        .unwrap_or_else(|| panic!("minted token has no '#tok_' marker: {token:?}"));
    let (secret, suffix) = rest
        .split_once('@')
        .unwrap_or_else(|| panic!("minted token has no '@' after its secret: {token:?}"));
    format!("{prefix}#tok_{}@{suffix}", "0".repeat(secret.len()))
}

/// Asserts a wrong-kind rejection is indistinguishable from a wrong-secret
/// one: same `tonic::Code` AND same message text. Comparing the two
/// runtime-produced statuses to EACH OTHER (rather than to a literal string
/// baked into the test) pins the non-disclosure property without making the
/// test brittle against a future reword of the shared message.
fn assert_indistinguishable(wrong_kind: &tonic::Status, wrong_secret: &tonic::Status) {
    assert_eq!(
        wrong_kind.code(),
        tonic::Code::PermissionDenied,
        "a wrong-kind token must be refused with PermissionDenied, got: {wrong_kind:?}"
    );
    assert_eq!(
        wrong_kind.code(),
        wrong_secret.code(),
        "a wrong-KIND token must be refused with the same status code as a wrong-SECRET \
         token — a distinguishable code is an oracle for probing token kinds. \
         wrong-kind: {wrong_kind:?}, wrong-secret: {wrong_secret:?}"
    );
    assert_eq!(
        wrong_kind.message(),
        wrong_secret.message(),
        "a wrong-KIND token must be refused with the same message as a wrong-SECRET \
         token — a distinguishable message is an oracle for probing token kinds. \
         wrong-kind: {wrong_kind:?}, wrong-secret: {wrong_secret:?}"
    );
}

/// GATEWAY boundary, negative: a `relay`-kind token must not be redeemable
/// as a gateway.
///
/// The token here is deliberately minted with `bound_cidrs` matching the
/// segment's CIDR exactly — i.e. EVERY other gateway-path check (bound-cidr
/// scope, segment resolution, one-gateway-per-segment occupancy) would pass.
/// The `AND kind IN ('gateway', 'rebind')` filter is therefore the ONLY
/// thing standing between this token and a successful gateway enrollment,
/// which is what makes this test genuinely red if that filter is ever
/// broadened (rather than tripping some later check and passing for the
/// wrong reason).
#[tokio::test]
async fn relay_token_rejected_at_gateway_enrollment_boundary() {
    let h = wiremesh_testkit::TestController::start().await;
    let mut admin = h.admin_client().await;

    admin
        .create_segment(CreateSegmentRequest {
            name: "aws".into(),
            cidrs: vec!["10.0.0.0/16".into()],
        })
        .await
        .expect("creating segment aws");

    let tok = admin
        .mint_token(MintTokenRequest {
            kind: "relay".into(),
            // See the doc comment: scoped so that ONLY the kind filter can
            // reject this token.
            bound_cidrs: vec!["10.0.0.0/16".into()],
            rebind_segment_id: 0,
        })
        .await
        .expect("minting a relay-kind token")
        .into_inner()
        .token;

    let mut enr = h.enrollment_client().await;

    // Empty `endpoint` selects the GATEWAY path (the handler routes relay
    // vs gateway by request shape, not by an explicit field).
    let (csr, _kp) = wiremesh_testkit::gen_csr("gw-aws");
    let wrong_kind = enr
        .enroll(EnrollRequest {
            token: tok.clone(),
            csr_pem: csr,
            cidrs: vec!["10.0.0.0/16".into()],
            wg_pubkey: String::new(),
            endpoint: String::new(),
        })
        .await
        .expect_err("a relay-kind token must not be redeemable as a gateway");

    // Baseline: same boundary, same request shape, a well-formed but
    // unknown secret.
    let (csr2, _kp2) = wiremesh_testkit::gen_csr("gw-aws");
    let wrong_secret = enr
        .enroll(EnrollRequest {
            token: with_bogus_secret(&tok),
            csr_pem: csr2,
            cidrs: vec!["10.0.0.0/16".into()],
            wg_pubkey: String::new(),
            endpoint: String::new(),
        })
        .await
        .expect_err("an unknown token secret must be refused");

    assert_indistinguishable(&wrong_kind, &wrong_secret);

    assert_eq!(
        footprint(&h).await,
        Footprint::NOTHING,
        "a rejected relay-token-as-gateway attempt must leave NOTHING behind — no gateway \
         row, no certificate row, and the single-use token must remain unspent so it can \
         still be redeemed at the boundary it was actually minted for"
    );
}

/// RELAY boundary, negative: a `gateway`-kind token must not be redeemable
/// as a relay.
///
/// (`tests/relay_enroll.rs::gateway_token_cannot_enroll_a_relay` covers the
/// same direction from the relay feature's side, asserting only "errored,
/// and no relay row". This one is the kind-enforcement pinning: exact
/// status, non-disclosure parity with a wrong secret, and the FULL
/// footprint — in particular that the CA-signed leaf the relay path
/// produces BEFORE the DB transaction is discarded rather than recorded,
/// and that the token is not burnt.)
#[tokio::test]
async fn gateway_token_rejected_at_relay_enrollment_boundary() {
    let h = wiremesh_testkit::TestController::start().await;
    let mut admin = h.admin_client().await;

    let tok = admin
        .mint_token(MintTokenRequest {
            kind: "gateway".into(),
            bound_cidrs: vec!["10.0.0.0/16".into()],
            rebind_segment_id: 0,
        })
        .await
        .expect("minting a gateway-kind token")
        .into_inner()
        .token;

    let mut enr = h.enrollment_client().await;

    // Non-empty `endpoint` (and empty `cidrs`) selects the RELAY path.
    let (csr, _kp) = wiremesh_testkit::gen_csr("relay-1");
    let wrong_kind = enr
        .enroll(EnrollRequest {
            token: tok.clone(),
            csr_pem: csr,
            cidrs: vec![],
            wg_pubkey: String::new(),
            endpoint: "203.0.113.9:51820".into(),
        })
        .await
        .expect_err("a gateway-kind token must not be redeemable as a relay");

    let (csr2, _kp2) = wiremesh_testkit::gen_csr("relay-1");
    let wrong_secret = enr
        .enroll(EnrollRequest {
            token: with_bogus_secret(&tok),
            csr_pem: csr2,
            cidrs: vec![],
            wg_pubkey: String::new(),
            endpoint: "203.0.113.9:51820".into(),
        })
        .await
        .expect_err("an unknown token secret must be refused");

    assert_indistinguishable(&wrong_kind, &wrong_secret);

    assert_eq!(
        footprint(&h).await,
        Footprint::NOTHING,
        "a rejected gateway-token-as-relay attempt must leave NOTHING behind — no relay \
         row, no certificate row (the leaf the relay path signs before its transaction \
         must be discarded, never recorded), and the token must remain unspent"
    );
}

/// RELAY boundary, negative: a `rebind`-kind token must not be redeemable as
/// a relay either.
///
/// This is the direction the review specifically called out as unpinned.
/// `rebind` is the newest kind and the one most likely to be accidentally
/// swept into a widened filter (`kind IN ('relay', 'rebind')` reads
/// plausible at a glance), yet a rebind token's entire authorization scope
/// is a SEGMENT id — a concept the relay path doesn't even look at, so a
/// rebind token accepted here would be an unscoped relay credential.
#[tokio::test]
async fn rebind_token_rejected_at_relay_enrollment_boundary() {
    let h = wiremesh_testkit::TestController::start().await;
    let mut admin = h.admin_client().await;

    // A rebind token needs a real, non-zero `rebind_segment_id` (MintToken
    // rejects 0 outright), so the token under test is a genuinely valid
    // rebind token — not one that would fail for an unrelated reason.
    let seg = admin
        .create_segment(CreateSegmentRequest {
            name: "aws".into(),
            cidrs: vec!["10.0.0.0/16".into()],
        })
        .await
        .expect("creating segment aws")
        .into_inner();

    let tok = admin
        .mint_token(MintTokenRequest {
            kind: "rebind".into(),
            bound_cidrs: vec![],
            rebind_segment_id: seg.id,
        })
        .await
        .expect("minting a rebind token bound to segment aws")
        .into_inner()
        .token;

    let mut enr = h.enrollment_client().await;

    let (csr, _kp) = wiremesh_testkit::gen_csr("relay-1");
    let wrong_kind = enr
        .enroll(EnrollRequest {
            token: tok.clone(),
            csr_pem: csr,
            cidrs: vec![],
            wg_pubkey: String::new(),
            endpoint: "203.0.113.9:51820".into(),
        })
        .await
        .expect_err("a rebind-kind token must not be redeemable as a relay");

    let (csr2, _kp2) = wiremesh_testkit::gen_csr("relay-1");
    let wrong_secret = enr
        .enroll(EnrollRequest {
            token: with_bogus_secret(&tok),
            csr_pem: csr2,
            cidrs: vec![],
            wg_pubkey: String::new(),
            endpoint: "203.0.113.9:51820".into(),
        })
        .await
        .expect_err("an unknown token secret must be refused");

    assert_indistinguishable(&wrong_kind, &wrong_secret);

    assert_eq!(
        footprint(&h).await,
        Footprint::NOTHING,
        "a rejected rebind-token-as-relay attempt must leave NOTHING behind — no relay \
         row, no certificate row, and the token must remain unspent"
    );
}

/// GATEWAY boundary, POSITIVE: a `rebind`-kind token IS accepted here, and
/// takes the rebind path rather than the ordinary gateway path.
///
/// This is the counterweight to the three negatives above: without it,
/// "fixing" a kind-rejection failure by narrowing the gateway filter to
/// `kind = 'gateway'` — or by hard-coding `is_rebind = false` — would look
/// green. So this pins both halves of what the filter's `IN ('gateway',
/// 'rebind')` + `is_rebind = kind == "rebind"` pair buys:
///
///   1. ACCEPTED — the replacement gateway enrolls at all (a narrowed filter
///      refuses it with PermissionDenied), and does so while declaring CIDRs
///      an existing segment already owns, which an ordinary gateway token
///      cannot do;
///   2. REBIND PATH TAKEN — the replaced gateway's row flips to `replaced`
///      and its certificate gets `revoked_at` set, neither of which the
///      ordinary gateway path does. (`is_rebind = false` would additionally
///      trip the bound-cidr check, since a rebind token carries no
///      `bound_cidrs` at all.)
///
/// `tests/rebind.rs` covers the same acceptance from the denylist/Sync-
/// projection angle; this asserts it at the DB rows the kind filter
/// directly controls.
#[tokio::test]
async fn rebind_token_accepted_at_gateway_boundary_and_takes_rebind_path() {
    let h = wiremesh_testkit::TestController::start().await;

    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    let old_id = a.id() as i64;
    let old_serial = a
        .cert_serial()
        .expect("parsing the original gateway's cert serial");

    let mut admin = h.admin_client().await;
    let tok = admin
        .mint_token(MintTokenRequest {
            kind: "rebind".into(),
            bound_cidrs: vec![],
            rebind_segment_id: a.segment_id(),
        })
        .await
        .expect("minting a rebind token bound to segment aws")
        .into_inner()
        .token;

    let b = wiremesh_testkit::StubGateway::enroll(&h, &tok, &["10.0.0.0/16"])
        .await
        .expect(
            "a rebind-kind token MUST be accepted at the gateway enrollment boundary — \
             it is one of the two kinds that boundary's filter admits",
        );
    let new_id = b.id() as i64;
    let new_serial = b
        .cert_serial()
        .expect("parsing the replacement gateway's cert serial");

    assert_ne!(
        new_id, old_id,
        "the rebind must enroll a NEW gateway row, not reuse the replaced one"
    );

    let db_path: PathBuf = h.data_dir().join("controller.db");
    let (statuses, certs) = tokio::task::spawn_blocking({
        let db_path = db_path.clone();
        move || (gateway_statuses(&db_path), certificate_revocations(&db_path))
    })
    .await
    .expect("blocking rebind-row inspection task panicked");

    let status_of = |id: i64| -> String {
        statuses
            .iter()
            .find(|(row_id, _)| *row_id == id)
            .unwrap_or_else(|| panic!("no gateway row with id {id}; rows were: {statuses:?}"))
            .1
            .clone()
    };
    assert_eq!(
        status_of(old_id),
        "replaced",
        "the rebind path must mark the replaced gateway's row 'replaced' (an ordinary \
         gateway enrollment never touches another gateway's row); rows were: {statuses:?}"
    );
    assert_eq!(
        status_of(new_id),
        "active",
        "the replacement gateway must be active; rows were: {statuses:?}"
    );

    let revoked_at_of = |serial: &str| -> Option<String> {
        certs
            .iter()
            .find(|(row_serial, _)| row_serial.eq_ignore_ascii_case(serial))
            .unwrap_or_else(|| {
                panic!("no certificate row with serial {serial}; rows were: {certs:?}")
            })
            .1
            .clone()
    };
    assert!(
        revoked_at_of(&old_serial).is_some(),
        "the rebind path must revoke the replaced gateway's cert (serial {old_serial}); \
         certificate rows were: {certs:?}"
    );
    assert!(
        revoked_at_of(&new_serial).is_none(),
        "the replacement gateway's freshly issued cert (serial {new_serial}) must NOT be \
         revoked; certificate rows were: {certs:?}"
    );
}
