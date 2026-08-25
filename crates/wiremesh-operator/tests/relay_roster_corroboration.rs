//! FAILING tests (test-author, final operator round) — RELAY ROSTER
//! CORROBORATION. **compile-RED** until the inline matching is extracted.
//!
//! # The behavior being pinned (relay.rs:105-115, d495d66)
//!
//! `identity_persisted` for a relay = the PVC exists AND the controller's relay
//! roster holds a row for this CR's ENDPOINT. Three properties are load-bearing
//! and each is easy to break by accident:
//!
//! 1. **Matched by ENDPOINT, never by name.** The controller names an enrolled
//!    relay `relay-<token-hash>` (`services/enrollment.rs`), never the CR's
//!    name; the endpoint is the CR's `spec.endpoint` verbatim. A name match
//!    would never hit → identity read as never-persisted → a spare token minted
//!    on EVERY 15s reconcile forever.
//! 2. **Deliberately NOT status-filtered.** The health pipeline EVICTS by
//!    flipping `status` (`Db::set_relay_status` — "a HEALTH-eviction state, not
//!    a revocation/de-enrollment"); it never deletes the row. Presence at ANY
//!    status is exactly "this relay completed an enrollment", which is the
//!    historical fact being asked about. (Contrast the gateway's
//!    `active_in_segment`, where the status filter guards the
//!    one-gateway-per-segment occupancy invariant — a different question.)
//! 3. **PVC still required.** A roster row alone is not enough: a replaced or
//!    not-yet-created PVC holds no identity, and that pass must re-mint.
//!
//! # Pinned implementer surface
//!
//! ```ignore
//! // in controllers::relay
//! /// `pvc_exists && the roster holds a row whose `endpoint` equals `endpoint`.
//! /// Endpoint-matched (the controller renames relays), and deliberately NOT
//! /// status-filtered (eviction flips status; the row persists).
//! pub fn relay_identity_persisted(
//!     pvc_exists: bool,
//!     roster: &[RelayRow],
//!     endpoint: &str,
//! ) -> bool;
//! ```
//! The reconciler keeps owning the I/O and the conservative failure rule (a
//! failed `list_relays` → treat as NOT enrolled → mint a spare token, which
//! lapses because `wiremesh-relay-enroll` now skips on a complete identity).
//! That error arm is a `match` around an `.await` and is NOT unit-testable
//! without a controller mock — it stays review-verified; what IS pinned here is
//! that an empty roster (the value the error arm substitutes) yields `false`.

use wiremesh_operator::admin_exec::RelayRow;
use wiremesh_operator::controllers::relay::relay_identity_persisted;

const EP: &str = "203.0.113.9:4443";

fn row(id: u64, name: &str, endpoint: &str, status: &str) -> RelayRow {
    RelayRow {
        id,
        name: name.to_string(),
        endpoint: endpoint.to_string(),
        status: status.to_string(),
    }
}

#[test]
fn endpoint_match_corroborates_regardless_of_status() {
    // Property 2: eviction is a health flip, not a de-enrollment. Every status
    // must corroborate — otherwise an evicted (but enrolled) relay re-mints a
    // spare token every reconcile for the whole outage.
    for status in ["active", "inactive", "evicted", "unhealthy", "unknown"] {
        let roster = vec![row(1, "relay-9f3ac2", EP, status)];
        assert!(
            relay_identity_persisted(true, &roster, EP),
            "a roster row with status {status:?} must still corroborate a persisted identity \
             (eviction flips status; the row is never deleted)"
        );
    }
}

#[test]
fn match_is_by_endpoint_not_by_cr_name() {
    // Property 1: the controller-side name is `relay-<token-hash>` and shares
    // nothing with the CR's name — matching on it would never hit.
    let roster = vec![row(1, "relay-9f3ac2", EP, "active")];
    assert!(
        relay_identity_persisted(true, &roster, EP),
        "the endpoint must be what is matched (the roster name is controller-generated)"
    );

    // A row whose NAME happens to equal the CR's name but whose ENDPOINT differs
    // must NOT corroborate — that is a different relay.
    let roster = vec![row(2, "relay-eu", "198.51.100.7:4443", "active")];
    assert!(
        !relay_identity_persisted(true, &roster, EP),
        "a name-only coincidence must NOT corroborate; the endpoint is the identity key"
    );
}

#[test]
fn no_matching_endpoint_is_not_persisted() {
    let roster = vec![
        row(1, "relay-aaa", "198.51.100.7:4443", "active"),
        row(2, "relay-bbb", "198.51.100.8:4443", "inactive"),
    ];
    assert!(
        !relay_identity_persisted(true, &roster, EP),
        "no row for this CR's endpoint → identity not persisted → mint a fresh token"
    );
}

#[test]
fn empty_roster_is_not_persisted() {
    // Also the value the conservative error arm substitutes on a failed
    // `list_relays`: an unreadable roster must never read as corroboration.
    assert!(
        !relay_identity_persisted(true, &[], EP),
        "empty roster (incl. the failed-probe substitute) → not persisted"
    );
}

#[test]
fn missing_pvc_is_never_persisted_even_with_a_roster_row() {
    // Property 3: the PVC is where the identity actually lives. A roster row
    // from a PREVIOUS incarnation must not suppress the mint for a pod whose
    // PVC does not exist yet (or was replaced) — that is the Init:Error wedge.
    let roster = vec![row(1, "relay-9f3ac2", EP, "active")];
    assert!(
        !relay_identity_persisted(false, &roster, EP),
        "no PVC → NOT persisted even with a matching roster row (the identity has nowhere to live)"
    );
    assert!(
        !relay_identity_persisted(false, &[], EP),
        "neither → not persisted"
    );
}

#[test]
fn exact_endpoint_comparison_no_prefix_or_port_slack() {
    // `203.0.113.9:4443` must not be corroborated by a different port on the
    // same host, nor by a host whose string merely contains it.
    let roster = vec![
        row(1, "relay-aaa", "203.0.113.9:4444", "active"),
        row(2, "relay-bbb", "203.0.113.90:4443", "active"),
        row(3, "relay-ccc", "203.0.113.9", "active"),
    ];
    assert!(
        !relay_identity_persisted(true, &roster, EP),
        "endpoint comparison must be exact — a neighbouring port/host must not corroborate"
    );
}
