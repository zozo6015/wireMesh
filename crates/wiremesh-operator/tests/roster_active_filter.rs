//! FAILING tests (test-author, operator hardening round, Backlog 4) — Fix 2:
//! ROSTER FILTER. **compile-RED** until the pinned helper exists.
//!
//! # The bug
//!
//! `Db::list_gateways` returns EVERY status ('active', 'drained', 'replaced',
//! …) ordered by id, but the gateway reconciler matches its roster row by
//! segment name FIRST-MATCH at four sites (gateway.rs:188 mint/status snapshot,
//! :244 adoption stale-id, :284 pre-drain recheck, :410 finalizer fallback).
//! With a stale drained row (lower id) present alongside the live active row:
//!   * status mis-reports the drained id / "drained" path state;
//!   * the CR-delete finalizer drains the WRONG id;
//!   * worst: `gateway_active` is derived from `seg_row.is_some()`, so a
//!     drained-only roster still reads "active" → `identity_persisted` true →
//!     mint suppressed → a gateway that actually needs a fresh token deadlocks
//!     (the mint-suppression deadlock).
//!
//! # Pinned implementer surface
//!
//! The selection is inline today, so the fix is pinned as an extraction — ONE
//! choke point that all four call sites route through:
//! ```ignore
//! // in controllers::gateway
//! pub fn active_in_segment<'a>(roster: &'a [GatewayRow], segment: &str) -> Option<&'a GatewayRow>
//! ```
//! Returns the roster row for `segment` whose `status == "active"` — never a
//! drained/replaced/draining row, regardless of roster ordering. (Filtering
//! status=="active" inside `AdminExec::list_gateways` instead is NOT
//! equivalent-safe: the adoption path must still SEE non-active rows absent
//! while the status path needs the active row — the per-segment selector is
//! the single correct boundary. If the implementer prefers the transport-level
//! filter they must still expose this fn so these tests bind.)

use wiremesh_operator::admin_exec::GatewayRow;
use wiremesh_operator::controllers::gateway::active_in_segment;

fn row(id: u64, segment: &str, status: &str) -> GatewayRow {
    GatewayRow {
        id,
        name: format!("gw-{id}"),
        segment: segment.to_string(),
        status: status.to_string(),
        applied_version: 0,
    }
}

#[test]
fn picks_active_row_over_older_drained_row_in_same_segment() {
    // Db::list_gateways orders by id, so the STALE drained row (id 3) precedes
    // the live active row (id 7). A first-match-by-segment would return id 3 —
    // the exact status/drain mis-report. The selector must skip to the active row.
    let roster = vec![row(3, "home", "drained"), row(7, "home", "active")];
    let got = active_in_segment(&roster, "home").expect("the active row must be found");
    assert_eq!(
        got.id, 7,
        "must select the ACTIVE row, not the older drained first-match"
    );
    assert_eq!(got.status, "active");
}

#[test]
fn returns_none_when_only_non_active_rows_exist() {
    // THE MINT-SUPPRESSION DEADLOCK KILLER: a drained-only roster must read as
    // "no active gateway" so `gateway_active` is false → `identity_persisted`
    // false → a fresh token IS minted. If this returned Some(drained row), the
    // reconciler would suppress the mint forever while the pod Init:Errors on
    // the spent token.
    let roster = vec![row(3, "home", "drained"), row(5, "home", "replaced")];
    assert!(
        active_in_segment(&roster, "home").is_none(),
        "drained/replaced-only roster → None (no active gateway; the mint must proceed)"
    );
}

#[test]
fn never_selects_intermediate_statuses() {
    // Every non-"active" status is excluded — not just 'drained'. 'draining' /
    // 'replaced' rows must never be reported as the segment's gateway either.
    for status in ["draining", "replaced", "drained", "revoked"] {
        let roster = vec![row(4, "aws", status)];
        assert!(
            active_in_segment(&roster, "aws").is_none(),
            "status {status:?} must not be selected as the segment's active gateway"
        );
    }
}

#[test]
fn matches_only_the_requested_segment() {
    let roster = vec![row(1, "aws", "active"), row(2, "home", "active")];
    assert_eq!(active_in_segment(&roster, "home").map(|g| g.id), Some(2));
    assert_eq!(active_in_segment(&roster, "aws").map(|g| g.id), Some(1));
    assert!(
        active_in_segment(&roster, "gcp").is_none(),
        "unknown segment → None"
    );
}

#[test]
fn empty_roster_yields_none() {
    assert!(active_in_segment(&[], "home").is_none());
}
