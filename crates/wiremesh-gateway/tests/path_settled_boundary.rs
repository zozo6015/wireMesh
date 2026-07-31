//! Settled-boundary transition classification (relay-wedge fix, round 4 —
//! gateway half (a) of the unsettle-re-brokering fix).
//!
//! ## Why this helper exists
//!
//! The authoritative case-4 run showed the remaining gap: after both sides
//! of a relayed pair detect a `TimedOut` relay death, clear their pins, and
//! punch, their punch windows are UNSYNCHRONIZED (idle-timeout detection +
//! backoff drift) — and a port-restricted pair needs simultaneity. The
//! controller broker is the synchronizer, but gateways only send a
//! `peer_paths` snapshot Report on `SyncEvent::State`, so the controller's
//! stored states still said `relayed`/`relayed` (settled — possibly even
//! settled-SKIPPING the pair) long after the pair fell off the relay, and
//! the pair's periodic punch budget had been exhausted back in the
//! establishment phase.
//!
//! Fix half (a): the gateway must Report PROMPTLY when any peer's path
//! state crosses INTO or OUT OF the settled set `{direct, relayed}` — the
//! `to_record` loop in `run_path_ticks` already computes every
//! `(before, after)` transition; what it needs is a pure classifier for
//! "does this transition change the pair's settled-ness as the broker sees
//! it". That classifier is the seam pinned here:
//!
//! ```ignore
//! // in wiremesh_gateway::path
//! pub fn transition_crosses_settled_boundary(before: PathState, after: PathState) -> bool;
//! ```
//!
//! Semantics: `true` iff settled-set membership CHANGES, where the settled
//! set is exactly the broker's `{Direct, Relayed}` (the states
//! `wiremesh-controller`'s pathstate-aware skip treats as settled — see
//! `crates/wiremesh-controller/tests/broker_pathstate.rs`). Both directions
//! matter: entering settled tells the broker it may STOP re-punching;
//! LEAVING settled (e.g. `direct -> degraded`, `relayed -> disconnected`)
//! is the edge that must un-skip the pair and re-arm its punch budget.
//! Movement WITHIN one side of the boundary (`connecting -> disconnected`,
//! `direct -> relayed`) changes nothing the broker acts on and must be
//! `false` — every `true` triggers a Report, and a `false`-worthy
//! transition reported eagerly would just re-create report chatter.
//!
//! ## What is deliberately integration-only (NOT pinned here)
//!
//! The plumbing that acts on this classifier lives in `main.rs` (the
//! binary, not the lib, so no integration test can import it): the
//! tick-loop -> sync-loop notify channel, and the debounce (at least one
//! coalesced snapshot Report per ~2s across all peers, rather than one RPC
//! per transition). Those are proven end-to-end, not structurally:
//! `relay_matrix.rs` case 4 only goes green if the unsettle Report
//! actually reaches the controller promptly (its recovery budget leaves no
//! room for waiting on the next `SyncEvent::State`), and the controller
//! half of the contract is pinned by `broker_pathstate.rs`'s
//! unsettle-re-brokering cases.
//!
//! NOTE: this file is intentionally compile-RED until the helper lands —
//! the function name, signature, and truth table below ARE the pinned API.

use wiremesh_gateway::path::{transition_crosses_settled_boundary, PathState};

/// The six transitions called out in the fix decision, pinned by name so a
/// regression points at the exact case (the exhaustive test below covers
/// the full matrix, but these are the load-bearing ones).
#[test]
fn named_boundary_cases() {
    use PathState::*;

    // Leaving the settled set — the edge that must un-skip the pair on the
    // broker and re-arm its punch budget.
    assert!(
        transition_crosses_settled_boundary(Relayed, Disconnected),
        "relayed -> disconnected leaves settled (the case-4 relay-death edge) — must report"
    );
    assert!(
        transition_crosses_settled_boundary(Direct, Degraded),
        "direct -> degraded leaves settled — leaving settled matters just as much as \
         entering it (the broker would otherwise keep settled-skipping a degrading pair)"
    );

    // Entering the settled set — tells the broker it may stop re-punching.
    assert!(
        transition_crosses_settled_boundary(Connecting, Direct),
        "connecting -> direct enters settled — must report"
    );
    assert!(
        transition_crosses_settled_boundary(Degraded, Relayed),
        "degraded -> relayed enters settled — must report"
    );

    // Movement entirely on the unsettled side — nothing the broker acts on.
    assert!(
        !transition_crosses_settled_boundary(Connecting, Disconnected),
        "connecting -> disconnected stays unsettled — no boundary crossing, no report"
    );
    assert!(
        !transition_crosses_settled_boundary(Disconnected, Connecting),
        "disconnected -> connecting stays unsettled — no boundary crossing, no report"
    );
}

/// Movement WITHIN the settled set is not a crossing either: the broker's
/// settled-skip treats `direct` and `relayed` identically (its OR-semantics
/// are pinned by `broker_pathstate.rs`'s mixed direct/relayed case), so a
/// make-before-break cutover between them must not fire the prompt-report
/// path.
#[test]
fn movement_within_settled_set_is_not_a_crossing() {
    use PathState::*;
    assert!(
        !transition_crosses_settled_boundary(Relayed, Direct),
        "relayed -> direct stays settled (make-before-break cutover) — not a crossing"
    );
    assert!(
        !transition_crosses_settled_boundary(Direct, Relayed),
        "direct -> relayed stays settled — not a crossing"
    );
}

/// The full 25-pair matrix, derived from the one rule the helper exists to
/// encode: `crosses(before, after) == (settled(before) != settled(after))`
/// with `settled = {Direct, Relayed}`. Exhaustive so a future sixth state
/// (or an accidental special case for some pair) cannot slip through a
/// hand-picked case list — including the five identity transitions, which
/// must all be `false` (a non-transition can never be a crossing; the
/// driver only consults the helper for `before != after` entries in
/// `to_record`, but the helper must not rely on that).
#[test]
fn exhaustive_matrix_matches_membership_rule() {
    use PathState::*;
    let all = [Connecting, Direct, Degraded, Relayed, Disconnected];
    let settled = |s: PathState| matches!(s, Direct | Relayed);

    for &before in &all {
        for &after in &all {
            let expected = settled(before) != settled(after);
            assert_eq!(
                transition_crosses_settled_boundary(before, after),
                expected,
                "{before:?} -> {after:?}: expected crossing={expected} \
                 (settled({before:?})={}, settled({after:?})={})",
                settled(before),
                settled(after)
            );
        }
    }
}
