//! Item 3a — the relay's duplicate-registration rule as a pure truth table.
//!
//! `register_decision` is the whole 2x2 (same/different owner × same/different
//! peer) plus the free-slot case, extracted so it is decidable WITHOUT a real
//! key collision and WITHOUT a relay process. `serve` is now purely its
//! executor: the two Reject arms log and close (application code `3` for
//! owned-by-other, preserved so `tests/impersonation.rs` is untouched; `4` for
//! collision), and the two Accept arms fall through to the same single
//! `reg.insert`.
//!
//! ```ignore
//! pub enum RegisterDecision { Accept, ReplaceOwnSlot, RejectOwnedByOther, RejectKeyCollision }
//!
//! pub fn register_decision(
//!     existing: Option<(&str /*owner*/, &str /*peer*/)>,
//!     cert_identity: &str,
//!     peer_identity: &str,
//! ) -> RegisterDecision;
//! ```
//!
//! # Why the ARM ORDER is the security property
//!
//! `cert_identity` is unforgeable — the relay reads it off the authenticated
//! client certificate's `gw-<id>` SAN. `peer_identity` is NOT: it is whatever
//! the registering connection typed on the wire, entirely attacker-chosen.
//!
//! That asymmetry is what re-graded this item. Because the peer half is free,
//! an attacker holding ANY valid gateway cert can brute-force a peer string P
//! with `registration_key("gw-C", P) == registration_key("gw-A", "gw-B")` and
//! aim its registration straight at another pair's slot. (Against the old
//! 32-bit key that is a ~4.3e9 target preimage — minutes on a laptop; the
//! widened 64-bit key is what makes it infeasible, but the decision must not
//! depend on that.) Landing there, it would lock gw-A out of its own relay
//! path and receive gw-B's datagrams.
//!
//! So ownership must be checked FIRST and UNCONDITIONALLY. An implementation
//! that tested the peer half first — the natural-looking
//!
//! ```ignore
//! Some((_, peer)) if peer == peer_identity => ReplaceOwnSlot,
//! Some((owner, _)) if owner != cert_identity => RejectOwnedByOther,
//! ```
//!
//! — is a slot-hijack primitive: the attacker simply types the incumbent's own
//! peer identity (`gw-B`, trivially guessable from the enumerable `gw-<rowid>`
//! naming) and the rejection is upgraded into a replace. Nothing else in the
//! relay would catch it, and nothing in a same-owner-only test would notice.
//! `different_owner_is_rejected_whatever_the_attacker_chosen_peer_half_says`
//! below is the assertion that fails loudly if the two arms are ever inverted.
//!
//! Modeled on `crates/wiremesh-operator/tests/mint_action_deferral.rs`, the
//! repo's precedent for pinning an extracted pure decision (d47fb36).

use wiremesh_relay::{register_decision, RegisterDecision};

/// The incumbent slot used throughout: owned by `gw-A`, registered for peer
/// `gw-B`. Both halves are deliberately guessable — production identities are
/// sequential `gw-<rowid>` (`services::enrollment`).
const INCUMBENT: Option<(&str, &str)> = Some(("gw-A", "gw-B"));

// ---------------------------------------------------------------------------
// The free-slot case
// ---------------------------------------------------------------------------

#[test]
fn a_free_slot_is_always_accepted() {
    assert_eq!(
        register_decision(None, "gw-A", "gw-B"),
        RegisterDecision::Accept,
        "an unoccupied key must be accepted"
    );
    // No identity is privileged when the slot is free — the receive-side
    // binding (my_identity == cert SAN) is enforced by `serve` before this
    // decision is ever consulted, so there is nothing left to gate on here.
    assert_eq!(
        register_decision(None, "gw-zzz", "anything-at-all"),
        RegisterDecision::Accept,
        "a free slot must be accepted regardless of which identities are involved"
    );
}

// ---------------------------------------------------------------------------
// The 2x2 over an occupied slot
// ---------------------------------------------------------------------------

#[test]
fn same_owner_same_peer_is_an_honest_reconnect_and_replaces() {
    // The deliberate fallthrough that must SURVIVE the collision fix: a
    // gateway whose previous connection went stale/half-open must be able to
    // take its own slot back, or it is stranded until QUIC's idle timeout.
    assert_eq!(
        register_decision(INCUMBENT, "gw-A", "gw-B"),
        RegisterDecision::ReplaceOwnSlot,
        "same owner re-registering the SAME pair is a reconnect and must replace its own slot"
    );
}

#[test]
fn same_owner_different_peer_is_a_key_collision_and_is_rejected() {
    // The branch that used to fall through to a silent `reg.insert`: the old
    // check compared only `existing.owner`, so two of ONE gateway's pairs
    // hashing onto one slot replaced each other with no log and no error.
    // Because the receiving gateway discards the forwarded src header
    // (`relay.rs`: `let (_src, data)`), the first pair's datagrams then landed
    // on the second pair's local socket and boringtun roamed the endpoint onto
    // the wrong leg. It must fail CLOSED.
    assert_eq!(
        register_decision(INCUMBENT, "gw-A", "gw-D"),
        RegisterDecision::RejectKeyCollision,
        "same owner, DIFFERENT peer is two of one gateway's pairs colliding on one slot — it \
         must be rejected, never silently replaced"
    );
}

#[test]
fn different_owner_different_peer_is_rejected_as_owned_by_other() {
    // The classic impersonation/eviction attempt `tests/impersonation.rs`
    // pins end-to-end (close code 3).
    assert_eq!(
        register_decision(INCUMBENT, "gw-C", "gw-D"),
        RegisterDecision::RejectOwnedByOther,
        "a slot held by a different cert identity must never be taken over"
    );
}

#[test]
fn different_owner_is_rejected_whatever_the_attacker_chosen_peer_half_says() {
    // *** THE ORDERING ARM ***
    //
    // The head case: a DIFFERENT owner typing the incumbent's OWN peer
    // identity. This is the single input that distinguishes "owner checked
    // first" from "peer checked first". Under a peer-first implementation it
    // returns ReplaceOwnSlot and the attacker owns gw-A's slot.
    assert_eq!(
        register_decision(INCUMBENT, "gw-C", "gw-B"),
        RegisterDecision::RejectOwnedByOther,
        "SLOT HIJACK: a DIFFERENT owner asserting the incumbent's own peer identity must be \
         rejected. Returning ReplaceOwnSlot here means the ownership check runs AFTER the peer \
         check, so the attacker-chosen (never cert-bound) peer half upgrades a rejection into a \
         replace — gw-A is locked out of its own relay path and gw-B's datagrams are delivered \
         to the attacker."
    );

    // And unconditionally: no peer string of any shape may change the verdict
    // once the owner differs. The peer half is free-form UTF-8 chosen by the
    // registering connection (`decode_registration` only rejects empty), so
    // this sweep covers the values an attacker would actually reach for.
    let long_peer = "gw-".repeat(300);
    let attacker_peer_choices: [&str; 14] = [
        "gw-B",         // the incumbent's own peer — the hijack input
        "gw-A",         // the incumbent's OWNER, typed as a peer
        "gw-C",         // the attacker's own identity
        "gw-D",         // an unrelated third party
        "gw-b",         // case-flipped near-miss of the incumbent peer
        "gw-B ",        // trailing whitespace
        " gw-B",        // leading whitespace
        "gw-B\0",       // NUL-suffixed
        "gw-B/../gw-A", // path-ish
        "gw-BB",        // superstring of the incumbent peer
        "gw-",          // prefix only
        "x",            // minimal
        "gw-Ω",         // non-ASCII
        long_peer.as_str(),
    ];
    for peer in attacker_peer_choices {
        assert_eq!(
            register_decision(INCUMBENT, "gw-C", peer),
            RegisterDecision::RejectOwnedByOther,
            "owner mismatch must reject unconditionally, but peer_identity {peer:?} produced a \
             different verdict — the attacker-chosen peer half must never influence the \
             ownership decision"
        );
    }
}

#[test]
fn ownership_comparison_is_exact_string_equality() {
    // Production identities are sequential `gw-<rowid>`, so near-miss
    // identities are not hypothetical: `gw-1` is a strict prefix of `gw-12`,
    // and both exist on any fabric with twelve or more gateways. A prefix,
    // substring, or case-insensitive owner comparison would hand `gw-1`'s slot
    // to `gw-12`.
    let slot = Some(("gw-1", "gw-2"));
    for impostor in ["gw-12", "gw-", "w-1", "GW-1", "gw-1 ", " gw-1", "gw-10"] {
        assert_eq!(
            register_decision(slot, impostor, "gw-2"),
            RegisterDecision::RejectOwnedByOther,
            "owner {impostor:?} is not the incumbent owner \"gw-1\" and must be rejected — the \
             comparison must be exact string equality, not prefix/substring/case-insensitive"
        );
    }
    // The genuine owner, for contrast: the same inputs with the exact identity
    // are a reconnect. Without this the test above could pass by rejecting
    // everything.
    assert_eq!(
        register_decision(slot, "gw-1", "gw-2"),
        RegisterDecision::ReplaceOwnSlot,
        "the EXACT incumbent owner re-registering the same pair must still replace"
    );
}

#[test]
fn peer_comparison_is_exact_string_equality() {
    // Same argument on the other half: for a same-owner registration, a peer
    // that merely resembles the incumbent's must be treated as a collision
    // (reject), not as a reconnect (replace). A loose comparison here would
    // reopen the silent cross-wire.
    let slot = Some(("gw-1", "gw-2"));
    for near_miss in ["gw-20", "gw-2 ", " gw-2", "GW-2", "gw-", "w-2"] {
        assert_eq!(
            register_decision(slot, "gw-1", near_miss),
            RegisterDecision::RejectKeyCollision,
            "peer {near_miss:?} is not the incumbent peer \"gw-2\", so this is a different pair \
             colliding on the slot and must be rejected — the comparison must be exact string \
             equality"
        );
    }
}

// ---------------------------------------------------------------------------
// Table-driven: the complete 2x2 in one place, so a future arm reorder cannot
// slip past hand-picked examples.
// ---------------------------------------------------------------------------

#[test]
fn the_full_truth_table_holds() {
    // (owner matches?, peer matches?) -> decision, over an occupied slot.
    let cases: [(&str, &str, RegisterDecision, &str); 4] = [
        ("gw-A", "gw-B", RegisterDecision::ReplaceOwnSlot, "same owner, same peer"),
        ("gw-A", "gw-D", RegisterDecision::RejectKeyCollision, "same owner, different peer"),
        ("gw-C", "gw-B", RegisterDecision::RejectOwnedByOther, "different owner, SAME peer"),
        ("gw-C", "gw-D", RegisterDecision::RejectOwnedByOther, "different owner, different peer"),
    ];
    for (cert_identity, peer_identity, expected, label) in cases {
        assert_eq!(
            register_decision(INCUMBENT, cert_identity, peer_identity),
            expected,
            "truth-table row [{label}] — existing=(\"gw-A\",\"gw-B\"), \
             cert_identity={cert_identity:?}, peer_identity={peer_identity:?}"
        );
    }

    // Both owner-mismatch rows must land on the SAME verdict: the peer half is
    // irrelevant once the owner differs. Stated as its own assertion so the
    // failure message names the property rather than a row.
    assert_eq!(
        register_decision(INCUMBENT, "gw-C", "gw-B"),
        register_decision(INCUMBENT, "gw-C", "gw-D"),
        "the two owner-mismatch rows must be indistinguishable — if they differ, the peer half \
         is influencing an ownership decision it must not reach"
    );

    // The two same-owner rows must NOT collapse: replace vs reject is exactly
    // the reconnect-vs-collision distinction `RegEntry.peer` was added for.
    assert_ne!(
        register_decision(INCUMBENT, "gw-A", "gw-B"),
        register_decision(INCUMBENT, "gw-A", "gw-D"),
        "a same-owner reconnect and a same-owner key collision must be different outcomes — \
         collapsing them either strands reconnecting gateways or restores the silent cross-wire"
    );
}

#[test]
fn the_two_rejections_are_distinct_outcomes() {
    // `serve` maps them to DIFFERENT QUIC application close codes — 3 for
    // owned-by-other (preserved, `tests/impersonation.rs` depends on the
    // behaviour behind it) and 4 for a key collision — and logs them
    // differently, because they mean different things operationally: one is an
    // attack or a misconfiguration, the other is a hash collision on this
    // relay process that the gateway can retry elsewhere. Collapsing them into
    // a single `Reject` would silently change the close code for one of the
    // two paths.
    assert_ne!(
        RegisterDecision::RejectOwnedByOther,
        RegisterDecision::RejectKeyCollision,
        "the two rejection reasons must remain distinct variants — serve maps them to \
         different close codes (3 vs 4)"
    );
    assert_ne!(
        register_decision(INCUMBENT, "gw-C", "gw-D"),
        register_decision(INCUMBENT, "gw-A", "gw-D"),
        "an owned-by-other rejection and a key-collision rejection must be reported as \
         different decisions, not folded into one"
    );

    // Neither rejection may be confusable with either accept variant.
    for reject in [
        register_decision(INCUMBENT, "gw-C", "gw-D"),
        register_decision(INCUMBENT, "gw-A", "gw-D"),
    ] {
        assert_ne!(reject, RegisterDecision::Accept);
        assert_ne!(reject, RegisterDecision::ReplaceOwnSlot);
    }
}

#[test]
fn register_decision_is_pure() {
    // The relay calls this under the registry lock and acts on the result; it
    // must be a total function of its three inputs with no hidden state.
    for _ in 0..4 {
        assert_eq!(register_decision(None, "gw-A", "gw-B"), RegisterDecision::Accept);
        assert_eq!(
            register_decision(INCUMBENT, "gw-A", "gw-B"),
            RegisterDecision::ReplaceOwnSlot
        );
        assert_eq!(
            register_decision(INCUMBENT, "gw-A", "gw-D"),
            RegisterDecision::RejectKeyCollision
        );
        assert_eq!(
            register_decision(INCUMBENT, "gw-C", "gw-B"),
            RegisterDecision::RejectOwnedByOther
        );
    }
}
