//! FAILING tests (test-author, final operator round) — ROSTER-FAILURE DEFERRAL.
//! **compile-RED** until the inline decision is extracted.
//!
//! # The behavior being pinned (gateway.rs, d495d66)
//!
//! A failed `list_gateways` must NOT be read as "not enrolled → ordinary mint".
//! With the roster unreadable, `gateway_active` is false → `identity_persisted`
//! is false → `should_mint_token` is true, so the ordinary-mint arm is
//! REACHABLE. If a rebind is pending, taking it is doubly wrong:
//!   * it mints a PLAIN token, which a still-occupied segment rejects with
//!     `SegmentAlreadyBound`; and
//!   * it rewrites the Secret's bound-CIDR record via `token_secret_body`, so
//!     `needs_rebind` reads false from then on and the required rebind is
//!     PERMANENTLY LOST — nothing re-derives it. The gateway then sits on an
//!     unusable plain token and wedges at the next re-enroll.
//! Deferring costs nothing: the not-enrolled requeue is 15s and the pending
//! rebind stays derivable from the untouched Secret.
//!
//! # Pinned implementer surface (the decision is an inline if/else-if chain
//! at gateway.rs:445-529 — extract it so it is assertable and has ONE definition)
//!
//! ```ignore
//! // in controllers::gateway
//! #[derive(Debug, Clone, Copy, PartialEq, Eq)]
//! pub enum MintAction {
//!     /// Roster unreadable while a rebind is pending: mint NOTHING and do not
//!     /// touch the token Secret (the pending rebind must stay derivable).
//!     Defer,
//!     /// Mint an ordinary gateway token bound to the segment CIDRs and
//!     /// (re)write the Secret's bound-CIDR record.
//!     MintOrdinary,
//!     /// Mint a `kind = "rebind"` token scoped to the segment id and refresh
//!     /// the Secret.
//!     MintRebind,
//!     /// Steady state: nothing to do.
//!     None,
//! }
//!
//! /// The whole mint decision, pure. `identity_persisted` is
//! /// `pvc_exists && gateway_active`; `gateway_active` is passed separately
//! /// because the rebind arm keys off it directly (and because a roster
//! /// failure forces it false while `pvc_exists` may be true).
//! pub fn mint_action(
//!     roster_ok: bool,
//!     gateway_active: bool,
//!     identity_persisted: bool,
//!     rebind_pending: bool,
//!     token_secret: Option<&Secret>,
//! ) -> MintAction;
//! ```
//!
//! Required semantics — the CURRENT chain, order-preserving:
//! ```ignore
//! if rebind_pending && !roster_ok            { Defer }
//! else if should_mint_token(identity_persisted, token_secret) { MintOrdinary }
//! else if gateway_active && rebind_pending   { MintRebind }
//! else                                       { None }
//! ```
//! `apply_gateway` then matches on it, so the guard cannot be bypassed by a
//! future edit reordering the arms. The I/O around it (the actual mint calls,
//! the Secret apply, `segment_id_by_name`'s not-yet-registered deferral) stays
//! in the reconciler and is NOT unit-testable without a kube/controller mock —
//! that part remains review-verified.

use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::ByteString;
use std::collections::BTreeMap;
use wiremesh_operator::controllers::gateway::{mint_action, MintAction};

/// A Secret carrying a (possibly spent) token — the steady-state shape.
fn populated() -> Secret {
    let mut data = BTreeMap::new();
    data.insert("token".to_string(), ByteString(b"wiremesh://tok".to_vec()));
    Secret {
        data: Some(data),
        ..Default::default()
    }
}

#[test]
fn roster_unreadable_with_pending_rebind_defers() {
    // THE FIX. Roster unreadable (`roster_ok == false`) forces gateway_active
    // false → identity_persisted false → the ordinary-mint arm would otherwise
    // fire and destroy the pending rebind. Must Defer instead.
    assert_eq!(
        mint_action(false, false, false, true, Some(&populated())),
        MintAction::Defer,
        "roster unreadable + rebind pending → DEFER: minting a plain token here is rejected \
         by the occupied segment AND overwrites the Secret's bound-CIDR record, losing the \
         rebind permanently"
    );

    // Defer regardless of the Secret's state — an absent/empty token Secret is
    // still not a reason to mint an ordinary token while a rebind is pending and
    // unverifiable.
    assert_eq!(
        mint_action(false, false, false, true, None),
        MintAction::Defer,
        "roster unreadable + rebind pending + no token Secret → still DEFER (never mint blind)"
    );
    assert_eq!(
        mint_action(false, false, false, true, Some(&Secret::default())),
        MintAction::Defer,
        "roster unreadable + rebind pending + Secret without a token key → still DEFER"
    );
}

#[test]
fn roster_readable_with_pending_rebind_mints_rebind() {
    // The roster confirms this gateway is the segment's active one, so the
    // rebind is both safe and necessary: identity persisted (PVC + active) means
    // should_mint_token is false, and the rebind arm fires.
    assert_eq!(
        mint_action(true, true, true, true, Some(&populated())),
        MintAction::MintRebind,
        "roster readable + gateway active + rebind pending → mint a REBIND token"
    );
}

#[test]
fn roster_unreadable_without_pending_rebind_mints_ordinary_spare() {
    // STATED CURRENT SAFE BEHAVIOR (unchanged by the fix, deliberately): with no
    // rebind pending there is no rebind record to destroy, so the reconciler
    // keeps its conservative posture — treat the gateway as not-active and mint
    // an ordinary SPARE token. That token simply lapses unused when the
    // persisted identity makes the idempotent enroll init skip, and it avoids
    // wedging a genuine first enroll on a transient controller hiccup. The
    // Secret's bound-CIDR record is rewritten with the SAME CIDRs (needs_rebind
    // was false), so nothing is lost.
    assert_eq!(
        mint_action(false, false, false, false, Some(&populated())),
        MintAction::MintOrdinary,
        "roster unreadable + NO rebind pending → mint an ordinary spare token (conservative; \
         nothing to lose, and a transient roster failure must not wedge a first enroll)"
    );
    assert_eq!(
        mint_action(false, false, false, false, None),
        MintAction::MintOrdinary,
        "roster unreadable + no rebind pending + no token Secret → mint"
    );
}

#[test]
fn steady_state_does_nothing() {
    // Identity persisted, token present, no rebind pending → no mint at all
    // (single-use tokens must not be re-minted on every reconcile).
    assert_eq!(
        mint_action(true, true, true, false, Some(&populated())),
        MintAction::None,
        "steady state → no mint"
    );
}

#[test]
fn first_enroll_mints_ordinary() {
    // Fresh PVC, nothing enrolled yet, roster readable and empty → ordinary
    // mint (the normal first-deploy path; must not be mistaken for a rebind).
    assert_eq!(
        mint_action(true, false, false, false, None),
        MintAction::MintOrdinary,
        "first-ever deploy → ordinary mint"
    );
}

#[test]
fn unpersisted_identity_takes_ordinary_mint_before_the_rebind_arm() {
    // ARM-ORDER PIN: a readable roster showing the gateway active but a MISSING
    // PVC (identity not persisted — e.g. the PVC was replaced) must take the
    // ordinary-mint arm, NOT the rebind arm, even with a rebind pending. The
    // pod has no identity to keep, so it needs an unspent ordinary token; the
    // rebind arm is for an enrolled gateway whose CIDRs moved underneath it.
    // (This is the current chain's behavior — pinning it stops a "fix" that
    // reorders the arms.)
    assert_eq!(
        mint_action(true, true, false, true, Some(&populated())),
        MintAction::MintOrdinary,
        "roster readable + active but identity NOT persisted → ordinary mint wins over rebind"
    );
}

#[test]
fn defer_takes_precedence_over_every_other_arm() {
    // The guard is FIRST in the chain: no combination of the other inputs may
    // produce a mint while the roster is unreadable and a rebind is pending.
    for gateway_active in [false, true] {
        for identity_persisted in [false, true] {
            for secret in [None, Some(populated())] {
                assert_eq!(
                    mint_action(
                        false,
                        gateway_active,
                        identity_persisted,
                        true,
                        secret.as_ref()
                    ),
                    MintAction::Defer,
                    "roster unreadable + rebind pending must DEFER for every other input \
                     combination (gateway_active={gateway_active}, \
                     identity_persisted={identity_persisted}, secret={})",
                    secret.is_some()
                );
            }
        }
    }
}
