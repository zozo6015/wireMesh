//! (CodeRabbit 🟡 Minor, PR #59) Pins the cross-crate relation this branch's
//! two candidate caps are supposed to hold:
//!
//! `Db::candidates_for` (`crate::db`) yields at most 1 controller-observed
//! endpoint + [`MAX_LOCAL_CANDIDATES`] locally-reported ones = 33 entries for
//! an HONEST control plane. `wiremesh-gateway/src/state.rs`'s
//! `MAX_PEER_CANDIDATES` (currently 64) must stay STRICTLY ABOVE that sum —
//! deliberate MARGIN, not a claim that 33 itself is unsafe: the gateway's
//! `partition_dialable` only starts dropping once its kept count REACHES the
//! cap, so a cap of exactly 33 would still keep a 33-entry honest
//! advertisement whole. The margin exists so the cap is never left sitting
//! exactly on the ceiling, one `MAX_LOCAL_CANDIDATES` bump away from
//! actually truncating a correctly-behaving controller's advertisement — the
//! one outcome a defensive cap must never produce (see that constant's own
//! doc comment, which states this exact relation in prose).
//!
//! # Why this is NOT a live cross-crate assertion
//!
//! The obviously-best fix — importing both constants into one test and
//! asserting `MAX_LOCAL_CANDIDATES + 1 < MAX_PEER_CANDIDATES` directly — is
//! not buildable in this workspace, for two independent reasons, either one
//! of which alone would already rule it out:
//!
//! 1. **No dependency edge.** `wiremesh-gateway` does not depend on
//!    `wiremesh-controller` (checked its `Cargo.toml`: only
//!    `wiremesh-proto`/`-policy`/`-enforcer`/`-trust`/`-relay`/`-enroll` plus
//!    `wiremesh-testkit` as a dev-dependency). `wiremesh-testkit` in turn
//!    DOES depend on `wiremesh-controller` (a real, normal dependency — see
//!    its `Cargo.toml` and the root workspace `Cargo.toml`'s `rustls`
//!    feature-unification comment, which explicitly names this exact chain:
//!    "any `wiremesh-gateway` test binary that pulls in `wiremesh-relay`
//!    ... AND `wiremesh-testkit`/`wiremesh-controller` ... as a
//!    dev-dependency"). So `wiremesh_controller` genuinely gets COMPILED
//!    into a `wiremesh-gateway` test binary's dependency graph today — but
//!    Cargo's per-crate extern prelude only makes a crate nameable
//!    (`use wiremesh_controller::...`) to packages that list it directly in
//!    their OWN `Cargo.toml`; a dependency-of-a-dev-dependency is linked but
//!    not nameable. `wiremesh-testkit` doesn't re-export it either (checked
//!    `crates/wiremesh-testkit/src/lib.rs`: only `pub mod netns;` and
//!    `pub mod conformance;`, no `pub use wiremesh_controller`). Confirmed
//!    empirically too: no file under `crates/wiremesh-gateway/tests/`
//!    references `wiremesh_controller::` anywhere today. Adding
//!    `wiremesh-controller` as a direct (even dev-only) dependency of
//!    `wiremesh-gateway` would fix this, but that is exactly the dependency
//!    edge the gateway deliberately does not have and this task was told not
//!    to introduce for a test's sake.
//!
//! 2. **Even with that edge, the constant is unreachable.** Independent of
//!    (1): `MAX_PEER_CANDIDATES` is declared `pub(crate)` in
//!    `crates/wiremesh-gateway/src/state.rs`. `pub(crate)` is invisible even
//!    to that SAME crate's own `tests/*.rs` integration binaries (those link
//!    against `wiremesh_gateway` as an external library and see only its
//!    `pub` surface) — it is visible only inside `wiremesh-gateway/src/`'s
//!    own `#[cfg(test)] mod tests` (where it already has a same-crate pin,
//!    `a_candidate_list_exactly_at_the_cap_is_kept_whole_and_silent`, though
//!    that one exercises `partition_dialable`'s behavior rather than
//!    asserting the cross-crate number). So no crate in this workspace — not
//!    even a hypothetical one depending on both — could see both constants
//!    without ALSO widening `MAX_PEER_CANDIDATES`'s visibility, a second
//!    production change beyond the forbidden dependency edge.
//!
//! # What this file does instead
//!
//! Pins [`MAX_LOCAL_CANDIDATES`] at its current value, and separately checks
//! the arithmetic relation against a manually-mirrored copy of the gateway's
//! constant (see [`GATEWAY_MAX_PEER_CANDIDATES_MIRROR`]'s doc comment for
//! exactly what that does and does not catch). Whoever raises
//! `MAX_LOCAL_CANDIDATES` gets a loud, named failure pointing at the exact
//! other file and constant to check, rather than the relation silently
//! drifting the way CodeRabbit flagged it as doing today.
use wiremesh_controller::services::sync::MAX_LOCAL_CANDIDATES;

/// A manually-kept-in-sync COPY of `MAX_PEER_CANDIDATES` from
/// `crates/wiremesh-gateway/src/state.rs` (as of this writing: 64). Not a
/// live reference — see this file's module doc comment (`# Why this is NOT
/// a live cross-crate assertion`) for why no import is possible.
///
/// **What this catches:** `MAX_LOCAL_CANDIDATES` (this crate) being raised
/// without a corresponding look at the gateway's cap —
/// [`the_cap_relation_holds_against_the_mirrored_gateway_value`] below will
/// fail the moment `1 + MAX_LOCAL_CANDIDATES` reaches this mirror.
///
/// **What this does NOT catch:** `MAX_PEER_CANDIDATES` being LOWERED on the
/// gateway side without anyone updating this mirror to match — this constant
/// would silently go stale and both tests below would stay green while the
/// real relation had already broken. That direction is closed by the
/// mirror-image test on the OTHER side instead:
/// `crates/wiremesh-gateway/src/state.rs`'s
/// `max_peer_candidates_stays_above_the_honest_controller_ceiling` (in that
/// file's `#[cfg(test)] mod tests`, the only place that can see the
/// `pub(crate)` `MAX_PEER_CANDIDATES`), which carries its own manually-synced
/// mirror of [`MAX_LOCAL_CANDIDATES`] and catches exactly this gap. The two
/// files are a deliberate pair — whichever one an editor opens, its doc
/// comments point at the other. That covers any SINGLE unmirrored edit on
/// either side; it does not cover two compounding ones (an unmirrored raise
/// here AND a separate unmirrored lower there, made at different times) —
/// each side's own pin would independently still read green against its own
/// stale mirror while the real cross-crate relation had already broken.
const GATEWAY_MAX_PEER_CANDIDATES_MIRROR: usize = 64;

/// Tripwire: `MAX_LOCAL_CANDIDATES` must not move without a conscious check
/// of the gateway's cap. Currently green (32 is today's actual value) — its
/// job is to turn red the instant someone edits the constant, which is
/// exactly the "silent drift" CodeRabbit flagged: today NOTHING in the repo
/// fails when `MAX_LOCAL_CANDIDATES` changes, cross-crate relation or not.
///
/// The production change that flips this red: editing
/// `crates/wiremesh-controller/src/services/sync.rs`'s
/// `pub const MAX_LOCAL_CANDIDATES: usize = 32;` to any other value.
#[test]
fn max_local_candidates_is_pinned_pending_a_conscious_gateway_cap_check() {
    assert_eq!(
        MAX_LOCAL_CANDIDATES, 32,
        "MAX_LOCAL_CANDIDATES changed from 32 to {MAX_LOCAL_CANDIDATES} — before updating \
         this pin, check whether `wiremesh-gateway/src/state.rs`'s `MAX_PEER_CANDIDATES` \
         (currently mirrored here as {GATEWAY_MAX_PEER_CANDIDATES_MIRROR}) still leaves \
         headroom above `1 + MAX_LOCAL_CANDIDATES`. `Db::candidates_for` yields at most \
         1 observed + MAX_LOCAL_CANDIDATES local entries, and the gateway silently \
         truncates any advertisement that EXCEEDS its own cap (equality is safe — the cap \
         only starts dropping once it's already been reached) — the two crates cannot see \
         each other's constant (see this file's module doc comment), so this pin is the \
         only thing standing between a raised cap here and a truncated one there."
    );
}

/// Checks the actual inequality the relation depends on, using the mirrored
/// gateway value: `Db::candidates_for`'s worst case (1 observed +
/// `MAX_LOCAL_CANDIDATES` local) must stay strictly below the gateway's
/// per-peer cap. Strictly-below is MARGIN, not the truncation threshold
/// itself — at exactly equal, the gateway's `partition_dialable` still keeps
/// the whole honest, fully-populated advertisement (it only drops once its
/// kept count reaches the cap); the margin instead keeps the cap from ever
/// sitting exactly on that ceiling.
///
/// Distinct from the pin above: that one catches ANY change to
/// `MAX_LOCAL_CANDIDATES`, whether or not it would actually violate the
/// relation (raising it from 32 to 33 is still safely under 64, but would
/// still fail the exact-value pin — deliberately, so a human re-checks). This
/// test instead does the arithmetic, so if the pin above is ever
/// deliberately updated (a human decided a new `MAX_LOCAL_CANDIDATES` value
/// is correct), THIS assertion is the one that still catches a value that
/// went too far.
#[test]
// The assertion IS constant on purpose: it pins the RELATION
// `1 + MAX_LOCAL_CANDIDATES < GATEWAY_MAX_PEER_CANDIDATES_MIRROR` at
// compile time so that moving either constant forces a human to re-check
// it. A constant value is the guarantee here, not a defect.
#[expect(
    clippy::assertions_on_constants,
    reason = "pins the relation `1 + MAX_LOCAL_CANDIDATES < GATEWAY_MAX_PEER_CANDIDATES_MIRROR` at compile time; constant IS the guarantee"
)]
fn the_cap_relation_holds_against_the_mirrored_gateway_value() {
    assert!(
        1 + MAX_LOCAL_CANDIDATES < GATEWAY_MAX_PEER_CANDIDATES_MIRROR,
        "1 (observed) + MAX_LOCAL_CANDIDATES ({MAX_LOCAL_CANDIDATES}) = {} must be strictly \
         less than the gateway's MAX_PEER_CANDIDATES (mirrored here as \
         {GATEWAY_MAX_PEER_CANDIDATES_MIRROR}). A value merely EQUAL would still fit — \
         `wiremesh-gateway`'s `partition_dialable` (crates/wiremesh-gateway/src/state.rs) \
         only starts dropping once its kept count reaches the cap, so it keeps an \
         honest, at-the-cap advertisement whole. Strictly-less is deliberate MARGIN, so \
         the cap is never left sitting exactly on the ceiling, one \
         MAX_LOCAL_CANDIDATES increase away from actually truncating a \
         correctly-behaving controller's own advertisement — the one outcome a defensive \
         cap must never produce. If this fails, raise MAX_PEER_CANDIDATES in \
         wiremesh-gateway/src/state.rs (and update the mirror above) before landing \
         whatever change raised MAX_LOCAL_CANDIDATES.",
        1 + MAX_LOCAL_CANDIDATES
    );
}
