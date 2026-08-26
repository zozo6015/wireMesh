//! (B10 / X-6) The version window this controller advertises.
//!
//! Lives at the crate root rather than in [`crate::projection`] because
//! projection is a CONSUMER of this policy, not its home: both snapshot
//! builders call it today, and Phase C's Watch-open gate will call the same
//! function. The dependency points from projection to policy, never back.

/// The oldest client build this controller advertises support for, derived
/// from its own stamped version.
///
/// **Rule (X-6's one-minor window, plus "the skew contract starts at 1.0"):**
/// the previous minor if that is `>= 1.0.0`, otherwise this build's own minor.
///
/// | controller | advertises | why |
/// |---|---|---|
/// | `0.10.x` | `0.10.0` | previous minor (`0.9.0`) predates the contract |
/// | `1.0.x`  | `1.0.0`  | there is no in-contract minor before it |
/// | `1.1.x`  | `1.0.0`  | previous minor, in contract |
/// | `1.2.x`  | `1.1.0`  | previous minor, in contract |
///
/// **DERIVED, never written down.** The literal this replaced was `"0.10.0"`,
/// chosen as "one minor back from v0.11.0" — a version that did not exist
/// yet. That is the tell: a hand-written floor is correct only for the
/// release someone imagined while writing it, and wrong from the next one on.
/// The derivation is correct in every configuration, including the ones
/// nobody pictured.
///
/// It would also go stale silently: nothing
/// recomputes it, no test covers it, and `scripts/set-version.sh` stamps crate
/// versions but would not touch it — so at the next minor the advertised floor
/// would still name the old one and the *stated* window would quietly widen
/// from two minors to three. Nobody would notice, because Phase B enforces
/// nothing; it would only surface once Phase C gates on a floor that was
/// already wrong.
///
/// **Pure, and takes the version as an argument** rather than reading
/// `env!("CARGO_PKG_VERSION")` internally: that keeps it unit-testable across
/// the whole ladder without a release, and follows the same discipline as
/// `rotation::decide` and `path.rs` — predicates take their inputs, they do
/// not reach for ambient state.
///
/// # Totality
///
/// `minor == 0` at major `>= 2` (e.g. `2.0.x`) cannot name its previous minor:
/// that would be `1.<last>.0`, and the last minor of a previous major is not
/// derivable from this string. It falls back to the own-minor branch (`2.0.0`).
/// **At a major boundary the one-minor window is deliberately SUSPENDED, not
/// satisfied** — so a reader who knows the vN/vN−1 contract does not read this
/// as a bug. It fails CLOSED: a narrow floor rejects peers that might have
/// worked, never admits peers that do not. **Needs a ruling before any 2.0
/// release.**
///
/// An unparseable version advertises itself unchanged. Reaching this branch
/// implies the stamping was bypassed — `scripts/set-version.sh` validates the
/// shape before writing it — so it signals a BUILD-PROCESS failure, not a
/// runtime one. Degrading to the narrowest claim beats a panic or an empty
/// field, consistent with the rule that a value nothing reads must never be
/// able to fail a connection.
pub fn min_supported_version(controller_version: &str) -> String {
    let core = controller_version
        .split(['-', '+'])
        .next()
        .unwrap_or(controller_version);
    let mut parts = core.split('.');
    let (Some(major), Some(minor)) = (parts.next(), parts.next()) else {
        return controller_version.to_string();
    };
    let (Ok(major), Ok(minor)) = (major.parse::<u64>(), minor.parse::<u64>()) else {
        return controller_version.to_string();
    };

    // The previous minor is in-contract only when this build is already >= 1.x
    // AND has a previous minor within its own major.
    if major >= 1 && minor > 0 {
        return format!("{major}.{}.0", minor - 1);
    }
    format!("{major}.{minor}.0")
}
