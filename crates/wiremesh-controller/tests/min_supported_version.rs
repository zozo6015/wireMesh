//! (B10 / X-6) `min_supported_version` is DERIVED from the controller's own
//! version, never a literal.
//!
//! # Why derived
//!
//! A literal is a second thing to bump at release time, and the one that gets
//! forgotten — it would sit at whatever value was right when it was last
//! touched, silently widening or narrowing the supported window with every
//! release that did not remember it. Deriving it makes the release process the
//! only input.
//!
//! # The rule, stated as it is coded
//!
//! The previous minor **iff `major >= 1 && minor > 0`**, otherwise the
//! controller's own minor. Read plainly: *the previous minor within the same
//! major, when there is one and the contract has started.*
//!
//! The `major >= 1 && minor > 0` guard is the part worth understanding,
//! because "the previous minor" alone underdetermines exactly the boundary
//! this exists to protect. At `1.0.x` the previous minor would be some `0.y` —
//! and *which* `0.y` is not derivable, because pre-1.0 minors carry no
//! compatibility promise and there is no last-0.x recorded anywhere. So `1.0.x`
//! floors at itself, and the window only starts widening at `1.1.x`.
//!
//! # The window's WIDTH is a ruled commitment, not an implementation detail
//!
//! Rev 1.43c-commitment, confirmed against the PRD: X-6 reads *"Controller vN
//! supports gateways/relays vN and vN−1 (one-minor skew window)"* — two
//! versions enumerated and the width named. So both properties this file pins
//! are decisions rather than accidents of the derivation:
//!
//!   * **non-cumulative** — a 1.2 controller supports 1.2 and 1.1, and **1.0
//!     is out of support**. It does NOT support everything since 1.0;
//!   * **patch-invariant** — the window is stated in minors, so no patch level
//!     moves it.
//!
//! The operator consequence, recorded because it is the cost of the rule and
//! someone will meet it before they read the PRD: **an operator running 1.0
//! gateways cannot move the controller past 1.1 without upgrading the gateways
//! first.** The emergency `--min-supported-version` lower-only override exists
//! to relieve exactly that, and is the pressure valve to reach for rather than
//! widening the derivation here.
//!
//! # This test is the ONLY guard on the function's purity
//!
//! `min_supported_version` must be a pure function of the string it is passed.
//! If it ever read `env!("CARGO_PKG_VERSION")` itself, the
//! stamped-reader guard in `wiremesh-operator/tests/release_version_stamping.rs`
//! would **not** catch it: that guard reds only for crates the release script
//! does not stamp, and `wiremesh-controller` IS stamped. Nothing else would
//! notice. Every case below therefore passes a version IN — never asserts
//! against the crate's own — which is what makes the function's purity
//! observable at all.

use wiremesh_controller::version::min_supported_version;

/// The four ruled rows. These are the contract; the totality cases below are
/// choices, and the distinction matters if one ever has to change.
#[test]
fn the_supported_window_opens_one_minor_back_once_the_contract_has_started() {
    assert_eq!(
        min_supported_version("0.10.4"),
        "0.10.0",
        "pre-1.0 the floor is the controller's OWN minor. There is no compatibility promise \
         across pre-1.0 minors, so widening the window backwards would claim support the \
         project has never made"
    );
    assert_eq!(
        min_supported_version("1.0.3"),
        "1.0.0",
        "at 1.0.x the floor is 1.0.0, NOT some 0.y. The previous minor here would be a \
         pre-1.0 release, and which one is not derivable — pre-1.0 minors carry no promise \
         and no `last 0.x` is recorded anywhere. This is the boundary the \
         `major >= 1 && minor > 0` guard exists for"
    );
    assert_eq!(
        min_supported_version("1.1.0"),
        "1.0.0",
        "1.1.x is the first release with a previous minor inside the contract, so the window \
         opens one minor back"
    );
    assert_eq!(
        min_supported_version("1.2.7"),
        "1.1.0",
        "the window is ONE minor wide, not cumulative — 1.2.x supports back to 1.1.0, not to \
         1.0.0. A wider window is a support commitment, not a derivation detail"
    );
}

/// The patch component never affects the answer.
///
/// Separate from the rows above because it is a different property: those pin
/// *which* minor, this pins that patches are irrelevant to the floor. A
/// derivation that accidentally carried the patch through would still satisfy
/// every row above if each were tested at only one patch level.
#[test]
fn the_patch_component_does_not_move_the_floor() {
    for v in ["1.2.0", "1.2.1", "1.2.99"] {
        assert_eq!(
            min_supported_version(v),
            "1.1.0",
            "{v} must floor at 1.1.0 — the supported window is expressed in minors, so the \
             patch level of the running controller cannot move it"
        );
    }
}

// -------------------------------------------------------------------------
// TOTALITY CHOICES — pinned AS THEY EXIST, so that changing one is deliberate.
//
// The function is total: it returns a String for every input, including ones
// with no sensible answer. These cases record what it currently does. They are
// NOT the contract in the way the four rows above are — if a ruling changes
// one, change it here and say so in the commit.
// -------------------------------------------------------------------------

/// A major bump has no derivable floor, and currently floors at itself.
///
/// The previous major's last minor is not derivable — nothing records how far
/// 1.x got before 2.0 shipped. Flooring at `2.0.0` is the conservative answer:
/// it claims support for nothing that has not shipped under this major.
///
/// **This is flagged to the architect for a ruling BEFORE any 2.0 tag.** The
/// alternative — carrying the last 1.x minor forward — would require recording
/// it somewhere, which is a release-process change, not a code change. Do not
/// change this quietly.
#[test]
fn a_major_bump_floors_at_itself_pending_a_ruling() {
    assert_eq!(
        min_supported_version("2.0.0"),
        "2.0.0",
        "2.0.x currently floors at itself, because the previous major's last minor is not \
         derivable from the version string alone. This is a documented totality choice, not \
         a ruled contract — it is flagged for the architect before any 2.0 tag, and changing \
         it means recording the last 1.x minor somewhere at release time"
    );
}

/// An unparseable version returns itself unchanged.
///
/// **Parseable means EXACTLY THREE NUMERIC COMPONENTS** after pre-release and
/// build metadata are stripped. Not "at least three", and not "the first two
/// parse": `"1.2"`, `"1.2.x"` and `"1.2.3.4"` are all unparseable, and each
/// must come back unchanged rather than have a floor derived from whatever
/// prefix happened to be numeric.
///
/// That strictness is the point rather than pedantry. A derivation that reads
/// the first two components and ignores the rest cannot tell `"1.2"` — which
/// is not a version this project ever produces — from `"1.2.3"`, so it answers
/// confidently for an input it did not understand. The whole value of this
/// field is telling an operator what a controller IS; a confident wrong answer
/// there is worse than the honest echo, which is visibly odd and prompts a
/// look.
///
/// The patch component is VALIDATED for shape here but still never used in the
/// derivation — patch-invariance is unaffected, and
/// [`the_patch_component_does_not_move_the_floor`] pins it separately.
///
/// The controller's version comes from `CARGO_PKG_VERSION`, so in practice it
/// always parses. Returning the input rather than panicking or emptying is the
/// fail-soft choice: `min_supported_version` is advisory in Phase B (stored,
/// never consulted), and taking the controller down over a malformed version
/// string would be a far worse failure than reporting an odd one.
#[test]
fn an_unparseable_version_is_returned_unchanged() {
    for v in [
        "not-a-version",
        "",
        "1",
        "1.x.0",
        // Too few components: two numbers are not a version, and deriving
        // `"1.1.0"` from `"1.2"` is the confident wrong answer above.
        "1.2",
        // Three components, but the third is not numeric — the shape must be
        // validated even though the value is never used.
        "1.2.x",
        // Too many components.
        "1.2.3.4",
    ] {
        assert_eq!(
            min_supported_version(v),
            v,
            "{v:?} does not parse as MAJOR.MINOR.PATCH and must be returned unchanged. \
             Panicking would take the controller down over an advisory field; returning \
             empty would be indistinguishable from a pre-B10 controller, which is the one \
             thing this field exists to make visible"
        );
    }
}

/// `0.0.x` floors at `0.0.0` — the pre-1.0 rule with nothing below it.
#[test]
fn a_zero_minor_floors_at_itself() {
    assert_eq!(
        min_supported_version("0.0.9"),
        "0.0.0",
        "0.0.x is pre-1.0 (own minor) AND has no previous minor, so both halves of the rule \
         agree on 0.0.0. Pinned because it is the one input where the two clauses could \
         disagree if the guard were ever rewritten"
    );
}

/// Pre-release and build metadata are stripped before parsing.
///
/// A release candidate is a candidate for its own version: `1.1.0-rc.1` must
/// derive the same floor `1.1.0` does, or the window would shift under an rc
/// and shift back at the tag — the sort of difference that only shows up in
/// production.
#[test]
fn pre_release_and_build_metadata_are_stripped_before_parsing() {
    assert_eq!(
        min_supported_version("1.1.0-rc.1"),
        "1.0.0",
        "a release candidate must derive the same floor as the release it is a candidate \
         for. Treating `-rc.1` as part of the version would make the supported window differ \
         between the rc and the tag"
    );
    assert_eq!(
        min_supported_version("1.2.0+build.5"),
        "1.1.0",
        "build metadata carries no version semantics and must not reach the parser"
    );
}
