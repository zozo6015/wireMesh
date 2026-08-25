//! Unit tests for `wiremesh_controller::parse_rotation_interval` and
//! `rotation_interval_from_env` — the pure, library-level parser behind the
//! operator-facing rotation-interval knob, and the environment resolution that
//! feeds it in `main.rs`.
//!
//! Why this knob exists (and why the DISABLED path is the one tested
//! hardest): when the rotation-initiation timer is armed, the controller
//! automatically rotates every active gateway's WireGuard key on it
//! (`services::sync::initiate_due_rotations`). Automatic rotation is currently
//! known-broken in ways that make a scheduled fabric-wide outage inevitable
//! (backlog item 9 — the rotation wedge: one failed rotation makes a gateway
//! silently ignore every further `RotateDirective` until it is restarted), so
//! an operator must be able to keep that timer OFF until the structural fix
//! lands. `off` is the explicit escape hatch, and the parser is its only gate
//! — an `off` that silently parses as "some interval" (or a `0s` that silently
//! parses as "off", or as a hot-looping zero interval) is the failure mode
//! this file exists to prevent.
//!
//! **Contract flip, owner-ratified 2026-08-12 — automatic rotation is now
//! OPT-IN.** An ABSENT `WIREMESH_ROTATION_INTERVAL` used to mean "rotate every
//! gateway every 30 days". That armed the wedge by default in every shipped
//! artifact — the `.deb`/`.rpm` (whose `deploy/packages/env/controller.env`
//! leaves the variable commented out), the ghcr container image, and any
//! source build; only the Kubernetes operator path escaped it, and only
//! because it emits `off` explicitly. Absent now resolves to `Ok(None)`, the
//! same no-timer state as `off`. Arming automatic rotation requires an
//! operator to write an interval down.
//!
//! Contract under test:
//!
//! ```ignore
//! pub fn parse_rotation_interval(s: &str) -> anyhow::Result<Option<std::time::Duration>>
//! ```
//!
//!   * `<integer><s|m|h|d>` → `Ok(Some(duration))`
//!   * `off` (case-insensitive) → `Ok(None)` = automatic rotation disabled
//!   * a ZERO duration (`0s`/`0m`/`0h`/`0d`) → `Err`, whose message points the
//!     operator at `off` (a zero interval would hot-loop rotations, so it can
//!     never be silently accepted, and it must not be silently reinterpreted
//!     as "disabled" either — the operator asked for something impossible and
//!     has to be told the word that does what they meant)
//!   * anything else (no suffix, unknown suffix, empty, negative, non-numeric,
//!     overflowing) → `Err`
//!   * surrounding whitespace is TRIMMED (env vars pick it up trivially);
//!     interior whitespace is NOT tolerated
//!   * an UPPERCASE unit suffix (`30D`, `15M`) is rejected — owner decision,
//!     because `M` reads as "months" to plenty of operators — and says so
//!     specifically, rather than hiding behind the generic "unknown suffix"
//!     message. That message is claimed ONLY when casing is the sole problem:
//!     `abcD` and a bare `D` are not miscased units, and telling their author
//!     to "write `d`" would hand them a second invalid value
//!   * an interval above the 3650d (10-year) cap is rejected. A timer that
//!     never fires is a SECOND, silent spelling of "disabled" — reachable
//!     without `off`, and therefore without the boot banner that is this
//!     binary's only runtime signal that rotation is off. Every route to "too
//!     large" — a saturating multiply, a count literal too big for `u64`, or a
//!     value simply over the cap — answers identically, since which one a value
//!     takes depends only on the unit the operator happened to choose
//!
//! And, for the environment resolution `main.rs` delegates to:
//!
//! ```ignore
//! pub const ROTATION_INTERVAL_ENV: &str = "WIREMESH_ROTATION_INTERVAL";
//! pub fn rotation_interval_from_env(
//!     lookup: impl FnOnce(&str) -> std::result::Result<String, std::env::VarError>,
//! ) -> anyhow::Result<Option<std::time::Duration>>
//! ```
//!
//! `lookup` mirrors `std::env::var`'s own signature rather than the lossy
//! `.ok()` form, and that is still load-bearing after the flip:
//! `Err(VarError::NotUnicode(..))` means PRESENT-but-not-UTF-8, and collapsing
//! it into "absent" would silently answer a question the operator DID answer,
//! with the answer they did not give.
//!
//!   * ABSENT (`Err(VarError::NotPresent)`) → `Ok(None)`, no timer — the
//!     operator made no choice, so none is made for them;
//!   * NOT UTF-8 (`Err(VarError::NotUnicode(..))`) → `Err`. The value is
//!     PRESENT, so it is a value the operator meant something by, and neither
//!     resolution is honest: silently arming an interval they may not have
//!     asked for, or silently running with no timer when they may have typed
//!     `12h`;
//!   * PRESENT (`Ok(raw)`) → whatever the parser makes of it, INCLUDING the
//!     error. A malformed value must never be swallowed into any fallback: an
//!     operator who typed `30dd` must find out at boot rather than discover
//!     months later that nothing has ever rotated.
//!
//! These tests do not compile until `parse_rotation_interval` exists — that
//! compile failure is the expected RED.

use std::env::VarError;
use std::time::Duration;

use wiremesh_controller::{
    parse_rotation_interval, rotation_interval_from_env, Config, ROTATION_INTERVAL_ENV,
};

/// Parses `s`, asserting success, and returns the parsed value. Failure
/// reports the operator-visible error text, since that is the only feedback a
/// real operator would get.
fn parsed(s: &str) -> Option<Duration> {
    parse_rotation_interval(s)
        .unwrap_or_else(|e| panic!("parse_rotation_interval({s:?}) must succeed, got error: {e:#}"))
}

/// The rejection message for `s` with the echoed-back input elided, so
/// rejections of DIFFERENT inputs can be compared for "is this the same
/// answer?".
///
/// Every rejection quotes the offending value back (`invalid rotation interval
/// "3651d": …`), which is the one part that legitimately differs between two
/// inputs. The needle is the QUOTED form, so eliding it cannot accidentally
/// chew through an unquoted coincidence elsewhere in the message (the accepted-
/// forms list ends `900s`, which contains `0s`).
fn rejection_reason(s: &str) -> String {
    rejected(s).replace(&format!("{s:?}"), "<value>")
}

/// Parses `s`, asserting failure, and returns the full error chain as the
/// operator would see it (`{:#}` so a `context`-wrapped cause is included).
fn rejected(s: &str) -> String {
    match parse_rotation_interval(s) {
        Ok(v) => panic!(
            "parse_rotation_interval({s:?}) must be REJECTED (a malformed or unusable \
             rotation interval must fail loudly at boot, never be silently accepted), \
             got: Ok({v:?})"
        ),
        Err(e) => format!("{e:#}"),
    }
}

/// Every accepted `<integer><unit>` form, for each of the four documented
/// suffixes, including multi-digit and 1-unit values.
#[test]
fn parses_every_documented_unit_suffix() {
    let cases: &[(&str, Duration)] = &[
        ("1s", Duration::from_secs(1)),
        ("900s", Duration::from_secs(900)),
        ("1m", Duration::from_secs(60)),
        ("15m", Duration::from_secs(15 * 60)),
        ("1h", Duration::from_secs(3600)),
        ("12h", Duration::from_secs(12 * 3600)),
        ("1d", Duration::from_secs(86_400)),
        ("30d", Duration::from_secs(30 * 86_400)),
        // Not a round number of anything — pins that the integer is parsed,
        // not matched against a table of blessed values.
        ("7331s", Duration::from_secs(7331)),
    ];
    for (input, want) in cases {
        assert_eq!(
            parsed(input),
            Some(*want),
            "parse_rotation_interval({input:?}) must yield Some({want:?}) — an enabled \
             timer at exactly that interval"
        );
    }
}

/// `off` disables automatic rotation, and the operator must not have to guess
/// the casing: an env var typed `OFF` has to work exactly like `off`.
#[test]
fn parses_off_case_insensitively_as_disabled() {
    for input in ["off", "OFF", "Off", "oFf", "ofF"] {
        assert_eq!(
            parsed(input),
            None,
            "parse_rotation_interval({input:?}) must yield None — automatic rotation \
             DISABLED. This is the escape hatch that removes a scheduled fabric-wide \
             outage; any casing an operator plausibly types must hit it."
        );
    }
}

/// Surrounding whitespace is trimmed (pinned decision: env vars and config
/// files pick up stray spaces/newlines trivially, and `WIREMESH_ROTATION_INTERVAL=" off "`
/// silently falling back to a 30-day timer is exactly the outage this knob
/// exists to prevent). Interior whitespace is still a hard error.
#[test]
fn trims_surrounding_whitespace_but_not_interior() {
    assert_eq!(parsed("  30d  "), Some(Duration::from_secs(30 * 86_400)));
    assert_eq!(parsed("\t15m\n"), Some(Duration::from_secs(15 * 60)));
    assert_eq!(parsed(" 900s"), Some(Duration::from_secs(900)));
    assert_eq!(parsed("12h "), Some(Duration::from_secs(12 * 3600)));

    assert_eq!(
        parsed("  off  "),
        None,
        "a whitespace-padded `off` must still DISABLE rotation — falling back to the \
         30-day timer here would reinstate the outage the operator just tried to switch off"
    );
    assert_eq!(parsed("\tOFF\n"), None);

    for input in ["30 d", "3 0d", "15m 30s", "of f"] {
        rejected(input);
    }
}

/// A zero interval is an ERROR, never "off" and never accepted: a zero-period
/// ticker would hot-loop `initiate_due_rotations`, rotating every gateway's
/// key as fast as the DB allows. The message is the operator's only feedback,
/// so it must name the thing they actually wanted (`off`).
#[test]
fn rejects_zero_duration_and_points_the_operator_at_off() {
    for input in ["0s", "0m", "0h", "0d", "  0d  ", "00s", "000d"] {
        let msg = rejected(input);
        assert!(
            msg.to_lowercase().contains("off"),
            "parse_rotation_interval({input:?}) must reject a ZERO interval with a message \
             that points the operator at `off` (the only supported way to disable automatic \
             rotation) — a bare 'invalid value' leaves them with no way to discover it. \
             Got: {msg:?}"
        );
        // Zero is the OPPOSITE failure from "too large", and must keep its own
        // diagnosis. It cannot saturate — `count == 0` times any multiplier is
        // still 0, and the zero check runs before the cap check — but "it
        // cannot happen" is exactly the reasoning worth a test rather than a
        // comment, now that a saturating multiply sits directly above it. The
        // cap message is identified by the maximum it quotes.
        assert!(
            !msg.contains("3650d"),
            "parse_rotation_interval({input:?}) is ZERO, not too large: it must get the \
             hot-loop diagnosis, never the 3650d cap message, which would tell an operator \
             who typed `0d` to try a SMALLER value. Got: {msg:?}"
        );
    }
}

/// Everything malformed fails loudly at boot rather than degrading to a
/// default: a mistyped interval must not silently leave the 30-day timer
/// running when the operator believed they had changed or disabled it.
#[test]
fn rejects_malformed_input() {
    let cases: &[&str] = &[
        // No unit suffix at all — ambiguous, never guessed at.
        "30",
        "0",
        // Unknown suffixes (no weeks/years/milliseconds in this contract).
        "30w",
        "30x",
        "30y",
        "500ms",
        // Empty / whitespace-only.
        "",
        "   ",
        "\n",
        // Negative.
        "-1d",
        "-0s",
        "-30",
        // Non-numeric.
        "abc",
        "d",
        "s",
        "dd",
        "many days",
        // Fractional — the contract is integer-only.
        "1.5h",
        "0.5d",
        // Suffix-shaped but not a single suffix.
        "30dd",
        "30ds",
        "30d30s",
        // `off`-adjacent strings that are NOT `off` — only the exact word
        // (modulo case and surrounding whitespace) disables rotation.
        "offs",
        "off d",
        "0ff",
        "disabled",
        "none",
        "false",
        "0off",
    ];
    for input in cases {
        rejected(input);
    }
}

/// Oversized values are rejected rather than wrapping, panicking, or — since
/// the multiply now saturates — quietly clamping to something that then looks
/// acceptable. Each one must also carry the CAP message: an operator whose
/// value was rejected for being too large needs to be told what the maximum is
/// and that `off` is what they probably wanted, regardless of which internal
/// route their particular value took to get there.
#[test]
fn rejects_overflowing_values() {
    for input in [
        // The count literal does not fit u64 at all — `parse` fails before any
        // multiply happens.
        "99999999999999999999999999d",
        "99999999999999999999999d",
        "184467440737095516150s",
        // Fits u64 as a count; saturates once multiplied into seconds.
        "18446744073709551615d",
        "18446744073709551615h",
        "18446744073709551615m",
    ] {
        let msg = rejected(input);
        assert!(
            msg.contains("3650d"),
            "{input:?} is rejected for being too large, so it must get the same help as any \
             other too-large value — including what the maximum actually is (3650d). \
             Saturating the multiply is only sound because it lands here. Got: {msg:?}"
        );
        assert!(
            msg.to_lowercase().contains("off"),
            "{input:?} is an attempt to make rotation effectively not happen; its rejection \
             must point at `off`. Got: {msg:?}"
        );
    }
}

/// **The invariant the shared message establishes.** All three structurally
/// different routes to "too large" must produce the SAME answer — not merely
/// three answers that happen to mention the cap.
///
/// Asserting only "each contains `3650d`" would pass just as happily for three
/// independently-worded messages, which is precisely the asymmetry that was
/// removed: whether a value overflows the multiply, saturates it, or fails to
/// parse as a `u64` at all is an implementation detail of the unit the operator
/// happened to choose, and it must not decide how much help they get.
#[test]
fn every_route_to_too_large_gives_the_same_answer() {
    // Same count, different units — and therefore different internal routes.
    let routes = [
        // No multiply overflow possible (`unit_secs == 1`): reaches the cap
        // check directly. This is the value that used to slip through entirely.
        "18446744073709551615s",
        // Saturates the multiply on the way to the cap check.
        "18446744073709551615d",
        "18446744073709551615h",
        // The count literal does not even fit u64: fails at `parse`.
        "99999999999999999999999d",
    ];

    let baseline = rejection_reason(routes[0]);
    for input in &routes[1..] {
        assert_eq!(
            rejection_reason(input),
            baseline,
            "{input:?} and {:?} are both simply too large, and must be answered identically \
             (modulo the value echoed back). Getting here via a saturating multiply, an \
             overflowing one, or a `u64` parse failure is invisible to the operator and must \
             stay that way.",
            routes[0]
        );
    }
}

// ---------------------------------------------------------------------------
// The 3650d (10-year) upper bound — the second silent route to a disabled
// timer, closed.
// ---------------------------------------------------------------------------

/// The cap in seconds, spelled out here rather than imported: the bound is part
/// of the operator-facing contract, so the test states it independently instead
/// of agreeing with whatever the implementation currently computes.
const MAX_SECS: u64 = 3650 * 24 * 60 * 60;

/// Exactly the cap is ACCEPTED — the bound is inclusive, and it must be
/// expressible in whichever unit the operator reached for. The bound is applied
/// to the computed seconds, so the same instant has to be accepted through all
/// four spellings.
#[test]
fn accepts_intervals_up_to_the_ten_year_cap() {
    for input in ["3650d", "87600h", "5256000m", "315360000s"] {
        assert_eq!(
            parsed(input),
            Some(Duration::from_secs(MAX_SECS)),
            "{input:?} is exactly the 3650d cap and must be ACCEPTED — the bound is \
             inclusive, and it must not depend on which unit the operator used to write it"
        );
    }
}

/// One unit above the cap is REJECTED, uniformly across units.
///
/// Why a cap exists at all: an interval large enough never to fire is a SECOND
/// way to disable automatic rotation — one that does not go through `off`, and
/// therefore never prints the boot banner. That banner is the controller's only
/// runtime signal that rotation is off (no metrics endpoint), so a silent route
/// past it defeats the safety mechanism this whole knob was built around.
/// `18446744073709551615s` was the concrete case: with unit `s` the overflow
/// check can never trip, and tokio's `Interval` saturates rather than
/// panicking, so it "worked".
#[test]
fn rejects_intervals_above_the_ten_year_cap() {
    for input in [
        // One unit past the boundary, in each unit.
        "3651d",
        "87601h",
        "5256001m",
        "315360001s",
        // The concrete finding: u64::MAX seconds, which no overflow check can
        // catch because the multiplier is 1.
        "18446744073709551615s",
        // And a merely absurd one an operator might actually type.
        "100000d",
    ] {
        let msg = rejected(input);
        assert!(
            msg.contains("3650d"),
            "the rejection of {input:?} must tell the operator what the maximum actually is \
             (3650d) — otherwise their only recourse is to guess downwards. Got: {msg:?}"
        );
        assert!(
            msg.to_lowercase().contains("off"),
            "an over-long interval is an attempt to make rotation not happen, so its \
             rejection must point at `off` — the one spelling that disables rotation AND \
             announces it at boot. Got: {msg:?}"
        );
    }
}

/// Requirement 6: `Config::default_rotation_interval()` still names 30 days,
/// and `30d` still parses to exactly it.
///
/// Both assertions predate the 2026-08-12 flip and both survive it — what
/// changed is what the constant MEANS. It is no longer "what an operator who
/// sets nothing gets" (silence now gets no timer at all — see
/// `env_absent_means_no_timer_never_a_default_interval`); it is simply the
/// interval the string `30d` denotes.
///
/// Why it survives at all, since no production path calls it any more: the
/// TESTS need a name for that interval — `wiremesh_testkit`'s
/// `TestController::start`/`start_on` boot with it, `boot_leaves_no_residue.rs`
/// builds its `Config` with it, and the second assertion below pins `30d`
/// against it, so a change to either end of that pair has to be deliberate.
/// Deleting it in the name of "there is no default any more" would scatter
/// `30 * 24 * 60 * 60` across those call sites; making it mean "the fallback"
/// again would re-arm every silent install.
///
/// What it is NOT is a value the operator-facing surfaces quote. They cannot:
/// the docs, `--help` and the disabled-rotation banner all spell the TOKEN
/// `30d` inside prose, which no constant can be interpolated into, and each is
/// pinned by its own test instead (`cli_help_version.rs`,
/// `rotation_disabled_banner.rs`). This doc comment claimed the opposite until
/// 2026-08-12, in the same words `Config::default_rotation_interval`'s own doc
/// used — two statements of one false rationale, each reading as corroboration
/// of the other, which is precisely how it survived. Both are now fixed; if
/// they ever disagree again, `lib.rs` is the one to believe.
///
/// It also stays a plain `Duration` — the `Option` lives on the `Config` field,
/// where `None` means "disabled".
#[test]
fn thirty_days_equals_the_named_interval_constant() {
    assert_eq!(
        Config::default_rotation_interval(),
        Duration::from_secs(30 * 24 * 60 * 60),
        "the constant must stay 30 days — it is the recommended rotation period quoted to \
         operators, and `30d` below is pinned against it"
    );
    assert_eq!(
        parsed("30d"),
        Some(Config::default_rotation_interval()),
        "`30d` must parse to exactly the named constant, so an operator who wants the \
         recommended 30-day rotation can write it down and get precisely that — which is \
         now the ONLY way to get it (see only_an_explicit_interval_can_arm_the_timer)"
    );
}

// ---------------------------------------------------------------------------
// Uppercase unit suffixes (owner decision: rejected, with a dedicated message).
// ---------------------------------------------------------------------------

/// `30D`/`15M`/`12H`/`900S` are rejected rather than case-folded — the owner
/// decision here is that `M` reads as "months" to plenty of operators, so
/// guessing at intent is worse than refusing.
///
/// The message must say *units are lowercase*: this is the operator's only
/// feedback, and a generic "unknown suffix" would send someone who typed `30D`
/// hunting for a suffix that they in fact used correctly apart from its case.
#[test]
fn rejects_uppercase_unit_suffixes_and_says_units_are_lowercase() {
    for input in ["30D", "15M", "12H", "900S", "1D", "  30D  "] {
        let msg = rejected(input);
        assert!(
            msg.to_lowercase().contains("lowercase"),
            "parse_rotation_interval({input:?}) must be rejected with a message that tells \
             the operator unit suffixes are LOWERCASE — the suffix letter itself is right, \
             only its case is wrong, and a generic 'unknown suffix' sends them looking for \
             the wrong problem. Got: {msg:?}"
        );
    }
}

/// The uppercase-unit rejection must be DISTINGUISHABLE from the genuinely
/// unknown-suffix rejection: a real unknown suffix (`30w`, `30x`, `500ms`)
/// must not claim the problem is casing, because lowercasing it would not help.
#[test]
fn unknown_suffix_rejection_does_not_claim_units_are_lowercase() {
    for input in ["30w", "30x", "30y", "500ms"] {
        let msg = rejected(input);
        assert!(
            !msg.to_lowercase().contains("lowercase"),
            "parse_rotation_interval({input:?}) has a genuinely UNKNOWN unit suffix, not a \
             miscased one — its rejection must not tell the operator to use lowercase (it \
             already is, and `{input}` in any case is still not a unit). That message is \
             reserved for `30D`-style inputs. Got: {msg:?}"
        );
    }
}

/// The lowercase claim must hold only when CASING IS THE SOLE PROBLEM. An
/// uppercase unit sitting on a broken count (`abcD`) — or standing alone with
/// no count at all (`D`) — is not a miscased interval, and "write `d`, not `D`"
/// would hand the operator a second value (`abcd`, `d`) that is *also*
/// rejected: two restarts to learn one thing. Those must fall through to the
/// ordinary bad-number / unknown-suffix rejections instead.
///
/// This is the shape the sibling test above does not reach: it covers a bad
/// SUFFIX with a good count, whereas this covers a good-looking suffix with a
/// bad count.
#[test]
fn miscased_suffix_on_a_broken_count_does_not_claim_units_are_lowercase() {
    // The control: casing IS the sole problem here, so the claim is true and
    // must still be made. Asserted alongside the negatives so this test fails
    // if the uppercase branch is deleted outright rather than narrowed.
    for input in ["30D", "15M", "900S", "12H"] {
        let msg = rejected(input);
        assert!(
            msg.to_lowercase().contains("lowercase"),
            "parse_rotation_interval({input:?}) is a well-formed count with a MISCASED unit \
             — casing is the only thing wrong with it, so the rejection must still say units \
             are lowercase. Got: {msg:?}"
        );
    }

    for input in ["abcD", "D", "  D  ", "S", "xM", "-1D", "1.5H", "offD"] {
        let msg = rejected(input);
        assert!(
            !msg.to_lowercase().contains("lowercase"),
            "parse_rotation_interval({input:?}) is not merely miscased — the part before the \
             suffix is not a whole number (or is missing entirely), so lowercasing the unit \
             would leave it just as invalid. Claiming 'units are lowercase' here sends the \
             operator back for another restart with a value that still fails. Got: {msg:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Environment resolution (`rotation_interval_from_env`).
// ---------------------------------------------------------------------------

/// **The important one.** An ABSENT variable means NO TIMER — the same
/// resolved value as `off`.
///
/// This is the path every shipped artifact takes out of the box: the
/// `.deb`/`.rpm` ship `deploy/packages/env/controller.env` with the variable
/// commented out, the ghcr container image's controller stage sets no env, and
/// a source build inherits whatever the host has (nothing). It used to resolve
/// to `Some(30 days)`, which armed the rotation-initiation timer for every one
/// of them.
///
/// Why that is not acceptable, in one line: automatic rotation still points at
/// a KNOWN-OPEN defect — backlog item 9, the rotation wedge, where a rotation
/// that fails part-way parks the gateway's phase off `Idle` and
/// `Rotation::on_directive` is honoured only from `Idle`, so that gateway
/// silently ignores every later `RotateDirective` until the process is
/// restarted, and never scrubs the old key. Arming that on a 30-day fuse for
/// anyone who merely installed the package is a decision the software was
/// making on the operator's behalf, out of their sight, with a failure that
/// only shows up 30 days later on a fabric nobody is watching.
///
/// So the rule is: an operator who never made a choice must not have one made
/// for them. Automatic rotation is now OPT-IN — arming it takes an explicit
/// interval, written down somewhere a human can find it.
///
/// An `Err` is equally wrong: every existing controller would refuse to boot
/// on upgrade over a variable it has never had set.
#[test]
fn env_absent_means_no_timer_never_a_default_interval() {
    let got = rotation_interval_from_env(|_| Err(VarError::NotPresent)).unwrap_or_else(|e| {
        panic!(
            "an ABSENT {ROTATION_INTERVAL_ENV} must not be an error — that would break the \
             boot of every deployment that has never set the variable, which is all of them \
             except the Kubernetes operator path. Got: {e:#}"
        )
    });
    assert_eq!(
        got, None,
        "with {ROTATION_INTERVAL_ENV} unset the controller must run with NO \
         rotation-initiation timer, exactly as if the operator had written \
         {ROTATION_INTERVAL_ENV}=off. `Some(_)` here — and \
         `Some(Config::default_rotation_interval())` in particular, which is what this \
         resolved to before 2026-08-12 — silently arms automatic key rotation for every \
         .deb/.rpm/container/source install that never set the variable, and automatic \
         rotation still walks into backlog item 9 (the rotation wedge: a part-failed \
         rotation parks the gateway off `Idle`, and every later RotateDirective is \
         silently ignored until it restarts). An operator who never made a choice must \
         not have one made for them. Got: {got:?}"
    );
}

/// A present, valid value is passed through to the parser and used verbatim.
#[test]
fn env_present_and_valid_yields_the_parsed_value() {
    for (raw, want) in [
        ("900s", Duration::from_secs(900)),
        ("15m", Duration::from_secs(15 * 60)),
        ("12h", Duration::from_secs(12 * 3600)),
        ("7d", Duration::from_secs(7 * 86_400)),
        // The former implicit default, now reachable only by writing it down.
        // An operator who WANTS 30-day rotation must still get exactly the
        // behaviour they used to get by accident.
        ("30d", Config::default_rotation_interval()),
        // Whitespace an env file or Kubernetes manifest would pick up.
        ("  15m\n", Duration::from_secs(15 * 60)),
    ] {
        let got = rotation_interval_from_env(|_| Ok(raw.to_string()))
            .unwrap_or_else(|e| panic!("{ROTATION_INTERVAL_ENV}={raw:?} must parse, got: {e:#}"));
        assert_eq!(
            got,
            Some(want),
            "{ROTATION_INTERVAL_ENV}={raw:?} must resolve to Some({want:?})"
        );
    }
}

/// `off` in the environment disables automatic rotation — the escape hatch,
/// reachable the way an operator actually sets it.
#[test]
fn env_present_off_disables_rotation() {
    for raw in ["off", "OFF", "  Off  "] {
        let got = rotation_interval_from_env(|_| Ok(raw.to_string())).unwrap_or_else(|e| {
            panic!("{ROTATION_INTERVAL_ENV}={raw:?} must be accepted, got: {e:#}")
        });
        assert_eq!(
            got, None,
            "{ROTATION_INTERVAL_ENV}={raw:?} must resolve to None — automatic rotation \
             DISABLED"
        );
    }
}

/// `off` and ABSENT now resolve to the same value, and that is the whole point
/// of the flip — but they agree by CONSTRUCTION, not by coincidence, and this
/// test exists to make a future regression prove which one it broke.
///
/// The trap it guards: `None` from `off` and `None` from absent are
/// indistinguishable in the return type, so a change that reintroduces a
/// default interval — "just restore the 30-day fallback, `off` still works" —
/// looks locally harmless and leaves every `off` test green while silently
/// re-arming every install that sets nothing. That is exactly the shape the
/// pre-2026-08-12 code had, and exactly how it survived unnoticed through the
/// `.deb`, the `.rpm`, and the container image.
///
/// So the property asserted is not "absent == off" (which a `None`-returning
/// stub would satisfy) but the one that actually matters: **the only way to
/// arm the timer is to say an interval out loud.** Both non-answers resolve to
/// no timer; a written-down interval, and only a written-down interval,
/// resolves to `Some`. `Config::default_rotation_interval()` survives as the
/// value `30d` names — it must never again be the value silence names.
#[test]
fn only_an_explicit_interval_can_arm_the_timer() {
    // The two ways an operator ends up having expressed no interval. Neither
    // is the operator asking for rotation.
    let absent = rotation_interval_from_env(|_| Err(VarError::NotPresent))
        .expect("an ABSENT variable must resolve, not error");
    let explicit_off = rotation_interval_from_env(|_| Ok("off".to_string()))
        .expect("an explicit `off` must resolve, not error");
    assert_eq!(
        absent, explicit_off,
        "an unset {ROTATION_INTERVAL_ENV} and an explicit {ROTATION_INTERVAL_ENV}=off must \
         resolve to the same thing: no rotation-initiation timer. Got absent={absent:?} vs \
         off={explicit_off:?} — they have diverged, which means one of the two paths grew a \
         default the other did not"
    );
    assert_eq!(
        absent, None,
        "...and the thing they agree on must be None. Two paths agreeing on \
         Some(interval) would satisfy the assertion above while arming exactly what this \
         contract exists to leave disarmed. Got: {absent:?}"
    );
    assert_ne!(
        absent,
        Some(Config::default_rotation_interval()),
        "silence must not resolve to the 30-day interval (or to any interval). This is the \
         literal pre-2026-08-12 behaviour, restated so that reintroducing it fails HERE, \
         with a message that says why, rather than in whichever gateway wedges 30 days \
         after someone installs the .deb"
    );

    // And the mirror: an interval the operator actually wrote down still arms
    // the timer, at exactly the value written. Without this, a
    // `rotation_interval_from_env` stubbed to `Ok(None)` would pass everything
    // above — "nothing rotates, ever" is not the contract either. The knob
    // still has to work for the operator who deliberately turns it on.
    for raw in ["30d", "12h", "900s"] {
        let armed = rotation_interval_from_env(|_| Ok(raw.to_string()))
            .unwrap_or_else(|e| panic!("{ROTATION_INTERVAL_ENV}={raw:?} must parse: {e:#}"));
        assert_eq!(
            armed,
            parse_rotation_interval(raw).expect("the same value parses standalone"),
            "the env path must resolve {raw:?} to exactly what the parser makes of it — \
             an explicit interval is the ONE input that arms the timer, so it must not be \
             filtered, clamped, or defaulted on its way through"
        );
        assert!(
            armed.is_some(),
            "{ROTATION_INTERVAL_ENV}={raw:?} is an operator explicitly asking for automatic \
             rotation and must resolve to Some(_). Making absence mean 'off' must not turn \
             into making everything mean 'off': the escape hatch is opt-in rotation, not \
             no rotation. Got: {armed:?}"
        );
    }
}

/// **The review finding.** A PRESENT variable whose bytes are not UTF-8
/// (`Err(VarError::NotUnicode(..))`) is a hard error — never any silent
/// resolution.
///
/// `std::env::var(k).ok()`, the obvious closure to pass, collapses this case
/// into `None`; `None` reads as absent. Before the 2026-08-12 flip that meant
/// silently ARMING the 30-day timer for someone who believed they had written
/// `off`. The flip does not retire this test, it only changes which lie gets
/// told: absent now means no timer, so collapsing a mis-encoded value into
/// "absent" would silently DISARM rotation for an operator who wrote `12h`.
/// Either way the software answers a question the operator did answer, with an
/// answer they did not give — and this is the one case where it can tell that
/// they answered at all. The whole point of `lookup` mirroring
/// `std::env::var`'s signature is that this third case cannot be dropped on
/// the floor, so the test asserts the distinction the type preserves.
///
/// It also pins the REJECTION PROSE, because that message currently explains
/// itself by reference to a default that no longer exists.
#[test]
fn env_non_utf8_value_is_a_hard_error_not_the_default() {
    // `off` with a stray continuation byte on the end — present, non-empty,
    // and not representable as a `String`.
    use std::os::unix::ffi::OsStringExt;
    let not_utf8 = std::ffi::OsString::from_vec(vec![b'o', b'f', b'f', 0x80]);

    match rotation_interval_from_env(|_| Err(VarError::NotUnicode(not_utf8))) {
        Ok(v) => panic!(
            "a PRESENT-but-not-UTF-8 {ROTATION_INTERVAL_ENV} must be a startup error, got \
             Ok({v:?}). {} The operator SET this variable; the one thing that must not \
             happen is the controller quietly picking a value for them and booting.",
            match v {
                Some(d) if d == Config::default_rotation_interval() =>
                    "Falling back to the 30-day interval (which is what happened here) arms \
                     automatic rotation for someone who may well have been typing `off`.",
                Some(_) =>
                    "Falling back to any interval arms automatic rotation for someone who \
                     may well have been typing `off`.",
                None =>
                    "Resolving to None (which is what happened here) is the mis-encoded \
                     value being treated as ABSENT — indistinguishable from having set \
                     nothing, so an operator who wrote `12h` runs with no timer at all and \
                     nothing tells them.",
            }
        ),
        Err(e) => {
            let msg = format!("{e:#}");
            assert!(
                msg.contains(ROTATION_INTERVAL_ENV),
                "the rejection must name the variable at fault ({ROTATION_INTERVAL_ENV}); \
                 the operator cannot see the raw bytes and needs to be told which variable \
                 to re-set. Got: {msg:?}"
            );
            assert!(
                msg.to_lowercase().contains("utf-8"),
                "the rejection must say the value is not valid UTF-8 — that is the ONLY \
                 clue the operator has, since the bytes themselves cannot be echoed back \
                 legibly. Got: {msg:?}"
            );
            assert!(
                !msg.to_lowercase().contains("-day default"),
                "the rejection must not justify itself by pointing at a default interval \
                 that no longer exists. This message used to read '...falling back to the \
                 30-day default here would silently arm the automatic key-rotation timer', \
                 interpolating Config::default_rotation_interval(); after the 2026-08-12 \
                 flip an unset variable arms nothing, so that sentence describes behaviour \
                 the code does not have. An operator who reads it goes looking for a \
                 30-day timer that is not running — the same class of misdirection this \
                 whole knob exists to remove. Say instead that the variable is set to \
                 something unreadable and must be re-set. Got: {msg:?}"
            );
        }
    }
}

/// A present-but-malformed value must propagate as an `Err` (which `main.rs`
/// turns into a non-zero exit), NOT degrade to the default.
///
/// This is the worst possible place for a silent fallback: an operator who
/// typed `of`, or `30dd`, or `0s`, would be left believing they had changed or
/// disabled rotation while the 30-day timer — the scheduled fabric-wide outage
/// this knob exists to remove — was still armed, and nothing would tell them
/// otherwise until it fired.
#[test]
fn env_present_malformed_is_a_startup_error_not_a_silent_default() {
    for raw in [
        "of", "0", "30", "30dd", "30D", "abc", "", "   ", "-1d", "30w",
    ] {
        match rotation_interval_from_env(|_| Ok(raw.to_string())) {
            Ok(v) => panic!(
                "{ROTATION_INTERVAL_ENV}={raw:?} is malformed and MUST be a startup error. \
                 Got Ok({v:?}) — a silent fallback here leaves an operator believing they \
                 changed or disabled automatic rotation when they did not."
            ),
            Err(e) => {
                let msg = format!("{e:#}");
                assert!(
                    msg.contains(ROTATION_INTERVAL_ENV),
                    "the rejection for {raw:?} must name the variable at fault \
                     ({ROTATION_INTERVAL_ENV}) — the controller reads several env vars and \
                     the operator has to know which one to fix. Got: {msg:?}"
                );
            }
        }
    }
}

/// Wrapping the parse error in the variable's name must not bury the reason:
/// the zero-interval rejection still has to point at `off` after
/// `rotation_interval_from_env` has added its context.
#[test]
fn env_error_preserves_the_underlying_reason() {
    let e = rotation_interval_from_env(|_| Ok("0s".to_string()))
        .expect_err("a zero interval must be rejected through the env path too");
    let msg = format!("{e:#}");
    assert!(
        msg.to_lowercase().contains("off"),
        "the env-level context must be ADDED to the parser's reason, not replace it — an \
         operator who set {ROTATION_INTERVAL_ENV}=0s still needs to be told that `off` is \
         the way to disable automatic rotation. Got: {msg:?}"
    );
}

/// The lookup must be called with the canonical constant, exactly once — a
/// hardcoded string inside the function could silently drift from
/// `ROTATION_INTERVAL_ENV` (which `main.rs`'s diagnostics and the
/// rotation-disabled boot banner both interpolate), leaving the documented
/// variable name and the one actually read pointing at different things.
#[test]
fn env_lookup_is_called_once_with_the_canonical_variable_name() {
    let seen = std::cell::RefCell::new(Vec::new());
    let got = rotation_interval_from_env(|key| {
        seen.borrow_mut().push(key.to_string());
        Err(VarError::NotPresent)
    })
    .expect("an absent variable must not be an error");
    assert_eq!(
        got, None,
        "sanity: the absent case resolves to no timer (the contract pinned in \
         env_absent_means_no_timer_never_a_default_interval) — asserted here too so this \
         test cannot pass against a lookup that was consulted correctly and then ignored"
    );

    let seen = seen.into_inner();
    assert_eq!(
        seen,
        vec![ROTATION_INTERVAL_ENV.to_string()],
        "rotation_interval_from_env must consult the environment exactly once, for \
         ROTATION_INTERVAL_ENV — got these lookups instead: {seen:?}"
    );
    assert_eq!(
        ROTATION_INTERVAL_ENV, "WIREMESH_ROTATION_INTERVAL",
        "the constant itself is the documented operator-facing variable name (it appears in \
         the deployment docs, the systemd unit, and the rotation-disabled boot banner) — \
         renaming it is a breaking change to every deployment that sets it, not a \
         refactor"
    );
}
