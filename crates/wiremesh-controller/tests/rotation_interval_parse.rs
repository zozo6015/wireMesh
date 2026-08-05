//! Unit tests for `wiremesh_controller::parse_rotation_interval` and
//! `rotation_interval_from_env` — the pure, library-level parser behind the
//! operator-facing rotation-interval knob, and the environment resolution that
//! feeds it in `main.rs`.
//!
//! Why this knob exists (and why the DISABLED path is the one tested
//! hardest): the controller automatically rotates every active gateway's
//! WireGuard key on a 30-day timer (`services::sync::initiate_due_rotations`).
//! Automatic rotation is currently known-broken in ways that make a scheduled
//! fabric-wide outage inevitable, so an operator must be able to turn the
//! timer OFF until the structural fix lands. `off` is that escape hatch, and
//! the parser is its only gate — an `off` that silently parses as "some
//! interval" (or a `0s` that silently parses as "off", or as a hot-looping
//! zero interval) is the failure mode this file exists to prevent.
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
//!     message
//!
//! And, for the environment resolution `main.rs` delegates to:
//!
//! ```ignore
//! pub const ROTATION_INTERVAL_ENV: &str = "WIREMESH_ROTATION_INTERVAL";
//! pub fn rotation_interval_from_env(
//!     lookup: impl FnOnce(&str) -> Option<String>,
//! ) -> anyhow::Result<Option<std::time::Duration>>
//! ```
//!
//!   * ABSENT → `Ok(Some(Config::default_rotation_interval()))` — the unchanged
//!     30-day behaviour every existing deployment takes;
//!   * PRESENT → whatever the parser makes of it, INCLUDING the error. A
//!     malformed value must never be swallowed into the default: an operator
//!     who typed `of` instead of `off` would otherwise believe rotation was
//!     disabled while a 30-day timer was in fact still armed.
//!
//! These tests do not compile until `parse_rotation_interval` exists — that
//! compile failure is the expected RED.

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

/// Oversized values are rejected rather than wrapping, saturating, or
/// panicking — `30d`-style inputs are multiplied up to seconds, so the
/// multiplication has to be checked.
#[test]
fn rejects_overflowing_values() {
    for input in [
        // Beyond u64 entirely.
        "99999999999999999999999999d",
        "184467440737095516150s",
        // Fits u64 as a count, overflows once multiplied into seconds.
        "18446744073709551615d",
        "18446744073709551615h",
        "18446744073709551615m",
    ] {
        rejected(input);
    }
}

/// Requirement 6: the default is unchanged at 30 days. `Config::default_rotation_interval()`
/// stays a plain `Duration` (the `Option` lives on the `Config` field, where
/// `None` means "disabled"), and `30d` — the string an operator would write to
/// restore the default explicitly — parses to exactly it.
#[test]
fn thirty_days_equals_the_unchanged_default() {
    assert_eq!(
        Config::default_rotation_interval(),
        Duration::from_secs(30 * 24 * 60 * 60),
        "the production default must stay 30 days — this knob only adds an override, it \
         must not change what an operator who sets nothing gets"
    );
    assert_eq!(
        parsed("30d"),
        Some(Config::default_rotation_interval()),
        "`30d` must parse to exactly the built-in default, so an operator can write the \
         default down explicitly and get identical behaviour"
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

// ---------------------------------------------------------------------------
// Environment resolution (`rotation_interval_from_env`).
// ---------------------------------------------------------------------------

/// **The important one.** An ABSENT variable is the path every existing
/// deployment takes: it must keep yielding the unchanged, ENABLED 30-day
/// timer. Neither `None` (rotation silently disabled fabric-wide for everyone
/// who never set the variable) nor an error (every existing controller refuses
/// to boot) is acceptable here.
#[test]
fn env_absent_yields_the_unchanged_thirty_day_default() {
    let got = rotation_interval_from_env(|_| None).unwrap_or_else(|e| {
        panic!("an ABSENT {ROTATION_INTERVAL_ENV} must not be an error, got: {e:#}")
    });
    assert_eq!(
        got,
        Some(Config::default_rotation_interval()),
        "with {ROTATION_INTERVAL_ENV} unset the controller must behave exactly as it did \
         before this knob existed: automatic rotation ENABLED at the 30-day default. \
         `None` here would silently disable rotation for every deployment that never set \
         the variable."
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
        // Whitespace an env file or Kubernetes manifest would pick up.
        ("  15m\n", Duration::from_secs(15 * 60)),
    ] {
        let got = rotation_interval_from_env(|_| Some(raw.to_string()))
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
        let got = rotation_interval_from_env(|_| Some(raw.to_string())).unwrap_or_else(|e| {
            panic!("{ROTATION_INTERVAL_ENV}={raw:?} must be accepted, got: {e:#}")
        });
        assert_eq!(
            got, None,
            "{ROTATION_INTERVAL_ENV}={raw:?} must resolve to None — automatic rotation \
             DISABLED"
        );
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
    for raw in ["of", "0", "30", "30dd", "30D", "abc", "", "   ", "-1d", "30w"] {
        match rotation_interval_from_env(|_| Some(raw.to_string())) {
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
    let e = rotation_interval_from_env(|_| Some("0s".to_string()))
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
        None
    })
    .expect("an absent variable must not be an error");
    assert_eq!(got, Some(Config::default_rotation_interval()));

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
