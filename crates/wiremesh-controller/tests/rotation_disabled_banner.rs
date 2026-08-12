//! The boot banner the controller prints when `Config::rotation_interval` is
//! `None` — automatic key rotation off, no rotation-initiation timer running.
//!
//! # Why this file exists now
//!
//! Before the 2026-08-12 contract flip, `rotation_interval: None` had exactly
//! one cause: an operator wrote `WIREMESH_ROTATION_INTERVAL=off`. The banner
//! could therefore state that as a fact, and it does — verbatim, as
//! `WIREMESH_ROTATION_INTERVAL=off — no rotation-initiation timer is running`.
//!
//! After the flip, `None` has TWO causes, and the second one is now the common
//! one: the variable is simply not set — which is every `.deb`/`.rpm` install
//! (`deploy/packages/env/controller.env` ships it commented out), every ghcr
//! container image, and every source build. For all of those, the banner's
//! first line is a false statement about the operator's configuration. Someone
//! who reads it goes looking for an `off` they never wrote: they grep
//! `/etc/wiremesh/controller.env`, find the line commented out, and are left
//! deciding whether the controller is lying, the env file is stale, or
//! something else on the host is setting the variable behind their back. The
//! banner is this binary's ONLY runtime signal that rotation is off (the
//! controller exposes no metrics endpoint, unlike the gateway), so it does not
//! get to be a sentence that sends its one reader on a hunt for a value that
//! does not exist.
//!
//! The fix is not to suppress the banner for the absent case — that would be
//! strictly worse. Absent is now the majority path, and it is precisely the
//! operator who set nothing who most needs to be told that nothing rotates.
//! The banner must fire for BOTH causes and must stop asserting which one it
//! was.
//!
//! # Contract under test
//!
//! The banner text is asserted at the library level, deliberately, rather than
//! by spawning the binary and reading stderr: a spawned real boot mints a CA
//! and trips the `/var/lib/wiremesh` re-mint guard on any host that happens to
//! have one (see `Config::legacy_data_dir`, which `main.rs` deliberately does
//! not expose to the environment), so a stderr-scraping test would go red on
//! real controller hosts and developer boxes for reasons having nothing to do
//! with the banner. This mirrors the choice already made in
//! `rotation_disabled.rs`, which reaches the disabled STATE through the
//! `RunningController::automatic_rotation_disabled()` accessor for the same
//! reason.
//!
//! That requires the text to be reachable:
//!
//! ```ignore
//! /// The banner `serve` prints when `rotation_interval: None`.
//! pub fn automatic_rotation_disabled_banner() -> String;
//! ```
//!
//! `warn_automatic_rotation_disabled()` stays the thing that PRINTS it (to
//! stderr, at boot, unchanged); it just stops being the only thing that knows
//! what it says. Until that function exists this file does not compile, and
//! that compile failure is the expected RED — the same idiom the sibling
//! `rotation_interval_parse.rs` opens with.
//!
//! # That the banner is actually EMITTED
//!
//! The tests above assert what the banner SAYS. They do not, on their own,
//! assert that anything ever says it: `serve` gates the print on
//! `config.rotation_interval == None`, and deleting that one call site would
//! leave every assertion in this file green while the controller's only
//! runtime signal that rotation is off disappeared — the controller exposes no
//! metrics endpoint, unlike the gateway, and
//! `RunningController::automatic_rotation_disabled()` reads
//! `rotation_timer_join.is_none()`, which is true whether or not anything was
//! printed. `MAX_ROTATION_INTERVAL_SECS`'s entire rationale is that a
//! never-firing timer would disable rotation *without* this line, so the line
//! not being printed at all defeats the same safety argument.
//!
//! `emitted_banner_survives_a_boot_and_a_restart` closes that, using the
//! second half of the seam:
//!
//! ```ignore
//! /// Prints the banner and returns what it printed.
//! fn warn_automatic_rotation_disabled() -> String;
//! /// `Some(banner)` iff this boot took the disabled branch and printed it.
//! impl RunningController { pub fn rotation_disabled_banner(&self) -> Option<&str>; }
//! ```
//!
//! The recorded value can only exist if the call happened, so the print site
//! cannot be deleted without a red test. It does not prove the bytes reached
//! fd 2 — that would take a `dup2` capture around an in-process boot, which
//! mutates a process-global fd shared with every other test thread; the
//! `eprintln!` is the only statement in a three-line function whose return
//! value is now pinned, which is the same trade `automatic_rotation_disabled()`
//! already makes.
//!
//! The full chain is therefore pinned end to end: an absent variable resolves
//! to `Ok(None)` (`rotation_interval_parse.rs`), that `None` reaches
//! `Config.rotation_interval` unmodified (`config_from_env.rs`), `serve` spawns
//! no timer for it (`rotation_disabled.rs`), and it says so out loud (here).

use std::time::Duration;

use wiremesh_controller::{
    automatic_rotation_disabled_banner, parse_rotation_interval, ROTATION_INTERVAL_ENV,
};

/// Case-insensitive containment, since the banner shouts parts of itself in
/// caps (`AUTOMATIC KEY ROTATION IS OFF`) and the exact casing of any one
/// phrase is not the contract.
fn says(banner: &str, needle: &str) -> bool {
    banner.to_lowercase().contains(&needle.to_lowercase())
}

/// The banner's lines with the `wiremesh-controller: ` prefix stripped.
///
/// Needed by any per-line co-occurrence check: every line carries that prefix,
/// so "this line also mentions the controller" is otherwise vacuously true.
fn body_lines(banner: &str) -> Vec<&str> {
    banner
        .lines()
        .map(|l| l.strip_prefix("wiremesh-controller: ").unwrap_or(l))
        .collect()
}

/// Does `line` contain a token an operator could paste into
/// `WIREMESH_ROTATION_INTERVAL` and get an ARMED timer?
///
/// Asked of the real parser rather than by matching a literal, so the banner's
/// example may be reworded, requoted, or changed to another valid interval
/// freely — and so the check means what it claims: not "the characters `30d`
/// appear somewhere" but "a value this controller would actually accept is
/// shown". Prose like "e.g. 30 days" does NOT satisfy it, correctly — it is
/// not an example of the grammar. Surrounding punctuation is trimmed so an
/// example embedded in a sentence (`` `30d`, ``) is still recoverable.
fn shows_a_pasteable_interval(line: &str) -> bool {
    line.split_whitespace()
        .map(|t| t.trim_matches(|c: char| !c.is_ascii_alphanumeric()))
        .any(|t| matches!(parse_rotation_interval(t), Ok(Some(_))))
}

/// **The finding.** The banner must not claim the operator set the variable to
/// `off`, because after the flip they very probably did not set it at all.
#[test]
fn banner_does_not_claim_the_variable_was_set_to_off() {
    let banner = automatic_rotation_disabled_banner();
    let lie = format!("{ROTATION_INTERVAL_ENV}=off");
    assert!(
        !says(&banner, &lie),
        "the banner states {lie:?} as a fact about the running configuration, but an unset \
         {ROTATION_INTERVAL_ENV} now produces this same banner — and unset is the majority \
         path (the .deb/.rpm ship the line commented out, the container image sets no env, \
         a source build inherits nothing). Telling an operator who set nothing that they \
         set `off` sends them grepping /etc/wiremesh/controller.env for a value that is not \
         there, and leaves them unsure whether to believe the controller or the file. Name \
         the variable, say rotation is off, and let the cause be either — do not assert \
         which. Got:\n{banner}"
    );
}

/// Naming the variable is not optional: it is the knob the reader has to touch
/// to change this state, and the controller reads several `WIREMESH_*` vars.
#[test]
fn banner_still_names_the_variable_and_the_state() {
    let banner = automatic_rotation_disabled_banner();
    assert!(
        banner.contains(ROTATION_INTERVAL_ENV),
        "the banner must name {ROTATION_INTERVAL_ENV} — dropping the variable's name to \
         avoid claiming a value would leave the reader knowing rotation is off and not \
         knowing what to set. Got:\n{banner}"
    );
    assert!(
        says(&banner, "rotation") && (says(&banner, "off") || says(&banner, "disabled")),
        "the banner must still say, in words, that automatic key rotation is off — it is \
         this binary's only runtime signal of that state (no metrics endpoint, unlike the \
         gateway), and the `MAX_ROTATION_INTERVAL_SECS` cap's whole rationale is that a \
         never-firing timer would disable rotation *without* this line. Got:\n{banner}"
    );
}

/// The new sentence has to cover the reader who set nothing — otherwise
/// removing the false `=off` claim just leaves them with a banner that never
/// mentions the situation they are actually in.
#[test]
fn banner_accounts_for_the_variable_being_unset() {
    let banner = automatic_rotation_disabled_banner();
    assert!(
        ["unset", "not set", "absent", "no value"]
            .iter()
            .any(|phrase| says(&banner, phrase)),
        "the banner must acknowledge that an UNSET {ROTATION_INTERVAL_ENV} is one of the \
         two ways to reach this state (the other being an explicit `off`). Since the \
         2026-08-12 flip, absent means no timer, and absent is what every stock install \
         has — so the operator most likely to read this line is the one who set nothing, \
         and the line has to describe their situation, not only the deliberate-`off` one. \
         Say something like: `{ROTATION_INTERVAL_ENV} is unset or set to `off``. Got:\n\
         {banner}"
    );
}

/// Everything the banner already told the operator has to survive the rewrite.
/// These are not decorative: the re-enable instruction is the only place the
/// accepted grammar appears at runtime, and the still-working facts are what
/// stop an operator concluding their fabric cannot rotate keys at all and
/// reaching for something more drastic.
#[test]
fn banner_keeps_the_recovery_and_still_working_facts() {
    let banner = automatic_rotation_disabled_banner();

    assert!(
        body_lines(&banner)
            .iter()
            .any(|line| shows_a_pasteable_interval(line)),
        "the banner must keep an example of an ACCEPTED interval — it is the reader's only \
         runtime hint at the grammar, and after the flip it is doing MORE work than before, \
         since writing an interval down is now the only way to arm rotation at all. The \
         example is checked by handing each word to parse_rotation_interval, not by matching \
         the literal `30d`, so the wording, the quoting and the value itself are all free to \
         change — what may not change is that the reader is shown something they can paste \
         and have accepted. Note that prose alone (`e.g. 30 days`) does not qualify: it is \
         not a value this controller takes. Got:\n{banner}"
    );
    assert!(
        body_lines(&banner)
            .iter()
            .any(|line| says(line, "restart") && line.contains(ROTATION_INTERVAL_ENV)),
        "the banner must keep telling the operator that the controller has to be RESTARTED \
         for a new interval to take effect — the variable is read once at boot, and an \
         operator who edits the env file and waits will wait forever. The word has to appear \
         in the same line as {ROTATION_INTERVAL_ENV}, i.e. as part of the re-enable \
         instruction: a bare search for `restart` anywhere in the banner is satisfied by the \
         unrelated sentence about rotations surviving a restart, so the instruction could be \
         deleted outright and this assertion would still pass. (Line-scoped rather than \
         whole-banner: if that instruction is ever reflowed across two lines, widen the \
         window here deliberately — do not go back to the bare substring.) Got:\n{banner}"
    );
    assert!(
        says(&banner, "fabricctl") || says(&banner, "RotateKey"),
        "the banner must keep saying that MANUAL rotation (fabricctl / Admin.RotateKey) \
         still works. `None` disables the SCHEDULE only — an operator who reads this line \
         while responding to a suspected key compromise must not conclude that rotation is \
         unavailable to them. Got:\n{banner}"
    );
    assert!(
        says(&banner, "in flight") || says(&banner, "in-flight") || says(&banner, "already"),
        "the banner must keep saying that rotations already underway still complete (the \
         decision sweep keeps running — see rotation_disabled.rs's \
         sweep_still_drives_in_flight_rotations_with_the_timer_disabled). Losing that \
         sentence would make the disabled state look like it strands whatever was in \
         progress, which is exactly the fear that would push an operator into re-enabling \
         the timer. Got:\n{banner}"
    );
}

/// The printed banner and the returned string must be the same text: exposing
/// the text for testing is only worth anything if `serve`'s boot output is
/// built from it.
///
/// This cannot observe stderr from in-process (see the module doc on why
/// spawning the binary is the wrong instrument here), so what it pins instead
/// is the shape that makes divergence impossible — a single multi-line block
/// carrying the binary's own prefix, i.e. the thing the print site can only
/// hand to `eprintln!` whole. A `warn_automatic_rotation_disabled` that kept
/// its own copy of the prose and let this function return a paraphrase would
/// leave every assertion above testing a string no operator ever sees.
#[test]
fn banner_is_the_text_the_boot_path_prints() {
    let banner = automatic_rotation_disabled_banner();
    assert!(
        banner.contains("wiremesh-controller:"),
        "the banner must carry the `wiremesh-controller:` line prefix the boot output uses, \
         so that what this test reads is literally what `warn_automatic_rotation_disabled` \
         hands to `eprintln!` — not a second, parallel wording that could drift from it. \
         Got:\n{banner}"
    );
    assert!(
        banner.lines().count() > 1,
        "the banner is a multi-line block (the boxed WARNING header plus the explanation); \
         a single line means the print site is composing the real thing from pieces this \
         function does not have, which is the drift this accessor exists to prevent. \
         Got:\n{banner}"
    );
}

// ---------------------------------------------------------------------------
// That the banner is EMITTED — see the module doc's second section.
// ---------------------------------------------------------------------------

/// A controller booted with rotation DISABLED emits the banner, at every boot;
/// one booted with rotation ARMED emits nothing.
///
/// The scenario this closes: delete the `warn_automatic_rotation_disabled()`
/// call in `serve`'s `None` arm, or replace it with a different `eprintln!`.
/// Every other test in this file goes on passing — they call the formatter —
/// and so does `rotation_disabled.rs`, whose accessor reads
/// `rotation_timer_join.is_none()` and is true whether or not anything was
/// said. The fabric would then have automatic rotation permanently off with
/// nothing at all announcing it, on a binary with no metrics endpoint to
/// publish it on instead.
///
/// Both directions are asserted, against two controllers differing only in
/// this setting, so an accessor stubbed to a constant cannot pass — the same
/// shape `disabled_state_is_observable_and_survives_restart` uses in
/// `rotation_disabled.rs`. The armed direction is not merely symmetry: a
/// controller that DOES rotate on a schedule must never print a block warning
/// that it does not, which would be a worse lie than silence.
///
/// The restart matters on its own. A restart is the one moment a controller
/// could change this state with nobody watching the console, and it is
/// precisely what an operator does after editing the interval — a banner that
/// fires only on the process's first-ever boot would be absent from exactly
/// the boot they are watching.
///
/// **Testkit requirement:** `RunningController::rotation_disabled_banner()` is
/// reached here through a one-line `TestController` passthrough, the same
/// shape as the existing `TestController::automatic_rotation_disabled()`
/// (`wiremesh-testkit/src/lib.rs`), because `TestController::running()` is
/// private:
///
/// ```ignore
/// pub fn rotation_disabled_banner(&self) -> Option<&str> {
///     self.running().rotation_disabled_banner()
/// }
/// ```
#[tokio::test]
async fn emitted_banner_survives_a_boot_and_a_restart() {
    // ARMED first, and at an interval long enough that the timer never fires
    // during the test: what is asserted is how the controller was CONFIGURED,
    // not whether a rotation has happened to occur yet.
    let enabled = wiremesh_testkit::TestController::start_with_rotation_intervals(
        Some(Duration::from_secs(3600)),
        Duration::from_millis(500),
    )
    .await;
    assert_eq!(
        enabled.rotation_disabled_banner(),
        None,
        "a controller booted with rotation_interval = Some(1h) has a live \
         rotation-initiation timer and must print NO disabled-rotation banner. Printing one \
         would tell an operator their fabric is unprotected when it is not — and it would \
         let a constant-returning accessor satisfy the disabled case below, which is the \
         whole reason this direction is asserted at all. Got: {:?}",
        enabled.rotation_disabled_banner()
    );
    drop(enabled);

    // DISABLED.
    let mut h = wiremesh_testkit::TestController::start_with_rotation_intervals(
        None,
        Duration::from_millis(500),
    )
    .await;
    let want = automatic_rotation_disabled_banner();
    assert_eq!(
        h.rotation_disabled_banner(),
        Some(want.as_str()),
        "a controller booted with rotation_interval = None must have PRINTED the \
         disabled-rotation banner, and printed exactly what automatic_rotation_disabled_banner() \
         returns — the recorded value is the print site's own return, so `None` here means \
         the call in serve's None arm is gone and the binary now runs with automatic \
         rotation off and says nothing about it, while every other test in this file stays \
         green. A DIFFERENT string here means the print site grew a second wording, so every \
         assertion above is testing prose no operator ever sees. Got: {:?}",
        h.rotation_disabled_banner()
    );

    h.restart().await;
    assert_eq!(
        h.rotation_disabled_banner(),
        Some(want.as_str()),
        "a RESTARTED controller must print the banner again — it is emitted per boot, not \
         once per process lifetime. The restart is the boot an operator is most likely to be \
         watching (it is what they do after editing the interval), and it is the one moment \
         this state could change unobserved. Got: {:?}",
        h.rotation_disabled_banner()
    );
}
