//! FAILING tests (test-author cycle 2026-07-28) for `wiremesh-gateway`'s
//! `-h`/`--help` and `-V`/`--version` handling — the live-deployment
//! diagnostics feature (plan `docs/superpowers/plans/2026-07-28-cli-help-version.md`).
//!
//! # Pure surface required from the implementer
//!
//! An integration test can only link the crate's *library* (`wiremesh_gateway`),
//! never `main.rs`, so the help/version interception MUST be exposed as a pure
//! library function that `main.rs` then calls at the very top of arg handling
//! (before the `enroll` subcommand dispatch AND before
//! `GatewayConfig::from_env`'s required-flag validation). This test pins that
//! surface as:
//!
//! ```ignore
//! pub mod cli {
//!     /// Pre-parse CLI intent, resolved BEFORE any required-flag validation
//!     /// or subcommand dispatch.
//!     pub enum CliAction {
//!         /// `-h`/`--help` seen: the fully rendered usage manual.
//!         Help(String),
//!         /// `-V`/`--version` seen: the rendered "<bin> <version>" line.
//!         Version(String),
//!         /// Neither: proceed with the normal enroll-vs-run dispatch.
//!         Run,
//!     }
//!     /// Takes a `std::env::args()`-shaped iterator (INCLUDING argv[0], which
//!     /// it skips itself) so `main` calls `cli_action(std::env::args())`.
//!     pub fn cli_action(args: impl Iterator<Item = String>) -> CliAction;
//! }
//! ```
//!
//! `cli_action` is intentionally infallible: help/version detection can never
//! error, which is exactly the "recognized BEFORE required-flag validation"
//! guarantee — `Run` is returned only when neither is present, deferring all
//! fallible parsing to `GatewayConfig::parse`. Because the library and the
//! `wiremesh-gateway` binary are the same crate, `env!("CARGO_PKG_VERSION")`
//! below is the gateway crate version the binary reports.
//!
//! Until that surface exists this file FAILS TO COMPILE — the intended RED.

use wiremesh_gateway::cli::{cli_action, CliAction};

fn argv(tokens: &[&str]) -> impl Iterator<Item = String> {
    tokens.iter().map(|s| s.to_string()).collect::<Vec<_>>().into_iter()
}

/// `--version` (long) yields `Version` whose rendered line carries the crate
/// version — never `Run`, never a panic.
#[test]
fn long_version_flag_yields_version_with_crate_version() {
    match cli_action(argv(&["wiremesh-gateway", "--version"])) {
        CliAction::Version(s) => {
            assert!(
                s.contains(env!("CARGO_PKG_VERSION")),
                "version output must contain CARGO_PKG_VERSION {:?}, got {s:?}",
                env!("CARGO_PKG_VERSION")
            );
            assert!(s.contains("wiremesh-gateway"), "version line names the binary, got {s:?}");
        }
        other => panic!("--version must yield Version, got {:?}", ActionDbg(&other)),
    }
}

/// `-V` (short) behaves identically to `--version`.
#[test]
fn short_version_flag_yields_version() {
    match cli_action(argv(&["wiremesh-gateway", "-V"])) {
        CliAction::Version(s) => assert!(
            s.contains(env!("CARGO_PKG_VERSION")),
            "-V must contain the crate version, got {s:?}"
        ),
        other => panic!("-V must yield Version, got {:?}", ActionDbg(&other)),
    }
}

/// `--help` (alone) yields a non-empty manual naming every top-level flag and
/// the `enroll` subcommand — and does NOT trip required-flag validation.
#[test]
fn long_help_flag_yields_full_manual() {
    match cli_action(argv(&["wiremesh-gateway", "--help"])) {
        CliAction::Help(m) => assert_manual(&m),
        other => panic!("--help must yield Help, got {:?}", ActionDbg(&other)),
    }
}

/// `-h` (short) behaves identically to `--help`.
#[test]
fn short_help_flag_yields_full_manual() {
    match cli_action(argv(&["wiremesh-gateway", "-h"])) {
        CliAction::Help(m) => assert_manual(&m),
        other => panic!("-h must yield Help, got {:?}", ActionDbg(&other)),
    }
}

/// `--help`/`--version` must be recognized even when they appear AFTER other
/// (here otherwise-valid-looking) run flags — "reasonably anywhere", and
/// crucially before the parser would reject anything.
#[test]
fn help_and_version_are_recognized_after_other_flags() {
    match cli_action(argv(&["wiremesh-gateway", "--controller-sync", "c:1", "--help"])) {
        CliAction::Help(m) => assert_manual(&m),
        other => panic!("--help after flags must yield Help, got {:?}", ActionDbg(&other)),
    }
    match cli_action(argv(&["wiremesh-gateway", "--tun", "wg0", "--version"])) {
        CliAction::Version(s) => assert!(s.contains(env!("CARGO_PKG_VERSION"))),
        other => panic!("--version after flags must yield Version, got {:?}", ActionDbg(&other)),
    }
}

/// Sanity: with NO help/version token the action is `Run`, so the normal
/// enroll-vs-run dispatch (and its required-flag validation) is unaffected —
/// the non-regression property the netns milestone depends on.
#[test]
fn plain_run_args_yield_run() {
    assert!(
        matches!(cli_action(argv(&["wiremesh-gateway", "--controller-sync", "c:1"])), CliAction::Run),
        "non-help/version argv must yield Run so normal dispatch proceeds"
    );
    // The `enroll` subcommand path is likewise Run (its own parser handles it).
    assert!(
        matches!(cli_action(argv(&["wiremesh-gateway", "enroll", "--token", "t"])), CliAction::Run),
        "enroll subcommand argv must yield Run"
    );
}

fn assert_manual(m: &str) {
    assert!(!m.trim().is_empty(), "help manual must be non-empty");
    for needle in ["--controller-sync", "--observe", "--tun", "--wg-port", "--state-dir", "enroll"] {
        assert!(m.contains(needle), "help manual must mention {needle:?}; got:\n{m}");
    }
}

/// Tiny debug shim so panics can name the unexpected variant without requiring
/// `CliAction: Debug` from the implementer.
struct ActionDbg<'a>(&'a CliAction);
impl std::fmt::Debug for ActionDbg<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            CliAction::Help(_) => write!(f, "Help(..)"),
            CliAction::Version(_) => write!(f, "Version(..)"),
            CliAction::Run => write!(f, "Run"),
        }
    }
}
