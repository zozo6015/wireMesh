//! FAILING tests (test-author cycle 2026-07-28) for `wiremesh-operator`'s
//! `-h`/`--help` and `-V`/`--version` handling (plan
//! `docs/superpowers/plans/2026-07-28-cli-help-version.md`).
//!
//! The operator dispatches `operator-admin <op>` and `idle` subcommands off
//! argv before starting the reconciler loop; help/version MUST intercept
//! before that dispatch, and the manual must name those subcommands.
//!
//! # Pure surface required from the implementer
//!
//! Interception lives in the `wiremesh_operator` library (integration tests
//! cannot link `main.rs`); `main.rs` calls it at the very top of `main`,
//! before the `operator-admin`/`idle` match:
//!
//! ```ignore
//! pub mod cli {
//!     pub enum CliAction { Help(String), Version(String), Run }
//!     /// Takes a `std::env::args()`-shaped iterator (skips argv[0] itself).
//!     pub fn cli_action(args: impl Iterator<Item = String>) -> CliAction;
//! }
//! ```
//!
//! `env!("CARGO_PKG_VERSION")` is the operator crate version. Until `cli`
//! exists this file FAILS TO COMPILE — the intended RED.

use wiremesh_operator::cli::{cli_action, CliAction};

fn argv(tokens: &[&str]) -> impl Iterator<Item = String> {
    tokens
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
        .into_iter()
}

#[test]
fn long_version_flag_yields_crate_version() {
    match cli_action(argv(&["wiremesh-operator", "--version"])) {
        CliAction::Version(s) => {
            assert!(
                s.contains(env!("CARGO_PKG_VERSION")),
                "version output must contain CARGO_PKG_VERSION {:?}, got {s:?}",
                env!("CARGO_PKG_VERSION")
            );
            assert!(
                s.contains("wiremesh-operator"),
                "version line names the binary, got {s:?}"
            );
        }
        other => panic!("--version must yield Version, got {:?}", ActionDbg(&other)),
    }
}

#[test]
fn short_version_flag_yields_crate_version() {
    match cli_action(argv(&["wiremesh-operator", "-V"])) {
        CliAction::Version(s) => assert!(s.contains(env!("CARGO_PKG_VERSION"))),
        other => panic!("-V must yield Version, got {:?}", ActionDbg(&other)),
    }
}

#[test]
fn long_help_flag_names_subcommands() {
    match cli_action(argv(&["wiremesh-operator", "--help"])) {
        CliAction::Help(m) => assert_manual(&m),
        other => panic!("--help must yield Help, got {:?}", ActionDbg(&other)),
    }
}

#[test]
fn short_help_flag_names_subcommands() {
    match cli_action(argv(&["wiremesh-operator", "-h"])) {
        CliAction::Help(m) => assert_manual(&m),
        other => panic!("-h must yield Help, got {:?}", ActionDbg(&other)),
    }
}

/// Neither help nor version → `Run`, so the `operator-admin`/`idle`/reconciler
/// dispatch is unaffected.
#[test]
fn subcommand_args_yield_run() {
    assert!(matches!(
        cli_action(argv(&["wiremesh-operator", "idle"])),
        CliAction::Run
    ));
    assert!(
        matches!(
            cli_action(argv(&[
                "wiremesh-operator",
                "operator-admin",
                "list-gateways"
            ])),
            CliAction::Run
        ),
        "operator-admin dispatch must still reach Run"
    );
}

fn assert_manual(m: &str) {
    assert!(!m.trim().is_empty(), "help manual must be non-empty");
    for needle in ["idle", "operator-admin"] {
        assert!(
            m.contains(needle),
            "operator manual must name the {needle:?} subcommand; got:\n{m}"
        );
    }
}

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
