//! FAILING tests (test-author cycle 2026-07-28) for `wiremesh-controller`'s
//! `-h`/`--help` and `-V`/`--version` handling (plan
//! `docs/superpowers/plans/2026-07-28-cli-help-version.md`).
//!
//! The controller binary is configured purely by environment variables (no
//! flags today), but it must STILL answer help/version for live-deployment
//! diagnostics — and its manual must document the env-var mechanism.
//!
//! # Pure surface required from the implementer
//!
//! Integration tests link only the `wiremesh_controller` library, so the
//! interception lives there and `main.rs` calls it at the very top of `main`,
//! before it reads any `WIREMESH_*` var or calls `serve`:
//!
//! ```ignore
//! pub mod cli {
//!     pub enum CliAction { Help(String), Version(String), Run }
//!     /// Takes a `std::env::args()`-shaped iterator (skips argv[0] itself).
//!     pub fn cli_action(args: impl Iterator<Item = String>) -> CliAction;
//! }
//! ```
//!
//! `env!("CARGO_PKG_VERSION")` here is the controller crate version (lib and
//! bin are the same crate). Until `cli` exists this file FAILS TO COMPILE —
//! the intended RED.

use wiremesh_controller::cli::{cli_action, CliAction};

fn argv(tokens: &[&str]) -> impl Iterator<Item = String> {
    tokens.iter().map(|s| s.to_string()).collect::<Vec<_>>().into_iter()
}

#[test]
fn long_version_flag_yields_crate_version() {
    match cli_action(argv(&["wiremesh-controller", "--version"])) {
        CliAction::Version(s) => {
            assert!(
                s.contains(env!("CARGO_PKG_VERSION")),
                "version output must contain CARGO_PKG_VERSION {:?}, got {s:?}",
                env!("CARGO_PKG_VERSION")
            );
            assert!(s.contains("wiremesh-controller"), "version line names the binary, got {s:?}");
        }
        other => panic!("--version must yield Version, got {:?}", ActionDbg(&other)),
    }
}

#[test]
fn short_version_flag_yields_crate_version() {
    match cli_action(argv(&["wiremesh-controller", "-V"])) {
        CliAction::Version(s) => assert!(s.contains(env!("CARGO_PKG_VERSION"))),
        other => panic!("-V must yield Version, got {:?}", ActionDbg(&other)),
    }
}

#[test]
fn long_help_flag_documents_env_config() {
    match cli_action(argv(&["wiremesh-controller", "--help"])) {
        CliAction::Help(m) => assert_manual(&m),
        other => panic!("--help must yield Help, got {:?}", ActionDbg(&other)),
    }
}

#[test]
fn short_help_flag_documents_env_config() {
    match cli_action(argv(&["wiremesh-controller", "-h"])) {
        CliAction::Help(m) => assert_manual(&m),
        other => panic!("-h must yield Help, got {:?}", ActionDbg(&other)),
    }
}

/// With neither help nor version, the action is `Run` so the normal env-driven
/// boot proceeds unchanged.
#[test]
fn plain_args_yield_run() {
    assert!(matches!(cli_action(argv(&["wiremesh-controller"])), CliAction::Run));
}

fn assert_manual(m: &str) {
    assert!(!m.trim().is_empty(), "help manual must be non-empty");
    // The controller is env-configured; the manual must document the real
    // WIREMESH_* variables an operator sets (the env-file mechanism note).
    for needle in ["WIREMESH_DATA_DIR", "WIREMESH_SYNC_TCP_PORT", "WIREMESH_BIND_IP"] {
        assert!(m.contains(needle), "controller manual must document {needle:?}; got:\n{m}");
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
