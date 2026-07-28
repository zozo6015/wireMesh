//! FAILING test (test-author cycle 2026-07-28) for the `wiremesh-relay-enroll`
//! binary's `-h`/`--help` and `-V`/`--version` handling (plan
//! `docs/superpowers/plans/2026-07-28-cli-help-version.md`).
//!
//! `wiremesh-relay-enroll` (`crates/wiremesh-relay/src/bin/enroll.rs`) is a
//! thin wrapper over `wiremesh_relay::enroll::parse_args`. The help/version
//! interception belongs beside that parser so the bin can call it before
//! `parse_args`' required-flag validation runs.
//!
//! # Pure surface required from the implementer
//!
//! ```ignore
//! // in `wiremesh_relay::enroll`
//! pub enum CliAction { Help(String), Version(String), Run }
//! /// Takes the args iterator positioned at argv[1..] (as the bin already
//! /// hands `std::env::args().skip(1)` to `parse_args`).
//! pub fn cli_action(args: impl Iterator<Item = String>) -> CliAction;
//! ```
//!
//! NOTE the argv convention: the bin does `std::env::args().skip(1)` before
//! calling into `enroll`, so `cli_action` receives tokens WITHOUT argv[0] —
//! matching `parse_args`. `env!("CARGO_PKG_VERSION")` is the `wiremesh-relay`
//! crate version (the enroll bin lives in that crate). Until `cli_action`
//! exists this file FAILS TO COMPILE — the intended RED.

use wiremesh_relay::enroll::{cli_action, CliAction};

fn argv(tokens: &[&str]) -> impl Iterator<Item = String> {
    tokens.iter().map(|s| s.to_string()).collect::<Vec<_>>().into_iter()
}

#[test]
fn version_flags_yield_crate_version() {
    for flag in ["--version", "-V"] {
        match cli_action(argv(&[flag])) {
            CliAction::Version(s) => {
                assert!(
                    s.contains(env!("CARGO_PKG_VERSION")),
                    "{flag} output must contain CARGO_PKG_VERSION {:?}, got {s:?}",
                    env!("CARGO_PKG_VERSION")
                );
                assert!(s.contains("wiremesh-relay-enroll"), "version line names the binary, got {s:?}");
            }
            other => panic!("{flag} must yield Version, got {:?}", ActionDbg(&other)),
        }
    }
}

#[test]
fn help_flags_yield_full_manual() {
    for flag in ["--help", "-h"] {
        match cli_action(argv(&[flag])) {
            CliAction::Help(m) => {
                assert!(!m.trim().is_empty(), "help manual must be non-empty");
                for needle in ["--token", "--controller", "--ca", "--certdir", "--endpoint"] {
                    assert!(m.contains(needle), "relay-enroll manual must mention {needle:?}; got:\n{m}");
                }
            }
            other => panic!("{flag} must yield Help, got {:?}", ActionDbg(&other)),
        }
    }
}

/// A normal enroll invocation (no help/version) yields `Run`, leaving
/// `parse_args`' behavior unchanged.
#[test]
fn normal_args_yield_run() {
    assert!(
        matches!(cli_action(argv(&["--token", "t", "--controller", "c:1"])), CliAction::Run),
        "non-help/version argv must yield Run so parse_args still handles it"
    );
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
