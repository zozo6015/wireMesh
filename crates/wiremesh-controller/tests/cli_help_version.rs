//! Tests for `wiremesh-controller`'s `-h`/`--help` and `-V`/`--version`
//! handling (plan `docs/superpowers/plans/2026-07-28-cli-help-version.md`).
//!
//! The controller binary is configured purely by environment variables (no
//! flags today), but it must still answer help/version for live-deployment
//! diagnostics — and its manual must document the env-var mechanism.
//!
//! # Contract under test
//!
//! Integration tests link only the `wiremesh_controller` library, so the
//! help/version interception lives there and `main.rs` calls it at the very
//! top of `main`, before it reads any `WIREMESH_*` var or calls `serve`:
//!
//! ```ignore
//! pub mod cli {
//!     pub enum CliAction { Help(String), Version(String), Run }
//!     /// Takes a `std::env::args()`-shaped iterator (skips argv[0] itself).
//!     pub fn cli_action(args: impl Iterator<Item = String>) -> CliAction;
//! }
//! ```
//!
//! `cli_action` is infallible: `Help`/`Version` are resolved before any
//! required-flag/env handling, and `Run` (returned only when neither flag is
//! present) defers to the normal env-driven boot. `env!("CARGO_PKG_VERSION")`
//! here is the controller crate version (lib and bin are the same crate).

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

/// The manual is operator-facing documentation shipped INSIDE the binary, so
/// it outlives every README and env-file comment on the host — which makes it
/// the last place a stale promise gets noticed.
///
/// It currently promises `WIREMESH_ROTATION_INTERVAL <interval|off>
/// (optional, default 30d)`, and warns in DEPLOYMENT that a recreated
/// Deployment lands "silently back on the 30d default". After the 2026-08-12
/// contract flip both sentences are false: an absent variable resolves to
/// `Ok(None)` — no rotation-initiation timer at all — so automatic rotation is
/// opt-in and there is no default interval left to fall back to. See
/// `rotation_interval_parse.rs::env_absent_means_no_timer_never_a_default_interval`.
///
/// This is not pedantry about wording. An operator who reads "default 30d"
/// believes their fabric rotates keys on a schedule; after the flip it does
/// not, and the belief is only corrected 30 days after the moment they would
/// have acted on it. The reverse of the bug the flip fixed, and just as quiet.
#[test]
fn help_manual_does_not_promise_a_default_rotation_interval() {
    let CliAction::Help(m) = cli_action(argv(&["wiremesh-controller", "--help"])) else {
        panic!("--help must yield Help");
    };
    let lower = m.to_lowercase();

    for claim in ["default 30d", "30d default"] {
        assert!(
            !lower.contains(claim),
            "the manual claims {claim:?}, but an absent WIREMESH_ROTATION_INTERVAL now \
             resolves to NO timer, not to a 30-day one — automatic rotation is opt-in \
             since 2026-08-12. Documenting a default that does not exist tells an operator \
             their keys rotate on a schedule when nothing is scheduled at all, and they \
             find out 30 days after they stopped thinking about it. Got:\n{m}"
        );
    }

    // ...and the entry must say what unset actually does now. Scoped to the
    // WIREMESH_ROTATION_INTERVAL block (up to the blank line that ends it), so
    // an unrelated "unset" elsewhere in the manual cannot satisfy this.
    let start = m
        .find("WIREMESH_ROTATION_INTERVAL")
        .unwrap_or_else(|| panic!("the manual must document WIREMESH_ROTATION_INTERVAL:\n{m}"));
    let entry = &m[start..];
    let entry = &entry[..entry.find("\n\n").unwrap_or(entry.len())];
    let entry_lower = entry.to_lowercase();
    assert!(
        ["unset", "not set", "no timer", "opt-in", "opt in"]
            .iter()
            .any(|phrase| entry_lower.contains(phrase)),
        "the WIREMESH_ROTATION_INTERVAL entry must state what happens when it is NOT set \
         — no rotation-initiation timer, i.e. automatic rotation is opt-in. Every other \
         entry in this section documents its default in the `(optional, default X)` slot, \
         so an entry that documents nothing there reads as 'unset does something the \
         author forgot to write down'. This entry's answer is that unset does the same \
         thing as `off`. Got:\n{entry}"
    );
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
