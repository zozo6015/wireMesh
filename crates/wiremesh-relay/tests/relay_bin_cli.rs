//! VERIFY-only tests (test-author cycle 2026-07-28) for the clap-based `relay`
//! binary's `--version`/`--help` (plan
//! `docs/superpowers/plans/2026-07-28-cli-help-version.md`).
//!
//! `relay` uses `#[derive(clap::Parser)]`. clap does NOT emit `--version`
//! unless the command carries a `version`/`#[command(version)]` attribute —
//! today `Args` has none, so `--version` currently exits non-zero with an
//! "unexpected argument" error: the `version_flag_*` test below is RED until
//! the implementer adds `#[command(version)]`. `--help` already works in clap,
//! so `help_flag_*` guards against it regressing.
//!
//! These are spawned-binary tests (`env!("CARGO_BIN_EXE_relay")`) because the
//! clap parser exits the process on `--help`/`--version`; there is no pure
//! surface to drive. The binary is named `relay` (see the crate's `[[bin]]`),
//! so its version is the `wiremesh-relay` crate's `CARGO_PKG_VERSION`.

use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_relay"))
        .args(args)
        .output()
        .expect("spawning the built relay binary")
}

#[test]
fn version_flag_prints_crate_version() {
    for flag in ["--version", "-V"] {
        let out = run(&[flag]);
        assert!(out.status.success(), "{flag} must exit 0, got {:?}\nstderr: {}", out.status, String::from_utf8_lossy(&out.stderr));
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains(env!("CARGO_PKG_VERSION")),
            "{flag} stdout must contain the crate version {:?}, got stdout={stdout:?}",
            env!("CARGO_PKG_VERSION")
        );
    }
}

#[test]
fn help_flag_prints_nonempty_usage() {
    for flag in ["--help", "-h"] {
        let out = run(&[flag]);
        assert!(out.status.success(), "{flag} must exit 0, got {:?}", out.status);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(!stdout.trim().is_empty(), "{flag} stdout must be non-empty");
        assert!(stdout.to_lowercase().contains("usage"), "{flag} must render a usage line, got {stdout:?}");
    }
}
