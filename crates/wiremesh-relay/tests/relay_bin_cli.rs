//! Guard tests (test-author cycle 2026-07-28) for the clap-based `relay`
//! binary's `--version`/`--help` (plan
//! `docs/superpowers/plans/2026-07-28-cli-help-version.md`).
//!
//! `relay` uses `#[derive(clap::Parser)]` with `#[command(version, ...)]` on
//! its `Args`. clap only emits `--version`/`-V` when a `version` attribute is
//! present, so `version_flag_*` guards that attribute against being dropped;
//! `--help`/`-h` is clap-built-in, and `help_flag_*` guards it against
//! regressing.
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
