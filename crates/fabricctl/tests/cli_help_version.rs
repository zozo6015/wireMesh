//! Guard tests (test-author cycle 2026-07-28) for the clap-based `fabricctl`
//! binary's `--version`/`--help` (plan
//! `docs/superpowers/plans/2026-07-28-cli-help-version.md`).
//!
//! `fabricctl`'s top-level `Cli` derives `clap::Parser` with
//! `#[command(name = "fabricctl", version, about = "...")]`. clap only emits
//! `--version`/`-V` when a `version` attribute is present, so
//! `version_flag_prints_crate_version` guards that attribute against being
//! dropped; `help_flag_prints_nonempty_usage` guards clap's built-in
//! `--help`/`-h` against regressing.
//!
//! Spawned-binary tests (`env!("CARGO_BIN_EXE_fabricctl")`) — clap exits the
//! process for `--help`/`--version`, so there is no pure surface. `fabricctl`
//! is its own crate, so `CARGO_PKG_VERSION` here is fabricctl's version.

use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_fabricctl"))
        .args(args)
        .output()
        .expect("spawning the built fabricctl binary")
}

#[test]
fn version_flag_prints_crate_version() {
    for flag in ["--version", "-V"] {
        let out = run(&[flag]);
        assert!(
            out.status.success(),
            "{flag} must exit 0, got {:?}\nstderr: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
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
        assert!(
            out.status.success(),
            "{flag} must exit 0, got {:?}",
            out.status
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(!stdout.trim().is_empty(), "{flag} stdout must be non-empty");
        assert!(
            stdout.to_lowercase().contains("usage"),
            "{flag} must render a usage line, got {stdout:?}"
        );
    }
}
