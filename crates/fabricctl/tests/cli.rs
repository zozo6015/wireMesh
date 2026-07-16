//! Task 13's failing test: drives the BUILT `fabricctl` binary (not a library
//! call) against a `TestController`'s Unix socket end-to-end — `segment
//! create` followed by `segment list` must round-trip through the real CLI
//! process, its arg parsing, its UDS transport, and the controller's Admin
//! service.
//!
//! `env!("CARGO_BIN_EXE_fabricctl")` resolves to the path of this crate's own
//! `fabricctl` binary target once one exists — Cargo sets that env var for
//! every integration test in a crate that has a matching `[[bin]]` (here,
//! the auto-discovered `src/main.rs`). Today there is no `src/main.rs` (only
//! an empty `src/lib.rs`), so this crate produces no `fabricctl` binary at
//! all and `CARGO_BIN_EXE_fabricctl` is never set — that makes `env!` fail
//! AT COMPILE TIME with "environment variable not defined", so this file does
//! not even COMPILE yet. That's the expected RED state for this step. The
//! implementer adds `crates/fabricctl/src/main.rs` (clap, `segment
//! {create,list,rm}` / `gateway {list,drain}` / `relay {register,list}` /
//! `token {mint,revoke}` / `audit query` / `status` subcommands, `--socket`
//! UDS transport, `--token` TCP+bearer transport) to turn this green.
use std::process::{Command, Output};

/// Runs the built `fabricctl` binary with `args`, returning its captured
/// output (status/stdout/stderr) — a thin `std::process::Command` wrapper,
/// not an async call: the binary itself does whatever async work it needs
/// internally and exits, so the test only needs to wait on the child
/// process, not drive an executor.
fn run_fabricctl(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fabricctl"))
        .args(args)
        .output()
        .expect("spawning the built fabricctl binary")
}

#[tokio::test]
async fn fabricctl_creates_and_lists_segments_over_uds() {
    let h = wiremesh_testkit::TestController::start().await;
    let socket = h
        .socket_path()
        .to_str()
        .expect("TestController socket path must be valid UTF-8")
        .to_string();

    let create = run_fabricctl(&[
        "--socket",
        &socket,
        "segment",
        "create",
        "aws",
        "--cidr",
        "10.0.0.0/16",
    ]);
    assert!(
        create.status.success(),
        "fabricctl segment create must succeed, stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&create.stdout),
        String::from_utf8_lossy(&create.stderr)
    );

    let list = run_fabricctl(&["--socket", &socket, "segment", "list"]);
    assert!(
        list.status.success(),
        "fabricctl segment list must succeed, stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&list.stdout),
        String::from_utf8_lossy(&list.stderr)
    );
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert!(
        stdout.contains("aws"),
        "expected fabricctl segment list's stdout to contain the created segment \"aws\", got: {stdout}"
    );
}
