//! Backlog 2 (Sync keepalive mirrors) — boot-time guard on the relay bin's
//! `--controller` dial target.
//!
//! `--controller` changed from a clap `SocketAddr` to a `host:port` String
//! (DDNS hostnames) with `value_parser = validated_host_port` (the shared
//! `wiremesh_relay::validate_host_port`, hosted in `wiremesh-enroll`). These
//! tests pin the CLI-level contract — regression pins, GREEN from day one:
//!
//!  - a hostname:port target PARSES (no DNS at boot — an unresolvable name
//!    must still boot, fail-static; resolution is per-dial inside
//!    `run_sync`), so the process gets past clap and fails later on the
//!    missing relay identity instead;
//!  - an IPv6 literal, a typo'd IPv4-shaped literal (`10.0.0.300:9500`),
//!    and `host:0` each exit non-zero AT PARSE (clap usage error naming the
//!    offending input) — never a process that runs forever logging dial
//!    failures.
//!
//! Spawned-binary tests (`env!("CARGO_BIN_EXE_relay")`), same pattern and
//! rationale as `tests/relay_bin_cli.rs`: clap's parse rejection exits the
//! process, so there is no pure in-process surface to drive. The
//! function-level contract (every accept/reject case incl. port 0) is
//! pinned in `wiremesh-enroll/tests/validate_host_port.rs`; this file pins
//! that the relay bin actually WIRES that check into `--controller`.
//! ./dev.sh run "cargo test -p wiremesh-relay --test relay_bin_controller_arg -- --test-threads=1 --nocapture"

use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_relay"))
        .args(args)
        .output()
        .expect("spawning the built relay binary")
}

/// A rejected `--controller` value must be a CLAP parse error: non-zero
/// exit, stderr naming both the flag and the offending input, plus the
/// shared validator's reason fragment — and it must fail BEFORE the boot
/// path (no denylist/cert activity).
fn assert_parse_rejection(target: &str, reason_fragment: &str) {
    // The bind positional is valid so the ONLY failure candidate is the
    // --controller value parser.
    let out = run(&["127.0.0.1:0", "--controller", target]);
    assert!(
        !out.status.success(),
        "--controller {target} must exit non-zero at parse, got {:?}",
        out.status
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--controller"),
        "--controller {target}: rejection must be a clap usage error naming the flag, \
         got stderr: {stderr}"
    );
    assert!(
        stderr.contains(target),
        "--controller {target}: the error must name the offending input, got stderr: {stderr}"
    );
    assert!(
        stderr.contains(reason_fragment),
        "--controller {target}: the error must carry the validator's reason \
         ({reason_fragment:?}), got stderr: {stderr}"
    );
    assert!(
        !stderr.contains("loaded denylist"),
        "--controller {target}: a parse rejection must exit before the boot path runs \
         (no denylist load), got stderr: {stderr}"
    );
}

/// The DDNS shape the flag exists for: `hostname:port` must PARSE — with no
/// DNS lookup, so even a never-resolvable name boots (fail-static). Proven
/// by the failure mode: pointed at an empty certdir, the process gets PAST
/// clap (denylist loads, logged to stderr) and dies on the missing relay
/// identity (`relay.pem`) — a boot error, not a usage error.
#[test]
fn controller_hostname_target_parses_without_dns() {
    let dir = tempfile::tempdir().expect("tempdir");
    let certdir = dir.path().to_str().expect("utf-8 tempdir path");

    for target in ["ctrl.example.com:9500", "never-resolvable.invalid:9500"] {
        let out = run(&["127.0.0.1:0", certdir, "--controller", target]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success(),
            "harness expectation: an empty certdir must fail boot (missing relay.pem), \
             got success for --controller {target}"
        );
        assert!(
            !stderr.contains("invalid value"),
            "--controller {target} (hostname, no DNS at boot) must NOT be a clap parse \
             rejection, got stderr: {stderr}"
        );
        assert!(
            stderr.contains("loaded denylist"),
            "--controller {target}: the process must get past clap into the boot path \
             (denylist load logs first), got stderr: {stderr}"
        );
        assert!(
            stderr.contains("relay.pem"),
            "--controller {target}: the eventual failure must be the missing relay \
             identity, not the dial target, got stderr: {stderr}"
        );
    }
}

/// v1 is IPv4-only end to end: an IPv6 dial-target literal can never be
/// reached, so it must exit non-zero at boot instead of failing every dial
/// forever.
#[test]
fn controller_ipv6_literal_is_rejected_at_parse() {
    assert_parse_rejection("[::1]:9500", "IPv6 dial target");
}

/// A typo'd IPv4-shaped literal (all-numeric labels are not a legal DNS
/// name, so it can never be a resolvable hostname either) must exit
/// non-zero at boot — the old `SocketAddr`-typed flag's behavior, kept.
#[test]
fn controller_typoed_ipv4_literal_is_rejected_at_parse() {
    assert_parse_rejection("10.0.0.300:9500", "invalid IP literal");
}

/// Port 0 is the OS's ephemeral-bind wildcard, never a dialable
/// destination: rejected at parse.
#[test]
fn controller_port_zero_is_rejected_at_parse() {
    assert_parse_rejection("ctrl.example.com:0", "not a dialable target");
}
