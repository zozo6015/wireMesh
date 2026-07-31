//! Contract pins for the SHARED boot-time dial-target check
//! `wiremesh_enroll::validate_host_port` — the one function behind the
//! gateway's `--controller-sync`/`--observe` parsing and the relay bin's
//! `--controller` value parser (re-exported as
//! `wiremesh_gateway::config::validate_host_port` and
//! `wiremesh_relay::validate_host_port`). Backlog 2 (Sync keepalive
//! mirrors); regression pins, GREEN from day one — this crate is the
//! canonical home of the contract now that both consumers share it.
//!
//! The contract (see the function's doc comment):
//!  - syntax-only: NO DNS — a currently-unresolvable hostname must still
//!    pass, because gateways/relays boot fail-static with the controller
//!    (and possibly the resolver) unreachable;
//!  - split on the LAST `:`; non-empty host; valid non-zero u16 port
//!    (port 0 is the OS's ephemeral-BIND wildcard, never dialable);
//!  - IPv6 dial targets rejected (v1 is IPv4-only end to end);
//!  - an IPv4-shaped host (digits/dots only — an all-numeric TLD can never
//!    be a legal DNS name) must make the whole input parse as a
//!    `SocketAddr`, so a typo'd literal like `10.0.0.300:9500` fails at
//!    boot instead of logging resolution failures forever;
//!  - every rejection names the offending input (operators diagnose from
//!    the one log/usage line).
//! ./dev.sh run "cargo test -p wiremesh-enroll --test validate_host_port -- --test-threads=1 --nocapture"

use wiremesh_enroll::validate_host_port;

/// Rejection helper: must error AND the error chain must name the input,
/// plus carry the case's reason fragment.
fn assert_rejects(input: &str, reason_fragment: &str) {
    let err = validate_host_port(input)
        .expect_err(&format!("{input:?} must be rejected ({reason_fragment})"));
    let chain = format!("{err:#}");
    assert!(
        chain.contains(input),
        "rejection of {input:?} must name the input, got: {chain}"
    );
    assert!(
        chain.contains(reason_fragment),
        "rejection of {input:?} must carry the reason fragment {reason_fragment:?}, got: {chain}"
    );
}

/// The accept set: hostnames (including never-resolvable ones — syntax
/// only, no DNS), IPv4 literals, and the full valid port range.
#[test]
fn accepts_hostnames_and_ipv4_literals_without_dns() {
    for input in [
        "ctrl.example.com:9500",
        // RFC-2606-reserved: guaranteed to never resolve — passing proves
        // the check does no DNS (fail-static boot requirement).
        "never-resolvable.invalid:9500",
        "localhost:9500",
        "host-with-dash.example:1",
        "127.0.0.1:9500",
        "192.0.2.1:65535",
    ] {
        validate_host_port(input)
            .unwrap_or_else(|e| panic!("{input:?} must pass boot-time validation, got: {e:#}"));
    }
}

/// Malformed shapes: no port separator, empty host, non-numeric and
/// out-of-range ports.
#[test]
fn rejects_malformed_host_port_shapes() {
    assert_rejects("ctrl.example.com", "expected host:port");
    assert_rejects(":9500", "empty host");
    assert_rejects("ctrl.example.com:notaport", "invalid port");
    assert_rejects("ctrl.example.com:70000", "invalid port");
}

/// Port 0 is the OS's "assign me an ephemeral port" wildcard for BINDS —
/// never a dialable destination — so it can only ever fail at every dial:
/// rejected at boot instead. Pinned here for BOTH consumers (the gateway's
/// own config pins live in its src-side unit tests; this is the shared
/// contract's canonical pin).
#[test]
fn rejects_port_zero_as_not_dialable() {
    assert_rejects("ctrl.example.com:0", "port 0");
    assert_rejects("ctrl.example.com:0", "not a dialable target");
    assert_rejects("127.0.0.1:0", "not a dialable target");
}

/// v1 is IPv4-only end to end: IPv6 dial targets — bracketed, or an
/// unbracketed host that parses as an IPv6 address — are rejected at boot,
/// not left to fail at every dial.
#[test]
fn rejects_ipv6_dial_targets() {
    assert_rejects("[::1]:9500", "IPv6 dial target");
    assert_rejects("[2001:db8::1]:9500", "IPv6 dial target");
    // Unbracketed: the last-`:` split leaves host "::1", which parses as an
    // IPv6 IpAddr and must be caught by the same rule.
    assert_rejects("::1:9500", "IPv6 dial target");
}

/// An IPv4-shaped host (digits and dots only) can never be a legal DNS
/// name, so it must parse as a real `SocketAddr` — a typo'd literal fails
/// at boot rather than being waved through as a "hostname" that resolves
/// nowhere forever.
#[test]
fn rejects_typoed_ipv4_shaped_literals() {
    assert_rejects("10.0.0.300:9500", "invalid IP literal");
    assert_rejects("999.1.2.3:9500", "invalid IP literal");
    assert_rejects("10.0.0.1.5:9500", "invalid IP literal");
}
