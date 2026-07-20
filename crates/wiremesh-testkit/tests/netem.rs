//! Cycle-4b Task 6: the `tc netem` latency knob on `Lab::nat_router_delayed`.
//!
//! Phase-0 Finding 2: a zero-latency veth lab lets a peer's inbound PING
//! arrive before the local side's own outbound packet has crossed its NAT,
//! poisoning conntrack and producing a FALSE punch-failure for ~30s. Any
//! Cycle-4b hole-punch test MUST give its NAT router(s) a delay like this
//! (~20ms, ≈40ms one-way) instead of a bare zero-latency link. This test
//! only exercises the harness knob itself — no actual hole punching —
//! asserting:
//!  1. `nat_router_delayed` gives the router a `netem` qdisc (with the
//!     requested delay) reachable on its outside interface (`out0`), and
//!  2. the plain `nat_router` (unchanged, back-compat) does NOT — it never
//!     wires `out0` at all (that's the caller's job via `Lab::veth`), so
//!     `netem_present` must report `false` rather than erroring.
//!
//! Run: `./dev.sh run "cargo test -p wiremesh-testkit --features netns \
//! --test netem -- --test-threads=1 --nocapture"`.
#![cfg(feature = "netns")]

use wiremesh_testkit::netns::{assert_netem_present, netem_present, Lab, NatKind};

#[test]
fn nat_router_delayed_installs_netem_on_out0() {
    let mut lab = Lab::new("aethnetem").unwrap();
    let router = lab
        .nat_router_delayed("r", NatKind::PortRestricted, 20)
        .unwrap();

    let out = router.exec(&["tc", "qdisc", "show", "dev", "out0"]).unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    println!("tc qdisc show dev out0: {text}");
    assert!(text.contains("netem"), "expected netem qdisc, got: {text}");
    assert!(
        text.contains("delay 20ms") || text.contains("delay 20.0ms"),
        "expected 20ms delay, got: {text}"
    );

    // Same assertions via the public helpers a punch test is meant to use.
    assert_netem_present(&router, "out0");
    assert!(netem_present(&router, "out0").unwrap());
}

#[test]
fn plain_nat_router_has_no_netem_back_compat() {
    let mut lab = Lab::new("aethnetem2").unwrap();
    let router = lab.nat_router("r", NatKind::PortRestricted).unwrap();

    // Plain `nat_router` never creates `out0` itself (only the caller's own
    // later `Lab::veth` call would) -- `netem_present` must treat that as
    // "no netem" rather than propagating the underlying "Cannot find
    // device" `tc` error, so a punch test can safety-check any router the
    // same way regardless of whether it happens to be wired yet.
    assert!(
        !netem_present(&router, "out0").unwrap(),
        "plain nat_router must NOT report netem present on out0"
    );
}
