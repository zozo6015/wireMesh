// spike/punch/tests/observe.rs
//
// Proves the whole point of Bet 4 part 1 (spec §6.1): a UDP-native
// observation endpoint reports the client's POST-NAT public mapping (the
// NAT router's public ip:port), never the client's private address. TCP
// connection inspection can't show this because NATs map TCP and UDP flows
// independently — this endpoint has to speak UDP itself to observe a UDP
// mapping.
//
// Topology (fresh Lab per test, distinct subnets from spike/natlab's own
// nat_behavior tests so parallel `cargo test` runs across crates never
// collide on veth/nft state):
//
//   c (client, 192.168.60.2/24) --veth-- r::in0 (192.168.60.1/24)
//                                         r (nat_router, PortRestricted)
//                                         r::out0 (203.0.114.1/24) --veth-- s::eth0 (203.0.114.10/24)
//
// `observe` runs in `s` bound to its public-subnet address; `whoami` runs in
// `c` and prints whatever address the server observed. `observe`/`whoami`
// are `[[bin]]` targets of this same crate, so `env!("CARGO_BIN_EXE_...")`
// resolves them directly (unlike spike/natlab's cross-crate examples, which
// need a manual target/debug/examples path).

use natlab::{Lab, NatKind};
use std::process::Child;
use std::time::Duration;

/// The NAT router's public (out0) address — what the server must observe as
/// the client's mapped source if the observation is actually crossing NAT.
const ROUTER_PUBLIC_IP: &str = "203.0.114.1";
/// The client's private address — what the server would report if the
/// observed addr were somehow the pre-NAT source instead (the bug this test
/// exists to catch).
const CLIENT_PRIVATE_ADDR: &str = "192.168.60.2";

/// Kills `child` on drop (including on panic-driven unwind), so a failed
/// assertion never leaks a long-lived `observe` server process into the
/// dev container background — `observe` loops forever, unlike natlab's
/// self-terminating `udpsink` example.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn observation_reports_nat_mapping_not_local_addr() {
    let mut lab = Lab::new("obs").unwrap();
    let c = lab.ns("c").unwrap();
    let r = lab.nat_router("r", NatKind::PortRestricted).unwrap();
    let s = lab.ns("s").unwrap();
    lab.veth(
        (&c, "eth0", &format!("{CLIENT_PRIVATE_ADDR}/24")),
        (&r, "in0", "192.168.60.1/24"),
    )
    .unwrap();
    lab.veth(
        (&r, "out0", &format!("{ROUTER_PUBLIC_IP}/24")),
        (&s, "eth0", "203.0.114.10/24"),
    )
    .unwrap();
    c.exec(&["ip", "route", "add", "default", "via", "192.168.60.1"])
        .unwrap();

    let server = s
        .spawn(&[env!("CARGO_BIN_EXE_observe"), "203.0.114.10:7777"])
        .unwrap();
    let _server_guard = KillOnDrop(server);
    // Let the server finish binding before the client's first probe.
    std::thread::sleep(Duration::from_millis(300));

    let out = c
        .exec(&[env!("CARGO_BIN_EXE_whoami"), "203.0.114.10:7777", "6001"])
        .unwrap();
    assert!(
        out.status.success(),
        "whoami exited non-zero (status {:?}): stdout={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let observed = String::from_utf8_lossy(&out.stdout);
    eprintln!("observed addr: {observed}");

    assert!(
        observed.starts_with(&format!("{ROUTER_PUBLIC_IP}:")),
        "observed addr should be the NAT router's public ip ({ROUTER_PUBLIC_IP}:<port>), got {observed:?}"
    );
    assert!(
        !observed.contains(CLIENT_PRIVATE_ADDR),
        "observed addr must not leak the client's private address {CLIENT_PRIVATE_ADDR}, got {observed:?}"
    );
}
