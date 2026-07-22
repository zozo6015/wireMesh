//! Two gateways, two netns, direct WG over veth: prove a handshake + ping.
//! ./dev.sh run "cargo test -p wiremesh-gateway --test tunnel_netns \
//!   --features netns-tests -- --test-threads=1 --nocapture"
//!
//! Uses `join_netns_and_mountns` (not plain `join_netns`): both gateways run
//! an in-process boringtun device named `wg0`, and boringtun's UAPI control
//! socket is keyed by the fixed path `/var/run/wireguard/<ifname>.sock`.
//! Plain `join_netns` only switches the network namespace, so the two
//! same-named devices would bind/connect to the exact same socket file in
//! the container's ambient mount namespace and cross-configure each other
//! (see `join_netns_and_mountns`'s doc comment in wiremesh-testkit).
//!
//! WireGuard's per-peer `allowed_ips` is cryptokey-routing config only (which
//! packets a peer may send/receive over the tunnel) — unlike `wg-quick`,
//! plain `ip link add type wireguard` + raw UAPI `set` (what `Tunnel`/`uapi`
//! do) never touches the kernel routing table. `ip addr add <ip>/24 dev wg0`
//! alone only yields a *connected* route for that side's own /24, not a
//! route to the peer's subnet. A real gateway boot sequence programs that
//! route itself (`routes::add_route`, already used by `routes_netns.rs`);
//! this test does the same for both sides so the ping has an actual path.
#![cfg(feature = "netns-tests")]
use std::time::Duration;
use wiremesh_gateway::routes;
use wiremesh_gateway::state::{DesiredState, PeerState};
use wiremesh_gateway::tunnel::Tunnel;
use wiremesh_gateway::uapi::base64_pub_from_priv; // helper added in Step 3
use wiremesh_testkit::netns::{join_netns_and_mountns, Lab};

fn gen_keypair() -> (String, String) {
    // wg genkey / pubkey via the tool present in the container.
    let priv_b64 = String::from_utf8(std::process::Command::new("wg").arg("genkey").output().unwrap().stdout)
        .unwrap().trim().to_string();
    let pub_b64 = base64_pub_from_priv(&priv_b64).unwrap();
    (priv_b64, pub_b64)
}

#[test]
fn two_gateways_handshake_and_ping_over_direct_wg() {
    let mut lab = Lab::new("gwtun").expect("lab");
    let a = lab.ns("a").unwrap();
    let b = lab.ns("b").unwrap();
    // underlay veth: a=10.9.0.1, b=10.9.0.2
    lab.veth((&a, "u0", "10.9.0.1/24"), (&b, "u0", "10.9.0.2/24")).unwrap();

    let (a_priv, a_pub) = gen_keypair();
    let (b_priv, b_pub) = gen_keypair();

    // Gateway A runs in a thread joined to netns a; B in netns b.
    let b_ns = b.clone();
    let hb = std::thread::spawn(move || {
        join_netns_and_mountns(&b_ns).unwrap();
        let t = Tunnel::up("wg0", &b_priv, 51820, 1280).unwrap();
        // A is B's peer, reachable at 10.9.0.1:51820, segment 10.10.1.0/24
        let ds = DesiredState { peers: vec![PeerState {
            gateway_id: 1, segment_name: "a".into(),
            active_pubkey_b64: Some(a_pub.clone()),
            keys: vec![],
            candidates: vec!["10.9.0.1:51820".into()],
            allowed_ips: vec!["10.10.1.0/24".into(), "10.10.2.2/32".into()],
        }], ..Default::default() };
        t.reconcile(&ds, 15).unwrap();
        std::process::Command::new("ip").args(["addr","add","10.10.2.2/24","dev","wg0"]).status().unwrap();
        routes::add_route("10.10.1.0/24", "wg0").unwrap();
        std::thread::sleep(Duration::from_secs(6));
    });

    join_netns_and_mountns(&a).unwrap();
    let ta = Tunnel::up("wg0", &a_priv, 51820, 1280).unwrap();
    let ds_a = DesiredState { peers: vec![PeerState {
        gateway_id: 2, segment_name: "b".into(),
        active_pubkey_b64: Some(b_pub.clone()),
        keys: vec![],
        candidates: vec!["10.9.0.2:51820".into()],
        allowed_ips: vec!["10.10.2.0/24".into(), "10.10.1.1/32".into()],
    }], ..Default::default() };
    ta.reconcile(&ds_a, 15).unwrap();
    std::process::Command::new("ip").args(["addr","add","10.10.1.1/24","dev","wg0"]).status().unwrap();
    routes::add_route("10.10.2.0/24", "wg0").unwrap();
    std::thread::sleep(Duration::from_secs(2)); // allow handshake

    let ping = std::process::Command::new("ping")
        .args(["-c", "3", "-W", "2", "10.10.2.2"]).output().unwrap();
    assert!(ping.status.success(), "ping over WG tunnel: {}", String::from_utf8_lossy(&ping.stdout));
    hb.join().unwrap();
    drop(lab);
}
