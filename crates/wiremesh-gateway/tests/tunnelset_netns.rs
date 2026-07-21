//! Two simultaneous boringtun Devices (two epochs) coexisting in one netns,
//! each with a distinct ifname/UAPI socket/listen-port/keypair, then tearing
//! one down without disturbing the other.
//! ./dev.sh run "cargo test -p wiremesh-gateway --test tunnelset_netns \
//!   --features netns-tests -- --test-threads=1 --nocapture"
//!
//! Model: `tunnel_netns.rs` (join_netns_and_mountns + wg genkey via
//! base64_pub_from_priv). Only one netns is needed here (unlike
//! tunnel_netns's two-namespace veth setup) because the property under test
//! is "two Devices in the SAME namespace don't collide" — distinct ifnames
//! give distinct `/var/run/wireguard/<ifname>.sock` UAPI sockets, so no
//! mount-namespace juggling across two peers is required.
#![cfg(feature = "netns-tests")]
use std::process::Command;
use wiremesh_gateway::routes;
use wiremesh_gateway::tunnelset::TunnelSet;
use wiremesh_gateway::uapi::base64_pub_from_priv;
use wiremesh_testkit::netns::{join_netns_and_mountns, Lab};

fn gen_keypair() -> (String, String) {
    // wg genkey / pubkey via the tool present in the container.
    let priv_b64 = String::from_utf8(std::process::Command::new("wg").arg("genkey").output().unwrap().stdout)
        .unwrap().trim().to_string();
    let pub_b64 = base64_pub_from_priv(&priv_b64).unwrap();
    (priv_b64, pub_b64)
}

#[test]
fn two_epoch_tunnels_coexist_and_tear_down() {
    let mut lab = Lab::new("tunset").unwrap();
    let a = lab.ns("a").unwrap();
    join_netns_and_mountns(&a).unwrap();

    let (k0_priv, k0_pub) = gen_keypair();
    let (k1_priv, k1_pub) = gen_keypair();

    let mut set = TunnelSet::new();
    set.bring_up(0, "wge0", &k0_priv, 51820, 1280).unwrap();
    set.bring_up(1, "wge1", &k1_priv, 51821, 1280).unwrap();

    assert_eq!(set.epochs(), vec![0, 1]);

    let show0 = Command::new("wg").args(["show", "wge0"]).output().unwrap();
    assert!(show0.status.success(), "wg show wge0 failed: {}", String::from_utf8_lossy(&show0.stderr));
    let show0_text = String::from_utf8_lossy(&show0.stdout);
    assert!(show0_text.contains("listening port: 51820"), "wge0 output missing expected port: {show0_text}");
    assert!(show0_text.contains(&k0_pub), "wge0 output missing expected pubkey: {show0_text}");

    let show1 = Command::new("wg").args(["show", "wge1"]).output().unwrap();
    assert!(show1.status.success(), "wg show wge1 failed: {}", String::from_utf8_lossy(&show1.stderr));
    let show1_text = String::from_utf8_lossy(&show1.stdout);
    assert!(show1_text.contains("listening port: 51821"), "wge1 output missing expected port: {show1_text}");
    assert!(show1_text.contains(&k1_pub), "wge1 output missing expected pubkey: {show1_text}");

    routes::add_route("10.30.0.0/24", "wge0").unwrap();
    routes::add_route("10.31.0.0/24", "wge1").unwrap();

    set.tear_down(1).unwrap();
    assert_eq!(set.epochs(), vec![0]);
    assert!(
        !Command::new("ip").args(["link", "show", "wge1"]).status().unwrap().success(),
        "wge1 should no longer exist after tear_down"
    );

    let show0_after = Command::new("wg").args(["show", "wge0"]).output().unwrap();
    assert!(show0_after.status.success(), "wge0 should still be live after tearing down wge1");

    drop(lab);
}
