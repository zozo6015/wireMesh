// spike/tunnel/tests/tunnel_ping.rs
mod common;

#[test]
fn wireguard_tunnel_pings_over_veth() {
    let (_lab, a, _b, mut tunnels) = common::wg_lab();

    let out = a.exec(&["ping", "-c", "2", "-W", "3", "10.10.0.2"]).unwrap();
    assert!(out.status.success(), "overlay ping failed");
    for t in &mut tunnels { let _ = t.kill(); }
}
