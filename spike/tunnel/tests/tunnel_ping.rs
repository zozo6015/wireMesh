// spike/tunnel/tests/tunnel_ping.rs
use natlab::Lab;
use std::{thread, time::Duration};

fn wg_keypair() -> (String, String) {
    let priv_out = std::process::Command::new("wg").arg("genkey").output().unwrap();
    let privkey = String::from_utf8(priv_out.stdout).unwrap().trim().to_string();
    let pub_out = {
        use std::io::Write;
        let mut c = std::process::Command::new("wg").arg("pubkey")
            .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped())
            .spawn().unwrap();
        c.stdin.as_mut().unwrap().write_all(privkey.as_bytes()).unwrap();
        c.wait_with_output().unwrap()
    };
    (privkey.clone(), String::from_utf8(pub_out.stdout).unwrap().trim().to_string())
}

#[test]
fn wireguard_tunnel_pings_over_veth() {
    let bin = env!("CARGO_BIN_EXE_spike-tunnel");
    let mut lab = Lab::new("wgt").unwrap();
    let a = lab.ns("a").unwrap();
    let b = lab.ns("b").unwrap();
    lab.veth((&a, "u0", "10.9.1.1/24"), (&b, "u1", "10.9.1.2/24")).unwrap();

    let (apriv, apub) = wg_keypair();
    let (bpriv, bpub) = wg_keypair();

    let mut ta = a.spawn(&[bin, "wg0"]).unwrap();
    let mut tb = b.spawn(&[bin, "wg0"]).unwrap();
    thread::sleep(Duration::from_millis(800)); // device + UAPI socket up

    for (ns, privkey, peer_pub, my_ip, peer_ip, peer_ep) in [
        (&a, &apriv, &bpub, "10.10.0.1/24", "10.10.0.2", "10.9.1.2:51820"),
        (&b, &bpriv, &apub, "10.10.0.2/24", "10.10.0.1", "10.9.1.1:51820"),
    ] {
        let kf = format!("/tmp/{}.key", ns.name);
        std::fs::write(&kf, privkey).unwrap();
        ns.exec(&["wg", "set", "wg0", "listen-port", "51820", "private-key", &kf,
                  "peer", peer_pub, "allowed-ips", &format!("{peer_ip}/32"),
                  "endpoint", peer_ep]).unwrap();
        ns.exec(&["ip", "addr", "add", my_ip, "dev", "wg0"]).unwrap();
        ns.exec(&["ip", "link", "set", "wg0", "up", "mtu", "1280"]).unwrap();
    }

    let out = a.exec(&["ping", "-c", "2", "-W", "3", "10.10.0.2"]).unwrap();
    assert!(out.status.success(), "overlay ping failed");
    let _ = ta.kill(); let _ = tb.kill();
}
