// spike/enforcer/enforcer/tests/common/mod.rs
//
// Adapted copy of the canonical two-node WireGuard tunnel lab helper
// (spike/tunnel/tests/common/mod.rs, Task 3 interface deliverable). Each
// spike crate is standalone (no root cargo workspace), so Tasks 6-9/14 reuse
// this pattern by copy rather than by depending on spike/tunnel directly.
//
// Returns a running lab: overlay 10.10.0.1 <-> 10.10.0.2 over underlay
// 10.9.1.0/24, with the spike-tunnel binary running in each namespace.
// Callers are responsible for killing the returned tunnel processes.
//
// ONE required adaptation vs. the tunnel crate's original: this crate can't
// use `env!("CARGO_BIN_EXE_spike-tunnel")` (that only resolves for binaries
// built by *this* crate/workspace) — the tunnel binary lives in a separate,
// standalone cargo workspace (spike/tunnel). Its path is passed in via the
// `SPIKE_TUNNEL_BIN` env var instead, set by whoever runs the test suite.

use natlab::{Lab, Ns};
use std::process::Child;
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

pub fn wg_lab() -> (Lab, Ns, Ns, Vec<Child>) {
    let bin = std::env::var("SPIKE_TUNNEL_BIN").expect(
        "SPIKE_TUNNEL_BIN must be set to the path of the built spike-tunnel binary \
         (e.g. /work/spike/tunnel/target/release/spike-tunnel) — this crate is a \
         standalone workspace and cannot use CARGO_BIN_EXE_spike-tunnel from a \
         different crate's build",
    );
    let bin = bin.as_str();
    let mut lab = Lab::new("wgt").unwrap();
    let a = lab.ns("a").unwrap();
    let b = lab.ns("b").unwrap();
    lab.veth((&a, "u0", "10.9.1.1/24"), (&b, "u1", "10.9.1.2/24")).unwrap();

    let (apriv, apub) = wg_keypair();
    let (bpriv, bpub) = wg_keypair();

    let ta = a.spawn(&[bin, "wg0"]).unwrap();
    let tb = b.spawn(&[bin, "wg0"]).unwrap();
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

    (lab, a, b, vec![ta, tb])
}
