//! Throughput smoke: iperf3 across the WG tunnel between two gateway netns.
//! Records Mbit/s to stdout; does NOT assert the G-2 >=1Gbps floor (that needs a
//! real 4-vCPU VM — see bench.md). Netns loopback numbers are harness-only.
//! ./dev.sh run "cargo test -p wiremesh-gateway --test throughput_bench \
//!   --features netns-tests -- --test-threads=1 --nocapture"
//!
//! Reuses the exact two-gateway direct-WG setup from `tunnel_netns.rs`
//! (`join_netns_and_mountns`, in-process boringtun `Tunnel`, real routes) —
//! see that file's doc comment for why plain `join_netns` is insufficient
//! (two same-named `wg0` UAPI sockets would collide in a shared mount ns).
#![cfg(feature = "netns-tests")]
use std::time::Duration;
use wiremesh_gateway::routes;
use wiremesh_gateway::state::{DesiredState, PeerState};
use wiremesh_gateway::tunnel::Tunnel;
use wiremesh_gateway::uapi::base64_pub_from_priv;
use wiremesh_testkit::netns::{join_netns_and_mountns, Lab};

fn gen_keypair() -> (String, String) {
    let priv_b64 = String::from_utf8(std::process::Command::new("wg").arg("genkey").output().unwrap().stdout)
        .unwrap().trim().to_string();
    let pub_b64 = base64_pub_from_priv(&priv_b64).unwrap();
    (priv_b64, pub_b64)
}

#[test]
fn iperf3_across_tunnel_reports_throughput() {
    // iperf3 isn't a hard dependency of the dev container image; skip loudly
    // (never fake a number) rather than fail the suite if it's ever absent.
    let has_iperf3 = std::process::Command::new("iperf3").arg("--version").output()
        .map(|o| o.status.success()).unwrap_or(false);
    if !has_iperf3 {
        eprintln!("SKIP: iperf3 not present in this container; throughput smoke not run.");
        return;
    }

    let mut lab = Lab::new("gwbench").expect("lab");
    let a = lab.ns("a").unwrap();
    let b = lab.ns("b").unwrap();
    // underlay veth: a=10.9.0.1, b=10.9.0.2
    lab.veth((&a, "u0", "10.9.0.1/24"), (&b, "u0", "10.9.0.2/24")).unwrap();

    let (a_priv, a_pub) = gen_keypair();
    let (b_priv, b_pub) = gen_keypair();

    // Gateway B runs in a thread joined to netns b; starts an iperf3 server
    // once the tunnel is up.
    let b_ns = b.clone();
    let hb = std::thread::spawn(move || {
        join_netns_and_mountns(&b_ns).unwrap();
        let t = Tunnel::up("wg0", &b_priv, 51820, 1280).unwrap();
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
        // iperf3 server: one run, then exit.
        let out = std::process::Command::new("iperf3")
            .args(["-s", "-1", "-p", "5601"]).output().unwrap();
        eprintln!("iperf3 server (netns b) output:\n{}", String::from_utf8_lossy(&out.stdout));
        // Keep the netns alive a bit longer so the client side can finish
        // reading its own results before the thread (and its netns) exits.
        std::thread::sleep(Duration::from_millis(500));
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
    std::thread::sleep(Duration::from_secs(2)); // allow handshake + server startup

    let client = std::process::Command::new("iperf3")
        .args(["-c", "10.10.2.2", "-p", "5601", "-t", "5", "-J"])
        .output()
        .expect("run iperf3 client");
    assert!(
        client.status.success(),
        "iperf3 client failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&client.stdout),
        String::from_utf8_lossy(&client.stderr)
    );

    let stdout = String::from_utf8_lossy(&client.stdout);
    let mbps = parse_receiver_mbps(&stdout);
    match mbps {
        Some(v) => println!("THROUGHPUT SMOKE (netns, harness-only, NOT the G-2 gate): {v:.2} Mbit/s"),
        None => println!("THROUGHPUT SMOKE: iperf3 completed but Mbit/s could not be parsed from JSON; raw output:\n{stdout}"),
    }
    eprintln!("throughput smoke: see stdout for Mbit/s; G-2 floor deferred to a 4-vCPU cloud run (see bench.md)");

    hb.join().unwrap();
    drop(lab);
}

/// Pull `end.sum_received.bits_per_second` out of iperf3's `-J` JSON report
/// with a minimal hand parser (no serde_json dependency needed for a single
/// scalar) and convert to Mbit/s.
fn parse_receiver_mbps(json: &str) -> Option<f64> {
    let idx = json.find("\"sum_received\"")?;
    let tail = &json[idx..];
    let key = "\"bits_per_second\"";
    let kidx = tail.find(key)? + key.len();
    let rest = tail[kidx..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let end = rest.find(|c: char| c == ',' || c == '}')?;
    rest[..end].trim().parse::<f64>().ok().map(|bps| bps / 1_000_000.0)
}
