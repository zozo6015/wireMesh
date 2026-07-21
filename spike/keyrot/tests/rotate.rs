// spike/keyrot/tests/rotate.rs
//
// KEY-ROTATION FAST-FOLLOW DE-RISK (linchpin for spec §4.4 "make-before-break"):
// prove a gateway can rotate its OWN WireGuard key from Ka to Kb while a
// continuous ping flood runs across the overlay, with ~ZERO packet loss over the
// cutover (spec C-5 allows <= one handshake RTT, i.e. <= ~1-2 packets).
//
// Topology (NO NAT — key rotation is orthogonal to NAT traversal): two gateways
// G_A and G_B in separate netns, connected DIRECTLY by one veth underlay
// (10.9.1.1 <-> 10.9.1.2). Overlay /24: G_A 10.20.0.1, G_B 10.20.0.2.
//
// MECHANISM (discovered; see docs/research/keyrot-spike-note.md for the finding):
// A single WireGuard interface has exactly ONE private key, and WireGuard's
// allowed-ips are EXCLUSIVE to one peer per interface — so a single interface
// CANNOT hold two keys / two peers for the same overlay IP simultaneously. True
// make-before-break therefore runs TWO boringtun Devices per gateway during the
// overlap: an OLD device (Ka on port 51820, tun *_o) and a NEW device (Kb on port
// 51821, tun *_n), each with its OWN allowed-ips namespace, both feeding the one
// overlay address (kept on `lo`, reachable via either tun). Because BOTH receive
// paths stay open through the whole overlap, the two send-side route flips are
// independent local operations and drop ZERO packets.
//
// Rotation choreography while the flood runs on Ka:
//   1. G_A generates Kb; bring its NEW device live alongside the OLD one.
//   2. G_B adds a NEW device that peers with Kb (Ka's device stays up).
//   3. Establish the Kb session via an out-of-band probe (does NOT touch the
//      flood route) -> BOTH keys now live simultaneously (proven: both
//      latest-handshakes > 0 at the same instant).
//   4. Flip G_A's send route Ka->Kb, then G_B's reply route Ka->Kb. Flood now
//      rides Kb; old receive path still open so nothing drops.
//   5. Retire Ka: kill both OLD devices. Flow continues on Kb (proven by a
//      post-teardown ping with Ka fully gone).
//
// Serial, in-container only (tun/netns/boringtun): `--test-threads=1 --nocapture`.

use natlab::{Lab, Ns};
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};

struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wg_keypair() -> (String, String) {
    let priv_out = Command::new("wg").arg("genkey").output().unwrap();
    let privkey = String::from_utf8(priv_out.stdout).unwrap().trim().to_string();
    let pub_out = {
        use std::io::Write;
        let mut c = Command::new("wg")
            .arg("pubkey")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        c.stdin.as_mut().unwrap().write_all(privkey.as_bytes()).unwrap();
        c.wait_with_output().unwrap()
    };
    (privkey, String::from_utf8(pub_out.stdout).unwrap().trim().to_string())
}

/// latest-handshake unix timestamp boringtun reports for `ifname`'s peer(s) (0 ==
/// never). Used to prove a REAL WG handshake happened on a given key/session.
fn latest_handshake(ns: &Ns, ifname: &str) -> u64 {
    let out = match ns.exec(&["wg", "show", ifname, "latest-handshakes"]) {
        Ok(o) => o,
        Err(_) => return 0,
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split_whitespace().last())
        .filter_map(|s| s.parse::<u64>().ok())
        .max()
        .unwrap_or(0)
}

fn wg_show(ns: &Ns, ifname: &str) -> String {
    ns.exec(&["wg", "show", ifname])
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// Poll until both endpoints report a handshake on the named interfaces, or time out.
fn wait_handshake(a: &Ns, aif: &str, b: &Ns, bif: &str, secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if latest_handshake(a, aif) > 0 && latest_handshake(b, bif) > 0 {
            return true;
        }
        thread::sleep(Duration::from_millis(200));
    }
    false
}

/// Parse "N packets transmitted, M received, ... % packet loss" -> (tx, rx).
fn parse_ping_stats(out: &str) -> Option<(u32, u32)> {
    let line = out.lines().find(|l| l.contains("packets transmitted"))?;
    let mut tx = None;
    let mut rx = None;
    let toks: Vec<&str> = line.split(',').collect();
    for t in toks {
        let t = t.trim();
        if let Some(n) = t.strip_suffix(" packets transmitted") {
            tx = n.trim().parse().ok();
        } else if let Some(n) = t.strip_suffix(" received") {
            rx = n.trim().parse().ok();
        }
    }
    Some((tx?, rx?))
}

#[test]
fn key_rotation_make_before_break_zero_drop() {
    // ---- lab: two gateways, one direct veth underlay (no NAT) ----
    let mut lab = Lab::new("kr").unwrap();
    let a = lab.ns("a").unwrap();
    let b = lab.ns("b").unwrap();
    lab.veth((&a, "u0", "10.9.1.1/24"), (&b, "u1", "10.9.1.2/24")).unwrap();

    // Overlay addresses live on `lo` so they are reachable via EITHER tun (old or
    // new) for the whole overlap — this is what makes both receive paths stay
    // open across the cutover. .1/.2 = main flow; .11/.12 = out-of-band probe pair
    // used only to establish the Kb session without touching the flood route.
    for (ns, main, probe) in [(&a, "10.20.0.1", "10.20.9.1"), (&b, "10.20.0.2", "10.20.9.2")] {
        ns.exec(&["ip", "addr", "add", &format!("{main}/32"), "dev", "lo"]).unwrap();
        ns.exec(&["ip", "addr", "add", &format!("{probe}/32"), "dev", "lo"]).unwrap();
    }

    // ---- keys ----
    // Ka/Kb: G_A's OLD and NEW (rotated) keys. G_B keeps ONE key (Kb_gw) used on
    // BOTH its devices — faithful to "only G_A's key rotates"; the two devices are
    // separate processes so a shared static key is fine.
    let (ka_priv, ka_pub) = wg_keypair();
    let (kb_priv, kb_pub) = wg_keypair();
    let (gb_priv, gb_pub) = wg_keypair();
    let keyfile = |name: &str, contents: &str| {
        let p = format!("/tmp/kr-{name}.key");
        std::fs::write(&p, contents).unwrap();
        p
    };
    let ka_f = keyfile("ka", &ka_priv);
    let kb_f = keyfile("kb", &kb_priv);
    let gb_f = keyfile("gb", &gb_priv);

    let bin = env!("CARGO_BIN_EXE_keyrot-dev");

    // ---- bring up ALL FOUR devices up front (idle until configured) ----
    // a: tunA_o (OLD, Ka), tunA_n (NEW, Kb).  b: tunB_o (OLD), tunB_n (NEW).
    let mut dev_a_o = Some(KillOnDrop(a.spawn(&[bin, "tunA_o"]).unwrap()));
    let mut dev_b_o = Some(KillOnDrop(b.spawn(&[bin, "tunB_o"]).unwrap()));
    let _dev_a_n = KillOnDrop(a.spawn(&[bin, "tunA_n"]).unwrap());
    let _dev_b_n = KillOnDrop(b.spawn(&[bin, "tunB_n"]).unwrap());
    thread::sleep(Duration::from_millis(1200)); // devices + UAPI sockets up

    // ---- configure the OLD tunnel (Ka <-> Kb_gw) and bring the flow up ----
    a.exec(&["wg", "set", "tunA_o", "listen-port", "51820", "private-key", &ka_f,
             "peer", &gb_pub, "allowed-ips", "10.20.0.2/32",
             "endpoint", "10.9.1.2:51820", "persistent-keepalive", "5"]).unwrap();
    a.exec(&["ip", "link", "set", "tunA_o", "up", "mtu", "1280"]).unwrap();
    a.exec(&["ip", "route", "add", "10.20.0.2/32", "dev", "tunA_o", "src", "10.20.0.1"]).unwrap();

    b.exec(&["wg", "set", "tunB_o", "listen-port", "51820", "private-key", &gb_f,
             "peer", &ka_pub, "allowed-ips", "10.20.0.1/32",
             "endpoint", "10.9.1.1:51820", "persistent-keepalive", "5"]).unwrap();
    b.exec(&["ip", "link", "set", "tunB_o", "up", "mtu", "1280"]).unwrap();
    b.exec(&["ip", "route", "add", "10.20.0.1/32", "dev", "tunB_o", "src", "10.20.0.2"]).unwrap();

    assert!(
        wait_handshake(&a, "tunA_o", &b, "tunB_o", 15),
        "OLD tunnel (Ka) failed to complete a real WG handshake:\n a:\n{}\n b:\n{}",
        wg_show(&a, "tunA_o"), wg_show(&b, "tunB_o")
    );
    // Sanity: flow works on Ka before we start.
    let pre = a.exec(&["ping", "-c", "2", "-W", "3", "10.20.0.2"]).unwrap();
    assert!(pre.status.success(), "overlay ping on Ka failed before rotation");

    // ---- START the continuous flood G_A -> G_B (rides Ka right now) ----
    // -i 0.2 -c 90 => ~18s window; the entire rotation happens inside it.
    let flood = a
        .spawn(&["ping", "-i", "0.2", "-c", "90", "-W", "2", "10.20.0.2"])
        .unwrap();
    let flood_start = Instant::now();
    thread::sleep(Duration::from_millis(800)); // let the flood settle on Ka

    // ================= MAKE-BEFORE-BREAK ROTATION (Ka -> Kb) =================
    // 1+2. Bring G_A's NEW device (Kb) live and add G_B's NEW device (peers Kb).
    //      OLD devices stay fully up — this is the "make" (overlap) phase.
    a.exec(&["wg", "set", "tunA_n", "listen-port", "51821", "private-key", &kb_f,
             "peer", &gb_pub, "allowed-ips", "10.20.0.2/32,10.20.9.2/32",
             "endpoint", "10.9.1.2:51821", "persistent-keepalive", "5"]).unwrap();
    a.exec(&["ip", "link", "set", "tunA_n", "up", "mtu", "1280"]).unwrap();
    a.exec(&["ip", "route", "add", "10.20.9.2/32", "dev", "tunA_n", "src", "10.20.9.1"]).unwrap();

    b.exec(&["wg", "set", "tunB_n", "listen-port", "51821", "private-key", &gb_f,
             "peer", &kb_pub, "allowed-ips", "10.20.0.1/32,10.20.9.1/32",
             "endpoint", "10.9.1.1:51821", "persistent-keepalive", "5"]).unwrap();
    b.exec(&["ip", "link", "set", "tunB_n", "up", "mtu", "1280"]).unwrap();
    b.exec(&["ip", "route", "add", "10.20.9.1/32", "dev", "tunB_n", "src", "10.20.9.2"]).unwrap();

    // 3. Establish the Kb session via the OUT-OF-BAND probe pair (10.20.9.x),
    //    which does NOT disturb the flood's 10.20.0.2 route.
    let probe = a.exec(&["ping", "-c", "2", "-W", "3", "10.20.9.2"]).unwrap();
    assert!(
        probe.status.success(),
        "Kb session probe ping failed — new key did not come live:\n a:\n{}\n b:\n{}",
        wg_show(&a, "tunA_n"), wg_show(&b, "tunB_n")
    );
    assert!(
        wait_handshake(&a, "tunA_n", &b, "tunB_n", 10),
        "NEW tunnel (Kb) failed to complete a real WG handshake during overlap"
    );

    // ---- PROOF OF OVERLAP: both keys live at the SAME instant ----
    let ka_hs = latest_handshake(&a, "tunA_o");
    let kb_hs = latest_handshake(&a, "tunA_n");
    assert!(
        ka_hs > 0 && kb_hs > 0,
        "both keys must be live simultaneously (Ka hs={ka_hs}, Kb hs={kb_hs})"
    );
    eprintln!("[overlap] BOTH keys live: Ka handshake={ka_hs}, Kb handshake={kb_hs}");

    // 4. CUTOVER: flip send routes Ka->Kb. Independent local ops; both receive
    //    paths remain open, so zero packets drop.
    a.exec(&["ip", "route", "replace", "10.20.0.2/32", "dev", "tunA_n", "src", "10.20.0.1"]).unwrap();
    b.exec(&["ip", "route", "replace", "10.20.0.1/32", "dev", "tunB_n", "src", "10.20.0.2"]).unwrap();
    thread::sleep(Duration::from_millis(800)); // flood now rides Kb; let it settle

    // 5. BREAK: retire Ka — tear down BOTH OLD devices and their routes.
    a.exec(&["ip", "route", "del", "10.20.9.2/32"]).ok();
    b.exec(&["ip", "route", "del", "10.20.9.1/32"]).ok();
    drop(dev_a_o.take()); // DeviceHandle drop tears down tunA_o
    drop(dev_b_o.take()); // ... and tunB_o (Ka fully gone)
    thread::sleep(Duration::from_millis(800));

    // ---- PROOF the flow continues on Kb with Ka fully torn down ----
    let post = a.exec(&["ping", "-c", "3", "-W", "3", "10.20.0.2"]).unwrap();
    let post_ok = post.status.success();

    // ---- collect the flood result ----
    let out = flood.wait_with_output().unwrap();
    let flood_out = String::from_utf8_lossy(&out.stdout).into_owned();
    let elapsed = flood_start.elapsed();

    // ---- evidence dump (always) ----
    eprintln!("=== key-rotation make-before-break evidence ===");
    eprintln!("rotation wall-time inside flood window: {:?} (flood budget ~18s)", elapsed);
    eprintln!("--- flood (G_A->G_B, spans the whole rotation) ---\n{flood_out}");
    eprintln!("--- post-teardown ping (Ka gone, Kb only) ---\n{}", String::from_utf8_lossy(&post.stdout));
    eprintln!("--- wg show tunA_n @a (Kb) ---\n{}", wg_show(&a, "tunA_n"));
    eprintln!("--- wg show tunB_n @b (Kb) ---\n{}", wg_show(&b, "tunB_n"));

    let (tx, rx) = parse_ping_stats(&flood_out)
        .unwrap_or_else(|| panic!("could not parse flood ping stats:\n{flood_out}"));
    let lost = tx.saturating_sub(rx);
    eprintln!("[result] flood: {tx} transmitted, {rx} received, {lost} lost");

    // ---- assertions ----
    assert!(post_ok, "flow must continue on Kb after Ka is torn down (post-teardown ping failed)");
    assert!(
        tx >= 40,
        "flood must span the rotation (only {tx} pings sent — rotation likely overran the window)"
    );
    // spec C-5: <= one handshake RTT of loss. We expect 0 with make-before-break.
    assert!(
        lost <= 2,
        "make-before-break must lose ~zero packets across the cutover; lost {lost} of {tx}"
    );
}
