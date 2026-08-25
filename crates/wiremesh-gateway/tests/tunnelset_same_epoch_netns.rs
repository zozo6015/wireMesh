//! Key-rotation T3, end-to-end half: an OWN-epoch Device and a Role-B OVERLAP
//! Device that carry the SAME epoch number must be able to be live at the same
//! time, as real kernel links with real UAPI sockets and real UDP ports.
//!
//! ./dev.sh run "cargo test -p wiremesh-gateway --test tunnelset_same_epoch_netns \
//!   --features netns-tests -- --test-threads=1 --nocapture"
//!
//! `tests/tunnel_id_decollision.rs` pins the DECISION (the planner's three
//! axes are distinct). This pins that the decision is actually REALIZABLE:
//! the kernel accepts both links, boringtun opens both
//! `/var/run/wireguard/<ifname>.sock` UAPI sockets, and both Devices bind
//! their own UDP port. A planner that emitted distinct-but-invalid names, or
//! ports already taken, would pass the pure suite and fail here.
//!
//! Kept in its OWN file rather than appended to `tunnelset_netns.rs`: this
//! target is compile-red until the `TunnelId` seam lands, and a non-compiling
//! target aborts the whole run — `tunnelset_netns.rs` must stay buildable.
//!
//! Model: `tunnelset_netns.rs`. One netns is enough — the property is "two
//! Devices in the SAME namespace don't collide", exactly as there. No traffic,
//! no veth pair, no netem: this is a resource-collision test, so it is seconds,
//! not minutes.
//!
//! # Production seam this file requires (does NOT exist yet — COMPILE-RED)
//!
//! Beyond `plan_tunnel`/`TunnelId`/`TunnelPlan` (specified in
//! `tests/tunnel_id_decollision.rs`), `TunnelSet`'s key type must widen:
//!
//! ```ignore
//! impl TunnelSet {
//!     pub fn bring_up(&mut self, id: TunnelId, ifname: &str, private_key_b64: &str,
//!                     listen_port: u16, mtu: u32) -> anyhow::Result<()>;
//!     pub fn get(&self, id: TunnelId) -> Option<&Tunnel>;
//!     pub fn tear_down(&mut self, id: TunnelId) -> anyhow::Result<()>;
//! }
//! ```
//!
//! i.e. exactly today's methods with `epoch: u32` replaced by `id: TunnelId`.
//! The existing call sites (`main.rs:476`, `:3409`, `:3464`, `:3692`, `:3794`,
//! and `tests/tunnelset_netns.rs`) are mechanical `Own { epoch }` /
//! `Overlap { gateway_id, epoch }` updates — no assertion in the existing
//! netns suite changes meaning.
#![cfg(feature = "netns-tests")]
use std::process::Command;
use wiremesh_gateway::tunnelset::{plan_tunnel, TunnelId, TunnelPlan, TunnelSet};
use wiremesh_gateway::uapi::base64_pub_from_priv;
use wiremesh_testkit::netns::{join_netns_and_mountns, Lab};

const BASE_TUN: &str = "wg0";
const BASE_PORT: u16 = 51820;

/// `wg genkey` + our own pubkey derivation, exactly as `tunnelset_netns.rs`
/// does it (the `wg` tool is present in the dev container).
fn gen_priv() -> String {
    let out = Command::new("wg").arg("genkey").output().unwrap();
    let priv_b64 = String::from_utf8(out.stdout).unwrap().trim().to_string();
    // Round-trip through the real derivation so a malformed key fails here
    // rather than deep inside boringtun.
    base64_pub_from_priv(&priv_b64).unwrap();
    priv_b64
}

/// `wg show <ifname>` succeeds and reports `listening port: <port>`.
fn assert_device_listening(ifname: &str, port: u16) {
    let out = Command::new("wg").args(["show", ifname]).output().unwrap();
    assert!(
        out.status.success(),
        "wg show {ifname} failed — the Device is not up: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains(&format!("listening port: {port}")),
        "{ifname} should be listening on {port}; wg show said:\n{text}"
    );
}

/// **THE CORE DEFECT, end to end.** This gateway is rotating to epoch 2 (Role
/// A) while peer 7 is rotating to pending epoch 2 (Role B) in the same tick —
/// the ordinary consequence of `initiate_due_rotations` walking every active
/// gateway off a single 30-day timer. Today both roles compute the same map
/// key, the same `wg0e2` ifname and the same `base+1` port; `bring_up` bails
/// on the second and the `?` at `main.rs:3794` discards the rest of the peer
/// loop. All three Devices must be live simultaneously.
#[test]
fn own_and_overlap_devices_at_the_same_epoch_coexist() {
    let mut lab = Lab::new("tunsame").unwrap();
    let a = lab.ns("a").unwrap();
    join_netns_and_mountns(&a).unwrap();

    let mut set = TunnelSet::new();

    // (1) The boot/active tun: the base name at the base port, brought up
    // directly rather than planned (main.rs:476-482, OD-1).
    let boot_id = TunnelId::Own { epoch: 1 };
    let boot_priv = gen_priv();
    set.bring_up(boot_id, BASE_TUN, &boot_priv, BASE_PORT, 1280)
        .unwrap();
    let boot_plan = TunnelPlan {
        id: boot_id,
        ifname: BASE_TUN.to_string(),
        listen_port: BASE_PORT,
    };
    let mut live = vec![boot_plan];

    // (2) Role A: our own new epoch 2.
    let own_id = TunnelId::Own { epoch: 2 };
    let own =
        plan_tunnel(own_id, BASE_TUN, BASE_PORT, &live).expect("planning our own epoch-2 tun");
    let own_priv = gen_priv();
    set.bring_up(own_id, &own.ifname, &own_priv, own.listen_port, 1280)
        .expect("Role A's own epoch-2 Device must come up");
    live.push(own.clone());

    // (3) Role B: an overlap toward peer 7's pending epoch — also 2. Runs OUR
    // ACTIVE key (main.rs:3786-3793), not a fresh one, so the private key here
    // is deliberately `boot_priv`: two Devices holding the same keypair on
    // different ports is legal WireGuard and is exactly what production does.
    let ovl_id = TunnelId::Overlap {
        gateway_id: 7,
        epoch: 2,
    };
    let ovl = plan_tunnel(ovl_id, BASE_TUN, BASE_PORT, &live)
        .expect("planning a Role-B overlap toward peer 7's pending epoch 2");
    set.bring_up(ovl_id, &ovl.ifname, &boot_priv, ovl.listen_port, 1280)
        .expect(
            "the Role-B overlap Device must come up ALONGSIDE our own epoch-2 Device — this \
                 is the shipped fabric-wide-outage bug (F3)",
        );
    live.push(ovl.clone());

    // All three are distinct map entries.
    assert!(
        set.get(boot_id).is_some(),
        "boot tun must still be in the set"
    );
    assert!(
        set.get(own_id).is_some(),
        "our own epoch-2 tun must be in the set"
    );
    assert!(
        set.get(ovl_id).is_some(),
        "the overlap toward peer 7 at epoch 2 must be in the set"
    );

    // All three are distinct, live kernel links on distinct ports. `wg show`
    // is the arbiter rather than the set's own bookkeeping: a scheme that
    // recorded distinct ports but bound the same one would pass an in-memory
    // check and fail here.
    assert_device_listening(BASE_TUN, BASE_PORT);
    assert_device_listening(&own.ifname, own.listen_port);
    assert_device_listening(&ovl.ifname, ovl.listen_port);

    // And the axes really are three, not one: the planner's own output has to
    // agree with what the kernel accepted.
    assert_ne!(
        own.ifname, ovl.ifname,
        "own-epoch and overlap tuns must not share an ifname"
    );
    assert_ne!(
        own.listen_port, ovl.listen_port,
        "own-epoch and overlap tuns must not share a port"
    );
    assert_ne!(
        own.ifname, BASE_TUN,
        "a rotation tun must never reuse the base tun's name"
    );
    assert_ne!(
        ovl.ifname, BASE_TUN,
        "an overlap tun must never reuse the base tun's name"
    );

    // Tearing the overlap down must not disturb our own epoch-2 Device: the
    // two rotations are independent and complete on independent schedules.
    set.tear_down(ovl_id).unwrap();
    assert!(
        set.get(ovl_id).is_none(),
        "the overlap must be gone from the set"
    );
    assert!(
        !Command::new("ip")
            .args(["link", "show", &ovl.ifname])
            .status()
            .unwrap()
            .success(),
        "{} should no longer exist after tear_down",
        ovl.ifname
    );
    assert_device_listening(&own.ifname, own.listen_port);
    assert_device_listening(BASE_TUN, BASE_PORT);

    drop(lab);
}

/// The multi-peer half: two peers rotating to the same pending epoch number in
/// the same tick each need their own Device. Today the second one's `bring_up`
/// bails and takes the rest of the loop with it.
#[test]
fn two_peers_overlapping_at_the_same_epoch_get_their_own_devices() {
    let mut lab = Lab::new("tunmulti").unwrap();
    let a = lab.ns("a").unwrap();
    join_netns_and_mountns(&a).unwrap();

    let mut set = TunnelSet::new();
    let boot_id = TunnelId::Own { epoch: 3 };
    let boot_priv = gen_priv();
    set.bring_up(boot_id, BASE_TUN, &boot_priv, BASE_PORT, 1280)
        .unwrap();
    let mut live = vec![TunnelPlan {
        id: boot_id,
        ifname: BASE_TUN.to_string(),
        listen_port: BASE_PORT,
    }];

    let mut brought_up = Vec::new();
    for gid in [11u64, 12, 13] {
        let id = TunnelId::Overlap {
            gateway_id: gid,
            epoch: 4,
        };
        let plan = plan_tunnel(id, BASE_TUN, BASE_PORT, &live)
            .unwrap_or_else(|e| panic!("planning overlap toward peer {gid} at epoch 4: {e:#}"));
        set.bring_up(id, &plan.ifname, &boot_priv, plan.listen_port, 1280)
            .unwrap_or_else(|e| {
                panic!("overlap Device for peer {gid} at epoch 4 must come up: {e:#}")
            });
        live.push(plan.clone());
        brought_up.push((gid, id, plan));
    }

    for (gid, id, plan) in &brought_up {
        assert!(
            set.get(*id).is_some(),
            "peer {gid}'s overlap must be in the set"
        );
        assert_device_listening(&plan.ifname, plan.listen_port);
    }
    assert_device_listening(BASE_TUN, BASE_PORT);

    drop(lab);
}
