//! Route/link/MSS programming inside a netns. Run inside the privileged
//! container: ./dev.sh run "cargo test -p wiremesh-gateway --test routes_netns \
//!   --features netns-tests -- --test-threads=1 --nocapture"
#![cfg(feature = "netns-tests")]
use wiremesh_gateway::routes;
use wiremesh_testkit::netns::{join_netns, Lab};

#[test]
fn programs_mtu_forward_route_and_mss() {
    let mut lab = Lab::new("gwrt").expect("create lab");
    let ns = lab.ns("a").expect("create netns a");
    // a dummy L3 interface to hang routes on
    ns.exec(&["ip", "link", "add", "dum0", "type", "dummy"]).unwrap();
    join_netns(&ns.name).expect("join netns a");

    routes::set_link_up_mtu("dum0", 1280).expect("set mtu/up");
    routes::enable_ip_forward().expect("ip_forward");
    routes::add_route("10.10.2.0/24", "dum0").expect("add route");
    routes::install_mss_clamp("dum0", 1240).expect("mss clamp");

    // Verify via the same netns (we're joined to it on this thread).
    let route = std::process::Command::new("ip").args(["route", "show", "10.10.2.0/24"]).output().unwrap();
    assert!(String::from_utf8_lossy(&route.stdout).contains("dum0"), "route present");
    let fwd = std::process::Command::new("sysctl").args(["-n", "net.ipv4.ip_forward"]).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&fwd.stdout).trim(), "1");
    let nft = std::process::Command::new("nft").args(["list", "table", "inet", "wiremesh_mss"]).output().unwrap();
    assert!(String::from_utf8_lossy(&nft.stdout).contains("maxseg"), "mss rule present");

    routes::del_route("10.10.2.0/24", "dum0").expect("del route idempotent");
    // Route is now already gone: a second delete must swallow the
    // "No such process" error and still return Ok.
    routes::del_route("10.10.2.0/24", "dum0").expect("del route already-gone is Ok");
    drop(lab);
}
