// spike/enforcer/enforcer/tests/enforce.rs
//
// Task 6, Step 5 (test author): the failing/RED integration test proving
// default-deny enforcement on a real WireGuard tun device.
//
// Brings up the canonical two-node wg lab (see tests/common/mod.rs), confirms
// the overlay ping works *before* enforcement, then starts the enforcer in
// namespace b with an empty rule set and asserts the overlay ping now fails
// and the pinned deny counter has risen.
mod common;
use common::wg_lab;

fn stats(ns: &natlab::Ns, bin: &str) -> serde_json::Value {
    let out = ns.exec(&[bin, "stats"]).unwrap();
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn default_deny_drops_overlay_ping_and_counts() {
    let enf = env!("CARGO_BIN_EXE_enforcer");
    let (lab, a, b, mut children) = wg_lab();
    // sanity: tunnel works before enforcement
    assert!(a.exec(&["ping", "-c", "1", "-W", "3", "10.10.0.2"]).unwrap().status.success());

    std::fs::write("/tmp/empty-rules.json", "[]").unwrap();
    children.push(b.spawn(&[enf, "run", "--iface", "wg0", "--rules", "/tmp/empty-rules.json"]).unwrap());
    std::thread::sleep(std::time::Duration::from_secs(1));

    // ping must now fail (denied at B's tun ingress), deny counter must rise.
    //
    // NOTE (deviation from the brief's literal listing): natlab::Ns::exec()
    // (see spike/natlab/src/lib.rs `run()`) bails with Err whenever the
    // command's exit status is non-success — it never returns Ok(Output)
    // with a failed status. `ping -c 2` with no reply exits non-zero, so
    // `.exec(...).unwrap()` would panic on the Err here rather than give us
    // an Output to negate-check, which would report this test as FAILED
    // (via panic) precisely when default-deny enforcement is working
    // correctly. Assert on `is_err()` instead of unwrapping.
    assert!(
        a.exec(&["ping", "-c", "2", "-W", "2", "10.10.0.2"]).is_err(),
        "ping should be blocked by default-deny enforcement, but it succeeded"
    );
    let s = stats(&b, enf);
    assert!(s["deny"].as_u64().unwrap() >= 2, "deny counter: {s}");
    for c in &mut children { let _ = c.kill(); }
    drop(lab);
}
