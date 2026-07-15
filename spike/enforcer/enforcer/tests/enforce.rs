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

// Task 8 (test author): variant of `stats` for the multi-enforcer-per-kernel
// case. `stats` (above) always queries the default `--pin-dir
// /sys/fs/bpf/aeth`, which is fine when only one enforcer instance exists at
// a time (Tasks 6-7). This test runs TWO concurrent enforcers (one per
// netns, one per side of the tunnel) with distinct `--pin-dir` flags (see
// Task 6's phase0-results.md note: `stats --pin-dir X` resolves via the pin
// or the pin-dir-keyed `/tmp/enforcer-<sanitized X>.mapids.json` file written
// by `run --pin-dir X`, so each side's counters are queried unambiguously by
// passing the matching pin dir here).
fn stats_pin(ns: &natlab::Ns, bin: &str, pin_dir: &str) -> serde_json::Value {
    let out = ns.exec(&[bin, "stats", "--pin-dir", pin_dir]).unwrap();
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

// Task 7, Step 3 (test author): two new failing tests pinning down the
// interface all later tasks reuse — the rules JSON format
// (`[{"src","dst","proto","ports","action"}]`, proto in tcp|udp|icmp|any,
// ports absent = any port) and SIGHUP-triggered atomic A/B rule-table flip.
//
// Both tests are adapted from the brief's literal listing to this file's
// established idiom from Task 6 (see the NOTE above
// `default_deny_drops_overlay_ping_and_counts`): `natlab::Ns::exec()` bails
// with `Err` on ANY non-zero exit, so "must succeed"/"must fail" assertions
// use `.is_ok()`/`.is_err()`, never `.unwrap().status.success()` — the
// latter would either panic (masking a real failure as a harness crash) or
// be vacuously true (since `exec()` only ever returns `Ok` for a successful
// exit, so `.status.success()` after an `unwrap()` that didn't panic is
// always true and asserts nothing).

#[test]
fn allow_rule_permits_tcp_and_denies_others() {
    let enf = env!("CARGO_BIN_EXE_enforcer");
    let (lab, a, b, mut children) = wg_lab();
    std::fs::write("/tmp/r1.json",
        r#"[{"src":"10.10.0.0/24","dst":"10.10.0.2/32","proto":"tcp","ports":[5201,5201],"action":"allow"}]"#).unwrap();
    children.push(b.spawn(&[enf, "run", "--iface", "wg0", "--rules", "/tmp/r1.json"]).unwrap());
    std::thread::sleep(std::time::Duration::from_secs(1));
    children.push(b.spawn(&["iperf3", "-s", "-p", "5201"]).unwrap());
    std::thread::sleep(std::time::Duration::from_millis(500));

    // allowed: iperf3 client (a) -> server (b) on tcp/5201, the sole allow
    // rule in r1.json. This isolates B-side ingress allow + B->A reply
    // traffic (A runs no enforcer, so only B's tun ingress can deny).
    assert!(
        a.exec(&["iperf3", "-c", "10.10.0.2", "-p", "5201", "-t", "2"]).is_ok(),
        "iperf3 client should succeed: tcp/5201 to 10.10.0.2 is allowed by r1.json"
    );
    // denied: ping (icmp has no allow rule in r1.json -> falls through to
    // default-deny, same mechanism proven in Task 6).
    assert!(
        a.exec(&["ping", "-c", "1", "-W", "2", "10.10.0.2"]).is_err(),
        "ping should be denied (no icmp allow rule in r1.json), but it succeeded"
    );
    for c in &mut children { let _ = c.kill(); }
    drop(lab);
}

#[test]
fn rule_flip_under_traffic_never_transiently_denies() {
    let enf = env!("CARGO_BIN_EXE_enforcer");
    let (lab, a, b, mut children) = wg_lab();
    std::fs::write("/tmp/r2.json",
        r#"[{"src":"10.10.0.0/24","dst":"10.10.0.2/32","proto":"icmp","action":"allow"}]"#).unwrap();
    let enf_child = b.spawn(&[enf, "run", "--iface", "wg0", "--rules", "/tmp/r2.json"]).unwrap();
    // b.spawn() execs the enforcer in-place via nsenter -- ip netns exec
    // (no intermediate fork that would leave enf_child.id() pointing at a
    // wrapper), and `ip netns exec` only isolates the *network* namespace,
    // not the PID namespace -- so the enforcer's real pid is both known
    // here and signalable from `b.exec(&["kill", "-HUP", ...])` below, which
    // runs in the same (root) pid namespace.
    let enf_pid = enf_child.id().to_string();
    children.push(enf_child);
    std::thread::sleep(std::time::Duration::from_secs(1));

    let deny_before = stats(&b, enf)["deny"].as_u64().unwrap();
    // Continuous ping (0.2s interval, 60 total => ~12s) from a, overlapped
    // with 50 SIGHUP-triggered reloads of the *same* icmp-allow ruleset at
    // 100ms intervals (~5s of flipping). Reloading identical rules must
    // never transiently deny traffic: the atomic ACTIVE flip (write the
    // inactive A/B table, then flip the index) means every packet's single
    // read of ACTIVE during scan_rules should see either the old or the new
    // table, both of which allow this traffic -- never a window with an
    // empty/inactive table.
    let mut pinger = a.spawn(&["ping", "-i", "0.2", "-c", "60", "10.10.0.2"]).unwrap();
    for _ in 0..50 {
        b.exec(&["kill", "-HUP", &enf_pid]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let out = pinger.wait_with_output().unwrap();
    let txt = String::from_utf8_lossy(&out.stdout);
    // Assertion strength kept exactly at the brief's level on purpose: 0%
    // packet loss and an unchanged deny counter across 50 flips are the
    // entire point of this test. Per CLAUDE.md, if this fails it is a
    // candidate spike finding about the read-once-ACTIVE-per-packet design
    // (record it in docs/research/ and investigate) -- not a reason to
    // loosen the assertion or delete the case to get green.
    assert!(txt.contains(" 0% packet loss"), "loss during flips: {txt}");
    assert_eq!(
        stats(&b, enf)["deny"].as_u64().unwrap(),
        deny_before,
        "transient denies during flip"
    );
    for c in &mut children { let _ = c.kill(); }
    drop(lab);
}

// Task 8, Step 1 (test author): proves spec §5.3 stateful reply semantics
// with enforcers running on BOTH gateways at once (Tasks 6-7 only ever ran
// one enforcer, in ns b). B allows inbound tcp:5201; A allows NOTHING
// inbound. The SYN passes B's allow rule normally, but the SYN-ACK arrives
// at A's tun ingress where NO rule permits it -- if A's enforcer only
// consulted the static rule table, the reply would be dropped and the
// iperf3 client would time out. It must instead be let through by A's own
// egress-recorded flow-table entry (A's egress path, when the SYN went out,
// records the flow; A's ingress path finds the reverse-key hit for the
// SYN-ACK and passes it before ever reaching the default-deny fallback).
//
// Adapted from the brief's literal listing per this file's established idiom
// (see the NOTE above `default_deny_drops_overlay_ping_and_counts`):
// `natlab::Ns::exec()` bails with `Err` on non-zero exit, so
// `a.exec(&["iperf3", ...])` is asserted with `.is_ok()`, not
// `.unwrap().status.success()`. Also uses the new `stats_pin` helper (see
// above) since this test needs the A-side enforcer's counters specifically,
// and two concurrent enforcers means the plain `stats` (default pin dir)
// helper cannot disambiguate between them.
#[test]
fn reply_traffic_passes_via_flow_table_with_enforcers_on_both_sides() {
    let enf = env!("CARGO_BIN_EXE_enforcer");
    let (lab, a, b, mut children) = wg_lab();
    // B allows inbound tcp:5201; A allows NOTHING inbound.
    std::fs::write("/tmp/rb.json",
        r#"[{"src":"10.10.0.0/24","dst":"10.10.0.2/32","proto":"tcp","ports":[5201,5201],"action":"allow"}]"#).unwrap();
    std::fs::write("/tmp/ra.json", "[]").unwrap();
    children.push(b.spawn(&[enf, "run", "--iface", "wg0", "--rules", "/tmp/rb.json",
                            "--pin-dir", "/sys/fs/bpf/aeth-b"]).unwrap());
    children.push(a.spawn(&[enf, "run", "--iface", "wg0", "--rules", "/tmp/ra.json",
                            "--pin-dir", "/sys/fs/bpf/aeth-a"]).unwrap());
    std::thread::sleep(std::time::Duration::from_secs(1));
    children.push(b.spawn(&["iperf3", "-s", "-p", "5201"]).unwrap());
    std::thread::sleep(std::time::Duration::from_millis(500));

    // A->B iperf: SYN passes B's allow rule; SYN-ACK arrives at A's tun
    // ingress, where NO rule allows it -- it must pass via A's
    // egress-recorded flow entry.
    assert!(
        a.exec(&["iperf3", "-c", "10.10.0.2", "-p", "5201", "-t", "2"]).is_ok(),
        "reply path through initiator-side flow table failed"
    );
    let sa = stats_pin(&a, enf, "/sys/fs/bpf/aeth-a");
    assert!(sa["flow_hit"].as_u64().unwrap() > 0, "A-side flow table never hit: {sa}");
    for c in &mut children { let _ = c.kill(); }
    drop(lab);
}
