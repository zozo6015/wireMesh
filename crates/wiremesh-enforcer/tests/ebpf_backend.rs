//! Task 7, Step 1 (test author): the one privileged smoke test for this
//! task -- proves `probe()` actually loads+attaches the real eBPF backend on
//! a live WireGuard tun device inside a netns, and that `apply()` of an
//! empty `PolicyIR` succeeds against that live attachment. Per
//! `.superpowers/sdd/task-7-brief.md`'s Step 1: "in a netns with a
//! veth-backed WireGuard pair (harness arrives fully in Task 12 -- for this
//! smoke test copy the spike's `wg_lab` helper inline as a `#[path]`-free
//! local `mod`), `probe("wg0", ..)` returns `BackendKind::Ebpf` and
//! `apply(&empty_ir)` succeeds."
//!
//! NOT `#[ignore]`d (per the brief and CLAUDE.md: "Host is macOS; all
//! code/tests run inside the privileged Linux container ... tun/eBPF/netns/
//! nftables do not work on the host" -- the dev container this always runs
//! in via `./dev.sh run` is always privileged).
//!
//! Requires `SPIKE_TUNNEL_BIN` to point at a built `spike-tunnel` release
//! binary, same as every spike/enforcer test (see
//! `docs/research/phase0-results.md`'s canonical command) -- e.g.:
//! ```text
//! ./dev.sh run "cd spike/tunnel && cargo build --release && cd /work && \
//!   SPIKE_TUNNEL_BIN=/work/spike/tunnel/target/release/spike-tunnel \
//!   cargo test -p wiremesh-enforcer --test ebpf_backend -- --test-threads=1 --nocapture"
//! ```
//!
//! RED evidence (current skeleton): `probe`'s body is `todo!()` (Task 7 Step
//! 1's skeleton, `src/lib.rs`) -- the test below panics with that message
//! (after successfully bringing up the lab) until Step 3 (implementer) fills
//! in the real eBPF loader in `src/ebpf.rs` (not yet created).

// Adapted inline copy of the canonical two-node WireGuard tunnel lab helper
// (spike/enforcer/enforcer/tests/common/mod.rs, itself adapted from
// spike/tunnel/tests/common/mod.rs) -- each spike crate (and now this crate,
// ahead of Task 12's graduated shared testkit harness) is standalone, so
// this is copied rather than depended on directly. `#[path]`-free per the
// brief: defined inline as its own module in this same file, not via
// `#[path = "..."] mod common;` pointing at a separate file.
mod lab {
    use natlab::{Lab, Ns};
    use std::io::Write;
    use std::process::Child;
    use std::{thread, time::Duration};

    fn wg_keypair() -> (String, String) {
        let priv_out = std::process::Command::new("wg")
            .arg("genkey")
            .output()
            .unwrap();
        let privkey = String::from_utf8(priv_out.stdout).unwrap().trim().to_string();
        let pub_out = {
            let mut c = std::process::Command::new("wg")
                .arg("pubkey")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            c.stdin.as_mut().unwrap().write_all(privkey.as_bytes()).unwrap();
            c.wait_with_output().unwrap()
        };
        (privkey.clone(), String::from_utf8(pub_out.stdout).unwrap().trim().to_string())
    }

    /// Returns a running lab: overlay 10.10.0.1 <-> 10.10.0.2 over underlay
    /// 10.9.1.0/24, with the spike-tunnel binary running in each namespace.
    /// Callers are responsible for killing the returned tunnel processes.
    pub fn wg_lab() -> (Lab, Ns, Ns, Vec<Child>) {
        let bin = std::env::var("SPIKE_TUNNEL_BIN").expect(
            "SPIKE_TUNNEL_BIN must be set to the path of the built spike-tunnel binary \
             (e.g. /work/spike/tunnel/target/release/spike-tunnel) -- this crate cannot use \
             CARGO_BIN_EXE_spike-tunnel from a different, standalone-workspace crate",
        );
        let bin = bin.as_str();
        let mut lab = Lab::new("aeth").unwrap();
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
            ns.exec(&[
                "wg", "set", "wg0", "listen-port", "51820", "private-key", &kf,
                "peer", peer_pub, "allowed-ips", &format!("{peer_ip}/32"),
                "endpoint", peer_ep,
            ]).unwrap();
            ns.exec(&["ip", "addr", "add", my_ip, "dev", "wg0"]).unwrap();
            ns.exec(&["ip", "link", "set", "wg0", "up", "mtu", "1280"]).unwrap();
        }

        (lab, a, b, vec![ta, tb])
    }
}

use lab::wg_lab;

/// Joins the CALLING OS thread to `ns_name`'s network namespace via
/// `setns(2)`/`CLONE_NEWNET`, so subsequent in-process library calls
/// (`probe`/`apply`) run as if executing inside that namespace -- the same
/// effect `ip netns exec` gets a subprocess (what the spike's binary-based
/// tests use instead), but there is no `wiremesh-enforcer` CLI binary here,
/// only the library. Safe to do from a test: libtest always runs each
/// `#[test]` fn on its own freshly spawned OS thread (true even under
/// `--test-threads=1`, which only bounds how many run *concurrently* -- see
/// CLAUDE.md's "Network tests are serial" rule), and Linux namespace
/// membership changed via `setns` is scoped to the calling thread alone, not
/// the whole process -- so this cannot leak into any other test.
///
/// Only joins the NETWORK namespace, not `b`'s private mount namespace
/// (`natlab::Ns::exec`/`spawn` additionally `nsenter --mount=...` for the
/// boringtun UAPI-socket collision reason documented in
/// `spike/natlab/src/lib.rs` -- irrelevant here since this test runs exactly
/// one enforcer instance, no concurrent same-named pins/sockets to
/// disambiguate).
fn join_netns(ns_name: &str) -> anyhow::Result<()> {
    use std::os::unix::io::AsRawFd;
    let path = format!("/var/run/netns/{ns_name}");
    let file = std::fs::File::open(&path)
        .map_err(|e| anyhow::anyhow!("open {path}: {e}"))?;
    let rc = unsafe { libc::setns(file.as_raw_fd(), libc::CLONE_NEWNET) };
    if rc != 0 {
        anyhow::bail!(
            "setns({path}, CLONE_NEWNET) failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

#[test]
fn probe_attaches_ebpf_and_applies_empty_policy_on_wg0() {
    let (lab, _a, b, mut children) = wg_lab();
    join_netns(&b.name).expect("join b's netns before probing wg0 in-process");

    let mut enforcer =
        wiremesh_enforcer::probe("wg0", wiremesh_enforcer::EnforcerConfig::default())
            .expect("probe should load + attach eBPF on wg0 inside the privileged dev container");
    assert_eq!(
        enforcer.kind(),
        wiremesh_enforcer::BackendKind::Ebpf,
        "the privileged dev container always has eBPF available -- probe must pick it, not \
         fall back to nftables"
    );

    let empty_ir = wiremesh_policy::PolicyIR {
        schema: 1,
        version: 0,
        blocks: vec![],
    };
    enforcer
        .apply(&empty_ir)
        .expect("apply of an empty policy IR should succeed");

    for c in &mut children {
        let _ = c.kill();
    }
    drop(lab);
}
