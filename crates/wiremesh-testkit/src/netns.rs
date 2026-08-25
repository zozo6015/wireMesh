//! `netns` — privileged Linux network-namespace test harness, graduated
//! (Task 12) from two previously-duplicated sources:
//!
//!  - `spike/natlab/src/lib.rs`'s `Lab`/`Ns`/`veth`/`NatKind`/`nat_router` —
//!    copied verbatim (see each item's doc comment below for the original
//!    rationale, preserved).
//!  - The kernel-WireGuard two-node lab helper (`wg_lab`) and the
//!    `setns(2)`-based `join_netns`, which lived as near-identical `mod lab`
//!    / `fn join_netns` copies in `crates/wiremesh-enforcer/tests/{ebpf_backend,
//!    generations,flow_table,deny_events}.rs` (one per Task 7/8/9/10) — this
//!    module is now the single source of truth those four files migrate to.
//!
//! Gated behind the `netns` cargo feature (see this crate's `Cargo.toml`) so
//! pure-userspace consumers of `wiremesh-testkit` (e.g. `wiremesh-controller`'s
//! own test suite, which never touches network namespaces) don't pull in
//! `libc` or compile any of this. Everything in this module requires Linux
//! (`CAP_NET_ADMIN`/`CAP_SYS_ADMIN` — i.e. the privileged dev container via
//! `./dev.sh run`, per `CLAUDE.md`'s "Host is macOS" execution rule); it will
//! not build, let alone run, on macOS or an unprivileged host.
//!
//! `wg_lab`'s one API change from its four duplicated originals: it now
//! takes an explicit `prefix: &str` argument (each of the four call sites
//! passed a distinct hardcoded `Lab::new` prefix — `"aeth"`, `"aeth8"`,
//! `"aeth9"`, `"aeth10"` — specifically so their netns/veth names never
//! collide with another test *binary*'s lab running concurrently; see
//! `deny_events.rs`'s original doc comment). A single shared function has to
//! keep that same collision-avoidance property, so the prefix moved from a
//! hardcoded literal to a caller-supplied parameter. Every other signature
//! (`Ns::exec`/`spawn`, `wg_lab(..) -> (Lab, Ns, Ns)`, `join_netns`) matches
//! the pre-graduation shape exactly.

use anyhow::{bail, Context, Result};
use std::io::Write;
use std::process::{Child, Command, Output, Stdio};

pub struct Lab {
    prefix: String,
    namespaces: Vec<String>,
}

#[derive(Clone)]
pub struct Ns {
    pub name: String,
    mountns: String,
}

fn run(cmd: &[&str]) -> Result<Output> {
    let out = Command::new(cmd[0])
        .args(&cmd[1..])
        .output()
        .with_context(|| format!("spawn {:?}", cmd))?;
    if !out.status.success() {
        bail!("{:?} failed: {}", cmd, String::from_utf8_lossy(&out.stderr));
    }
    Ok(out)
}

/// Directory holding one persistent mount-namespace reference file per `Ns`
/// (created via `unshare --mount=<file>`). `ip netns exec` only isolates the
/// *network* namespace — it does not give each namespace a private `/run`.
/// Filesystem-scoped daemons that key state off a fixed path under `/run`
/// (e.g. boringtun's WireGuard UAPI socket at `/var/run/wireguard/<ifname>.sock`,
/// see spike/tunnel's API-friction notes) would otherwise collide across
/// namespaces that use the same name. Giving each `Ns` its own persistent
/// mount namespace with a private `tmpfs` at `/var/run/wireguard` avoids that,
/// and mirrors how real gateway deployments are isolated (separate host/pod
/// per gateway, not just a separate network namespace).
const MOUNTNS_DIR: &str = "/run/natlab-mountns";

fn mountns_path(full_name: &str) -> String {
    format!("{MOUNTNS_DIR}/{full_name}")
}

impl Lab {
    pub fn new(prefix: &str) -> Result<Self> {
        Ok(Self {
            prefix: prefix.into(),
            namespaces: vec![],
        })
    }

    pub fn ns(&mut self, name: &str) -> Result<Ns> {
        let full = format!("{}-{}", self.prefix, name);
        run(&["ip", "netns", "add", &full])?;
        // Track immediately so Drop cleans up even if later steps fail.
        self.namespaces.push(full.clone());
        run(&[
            "ip", "netns", "exec", &full, "ip", "link", "set", "lo", "up",
        ])?;

        std::fs::create_dir_all(MOUNTNS_DIR).context("create natlab mountns dir")?;
        let mountns = mountns_path(&full);
        std::fs::File::create(&mountns).context("create mountns pin file")?;
        run(&[
            "unshare",
            &format!("--mount={mountns}"),
            "--",
            "bash",
            "-c",
            // --make-rprivate first: isolation must hold by construction, not
            // depend on the container's ambient mount-propagation default for
            // /run (if that were ever `shared`, the tmpfs would propagate to
            // sibling namespaces and silently reintroduce the wg0.sock
            // collision disguised as isolation).
            "mount --make-rprivate / && mkdir -p /var/run/wireguard && mount -t tmpfs tmpfs /var/run/wireguard",
        ])?;

        Ok(Ns {
            name: full,
            mountns,
        })
    }

    pub fn veth(&mut self, a: (&Ns, &str, &str), b: (&Ns, &str, &str)) -> Result<()> {
        let (na, ia, addra) = a;
        let (nb, ib, addrb) = b;
        // unique temp names to avoid collisions across parallel labs
        let ta = format!("{}0", self.prefix);
        let tb = format!("{}1", self.prefix);
        run(&[
            "ip", "link", "add", &ta, "type", "veth", "peer", "name", &tb,
        ])?;
        let setup = (|| -> Result<()> {
            run(&["ip", "link", "set", &ta, "netns", &na.name, "name", ia])?;
            run(&["ip", "link", "set", &tb, "netns", &nb.name, "name", ib])?;
            na.exec(&["ip", "addr", "add", addra, "dev", ia])?;
            nb.exec(&["ip", "addr", "add", addrb, "dev", ib])?;
            na.exec(&["ip", "link", "set", ia, "up"])?;
            nb.exec(&["ip", "link", "set", ib, "up"])?;
            Ok(())
        })();
        if let Err(e) = setup {
            // Best-effort reap of any end left in the root ns; deleting either
            // remaining end of a veth pair removes both. Exit status ignored.
            let deleted_ta = Command::new("ip")
                .args(["link", "del", &ta])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !deleted_ta {
                let _ = Command::new("ip").args(["link", "del", &tb]).status();
            }
            return Err(e);
        }
        Ok(())
    }
}

/// Which NAT mapping behavior a router cell exhibits, per the classic
/// STUN/RFC 4787 taxonomy. `PortRestricted` (endpoint-independent mapping,
/// port-restricted filtering) is what plain `masquerade` gives you; a real
/// symmetric NAT (endpoint-dependent mapping) requires per-destination port
/// randomization, which nftables approximates with `masquerade fully-random`.
#[derive(Clone, Copy)]
pub enum NatKind {
    PortRestricted,
    Symmetric,
}

impl Lab {
    /// Creates a router `Ns` with IPv4 forwarding enabled and an nftables
    /// masquerade rule installed on egress. Convention: callers wire the
    /// router's outside (public-facing) interface as `out0` and its inside
    /// (private-facing) interface as `in0` via `Lab::veth`.
    pub fn nat_router(&mut self, name: &str, kind: NatKind) -> Result<Ns> {
        self.nat_router_impl(name, kind)
    }

    /// Same as [`Lab::nat_router`], but additionally gives the router a
    /// `tc netem` delay on its outside interface (`out0`) — Phase-0 Finding
    /// 2: a zero-latency veth lab lets a peer's inbound PING arrive before
    /// the local side's own outbound packet has crossed its NAT, poisoning
    /// conntrack and producing a FALSE punch-failure for ~30s. Any Cycle-4b
    /// hole-punch test MUST have its NAT router(s) carry a delay like this
    /// (`delay_ms` around 20ms, i.e. ≈40ms one-way, matching real-world NAT
    /// traversal latencies) — see `docs/research/phase0-results.md`'s
    /// Finding 2 and this crate's `netem` test.
    ///
    /// `nft`'s `oifname "out0"` masquerade rule (installed by both this and
    /// plain `nat_router`) tolerates `out0` not existing yet at rule-install
    /// time — the kernel matches it dynamically once traffic actually flows
    /// — which is why the established convention (see `nat_router`'s own
    /// doc comment and `spike/natlab/tests/nat_behavior.rs`) is
    /// `nat_router(..)` THEN `Lab::veth(..)` to wire the real `out0`
    /// afterward. `tc qdisc add` has no such tolerance: it hard-fails with
    /// "Cannot find device" if `out0` doesn't exist yet (confirmed by
    /// hand), so it cannot be bolted onto that same before-`veth` step. This
    /// method instead gives the router a placeholder `out0` (a `dummy`
    /// netdev, brought up immediately) purely so the delay is present and
    /// independently verifiable (`assert_netem_present`/`netem_present`)
    /// without requiring a full external topology — enough for exercising
    /// the harness capability in isolation, as this crate's own `netem`
    /// test does.
    ///
    /// A REAL dual-NAT hole-punch topology needs genuine connectivity
    /// through `out0`, not a dummy: for that, use plain `nat_router`, wire
    /// the real `out0` via `Lab::veth` (do NOT also call
    /// `nat_router_delayed` on that router — its placeholder `out0` would
    /// collide with `Lab::veth`'s rename-into-place and fail), and once
    /// that real interface exists call [`apply_netem`] directly — the same
    /// helper this method uses internally.
    pub fn nat_router_delayed(&mut self, name: &str, kind: NatKind, delay_ms: u32) -> Result<Ns> {
        let ns = self.nat_router_impl(name, kind)?;
        ns.exec(&["ip", "link", "add", "out0", "type", "dummy"])?;
        ns.exec(&["ip", "link", "set", "out0", "up"])?;
        apply_netem(&ns, "out0", delay_ms)?;
        Ok(ns)
    }

    fn nat_router_impl(&mut self, name: &str, kind: NatKind) -> Result<Ns> {
        let ns = self.ns(name)?;
        ns.exec(&["sysctl", "-w", "net.ipv4.ip_forward=1"])?;
        let flags = match kind {
            NatKind::PortRestricted => "",
            NatKind::Symmetric => " fully-random",
        };
        // nft's block syntax needs a newline (or semicolon) between the
        // `type nat hook ...` chain header and the rule that follows it, and
        // will not accept a bare `;}}` — closing braces must be preceded by
        // a statement terminator on their own line. A fully inline one-liner
        // (`{ ... ; } }`) fails with "syntax error, unexpected '}'".
        let ruleset = format!(
            "table ip nat {{\n  chain post {{\n    type nat hook postrouting priority 100;\n    oifname \"out0\" masquerade{flags};\n  }}\n}}\n"
        );
        let ruleset_path = format!("/tmp/{}.nft", ns.name);
        std::fs::write(&ruleset_path, &ruleset)
            .with_context(|| format!("write nft ruleset {ruleset_path}"))?;
        ns.exec(&["nft", "-f", &ruleset_path])?;
        Ok(ns)
    }
}

/// Applies a `tc netem` delay qdisc to `iface` inside `ns`. `iface` must
/// already exist as a real net device (e.g. already wired via `Lab::veth`,
/// or a placeholder like [`Lab::nat_router_delayed`]'s dummy `out0`) —
/// unlike nft's `oifname` matching, `tc qdisc add` hard-fails ("Cannot find
/// device") against a not-yet-existing interface, so this is deliberately a
/// separate step from ns/NAT creation rather than folded into it.
pub fn apply_netem(ns: &Ns, iface: &str, delay_ms: u32) -> Result<()> {
    let delay_arg = format!("{delay_ms}ms");
    ns.exec(&[
        "tc", "qdisc", "add", "dev", iface, "root", "netem", "delay", &delay_arg,
    ])?;
    Ok(())
}

/// Runs `tc qdisc show dev {iface}` inside `ns` and reports whether a
/// `netem` qdisc is present — lets a punch test assert delay fidelity
/// (Phase-0 Finding 2, see [`Lab::nat_router_delayed`]'s doc comment)
/// before it starts punching, rather than silently running on a
/// zero-latency link if the qdisc install were ever skipped/dropped. A
/// nonexistent `iface` (e.g. a plain `nat_router`'s never-wired `out0`)
/// reports `Ok(false)` rather than an error — no device trivially means no
/// netem on it.
pub fn netem_present(ns: &Ns, iface: &str) -> Result<bool> {
    match ns.exec(&["tc", "qdisc", "show", "dev", iface]) {
        Ok(out) => Ok(String::from_utf8_lossy(&out.stdout).contains("netem")),
        Err(_) => Ok(false),
    }
}

/// Asserts [`netem_present`] is true, panicking with the actual `tc qdisc
/// show` output (or the lookup error, if `iface` doesn't exist) on failure
/// so a failed assertion is immediately diagnosable without a second manual
/// `tc` invocation.
pub fn assert_netem_present(ns: &Ns, iface: &str) {
    match ns.exec(&["tc", "qdisc", "show", "dev", iface]) {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            assert!(
                text.contains("netem"),
                "expected netem qdisc on {iface} in {}, got: {text}",
                ns.name
            );
        }
        Err(e) => panic!("expected netem qdisc on {iface} in {}, but: {e}", ns.name),
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        for ns in &self.namespaces {
            let _ = Command::new("ip").args(["netns", "del", ns]).status();
            let mountns = mountns_path(ns);
            let _ = Command::new("umount").arg(&mountns).status();
            let _ = std::fs::remove_file(&mountns);
        }
    }
}

impl Ns {
    /// `nsenter --mount=<pin>` enters this Ns's private, persistent mount
    /// namespace *before* handing off to `ip netns exec`, so the private
    /// `/var/run/wireguard` tmpfs (set up in `Lab::ns`) is part of the mount
    /// table `ip netns exec`'s own internal unshare(CLONE_NEWNS) copies —
    /// see the `MOUNTNS_DIR` doc comment above.
    pub fn exec(&self, cmd: &[&str]) -> Result<Output> {
        let mount_arg = format!("--mount={}", self.mountns);
        let mut full = vec![
            "nsenter", &mount_arg, "--", "ip", "netns", "exec", &self.name,
        ];
        full.extend_from_slice(cmd);
        run(&full)
    }
    pub fn spawn(&self, cmd: &[&str]) -> Result<Child> {
        Command::new("nsenter")
            .arg(format!("--mount={}", self.mountns))
            .args(["--", "ip", "netns", "exec", &self.name])
            .args(cmd)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawn in netns")
    }
}

/// Generates a fresh WireGuard keypair (private, public) via the `wg`
/// CLI — graduated verbatim from the four enforcer test files' identical
/// `wg_keypair` helper.
fn wg_keypair() -> (String, String) {
    let priv_out = Command::new("wg").arg("genkey").output().unwrap();
    let privkey = String::from_utf8(priv_out.stdout)
        .unwrap()
        .trim()
        .to_string();
    let pub_out = {
        let mut c = Command::new("wg")
            .arg("pubkey")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        c.stdin
            .as_mut()
            .unwrap()
            .write_all(privkey.as_bytes())
            .unwrap();
        c.wait_with_output().unwrap()
    };
    (
        privkey.clone(),
        String::from_utf8(pub_out.stdout)
            .unwrap()
            .trim()
            .to_string(),
    )
}

/// Returns a running lab: overlay `10.10.0.1 <-> 10.10.0.2` over underlay
/// `10.9.1.0/24`, `wg0` created via the KERNEL WireGuard implementation
/// directly inside each namespace (`ip link add wg0 type wireguard`) — no
/// userspace tunnel process involved, so there is nothing for the caller to
/// kill afterward (unlike the Phase-0 spike's boringtun-backed version, see
/// `spike/enforcer/enforcer/tests/common/mod.rs`).
///
/// `prefix` becomes the `Lab::new` prefix (and thus every netns/veth name
/// this lab creates) — callers MUST pass a prefix distinct from any other
/// test binary's, since separate `cargo test` integration-test binaries can
/// run concurrently as separate processes even under `--test-threads=1`
/// (which only bounds *intra*-process thread concurrency — see `CLAUDE.md`'s
/// "Network tests are serial" rule and each pre-graduation caller's own
/// `Lab::new` doc comment for the collision this avoids).
///
/// `allowed-ips` is WireGuard cryptokey routing's OWN allow-list, fully
/// independent of (and evaluated before) anything a `wiremesh-enforcer`
/// backend ever sees: a packet whose src (outbound) or claimed src
/// (inbound) falls outside it is silently dropped by the kernel WG
/// implementation itself, never reaching `wg0`'s tc classifier/nft ruleset
/// at all. Set to the whole overlay `10.10.0.0/24` (not just the bare peer
/// host `/32`) — root-caused via a bare `ping -I <alias>` repro, zero
/// enforcer involvement — so callers that source traffic from secondary IP
/// aliases on `wg0` (e.g. LPM/rate-cap tests binding extra addresses in
/// addition to the primary `10.10.0.1`/`10.10.0.2`) actually reach the peer
/// instead of being dropped before any backend ever runs.
pub fn wg_lab(prefix: &str) -> (Lab, Ns, Ns) {
    let mut lab = Lab::new(prefix).unwrap();
    let a = lab.ns("a").unwrap();
    let b = lab.ns("b").unwrap();
    lab.veth((&a, "u0", "10.9.1.1/24"), (&b, "u1", "10.9.1.2/24"))
        .unwrap();

    let (apriv, apub) = wg_keypair();
    let (bpriv, bpub) = wg_keypair();

    for (ns, privkey, peer_pub, my_ip, _peer_ip, peer_ep) in [
        (
            &a,
            &apriv,
            &bpub,
            "10.10.0.1/24",
            "10.10.0.2",
            "10.9.1.2:51820",
        ),
        (
            &b,
            &bpriv,
            &apub,
            "10.10.0.2/24",
            "10.10.0.1",
            "10.9.1.1:51820",
        ),
    ] {
        ns.exec(&["ip", "link", "add", "wg0", "type", "wireguard"])
            .unwrap();
        let kf = format!("/tmp/{}.key", ns.name);
        std::fs::write(&kf, privkey).unwrap();
        ns.exec(&[
            "wg",
            "set",
            "wg0",
            "listen-port",
            "51820",
            "private-key",
            &kf,
            "peer",
            peer_pub,
            "allowed-ips",
            "10.10.0.0/24",
            "endpoint",
            peer_ep,
        ])
        .unwrap();
        ns.exec(&["ip", "addr", "add", my_ip, "dev", "wg0"])
            .unwrap();
        ns.exec(&["ip", "link", "set", "wg0", "up", "mtu", "1280"])
            .unwrap();
    }

    (lab, a, b)
}

/// Joins the CALLING OS thread to `ns_name`'s network namespace via
/// `setns(2)`/`CLONE_NEWNET`, so subsequent in-process library calls
/// (`probe`/`apply`) run as if executing inside that namespace — the same
/// effect `ip netns exec` gets a subprocess, but there is no
/// `wiremesh-enforcer` CLI binary, only the library. Safe to do from a
/// test: libtest always runs each `#[test]` fn on its own freshly spawned OS
/// thread (true even under `--test-threads=1`, which only bounds how many
/// run *concurrently* — see `CLAUDE.md`'s "Network tests are serial" rule),
/// and Linux namespace membership changed via `setns` is scoped to the
/// calling thread alone, not the whole process — so this cannot leak into
/// any other test.
///
/// Only joins the NETWORK namespace, not the target `Ns`'s private mount
/// namespace (`Ns::exec`/`spawn` additionally `nsenter --mount=...` for a
/// boringtun UAPI-socket collision reason documented on `MOUNTNS_DIR` above
/// — moot for the kernel-WireGuard `wg_lab` above, which never uses
/// boringtun, but harmless either way since callers run exactly one
/// enforcer instance per joined namespace, no concurrent same-named
/// pins/sockets to disambiguate).
pub fn join_netns(ns_name: &str) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    let path = format!("/var/run/netns/{ns_name}");
    let file = std::fs::File::open(&path).map_err(|e| anyhow::anyhow!("open {path}: {e}"))?;
    let rc = unsafe { libc::setns(file.as_raw_fd(), libc::CLONE_NEWNET) };
    if rc != 0 {
        bail!(
            "setns({path}, CLONE_NEWNET) failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

/// Joins the calling OS thread to `ns`'s network namespace (as `join_netns`
/// does) AND its private, persistent mount namespace (pinned at `Lab::ns`
/// time — see `MOUNTNS_DIR`'s doc comment). `join_netns` alone is sufficient
/// for every existing in-process caller because they either run a single
/// enforcer instance per joined namespace (no same-named socket to collide
/// with) or drive kernel WireGuard (`wg_lab`), which never touches
/// `/var/run/wireguard` at all.
///
/// It is NOT sufficient for two *simultaneous, in-process* boringtun
/// devices that share an interface name (e.g. two gateways each running
/// `wg0`): boringtun's UAPI control socket is keyed by the fixed path
/// `/var/run/wireguard/<ifname>.sock`, and plain `join_netns` only switches
/// `CLONE_NEWNET` — the mount namespace (and therefore that path) stays the
/// process's ambient one, so both devices would bind/connect to the exact
/// same socket file and cross-configure each other. This function additionally
/// `setns(CLONE_NEWNS)`s into `ns`'s pinned mount namespace, which has its
/// own private tmpfs at `/var/run/wireguard`, giving each `Ns` a truly
/// isolated boringtun UAPI socket — the in-process equivalent of what
/// `Ns::exec`/`spawn`'s `nsenter --mount=...` already does for subprocesses.
pub fn join_netns_and_mountns(ns: &Ns) -> Result<()> {
    join_netns(&ns.name)?;
    use std::os::unix::io::AsRawFd;
    // setns(CLONE_NEWNS) refuses a thread whose fs_struct (root dir, cwd,
    // umask) is still shared with sibling threads — true by default for any
    // Rust thread spawned via std::thread::spawn, which clones with
    // CLONE_FS like any other pthread (errno EINVAL; see `man 2 setns`).
    // unshare(CLONE_FS) gives this thread its own private fs_struct first.
    let rc = unsafe { libc::unshare(libc::CLONE_FS) };
    if rc != 0 {
        bail!(
            "unshare(CLONE_FS) failed: {}",
            std::io::Error::last_os_error()
        );
    }
    let file = std::fs::File::open(&ns.mountns)
        .map_err(|e| anyhow::anyhow!("open {}: {e}", ns.mountns))?;
    let rc = unsafe { libc::setns(file.as_raw_fd(), libc::CLONE_NEWNS) };
    if rc != 0 {
        bail!(
            "setns({}, CLONE_NEWNS) failed: {}",
            ns.mountns,
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}
