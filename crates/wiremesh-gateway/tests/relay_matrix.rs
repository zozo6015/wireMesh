//! Cycle 4c Task 9 done-bar (design spec §2 case 1 / §7 conformance): the
//! RELAY netns-conformance milestone. Two REAL `wiremesh-gateway` binary
//! processes, each behind its OWN **symmetric** NAT router (the brokered
//! simultaneous hole punch genuinely CANNOT succeed against that NAT kind —
//! Cycle 4b's `nat_matrix.rs` `case2_symmetric_relay_needed` already proves
//! the punch fails and the path SM reaches the relay-needed verdict), form a
//! working overlay path by falling back to the real `wiremesh-relay` QUIC
//! relay that the controller enrolls and advertises over Sync. This
//! graduates `spike/relay/tests/wg_over_relay.rs`'s "relay is the only path"
//! proof (Phase 0, Bet 3) into full gateway+controller+relay conformance,
//! the way `nat_matrix.rs` graduated `spike/natpunch`'s punch proof in
//! Cycle 4b.
//!
//! Also here (Cycle 4c Task 10 done-bar, §2 case 3): `case3_relay_
//! eviction_repaths_to_second_relay`, which extends the same topology with a
//! SECOND relay and proves the pair survives losing R1 by re-pathing onto R2
//! — Task 6's controller eviction + Task 8's gateway re-path exercised
//! end-to-end, for the first time, under netns. See that test fn's own doc
//! comment for the eviction mechanism and why.
//!
//! ./dev.sh run "cargo test -p wiremesh-gateway --test relay_matrix \
//!   --features netns-tests -- --test-threads=1 --nocapture"
//!
//! (Deliberately `--test relay_matrix`, not the whole crate: this and
//! `nat_matrix.rs` each build their OWN root-netns bridge/veth names: running
//! two `netns-tests` binaries concurrently in the same root netns would
//! collide on interface creation. Same convention `nat_matrix.rs` documents.)
//!
//! ## Topology
//!
//! Root netns = the "internet". The in-process controller AND the in-process
//! relay (both just plain sockets bound in the root netns, exactly like
//! `nat_matrix.rs`'s in-process controller) share bridge `wmrbr0`, so both
//! are reachable from either NAT'd gateway the same way the controller
//! already is in Cycle 4b's conformance. Each gateway sits behind its own
//! **symmetric** NAT router (masquerade `fully-random`: a fresh, unguessable
//! external port per NEW conntrack entry — the property that breaks
//! hole-punch coordinate-guessing, per Cycle 4b's `NatKind::Symmetric`) whose
//! `out0` carries the MANDATORY `tc netem delay 20ms` (Phase-0 Finding 2: a
//! zero-latency lab produces false punch results). There is deliberately NO
//! route from gwA's or gwB's private subnet to the other's — the only shared
//! reachable point is the bridge, where the controller and relay sit:
//!
//! ```text
//!   root netns (test process + in-process controller @ 198.51.100.1
//!               + in-process relay @ 198.51.100.4:5555)
//!                        bridge wmrbr0
//!               |                                       |
//!        out0 198.51.100.2/24 (netem 20ms)      out0 198.51.100.3/24 (netem 20ms)
//!            ra netns [NAT, symmetric]              rb netns [NAT, symmetric]
//!        in0 192.168.80.1/24                     in0 192.168.81.1/24
//!               |                                       |
//!   gwA nat0 192.168.80.2/24                gwB nat0 192.168.81.2/24
//!   gwA seg0 10.10.11.1/24                   gwB seg0 10.10.12.1/24
//!        wg0 <== relayed via 198.51.100.4:5555, direct-punch impossible ==> wg0
//!         |                                                             |
//!   wlA eth0 10.10.11.2/24 (seg-a)                wlB eth0 10.10.12.2/24 (seg-b)
//! ```
//!
//! ## The relay's identity — a real finding, not a testkit gap
//!
//! The gateway's relay client (`wiremesh_gateway::relay::RelayTransport` ->
//! `wiremesh_relay::Client::connect_with_pems`) dials the relay with
//! `wiremesh_relay`'s hardcoded `RELAY_SERVER_NAME = "relay"` as both the
//! QUIC SNI and the rustls hostname-verification target, and trusts it
//! against `Identity.ca_bundle_pem` — i.e. it expects the relay's QUIC
//! server cert to carry `"relay"` as a Subject Alternative Name, chained to
//! the CONTROLLER's own CA (the same CA that issued the gateway's own
//! cert). This test enrolls the relay through the REAL controller
//! (`Enrollment.Enroll` with a non-empty `endpoint`, exactly like
//! `wiremesh-testkit`'s existing `enroll_relay` helper, inlined here because
//! that helper discards the CSR's private key and this test needs to
//! actually RUN a relay, not just register one) — but
//! `wiremesh-trust::EmbeddedTrust::sign` (the function that path calls)
//! unconditionally does `params.subject_alt_names.clear()` before signing
//! ANY CSR, gateway or relay. A cert with zero SANs fails rustls's webpki
//! hostname check outright (no CN fallback) regardless of what CN the
//! subject carries. **This is expected to be the reason this test is RED**:
//! `RelayTransport::start` will fail its QUIC handshake against a
//! controller-issued relay cert until the signing path gives a
//! `relay`-kind CSR a `"relay"` SAN (or some other fix that makes the
//! hostname check pass) — that fix, plus anything else this surfaces (e.g.
//! a make-before-break gating bug on the Relayed<->Direct cutover, mirroring
//! Cycle 4b Task 11's rx-liveness fix), is this task's implementation work,
//! not this test's.
//!
//! No new `wiremesh-testkit` helper is assumed beyond what already exists
//! (`gen_csr`, `TestController::{admin_client, enrollment_client, apply,
//! sync_tcp_addr, observe_addr}`, `StubGateway::enroll_with_wg_pubkey`,
//! `netns::{Lab, Ns, NatKind, apply_netem, assert_netem_present}`) — the
//! relay's own enrollment is done inline below (see
//! `enroll_and_spawn_relay`) precisely because it needs the private key
//! `wiremesh-testkit::enroll_relay` throws away. The real
//! `wiremesh-relay` server is run IN-PROCESS via `wiremesh_relay::spawn_server`
//! (the same public API `tests/relay_transport.rs` already uses), bound
//! directly on the bridge — exactly how the in-process `TestController`
//! already sits on this same bridge in every `netns-tests` conformance test.
#![cfg(feature = "netns-tests")]

use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use wiremesh_gateway::identity::Identity;
use wiremesh_gateway::uapi::base64_pub_from_priv;
use wiremesh_proto::v1::{EnrollRequest, MintTokenRequest};
use wiremesh_testkit::netns::{apply_netem, assert_netem_present, Lab, NatKind, Ns};
use wiremesh_testkit::{gen_csr, StubGateway, TestController};

const GW_BIN: &str = env!("CARGO_BIN_EXE_wiremesh-gateway");
const BRIDGE: &str = "wmrbr0";
const CTRL_IP: &str = "198.51.100.1";
/// The relay's bind address on the SAME bridge as the controller — reachable
/// from both NAT'd gateways over the masquerade, exactly like `CTRL_IP` is.
/// A fixed (not ephemeral) port so the address can be handed to
/// `Enrollment.Enroll` BEFORE the relay endpoint is actually bound (the
/// relay's own cert, needed to bind, is itself the enrollment's output —
/// see `enroll_and_spawn_relay`'s doc comment for why the ordering has to
/// go "pick the address, enroll, THEN bind").
const RELAY_ADDR: &str = "198.51.100.4:5555";
/// A second relay's bind address (Cycle 4c Task 10,
/// `case3_relay_eviction_repaths_to_second_relay`): that case advertises TWO
/// relays so a killed/evicted R1 (`RELAY_ADDR`) has somewhere for
/// `ensure_relay_transport`'s per-peer round-robin cursor to land next (see
/// that fn's doc comment). Unused by `case1_symmetric_pair_flows_over_relay`,
/// which only ever advertises `RELAY_ADDR`.
const RELAY_ADDR_2: &str = "198.51.100.5:5556";
const METRICS_PORT: u16 = 9099;
const WG_PORT: u16 = 51820;

/// Fabric: seg-a -> seg-b, allow icmp only (default-deny otherwise). A ping
/// crossing proves both that the tunnel actually carries data AND that the
/// enforcer is live on the relayed path — same evidentiary role
/// `nat_matrix.rs`'s tcp/8080 rule plays for the direct path, just with the
/// workload primitive the done-bar case actually asks for (a ping).
const FABRIC: &str = r#"
segments:
  - name: seg-a
    cidrs: ["10.10.11.0/24"]
  - name: seg-b
    cidrs: ["10.10.12.0/24"]
policy:
  - from: seg-a
    to: seg-b
    rules:
      - allow: { proto: icmp }
"#;

// --- root-netns shell helpers ------------------------------------------------

fn run_root(args: &[&str]) {
    let out = Command::new(args[0])
        .args(&args[1..])
        .output()
        .unwrap_or_else(|e| panic!("spawn {args:?}: {e}"));
    if !out.status.success() {
        panic!("{args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
    }
}

fn run_root_best_effort(args: &[&str]) {
    let _ = Command::new(args[0]).args(&args[1..]).status();
}

/// Host-side veth ends parked on the root bridge (one per NAT router).
const HOST_ENDS: [&str; 2] = ["wmriah", "wmribh"];

/// Deletes any leftover bridge/host-veths from a prior run, then builds the
/// internet bridge carrying BOTH the controller's and the relay's routable
/// IPs in the root netns.
fn setup_bridge() {
    for h in HOST_ENDS {
        run_root_best_effort(&["ip", "link", "del", h]);
    }
    run_root_best_effort(&["ip", "link", "del", BRIDGE]);
    run_root(&["ip", "link", "add", BRIDGE, "type", "bridge"]);
    run_root(&["ip", "addr", "add", &format!("{CTRL_IP}/24"), "dev", BRIDGE]);
    run_root(&["ip", "addr", "add", RELAY_ADDR_CIDR, "dev", BRIDGE]);
    // Always added (harmless if unused): see `RELAY_ADDR_2`'s doc comment.
    // Only case 3 actually enrolls+advertises a relay at this address, but
    // giving every test's bridge both addresses up front means case 3 needs
    // no bridge-setup variant of its own.
    run_root(&["ip", "addr", "add", RELAY_ADDR_2_CIDR, "dev", BRIDGE]);
    run_root(&["ip", "link", "set", BRIDGE, "up"]);
}

/// `RELAY_ADDR`'s host, reformatted as a `/24` for `ip addr add` (a second
/// address on the same bridge, alongside `CTRL_IP`).
const RELAY_ADDR_CIDR: &str = "198.51.100.4/24";
/// `RELAY_ADDR_2`'s host, reformatted as a `/24` — see `RELAY_ADDR_2`'s doc
/// comment.
const RELAY_ADDR_2_CIDR: &str = "198.51.100.5/24";

/// Best-effort teardown of the root-netns bridge + host-side veth ends (the
/// child-netns ends go away with the `Lab`'s netns). Runs even on panic.
struct RootNetGuard;
impl Drop for RootNetGuard {
    fn drop(&mut self) {
        for h in HOST_ENDS {
            run_root_best_effort(&["ip", "link", "del", h]);
        }
        run_root_best_effort(&["ip", "link", "del", BRIDGE]);
    }
}

/// Wires a veth from the root bridge into router netns `ns`, naming the
/// moved end `ifname` (must be `out0` for the router's masquerade + netem)
/// and addressing it `cidr`.
fn attach_bridge(ns: &Ns, host_end: &str, ns_end_tag: &str, ifname: &str, cidr: &str) {
    let tmp = format!("wmri{ns_end_tag}n");
    run_root(&["ip", "link", "add", host_end, "type", "veth", "peer", "name", &tmp]);
    run_root(&["ip", "link", "set", host_end, "master", BRIDGE]);
    run_root(&["ip", "link", "set", host_end, "up"]);
    run_root(&["ip", "link", "set", &tmp, "netns", &ns.name]);
    ns.exec(&["ip", "link", "set", &tmp, "down"])
        .unwrap_or_else(|e| panic!("down {ifname}: {e}"));
    ns.exec(&["ip", "link", "set", &tmp, "name", ifname])
        .unwrap_or_else(|e| panic!("rename to {ifname}: {e}"));
    ns.exec(&["ip", "addr", "add", cidr, "dev", ifname])
        .unwrap_or_else(|e| panic!("addr {cidr} on {ifname}: {e}"));
    ns.exec(&["ip", "link", "set", ifname, "up"])
        .unwrap_or_else(|e| panic!("up {ifname}: {e}"));
}

// --- WireGuard identity provisioning ----------------------------------------

fn wg_keypair() -> (String, String) {
    let priv_b64 = String::from_utf8(Command::new("wg").arg("genkey").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_string();
    let pub_b64 = base64_pub_from_priv(&priv_b64).expect("derive wg pubkey");
    (priv_b64, pub_b64)
}

/// Mints a gateway token bound to `cidr` and enrolls a gateway carrying the
/// real `wg_pub` into the ALREADY-EXISTING segment (created by the fabric
/// apply).
async fn enroll_into(h: &TestController, cidr: &str, wg_pub: &str) -> StubGateway {
    let token = h
        .admin_client()
        .await
        .mint_token(MintTokenRequest {
            kind: "gateway".to_string(),
            bound_cidrs: vec![cidr.to_string()],
            rebind_segment_id: 0,
        })
        .await
        .expect("Admin.MintToken")
        .into_inner()
        .token;
    StubGateway::enroll_with_wg_pubkey(h, &token, &[cidr], wg_pub)
        .await
        .expect("enroll gateway with wg pubkey")
}

fn write_identity(gw: &StubGateway, wg_priv: &str, dir: &Path) {
    let id = Identity {
        cert_pem: gw.cert_pem().to_string(),
        key_pem: gw.key_pem().to_string(),
        ca_bundle_pem: gw.ca_bundle_pem().to_string(),
        gateway_id: gw.id(),
        observe_key: gw.observe_key(),
        wg_private_key_b64: wg_priv.to_string(),
    };
    id.store(dir).expect("store gateway identity");
}

// --- the relay: real controller enrollment + a real in-process QUIC server -

/// Enrolls a relay through the REAL controller (`Enrollment.Enroll`, relay
/// path: non-empty `endpoint`, exactly what makes `EnrollmentSvc::enroll`
/// register an `active` relay row AND immediately advertise it in a `Delta`
/// to every connected gateway) at `addr`, then writes the issued identity
/// into a fresh certdir as `relay.pem`/`relay.key`/`ca.pem` — the file
/// layout both `wiremesh_relay::server_config` and
/// `server_config_with_denylist` expect. Shared front half of
/// `enroll_and_spawn_relay` (case 1, and case 3's R2) and
/// `enroll_and_spawn_killable_relay` (case 3's R1 — Cycle 4c Task 10).
///
/// Inlined rather than using `wiremesh_testkit::enroll_relay` because that
/// helper discards the CSR's private key (by design — see its doc comment:
/// no relay-side test needed to actually RUN a relay before this one).
async fn enroll_relay_certs(h: &TestController, addr: &str, csr_tag: &str) -> tempfile::TempDir {
    let token = h
        .admin_client()
        .await
        .mint_token(MintTokenRequest {
            kind: "relay".to_string(),
            bound_cidrs: vec![],
            rebind_segment_id: 0,
        })
        .await
        .expect("Admin.MintToken (relay)")
        .into_inner()
        .token;

    let (csr_pem, key_pair) = gen_csr(csr_tag);
    let resp = h
        .enrollment_client()
        .await
        .enroll(EnrollRequest {
            token,
            csr_pem,
            cidrs: vec![],
            wg_pubkey: String::new(),
            endpoint: addr.to_string(),
        })
        .await
        .expect("Enrollment.Enroll (relay path)")
        .into_inner();

    let certdir = tempfile::tempdir().expect("relay certdir");
    std::fs::write(certdir.path().join("relay.pem"), &resp.cert_pem).expect("write relay.pem");
    std::fs::write(certdir.path().join("relay.key"), key_pair.serialize_pem())
        .expect("write relay.key");
    std::fs::write(certdir.path().join("ca.pem"), &resp.ca_bundle_pem).expect("write ca.pem");
    eprintln!("enroll_relay_certs: relay_id={} addr={addr}", resp.gateway_id);

    certdir
}

/// Enrolls (via [`enroll_relay_certs`]) and starts the real
/// `wiremesh_relay::serve` loop on `addr` via `wiremesh_relay::spawn_server`
/// — the same public embedding API `tests/relay_transport.rs` (Task 7)
/// already exercises, just bound on the shared bridge instead of loopback so
/// the NAT'd gateways can actually reach it. Returns the certdir (kept alive
/// for the relay's lifetime) and the `spawn_server` task handle.
async fn enroll_and_spawn_relay(
    h: &TestController,
    addr: &str,
    csr_tag: &str,
) -> (tempfile::TempDir, tokio::task::JoinHandle<()>) {
    let certdir = enroll_relay_certs(h, addr, csr_tag).await;
    let bind: std::net::SocketAddr = addr.parse().expect("relay addr must parse");
    let (bound_addr, handle) = wiremesh_relay::spawn_server(bind, certdir.path())
        .await
        .unwrap_or_else(|e| panic!("spawn_server on {addr}: {e}"));
    assert_eq!(
        bound_addr, bind,
        "relay must bind exactly the enrolled/advertised endpoint"
    );
    eprintln!("enroll_and_spawn_relay: listening on {bound_addr}");

    (certdir, handle)
}

/// Like [`enroll_and_spawn_relay`], but builds its own `quinn::Endpoint`
/// (via the same public `wiremesh_relay::server_config` +
/// `wiremesh_relay::serve` functions `spawn_server` composes internally)
/// instead of going through `spawn_server`, and returns that `Endpoint`
/// alongside the certdir/task handle (Cycle 4c Task 10, case 3's R1).
///
/// Why: case 3 needs to EVICT a relay out from under two already-connected
/// gateways and prove they re-path onto a second one.
/// `wiremesh_relay::spawn_server`'s returned `JoinHandle` covers only
/// `serve`'s outer accept loop — `serve` spawns each accepted connection's
/// own registration+forwarding loop as a SEPARATE, independent
/// `tokio::spawn`ed task (see `wiremesh_relay::serve`'s body), so aborting
/// that handle would leave an already-registered relayed session running
/// completely untouched; it would not be a genuine eviction. `quinn::
/// Endpoint::close` instead immediately closes EVERY connection currently
/// open on the endpoint (sending each a real QUIC `CONNECTION_CLOSE`
/// frame) and rejects new ones — a real, observable severance both
/// gateways' `RelayTransport::is_healthy` (`Client::is_alive`,
/// `conn.close_reason().is_none()`) will see essentially immediately,
/// rather than waiting on `transport_config`'s 30s `max_idle_timeout`. This
/// also sidesteps spawning the real `relay` binary as a cross-crate
/// subprocess: `tests/relay_transport.rs`'s own doc comment already notes
/// that `CARGO_BIN_EXE_relay` cross-crate lookup doesn't apply from this
/// crate (`relay` is a bin target of `wiremesh-relay`, a dependency, not a
/// bin `wiremesh-gateway` owns — Cargo only auto-builds/exposes
/// `CARGO_BIN_EXE_<name>` for a package's OWN bin targets).
async fn enroll_and_spawn_killable_relay(
    h: &TestController,
    addr: &str,
    csr_tag: &str,
) -> (tempfile::TempDir, quinn::Endpoint, tokio::task::JoinHandle<()>) {
    let certdir = enroll_relay_certs(h, addr, csr_tag).await;
    let bind: std::net::SocketAddr = addr.parse().expect("relay addr must parse");
    let cfg = wiremesh_relay::server_config(certdir.path()).expect("relay server_config");
    let endpoint = quinn::Endpoint::server(cfg, bind)
        .unwrap_or_else(|e| panic!("binding killable relay endpoint on {addr}: {e}"));
    let bound_addr = endpoint.local_addr().expect("reading bound relay endpoint address");
    assert_eq!(
        bound_addr, bind,
        "killable relay must bind exactly the enrolled/advertised endpoint"
    );
    let handle = tokio::spawn(wiremesh_relay::serve(endpoint.clone()));
    eprintln!("enroll_and_spawn_killable_relay: listening on {bound_addr}");

    (certdir, endpoint, handle)
}

/// Which kind of relay to enroll+run for a given [`build_scenario`] slot —
/// case 1 uses a single `InProcess` relay (unchanged behavior from before
/// Cycle 4c Task 10); case 3 needs a `Killable` relay for R1 specifically
/// (see [`enroll_and_spawn_killable_relay`]'s doc comment for why) plus a
/// second, ordinary `InProcess` one for R2.
enum RelaySpec<'a> {
    InProcess { addr: &'a str, csr_tag: &'a str },
    Killable { addr: &'a str, csr_tag: &'a str },
}

/// A running relay, however it was started — kept alive for the
/// [`Scenario`]'s lifetime (or, for `Killable`, evicted early by case 3).
enum RelayHandle {
    InProcess(tempfile::TempDir, tokio::task::JoinHandle<()>),
    Killable(tempfile::TempDir, quinn::Endpoint, tokio::task::JoinHandle<()>),
}

impl RelayHandle {
    /// Force-closes every connection on a `Killable` relay's endpoint — case
    /// 3's R1 eviction. Panics on `InProcess` (no case needs to evict one of
    /// those; keeping this method total per-variant would let a
    /// wrong-variant call silently no-op instead of failing loud).
    fn evict(&self) {
        match self {
            RelayHandle::Killable(_, endpoint, _) => {
                endpoint.close(0u32.into(), b"case3: evicting R1");
            }
            RelayHandle::InProcess(..) => {
                panic!("evict() called on an InProcess RelayHandle")
            }
        }
    }
}

// --- gateway process management ---------------------------------------------

struct GwProc {
    child: Child,
    err_log: std::path::PathBuf,
    drains: Vec<std::thread::JoinHandle<()>>,
}

impl GwProc {
    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        for h in self.drains.drain(..) {
            let _ = h.join();
        }
    }
    fn stderr_tail(&self) -> String {
        let s = std::fs::read_to_string(&self.err_log).unwrap_or_default();
        let mut start = s.len().saturating_sub(4000);
        while start < s.len() && !s.is_char_boundary(start) {
            start += 1;
        }
        s[start..].to_string()
    }
}

impl Drop for GwProc {
    fn drop(&mut self) {
        self.kill();
    }
}

fn spawn_gw(ns: &Ns, statedir: &Path, sync: &str, observe: &str, logdir: &Path, tag: &str) -> GwProc {
    let metrics = format!("0.0.0.0:{METRICS_PORT}");
    let wg_port = WG_PORT.to_string();
    let statedir_s = statedir.to_str().unwrap();
    let args = [
        GW_BIN,
        "--controller-sync", sync,
        "--observe", observe,
        "--tun", "wg0",
        "--wg-port", &wg_port,
        "--state-dir", statedir_s,
        "--metrics", &metrics,
    ];
    let mut child = ns.spawn(&args).expect("spawn wiremesh-gateway");
    let mut drains = vec![];
    if let Some(mut o) = child.stdout.take() {
        let p = logdir.join(format!("{tag}.out.log"));
        drains.push(std::thread::spawn(move || {
            if let Ok(mut f) = std::fs::File::create(&p) {
                let _ = std::io::copy(&mut o, &mut f);
            }
        }));
    }
    let err_log = logdir.join(format!("{tag}.err.log"));
    if let Some(mut e) = child.stderr.take() {
        let p = err_log.clone();
        drains.push(std::thread::spawn(move || {
            if let Ok(mut f) = std::fs::File::create(&p) {
                let _ = std::io::copy(&mut e, &mut f);
            }
        }));
    }
    GwProc { child, err_log, drains }
}

// --- traffic + metrics probes -----------------------------------------------

/// A single ICMP echo, bounded 2s. `true` iff it got a reply.
fn ping_ok(ns: &Ns, dst: &str) -> bool {
    ns.exec(&["ping", "-c", "1", "-W", "2", dst]).is_ok()
}

/// Scrapes the gateway's Prometheus `/metrics` from INSIDE its netns (its
/// private NAT IP isn't reachable from the root netns, so we scrape
/// loopback) — identical approach to `nat_matrix.rs`.
fn scrape_metrics(ns: &Ns) -> Option<String> {
    let script = r#"
import socket, sys
try:
    s = socket.create_connection(("127.0.0.1", 9099), 2)
    s.settimeout(2)
    s.sendall(b"GET /metrics HTTP/1.0\r\n\r\n")
    data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    sys.stdout.write(data.decode("utf-8", "replace"))
except Exception as e:
    sys.stderr.write(str(e))
    sys.exit(1)
"#;
    let out = ns.exec(&["python3", "-c", script]).ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Current path state label for the gateway's single peer, parsed from the
/// `wiremesh_gateway_path_state{peer="..",state="X"} 1` scrape line — same
/// parser as `nat_matrix.rs`, generalized to whatever `PathState::as_str()`
/// emits (so it transparently picks up `"relayed"` with no changes needed
/// here).
fn path_state(ns: &Ns) -> Option<String> {
    let body = scrape_metrics(ns)?;
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("wiremesh_gateway_path_state{") {
            if let Some(idx) = rest.find("state=\"") {
                let tail = &rest[idx + 7..];
                if let Some(end) = tail.find('"') {
                    return Some(tail[..end].to_string());
                }
            }
        }
    }
    None
}

/// boringtun's latest-handshake unix timestamp for wg0's single peer (0 =
/// never).
fn latest_handshake(ns: &Ns) -> u64 {
    let out = match ns.exec(&["wg", "show", "wg0", "latest-handshakes"]) {
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

fn wg_show(ns: &Ns) -> String {
    ns.exec(&["wg", "show", "wg0"])
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// `wg show wg0 endpoints`'s single-peer endpoint field (`<ip>:<port>`, or
/// `None` if unset/unavailable) — the concrete, load-bearing "not a direct
/// candidate" check for this case: `wiremesh_gateway::relay::RelayTransport`
/// binds its local bridge socket on `127.0.0.1`, and
/// `main.rs::ensure_relay_transport` points the WG peer's endpoint AT that
/// local socket once relayed — so a `127.0.0.1:<port>` endpoint here is only
/// possible via the relay path; any real direct/punched candidate would show
/// a routable address instead (`192.168.8x.x` or `198.51.100.x`).
fn wg_endpoint(ns: &Ns) -> Option<String> {
    let out = ns.exec(&["wg", "show", "wg0", "endpoints"]).ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split_whitespace().last())
        .find(|s| *s != "(none)")
        .map(str::to_string)
}

fn wait_until<F: FnMut() -> bool>(timeout: Duration, mut f: F) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if f() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn dump_diag(label: &str, sc: &Scenario) {
    eprintln!("\n========== DIAGNOSTICS: {label} ==========");
    for (name, ns) in [("gwA", &sc.gwa), ("gwB", &sc.gwb)] {
        eprintln!("--- {name} wg show ---\n{}", wg_show(ns));
        eprintln!("--- {name} wg endpoints ---\n{:?}", wg_endpoint(ns));
        eprintln!("--- {name} path_state ---\n{:?}", path_state(ns));
        eprintln!("--- {name} latest-handshake ---\n{}", latest_handshake(ns));
    }
    eprintln!("--- gwA stderr tail ---\n{}", sc.pa.stderr_tail());
    eprintln!("--- gwB stderr tail ---\n{}", sc.pb.stderr_tail());
    eprintln!("========== END DIAGNOSTICS ==========\n");
}

// --- the scenario -----------------------------------------------------------

/// A fully-wired, running dual-symmetric-NAT gateway pair + in-process
/// controller + one-or-more relays. Fields are declared so `Drop` kills the
/// gateway processes BEFORE the lab tears down the netns, and the root
/// bridge last — same ordering discipline as `nat_matrix.rs`'s `Scenario`.
///
/// `relays` is NOT `_`-prefixed (unlike the other keep-alive-only fields):
/// case 3 (Cycle 4c Task 10) reads it back to `evict()` R1 specifically.
struct Scenario {
    pa: GwProc,
    pb: GwProc,
    gwa: Ns,
    gwb: Ns,
    wla: Ns,
    wlb: Ns,
    _lab: Lab,
    _h: TestController,
    relays: Vec<RelayHandle>,
    _sda: tempfile::TempDir,
    _sdb: tempfile::TempDir,
    _logdir: tempfile::TempDir,
    _root_guard: RootNetGuard,
}

/// Builds the full topology: both gateways behind SYMMETRIC NAT (so the
/// brokered punch genuinely fails — Cycle 4b `nat_matrix.rs`'s
/// `case2_symmetric_relay_needed` already establishes that fact for this
/// exact NAT kind), one real controller-enrolled+advertised relay per entry
/// in `relay_specs` (advertisement order == `relay_specs` order, which is
/// what `ensure_relay_transport`'s round-robin cursor picks in), and both
/// REAL gateway binaries. Does NOT wait for convergence — the caller (the
/// test fn) asserts the expected relayed outcome.
async fn build_scenario(prefix: &str, relay_specs: Vec<RelaySpec<'_>>) -> Scenario {
    setup_bridge();
    let root_guard = RootNetGuard;

    let h = TestController::start_on(CTRL_IP.parse().unwrap()).await;

    // Fabric BEFORE enrollment, so each gateway's first snapshot already
    // carries the compiled policy.
    let diff = h.apply(FABRIC).await;
    assert!(diff.policy_updated, "fabric apply must compile a real policy, got: {diff:?}");

    // Enroll + spawn every relay BEFORE the gateways connect, so the very
    // first `Sync.Watch` snapshot either gateway receives already carries
    // ALL of them in `relays` (no reliance on a later Delta).
    let mut relays = Vec::with_capacity(relay_specs.len());
    for spec in relay_specs {
        match spec {
            RelaySpec::InProcess { addr, csr_tag } => {
                let (certdir, task) = enroll_and_spawn_relay(&h, addr, csr_tag).await;
                relays.push(RelayHandle::InProcess(certdir, task));
            }
            RelaySpec::Killable { addr, csr_tag } => {
                let (certdir, endpoint, task) =
                    enroll_and_spawn_killable_relay(&h, addr, csr_tag).await;
                relays.push(RelayHandle::Killable(certdir, endpoint, task));
            }
        }
    }

    let (a_priv, a_pub) = wg_keypair();
    let (b_priv, b_pub) = wg_keypair();
    let ga = enroll_into(&h, "10.10.11.0/24", &a_pub).await;
    let gb = enroll_into(&h, "10.10.12.0/24", &b_pub).await;

    // netns lab: two gateways, two SYMMETRIC NAT routers, two workloads.
    let mut lab = Lab::new(prefix).expect("lab");
    let gwa = lab.ns("ga").expect("gwA netns");
    let gwb = lab.ns("gb").expect("gwB netns");
    let wla = lab.ns("wa").expect("wlA netns");
    let wlb = lab.ns("wb").expect("wlB netns");
    let ra = lab.nat_router("ra", NatKind::Symmetric).expect("ra");
    let rb = lab.nat_router("rb", NatKind::Symmetric).expect("rb");

    // Inside (gateway <-> router) links.
    lab.veth((&gwa, "nat0", "192.168.80.2/24"), (&ra, "in0", "192.168.80.1/24"))
        .expect("gwA<->ra");
    lab.veth((&gwb, "nat0", "192.168.81.2/24"), (&rb, "in0", "192.168.81.1/24"))
        .expect("gwB<->rb");

    // Router outside interfaces onto the internet bridge (must be `out0`).
    attach_bridge(&ra, HOST_ENDS[0], "ra", "out0", "198.51.100.2/24");
    attach_bridge(&rb, HOST_ENDS[1], "rb", "out0", "198.51.100.3/24");

    // MANDATORY netem on each REAL out0 (Phase-0 Finding 2) — call once per
    // iface, AFTER the veth wires it, and assert it's present before
    // anything else runs (mirrors `nat_matrix.rs` exactly).
    apply_netem(&ra, "out0", 20).expect("netem ra/out0");
    apply_netem(&rb, "out0", 20).expect("netem rb/out0");
    assert_netem_present(&ra, "out0");
    assert_netem_present(&rb, "out0");

    // Segment (workload) links + default routes.
    lab.veth((&gwa, "seg0", "10.10.11.1/24"), (&wla, "eth0", "10.10.11.2/24"))
        .expect("seg-a veth");
    lab.veth((&gwb, "seg0", "10.10.12.1/24"), (&wlb, "eth0", "10.10.12.2/24"))
        .expect("seg-b veth");
    wla.exec(&["ip", "route", "add", "default", "via", "10.10.11.1"]).expect("wlA route");
    wlb.exec(&["ip", "route", "add", "default", "via", "10.10.12.1"]).expect("wlB route");

    // Gateway default routes point at their NAT router (so the controller +
    // relay's shared-bridge addresses are reachable through the NAT — same
    // as `nat_matrix.rs`).
    gwa.exec(&["ip", "route", "add", "default", "via", "192.168.80.1"]).expect("gwA route");
    gwb.exec(&["ip", "route", "add", "default", "via", "192.168.81.1"]).expect("gwB route");

    // Right-reason guard: there really is no route from gwA's private
    // subnet to gwB's (or vice versa) at the network layer at all — neither
    // NAT router has any route toward the other's inside subnet, only to
    // the shared bridge. So a later successful overlay ping can only have
    // gone through something BOTH sides can actually reach: the relay.
    // Mirrors `spike/relay/tests/wg_over_relay.rs`'s "A has no direct path
    // to B" sanity check.
    assert!(
        gwa.exec(&["ping", "-c", "1", "-W", "1", "192.168.81.2"]).is_err(),
        "gwA must have NO direct network-layer route/reachability to gwB's private \
         address — otherwise a passing overlay ping wouldn't prove the relay carried it"
    );
    assert!(
        gwb.exec(&["ping", "-c", "1", "-W", "1", "192.168.80.2"]).is_err(),
        "gwB must have NO direct network-layer route/reachability to gwA's private \
         address — otherwise a passing overlay ping wouldn't prove the relay carried it"
    );

    // Provision identity dirs and spawn the two REAL gateway binaries.
    let sda = tempfile::tempdir().unwrap();
    let sdb = tempfile::tempdir().unwrap();
    write_identity(&ga, &a_priv, sda.path());
    write_identity(&gb, &b_priv, sdb.path());
    let logdir = tempfile::tempdir().unwrap();

    let sync_addr = h.sync_tcp_addr().to_string();
    let observe_addr = h.observe_addr().to_string();
    eprintln!(
        "build_scenario[{prefix}]: controller sync={sync_addr} observe={observe_addr} \
         relays={}",
        relays.len()
    );

    let pa = spawn_gw(&gwa, sda.path(), &sync_addr, &observe_addr, logdir.path(), "a");
    let pb = spawn_gw(&gwb, sdb.path(), &sync_addr, &observe_addr, logdir.path(), "b");

    Scenario {
        pa,
        pb,
        gwa,
        gwb,
        wla,
        wlb,
        _lab: lab,
        _h: h,
        relays,
        _sda: sda,
        _sdb: sdb,
        _logdir: logdir,
        _root_guard: root_guard,
    }
}

// --- the case -----------------------------------------------------------

/// Case 1 (design spec §2 done-bar case 1): a symmetric<->symmetric pair —
/// direct punch impossible — reaches `path_state = relayed` on BOTH sides
/// and passes real workload traffic (an ICMP ping, policy-permitted only
/// seg-a -> seg-b) over the tunnel, with the WG handshake's own endpoint
/// proving the data actually crossed the relay rather than some accidental
/// direct path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn case1_symmetric_pair_flows_over_relay() {
    let sc = build_scenario(
        "rm1",
        vec![RelaySpec::InProcess { addr: RELAY_ADDR, csr_tag: "relay-case1" }],
    )
    .await;
    let start = Instant::now();

    // Phase 1: both sides reach path_state=relayed. Nominal budget per the
    // done-bar is <=30s (CONNECT_TIMEOUT=10s before the SM gives up on a
    // direct handshake and marks relay-needed, plus ~1s path-tick cadence,
    // plus the relay QUIC connect); bounded generously above that (like
    // `nat_matrix.rs`'s `establish_direct`) so container CPU contention
    // doesn't turn ordinary jitter into a flake, logging progress every ~5s
    // so a regression is diagnosable from one run's captured stdout.
    let mut last_log = Instant::now() - Duration::from_secs(5);
    let relayed = wait_until(Duration::from_secs(45), || {
        if last_log.elapsed() >= Duration::from_secs(5) {
            eprintln!(
                "case1: t+{:?} gwA={:?} gwB={:?}",
                start.elapsed(),
                path_state(&sc.gwa),
                path_state(&sc.gwb),
            );
            last_log = Instant::now();
        }
        path_state(&sc.gwa).as_deref() == Some("relayed")
            && path_state(&sc.gwb).as_deref() == Some("relayed")
    });
    if !relayed {
        dump_diag("case1 reach-relayed", &sc);
        panic!(
            "case1: symmetric pair never reached path_state=relayed on both sides \
             (gwA={:?}, gwB={:?}) within 45s",
            path_state(&sc.gwa),
            path_state(&sc.gwb)
        );
    }
    eprintln!("case1: PASS both sides reached path_state=relayed in {:?}", start.elapsed());

    // Concrete "not a direct candidate" proof: the WG peer endpoint on BOTH
    // sides must be the LOCAL relay-transport socket (127.0.0.1:<port>) —
    // see `wg_endpoint`'s doc comment for why only the relay path can
    // produce that.
    let ep_a = wg_endpoint(&sc.gwa);
    let ep_b = wg_endpoint(&sc.gwb);
    if !ep_a.as_deref().is_some_and(|e| e.starts_with("127.0.0.1:"))
        || !ep_b.as_deref().is_some_and(|e| e.starts_with("127.0.0.1:"))
    {
        dump_diag("case1 endpoint-check", &sc);
        panic!(
            "case1: expected BOTH peers' WG endpoint to be the local relay socket \
             (127.0.0.1:<port>) while relayed, got gwA={ep_a:?} gwB={ep_b:?}"
        );
    }
    eprintln!("case1: PASS both WG endpoints point at the local relay socket (gwA={ep_a:?}, gwB={ep_b:?})");

    // Phase 2: the policy-permitted ping crossing. Boringtun only initiates
    // a WG handshake toward the (now relay-pointed) endpoint on outbound
    // data demand, so the ping attempts themselves are what drive the
    // handshake to completion over the relay — the same "connect attempts
    // create tunnel demand" pattern `nat_matrix.rs`'s `establish_direct`
    // documents, just with icmp instead of tcp/8080. Bounded 25s.
    let crossed = wait_until(Duration::from_secs(25), || ping_ok(&sc.wla, "10.10.12.2"));
    if !crossed {
        dump_diag("case1 ping-cross", &sc);
        panic!("case1: wlA -> wlB ping (10.10.12.2) never crossed the relayed tunnel");
    }
    eprintln!("case1: PASS wlA -> wlB ping crossed the relayed tunnel");

    // A real WG handshake completed (not just an SM state label).
    let ha = latest_handshake(&sc.gwa);
    let hb = latest_handshake(&sc.gwb);
    if ha == 0 || hb == 0 {
        dump_diag("case1 handshake-check", &sc);
        panic!("case1: expected a real WG handshake on both sides, got gwA={ha} gwB={hb}");
    }

    // Honesty guard (mirrors `nat_matrix.rs`'s `case2_symmetric_relay_needed`):
    // a symmetric<->symmetric pair reaching `direct` at ANY point here would
    // undermine the whole proof that this traffic crossed the relay — fail
    // loud rather than silently accept it.
    let final_a = path_state(&sc.gwa);
    let final_b = path_state(&sc.gwb);
    if final_a.as_deref() == Some("direct") || final_b.as_deref() == Some("direct") {
        dump_diag("case1 unexpected-direct", &sc);
        panic!(
            "case1: symmetric<->symmetric pair unexpectedly reached path_state=direct \
             (gwA={final_a:?}, gwB={final_b:?}) — investigate before changing the assertion"
        );
    }

    eprintln!(
        "CASE 1 PASS: symmetric<->symmetric pair flowed real ping traffic over the relay \
         in {:?} (handshake gwA={ha} gwB={hb}, endpoints gwA={ep_a:?} gwB={ep_b:?}).",
        start.elapsed()
    );
}

/// Case 3 (design spec §2 done-bar case 3, Cycle 4c Task 10): relay
/// eviction / re-path, ≤15s intent. Same symmetric<->symmetric pair as case
/// 1 (direct is genuinely impossible for this NAT pairing — see case 1's
/// doc comment), but with TWO relays (R1 = `RELAY_ADDR`, R2 = `RELAY_ADDR_2`)
/// enrolled+advertised from the start. The pair first converges to
/// `Relayed` via R1 (the controller's advertisement order is
/// `[R1, R2]` and `ensure_relay_transport`'s per-peer round-robin cursor
/// picks index 0 on a peer's very first connect attempt — see that fn's doc
/// comment), proven exactly like case 1 (flowing ping + local-relay-socket
/// endpoint on both sides).
///
/// R1 is then EVICTED — see [`enroll_and_spawn_killable_relay`]'s doc
/// comment for why this test forces R1's `quinn::Endpoint` closed (a real,
/// immediate severance of both gateways' live QUIC connections to it) rather
/// than either killing a separate `relay` OS process (this harness has no
/// reliable cross-crate way to spawn `wiremesh-relay`'s `relay` binary from
/// this crate's tests — see that doc comment) or driving the controller's
/// `Report.relay_health` pipeline directly (Task 6) to de-advertise R1. This
/// choice does still exercise Task 6 end-to-end, just not as the thing being
/// directly asserted on: once R1's transport goes unhealthy on either
/// gateway, that gateway's own next `Sync.Report` carries `relay_health =
/// [{relay_id: R1, healthy: false}]` (see `PathCtx::relay_health_snapshot`'s
/// doc comment), which is exactly the controller-side input Task 6's
/// eviction pipeline consumes — this test doesn't separately assert that
/// controller-internal transition because the done-bar's real
/// requirement (R-3) is the END-TO-END outcome: the pair actually re-paths
/// and traffic actually flows again. That outcome is asserted below.
///
/// Right-reason note (mirrors case 1): this is still a symmetric<->symmetric
/// pair with no network-layer route between the two private subnets (see
/// `build_scenario`'s reachability guard), so a ping crossing again AFTER
/// R1's eviction can only have gone through R2.
///
/// Implementer note: this is the FIRST time Task 6's controller eviction and
/// Task 8's gateway re-path get exercised end-to-end under netns — expect
/// this to plausibly surface a re-path timing/stability bug the way case
/// 1's own `ProbeDirect`/`SO_REUSEPORT` interaction did (see
/// `run_path_ticks`'s "Stability debug note" doc comment and
/// docs/research/cycle4c-relay-stability-note.md). If the round-robin
/// cursor (`ctx.relay_next_idx`) or the unhealthy-transport detection
/// (`RelayTransport::is_healthy` / `Client::is_alive`) doesn't actually
/// drive a reconnect to R2 promptly once R1's endpoint closes, that is this
/// task's implementation work to fix, not this test's to route around.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn case3_relay_eviction_repaths_to_second_relay() {
    let sc = build_scenario(
        "rm3",
        vec![
            RelaySpec::Killable { addr: RELAY_ADDR, csr_tag: "relay-case3-r1" },
            RelaySpec::InProcess { addr: RELAY_ADDR_2, csr_tag: "relay-case3-r2" },
        ],
    )
    .await;
    let start = Instant::now();

    // Phase 1: converge to Relayed via R1, exactly like case 1 (same NAT
    // pairing, same reason direct is impossible, same bound).
    let mut last_log = Instant::now() - Duration::from_secs(5);
    let relayed = wait_until(Duration::from_secs(45), || {
        if last_log.elapsed() >= Duration::from_secs(5) {
            eprintln!(
                "case3: t+{:?} pre-evict gwA={:?} gwB={:?}",
                start.elapsed(),
                path_state(&sc.gwa),
                path_state(&sc.gwb),
            );
            last_log = Instant::now();
        }
        path_state(&sc.gwa).as_deref() == Some("relayed")
            && path_state(&sc.gwb).as_deref() == Some("relayed")
    });
    if !relayed {
        dump_diag("case3 reach-relayed (pre-evict)", &sc);
        panic!(
            "case3: symmetric pair never reached path_state=relayed on both sides \
             (gwA={:?}, gwB={:?}) within 45s, before R1 was even evicted",
            path_state(&sc.gwa),
            path_state(&sc.gwb)
        );
    }
    eprintln!("case3: PASS both sides reached path_state=relayed (via R1) in {:?}", start.elapsed());

    // Prove the FIRST flow (via R1), exactly like case 1: a policy-permitted
    // ping crossing, plus the WG endpoint pointing at a local relay socket
    // on both sides.
    let crossed = wait_until(Duration::from_secs(25), || ping_ok(&sc.wla, "10.10.12.2"));
    if !crossed {
        dump_diag("case3 ping-cross (pre-evict)", &sc);
        panic!("case3: wlA -> wlB ping never crossed the relayed tunnel via R1");
    }
    let ep_a_before = wg_endpoint(&sc.gwa);
    let ep_b_before = wg_endpoint(&sc.gwb);
    if !ep_a_before.as_deref().is_some_and(|e| e.starts_with("127.0.0.1:"))
        || !ep_b_before.as_deref().is_some_and(|e| e.starts_with("127.0.0.1:"))
    {
        dump_diag("case3 endpoint-check (pre-evict)", &sc);
        panic!(
            "case3: expected BOTH peers' WG endpoint to be a local relay socket \
             (127.0.0.1:<port>) while relayed via R1, got gwA={ep_a_before:?} gwB={ep_b_before:?}"
        );
    }
    eprintln!(
        "case3: PASS flowed via R1 in {:?} (endpoints gwA={ep_a_before:?} gwB={ep_b_before:?})",
        start.elapsed()
    );

    // Phase 2: EVICT R1 — force-close its QUIC endpoint out from under both
    // gateways' already-live connections. See this fn's own doc comment and
    // `enroll_and_spawn_killable_relay`'s for why this (rather than an OS
    // process kill or a controller-health-report shortcut) is this test's
    // eviction mechanism.
    let evict_at = Instant::now();
    sc.relays[0].evict();
    eprintln!("case3: evicted R1 at t+{:?}", start.elapsed());

    // Phase 3: both sides RE-PATH — end up (or stay) `relayed`, via R2, and
    // a FRESH ping (only attempted after the eviction, so a pass can only be
    // attributed to R2 carrying it) crosses again. Bounded generously above
    // the design's ~15s R-3 intent (like case 1's own generous-but-bounded
    // budgets), logging progress every ~5s so a regression is diagnosable
    // from one run's captured stdout.
    let mut last_log2 = Instant::now() - Duration::from_secs(5);
    let repathed = wait_until(Duration::from_secs(30), || {
        if last_log2.elapsed() >= Duration::from_secs(5) {
            eprintln!(
                "case3: t+{:?} post-evict gwA={:?} gwB={:?}",
                evict_at.elapsed(),
                path_state(&sc.gwa),
                path_state(&sc.gwb),
            );
            last_log2 = Instant::now();
        }
        path_state(&sc.gwa).as_deref() == Some("relayed")
            && path_state(&sc.gwb).as_deref() == Some("relayed")
            && ping_ok(&sc.wla, "10.10.12.2")
    });
    if !repathed {
        dump_diag("case3 re-path", &sc);
        panic!(
            "case3: pair never re-established a FLOWING relayed path (via R2) within 30s of \
             R1's eviction (gwA={:?}, gwB={:?}) — never stuck disconnected/degraded was the \
             R-3 requirement",
            path_state(&sc.gwa),
            path_state(&sc.gwb)
        );
    }
    eprintln!("case3: PASS re-pathed and flowed again within {:?} of R1's eviction", evict_at.elapsed());

    // Concrete "really on a relay socket again, and it's a DIFFERENT one
    // than before" proof: both R1 and R2 point the WG peer at a LOCAL
    // 127.0.0.1:<port> socket (see `wg_endpoint`'s doc comment), so the
    // local port alone doesn't distinguish R1 from R2 — but a genuine
    // re-path binds a FRESH `RelayTransport` (a fresh ephemeral local UDP
    // socket), so the port is expected to differ from the pre-eviction
    // reading. An unchanged endpoint here would mean this "pass" is really
    // just a stale reading with R1's session never actually replaced.
    let ep_a_after = wg_endpoint(&sc.gwa);
    let ep_b_after = wg_endpoint(&sc.gwb);
    if !ep_a_after.as_deref().is_some_and(|e| e.starts_with("127.0.0.1:"))
        || !ep_b_after.as_deref().is_some_and(|e| e.starts_with("127.0.0.1:"))
    {
        dump_diag("case3 endpoint-check (post-evict)", &sc);
        panic!(
            "case3: expected BOTH peers back on a local relay socket after re-path, \
             got gwA={ep_a_after:?} gwB={ep_b_after:?}"
        );
    }
    if ep_a_after == ep_a_before || ep_b_after == ep_b_before {
        dump_diag("case3 endpoint-unchanged (post-evict)", &sc);
        panic!(
            "case3: expected the WG endpoint's local relay-socket port to CHANGE after \
             re-path (a fresh RelayTransport binds a fresh ephemeral port) — got an \
             unchanged endpoint (gwA {ep_a_before:?} -> {ep_a_after:?}, gwB {ep_b_before:?} \
             -> {ep_b_after:?}), suggesting no real re-path to R2 occurred"
        );
    }
    eprintln!(
        "case3: PASS both endpoints changed after re-path (gwA {ep_a_before:?} -> \
         {ep_a_after:?}, gwB {ep_b_before:?} -> {ep_b_after:?})"
    );

    // Honesty guard (mirrors case 1): still a symmetric<->symmetric pair —
    // a `direct` reading at any point here would undermine the whole proof
    // that this traffic crossed a relay (R1 first, then R2).
    let final_a = path_state(&sc.gwa);
    let final_b = path_state(&sc.gwb);
    if final_a.as_deref() == Some("direct") || final_b.as_deref() == Some("direct") {
        dump_diag("case3 unexpected-direct", &sc);
        panic!(
            "case3: symmetric<->symmetric pair unexpectedly reached path_state=direct \
             (gwA={final_a:?}, gwB={final_b:?}) — investigate before changing the assertion"
        );
    }

    eprintln!(
        "CASE 3 PASS: symmetric<->symmetric pair survived R1's eviction and re-flowed real \
         ping traffic over R2 within {:?} of the eviction (total test time {:?}).",
        evict_at.elapsed(),
        start.elapsed()
    );
}
