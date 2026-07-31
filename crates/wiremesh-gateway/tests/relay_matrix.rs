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
//! Also here (aether-prod-fi-01 relay-wedge regression):
//! `case4_relay_leg_death_unwedges_direct_punch`, which varies the shared
//! topology — **port-restricted** NAT on both sides plus a temporary
//! direct-lane blackhole (`build_scenario`'s `nat`/`block_direct` params) —
//! to prove a relayed pair whose relay legs die OF SILENCE (an in-transit
//! severance detected only by QUIC's idle timeout — the `TimedOut`
//! death-reason branch; case 3 remains the graceful-close/eviction
//! fast-path pin) recovers a real DIRECT path instead of sawtoothing
//! forever on a stale `relay_pointed` pin. See that test fn's doc comment
//! for the incident and the repro-design rationale.
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
use wiremesh_gateway::path::PROBE_DIRECT_INTERVAL;
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

/// The make-before-break yield line `punch_and_apply` (src/main.rs) prints
/// when a spawned punch trial finds the path no longer `Connecting` and
/// defers to the live relay path. Counted by case 1's defer-spam guard (see
/// that phase's comment). A substring of the full line (not the whole
/// message) so peer-id formatting changes don't silently blind the guard —
/// but distinctive enough that nothing else in the gateway's stderr can
/// match it.
const DEFER_NEEDLE: &str = "deferring direct punch";

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
/// The two NAT routers' external (bridge-facing) addresses — the source/
/// destination every masqueraded gateway<->gateway datagram carries on the
/// bridge. Case 4 blackholes each one inside the OPPOSITE router (see
/// `build_scenario`'s `block_direct`) to force the pair onto the relay
/// during establishment even though its NAT pairing could punch direct.
const RA_EXT: &str = "198.51.100.2";
const RB_EXT: &str = "198.51.100.3";

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
    /// Current byte length of the captured stderr log — a position marker so
    /// a later [`Self::stderr_from`] read can be scoped to output the
    /// gateway emitted AFTER this instant (the drain thread appends to the
    /// log file continuously, so the file's length at time T is a stable
    /// "everything before T" boundary, modulo pipe latency — which is why
    /// counts taken against such a marker need a ±1 tolerance around
    /// transitions).
    fn stderr_len(&self) -> u64 {
        std::fs::metadata(&self.err_log).map(|m| m.len()).unwrap_or(0)
    }
    /// Everything the gateway wrote to stderr from byte `offset` onward
    /// (lossy UTF-8; `offset` clamped to the file's current length).
    fn stderr_from(&self, offset: u64) -> String {
        let bytes = std::fs::read(&self.err_log).unwrap_or_default();
        let start = (offset as usize).min(bytes.len());
        String::from_utf8_lossy(&bytes[start..]).into_owned()
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
    /// The two NAT router namespaces, kept so a case can mutate in-transit
    /// reachability mid-test (case 4 lifts the `block_direct` blackholes via
    /// [`unblock_direct`]). `Ns` is a non-owning handle — the `Lab` still
    /// owns netns teardown — so holding these adds no Drop-order hazard.
    ra: Ns,
    rb: Ns,
    _lab: Lab,
    _h: TestController,
    relays: Vec<RelayHandle>,
    _sda: tempfile::TempDir,
    _sdb: tempfile::TempDir,
    _logdir: tempfile::TempDir,
    _root_guard: RootNetGuard,
}

/// Lifts the `block_direct` blackhole routes installed by [`build_scenario`]
/// (case 4's phase 2): from this instant the two gateways' masqueraded
/// datagrams can genuinely reach each other's router again, so a direct
/// punch — for a NAT pairing that allows one — becomes possible.
fn unblock_direct(sc: &Scenario) {
    sc.ra
        .exec(&["ip", "route", "del", "blackhole", &format!("{RB_EXT}/32")])
        .expect("lift ra blackhole");
    sc.rb
        .exec(&["ip", "route", "del", "blackhole", &format!("{RA_EXT}/32")])
        .expect("lift rb blackhole");
}

/// Case 4's relay-leg severance: blackholes the relay's address in BOTH NAT
/// routers, so from this instant every gateway<->relay datagram silently
/// dies in transit — in BOTH directions, because with the gateways' outbound
/// dropped the relay stops receiving, and (having no keep-alives and no data
/// of its own) therefore stops sending; any stray packet it did emit could
/// not matter, since no CONNECTION_CLOSE is ever generated (see below).
///
/// The point of this mechanism — versus case 3's `RelayHandle::evict`
/// (`quinn::Endpoint::close`) — is that NO close frame can possibly reach
/// either gateway, so both legs die the way the PRODUCTION wedge's did: of
/// pure silence, detected only by QUIC's idle timer and classified
/// `TimedOut`, which is the punch-window driver branch this case pins. A
/// graceful `Endpoint::close` would instead classify `Closed` and take the
/// eviction fast-path (immediate reconnect — case 3's branch, already
/// pinned there). Guarantees: the blackhole route type drops without ICMP;
/// QUIC idle timeout is a silent discard on both ends (RFC 9000 §10.1 — no
/// close frame is sent at expiry, and quinn follows this); and the relay
/// process itself is left alive and unclosed the whole time, so no
/// close-at-shutdown can leak either.
fn sever_relay(sc: &Scenario) {
    let relay_host = RELAY_ADDR.split(':').next().expect("RELAY_ADDR has a host");
    sc.ra
        .exec(&["ip", "route", "add", "blackhole", &format!("{relay_host}/32")])
        .expect("install ra relay blackhole");
    sc.rb
        .exec(&["ip", "route", "add", "blackhole", &format!("{relay_host}/32")])
        .expect("install rb relay blackhole");
}

/// Builds the full topology: both gateways behind `nat`-kind NAT (cases 1
/// and 3 pass `NatKind::Symmetric` so the brokered punch genuinely fails —
/// Cycle 4b `nat_matrix.rs`'s `case2_symmetric_relay_needed` already
/// establishes that fact for that NAT kind; case 4 passes
/// `NatKind::PortRestricted`, the pairing `nat_matrix.rs` case 1 proves CAN
/// punch direct), one real controller-enrolled+advertised relay per entry
/// in `relay_specs` (advertisement order == `relay_specs` order, which is
/// what `ensure_relay_transport`'s round-robin cursor picks in), and both
/// REAL gateway binaries. Does NOT wait for convergence — the caller (the
/// test fn) asserts the expected relayed outcome.
///
/// `block_direct` (case 4): installs a `/32` blackhole route in EACH router
/// toward the OTHER router's external address BEFORE the gateways spawn, so
/// every masqueraded gateway<->gateway datagram (punch probes and WG alike)
/// is silently dropped in transit while the controller (`CTRL_IP`) and the
/// relay addresses on the same bridge stay fully reachable — forcing even a
/// punch-capable NAT pairing onto the relay during establishment, exactly
/// like a transiently unpunchable real-world path would. Lifted later via
/// [`unblock_direct`]. Installed router-side (not in the gateway netns) so
/// gateway-side sends still succeed and die in transit — no local send
/// errors that the real incident never had.
async fn build_scenario(
    prefix: &str,
    relay_specs: Vec<RelaySpec<'_>>,
    nat: NatKind,
    block_direct: bool,
) -> Scenario {
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
    let ra = lab.nat_router("ra", nat).expect("ra");
    let rb = lab.nat_router("rb", nat).expect("rb");

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

    // Case 4's direct-lane block (see this fn's doc comment): installed
    // BEFORE the gateways spawn, so the very first punch cycles are already
    // deterministically doomed and the pair's initial convergence can only
    // be the relay. A `/32` blackhole overrides the routers' connected-/24
    // route for exactly the opposite router's external address and silently
    // drops (no ICMP), leaving controller+relay reachability untouched.
    if block_direct {
        ra.exec(&["ip", "route", "add", "blackhole", &format!("{RB_EXT}/32")])
            .expect("install ra blackhole");
        rb.exec(&["ip", "route", "add", "blackhole", &format!("{RA_EXT}/32")])
            .expect("install rb blackhole");
    }

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
        ra,
        rb,
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
///
/// Also here (defer-spam guard, final phase): the same stably-relayed pair
/// is then HELD relayed for >=2.5 x `path::PROBE_DIRECT_INTERVAL` and each
/// gateway's post-steady-state stderr is counted for the make-before-break
/// "deferring direct punch" yield line — see the phase-4 comment below for
/// the bug this pins down (one doomed punch spawn + stderr line per relayed
/// peer per interval, forever).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn case1_symmetric_pair_flows_over_relay() {
    let sc = build_scenario(
        "rm1",
        vec![RelaySpec::InProcess { addr: RELAY_ADDR, csr_tag: "relay-case1" }],
        NatKind::Symmetric,
        false,
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

    // Marker for the defer-spam guard (phase 4 below): everything either
    // gateway writes to stderr AFTER this instant is post-steady-state
    // output. Taken HERE — the moment both sides' relayed state is
    // confirmed — not later, so the guard's window covers the earliest
    // `ProbeDirect` the Relayed arm can emit (one full
    // `PROBE_DIRECT_INTERVAL` grace after entering Relayed).
    let steady_at = Instant::now();
    let defer_off_a = sc.pa.stderr_len();
    let defer_off_b = sc.pb.stderr_len();

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

    // Phase 4 (defer-spam guard): a STABLY-relayed pair must not burn a
    // doomed punch trial per `PROBE_DIRECT_INTERVAL`, forever. On the buggy
    // driver, `Path::tick`'s Relayed arm emits `PathAction::ProbeDirect`
    // every interval (src/path.rs, Relayed arm), `run_path_ticks` treats it
    // exactly like `StartPunch` and spawns `punch_and_apply` (src/main.rs),
    // and that trial's make-before-break guard then yields IMMEDIATELY for
    // any non-`Connecting` path — printing the `DEFER_NEEDLE` stderr line.
    // Net effect in production: one such line per relayed peer every 20s,
    // indefinitely (and the deferred trial deliberately records no punch
    // outcome, so the pair back-off never opens a window to dampen it). The
    // Relayed->Direct cutover is a DOCUMENTED fast-follow (CLAUDE.md /
    // docs/research/cycle4c-relay-notes.md) — until it lands, the driver
    // must not spawn a punch trial it KNOWS will yield, so a stably-relayed
    // pair should emit this line rarely or never.
    //
    // Mechanics: hold the (already fully proven, still-running) pair for
    // >=2.5 x PROBE_DIRECT_INTERVAL past the steady-state marker taken in
    // phase 1, then count `DEFER_NEEDLE` occurrences in each gateway's
    // stderr AFTER that marker. Tolerance <=1 per gateway: a punch trial
    // legitimately spawned while the path was still `Connecting` can land
    // its one yield line just after the transition (and the phase-1 marker
    // itself races the stderr pipe drain by a line at most) — but the
    // per-interval spam produces ~2-3 lines in this window, so the buggy
    // driver fails loud here.
    let window = PROBE_DIRECT_INTERVAL * 5 / 2 + Duration::from_secs(5);
    let mut last_log3 = Instant::now() - Duration::from_secs(10);
    // Per-iteration stability sampling (review finding): checking stability
    // only at the window's END would miss a mid-window flap off `relayed`
    // that self-heals before then — and a flap passes back through
    // `Connecting`, whose LEGITIMATE punch trials can land defer lines of
    // their own, making the count below meaningless. Sample both sides on
    // every wakeup (~500ms, same cadence `wait_until` already scrapes at)
    // and record the FIRST instability with its offset-into-window and both
    // states; fail loud on it after the loop.
    let mut unstable_at: Option<(Duration, Option<String>, Option<String>)> = None;
    while steady_at.elapsed() < window {
        let st_a = path_state(&sc.gwa);
        let st_b = path_state(&sc.gwb);
        if st_a.as_deref() != Some("relayed") || st_b.as_deref() != Some("relayed") {
            unstable_at = Some((steady_at.elapsed(), st_a, st_b));
            break;
        }
        if last_log3.elapsed() >= Duration::from_secs(10) {
            eprintln!(
                "case1: t+{:?} defer-spam hold {:?}/{window:?} (gwA={st_a:?} gwB={st_b:?})",
                start.elapsed(),
                steady_at.elapsed(),
            );
            last_log3 = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    if let Some((at, ua, ub)) = unstable_at {
        dump_diag("case1 defer-spam mid-window flap", &sc);
        panic!(
            "case1: pair flapped off path_state=relayed {at:?} into the {window:?} \
             defer-spam observation window (gwA={ua:?}, gwB={ub:?}) — a flap re-enters \
             Connecting, whose legitimate punch trials can add {DEFER_NEEDLE:?} lines, so \
             the defer-line count would be meaningless; investigate the instability first"
        );
    }

    // The guard's premise is a STABLY-relayed pair — the per-iteration
    // sampling above covers the window's interior; this closes the final
    // <=500ms gap after the loop's last sample.
    let held_a = path_state(&sc.gwa);
    let held_b = path_state(&sc.gwb);
    if held_a.as_deref() != Some("relayed") || held_b.as_deref() != Some("relayed") {
        dump_diag("case1 defer-spam hold-stability", &sc);
        panic!(
            "case1: pair did not STAY path_state=relayed across the {window:?} defer-spam \
             observation window (gwA={held_a:?}, gwB={held_b:?}) — investigate the \
             instability before reading anything into the defer-line count"
        );
    }

    let defers_a = sc.pa.stderr_from(defer_off_a).matches(DEFER_NEEDLE).count();
    let defers_b = sc.pb.stderr_from(defer_off_b).matches(DEFER_NEEDLE).count();
    if defers_a > 1 || defers_b > 1 {
        dump_diag("case1 defer-spam", &sc);
        panic!(
            "case1: stably-relayed pair kept spawning doomed direct-punch trials — counted \
             {DEFER_NEEDLE:?} {defers_a}x on gwA and {defers_b}x on gwB in the {window:?} \
             after relayed steady state (tolerance: <=1 each, from the Connecting \
             transition window). More than one means `run_path_ticks` is still turning the \
             Relayed arm's `ProbeDirect` into a `punch_and_apply` spawn whose \
             make-before-break guard instantly yields: per-peer stderr spam every \
             PROBE_DIRECT_INTERVAL, forever, in production"
        );
    }
    eprintln!(
        "case1: PASS defer-spam guard — {defers_a} (gwA) / {defers_b} (gwB) deferred-punch \
         lines across {window:?} of relayed steady state"
    );

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
        NatKind::Symmetric,
        false,
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

/// Case 4's DEATH-DETECTION budget: how long after the in-transit severance
/// ([`sever_relay`]) each gateway's transport takes to actually notice its
/// leg is dead. A close-frame-less severance is detected ONLY by QUIC's idle
/// timer: `wiremesh_relay::transport_config` fixes `max_idle_timeout = 30s`
/// on both sides with no keep-alives, `Client::is_alive` (=
/// `RelayTransport::is_healthy`) flips exactly when quinn's idle timer
/// expires and records the `TimedOut` close reason — nothing flips it
/// earlier (a blackholed route emits no ICMP, and the relay never sends a
/// close: RFC 9000 idle timeout is a SILENT discard on both ends). Until
/// that instant the path legitimately stays `Relayed` (the SM's
/// relay-death branch is `relay_available`-driven, i.e. health-driven).
/// Budget = the 30s constant + margin for the last pre-severance received
/// packet (idle timers restart on receipt; keepalive/probe traffic means
/// the last receipt is ≤ a few seconds before the severance instant), the
/// ~1s path-tick cadence, and container CPU jitter.
const CASE4_DEATH_DETECTION_BUDGET: Duration = Duration::from_secs(35);

/// Case 4's RECOVERY budget AFTER the death is detectable: with the fix the
/// recovery is one or two `Disconnected -> Connecting -> StartPunch` cycles
/// (backoff 4-16s + `CONNECT_TIMEOUT` 10s each) plus the handshake itself,
/// so ~10-15s nominal after detection (~40-45s total from severance,
/// ~55-60s expected worst with one failed cycle); on PRE-FIX code the wedge
/// sawtooth runs forever, so no budget would ever be enough — the bound
/// only exists to fail loud in bounded time. The recovery wait below is
/// bounded by `CASE4_DEATH_DETECTION_BUDGET + CASE4_RECOVERY_BUDGET` from
/// the severance instant, so this component stays a pure
/// recovery-after-detection allowance.
const CASE4_RECOVERY_BUDGET: Duration = Duration::from_secs(90);

/// Post-severance `DEFER_NEEDLE` tolerance per gateway (case 4). During the
/// ~30s silent detection phase NO defer lines can accrue at all: the path
/// stays `Relayed` (see [`CASE4_DEATH_DETECTION_BUDGET`] — health flips
/// only at the idle-timer expiry), so there are no `Connecting` cycles, no
/// tick-driven punch spawns, and directives stay filtered. On PRE-FIX code,
/// once detection lands every `Disconnected -> Connecting` cycle spawns a
/// punch trial that instantly defers against the stale `relay_pointed` pin
/// — one defer line per sawtooth cycle (backoff 4s doubling toward 30s +
/// 10s `CONNECT_TIMEOUT`), i.e. 3+ lines inside the recovery window,
/// repeating forever. With the fix the pin is cleared on relay death, so a
/// defer can only come from the benign race the make-before-break guard
/// exists for: a punch trial still in flight when `Connecting` times out
/// mid-recovery (at most one line per failed recovery cycle, and recovery
/// completes within a cycle or two). ≤2 separates the two worlds.
///
/// Known UN-MODELED flake margins (for diagnosing a future red without
/// assuming the wedge regressed):
/// (a) each failed recovery cycle whose punch trial straddles the 10s
///     `CONNECT_TIMEOUT` prints one defer line, so ≥3 failed cycles before
///     an ultimately-successful recovery would breach this bound even
///     though recovery was legitimately in progress;
/// (b) `punch_backoff` (`FAILURE_THRESHOLD` = 3 consecutive failures opens
///     a ~30s window) can silently swallow phase 4's FIRST `StartPunch`
///     spawn (+~18s to recovery) if phase 1's blocked-direct punches
///     already accrued 3 recorded failures.
const CASE4_MAX_POST_DEATH_DEFERS: usize = 2;

/// Case 4 (aether-prod-fi-01 relay-wedge regression, v0.3.0 incident): a
/// RELAYED pair whose relay legs die OF SILENCE (close-frame-less, QUIC
/// idle timeout — the `RelayDeathReason::TimedOut` classification, i.e. the
/// production wedge's death mode) — with no reachable relay to re-path onto
/// and a NAT pairing that genuinely allows a direct punch — must UNWEDGE:
/// clear the dead relay's `relay_pointed` pin, get a clean direct punch
/// window, and re-establish real WG flow direct. RED on pre-fix code.
///
/// ## The production wedge being reproduced
///
/// Gateway A was `Relayed` toward peer B; B restarted fresh and punched A
/// direct, tearing down B's relay leg. A's own relay leg then died (downlink
/// recv error -> `is_healthy()` false), and A sawtoothed forever (~40s
/// period): `Relayed -> Disconnected` (+`MarkRelayNeeded` -> immediate relay
/// reconnect on a fresh socket), `Disconnected -> Connecting` + `StartPunch`
/// whose trial instantly printed `DEFER_NEEDLE` and yielded — because
/// `relay_pointed` is only cleared by a successful DIRECT endpoint commit or
/// roster pruning, and `teardown_relay_transport` runs only on reaching
/// `Direct`, a DEAD transport never cleared the pin — then `Connecting`
/// timed out, re-relayed toward a relay the peer had left, timed out again,
/// repeat. The peer never got one clean direct-punch window.
///
/// ## Repro design (the cheapest DETERMINISTIC one this harness supports)
///
/// Production's exact shape — a one-sided leg death with the relay still
/// serving and the peer punching in unilaterally — is not deterministically
/// reproducible here: `RelayHandle::Killable`'s `quinn::Endpoint::close`
/// severs EVERY connection on the relay (the per-connection registry isn't
/// addressable from the test), and a one-sided network severance (e.g.
/// blackholing one router's route to the relay) would strand the OTHER side
/// `Relayed`-on-a-healthy-leg with no traffic — a distinct, out-of-scope
/// stall (`Relayed` has no silence-based exit), under which not even the fix
/// could recover the pair, so nothing would discriminate. The wedge's ROOT
/// CAUSE, however, is per-side and mechanism-identical under a both-sides
/// leg death: dead transport -> `Relayed -> Disconnected` -> pin never
/// cleared -> every punch defers -> sawtooth. So:
///
/// 1. Both gateways behind **port-restricted** NAT (`nat_matrix.rs` case 1
///    proves this pairing punches to a real `Direct` WG handshake), ONE
///    `Killable` relay, and `build_scenario`'s `block_direct` blackholes so
///    the initial punches deterministically fail in transit and the pair's
///    only possible first convergence is `Relayed` — proven flowing exactly
///    like case 1.
/// 2. Lift the blackholes (direct becomes genuinely possible) and confirm
///    the pair deliberately STAYS relayed — the driver no-ops `ProbeDirect`
///    and filters punch directives against `relay_pointed`, so nothing may
///    move a healthy relayed pair (that cutover is the documented
///    fast-follow, not this case's subject; this also pins that the later
///    recovery is attributable to the leg-death handling, not the unblock).
/// 3. Sever both relay legs IN TRANSIT ([`sever_relay`]: the relay's `/32`
///    blackholed in both routers) — deliberately NOT case 3's
///    `RelayHandle::evict`/`quinn::Endpoint::close`, whose graceful
///    CONNECTION_CLOSE classifies as `RelayDeathReason::Closed` and takes
///    the eviction fast-path (immediate reconnect), a DIFFERENT driver
///    branch from the one that wedged in production. Pure silence means
///    both transports die only when QUIC's 30s idle timer expires
///    (`TimedOut` — see [`CASE4_DEATH_DETECTION_BUDGET`] for the exact
///    detection semantics), and with no reachable relay and a
///    punch-capable pairing, DIRECT is the only possible recovery —
///    exactly the window the wedge permanently blocks.
///
/// ## Why this cannot conflate with case 3's eviction re-path
///
/// Case 3's `RelaysChanged`-driven re-path kills R1 GRACEFULLY (a real
/// CONNECTION_CLOSE ⇒ `Closed` ⇒ the immediate-reconnect fast-path) with a
/// SECOND advertised relay standing by: the death is immediately followed
/// by a successful re-relay that the PEER also lands on, so traffic
/// recovers over R2 and the (re-pinned) `relay_pointed` is correct — no
/// wedge, and that behavior must keep working (case 3 stays green and
/// untouched as the `Closed`-branch pin). This case severs by SILENCE
/// (`TimedOut`), removes the second relay, and makes the NAT pairing
/// punch-capable, so the ONLY way to recover flow is the direct punch
/// window that clearing the pin grants — the two cases pin the two driver
/// branches of `RelayDied` respectively.
///
/// ## RED/GREEN discrimination
///
/// Pre-fix: `relay_pointed` stays pinned on both sides; every punch trial
/// defers (`DEFER_NEEDLE` once per sawtooth cycle, forever); and even if a
/// post-eviction `apply_state` rebuild happens to re-point WG at real
/// candidates and traffic leaks through, the stale pin routes every
/// corroborated handshake to `on_authenticated_inbound` instead of
/// `on_handshake(_, true)`, so `path_state` can NEVER reach `direct` — the
/// recovery assertion (direct + flowing ping) fails, and the defer count
/// shows the sawtooth. Post-fix: the relay-death action tears down the dead
/// transport, clears the pin, skips the immediate re-relay; the next punch
/// window commits real candidates on both sides, the handshake corroborates
/// -> `direct` on both, the ping crosses, defers stay ≤
/// `CASE4_MAX_POST_DEATH_DEFERS`. Expected timeline from the severance:
/// ~30s silent detection ([`CASE4_DEATH_DETECTION_BUDGET`]) + one or two
/// punch cycles (~10-30s) ≈ 40-60s total; the wait below is bounded by
/// detection budget + [`CASE4_RECOVERY_BUDGET`] so the recovery allowance
/// itself stays 90s-after-detection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn case4_relay_leg_death_unwedges_direct_punch() {
    // `InProcess` deliberately (NOT `Killable`): case 4 never closes the
    // relay — the severance is in-transit silence (`sever_relay`), and the
    // relay endpoint must stay alive and unclosed for the whole test so no
    // CONNECTION_CLOSE frame can possibly originate anywhere (a close would
    // classify `Closed` and take the eviction fast-path instead of the
    // `TimedOut` punch-window branch this case pins).
    let sc = build_scenario(
        "rm4",
        vec![RelaySpec::InProcess { addr: RELAY_ADDR, csr_tag: "relay-case4" }],
        NatKind::PortRestricted,
        true,
    )
    .await;
    let start = Instant::now();

    // Phase 1: with the direct lane blackholed, the pair's only possible
    // convergence is the relay — same reach-relayed bound and proof shape as
    // case 1 (state on both sides, flowing ping, local-relay-socket
    // endpoints).
    let mut last_log = Instant::now() - Duration::from_secs(5);
    let relayed = wait_until(Duration::from_secs(45), || {
        if last_log.elapsed() >= Duration::from_secs(5) {
            eprintln!(
                "case4: t+{:?} pre-death gwA={:?} gwB={:?}",
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
        dump_diag("case4 reach-relayed", &sc);
        panic!(
            "case4: blocked-direct port-restricted pair never reached path_state=relayed on \
             both sides (gwA={:?}, gwB={:?}) within 45s — the wedge scenario needs a \
             genuinely relayed starting point",
            path_state(&sc.gwa),
            path_state(&sc.gwb)
        );
    }
    let crossed = wait_until(Duration::from_secs(25), || ping_ok(&sc.wla, "10.10.12.2"));
    if !crossed {
        dump_diag("case4 ping-cross (relayed)", &sc);
        panic!("case4: wlA -> wlB ping never crossed the relayed tunnel before the leg death");
    }
    let ep_a_relayed = wg_endpoint(&sc.gwa);
    let ep_b_relayed = wg_endpoint(&sc.gwb);
    if !ep_a_relayed.as_deref().is_some_and(|e| e.starts_with("127.0.0.1:"))
        || !ep_b_relayed.as_deref().is_some_and(|e| e.starts_with("127.0.0.1:"))
    {
        dump_diag("case4 endpoint-check (relayed)", &sc);
        panic!(
            "case4: expected BOTH peers' WG endpoint on the local relay socket while \
             relayed, got gwA={ep_a_relayed:?} gwB={ep_b_relayed:?}"
        );
    }
    eprintln!(
        "case4: PASS pair is genuinely relayed and flowing in {:?} \
         (endpoints gwA={ep_a_relayed:?} gwB={ep_b_relayed:?})",
        start.elapsed()
    );

    // Phase 2: lift the blackholes — direct is now genuinely possible — and
    // confirm the healthy relayed pair deliberately stays put (see the doc
    // comment: nothing may disturb a live relay path until its leg actually
    // dies, so the later recovery is attributable to the death handling).
    unblock_direct(&sc);
    let settle_until = Instant::now() + Duration::from_secs(5);
    while Instant::now() < settle_until {
        let st_a = path_state(&sc.gwa);
        let st_b = path_state(&sc.gwb);
        if st_a.as_deref() != Some("relayed") || st_b.as_deref() != Some("relayed") {
            dump_diag("case4 post-unblock flap", &sc);
            panic!(
                "case4: pair left path_state=relayed after merely unblocking the direct \
                 lane (gwA={st_a:?}, gwB={st_b:?}) — a healthy relay path must not be \
                 disturbed before its leg dies; investigate before reading the recovery \
                 phase"
            );
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    eprintln!("case4: PASS pair stayed relayed across the unblock settle window");

    // Phase 3: sever both relay legs IN TRANSIT (silence, no close frame —
    // see `sever_relay`'s doc for the guarantees). Stderr offsets taken at
    // the severance instant scope the defer-spam count below to post-death
    // output only; the legs stay nominally healthy (path `Relayed`) for the
    // ~30s silent detection phase that follows, during which no defer line
    // can accrue (see `CASE4_MAX_POST_DEATH_DEFERS`).
    let defer_off_a = sc.pa.stderr_len();
    let defer_off_b = sc.pb.stderr_len();
    let severed_at = Instant::now();
    sever_relay(&sc);
    eprintln!("case4: severed both relay legs (silence, no close frame) at t+{:?}", start.elapsed());

    // Phase 4: THE regression assertion. Within detection budget + recovery
    // budget both sides must reach a REAL direct path — path_state=direct on
    // both AND a flowing workload ping. Requiring the state label (not just
    // the ping) is load-bearing: on pre-fix code the stale relay_pointed pin
    // routes every corroborated handshake away from the Direct cutover, so
    // even accidentally-flowing traffic can never produce `direct` — the
    // wedge is caught regardless of any data-plane luck. The ping attempts
    // double as the tunnel demand that drives boringtun's handshakes (same
    // pattern as case 1 / nat_matrix's establish_direct). Expect the first
    // ~30s of progress logs to show both sides still "relayed" — that is
    // the silent idle-timeout detection phase, not a failure.
    let recovery_bound = CASE4_DEATH_DETECTION_BUDGET + CASE4_RECOVERY_BUDGET;
    let mut last_log2 = Instant::now() - Duration::from_secs(5);
    let recovered = wait_until(recovery_bound, || {
        if last_log2.elapsed() >= Duration::from_secs(5) {
            eprintln!(
                "case4: t+{:?} post-severance gwA={:?} gwB={:?}",
                severed_at.elapsed(),
                path_state(&sc.gwa),
                path_state(&sc.gwb),
            );
            last_log2 = Instant::now();
        }
        path_state(&sc.gwa).as_deref() == Some("direct")
            && path_state(&sc.gwb).as_deref() == Some("direct")
            && ping_ok(&sc.wla, "10.10.12.2")
    });
    if !recovered {
        let defers_a = sc.pa.stderr_from(defer_off_a).matches(DEFER_NEEDLE).count();
        let defers_b = sc.pb.stderr_from(defer_off_b).matches(DEFER_NEEDLE).count();
        dump_diag("case4 wedge", &sc);
        panic!(
            "case4: pair never re-established a REAL direct path within {recovery_bound:?} of \
             the silent relay-leg severance (= {CASE4_DEATH_DETECTION_BUDGET:?} idle-timeout \
             detection + {CASE4_RECOVERY_BUDGET:?} recovery-after-detection; gwA={:?}, \
             gwB={:?}; {DEFER_NEEDLE:?} counted {defers_a}x on gwA / {defers_b}x on gwB since \
             the severance) — this is the aether-prod-fi-01 relay wedge: a relay leg dead of \
             silence (TimedOut) never clears relay_pointed, so every StartPunch cycle defers \
             its punch trial and the pair sawtooths Disconnected/Connecting (re-relaying at \
             each Connecting timeout) forever instead of getting one clean direct-punch \
             window",
            path_state(&sc.gwa),
            path_state(&sc.gwb)
        );
    }
    eprintln!(
        "case4: PASS pair recovered a direct flowing path {:?} after the severance \
         (~30s of that is the idle-timeout detection phase)",
        severed_at.elapsed()
    );

    // Concrete "really direct now" proof: both WG endpoints must be the
    // peer's ROUTABLE masqueraded address on the bridge (198.51.100.x) — a
    // 127.0.0.1 endpoint would mean still pointed at a (dead) relay socket.
    let ep_a_direct = wg_endpoint(&sc.gwa);
    let ep_b_direct = wg_endpoint(&sc.gwb);
    if !ep_a_direct.as_deref().is_some_and(|e| e.starts_with("198.51.100."))
        || !ep_b_direct.as_deref().is_some_and(|e| e.starts_with("198.51.100."))
    {
        dump_diag("case4 endpoint-check (direct)", &sc);
        panic!(
            "case4: expected BOTH recovered WG endpoints on routable bridge addresses \
             (198.51.100.x), got gwA={ep_a_direct:?} gwB={ep_b_direct:?}"
        );
    }
    eprintln!(
        "case4: PASS recovered endpoints are routable direct candidates \
         (gwA={ep_a_direct:?} gwB={ep_b_direct:?})"
    );

    // Defer-spam bound (the second RED signal): after the severance the
    // "deferring direct punch" line must not repeat unboundedly. See
    // `CASE4_MAX_POST_DEATH_DEFERS` for the pre-fix (~1 per sawtooth cycle,
    // forever) vs post-fix (at most a benign in-flight-trial race per failed
    // recovery cycle) separation, and for the two known un-modeled flake
    // margins to check before reading a red here as the wedge regressing.
    let defers_a = sc.pa.stderr_from(defer_off_a).matches(DEFER_NEEDLE).count();
    let defers_b = sc.pb.stderr_from(defer_off_b).matches(DEFER_NEEDLE).count();
    if defers_a > CASE4_MAX_POST_DEATH_DEFERS || defers_b > CASE4_MAX_POST_DEATH_DEFERS {
        dump_diag("case4 defer-spam", &sc);
        panic!(
            "case4: counted {DEFER_NEEDLE:?} {defers_a}x on gwA and {defers_b}x on gwB after \
             the relay leg severance (tolerance: <={CASE4_MAX_POST_DEATH_DEFERS} each) — punch \
             trials are still being deferred against a relay path that is DEAD, i.e. the \
             relay_pointed pin outlived its transport (see CASE4_MAX_POST_DEATH_DEFERS's doc \
             for the two benign margins to rule out first)"
        );
    }
    eprintln!(
        "case4: PASS defer-spam bound — {defers_a} (gwA) / {defers_b} (gwB) deferred-punch \
         lines since the severance"
    );

    // Stability hold: the recovered direct path must be a real steady state,
    // not a transient reading — and no late sawtooth may resume (final defer
    // recount covers the whole post-death window including this hold).
    let hold_until = Instant::now() + Duration::from_secs(20);
    while Instant::now() < hold_until {
        let st_a = path_state(&sc.gwa);
        let st_b = path_state(&sc.gwb);
        if st_a.as_deref() != Some("direct") || st_b.as_deref() != Some("direct") {
            dump_diag("case4 direct-hold flap", &sc);
            panic!(
                "case4: recovered pair did not STAY path_state=direct \
                 (gwA={st_a:?}, gwB={st_b:?} during the 20s stability hold)"
            );
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    if !ping_ok(&sc.wla, "10.10.12.2") {
        dump_diag("case4 direct-hold ping", &sc);
        panic!("case4: wlA -> wlB ping stopped crossing during the post-recovery hold");
    }
    let defers_a = sc.pa.stderr_from(defer_off_a).matches(DEFER_NEEDLE).count();
    let defers_b = sc.pb.stderr_from(defer_off_b).matches(DEFER_NEEDLE).count();
    if defers_a > CASE4_MAX_POST_DEATH_DEFERS || defers_b > CASE4_MAX_POST_DEATH_DEFERS {
        dump_diag("case4 defer-spam (post-hold)", &sc);
        panic!(
            "case4: defer lines kept accruing after recovery — {defers_a}x gwA / {defers_b}x \
             gwB across the whole post-death window (tolerance \
             <={CASE4_MAX_POST_DEATH_DEFERS} each)"
        );
    }

    eprintln!(
        "CASE 4 PASS: relayed pair whose relay legs died of silence recovered a REAL direct \
         path in {:?} from the severance (~30s of that is idle-timeout detection; endpoints \
         gwA={ep_a_direct:?} gwB={ep_b_direct:?}, defers gwA={defers_a} gwB={defers_b}; \
         total test time {:?}).",
        severed_at.elapsed(),
        start.elapsed()
    );
}
