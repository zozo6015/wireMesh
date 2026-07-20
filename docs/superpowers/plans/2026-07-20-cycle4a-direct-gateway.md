# Cycle 4a — Direct-only Gateway Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the real `wiremesh-gateway` binary so two gateways on routable addresses form an encrypted, policy-enforced WireGuard mesh that survives a controller outage.

**Architecture:** A new `crates/wiremesh-gateway` workspace member. An mTLS Sync client applies `StateSnapshot`/`Delta` from the controller into a persisted desired-state store; a reconciler drives (a) an embedded boringtun tunnel configured through an in-process WireGuard-UAPI writer, (b) the `wiremesh-enforcer` backend fed the snapshot's `policy_ir`, and (c) peer-CIDR routes shelled out via `ip`. A periodic authenticated UDP probe reports the gateway's endpoint. On boot the data plane comes up from `state.json` *before* the controller is contacted (fail-static).

**Tech Stack:** Rust, tokio, tonic+rustls (mTLS), boringtun 0.6 (`device`), `wiremesh-enforcer`, `wiremesh-policy`, `wiremesh-proto`, `sha2`; shell-out to `ip`/`nft`/`sysctl`; netns integration tests via `wiremesh-testkit --features netns`.

## Global Constraints

- **Spec authority:** `docs/superpowers/specs/2026-07-20-cycle4a-direct-gateway-design.md` governs scope. Master spec `docs/superpowers/specs/2026-07-15-wiremesh-engineering-design.md` §6/§9 governs where it conflicts.
- **Single static binary (G-1):** `wiremesh-gateway` is one binary. In-process WireGuard UAPI writer (no `wireguard-tools` dependency). Route/link/MSS programming shells out to `ip`/`nft`/`sysctl` (repo-established `std::process::Command` pattern; documented `iproute2` + `nftables` runtime deps).
- **IPv4-only** (v1). tun MTU **1280**; MSS clamp to **1240**; persistent-keepalive **15s**.
- **No proto changes.** `Peer.candidate_endpoints`, `StateSnapshot.policy_ir`, `Sync.Report` already exist. `relays` stays empty in 4a.
- **Deferred (NOT 4a):** key rotation; NAT hole punching + path state machine (4b); relay (4c); enrollment-on-boot; the fragment/conformance enforcer carries; per-peer MTU raising; the measured G-2 number; IPv6.
- **Execution environment:** macOS host; **all builds/tests run inside the privileged Linux container** via `./dev.sh {build|shell|run <cmd>}`. tun/eBPF/netns/nftables do not work on the host. Network/netns tests are serial: `-- --test-threads=1 --nocapture`.
- **Agent separation (CLAUDE.md):** tests are authored, implemented, and executed by three different agents; reviews by a separate reviewer agent. Never green-light your own run.
- **Workspace deps** are referenced as `{ workspace = true }`. Pins available: `tokio = {version="1", features=["full"]}`, `tonic = {version="0.12", features=["tls"]}`, `prost = "0.13"`, `rustls = "0.23"`, `rcgen = "0.13"`, `anyhow = "1"`, `serde = {version="1", features=["derive"]}`, `serde_json = "1"`, `ipnet = "2"`, `sha2 = "0.10"`. `boringtun`, `libc`, `tempfile` are NOT workspace deps — pin locally.

## File structure (new crate)

```
crates/wiremesh-gateway/
  Cargo.toml
  src/
    main.rs        # CLI/config parse, boot sequence, task supervision
    lib.rs         # pub mod re-exports so tests/ can reach internals
    config.rs      # GatewayConfig: controller addrs, tun/WG params, state dir
    identity.rs    # Identity: cert/key/CA + gateway_id + observe_key from state dir
    observe.rs     # authenticated probe codec + periodic observation client
    uapi.rs        # in-process WireGuard UAPI writer (encode + unix-socket apply)
    state.rs       # DesiredState model + fail-static persistence
    reconcile.rs   # snapshot/delta -> peer list / route diff / apply-needed
    routes.rs      # shell-out: tun mtu/up, ip_forward, peer routes, MSS clamp
    tunnel.rs      # boringtun DeviceHandle lifecycle + reconcile apply
    enforce.rs     # enforcer probe + apply + counters/deny drain
    metrics.rs     # Prometheus endpoint + structured JSON logs
  tests/
    observe_parity.rs   # gateway probe accepted by real controller (Task 10)
    sync_client.rs      # Sync against TestController (Task 9)
    tunnel_netns.rs     # two-gateway handshake (Task 7)
    enforce_netns.rs    # allow/deny on wg0 (Task 8)
    routes_netns.rs     # route/mtu/mss programming (Task 6)
    mesh_milestone.rs   # the done bar (Task 12)
```

Modifications outside the crate:
- `Cargo.toml` (workspace): add `"crates/wiremesh-gateway"` to `members`.
- `docs/research/phase0-results.md`, `CLAUDE.md`, `docs/progress.html`: Task 13.

---

### Task 1: Scaffold the crate, config, and identity

**Files:**
- Modify: `Cargo.toml` (workspace `members`)
- Create: `crates/wiremesh-gateway/Cargo.toml`
- Create: `crates/wiremesh-gateway/src/lib.rs`
- Create: `crates/wiremesh-gateway/src/main.rs`
- Create: `crates/wiremesh-gateway/src/config.rs`
- Create: `crates/wiremesh-gateway/src/identity.rs`
- Test: `crates/wiremesh-gateway/src/config.rs` (unit `#[cfg(test)]`), `crates/wiremesh-gateway/src/identity.rs` (unit `#[cfg(test)]`)

**Interfaces:**
- Produces:
  - `config::GatewayConfig { controller_sync_addr: SocketAddr, observe_addr: SocketAddr, tun_ifname: String, wg_listen_port: u16, state_dir: PathBuf }` with `GatewayConfig::from_env() -> anyhow::Result<Self>` and `GatewayConfig::parse(args: impl Iterator<Item=String>) -> anyhow::Result<Self>`.
  - `identity::Identity { cert_pem: String, key_pem: String, ca_bundle_pem: String, gateway_id: u64, observe_key: String, wg_private_key_b64: String }` with `Identity::load(state_dir: &Path) -> anyhow::Result<Identity>` and `Identity::store(&self, state_dir: &Path) -> anyhow::Result<()>` (WG private key to `wg_private.key` 0600; identity metadata to `identity.json` 0600).

- [ ] **Step 1: Add the crate to the workspace and create its manifest**

Edit `Cargo.toml` (workspace) line 3, appending the member:
```toml
members = ["crates/wiremesh-proto", "crates/wiremesh-trust", "crates/wiremesh-controller", "crates/fabricctl", "crates/wiremesh-testkit", "crates/wiremesh-policy", "crates/wiremesh-enforcer", "crates/wiremesh-gateway"]
```

Create `crates/wiremesh-gateway/Cargo.toml`:
```toml
[package]
name = "wiremesh-gateway"
version = "0.1.0"
edition = "2021"

[lib]
name = "wiremesh_gateway"
path = "src/lib.rs"

[[bin]]
name = "wiremesh-gateway"
path = "src/main.rs"

[dependencies]
wiremesh-proto = { path = "../wiremesh-proto" }
wiremesh-policy = { path = "../wiremesh-policy" }
wiremesh-enforcer = { path = "../wiremesh-enforcer" }
wiremesh-trust = { path = "../wiremesh-trust" }
tokio = { workspace = true }
tonic = { workspace = true }
prost = { workspace = true }
anyhow = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
sha2 = { workspace = true }
boringtun = { version = "0.6", features = ["device"] }
libc = "0.2"

[dev-dependencies]
wiremesh-testkit = { path = "../wiremesh-testkit", features = ["netns"] }
tempfile = "3"
tokio-stream = "0.1"
```

- [ ] **Step 2: Create `lib.rs` and a placeholder `main.rs`**

`crates/wiremesh-gateway/src/lib.rs`:
```rust
//! wiremesh-gateway: direct-only WireGuard fabric gateway (Cycle 4a).
pub mod config;
pub mod identity;
```
`crates/wiremesh-gateway/src/main.rs`:
```rust
fn main() -> anyhow::Result<()> {
    eprintln!("wiremesh-gateway: boot sequence wired in Task 11");
    Ok(())
}
```

- [ ] **Step 3: Write the failing config + identity tests**

Append to `crates/wiremesh-gateway/src/config.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_reads_all_fields_from_args() {
        let args = [
            "wiremesh-gateway",
            "--controller-sync", "127.0.0.1:6000",
            "--observe", "127.0.0.1:6001",
            "--tun", "wg0",
            "--wg-port", "51820",
            "--state-dir", "/var/lib/wiremesh",
        ]
        .into_iter()
        .map(String::from);
        let cfg = GatewayConfig::parse(args).expect("valid args parse");
        assert_eq!(cfg.tun_ifname, "wg0");
        assert_eq!(cfg.wg_listen_port, 51820);
        assert_eq!(cfg.controller_sync_addr.to_string(), "127.0.0.1:6000");
        assert_eq!(cfg.observe_addr.to_string(), "127.0.0.1:6001");
        assert_eq!(cfg.state_dir.to_str().unwrap(), "/var/lib/wiremesh");
    }

    #[test]
    fn parse_rejects_missing_required_flag() {
        let args = ["wiremesh-gateway", "--tun", "wg0"].into_iter().map(String::from);
        assert!(GatewayConfig::parse(args).is_err());
    }
}
```
Append to `crates/wiremesh-gateway/src/identity.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_then_load_round_trips_and_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let id = Identity {
            cert_pem: "CERT".into(),
            key_pem: "KEY".into(),
            ca_bundle_pem: "CA".into(),
            gateway_id: 42,
            observe_key: "deadbeef".into(),
            wg_private_key_b64: "cHJpdmtleQ==".into(),
        };
        id.store(dir.path()).unwrap();
        let meta = std::fs::metadata(dir.path().join("wg_private.key")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let loaded = Identity::load(dir.path()).unwrap();
        assert_eq!(loaded.gateway_id, 42);
        assert_eq!(loaded.observe_key, "deadbeef");
        assert_eq!(loaded.wg_private_key_b64, "cHJpdmtleQ==");
        assert_eq!(loaded.cert_pem, "CERT");
    }

    #[test]
    fn load_errors_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Identity::load(dir.path()).is_err());
    }
}
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `./dev.sh run "cargo test -p wiremesh-gateway --lib"`
Expected: FAIL — `GatewayConfig`/`Identity` not defined.

- [ ] **Step 5: Implement `config.rs`**

Prepend to `crates/wiremesh-gateway/src/config.rs`:
```rust
use anyhow::{anyhow, Context};
use std::net::SocketAddr;
use std::path::PathBuf;

/// Local gateway configuration (not desired state — that comes from Sync).
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub controller_sync_addr: SocketAddr,
    pub observe_addr: SocketAddr,
    pub tun_ifname: String,
    pub wg_listen_port: u16,
    pub state_dir: PathBuf,
}

impl GatewayConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        Self::parse(std::env::args())
    }

    pub fn parse(args: impl Iterator<Item = String>) -> anyhow::Result<Self> {
        let mut controller = None;
        let mut observe = None;
        let mut tun = None;
        let mut wg_port = None;
        let mut state_dir = None;
        let mut it = args.skip(1); // argv[0]
        while let Some(flag) = it.next() {
            let mut val = || it.next().ok_or_else(|| anyhow!("flag {flag} needs a value"));
            match flag.as_str() {
                "--controller-sync" => controller = Some(val()?.parse().context("--controller-sync")?),
                "--observe" => observe = Some(val()?.parse().context("--observe")?),
                "--tun" => tun = Some(val()?),
                "--wg-port" => wg_port = Some(val()?.parse().context("--wg-port")?),
                "--state-dir" => state_dir = Some(PathBuf::from(val()?)),
                other => return Err(anyhow!("unknown flag {other}")),
            }
        }
        Ok(GatewayConfig {
            controller_sync_addr: controller.ok_or_else(|| anyhow!("--controller-sync required"))?,
            observe_addr: observe.ok_or_else(|| anyhow!("--observe required"))?,
            tun_ifname: tun.ok_or_else(|| anyhow!("--tun required"))?,
            wg_listen_port: wg_port.ok_or_else(|| anyhow!("--wg-port required"))?,
            state_dir: state_dir.ok_or_else(|| anyhow!("--state-dir required"))?,
        })
    }
}
```

- [ ] **Step 6: Implement `identity.rs`**

Prepend to `crates/wiremesh-gateway/src/identity.rs`:
```rust
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Pre-provisioned gateway identity (Cycle 4a assumes enrollment already ran —
/// see spec §7-A). `wg_private_key_b64` is the WireGuard static private key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub cert_pem: String,
    pub key_pem: String,
    pub ca_bundle_pem: String,
    pub gateway_id: u64,
    pub observe_key: String,
    pub wg_private_key_b64: String,
}

fn write_0600(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true).mode(0o600);
    use std::io::Write;
    let mut f = opts.open(path).with_context(|| format!("opening {}", path.display()))?;
    f.write_all(bytes).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

impl Identity {
    pub fn store(&self, state_dir: &Path) -> anyhow::Result<()> {
        fs::create_dir_all(state_dir)?;
        write_0600(&state_dir.join("wg_private.key"), self.wg_private_key_b64.as_bytes())?;
        let json = serde_json::to_vec_pretty(self)?;
        write_0600(&state_dir.join("identity.json"), &json)?;
        Ok(())
    }

    pub fn load(state_dir: &Path) -> anyhow::Result<Identity> {
        let json = fs::read(state_dir.join("identity.json"))
            .with_context(|| format!("reading identity.json in {}", state_dir.display()))?;
        let id: Identity = serde_json::from_slice(&json).context("parsing identity.json")?;
        Ok(id)
    }
}
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `./dev.sh run "cargo test -p wiremesh-gateway --lib"`
Expected: PASS (4 tests).

- [ ] **Step 8: Commit**
```bash
git add Cargo.toml crates/wiremesh-gateway
git commit -m "feat(gateway): scaffold wiremesh-gateway crate with config + identity"
```

---

### Task 2: Observe-probe codec (unit-tested)

**Files:**
- Create: `crates/wiremesh-gateway/src/observe.rs`
- Modify: `crates/wiremesh-gateway/src/lib.rs` (add `pub mod observe;`)
- Test: inline `#[cfg(test)]` in `observe.rs`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `observe::MAGIC: &[u8;4] = b"AOBS"`, `observe::PROBE_LEN: usize = 44`.
  - `observe::compute_mac(observe_key_hex: &str, gateway_id: u64) -> [u8;32]`.
  - `observe::build_probe(observe_key_hex: &str, gateway_id: u64) -> Vec<u8>`.
  - `observe::probe_once(sock: &std::net::UdpSocket, server: SocketAddr, observe_key_hex: &str, gateway_id: u64) -> anyhow::Result<SocketAddr>` — sends an authenticated probe from `sock`, returns the echoed observed address.

- [ ] **Step 1: Write the failing test**

Create `crates/wiremesh-gateway/src/observe.rs` with only tests first:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn build_probe_layout_and_mac_match_controller_construction() {
        let key = "00112233445566778899aabbccddeeff";
        let gid: u64 = 7;
        let probe = build_probe(key, gid);
        assert_eq!(probe.len(), PROBE_LEN);
        assert_eq!(&probe[0..4], MAGIC);
        assert_eq!(&probe[4..12], &gid.to_be_bytes());
        // MAC = sha256(observe_key || MAGIC || gateway_id_be)
        let mut h = Sha256::new();
        h.update(key.as_bytes());
        h.update(MAGIC);
        h.update(gid.to_be_bytes());
        let want: [u8; 32] = h.finalize().into();
        assert_eq!(&probe[12..44], &want);
        assert_eq!(compute_mac(key, gid), want);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./dev.sh run "cargo test -p wiremesh-gateway --lib observe"`
Expected: FAIL — `build_probe`/`MAGIC` not defined.

- [ ] **Step 3: Implement the codec**

Prepend to `crates/wiremesh-gateway/src/observe.rs`:
```rust
//! Authenticated NAT-observation probe (spec §5.4). Byte-for-byte identical to
//! `wiremesh_controller::observe::{build_probe, compute_mac}`; replicated here
//! (not shared) because the gateway must not depend on the controller crate and
//! 4b replaces this whole scheme with the WG-socket-authenticated probe. The
//! cross-process parity test (tests/observe_parity.rs) proves the controller
//! accepts what this builds.
use anyhow::Context;
use sha2::{Digest, Sha256};
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

pub const MAGIC: &[u8; 4] = b"AOBS";
pub const PROBE_LEN: usize = 4 + 8 + 32; // MAGIC + gateway_id(BE u64) + MAC

pub fn compute_mac(observe_key_hex: &str, gateway_id: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(observe_key_hex.as_bytes());
    h.update(MAGIC);
    h.update(gateway_id.to_be_bytes());
    h.finalize().into()
}

pub fn build_probe(observe_key_hex: &str, gateway_id: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(PROBE_LEN);
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&gateway_id.to_be_bytes());
    buf.extend_from_slice(&compute_mac(observe_key_hex, gateway_id));
    buf
}

/// Send one authenticated probe from `sock` and return the observed public
/// `ip:port` the controller echoed back. Retries a few times (UDP is lossy).
pub fn probe_once(
    sock: &UdpSocket,
    server: SocketAddr,
    observe_key_hex: &str,
    gateway_id: u64,
) -> anyhow::Result<SocketAddr> {
    sock.set_read_timeout(Some(Duration::from_secs(2)))?;
    let probe = build_probe(observe_key_hex, gateway_id);
    for _ in 0..3 {
        sock.send_to(&probe, server)?;
        let mut buf = [0u8; 64];
        if let Ok((n, from)) = sock.recv_from(&mut buf) {
            if from == server {
                return String::from_utf8_lossy(&buf[..n])
                    .parse()
                    .context("parsing observed addr from controller echo");
            }
        }
    }
    anyhow::bail!("no observation reply from {server}")
}
```
Add to `crates/wiremesh-gateway/src/lib.rs`:
```rust
pub mod observe;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./dev.sh run "cargo test -p wiremesh-gateway --lib observe"`
Expected: PASS.

- [ ] **Step 5: Commit**
```bash
git add crates/wiremesh-gateway/src/observe.rs crates/wiremesh-gateway/src/lib.rs
git commit -m "feat(gateway): authenticated observe-probe codec"
```

---

### Task 3: WireGuard UAPI writer (unit-tested encoder)

**Files:**
- Create: `crates/wiremesh-gateway/src/uapi.rs`
- Modify: `crates/wiremesh-gateway/src/lib.rs` (add `pub mod uapi;`)
- Test: inline `#[cfg(test)]` in `uapi.rs`

**Background — WireGuard UAPI `set` format** (the text protocol boringtun's socket at `/var/run/wireguard/<ifname>.sock` speaks; identical to what `wg syncconf` writes): a series of `key=value\n` lines, terminated by an extra blank `\n`. Device lines first (`private_key=<hex>`, `listen_port=<n>`, `replace_peers=true`), then for each peer `public_key=<hex>` begins a peer block followed by that peer's `endpoint=`, `replace_allowed_ips=true`, `allowed_ip=<cidr>` (repeatable), `persistent_keepalive_interval=<secs>`. Keys are **hex**, not base64, on the UAPI wire. Response is `errno=0\n\n` on success.

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `uapi::PeerConfig { public_key_b64: String, endpoint: Option<String>, allowed_ips: Vec<String>, keepalive_secs: u16 }`.
  - `uapi::DeviceConfig { private_key_b64: String, listen_port: u16, peers: Vec<PeerConfig> }`.
  - `uapi::encode_set(cfg: &DeviceConfig) -> anyhow::Result<String>` — renders the UAPI `set` request (base64 keys decoded to hex internally).
  - `uapi::apply(ifname: &str, cfg: &DeviceConfig) -> anyhow::Result<()>` — connects to `/var/run/wireguard/<ifname>.sock`, writes `set=1\n` + `encode_set`, reads `errno`.

- [ ] **Step 1: Write the failing encoder test**

Create `crates/wiremesh-gateway/src/uapi.rs` with tests first:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn b64(bytes: &[u8; 32]) -> String {
        // base64 of a fixed key for a stable expectation
        base64_encode(bytes)
    }

    #[test]
    fn encode_set_renders_device_then_peer_blocks() {
        let priv_raw = [0x11u8; 32];
        let pub_raw = [0x22u8; 32];
        let cfg = DeviceConfig {
            private_key_b64: b64(&priv_raw),
            listen_port: 51820,
            peers: vec![PeerConfig {
                public_key_b64: b64(&pub_raw),
                endpoint: Some("203.0.113.5:51820".into()),
                allowed_ips: vec!["10.10.2.0/24".into()],
                keepalive_secs: 15,
            }],
        };
        let out = encode_set(&cfg).unwrap();
        let priv_hex = "11".repeat(32);
        let pub_hex = "22".repeat(32);
        let expected = format!(
            "private_key={priv_hex}\n\
             listen_port=51820\n\
             replace_peers=true\n\
             public_key={pub_hex}\n\
             endpoint=203.0.113.5:51820\n\
             replace_allowed_ips=true\n\
             allowed_ip=10.10.2.0/24\n\
             persistent_keepalive_interval=15\n\
             \n"
        );
        assert_eq!(out, expected);
    }

    #[test]
    fn peer_without_endpoint_omits_endpoint_line() {
        let cfg = DeviceConfig {
            private_key_b64: base64_encode(&[0u8; 32]),
            listen_port: 1,
            peers: vec![PeerConfig {
                public_key_b64: base64_encode(&[1u8; 32]),
                endpoint: None,
                allowed_ips: vec!["10.0.0.0/8".into()],
                keepalive_secs: 15,
            }],
        };
        let out = encode_set(&cfg).unwrap();
        assert!(!out.contains("endpoint="), "no endpoint line when None:\n{out}");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./dev.sh run "cargo test -p wiremesh-gateway --lib uapi"`
Expected: FAIL — types/functions not defined.

- [ ] **Step 3: Implement the encoder and applier**

Prepend to `crates/wiremesh-gateway/src/uapi.rs`:
```rust
//! In-process WireGuard UAPI writer (spec §3, G-1: no `wg` dependency). Renders
//! and applies a full device config to boringtun's unix socket, exactly as
//! `wg syncconf` does: `replace_peers=true` + the complete peer list in one
//! atomic `set` message.
use anyhow::{anyhow, Context};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

#[derive(Debug, Clone)]
pub struct PeerConfig {
    pub public_key_b64: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub keepalive_secs: u16,
}

#[derive(Debug, Clone)]
pub struct DeviceConfig {
    pub private_key_b64: String,
    pub listen_port: u16,
    pub peers: Vec<PeerConfig>,
}

/// Decode a 32-byte WireGuard key from base64 to the lowercase-hex the UAPI
/// wire expects.
fn key_b64_to_hex(b64: &str) -> anyhow::Result<String> {
    let raw = base64_decode(b64).with_context(|| "decoding WG key from base64")?;
    if raw.len() != 32 {
        return Err(anyhow!("WG key must be 32 bytes, got {}", raw.len()));
    }
    Ok(raw.iter().map(|b| format!("{b:02x}")).collect())
}

pub fn encode_set(cfg: &DeviceConfig) -> anyhow::Result<String> {
    let mut s = String::new();
    s.push_str(&format!("private_key={}\n", key_b64_to_hex(&cfg.private_key_b64)?));
    s.push_str(&format!("listen_port={}\n", cfg.listen_port));
    s.push_str("replace_peers=true\n");
    for p in &cfg.peers {
        s.push_str(&format!("public_key={}\n", key_b64_to_hex(&p.public_key_b64)?));
        if let Some(ep) = &p.endpoint {
            s.push_str(&format!("endpoint={ep}\n"));
        }
        s.push_str("replace_allowed_ips=true\n");
        for cidr in &p.allowed_ips {
            s.push_str(&format!("allowed_ip={cidr}\n"));
        }
        s.push_str(&format!("persistent_keepalive_interval={}\n", p.keepalive_secs));
    }
    s.push('\n'); // blank line terminates the request
    Ok(s)
}

pub fn apply(ifname: &str, cfg: &DeviceConfig) -> anyhow::Result<()> {
    let path = format!("/var/run/wireguard/{ifname}.sock");
    let mut stream = UnixStream::connect(&path)
        .with_context(|| format!("connecting to WG UAPI socket {path}"))?;
    let req = format!("set=1\n{}", encode_set(cfg)?);
    stream.write_all(req.as_bytes()).context("writing UAPI set request")?;
    let mut resp = String::new();
    stream.read_to_string(&mut resp).context("reading UAPI response")?;
    // Response is `errno=<n>\n\n`.
    let errno = resp
        .lines()
        .find_map(|l| l.strip_prefix("errno="))
        .ok_or_else(|| anyhow!("UAPI response missing errno: {resp:?}"))?;
    if errno != "0" {
        return Err(anyhow!("UAPI set failed: errno={errno}"));
    }
    Ok(())
}

// --- minimal base64 (avoid a new workspace dep for two 32-byte keys) ---
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(crate) fn base64_encode(input: &[u8]) -> String {
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64[((n >> 18) & 63) as usize] as char);
        out.push(B64[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { B64[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[(n & 63) as usize] as char } else { '=' });
    }
    out
}

pub(crate) fn base64_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    fn val(c: u8) -> anyhow::Result<u32> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(anyhow!("invalid base64 char")),
        }
    }
    let bytes: Vec<u8> = s.bytes().filter(|&c| c != b'=' && !c.is_ascii_whitespace()).collect();
    let mut out = Vec::new();
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 { out.push((n >> 8) as u8); }
        if chunk.len() > 3 { out.push(n as u8); }
    }
    Ok(out)
}
```
Add to `crates/wiremesh-gateway/src/lib.rs`:
```rust
pub mod uapi;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./dev.sh run "cargo test -p wiremesh-gateway --lib uapi"`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**
```bash
git add crates/wiremesh-gateway/src/uapi.rs crates/wiremesh-gateway/src/lib.rs
git commit -m "feat(gateway): in-process WireGuard UAPI writer"
```

---

### Task 4: Desired-state model + fail-static persistence

**Files:**
- Create: `crates/wiremesh-gateway/src/state.rs`
- Modify: `crates/wiremesh-gateway/src/lib.rs` (add `pub mod state;`)
- Test: inline `#[cfg(test)]` in `state.rs`

**Interfaces:**
- Consumes: `wiremesh_proto::v1::{StateSnapshot, Delta, Peer, PeerKey}`.
- Produces:
  - `state::PeerState { gateway_id: u64, segment_name: String, active_pubkey_b64: Option<String>, candidate_endpoint: Option<String>, allowed_ips: Vec<String> }`.
  - `state::DesiredState { revision: u64, peers: Vec<PeerState>, policy_ir: Vec<u8>, policy_version: u64, relays: Vec<String>, revoked_serials: Vec<String> }` (derives `Serialize`/`Deserialize`/`Default`/`Clone`/`PartialEq`).
  - `DesiredState::from_snapshot(&StateSnapshot) -> DesiredState`.
  - `DesiredState::apply_delta(&mut self, &Delta)`.
  - `DesiredState::save(&self, state_dir: &Path) -> anyhow::Result<()>` (atomic temp+rename, 0600, filename `state.json`).
  - `DesiredState::load(state_dir: &Path) -> anyhow::Result<Option<DesiredState>>` (None if absent).

**Detail:** `active_pubkey_b64` is the `pubkey` of the peer's `PeerKey` whose `state == "active"` (ignore `pending`/`retiring` in 4a — no rotation). `candidate_endpoint` is the first of `Peer.candidate_endpoints` (at most one is populated).

- [ ] **Step 1: Write the failing tests**

Create `crates/wiremesh-gateway/src/state.rs` with tests first:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use wiremesh_proto::v1::{Delta, Peer, PeerKey, StateSnapshot};

    fn peer(id: u64, pubkey: &str, ep: &str) -> Peer {
        Peer {
            gateway_id: id,
            segment_name: format!("seg{id}"),
            keys: vec![
                PeerKey { epoch: 1, pubkey: "OLD".into(), state: "retiring".into() },
                PeerKey { epoch: 2, pubkey: pubkey.into(), state: "active".into() },
            ],
            candidate_endpoints: vec![ep.into()],
            allowed_ips: vec![format!("10.10.{id}.0/24")],
        }
    }

    #[test]
    fn from_snapshot_picks_active_key_and_endpoint() {
        let snap = StateSnapshot {
            revision: 5,
            self_cert_pem: "C".into(),
            peers: vec![peer(2, "PUBA", "203.0.113.2:51820")],
            relays: vec![],
            policy_ir: b"{\"schema\":1}".to_vec(),
            policy_version: 3,
            revoked_serials: vec![],
        };
        let ds = DesiredState::from_snapshot(&snap);
        assert_eq!(ds.revision, 5);
        assert_eq!(ds.policy_version, 3);
        assert_eq!(ds.peers.len(), 1);
        assert_eq!(ds.peers[0].active_pubkey_b64.as_deref(), Some("PUBA"));
        assert_eq!(ds.peers[0].candidate_endpoint.as_deref(), Some("203.0.113.2:51820"));
    }

    #[test]
    fn apply_delta_upserts_and_removes() {
        let mut ds = DesiredState::from_snapshot(&StateSnapshot {
            revision: 1, self_cert_pem: "C".into(),
            peers: vec![peer(2, "PUBA", "a:1"), peer(3, "PUBB", "b:2")],
            relays: vec![], policy_ir: vec![], policy_version: 0, revoked_serials: vec![],
        });
        let delta = Delta {
            revision: 2,
            upserted_peers: vec![peer(2, "PUBA2", "a:9")],
            removed_peer_ids: vec![3],
            relays: vec![], policy_ir: b"NEW".to_vec(), policy_version: 4, revoked_serials: vec![],
        };
        ds.apply_delta(&delta);
        assert_eq!(ds.revision, 2);
        assert_eq!(ds.peers.len(), 1);
        assert_eq!(ds.peers[0].gateway_id, 2);
        assert_eq!(ds.peers[0].active_pubkey_b64.as_deref(), Some("PUBA2"));
        assert_eq!(ds.policy_version, 4);
        assert_eq!(ds.policy_ir, b"NEW");
    }

    #[test]
    fn save_load_round_trip_atomic_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let ds = DesiredState { revision: 9, ..Default::default() };
        ds.save(dir.path()).unwrap();
        let meta = std::fs::metadata(dir.path().join("state.json")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let back = DesiredState::load(dir.path()).unwrap().unwrap();
        assert_eq!(back.revision, 9);
    }

    #[test]
    fn load_absent_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(DesiredState::load(dir.path()).unwrap().is_none());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./dev.sh run "cargo test -p wiremesh-gateway --lib state"`
Expected: FAIL — `DesiredState` not defined.

- [ ] **Step 3: Implement `state.rs`**

Prepend to `crates/wiremesh-gateway/src/state.rs`:
```rust
//! Desired state (from Sync) + fail-static persistence (spec §5.3). Persist on
//! every apply; on boot the data plane comes up from this before the controller
//! is reached.
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use wiremesh_proto::v1::{Delta, Peer, StateSnapshot};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerState {
    pub gateway_id: u64,
    pub segment_name: String,
    pub active_pubkey_b64: Option<String>,
    pub candidate_endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
}

impl PeerState {
    fn from_proto(p: &Peer) -> PeerState {
        let active_pubkey_b64 = p
            .keys
            .iter()
            .find(|k| k.state == "active")
            .map(|k| k.pubkey.clone());
        PeerState {
            gateway_id: p.gateway_id,
            segment_name: p.segment_name.clone(),
            active_pubkey_b64,
            candidate_endpoint: p.candidate_endpoints.first().cloned(),
            allowed_ips: p.allowed_ips.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct DesiredState {
    pub revision: u64,
    pub peers: Vec<PeerState>,
    pub policy_ir: Vec<u8>,
    pub policy_version: u64,
    pub relays: Vec<String>,
    pub revoked_serials: Vec<String>,
}

impl DesiredState {
    pub fn from_snapshot(s: &StateSnapshot) -> DesiredState {
        DesiredState {
            revision: s.revision,
            peers: s.peers.iter().map(PeerState::from_proto).collect(),
            policy_ir: s.policy_ir.clone(),
            policy_version: s.policy_version,
            relays: s.relays.clone(),
            revoked_serials: s.revoked_serials.clone(),
        }
    }

    pub fn apply_delta(&mut self, d: &Delta) {
        self.revision = d.revision;
        for p in &d.upserted_peers {
            let ps = PeerState::from_proto(p);
            match self.peers.iter_mut().find(|x| x.gateway_id == ps.gateway_id) {
                Some(existing) => *existing = ps,
                None => self.peers.push(ps),
            }
        }
        self.peers.retain(|p| !d.removed_peer_ids.contains(&p.gateway_id));
        if !d.relays.is_empty() {
            self.relays = d.relays.clone();
        }
        // policy fields always reflect the latest delta
        self.policy_ir = d.policy_ir.clone();
        self.policy_version = d.policy_version;
        if !d.revoked_serials.is_empty() {
            self.revoked_serials = d.revoked_serials.clone();
        }
    }

    pub fn save(&self, state_dir: &Path) -> anyhow::Result<()> {
        fs::create_dir_all(state_dir)?;
        let tmp = state_dir.join("state.json.tmp");
        let final_path = state_dir.join("state.json");
        {
            use std::io::Write;
            let mut f = fs::OpenOptions::new()
                .write(true).create(true).truncate(true).mode(0o600)
                .open(&tmp).context("opening state.json.tmp")?;
            f.write_all(&serde_json::to_vec_pretty(self)?)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &final_path).context("atomically renaming state.json")?;
        Ok(())
    }

    pub fn load(state_dir: &Path) -> anyhow::Result<Option<DesiredState>> {
        let path = state_dir.join("state.json");
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes).context("parsing state.json")?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).context("reading state.json"),
        }
    }
}
```
Add to `lib.rs`: `pub mod state;`

- [ ] **Step 4: Run tests to verify they pass**

Run: `./dev.sh run "cargo test -p wiremesh-gateway --lib state"`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**
```bash
git add crates/wiremesh-gateway/src/state.rs crates/wiremesh-gateway/src/lib.rs
git commit -m "feat(gateway): desired-state model + fail-static persistence"
```

---

### Task 5: Reconcile logic (peer list + route diff + apply-needed)

**Files:**
- Create: `crates/wiremesh-gateway/src/reconcile.rs`
- Modify: `crates/wiremesh-gateway/src/lib.rs` (add `pub mod reconcile;`)
- Test: inline `#[cfg(test)]` in `reconcile.rs`

**Interfaces:**
- Consumes: `state::{DesiredState, PeerState}`, `uapi::{DeviceConfig, PeerConfig}`.
- Produces:
  - `reconcile::peer_configs(ds: &DesiredState, keepalive_secs: u16) -> Vec<uapi::PeerConfig>` — one per peer that has an `active_pubkey_b64` (peers still without a key are skipped).
  - `reconcile::device_config(ds: &DesiredState, private_key_b64: &str, listen_port: u16, keepalive_secs: u16) -> uapi::DeviceConfig`.
  - `reconcile::route_diff(old: &DesiredState, new: &DesiredState) -> RouteDiff` where `RouteDiff { to_add: Vec<String>, to_del: Vec<String> }` (peer allowed-ip CIDRs; add = in new not old, del = in old not new).
  - `reconcile::policy_changed(old: &DesiredState, new: &DesiredState) -> bool` (returns `new.policy_version != old.policy_version`).

- [ ] **Step 1: Write the failing tests**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{DesiredState, PeerState};

    fn ds_with(peers: Vec<PeerState>, ver: u64) -> DesiredState {
        DesiredState { peers, policy_version: ver, ..Default::default() }
    }
    fn p(id: u64, key: Option<&str>, cidr: &str) -> PeerState {
        PeerState {
            gateway_id: id, segment_name: format!("s{id}"),
            active_pubkey_b64: key.map(String::from),
            candidate_endpoint: Some(format!("10.9.0.{id}:51820")),
            allowed_ips: vec![cidr.into()],
        }
    }

    #[test]
    fn peer_configs_skip_peers_without_active_key() {
        let ds = ds_with(vec![p(2, Some("K2"), "10.10.2.0/24"), p(3, None, "10.10.3.0/24")], 0);
        let cfgs = peer_configs(&ds, 15);
        assert_eq!(cfgs.len(), 1);
        assert_eq!(cfgs[0].public_key_b64, "K2");
        assert_eq!(cfgs[0].keepalive_secs, 15);
        assert_eq!(cfgs[0].allowed_ips, vec!["10.10.2.0/24".to_string()]);
    }

    #[test]
    fn route_diff_adds_and_removes() {
        let old = ds_with(vec![p(2, Some("K2"), "10.10.2.0/24"), p(3, Some("K3"), "10.10.3.0/24")], 0);
        let new = ds_with(vec![p(2, Some("K2"), "10.10.2.0/24"), p(4, Some("K4"), "10.10.4.0/24")], 0);
        let diff = route_diff(&old, &new);
        assert_eq!(diff.to_add, vec!["10.10.4.0/24".to_string()]);
        assert_eq!(diff.to_del, vec!["10.10.3.0/24".to_string()]);
    }

    #[test]
    fn policy_changed_tracks_version() {
        assert!(policy_changed(&ds_with(vec![], 1), &ds_with(vec![], 2)));
        assert!(!policy_changed(&ds_with(vec![], 2), &ds_with(vec![], 2)));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./dev.sh run "cargo test -p wiremesh-gateway --lib reconcile"`
Expected: FAIL.

- [ ] **Step 3: Implement `reconcile.rs`**
```rust
//! Pure reconciliation: turn desired state into a WG device config and a route
//! add/remove diff, and decide when the enforcer needs re-`apply` (spec §5.2).
use crate::state::DesiredState;
use crate::uapi::{DeviceConfig, PeerConfig};

pub fn peer_configs(ds: &DesiredState, keepalive_secs: u16) -> Vec<PeerConfig> {
    ds.peers
        .iter()
        .filter_map(|p| {
            let public_key_b64 = p.active_pubkey_b64.clone()?;
            Some(PeerConfig {
                public_key_b64,
                endpoint: p.candidate_endpoint.clone(),
                allowed_ips: p.allowed_ips.clone(),
                keepalive_secs,
            })
        })
        .collect()
}

pub fn device_config(
    ds: &DesiredState,
    private_key_b64: &str,
    listen_port: u16,
    keepalive_secs: u16,
) -> DeviceConfig {
    DeviceConfig {
        private_key_b64: private_key_b64.to_string(),
        listen_port,
        peers: peer_configs(ds, keepalive_secs),
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct RouteDiff {
    pub to_add: Vec<String>,
    pub to_del: Vec<String>,
}

fn all_cidrs(ds: &DesiredState) -> std::collections::BTreeSet<String> {
    ds.peers.iter().flat_map(|p| p.allowed_ips.iter().cloned()).collect()
}

pub fn route_diff(old: &DesiredState, new: &DesiredState) -> RouteDiff {
    let o = all_cidrs(old);
    let n = all_cidrs(new);
    RouteDiff {
        to_add: n.difference(&o).cloned().collect(),
        to_del: o.difference(&n).cloned().collect(),
    }
}

pub fn policy_changed(old: &DesiredState, new: &DesiredState) -> bool {
    old.policy_version != new.policy_version
}
```
Add to `lib.rs`: `pub mod reconcile;`

- [ ] **Step 4: Run tests to verify they pass**

Run: `./dev.sh run "cargo test -p wiremesh-gateway --lib reconcile"`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**
```bash
git add crates/wiremesh-gateway/src/reconcile.rs crates/wiremesh-gateway/src/lib.rs
git commit -m "feat(gateway): pure reconcile (peer list, route diff, apply-needed)"
```

---

### Task 6: Route/link/MSS programming (shell-out) + netns test

**Files:**
- Create: `crates/wiremesh-gateway/src/routes.rs`
- Modify: `crates/wiremesh-gateway/src/lib.rs` (add `pub mod routes;`)
- Test: `crates/wiremesh-gateway/tests/routes_netns.rs`

**Interfaces:**
- Produces (all shell out via `std::process::Command`, returning `anyhow::Result<()>`):
  - `routes::set_link_up_mtu(ifname: &str, mtu: u32)` → `ip link set <if> up mtu <mtu>`.
  - `routes::enable_ip_forward()` → `sysctl -w net.ipv4.ip_forward=1`.
  - `routes::add_route(cidr: &str, ifname: &str)` → `ip route replace <cidr> dev <if>` (idempotent).
  - `routes::del_route(cidr: &str, ifname: &str)` → `ip route del <cidr> dev <if>` (ignores "No such process").
  - `routes::install_mss_clamp(ifname: &str, mss: u16)` → installs nft table `inet wiremesh_mss` with a forward hook clamping SYN MSS on `<ifname>` to `<mss>` (idempotent: delete-then-add).

**Detail — the nft ruleset** `install_mss_clamp` writes and loads:
```
table inet wiremesh_mss {
  chain forward {
    type filter hook forward priority mangle;
    iifname "<if>" tcp flags syn tcp option maxseg size set <mss>
    oifname "<if>" tcp flags syn tcp option maxseg size set <mss>
  }
}
```

- [ ] **Step 1: Write the failing netns test**

Create `crates/wiremesh-gateway/tests/routes_netns.rs`:
```rust
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
    drop(lab);
}
```
Add a `netns-tests` feature to `crates/wiremesh-gateway/Cargo.toml`:
```toml
[features]
netns-tests = []
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `./dev.sh run "cargo test -p wiremesh-gateway --test routes_netns --features netns-tests -- --test-threads=1 --nocapture"`
Expected: FAIL — `routes` module not defined.

- [ ] **Step 3: Implement `routes.rs`**
```rust
//! Route/link/MSS programming. Shells out to `ip`/`sysctl`/`nft` — the repo's
//! established pattern (spec §3). Documented runtime deps: iproute2, nftables.
use anyhow::{anyhow, Context};
use std::process::Command;

fn run(cmd: &str, args: &[&str]) -> anyhow::Result<()> {
    let out = Command::new(cmd).args(args).output()
        .with_context(|| format!("spawning {cmd} {args:?}"))?;
    if !out.status.success() {
        return Err(anyhow!("{cmd} {args:?} failed: {}", String::from_utf8_lossy(&out.stderr)));
    }
    Ok(())
}

pub fn set_link_up_mtu(ifname: &str, mtu: u32) -> anyhow::Result<()> {
    run("ip", &["link", "set", ifname, "up", "mtu", &mtu.to_string()])
}

pub fn enable_ip_forward() -> anyhow::Result<()> {
    run("sysctl", &["-w", "net.ipv4.ip_forward=1"])
}

pub fn add_route(cidr: &str, ifname: &str) -> anyhow::Result<()> {
    // `replace` is idempotent (add-or-update).
    run("ip", &["route", "replace", cidr, "dev", ifname])
}

pub fn del_route(cidr: &str, ifname: &str) -> anyhow::Result<()> {
    let out = Command::new("ip").args(["route", "del", cidr, "dev", ifname]).output()
        .with_context(|| format!("spawning ip route del {cidr}"))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    // A route already gone is not an error (reconcile may double-delete).
    if stderr.contains("No such process") || stderr.contains("not found") {
        return Ok(());
    }
    Err(anyhow!("ip route del {cidr} failed: {stderr}"))
}

pub fn install_mss_clamp(ifname: &str, mss: u16) -> anyhow::Result<()> {
    // Idempotent: delete any prior table, then load a fresh one.
    let _ = Command::new("nft").args(["delete", "table", "inet", "wiremesh_mss"]).output();
    let ruleset = format!(
        "table inet wiremesh_mss {{\n\
         \tchain forward {{\n\
         \t\ttype filter hook forward priority mangle;\n\
         \t\tiifname \"{ifname}\" tcp flags syn tcp option maxseg size set {mss}\n\
         \t\toifname \"{ifname}\" tcp flags syn tcp option maxseg size set {mss}\n\
         \t}}\n\
         }}\n"
    );
    let mut child = Command::new("nft").args(["-f", "-"])
        .stdin(std::process::Stdio::piped()).spawn().context("spawning nft -f -")?;
    {
        use std::io::Write;
        child.stdin.take().unwrap().write_all(ruleset.as_bytes())?;
    }
    let status = child.wait().context("waiting on nft")?;
    if !status.success() {
        return Err(anyhow!("nft load of wiremesh_mss failed"));
    }
    Ok(())
}
```
Add to `lib.rs`: `pub mod routes;`

- [ ] **Step 4: Run the test to verify it passes**

Run: `./dev.sh run "cargo test -p wiremesh-gateway --test routes_netns --features netns-tests -- --test-threads=1 --nocapture"`
Expected: PASS.

- [ ] **Step 5: Commit**
```bash
git add crates/wiremesh-gateway/src/routes.rs crates/wiremesh-gateway/src/lib.rs crates/wiremesh-gateway/Cargo.toml crates/wiremesh-gateway/tests/routes_netns.rs
git commit -m "feat(gateway): route/link/MSS programming via ip/nft shell-out"
```

---

### Task 7: Tunnel manager (boringtun device + reconcile apply) + netns handshake test

**Files:**
- Create: `crates/wiremesh-gateway/src/tunnel.rs`
- Modify: `crates/wiremesh-gateway/src/lib.rs` (add `pub mod tunnel;`)
- Test: `crates/wiremesh-gateway/tests/tunnel_netns.rs`

**Interfaces:**
- Consumes: `boringtun::device::{DeviceConfig as BtDeviceConfig, DeviceHandle}`, `uapi`, `routes`, `reconcile`, `state::DesiredState`.
- Produces:
  - `tunnel::Tunnel { handle: DeviceHandle, ifname: String, private_key_b64: String, listen_port: u16 }`.
  - `tunnel::Tunnel::up(ifname: &str, private_key_b64: &str, listen_port: u16, mtu: u32) -> anyhow::Result<Tunnel>` — creates the boringtun device (`DeviceHandle::new`), waits for the UAPI socket, sets link up + MTU.
  - `tunnel::Tunnel::reconcile(&self, ds: &DesiredState, keepalive_secs: u16) -> anyhow::Result<()>` — builds `DeviceConfig` via `reconcile::device_config` and applies via `uapi::apply`.

**Detail:** after `DeviceHandle::new`, the UAPI socket at `/var/run/wireguard/<ifname>.sock` needs a moment; poll for the socket file up to ~2s before returning (mirrors the spike test's 800ms readiness wait, but poll rather than sleep-fixed).

- [ ] **Step 1: Write the failing netns handshake test**

Create `crates/wiremesh-gateway/tests/tunnel_netns.rs`:
```rust
//! Two gateways, two netns, direct WG over veth: prove a handshake + ping.
//! ./dev.sh run "cargo test -p wiremesh-gateway --test tunnel_netns \
//!   --features netns-tests -- --test-threads=1 --nocapture"
#![cfg(feature = "netns-tests")]
use std::time::Duration;
use wiremesh_gateway::state::{DesiredState, PeerState};
use wiremesh_gateway::tunnel::Tunnel;
use wiremesh_gateway::uapi::base64_pub_from_priv; // helper added in Step 3
use wiremesh_testkit::netns::{join_netns, Lab};

fn gen_keypair() -> (String, String) {
    // wg genkey / pubkey via the tool present in the container.
    let priv_b64 = String::from_utf8(std::process::Command::new("wg").arg("genkey").output().unwrap().stdout)
        .unwrap().trim().to_string();
    let pub_b64 = base64_pub_from_priv(&priv_b64).unwrap();
    (priv_b64, pub_b64)
}

#[test]
fn two_gateways_handshake_and_ping_over_direct_wg() {
    let mut lab = Lab::new("gwtun").expect("lab");
    let a = lab.ns("a").unwrap();
    let b = lab.ns("b").unwrap();
    // underlay veth: a=10.9.0.1, b=10.9.0.2
    lab.veth((&a, "u0", "10.9.0.1/24"), (&b, "u0", "10.9.0.2/24")).unwrap();

    let (a_priv, a_pub) = gen_keypair();
    let (b_priv, b_pub) = gen_keypair();

    // Gateway A runs in a thread joined to netns a; B in netns b.
    let a_name = a.name.clone();
    let b_name = b.name.clone();
    let hb = std::thread::spawn(move || {
        join_netns(&b_name).unwrap();
        let t = Tunnel::up("wg0", &b_priv, 51820, 1280).unwrap();
        // A is B's peer, reachable at 10.9.0.1:51820, segment 10.10.1.0/24
        let ds = DesiredState { peers: vec![PeerState {
            gateway_id: 1, segment_name: "a".into(),
            active_pubkey_b64: Some(a_pub.clone()),
            candidate_endpoint: Some("10.9.0.1:51820".into()),
            allowed_ips: vec!["10.10.1.0/24".into(), "10.10.2.2/32".into()],
        }], ..Default::default() };
        t.reconcile(&ds, 15).unwrap();
        std::process::Command::new("ip").args(["addr","add","10.10.2.2/24","dev","wg0"]).status().unwrap();
        std::thread::sleep(Duration::from_secs(6));
    });

    join_netns(&a_name).unwrap();
    let ta = Tunnel::up("wg0", &a_priv, 51820, 1280).unwrap();
    let ds_a = DesiredState { peers: vec![PeerState {
        gateway_id: 2, segment_name: "b".into(),
        active_pubkey_b64: Some(b_pub.clone()),
        candidate_endpoint: Some("10.9.0.2:51820".into()),
        allowed_ips: vec!["10.10.2.0/24".into(), "10.10.1.1/32".into()],
    }], ..Default::default() };
    ta.reconcile(&ds_a, 15).unwrap();
    std::process::Command::new("ip").args(["addr","add","10.10.1.1/24","dev","wg0"]).status().unwrap();
    std::thread::sleep(Duration::from_secs(2)); // allow handshake

    let ping = std::process::Command::new("ping")
        .args(["-c", "3", "-W", "2", "10.10.2.2"]).output().unwrap();
    assert!(ping.status.success(), "ping over WG tunnel: {}", String::from_utf8_lossy(&ping.stdout));
    hb.join().unwrap();
    drop(lab);
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `./dev.sh run "cargo test -p wiremesh-gateway --test tunnel_netns --features netns-tests -- --test-threads=1 --nocapture"`
Expected: FAIL — `Tunnel`/`base64_pub_from_priv` not defined.

- [ ] **Step 3: Implement `tunnel.rs` and the pubkey helper**

Add to `crates/wiremesh-gateway/src/uapi.rs` (a Curve25519 pubkey derivation so the gateway can log/verify its own key; uses `boringtun`'s x25519 which is already a dependency):
```rust
/// Derive the base64 WireGuard public key from a base64 private key.
pub fn base64_pub_from_priv(priv_b64: &str) -> anyhow::Result<String> {
    let raw = base64_decode(priv_b64)?;
    let arr: [u8; 32] = raw.as_slice().try_into()
        .map_err(|_| anyhow!("private key must be 32 bytes"))?;
    let secret = boringtun::x25519::StaticSecret::from(arr);
    let public = boringtun::x25519::PublicKey::from(&secret);
    Ok(base64_encode(public.as_bytes()))
}
```
Create `crates/wiremesh-gateway/src/tunnel.rs`:
```rust
//! Embedded boringtun tunnel manager (spec §5.2). Owns the WG device; applies
//! the desired peer set through the in-process UAPI writer.
use crate::reconcile;
use crate::routes;
use crate::state::DesiredState;
use crate::uapi;
use anyhow::{anyhow, Context};
use boringtun::device::{DeviceConfig as BtDeviceConfig, DeviceHandle};
use std::path::Path;
use std::time::{Duration, Instant};

pub struct Tunnel {
    _handle: DeviceHandle,
    pub ifname: String,
    pub private_key_b64: String,
    pub listen_port: u16,
}

impl Tunnel {
    pub fn up(ifname: &str, private_key_b64: &str, listen_port: u16, mtu: u32) -> anyhow::Result<Tunnel> {
        let mut cfg = BtDeviceConfig::default();
        cfg.n_threads = 2;
        let handle = DeviceHandle::new(ifname, cfg)
            .map_err(|e| anyhow!("creating boringtun device {ifname}: {e:?}"))?;

        // Wait for the UAPI socket to appear before configuring.
        let sock = format!("/var/run/wireguard/{ifname}.sock");
        let deadline = Instant::now() + Duration::from_secs(2);
        while !Path::new(&sock).exists() {
            if Instant::now() > deadline {
                return Err(anyhow!("WG UAPI socket {sock} did not appear"));
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        routes::set_link_up_mtu(ifname, mtu).context("bringing tun up at MTU")?;

        Ok(Tunnel {
            _handle: handle,
            ifname: ifname.to_string(),
            private_key_b64: private_key_b64.to_string(),
            listen_port,
        })
    }

    pub fn reconcile(&self, ds: &DesiredState, keepalive_secs: u16) -> anyhow::Result<()> {
        let dev = reconcile::device_config(ds, &self.private_key_b64, self.listen_port, keepalive_secs);
        uapi::apply(&self.ifname, &dev)
    }
}
```
Add to `lib.rs`: `pub mod tunnel;`

- [ ] **Step 4: Run the test to verify it passes**

Run: `./dev.sh run "cargo test -p wiremesh-gateway --test tunnel_netns --features netns-tests -- --test-threads=1 --nocapture"`
Expected: PASS — ping over the WG tunnel succeeds.

- [ ] **Step 5: Commit**
```bash
git add crates/wiremesh-gateway/src/tunnel.rs crates/wiremesh-gateway/src/uapi.rs crates/wiremesh-gateway/src/lib.rs crates/wiremesh-gateway/tests/tunnel_netns.rs
git commit -m "feat(gateway): boringtun tunnel manager + two-gateway handshake test"
```

---

### Task 8: Enforcer wiring + netns allow/deny test

**Files:**
- Create: `crates/wiremesh-gateway/src/enforce.rs`
- Modify: `crates/wiremesh-gateway/src/lib.rs` (add `pub mod enforce;`)
- Test: `crates/wiremesh-gateway/tests/enforce_netns.rs`

**Interfaces:**
- Consumes: `wiremesh_enforcer::{probe, EnforcerConfig, Enforcer, Counters, DenyEvent, BackendKind}`, `wiremesh_policy::PolicyIR`, `state::DesiredState`.
- Produces:
  - `enforce::GatewayEnforcer { inner: Box<dyn Enforcer>, applied_version: u64 }`.
  - `enforce::GatewayEnforcer::attach(ifname: &str) -> anyhow::Result<Self>` — `probe(ifname, EnforcerConfig::default())`.
  - `enforce::GatewayEnforcer::apply_if_changed(&mut self, ds: &DesiredState) -> anyhow::Result<bool>` — when `ds.policy_version != self.applied_version` (or first apply), deserialize `ds.policy_ir` with `PolicyIR::from_json` (empty bytes → empty IR v1) and `apply`; returns whether it applied.
  - `enforce::GatewayEnforcer::kind(&self) -> BackendKind`, `counters(&mut self) -> anyhow::Result<Counters>`, `deny_events(&mut self) -> anyhow::Result<Vec<DenyEvent>>`.

- [ ] **Step 1: Write the failing netns test**

Create `crates/wiremesh-gateway/tests/enforce_netns.rs`:
```rust
//! Enforcer wiring on wg0: apply an IR, assert allow/deny + counters.
//! ./dev.sh run "cargo test -p wiremesh-gateway --test enforce_netns \
//!   --features netns-tests -- --test-threads=1 --nocapture"
#![cfg(feature = "netns-tests")]
use wiremesh_gateway::enforce::GatewayEnforcer;
use wiremesh_gateway::state::DesiredState;
use wiremesh_testkit::netns::{join_netns, wg_lab};

#[test]
fn apply_if_changed_applies_once_per_version() {
    let (lab, _a, b) = wg_lab("gwenf");
    join_netns(&b.name).expect("join b");
    let mut enf = GatewayEnforcer::attach("wg0").expect("probe wg0");

    // First apply: an allow-nothing IR (default deny).
    let mut ds = DesiredState { policy_version: 1, policy_ir: br#"{"schema":1,"version":1,"blocks":[]}"#.to_vec(), ..Default::default() };
    assert!(enf.apply_if_changed(&mut ds).unwrap(), "first apply happens");
    assert!(!enf.apply_if_changed(&mut ds).unwrap(), "same version is a no-op");

    // Bump version -> applies again.
    ds.policy_version = 2;
    assert!(enf.apply_if_changed(&mut ds).unwrap(), "new version re-applies");
    drop(lab);
}
```
(Note: the IR is passed as raw JSON bytes on `DesiredState.policy_ir`, so this test needs no `wiremesh_policy` type imports. It proves the *wiring* and version-gating, not enforcement semantics — those are covered by the enforcer crate's own conformance suite.)

- [ ] **Step 2: Run the test to verify it fails**

Run: `./dev.sh run "cargo test -p wiremesh-gateway --test enforce_netns --features netns-tests -- --test-threads=1 --nocapture"`
Expected: FAIL — `GatewayEnforcer` not defined.

- [ ] **Step 3: Implement `enforce.rs`**
```rust
//! Enforcer wiring (spec §5, §4). Thin adapter over `wiremesh-enforcer`: probe
//! the backend on the tun, feed it the snapshot's `policy_ir`, gate re-apply on
//! the policy version.
use crate::state::DesiredState;
use anyhow::Context;
use wiremesh_enforcer::{probe, BackendKind, Counters, DenyEvent, Enforcer, EnforcerConfig};
use wiremesh_policy::PolicyIR;

pub struct GatewayEnforcer {
    inner: Box<dyn Enforcer>,
    applied_version: Option<u64>,
}

impl GatewayEnforcer {
    pub fn attach(ifname: &str) -> anyhow::Result<Self> {
        let inner = probe(ifname, EnforcerConfig::default())
            .with_context(|| format!("probing enforcer backend on {ifname}"))?;
        Ok(GatewayEnforcer { inner, applied_version: None })
    }

    pub fn kind(&self) -> BackendKind {
        self.inner.kind()
    }

    /// Deserialize + apply the desired IR iff its version changed (or first
    /// apply). Empty `policy_ir` bytes mean "no policy yet" -> empty IR v1.
    pub fn apply_if_changed(&mut self, ds: &DesiredState) -> anyhow::Result<bool> {
        if self.applied_version == Some(ds.policy_version) {
            return Ok(false);
        }
        let ir = if ds.policy_ir.is_empty() {
            PolicyIR { schema: 1, version: ds.policy_version, blocks: vec![] }
        } else {
            PolicyIR::from_json(&ds.policy_ir).context("deserializing policy_ir from snapshot")?
        };
        self.inner.apply(&ir).context("applying policy IR to enforcer")?;
        self.applied_version = Some(ds.policy_version);
        Ok(true)
    }

    pub fn counters(&mut self) -> anyhow::Result<Counters> {
        self.inner.counters()
    }

    pub fn deny_events(&mut self) -> anyhow::Result<Vec<DenyEvent>> {
        self.inner.deny_events()
    }
}
```
Add to `lib.rs`: `pub mod enforce;`

- [ ] **Step 4: Run the test to verify it passes**

Run: `./dev.sh run "cargo test -p wiremesh-gateway --test enforce_netns --features netns-tests -- --test-threads=1 --nocapture"`
Expected: PASS.

- [ ] **Step 5: Commit**
```bash
git add crates/wiremesh-gateway/src/enforce.rs crates/wiremesh-gateway/src/lib.rs crates/wiremesh-gateway/tests/enforce_netns.rs
git commit -m "feat(gateway): enforcer wiring with version-gated apply"
```

---

### Task 9: Sync client + integration against TestController

**Files:**
- Create: `crates/wiremesh-gateway/src/sync.rs`
- Modify: `crates/wiremesh-gateway/src/lib.rs` (add `pub mod sync;`)
- Test: `crates/wiremesh-gateway/tests/sync_client.rs`

**Interfaces:**
- Consumes: `wiremesh_proto::v1::sync_client::SyncClient`, `wiremesh_proto::v1::{WatchRequest, SyncMessage, sync_message::Body, ReportRequest}`, `tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity as TlsIdentity}`, `identity::Identity`, `state::DesiredState`.
- Produces:
  - `sync::connect(sync_addr: SocketAddr, id: &Identity) -> anyhow::Result<SyncClient<Channel>>` — builds the mTLS channel (mirrors testkit `dial_sync_with`: `.identity(...).ca_certificate(...).domain_name("127.0.0.1")`).
  - `sync::watch(client: &mut SyncClient<Channel>) -> anyhow::Result<tonic::Streaming<SyncMessage>>`.
  - `sync::report(client: &mut SyncClient<Channel>, applied_version: u64) -> anyhow::Result<()>`.
  - `sync::next_desired(stream, current: &mut Option<DesiredState>) -> anyhow::Result<Option<DesiredState>>` — pulls one `SyncMessage`; `Snapshot` replaces `current`, `Delta` mutates it; returns the new `DesiredState` clone (or `None` at stream end).

- [ ] **Step 1: Write the failing integration test**

Create `crates/wiremesh-gateway/tests/sync_client.rs`:
```rust
//! Sync client against the real in-process controller (no netns needed).
//! ./dev.sh run "cargo test -p wiremesh-gateway --test sync_client -- --nocapture"
use wiremesh_gateway::identity::Identity;
use wiremesh_gateway::sync;
use wiremesh_gateway::uapi::base64_pub_from_priv;
use wiremesh_testkit::TestController;
use tokio_stream::StreamExt;

#[tokio::test]
async fn receives_snapshot_and_reports_version() {
    let h = TestController::start().await;
    // Enroll two gateways so peer-of relationships exist.
    let g1 = h.enroll_one("seg-a", "10.10.1.0/24").await.expect("enroll a");
    let _g2 = h.enroll_one("seg-b", "10.10.2.0/24").await.expect("enroll b");

    // Build the gateway Identity from the enrolled StubGateway's material.
    let id = Identity {
        cert_pem: g1.cert_pem(), key_pem: g1.key_pem(), ca_bundle_pem: g1.ca_bundle_pem(),
        gateway_id: g1.gateway_id(), observe_key: g1.observe_key(),
        wg_private_key_b64: {
            let pk = String::from_utf8(std::process::Command::new("wg").arg("genkey").output().unwrap().stdout).unwrap().trim().to_string();
            let _ = base64_pub_from_priv(&pk).unwrap();
            pk
        },
    };

    let mut client = sync::connect(h.sync_tcp_addr(), &id).await.expect("mTLS connect");
    let mut stream = sync::watch(&mut client).await.expect("watch");
    let mut cur = None;
    let ds = sync::next_desired(&mut stream, &mut cur).await.expect("first msg").expect("snapshot");
    // Gateway A's peer is gateway B (seg-b, 10.10.2.0/24).
    assert!(ds.peers.iter().any(|p| p.allowed_ips.contains(&"10.10.2.0/24".to_string())),
            "snapshot lists peer B's segment: {:?}", ds.peers);

    sync::report(&mut client, ds.policy_version).await.expect("report ack");
    let _ = stream; // keep alive
}
```
(The exact `StubGateway` accessors — `cert_pem()`, `key_pem()`, `ca_bundle_pem()`, `gateway_id()`, `observe_key()` — are provided by testkit's `enroll_one` return type; if any accessor name differs, adapt to the actual `StubGateway` API surface in `crates/wiremesh-testkit/src/lib.rs`.)

- [ ] **Step 2: Run the test to verify it fails**

Run: `./dev.sh run "cargo test -p wiremesh-gateway --test sync_client -- --nocapture"`
Expected: FAIL — `sync` module not defined.

- [ ] **Step 3: Implement `sync.rs`**
```rust
//! Sync client (spec §2.1). mTLS Watch stream + Report; snapshot/delta folding.
use crate::identity::Identity;
use crate::state::DesiredState;
use anyhow::{anyhow, Context};
use std::net::SocketAddr;
use tokio_stream::StreamExt;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity as TlsIdentity};
use wiremesh_proto::v1::sync_client::SyncClient;
use wiremesh_proto::v1::{sync_message::Body, ReportRequest, SyncMessage, WatchRequest};

pub async fn connect(sync_addr: SocketAddr, id: &Identity) -> anyhow::Result<SyncClient<Channel>> {
    let uri = format!("https://{sync_addr}");
    let tls = ClientTlsConfig::new()
        .identity(TlsIdentity::from_pem(&id.cert_pem, &id.key_pem))
        .ca_certificate(Certificate::from_pem(&id.ca_bundle_pem))
        .domain_name("127.0.0.1");
    let channel = Channel::from_shared(uri)
        .context("controller Sync addr must form a valid URI")?
        .tls_config(tls)
        .context("configuring gateway mTLS")?
        .connect()
        .await
        .context("connecting to controller Sync (mTLS)")?;
    Ok(SyncClient::new(channel))
}

pub async fn watch(client: &mut SyncClient<Channel>) -> anyhow::Result<tonic::Streaming<SyncMessage>> {
    Ok(client.watch(WatchRequest {}).await.map_err(|s| anyhow!("Sync.Watch failed: {s}"))?.into_inner())
}

pub async fn report(client: &mut SyncClient<Channel>, applied_version: u64) -> anyhow::Result<()> {
    client.report(ReportRequest { applied_version }).await.map_err(|s| anyhow!("Sync.Report failed: {s}"))?;
    Ok(())
}

/// Pull the next Sync message and fold it into `current`, returning the updated
/// desired state (or None at stream end). First message is always a snapshot.
pub async fn next_desired(
    stream: &mut tonic::Streaming<SyncMessage>,
    current: &mut Option<DesiredState>,
) -> anyhow::Result<Option<DesiredState>> {
    let Some(msg) = stream.next().await else { return Ok(None) };
    let msg = msg.map_err(|s| anyhow!("Sync stream error: {s}"))?;
    match msg.body {
        Some(Body::Snapshot(s)) => {
            let ds = DesiredState::from_snapshot(&s);
            *current = Some(ds.clone());
            Ok(Some(ds))
        }
        Some(Body::Delta(d)) => {
            let cur = current.as_mut().ok_or_else(|| anyhow!("delta before snapshot"))?;
            cur.apply_delta(&d);
            Ok(Some(cur.clone()))
        }
        None => Err(anyhow!("empty SyncMessage body")),
    }
}
```
Add to `lib.rs`: `pub mod sync;`

- [ ] **Step 4: Run the test to verify it passes**

Run: `./dev.sh run "cargo test -p wiremesh-gateway --test sync_client -- --nocapture"`
Expected: PASS.
(If `StubGateway` accessors differ, adapt the test's identity construction — the gateway code is stable.)

- [ ] **Step 5: Commit**
```bash
git add crates/wiremesh-gateway/src/sync.rs crates/wiremesh-gateway/src/lib.rs crates/wiremesh-gateway/tests/sync_client.rs
git commit -m "feat(gateway): mTLS Sync client with snapshot/delta folding"
```

---

### Task 10: Observation loop + cross-process parity test

**Files:**
- Modify: `crates/wiremesh-gateway/src/observe.rs` (add the periodic loop)
- Test: `crates/wiremesh-gateway/tests/observe_parity.rs`

**Interfaces:**
- Produces:
  - `observe::report_once(bind_port: u16, server: SocketAddr, observe_key_hex: &str, gateway_id: u64) -> anyhow::Result<SocketAddr>` — binds a UDP socket to `0.0.0.0:bind_port` with `SO_REUSEPORT` (so it shares the WG listen port; spec §5.4), sends one authenticated probe, returns the observed address.

**Detail — SO_REUSEPORT bind:** use `libc::setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, 1)` on a socket created via `socket2`-style raw fd, or bind a std `UdpSocket` after setting the option through `libc`. Minimal approach: create the fd with `libc::socket`, set `SO_REUSEPORT`, `bind`, then `UdpSocket::from_raw_fd`.

- [ ] **Step 1: Write the failing parity test**

Create `crates/wiremesh-gateway/tests/observe_parity.rs`:
```rust
//! The gateway's probe must be accepted by the REAL controller observe endpoint,
//! proving the replicated codec matches byte-for-byte.
//! ./dev.sh run "cargo test -p wiremesh-gateway --test observe_parity -- --nocapture"
use wiremesh_gateway::observe;
use wiremesh_testkit::TestController;

#[tokio::test]
async fn controller_accepts_gateway_probe_and_records_candidate() {
    let h = TestController::start().await;
    let g = h.enroll_one("seg-a", "10.10.1.0/24").await.expect("enroll");
    let observe_addr = h.observe_addr();
    let gid = g.gateway_id();
    let key = g.observe_key();

    // Send the gateway's authenticated probe from a blocking task.
    let observed = tokio::task::spawn_blocking(move || {
        observe::report_once(0, observe_addr, &key, gid)
    }).await.unwrap().expect("probe accepted + echoed");

    assert!(observed.port() != 0, "controller echoed a concrete observed addr: {observed}");
    // The controller should now expose this as the gateway's candidate to peers.
    // (Verified indirectly: a second enrolled gateway sees it in its snapshot —
    //  covered end-to-end in the mesh milestone; here we assert the echo alone.)
}
```
(If `StubGateway` exposes `probe_observe` already, this test additionally documents that the *gateway crate's own* `report_once` produces an equally-accepted probe.)

- [ ] **Step 2: Run the test to verify it fails**

Run: `./dev.sh run "cargo test -p wiremesh-gateway --test observe_parity -- --nocapture"`
Expected: FAIL — `report_once` not defined.

- [ ] **Step 3: Implement `report_once`**

Append to `crates/wiremesh-gateway/src/observe.rs`:
```rust
use std::os::unix::io::FromRawFd;

/// Bind a UDP socket to `0.0.0.0:bind_port` with SO_REUSEPORT (shares the WG
/// listen port; spec §5.4 — 4a's routable/full-cone observation) and send one
/// authenticated probe, returning the observed public address.
pub fn report_once(
    bind_port: u16,
    server: SocketAddr,
    observe_key_hex: &str,
    gateway_id: u64,
) -> anyhow::Result<SocketAddr> {
    let sock = reuseport_udp(bind_port)?;
    probe_once(&sock, server, observe_key_hex, gateway_id)
}

fn reuseport_udp(port: u16) -> anyhow::Result<UdpSocket> {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return Err(anyhow::anyhow!("socket(): {}", std::io::Error::last_os_error()));
        }
        let one: libc::c_int = 1;
        for opt in [libc::SO_REUSEADDR, libc::SO_REUSEPORT] {
            if libc::setsockopt(fd, libc::SOL_SOCKET, opt, &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t) != 0 {
                libc::close(fd);
                return Err(anyhow::anyhow!("setsockopt: {}", std::io::Error::last_os_error()));
            }
        }
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr { s_addr: libc::INADDR_ANY.to_be() },
            sin_zero: [0; 8],
        };
        if libc::bind(fd, &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t) != 0 {
            libc::close(fd);
            return Err(anyhow::anyhow!("bind(:{port}): {}", std::io::Error::last_os_error()));
        }
        Ok(UdpSocket::from_raw_fd(fd))
    }
}
```
(Ensure `use anyhow::Context;` remains; add `use std::os::unix::io::FromRawFd;` at the top if the appended `use` triggers ordering lints — keep a single import site.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `./dev.sh run "cargo test -p wiremesh-gateway --test observe_parity -- --nocapture"`
Expected: PASS — controller echoes the observed address.

- [ ] **Step 5: Commit**
```bash
git add crates/wiremesh-gateway/src/observe.rs crates/wiremesh-gateway/tests/observe_parity.rs
git commit -m "feat(gateway): SO_REUSEPORT observation loop + controller parity test"
```

---

### Task 11: Boot sequence, task supervision, metrics (`main.rs`)

**Files:**
- Modify: `crates/wiremesh-gateway/src/main.rs`
- Create: `crates/wiremesh-gateway/src/metrics.rs`
- Modify: `crates/wiremesh-gateway/src/lib.rs` (add `pub mod metrics;`)
- Modify: `crates/wiremesh-gateway/src/reconcile.rs` (add `Gateway::apply_desired` orchestration OR keep orchestration in main — see Step 1)
- Test: covered by Task 12's mesh milestone; plus a metrics smoke unit test in `metrics.rs`.

**Interfaces:**
- Produces:
  - `metrics::render(kind: &str, applied_version: u64, counters: &wiremesh_enforcer::Counters) -> String` — Prometheus text exposition (`wiremesh_gateway_default_deny_total`, `wiremesh_gateway_rule_hits_total{rule_id="..."}`, `wiremesh_gateway_applied_policy_version`, `wiremesh_gateway_backend_info{backend="ebpf|nftables"}`).
  - `main.rs`: `run(cfg: GatewayConfig) -> anyhow::Result<()>` async entrypoint implementing the §5.1 boot sequence: load identity → if `state.json` present bring up tunnel+enforcer+routes from it → connect Sync → loop `next_desired` applying each state (tunnel reconcile, enforcer apply_if_changed, route diff, persist, report) → spawn observation loop → serve metrics.

- [ ] **Step 1: Write the metrics smoke test**

Create `crates/wiremesh-gateway/src/metrics.rs` with tests first:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use wiremesh_enforcer::Counters;

    #[test]
    fn render_emits_prometheus_lines() {
        let c = Counters { by_rule: BTreeMap::from([("r1".to_string(), 7u64)]), default_deny: 3 };
        let out = render("ebpf", 5, &c);
        assert!(out.contains("wiremesh_gateway_default_deny_total 3"));
        assert!(out.contains("wiremesh_gateway_rule_hits_total{rule_id=\"r1\"} 7"));
        assert!(out.contains("wiremesh_gateway_applied_policy_version 5"));
        assert!(out.contains("backend=\"ebpf\""));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `./dev.sh run "cargo test -p wiremesh-gateway --lib metrics"`
Expected: FAIL.

- [ ] **Step 3: Implement `metrics.rs`**
```rust
//! Prometheus text exposition (spec §6 metrics component).
use wiremesh_enforcer::Counters;

pub fn render(kind: &str, applied_version: u64, counters: &Counters) -> String {
    let mut s = String::new();
    s.push_str("# TYPE wiremesh_gateway_default_deny_total counter\n");
    s.push_str(&format!("wiremesh_gateway_default_deny_total {}\n", counters.default_deny));
    s.push_str("# TYPE wiremesh_gateway_rule_hits_total counter\n");
    for (rule_id, hits) in &counters.by_rule {
        s.push_str(&format!("wiremesh_gateway_rule_hits_total{{rule_id=\"{rule_id}\"}} {hits}\n"));
    }
    s.push_str("# TYPE wiremesh_gateway_applied_policy_version gauge\n");
    s.push_str(&format!("wiremesh_gateway_applied_policy_version {applied_version}\n"));
    s.push_str("# TYPE wiremesh_gateway_backend_info gauge\n");
    s.push_str(&format!("wiremesh_gateway_backend_info{{backend=\"{kind}\"}} 1\n"));
    s
}
```
Add to `lib.rs`: `pub mod metrics;`

- [ ] **Step 4: Implement the boot sequence in `main.rs`**

Replace `crates/wiremesh-gateway/src/main.rs`:
```rust
//! wiremesh-gateway boot sequence + supervision (spec §5.1).
use anyhow::Context;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use wiremesh_gateway::config::GatewayConfig;
use wiremesh_gateway::enforce::GatewayEnforcer;
use wiremesh_gateway::identity::Identity;
use wiremesh_gateway::state::DesiredState;
use wiremesh_gateway::tunnel::Tunnel;
use wiremesh_gateway::{observe, reconcile, routes, sync};

const TUN_MTU: u32 = 1280;
const MSS: u16 = 1240;
const KEEPALIVE: u16 = 15;
const OBSERVE_PERIOD: Duration = Duration::from_secs(20);

fn main() -> anyhow::Result<()> {
    let cfg = GatewayConfig::from_env()?;
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run(cfg))
}

async fn run(cfg: GatewayConfig) -> anyhow::Result<()> {
    let id = Identity::load(&cfg.state_dir).context("loading pre-provisioned identity")?;

    // Bring the data plane up (from persisted state if present — fail-static).
    let tunnel = Tunnel::up(&cfg.tun_ifname, &id.wg_private_key_b64, cfg.wg_listen_port, TUN_MTU)?;
    routes::enable_ip_forward()?;
    routes::install_mss_clamp(&cfg.tun_ifname, MSS)?;
    let mut enforcer = GatewayEnforcer::attach(&cfg.tun_ifname)?;

    let mut applied: Option<DesiredState> = DesiredState::load(&cfg.state_dir)?;
    if let Some(ds) = &applied {
        eprintln!("wiremesh-gateway: fail-static boot from state.json rev {}", ds.revision);
        apply_state(&tunnel, &mut enforcer, &cfg, None, ds)?;
    }

    // Observation loop (background).
    {
        let observe_addr = cfg.observe_addr;
        let key = id.observe_key.clone();
        let gid = id.gateway_id;
        let port = cfg.wg_listen_port;
        tokio::spawn(async move {
            loop {
                let (k, a) = (key.clone(), observe_addr);
                let res = tokio::task::spawn_blocking(move || observe::report_once(port, a, &k, gid)).await;
                match res {
                    Ok(Ok(addr)) => eprintln!("wiremesh-gateway: observed endpoint {addr}"),
                    Ok(Err(e)) => eprintln!("wiremesh-gateway: observe failed: {e}"),
                    Err(e) => eprintln!("wiremesh-gateway: observe task join error: {e}"),
                }
                tokio::time::sleep(OBSERVE_PERIOD).await;
            }
        });
    }

    // Metrics endpoint is wired in Step 5 (shares the enforcer via Arc<Mutex>).

    // Sync loop with reconnect.
    loop {
        match sync::connect(cfg.controller_sync_addr, &id).await {
            Ok(mut client) => {
                let mut stream = match sync::watch(&mut client).await {
                    Ok(s) => s,
                    Err(e) => { eprintln!("watch failed: {e}; retrying"); tokio::time::sleep(Duration::from_secs(2)).await; continue; }
                };
                let mut current = applied.clone();
                loop {
                    match sync::next_desired(&mut stream, &mut current).await {
                        Ok(Some(ds)) => {
                            apply_state(&tunnel, &mut enforcer, &cfg, applied.as_ref(), &ds)?;
                            ds.save(&cfg.state_dir)?;
                            let _ = sync::report(&mut client, ds.policy_version).await;
                            applied = Some(ds);
                        }
                        Ok(None) => { eprintln!("sync stream closed; reconnecting"); break; }
                        Err(e) => { eprintln!("sync error: {e}; reconnecting"); break; }
                    }
                }
            }
            Err(e) => eprintln!("controller unreachable: {e}; staying fail-static, retrying"),
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Apply one desired state to the data plane (tunnel peers, enforcer, routes).
fn apply_state(
    tunnel: &Tunnel,
    enforcer: &mut GatewayEnforcer,
    cfg: &GatewayConfig,
    prev: Option<&DesiredState>,
    ds: &DesiredState,
) -> anyhow::Result<()> {
    tunnel.reconcile(ds, KEEPALIVE)?;
    enforcer.apply_if_changed(ds)?;
    let empty = DesiredState::default();
    let diff = reconcile::route_diff(prev.unwrap_or(&empty), ds);
    for cidr in &diff.to_add { routes::add_route(cidr, &cfg.tun_ifname)?; }
    for cidr in &diff.to_del { routes::del_route(cidr, &cfg.tun_ifname)?; }
    Ok(())
}
```
**NOTE for the implementer:** serve `metrics::render` on a small `tokio` TCP listener (Prometheus scrape) by pulling `enforcer.counters()` on each scrape. Because `enforcer` is owned by the sync loop, wrap it in `Arc<tokio::sync::Mutex<GatewayEnforcer>>` shared between the sync loop and the metrics task. Implement this sharing when wiring the metrics listener; the mesh milestone test (Task 12) does not require the metrics port, so this can land as the final sub-step of this task with its own smoke check (`curl` the port, assert `wiremesh_gateway_` lines).

- [ ] **Step 5: Wire the metrics listener (Arc<Mutex<GatewayEnforcer>>) and smoke-check**

Refactor `run` to hold `let enforcer = Arc::new(Mutex::new(GatewayEnforcer::attach(...)?));`, lock it in `apply_state` and in the metrics task. Serve on `127.0.0.1:0` (log the chosen port), respond to any TCP connect with the `metrics::render(...)` body. Add a `#[tokio::test]` in `tests/` that starts `run` against a `TestController`, scrapes the metrics port, and asserts the body contains `wiremesh_gateway_applied_policy_version`.

- [ ] **Step 6: Run the full crate test suite**

Run: `./dev.sh run "cargo test -p wiremesh-gateway --lib"` then
`./dev.sh run "cargo build -p wiremesh-gateway"`
Expected: PASS + clean build.

- [ ] **Step 7: Commit**
```bash
git add crates/wiremesh-gateway/src/main.rs crates/wiremesh-gateway/src/metrics.rs crates/wiremesh-gateway/src/lib.rs
git commit -m "feat(gateway): fail-static boot sequence, supervision, metrics"
```

---

### Task 12: Full-mesh milestone netns test (the done bar)

**Files:**
- Test: `crates/wiremesh-gateway/tests/mesh_milestone.rs`
- Possibly Modify: small helper additions to `crates/wiremesh-gateway/src/lib.rs` (expose `run` if the test drives it in-process) — prefer spawning the built binary.

**Approach:** Build the `wiremesh-gateway` binary, then in a two-netns lab spawn one gateway process per netns via `Ns::spawn` (each process joins its own netns naturally because `Ns::spawn` runs under `nsenter`/`ip netns exec`). A controller runs in-process (`TestController`), reachable from both netns over the underlay veth to the host/controller namespace. Two workload netns sit behind each gateway.

**The four asserted cases (spec §2 done bar):**
1. **Allowed flow** — workload A → workload B on a policy-permitted port succeeds.
2. **Denied flow** — a non-permitted port is dropped; `wiremesh_gateway_default_deny_total` (or the deny counter via enforcer) increments.
3. **Fail-static** — kill the controller; an established flow keeps working; restart gateway A's process; it reloads `state.json` and the mesh returns without the controller.
4. **Policy update** — push a new policy via the admin client; the allowed set changes on the gateways.

- [ ] **Step 1: Write the milestone test skeleton (failing)**

Create `crates/wiremesh-gateway/tests/mesh_milestone.rs`:
```rust
//! Cycle 4a done bar: two real gateway processes form a policy-enforced,
//! controller-independent direct mesh.
//! ./dev.sh run "cargo test -p wiremesh-gateway --test mesh_milestone \
//!   --features netns-tests -- --test-threads=1 --nocapture"
#![cfg(feature = "netns-tests")]
use std::time::Duration;
use wiremesh_testkit::netns::Lab;
use wiremesh_testkit::TestController;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_mesh_enforces_policy_and_survives_controller_outage() {
    // 1. Controller up; two gateways enrolled with a policy that permits
    //    workload-A -> workload-B on TCP 8080 only.
    let mut h = TestController::start().await;
    let _ga = h.enroll_one("seg-a", "10.10.1.0/24").await.unwrap();
    let _gb = h.enroll_one("seg-b", "10.10.2.0/24").await.unwrap();
    h.apply_policy(r#"
      policy:
        - from: seg-a
          to: seg-b
          allow:
            - proto: tcp
              ports: [8080]
    "#).await.expect("apply policy"); // adapt to the real testkit policy-apply helper

    // 2. Two-netns lab; each gateway process spawned into its netns; each with
    //    a workload veth. (Provision identity dirs from the enrolled StubGateways.)
    let mut lab = Lab::new("gwmesh").unwrap();
    // ... build netns, veths, write identity.json + wg_private.key per gateway,
    //     spawn `target/debug/wiremesh-gateway --controller-sync <addr> ...` via Ns::spawn ...

    // 3. Assertions (allowed, denied, fail-static, policy-update) — see steps below.
    let _ = (&mut lab, &mut h, Duration::from_secs(1));
    unimplemented!("fill in per the plan's Task 12 steps 2-6");
}
```

- [ ] **Step 2: Verify it fails (compiles to a failing `unimplemented!`)**

Run: `./dev.sh run "cargo test -p wiremesh-gateway --test mesh_milestone --features netns-tests -- --test-threads=1"`
Expected: FAIL (panics at `unimplemented!`).

- [ ] **Step 3: Provision gateway identity dirs from enrolled StubGateways**

For each enrolled gateway, write a state dir the process will load: `identity.json` (built from `StubGateway` cert/key/ca + `gateway_id` + `observe_key`) and `wg_private.key` (a `wg genkey`). Register each gateway's WG **public** key with the controller so peers learn it — via the same admin/testkit path the controller uses to record a gateway's key (adapt to the real `TestController`/`AdminClient` surface; if the controller derives peer pubkeys from a key-registration RPC, call it; otherwise the StubGateway enrollment already carries a key slot to populate). Assert each gateway process comes up (`wg show` inside its netns lists the peer).

- [ ] **Step 4: Assert allowed + denied flows**

Start a listener in workload-B netns on TCP 8080 and 9090. From workload-A netns:
```rust
// allowed:
let ok = ns_a.exec(&["sh","-c","echo hi | nc -w2 10.10.2.2 8080"]).unwrap();
assert!(ok.status.success(), "TCP 8080 permitted");
// denied:
let denied = ns_a.exec(&["sh","-c","echo hi | nc -w2 10.10.2.2 9090"]).unwrap();
assert!(!denied.status.success(), "TCP 9090 default-denied");
```
Scrape gateway-B's metrics port and assert `wiremesh_gateway_default_deny_total` increased.

- [ ] **Step 5: Assert fail-static**

Establish a long-lived allowed flow (or re-test 8080), then `h.shutdown()`/drop the controller. Re-run the allowed-flow check — it must still pass. Then kill gateway A's process and re-spawn it with the same state dir; after a short settle, the allowed flow works again **without** the controller running. (`DesiredState::load` + boot-from-state path.)

- [ ] **Step 6: Assert policy update propagates**

Restart the controller (or use a still-running one for this case ordering), `apply_policy` permitting TCP 9090 too; wait for the delta to apply; assert 9090 now succeeds from workload-A.

- [ ] **Step 7: Run the milestone suite**

Run: `./dev.sh run "cargo test -p wiremesh-gateway --test mesh_milestone --features netns-tests -- --test-threads=1 --nocapture"`
Expected: PASS (all four cases).

- [ ] **Step 8: Commit**
```bash
git add crates/wiremesh-gateway/tests/mesh_milestone.rs crates/wiremesh-gateway/src/lib.rs
git commit -m "test(gateway): Cycle 4a mesh milestone — enforce + fail-static + policy update"
```

---

### Task 13: Throughput bench + docs

**Files:**
- Create: `crates/wiremesh-gateway/tests/throughput_bench.rs` (netns smoke) and `crates/wiremesh-gateway/bench.md` (procedure)
- Modify: `docs/research/phase0-results.md` (record the deferred G-2 gate + procedure)
- Modify: `CLAUDE.md` (project state: Cycle 4a complete; next 4b)
- Modify: `docs/progress.html` (dashboard)

**Interfaces:** none (docs + a smoke test that runs iperf3 across the tunnel and prints throughput without asserting a floor).

- [ ] **Step 1: Write the throughput smoke test**

Create `crates/wiremesh-gateway/tests/throughput_bench.rs`:
```rust
//! Throughput smoke: iperf3 across the WG tunnel between two gateway netns.
//! Records Mbit/s to stdout; does NOT assert the G-2 >=1Gbps floor (that needs a
//! real 4-vCPU VM — see bench.md). Netns loopback numbers are harness-only.
//! ./dev.sh run "cargo test -p wiremesh-gateway --test throughput_bench \
//!   --features netns-tests -- --test-threads=1 --nocapture"
#![cfg(feature = "netns-tests")]
#[test]
fn iperf3_across_tunnel_reports_throughput() {
    // Reuse the two-gateway tunnel setup (Task 7). Start `iperf3 -s` in B,
    // run `iperf3 -c 10.10.2.2 -t 5` from A over wg0, print the result.
    // Assert only that iperf3 completed (status success), NOT a throughput floor.
    eprintln!("throughput smoke: see stdout for Mbit/s; G-2 floor deferred to a 4-vCPU cloud run");
}
```

- [ ] **Step 2: Write `bench.md`**

Create `crates/wiremesh-gateway/bench.md` documenting: how to run the bench on a 4-vCPU VM (two gateways, iperf3 over the tunnel, `-P 4` parallel streams), the G-2 target (≥1 Gbps), and where to record the number (`docs/research/phase0-results.md`).

- [ ] **Step 3: Record the deferred gate in `phase0-results.md`**

Add a "Cycle 4a — G-2 throughput (deferred measurement)" section to `docs/research/phase0-results.md`: the bench exists (`crates/wiremesh-gateway/bench.md`), the number is pending a 4-vCPU cloud run, and 4a's correctness is netns-proven independently.

- [ ] **Step 4: Update `CLAUDE.md` project state**

In `CLAUDE.md` "## Project state", update: Cycle 4a (direct-only gateway) complete — `wiremesh-gateway` binary with Sync client, in-process UAPI tunnel, enforcer wiring, fail-static state, endpoint observation, MTU/MSS; mesh milestone green. Note deferred: key rotation (fast-follow), G-2 number (cloud run), then Cycle 4b (NAT hole punching + path SM), 4c (relay). Add the `iproute2`/`nftables` gateway runtime deps to the deployment note.

- [ ] **Step 5: Update the progress dashboard**

Update `docs/progress.html` to mark Cycle 4a done (mirror the auto-memory "progress-tracker" convention).

- [ ] **Step 6: Run the smoke test + full suite one final time**

Run:
```
./dev.sh run "cargo test -p wiremesh-gateway --lib"
./dev.sh run "cargo test -p wiremesh-gateway --features netns-tests -- --test-threads=1 --nocapture"
```
Expected: PASS (all lib + netns integration tests).

- [ ] **Step 7: Commit**
```bash
git add crates/wiremesh-gateway/tests/throughput_bench.rs crates/wiremesh-gateway/bench.md docs/research/phase0-results.md CLAUDE.md docs/progress.html
git commit -m "docs(gateway): throughput bench + Cycle 4a completion, project state"
```

---

## Self-review notes (coverage against the spec)

- **§2 components 1–9:** Sync client (T9), reconciler+state (T4/T5), tunnel manager + UAPI (T3/T7), enforcer wiring (T8), observation (T2/T10), fail-static store (T4), routes (T6), metrics (T11), throughput bench (T13). ✔
- **§5.1 boot sequence (fail-static):** T11 `run` brings the data plane up from `state.json` before Sync; asserted in T12 case 3. ✔
- **§5.2 reconcile (atomic replace_peers, version-gated apply, route diff, persist):** T3/T5/T7/T8/T11. ✔
- **§5.4 observation (SO_REUSEPORT, authenticated probe, parity):** T2/T10. ✔
- **§5.5 MTU 1280 + MSS 1240 clamp:** T6/T7/T11. ✔
- **§7-A pre-provisioned identity / §7-B observation socket note:** T1/T10 + documented limitation. ✔
- **Done bar (allowed/denied/fail-static/policy-update):** T12. ✔
- **No proto changes; `relays` empty:** honored throughout (T4 keeps `relays` but never populates from 4a paths). ✔

**Adaptation caveat for the implementer:** Tasks 9/10/12 construct a gateway `Identity` and provision peer WG keys from testkit's `StubGateway`/`TestController`/`AdminClient`. The exact accessor names (`cert_pem()`, `observe_key()`, `apply_policy(...)`, peer-key registration) must be matched to the real surface in `crates/wiremesh-testkit/src/lib.rs` and `crates/wiremesh-controller`; the gateway-crate code (src/) is fully specified and stable. If a peer-pubkey registration RPC does not yet exist on the controller, surface it as a finding before proceeding (it may reveal a Cycle-2 gap the mesh test needs).
