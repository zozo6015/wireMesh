# WireMesh Phase 0 Spike Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** De-risk the five technical bets from spec §12 before any controller work: boringtun embedding + throughput, stateful tc-BPF ACL on a tun device (flow table + ICMP-error handling + atomic rule flip), QUIC-datagram relay with mutual TLS + DPLPMTUD, UDP-native NAT endpoint observation + brokered hole punch, and a NAT-matrix test harness skeleton.

**Architecture:** Spike-quality Rust crates under `spike/`, each proving one bet, sharing a netns-based lab helper (`natlab`). Everything runs inside a privileged Linux dev container (host is macOS; tun/eBPF/nftables/netns are Linux-only). Findings land in `docs/research/`, culminating in a go/no-go report per bet.

**Tech Stack:** Rust stable (+ nightly for eBPF codegen), boringtun 0.6 (device feature), aya 0.13 / aya-ebpf (tc classifier, LRU hash, no clang/libbpf), quinn 0.11 + rustls 0.23 + rcgen 0.13 (QUIC datagrams, mutual TLS), tokio, iproute2 / nftables / wireguard-tools / iperf3 inside the container.

## Global Constraints

- **Spec:** `docs/superpowers/specs/2026-07-15-wiremesh-engineering-design.md` — spike items per §12(1); success criteria referenced per task.
- **All code, tests, and commands run inside the dev container** (Task 1). Shell commands below are written for that container's shell as root unless prefixed with `HOST:`.
- Kernel floor for the eBPF path: **≥ 5.10** (spec D1). The container `doctor.sh` verifies this.
- v1 fabric is **IPv4-only** (spec §1); no IPv6 anywhere in the spike.
- Spike quality bar: code is throwaway-grade but **behavior is test-proven**; every measured number is recorded in `docs/research/phase0-results.md`, never just in a terminal.
- Network tests are serial: always `cargo test -- --test-threads=1 --nocapture`.
- Rust workspace layout: each spike crate is standalone under `spike/` (no root workspace — the aya template ships its own workspace and must not be nested).
- Commit after every green test cycle. Commit messages end with `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## File Structure (end state)

```
dev/Dockerfile               # Linux toolchain image
dev/doctor.sh                # environment capability check
dev.sh                       # HOST-side wrapper: build image, run container, exec commands
spike/natlab/                # netns lab helper lib + NAT cells (bet 5)
spike/tunnel/                # boringtun embedding binary + throughput bench (bet 1)
spike/enforcer/              # aya workspace: tc-BPF ACL + flow table + ICMP (bet 2)
spike/relay/                 # QUIC datagram relay + udp shim (bet 3)
spike/punch/                 # UDP observation + brokered hole punch (bet 4)
docs/research/boringtun-assessment.md
docs/research/phase0-results.md
docs/research/phase0-report.md
```

---

### Task 1: Dev container + environment doctor

**Files:**
- Create: `dev/Dockerfile`
- Create: `dev/doctor.sh`
- Create: `dev.sh`
- Create: `docs/research/phase0-results.md` (empty results log with section headers)

**Interfaces:**
- Produces: `./dev.sh shell` (interactive root shell in the container, repo mounted at `/work`), `./dev.sh run <cmd...>` (one-shot command). Every later task's commands execute via these.

- [ ] **Step 1: Write the Dockerfile**

```dockerfile
# dev/Dockerfile
FROM rust:1-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 nftables iperf3 wireguard-tools tcpdump jq \
    pkg-config libssl-dev ca-certificates kmod procps \
    && rm -rf /var/lib/apt/lists/*

# eBPF toolchain: nightly rustc (BPF codegen) + bpf-linker + cargo-generate
RUN rustup toolchain install nightly --component rust-src \
    && cargo install bpf-linker cargo-generate

WORKDIR /work
```

- [ ] **Step 2: Write the host wrapper**

```bash
#!/usr/bin/env bash
# dev.sh — run from repo root on the macOS host
set -euo pipefail
IMAGE=wiremesh-dev
case "${1:-}" in
  build) docker build -t "$IMAGE" dev/ ;;
  shell) docker run --rm -it --privileged \
           -v "$PWD":/work -v wiremesh-cargo:/usr/local/cargo/registry \
           "$IMAGE" bash ;;
  run)   shift; docker run --rm --privileged \
           -v "$PWD":/work -v wiremesh-cargo:/usr/local/cargo/registry \
           "$IMAGE" bash -lc "$*" ;;
  *) echo "usage: ./dev.sh {build|shell|run <cmd>}"; exit 1 ;;
esac
```

- [ ] **Step 3: Write the doctor script**

```bash
#!/usr/bin/env bash
# dev/doctor.sh — verify the container/kernel can run every spike
set -u
pass=0; fail=0
chk() { if eval "$2" >/dev/null 2>&1; then echo "PASS $1"; ((pass++)); else echo "FAIL $1"; ((fail++)); fi; }

chk "kernel >= 5.10"        '[ "$(uname -r | cut -d. -f1)" -ge 6 ] || { [ "$(uname -r | cut -d. -f1)" -eq 5 ] && [ "$(uname -r | cut -d. -f2)" -ge 10 ]; }'
chk "netns create/delete"   'ip netns add __doc && ip netns del __doc'
chk "tun device"            'ip tuntap add __doc0 mode tun && ip link del __doc0'
chk "clsact qdisc"          'ip link add __docv0 type veth peer name __docv1 && tc qdisc add dev __docv0 clsact && ip link del __docv0'
chk "bpf syscall"           'bpftool prog list 2>/dev/null || [ -e /proc/sys/kernel/unprivileged_bpf_disabled ]'
chk "nftables"              'nft add table inet __doc && nft delete table inet __doc'
chk "wireguard-tools (wg)"  'wg --version'
chk "iperf3"                'iperf3 --version'
echo "---"; echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
```

- [ ] **Step 4: Create the results log skeleton**

```markdown
# Phase 0 Spike — Measured Results

Environment: (fill in `uname -a`, CPU, container details at first measurement)

## Bet 1: boringtun throughput
## Bet 2: tc-BPF enforcer
## Bet 3: QUIC relay
## Bet 4: NAT observation + hole punch
## Bet 5: NAT matrix harness
```

- [ ] **Step 5: Build and verify**

Run (HOST): `chmod +x dev.sh dev/doctor.sh && ./dev.sh build && ./dev.sh run bash dev/doctor.sh`
Expected: image builds; doctor prints `8 passed, 0 failed`. If clsact or bpf checks fail under Docker Desktop, STOP and switch to a Lima/UTM Ubuntu VM before proceeding — record the choice in `docs/research/phase0-results.md`.

- [ ] **Step 6: Commit**

```bash
git add dev/ dev.sh docs/research/phase0-results.md
git commit -m "chore(spike): dev container, doctor script, results log"
```

---

### Task 2: natlab — netns lab helper

**Files:**
- Create: `spike/natlab/Cargo.toml`
- Create: `spike/natlab/src/lib.rs`
- Test: `spike/natlab/tests/veth_ping.rs`

**Interfaces:**
- Produces (used by every later task):
  - `natlab::Lab::new(prefix: &str) -> Result<Lab>` — owns netns lifecycle; `Drop` deletes all namespaces it created.
  - `Lab::ns(&mut self, name: &str) -> Result<Ns>` — `Ns` is `Clone` and carries the full namespace name.
  - `Lab::veth(&mut self, a: (&Ns, &str, &str), b: (&Ns, &str, &str)) -> Result<()>` — `(namespace, ifname, cidr)` each side; creates pair, moves, addrs, up.
  - `Ns::exec(&self, cmd: &[&str]) -> Result<std::process::Output>` — run inside the namespace, error if non-zero exit.
  - `Ns::spawn(&self, cmd: &[&str]) -> Result<std::process::Child>` — long-running process inside the namespace.

- [ ] **Step 1: Crate manifest**

```toml
# spike/natlab/Cargo.toml
[package]
name = "natlab"
version = "0.1.0"
edition = "2021"

[dependencies]
anyhow = "1"
```

- [ ] **Step 2: Write the failing test**

```rust
// spike/natlab/tests/veth_ping.rs
use natlab::Lab;

#[test]
fn veth_pair_pings() {
    let mut lab = Lab::new("nlping").unwrap();
    let a = lab.ns("a").unwrap();
    let b = lab.ns("b").unwrap();
    lab.veth((&a, "v0", "10.9.0.1/24"), (&b, "v1", "10.9.0.2/24")).unwrap();
    let out = a.exec(&["ping", "-c", "1", "-W", "2", "10.9.0.2"]).unwrap();
    assert!(out.status.success(), "ping failed: {}", String::from_utf8_lossy(&out.stderr));
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `./dev.sh run "cd spike/natlab && cargo test -- --test-threads=1"`
Expected: FAIL — `Lab` not found (compile error).

- [ ] **Step 4: Implement**

```rust
// spike/natlab/src/lib.rs
use anyhow::{bail, Context, Result};
use std::process::{Child, Command, Output, Stdio};

pub struct Lab { prefix: String, namespaces: Vec<String> }

#[derive(Clone)]
pub struct Ns { pub name: String }

fn run(cmd: &[&str]) -> Result<Output> {
    let out = Command::new(cmd[0]).args(&cmd[1..]).output()
        .with_context(|| format!("spawn {:?}", cmd))?;
    if !out.status.success() {
        bail!("{:?} failed: {}", cmd, String::from_utf8_lossy(&out.stderr));
    }
    Ok(out)
}

impl Lab {
    pub fn new(prefix: &str) -> Result<Self> {
        Ok(Self { prefix: prefix.into(), namespaces: vec![] })
    }

    pub fn ns(&mut self, name: &str) -> Result<Ns> {
        let full = format!("{}-{}", self.prefix, name);
        run(&["ip", "netns", "add", &full])?;
        run(&["ip", "netns", "exec", &full, "ip", "link", "set", "lo", "up"])?;
        self.namespaces.push(full.clone());
        Ok(Ns { name: full })
    }

    pub fn veth(&mut self, a: (&Ns, &str, &str), b: (&Ns, &str, &str)) -> Result<()> {
        let (na, ia, addra) = a;
        let (nb, ib, addrb) = b;
        // unique temp names to avoid collisions across parallel labs
        let ta = format!("{}0", &self.prefix);
        let tb = format!("{}1", &self.prefix);
        run(&["ip", "link", "add", &ta, "type", "veth", "peer", "name", &tb])?;
        run(&["ip", "link", "set", &ta, "netns", &na.name, "name", ia])?;
        run(&["ip", "link", "set", &tb, "netns", &nb.name, "name", ib])?;
        na.exec(&["ip", "addr", "add", addra, "dev", ia])?;
        nb.exec(&["ip", "addr", "add", addrb, "dev", ib])?;
        na.exec(&["ip", "link", "set", ia, "up"])?;
        nb.exec(&["ip", "link", "set", ib, "up"])?;
        Ok(())
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        for ns in &self.namespaces {
            let _ = Command::new("ip").args(["netns", "del", ns]).status();
        }
    }
}

impl Ns {
    pub fn exec(&self, cmd: &[&str]) -> Result<Output> {
        let mut full = vec!["ip", "netns", "exec", &self.name];
        full.extend_from_slice(cmd);
        run(&full)
    }
    pub fn spawn(&self, cmd: &[&str]) -> Result<Child> {
        Command::new("ip")
            .args(["netns", "exec", &self.name])
            .args(cmd)
            .stdout(Stdio::piped()).stderr(Stdio::piped())
            .spawn().context("spawn in netns")
    }
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `./dev.sh run "cd spike/natlab && cargo test -- --test-threads=1"`
Expected: PASS (1 test).

- [ ] **Step 6: Commit**

```bash
git add spike/natlab
git commit -m "feat(spike): natlab netns helper with veth + ping test"
```

---

### Task 3: spike-tunnel — embedded boringtun static tunnel

**Files:**
- Create: `spike/tunnel/Cargo.toml`
- Create: `spike/tunnel/src/main.rs`
- Test: `spike/tunnel/tests/tunnel_ping.rs`

**Interfaces:**
- Consumes: `natlab::{Lab, Ns}` (path dependency `../natlab`).
- Produces: `spike-tunnel <ifname>` binary — creates a userspace WireGuard device via embedded boringtun and blocks until SIGTERM. Configuration happens externally via standard `wg set` (UAPI socket) — this is exactly the embedding mode the gateway will use, so proving `wg`-compatibility proves the embedding.
- Produces (for later tasks): the test helper `spike/tunnel/tests/common/mod.rs::wg_lab()` which returns a running two-node tunnel lab (overlay `10.10.0.1 <-> 10.10.0.2` over underlay `10.9.1.0/24`). Tasks 6–9 and 14 reuse this pattern by copy (each crate is standalone) — the canonical copy lives here.

- [ ] **Step 1: Crate manifest**

```toml
# spike/tunnel/Cargo.toml
[package]
name = "spike-tunnel"
version = "0.1.0"
edition = "2021"

[dependencies]
boringtun = { version = "0.6", features = ["device"] }
anyhow = "1"

[dev-dependencies]
natlab = { path = "../natlab" }
```

- [ ] **Step 2: Write the binary**

```rust
// spike/tunnel/src/main.rs
use anyhow::Result;
use boringtun::device::{DeviceConfig, DeviceHandle};

fn main() -> Result<()> {
    let ifname = std::env::args().nth(1).expect("usage: spike-tunnel <ifname>");
    let mut cfg = DeviceConfig::default();
    cfg.n_threads = 2;
    let mut handle = DeviceHandle::new(&ifname, cfg)?;
    eprintln!("spike-tunnel: device {ifname} up; configure with `wg set {ifname} ...`");
    handle.wait(); // blocks until the device is torn down
    Ok(())
}
```

- [ ] **Step 3: Write the failing integration test**

```rust
// spike/tunnel/tests/tunnel_ping.rs
use natlab::Lab;
use std::{thread, time::Duration};

fn wg_keypair() -> (String, String) {
    let priv_out = std::process::Command::new("wg").arg("genkey").output().unwrap();
    let privkey = String::from_utf8(priv_out.stdout).unwrap().trim().to_string();
    let pub_out = {
        use std::io::Write;
        let mut c = std::process::Command::new("wg").arg("pubkey")
            .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped())
            .spawn().unwrap();
        c.stdin.as_mut().unwrap().write_all(privkey.as_bytes()).unwrap();
        c.wait_with_output().unwrap()
    };
    (privkey.clone(), String::from_utf8(pub_out.stdout).unwrap().trim().to_string())
}

#[test]
fn wireguard_tunnel_pings_over_veth() {
    let bin = env!("CARGO_BIN_EXE_spike-tunnel");
    let mut lab = Lab::new("wgt").unwrap();
    let a = lab.ns("a").unwrap();
    let b = lab.ns("b").unwrap();
    lab.veth((&a, "u0", "10.9.1.1/24"), (&b, "u1", "10.9.1.2/24")).unwrap();

    let (apriv, apub) = wg_keypair();
    let (bpriv, bpub) = wg_keypair();

    let mut ta = a.spawn(&[bin, "wg0"]).unwrap();
    let mut tb = b.spawn(&[bin, "wg0"]).unwrap();
    thread::sleep(Duration::from_millis(800)); // device + UAPI socket up

    for (ns, privkey, peer_pub, my_ip, peer_ip, peer_ep) in [
        (&a, &apriv, &bpub, "10.10.0.1/24", "10.10.0.2", "10.9.1.2:51820"),
        (&b, &bpriv, &apub, "10.10.0.2/24", "10.10.0.1", "10.9.1.1:51820"),
    ] {
        let kf = format!("/tmp/{}.key", ns.name);
        std::fs::write(&kf, privkey).unwrap();
        ns.exec(&["wg", "set", "wg0", "listen-port", "51820", "private-key", &kf,
                  "peer", peer_pub, "allowed-ips", &format!("{peer_ip}/32"),
                  "endpoint", peer_ep]).unwrap();
        ns.exec(&["ip", "addr", "add", my_ip, "dev", "wg0"]).unwrap();
        ns.exec(&["ip", "link", "set", "wg0", "up", "mtu", "1280"]).unwrap();
    }

    let out = a.exec(&["ping", "-c", "2", "-W", "3", "10.10.0.2"]).unwrap();
    assert!(out.status.success(), "overlay ping failed");
    let _ = ta.kill(); let _ = tb.kill();
}
```

- [ ] **Step 4: Run test to verify it fails, then iterate to green**

Run: `./dev.sh run "cd spike/tunnel && cargo test -- --test-threads=1 --nocapture"`
Expected first run: likely FAIL (boringtun 0.6 `DeviceConfig` field names may differ — fix against the crate docs, this API check IS the spike). Iterate until PASS. **If the `device` feature or UAPI socket doesn't work as documented, record the discrepancy in `docs/research/boringtun-assessment.md` scratch notes — that's assessment input, not just a bug.**

- [ ] **Step 5: Commit**

```bash
git add spike/tunnel
git commit -m "feat(spike): embedded boringtun tunnel proves wg-UAPI config + overlay ping"
```

---

### Task 4: Bet 1 measurement — throughput benchmark

**Files:**
- Create: `spike/tunnel/bench.sh`
- Modify: `docs/research/phase0-results.md` (Bet 1 section)

**Interfaces:**
- Consumes: `spike-tunnel` binary, natlab-style netns setup (shell here — no Rust needed).
- Produces: recorded numbers; the benchmark protocol reused later on a real 4-vCPU cloud VM (spec G-2 acceptance).

- [ ] **Step 1: Write the benchmark script**

```bash
#!/usr/bin/env bash
# spike/tunnel/bench.sh — iperf3 through the boringtun tunnel, plus veth baseline
set -euo pipefail
BIN=${1:?usage: bench.sh <path-to-spike-tunnel-binary>}
cleanup() { ip netns del bwa 2>/dev/null || true; ip netns del bwb 2>/dev/null || true; }
trap cleanup EXIT; cleanup

ip netns add bwa; ip netns add bwb
ip link add bw0 type veth peer name bw1
ip link set bw0 netns bwa; ip link set bw1 netns bwb
ip netns exec bwa bash -c "ip addr add 10.9.2.1/24 dev bw0; ip link set bw0 up; ip link set lo up"
ip netns exec bwb bash -c "ip addr add 10.9.2.2/24 dev bw1; ip link set bw1 up; ip link set lo up"

echo "== baseline: veth, no tunnel =="
ip netns exec bwb iperf3 -s -D
sleep 1
ip netns exec bwa iperf3 -c 10.9.2.2 -t 10 | tail -4
ip netns exec bwb pkill iperf3

APRIV=$(wg genkey); APUB=$(echo "$APRIV" | wg pubkey)
BPRIV=$(wg genkey); BPUB=$(echo "$BPRIV" | wg pubkey)
ip netns exec bwa "$BIN" wg0 & ip netns exec bwb "$BIN" wg0 &
sleep 1
ip netns exec bwa bash -c "echo $APRIV > /tmp/a.key; wg set wg0 listen-port 51820 private-key /tmp/a.key peer $BPUB allowed-ips 10.10.2.2/32 endpoint 10.9.2.2:51820; ip addr add 10.10.2.1/24 dev wg0; ip link set wg0 up mtu 1280"
ip netns exec bwb bash -c "echo $BPRIV > /tmp/b.key; wg set wg0 listen-port 51820 private-key /tmp/b.key peer $APUB allowed-ips 10.10.2.1/32 endpoint 10.9.2.1:51820; ip addr add 10.10.2.2/24 dev wg0; ip link set wg0 up mtu 1280"

echo "== boringtun tunnel, mtu 1280 =="
ip netns exec bwb iperf3 -s -D
sleep 1
ip netns exec bwa iperf3 -c 10.10.2.2 -t 10 | tail -4
echo "== boringtun tunnel, udp + reverse =="
ip netns exec bwa iperf3 -c 10.10.2.2 -t 10 -R | tail -4
ip netns exec bwb pkill iperf3; pkill -f "$BIN" || true
```

- [ ] **Step 2: Run and record**

Run: `./dev.sh run "cd spike/tunnel && cargo build --release && bash bench.sh target/release/spike-tunnel"`
Expected: three iperf summaries print. Record ALL numbers (baseline + tunnel fwd/rev), plus `uname -a` and host CPU, into `docs/research/phase0-results.md` Bet 1. **Note explicitly**: container-on-macOS numbers are indicative only; the G-2 gate (≥1 Gbps on 4-vCPU cloud VM) is a separate manual run using this same script — add a "pending cloud run" line item.

- [ ] **Step 3: Commit**

```bash
git add spike/tunnel/bench.sh docs/research/phase0-results.md
git commit -m "feat(spike): boringtun throughput benchmark protocol + first numbers"
```

---

### Task 5: Bet 1 assessment — boringtun maintenance health

**Files:**
- Create: `docs/research/boringtun-assessment.md`

**Interfaces:**
- Consumes: findings/scratch notes from Tasks 3–4.
- Produces: a written recommendation the Phase 0 report (Task 15) cites.

- [ ] **Step 1: Gather upstream facts**

Run (HOST, needs `gh`):
```bash
gh api repos/cloudflare/boringtun --jq '{pushed_at, open_issues_count, archived}'
gh api repos/cloudflare/boringtun/releases --jq '.[0:3][] | {tag_name, published_at}'
gh api "repos/cloudflare/boringtun/commits?per_page=5" --jq '.[].commit.committer.date'
```
Record raw output in the doc's appendix.

- [ ] **Step 2: Write the assessment**

Structure (fill every section with the gathered facts — no section may be empty):

```markdown
# boringtun Maintenance-Health Assessment (Phase 0, Bet 1)

## Facts (as of YYYY-MM-DD)
last release / last commit / open issues / archived? / our observed API friction (from Task 3 step 4 notes)

## Alternatives considered
| Option | Pros | Cons |
| boringtun as-is (crates.io) | ... | ... |
| boringtun vendored fork | full control, patch freely | maintenance burden on us |
| kernel WireGuard only (netlink via `wireguard-control` crate) | fastest, maintained in-kernel | kills userspace-everywhere story (LXC, no-module hosts); spec wants boringtun primary |
| own Noise impl (snow crate) + own device layer | no dependency | reimplementing WireGuard is out of spike budget and audit scope |

## Throughput evidence
(reference phase0-results.md Bet 1)

## Recommendation
one of: adopt as-is / adopt with vendored fork / escalate to spec change — with reasoning tied to the facts above.

## Appendix: raw gh api output
```

- [ ] **Step 3: Commit**

```bash
git add docs/research/boringtun-assessment.md
git commit -m "docs(spike): boringtun maintenance-health assessment"
```

---

### Task 6: enforcer scaffold — aya tc classifier, default-deny + counters on tun

**Files:**
- Create: `spike/enforcer/` (via aya template — generates `enforcer/`, `enforcer-ebpf/`, `enforcer-common/` workspace)
- Modify: `spike/enforcer/enforcer-ebpf/src/main.rs`
- Modify: `spike/enforcer/enforcer/src/main.rs`
- Create: `spike/enforcer/enforcer-common/src/lib.rs`
- Test: `spike/enforcer/enforcer/tests/enforce.rs`

**Interfaces:**
- Consumes: `spike-tunnel` (built binary path passed via env `SPIKE_TUNNEL_BIN`), natlab (path dep `../../natlab`), the two-node tunnel lab pattern from Task 3's test (copy it into this crate's test as `mod common`).
- Produces:
  - eBPF programs `aeth_ingress` (tc ingress on tun: enforcement) and `aeth_egress` (tc egress on tun: flow recording — no-op until Task 8).
  - Userspace binary: `enforcer run --iface wg0 --rules rules.json --pin-dir /sys/fs/bpf/aeth` (loads, attaches, applies rules, keeps running; SIGHUP re-reads rules — Task 7).
  - `enforcer stats --pin-dir /sys/fs/bpf/aeth` → JSON `{"allow":N,"deny":N,"flow_hit":N,"icmp_err_pass":N}` read from pinned counter map.
  - Shared types in `enforcer-common`: `Rule`, `FlowKey`, counter index constants `CTR_ALLOW=0, CTR_DENY=1, CTR_FLOW_HIT=2, CTR_ICMP_ERR=3`.

- [ ] **Step 1: Generate the aya workspace**

Run: `./dev.sh run "cd spike && cargo generate --git https://github.com/aya-rs/aya-template --name enforcer -d program_type=classifier"`
Expected: `spike/enforcer/` workspace compiles out of the box: `./dev.sh run "cd spike/enforcer && cargo build"` → success. (The template pins the nightly/bpf-linker wiring — do not hand-roll it.)

- [ ] **Step 2: Shared types**

```rust
// spike/enforcer/enforcer-common/src/lib.rs
#![no_std]

pub const CTR_ALLOW: u32 = 0;
pub const CTR_DENY: u32 = 1;
pub const CTR_FLOW_HIT: u32 = 2;
pub const CTR_ICMP_ERR: u32 = 3;

pub const ACT_DENY: u32 = 0;
pub const ACT_ALLOW: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Rule {
    pub src: u32,       // network byte order
    pub src_plen: u32,
    pub dst: u32,
    pub dst_plen: u32,
    pub proto: u32,     // 6 tcp, 17 udp, 1 icmp, 0 any
    pub port_lo: u16,   // dst port range, host order; 0..=0 means any
    pub port_hi: u16,
    pub action: u32,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src: u32,   // network byte order
    pub dst: u32,
    pub sport: u16, // network byte order; ICMP echo: identifier in sport, 0 in dport
    pub dport: u16,
    pub proto: u8,
    pub _pad: [u8; 3],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Rule {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowKey {}
```

(Add `[features] user = ["aya"]` and optional `aya` dep to `enforcer-common/Cargo.toml`; the userspace crate enables `user`.)

- [ ] **Step 3: Kernel side — default-deny ingress + pass-through egress + counters**

```rust
// spike/enforcer/enforcer-ebpf/src/main.rs
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    macros::{classifier, map},
    maps::{Array, LruHashMap},
    programs::TcContext,
};
use enforcer_common::*;

#[map] static COUNTERS: Array<u64> = Array::with_max_entries(4, 0);
#[map] static ACTIVE: Array<u32> = Array::with_max_entries(1, 0);
#[map] static RULES_A: Array<Rule> = Array::with_max_entries(64, 0);
#[map] static RULES_B: Array<Rule> = Array::with_max_entries(64, 0);
#[map] static RULE_LEN: Array<u32> = Array::with_max_entries(2, 0); // len per table
#[map] static FLOWS: LruHashMap<FlowKey, u64> = LruHashMap::with_max_entries(65536, 0);

fn bump(idx: u32) {
    if let Some(c) = COUNTERS.get_ptr_mut(idx) {
        unsafe { *c += 1 };
    }
}

#[classifier]
pub fn aeth_ingress(ctx: TcContext) -> i32 {
    match try_ingress(&ctx) {
        Ok(verdict) => verdict,
        Err(_) => TC_ACT_SHOT, // unparseable => deny (default-deny posture)
    }
}

#[classifier]
pub fn aeth_egress(ctx: TcContext) -> i32 {
    let _ = try_egress(&ctx); // recording only, never blocks
    TC_ACT_PIPE
}

// tun is L3: byte 0 is the IP header. IPv4 only (spec §1).
fn ipv4_at(ctx: &TcContext) -> Result<(u32, u32, u8, usize), ()> {
    let vihl: u8 = ctx.load(0).map_err(|_| ())?;
    if vihl >> 4 != 4 { return Err(()); }
    let ihl = ((vihl & 0x0f) as usize) * 4;
    let proto: u8 = ctx.load(9).map_err(|_| ())?;
    let src: u32 = ctx.load(12).map_err(|_| ())?; // stays big-endian as loaded
    let dst: u32 = ctx.load(16).map_err(|_| ())?;
    Ok((src, dst, proto, ihl))
}

fn ports_at(ctx: &TcContext, off: usize, proto: u8) -> (u16, u16) {
    match proto {
        6 | 17 => (
            ctx.load::<u16>(off).unwrap_or(0),
            ctx.load::<u16>(off + 2).unwrap_or(0),
        ),
        1 => {
            // ICMP echo: type(0)/code(1)/csum(2..4)/identifier(4..6)
            let id: u16 = ctx.load::<u16>(off + 4).unwrap_or(0);
            (id, 0)
        }
        _ => (0, 0),
    }
}

fn try_ingress(ctx: &TcContext) -> Result<i32, ()> {
    let (src, dst, proto, ihl) = ipv4_at(ctx)?;
    let (sport, dport) = ports_at(ctx, ihl, proto);

    // 1) reply of an inside-initiated flow? (egress recorded src=inside)
    let rev = FlowKey { src: dst, dst: src, sport: dport, dport: sport, proto, _pad: [0; 3] };
    if unsafe { FLOWS.get(&rev) }.is_some() {
        bump(CTR_FLOW_HIT);
        return Ok(TC_ACT_PIPE);
    }
    // 2) continuation of an inbound-allowed flow?
    let fwd = FlowKey { src, dst, sport, dport, proto, _pad: [0; 3] };
    if unsafe { FLOWS.get(&fwd) }.is_some() {
        bump(CTR_FLOW_HIT);
        return Ok(TC_ACT_PIPE);
    }
    // 3) rules (default deny) — Task 7 fills scan_rules; scaffold denies all
    if scan_rules(src, dst, proto, dport) == ACT_ALLOW {
        let _ = FLOWS.insert(&fwd, &1, 0);
        bump(CTR_ALLOW);
        return Ok(TC_ACT_PIPE);
    }
    bump(CTR_DENY);
    Ok(TC_ACT_SHOT)
}

fn try_egress(ctx: &TcContext) -> Result<(), ()> {
    let (src, dst, proto, ihl) = ipv4_at(ctx)?;
    let (sport, dport) = ports_at(ctx, ihl, proto);
    let key = FlowKey { src, dst, sport, dport, proto, _pad: [0; 3] };
    let _ = FLOWS.insert(&key, &1, 0);
    Ok(())
}

fn scan_rules(_src: u32, _dst: u32, _proto: u8, _dport: u16) -> u32 {
    ACT_DENY // scaffold: Task 7 implements first-match scan over active table
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }
```

- [ ] **Step 4: Userspace — load, attach to tun, pin maps, stats subcommand**

```rust
// spike/enforcer/enforcer/src/main.rs
use anyhow::{Context, Result};
use aya::{
    maps::{Array, MapData},
    programs::{tc, SchedClassifier, TcAttachType},
    Ebpf,
};
use clap::{Parser, Subcommand};

#[derive(Parser)]
struct Cli { #[command(subcommand)] cmd: Cmd }

#[derive(Subcommand)]
enum Cmd {
    Run {
        #[arg(long)] iface: String,
        #[arg(long)] rules: std::path::PathBuf,
        #[arg(long, default_value = "/sys/fs/bpf/aeth")] pin_dir: std::path::PathBuf,
    },
    Stats {
        #[arg(long, default_value = "/sys/fs/bpf/aeth")] pin_dir: std::path::PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Run { iface, rules, pin_dir } => run(&iface, &rules, &pin_dir),
        Cmd::Stats { pin_dir } => stats(&pin_dir),
    }
}

fn run(iface: &str, rules_path: &std::path::Path, pin_dir: &std::path::Path) -> Result<()> {
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"), "/enforcer"
    )))?;
    let _ = tc::qdisc_add_clsact(iface); // idempotent-ish: ignore EEXIST
    for (prog, at) in [("aeth_ingress", TcAttachType::Ingress), ("aeth_egress", TcAttachType::Egress)] {
        let p: &mut SchedClassifier = ebpf.program_mut(prog).context(prog)?.try_into()?;
        p.load()?;
        p.attach(iface, at)?;
    }
    std::fs::create_dir_all(pin_dir)?;
    for m in ["COUNTERS", "ACTIVE", "RULES_A", "RULES_B", "RULE_LEN", "FLOWS"] {
        ebpf.map_mut(m).context(m)?.pin(pin_dir.join(m))?;
    }
    apply_rules(&mut ebpf, rules_path)?; // Task 7 — scaffold: writes zero-length table
    eprintln!("enforcer: attached on {iface}; SIGHUP reloads rules");
    // SIGHUP loop added in Task 7; scaffold just parks:
    loop { std::thread::park(); }
}

fn apply_rules(ebpf: &mut Ebpf, _rules_path: &std::path::Path) -> Result<()> {
    let mut len: Array<&mut MapData, u32> = Array::try_from(ebpf.map_mut("RULE_LEN").unwrap())?;
    len.set(0, 0, 0)?;
    let mut active: Array<&mut MapData, u32> = Array::try_from(ebpf.map_mut("ACTIVE").unwrap())?;
    active.set(0, 0, 0)?;
    Ok(())
}

fn stats(pin_dir: &std::path::Path) -> Result<()> {
    let m = MapData::from_pin(pin_dir.join("COUNTERS"))?;
    let counters: Array<MapData, u64> = Array::try_from(aya::maps::Map::Array(m))?;
    let get = |i| counters.get(&i, 0).unwrap_or(0);
    println!(
        "{{\"allow\":{},\"deny\":{},\"flow_hit\":{},\"icmp_err_pass\":{}}}",
        get(0), get(1), get(2), get(3)
    );
    Ok(())
}
```

- [ ] **Step 5: Write the failing integration test (default-deny through a real WG tun)**

```rust
// spike/enforcer/enforcer/tests/enforce.rs
// Copy the wg two-node lab from spike/tunnel/tests/tunnel_ping.rs into a
// helper `fn wg_lab() -> (Lab, Ns, Ns, Vec<Child>)` at the top of this file
// (overlay 10.10.0.1 <-> 10.10.0.2, tunnel binary from env SPIKE_TUNNEL_BIN).
use natlab::Lab; // + the copied helper

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

    // ping must now fail (denied at B's tun ingress), deny counter must rise
    assert!(!a.exec(&["ping", "-c", "2", "-W", "2", "10.10.0.2"]).unwrap().status.success());
    let s = stats(&b, enf);
    assert!(s["deny"].as_u64().unwrap() >= 2, "deny counter: {s}");
    for c in &mut children { let _ = c.kill(); }
    drop(lab);
}
```

- [ ] **Step 6: Run to fail, build tunnel dep, iterate to green**

Run:
```bash
./dev.sh run "cd spike/tunnel && cargo build --release"
./dev.sh run "cd spike/enforcer && SPIKE_TUNNEL_BIN=/work/spike/tunnel/target/release/spike-tunnel cargo test -- --test-threads=1 --nocapture"
```
Expected: compile errors first (aya API drift is likely — fix against aya 0.13 docs; the template's generated loader shows the current idioms). Iterate until PASS. **This test passing proves: tc-BPF attaches to a tun device, L3 parsing works (no eth header), default-deny + counters work.** Record kernel version + any Docker Desktop BPF quirks in results log Bet 2.

- [ ] **Step 7: Commit**

```bash
git add spike/enforcer
git commit -m "feat(spike): aya tc enforcer scaffold — default-deny on real WG tun, pinned counters"
```

---

### Task 7: enforcer rules — first-match scan + atomic A/B table flip

**Files:**
- Modify: `spike/enforcer/enforcer-ebpf/src/main.rs` (implement `scan_rules`)
- Modify: `spike/enforcer/enforcer/src/main.rs` (rules JSON parsing, SIGHUP reload, A/B flip)
- Test: `spike/enforcer/enforcer/tests/enforce.rs` (two new tests)

**Interfaces:**
- Consumes: Task 6 maps/programs.
- Produces: rules JSON format used by all later tests:
  `[{"src":"10.10.0.0/24","dst":"10.10.0.2/32","proto":"tcp","ports":[5201,5201],"action":"allow"}]`
  (`proto`: `"tcp"|"udp"|"icmp"|"any"`; `ports` absent = any). SIGHUP = write inactive table, flip `ACTIVE`.

- [ ] **Step 1: Implement kernel-side scan**

Replace the `scan_rules` stub (keep signature; read `ACTIVE` once — the spec's one-generation-read-per-packet rule):

```rust
fn scan_rules(src: u32, dst: u32, proto: u8, dport: u16) -> u32 {
    let table = ACTIVE.get(0).copied().unwrap_or(0);
    let len = RULE_LEN.get(table).copied().unwrap_or(0).min(64);
    let mut i = 0u32;
    while i < len {
        let r = match if table == 0 { RULES_A.get(i) } else { RULES_B.get(i) } {
            Some(r) => r,
            None => break,
        };
        if rule_matches(r, src, dst, proto, dport) {
            return r.action;
        }
        i += 1;
    }
    ACT_DENY
}

fn prefix_match(addr: u32, net: u32, plen: u32) -> bool {
    if plen == 0 { return true; }
    let mask = u32::MAX << (32 - plen);
    (u32::from_be(addr) & mask) == (u32::from_be(net) & mask)
}

fn rule_matches(r: &Rule, src: u32, dst: u32, proto: u8, dport: u16) -> bool {
    prefix_match(src, r.src, r.src_plen)
        && prefix_match(dst, r.dst, r.dst_plen)
        && (r.proto == 0 || r.proto == proto as u32)
        && (r.port_hi == 0 || {
            let p = u16::from_be(dport);
            p >= r.port_lo && p <= r.port_hi
        })
}
```

- [ ] **Step 2: Userspace — JSON parsing + flip + SIGHUP**

Replace `apply_rules` and the park loop:

```rust
#[derive(serde::Deserialize)]
struct RuleSpec { src: String, dst: String, proto: String,
                  ports: Option<[u16; 2]>, action: String }

fn parse_cidr(s: &str) -> Result<(u32, u32)> {
    let (ip, plen) = s.split_once('/').context("cidr")?;
    Ok((u32::from(ip.parse::<std::net::Ipv4Addr>()?).to_be(), plen.parse()?))
}

fn apply_rules(ebpf: &mut Ebpf, path: &std::path::Path) -> Result<()> {
    let specs: Vec<RuleSpec> = serde_json::from_slice(&std::fs::read(path)?)?;
    let rules: Vec<Rule> = specs.iter().map(|s| {
        let (src, src_plen) = parse_cidr(&s.src).unwrap();
        let (dst, dst_plen) = parse_cidr(&s.dst).unwrap();
        Rule {
            src, src_plen, dst, dst_plen,
            proto: match s.proto.as_str() { "tcp" => 6, "udp" => 17, "icmp" => 1, _ => 0 },
            port_lo: s.ports.map(|p| p[0]).unwrap_or(0),
            port_hi: s.ports.map(|p| p[1]).unwrap_or(0),
            action: if s.action == "allow" { ACT_ALLOW } else { ACT_DENY },
        }
    }).collect();

    let active_now = { let a: Array<&MapData, u32> = Array::try_from(ebpf.map("ACTIVE").unwrap())?; a.get(&0, 0)? };
    let target = 1 - active_now; // write the INACTIVE table
    let table_name = if target == 0 { "RULES_A" } else { "RULES_B" };
    let mut tbl: Array<&mut MapData, Rule> = Array::try_from(ebpf.map_mut(table_name).unwrap())?;
    for (i, r) in rules.iter().enumerate() { tbl.set(i as u32, *r, 0)?; }
    let mut len: Array<&mut MapData, u32> = Array::try_from(ebpf.map_mut("RULE_LEN").unwrap())?;
    len.set(target, rules.len() as u32, 0)?;
    let mut active: Array<&mut MapData, u32> = Array::try_from(ebpf.map_mut("ACTIVE").unwrap())?;
    active.set(0, target, 0)?; // ATOMIC FLIP
    eprintln!("enforcer: {} rules active on table {}", rules.len(), target);
    Ok(())
}
```

And in `run()`, replace the park loop with a SIGHUP reload loop (use the `signal-hook` crate: on SIGHUP call `apply_rules` again).

- [ ] **Step 3: Write the failing tests**

```rust
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

    // allowed: iperf3 on 5201 (also proves reply path via flow table reverse lookup at A? No —
    // A has no enforcer; this test isolates B-side ingress allow + B->A replies unhindered)
    assert!(a.exec(&["iperf3", "-c", "10.10.0.2", "-p", "5201", "-t", "2"]).unwrap().status.success());
    // denied: ping (icmp has no allow rule)
    assert!(!a.exec(&["ping", "-c", "1", "-W", "2", "10.10.0.2"]).unwrap().status.success());
    for c in &mut children { let _ = c.kill(); } drop(lab);
}

#[test]
fn rule_flip_under_traffic_never_transiently_denies() {
    let enf = env!("CARGO_BIN_EXE_enforcer");
    let (lab, a, b, mut children) = wg_lab();
    std::fs::write("/tmp/r2.json",
        r#"[{"src":"10.10.0.0/24","dst":"10.10.0.2/32","proto":"icmp","action":"allow"}]"#).unwrap();
    let enf_child = b.spawn(&[enf, "run", "--iface", "wg0", "--rules", "/tmp/r2.json"]).unwrap();
    let enf_pid = enf_child.id().to_string();
    children.push(enf_child);
    std::thread::sleep(std::time::Duration::from_secs(1));

    let deny_before = stats(&b, enf)["deny"].as_u64().unwrap();
    // continuous ping (5/s) while flipping the SAME allow ruleset 50 times
    let mut pinger = a.spawn(&["ping", "-i", "0.2", "-c", "60", "10.10.0.2"]).unwrap();
    for _ in 0..50 {
        b.exec(&["kill", "-HUP", &enf_pid]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let out = pinger.wait_with_output().unwrap();
    let txt = String::from_utf8_lossy(&out.stdout);
    assert!(txt.contains(" 0% packet loss"), "loss during flips: {txt}");
    assert_eq!(stats(&b, enf)["deny"].as_u64().unwrap(), deny_before, "transient denies during flip");
    for c in &mut children { let _ = c.kill(); } drop(lab);
}
```

- [ ] **Step 4: Run to fail → implement → green**

Run: `./dev.sh run "cd spike/enforcer && SPIKE_TUNNEL_BIN=/work/spike/tunnel/target/release/spike-tunnel cargo test -- --test-threads=1 --nocapture"`
Expected: all 3 tests PASS. The flip test failing on transient denies would be a **spike finding, not a test bug** — investigate read-once semantics before touching the test. Record outcome in results log Bet 2.

- [ ] **Step 5: Commit**

```bash
git add spike/enforcer
git commit -m "feat(spike): first-match rules + atomic A/B flip proven under traffic"
```

---

### Task 8: enforcer flow table — stateful return traffic end-to-end

**Files:**
- Test: `spike/enforcer/enforcer/tests/enforce.rs` (one new test; kernel code from Task 6 already records/checks flows)

**Interfaces:**
- Consumes: everything from Tasks 6–7.
- Produces: proof of spec §5.3 stateful semantics with enforcers on BOTH gateways.

- [ ] **Step 1: Write the failing test — replies cross the initiator's enforcer with no reverse rule**

```rust
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

    // A->B iperf: SYN passes B's allow rule; SYN-ACK arrives at A's tun ingress,
    // where NO rule allows it — it must pass via A's egress-recorded flow entry.
    assert!(a.exec(&["iperf3", "-c", "10.10.0.2", "-p", "5201", "-t", "2"]).unwrap().status.success(),
        "reply path through initiator-side flow table failed");
    let sa = { let out = a.exec(&[enf, "stats", "--pin-dir", "/sys/fs/bpf/aeth-a"]).unwrap();
               serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap() };
    assert!(sa["flow_hit"].as_u64().unwrap() > 0, "A-side flow table never hit: {sa}");
    for c in &mut children { let _ = c.kill(); } drop(lab);
}
```

- [ ] **Step 2: Run to fail → fix → green**

Run: same test command as Task 7. If this fails, likely causes (in order): pin-dir collision between the two enforcer instances (each netns needs its own — hence the `--pin-dir` args), FlowKey byte-order asymmetry between egress record and ingress reverse lookup. Fix, re-run to PASS.

- [ ] **Step 3: Commit**

```bash
git add spike/enforcer
git commit -m "test(spike): stateful reply path proven with enforcers on both gateways"
```

---

### Task 9: enforcer ICMP — echo keying + embedded-error lookup

**Files:**
- Modify: `spike/enforcer/enforcer-ebpf/src/main.rs` (ICMP-error branch in `try_ingress`)
- Create: `spike/enforcer/enforcer/src/bin/pktgen.rs` (crafted ICMP frag-needed injector)
- Test: `spike/enforcer/enforcer/tests/enforce.rs` (one new test)

**Interfaces:**
- Consumes: Tasks 6–8.
- Produces: `pktgen <src_ip> <dst_ip> --embed <esrc> <edst> <eproto> <esport> <edport>` — sends one ICMP type-3/code-4 (frag-needed) packet via raw socket whose payload embeds the given original-packet header. Proves spec §5.3's ICMP-error rule.

- [ ] **Step 1: Kernel — ICMP error branch (insert before the rules scan in `try_ingress`)**

```rust
    // ICMP errors: pass iff the EMBEDDED original packet matches a recorded flow.
    if proto == 1 {
        let itype: u8 = ctx.load(ihl).map_err(|_| ())?;
        if itype == 3 || itype == 11 || itype == 12 {
            // embedded original IP header starts at ihl + 8 (icmp hdr)
            let eoff = ihl + 8;
            let evihl: u8 = ctx.load(eoff).map_err(|_| ())?;
            if evihl >> 4 == 4 {
                let eihl = ((evihl & 0x0f) as usize) * 4;
                let eproto: u8 = ctx.load(eoff + 9).map_err(|_| ())?;
                let esrc: u32 = ctx.load(eoff + 12).map_err(|_| ())?;
                let edst: u32 = ctx.load(eoff + 16).map_err(|_| ())?;
                let esport: u16 = ctx.load(eoff + eihl).unwrap_or(0);
                let edport: u16 = ctx.load(eoff + eihl + 2).unwrap_or(0);
                // original packet was OUTBOUND from this segment => recorded at egress as-is
                let ekey = FlowKey { src: esrc, dst: edst, sport: esport, dport: edport,
                                     proto: eproto, _pad: [0; 3] };
                if unsafe { FLOWS.get(&ekey) }.is_some() {
                    bump(CTR_ICMP_ERR);
                    return Ok(TC_ACT_PIPE);
                }
            }
        }
    }
```

- [ ] **Step 2: pktgen injector**

```rust
// spike/enforcer/enforcer/src/bin/pktgen.rs
// Sends one ICMPv4 "fragmentation needed" (type 3, code 4) from this netns,
// embedding a fake original IPv4+TCP header, to <dst>.
use std::net::Ipv4Addr;

fn csum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for c in data.chunks(2) {
        sum += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16); }
    !(sum as u16)
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let dst: Ipv4Addr = a[1].parse().unwrap();       // where to send the ICMP error
    let esrc: Ipv4Addr = a[2].parse().unwrap();      // embedded original src
    let edst: Ipv4Addr = a[3].parse().unwrap();      // embedded original dst
    let esport: u16 = a[4].parse().unwrap();
    let edport: u16 = a[5].parse().unwrap();

    // embedded original: minimal IPv4 hdr (proto tcp) + first 8 bytes of TCP hdr
    let mut emb = vec![0u8; 28];
    emb[0] = 0x45; emb[8] = 64; emb[9] = 6;
    emb[12..16].copy_from_slice(&esrc.octets());
    emb[16..20].copy_from_slice(&edst.octets());
    emb[20..22].copy_from_slice(&esport.to_be_bytes());
    emb[22..24].copy_from_slice(&edport.to_be_bytes());
    let ecs = csum(&emb[0..20]); emb[10..12].copy_from_slice(&ecs.to_be_bytes());

    // icmp: type 3 code 4, unused(2B)=0, next-hop mtu = 1000
    let mut icmp = vec![3u8, 4, 0, 0, 0, 0, 0x03, 0xe8];
    icmp.extend_from_slice(&emb);
    let cs = csum(&icmp); icmp[2..4].copy_from_slice(&cs.to_be_bytes());

    let sock = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::RAW,
        Some(socket2::Protocol::ICMPV4)).unwrap();
    sock.send_to(&icmp, &std::net::SocketAddr::from((dst, 0)).into()).unwrap();
    println!("sent frag-needed to {dst} embedding {esrc}:{esport}->{edst}:{edport}");
}
```

(Add `socket2 = "0.5"` to `enforcer/Cargo.toml`.)

- [ ] **Step 3: Write the failing test**

```rust
#[test]
fn icmp_error_for_recorded_flow_passes_unrelated_icmp_error_dropped() {
    let enf = env!("CARGO_BIN_EXE_enforcer");
    let pktgen = env!("CARGO_BIN_EXE_pktgen");
    let (lab, a, b, mut children) = wg_lab();
    std::fs::write("/tmp/ra.json", "[]").unwrap(); // A allows nothing inbound
    children.push(a.spawn(&[enf, "run", "--iface", "wg0", "--rules", "/tmp/ra.json",
                            "--pin-dir", "/sys/fs/bpf/aeth-a"]).unwrap());
    std::thread::sleep(std::time::Duration::from_secs(1));

    // create an outbound flow record on A: tcp 10.10.0.1:44444 -> 10.10.0.2:5201
    // (nc will fail to connect — that's fine, egress recording happens on the SYN)
    let _ = a.exec(&["timeout", "1", "nc", "-p", "44444", "10.10.0.2", "5201"]);

    let stats_a = || -> serde_json::Value {
        let out = a.exec(&[enf, "stats", "--pin-dir", "/sys/fs/bpf/aeth-a"]).unwrap();
        serde_json::from_slice(&out.stdout).unwrap()
    };
    let (icmp0, deny0) = { let s = stats_a();
        (s["icmp_err_pass"].as_u64().unwrap(), s["deny"].as_u64().unwrap()) };

    // matching frag-needed from B — must PASS
    b.exec(&[pktgen, "10.10.0.1", "10.10.0.1", "10.10.0.2", "44444", "5201"]).unwrap();
    // non-matching (no such flow) — must be DENIED
    b.exec(&[pktgen, "10.10.0.1", "10.10.0.1", "10.10.0.2", "12345", "9999"]).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));

    let s = stats_a();
    assert_eq!(s["icmp_err_pass"].as_u64().unwrap(), icmp0 + 1, "matching ICMP error not passed: {s}");
    assert!(s["deny"].as_u64().unwrap() > deny0, "unrelated ICMP error not denied: {s}");
    for c in &mut children { let _ = c.kill(); } drop(lab);
}
```

- [ ] **Step 4: Run to fail → implement → green; record Bet 2 complete**

Run: same test command. Expected: PASS (5 tests total in the crate). Record in results log Bet 2: kernel version, all five behaviors proven (attach-on-tun, default-deny, first-match+atomic flip, stateful both-sides, ICMP-error pass/deny), and any verifier fights encountered.

- [ ] **Step 5: Commit**

```bash
git add spike/enforcer
git commit -m "feat(spike): ICMP echo keying + embedded-error flow lookup proven"
```

---

### Task 10: natlab NAT cells — port-restricted, symmetric, CGNAT

**Files:**
- Modify: `spike/natlab/src/lib.rs` (add `nat_router` + `NatKind`)
- Test: `spike/natlab/tests/nat_behavior.rs`

**Interfaces:**
- Consumes: Task 2 Lab/Ns.
- Produces:
  - `pub enum NatKind { PortRestricted, Symmetric }`
  - `Lab::nat_router(&mut self, name: &str, kind: NatKind, inside: (&str /*if*/, &str /*cidr*/), outside: (&str, &str)) -> Result<Ns>` — creates a router namespace with nftables masquerade (`PortRestricted` = plain `masquerade`; `Symmetric` = `masquerade fully-random`), IP forwarding enabled. Caller wires veths to it with `Lab::veth`.
  - CGNAT = two chained `Symmetric` routers (test demonstrates the composition; no dedicated kind).

- [ ] **Step 1: Implement `nat_router`**

```rust
#[derive(Clone, Copy)]
pub enum NatKind { PortRestricted, Symmetric }

impl Lab {
    pub fn nat_router(&mut self, name: &str, kind: NatKind) -> Result<Ns> {
        let ns = self.ns(name)?;
        ns.exec(&["sysctl", "-w", "net.ipv4.ip_forward=1"])?;
        let flags = match kind { NatKind::PortRestricted => "", NatKind::Symmetric => " fully-random" };
        let ruleset = format!(
            "table ip nat {{ chain post {{ type nat hook postrouting priority 100; oifname \"out0\" masquerade{flags}; }} }}"
        );
        std::fs::write(format!("/tmp/{}.nft", ns.name), &ruleset)?;
        ns.exec(&["nft", "-f", &format!("/tmp/{}.nft", ns.name)])?;
        Ok(ns)
    }
}
```

Convention: the router's outside interface is always named `out0`, inside is `in0` (callers pass those names to `veth`).

- [ ] **Step 2: Write the failing behavior test**

The test builds `client -- router -- server1/server2` (server ns has two IPs), sends UDP from ONE client socket to both server addresses, and asserts the observed source port at the servers: equal ⇒ endpoint-independent mapping (PortRestricted), different ⇒ Symmetric. Use a 10-line UDP echo in the test via `socat` — no, keep it in Rust:

```rust
// spike/natlab/tests/nat_behavior.rs
use natlab::{Lab, NatKind};
use std::net::UdpSocket;

fn observed_port(kind: NatKind) -> (u16, u16) {
    let mut lab = Lab::new(match kind { NatKind::PortRestricted => "npr", NatKind::Symmetric => "nsy" }).unwrap();
    let c = lab.ns("c").unwrap();
    let r = lab.nat_router("r", kind).unwrap();
    let s = lab.ns("s").unwrap();
    lab.veth((&c, "eth0", "192.168.50.2/24"), (&r, "in0", "192.168.50.1/24")).unwrap();
    lab.veth((&r, "out0", "203.0.113.1/24"), (&s, "eth0", "203.0.113.10/24")).unwrap();
    c.exec(&["ip", "route", "add", "default", "via", "192.168.50.1"]).unwrap();
    s.exec(&["ip", "addr", "add", "203.0.113.11/24", "dev", "eth0"]).unwrap();

    // server: one UDP recv per address, reports peer port (run via `ip netns exec` + python? No —
    // spawn this same test binary's helper) — simplest: use socat, present in container? Use nc -u -l.
    // Deterministic approach: spawn two `nc -u -l -p 7001/7002` with -v and parse... fragile.
    // Robust approach: tiny rust helper bin in natlab: examples/udpsink.rs prints "PEER <addr>" per packet.
    todo!("see step 3: examples/udpsink.rs");
}

#[test]
fn port_restricted_nat_is_endpoint_independent() {
    let (p1, p2) = observed_port(NatKind::PortRestricted);
    assert_eq!(p1, p2, "plain masquerade should map endpoint-independently");
}

#[test]
fn symmetric_nat_maps_per_destination() {
    let (p1, p2) = observed_port(NatKind::Symmetric);
    assert_ne!(p1, p2, "fully-random masquerade should differ per destination");
}
```

- [ ] **Step 3: Add `spike/natlab/examples/udpsink.rs` and finish the test**

```rust
// spike/natlab/examples/udpsink.rs — bind <addr:port>, print peer of first datagram, exit
fn main() {
    let bind = std::env::args().nth(1).unwrap();
    let sock = std::net::UdpSocket::bind(&bind).unwrap();
    let mut buf = [0u8; 64];
    let (_, peer) = sock.recv_from(&mut buf).unwrap();
    println!("PEER {peer}");
}
```

Finish `observed_port`: spawn `udpsink 203.0.113.10:7001` and `udpsink 203.0.113.11:7002` in `s` (path: `env!("CARGO_BIN_EXE_udpsink")` is not available for examples in integration tests — build first and use `../target/debug/examples/udpsink`), send two datagrams from one bound client socket (`c.exec` + a tiny inline `python3`? No python in image) — send from the client ns by spawning `udpsink`'s sibling: add `examples/udpsend.rs` (bind 0.0.0.0:6000, send "x" to both targets), then read both sink outputs and parse the ports.

```rust
// spike/natlab/examples/udpsend.rs — bind :6000, send one datagram to each arg
fn main() {
    let sock = std::net::UdpSocket::bind("0.0.0.0:6000").unwrap();
    for target in std::env::args().skip(1) {
        sock.send_to(b"x", &target).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}
```

- [ ] **Step 4: Run to fail → wire up → green**

Run: `./dev.sh run "cd spike/natlab && cargo build --examples && cargo test -- --test-threads=1 --nocapture"`
Expected: both NAT-behavior tests PASS. **If `fully-random` still yields equal ports** (kernel SNAT port-preservation can win), that's a finding: try `masquerade random`, then explicit per-destination `snat to :30000-40000`/`:40001-50000` rules — the cell must actually behave symmetrically, however achieved. Record what worked in results log Bet 5.

- [ ] **Step 5: Commit**

```bash
git add spike/natlab
git commit -m "feat(spike): NAT cells (port-restricted, symmetric) with behavior-asserting tests"
```

---

### Task 11: punch — UDP observation endpoint + client

**Files:**
- Create: `spike/punch/Cargo.toml` (deps: `tokio = { version = "1", features = ["full"] }`, `anyhow = "1"`, `serde = { version = "1", features = ["derive"] }`, `serde_json = "1"`; dev-dep `natlab = { path = "../natlab" }`)
- Create: `spike/punch/src/bin/observe.rs`
- Create: `spike/punch/src/lib.rs`
- Test: `spike/punch/tests/observe.rs`

**Interfaces:**
- Consumes: natlab + NAT cells (Task 10).
- Produces:
  - `observe <bind_addr>` — UDP server; on 4-byte magic `AOBS` replies with the observed `ip:port` as UTF-8. (The spike version of the controller's UDP observation endpoint, spec §6.1.)
  - `punch::observe(local_sock: &UdpSocket, server: SocketAddr) -> Result<SocketAddr>` — client helper sending the magic from an existing socket (the "from the WG socket" property).

- [ ] **Step 1: Server + client lib**

```rust
// spike/punch/src/bin/observe.rs
fn main() -> anyhow::Result<()> {
    let bind = std::env::args().nth(1).unwrap_or_else(|| "0.0.0.0:7777".into());
    let sock = std::net::UdpSocket::bind(&bind)?;
    eprintln!("observe: listening on {bind}");
    let mut buf = [0u8; 16];
    loop {
        let (n, peer) = sock.recv_from(&mut buf)?;
        if n >= 4 && &buf[..4] == b"AOBS" {
            sock.send_to(peer.to_string().as_bytes(), peer)?;
        }
    }
}
```

```rust
// spike/punch/src/lib.rs
use anyhow::{Context, Result};
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

pub fn observe(local: &UdpSocket, server: SocketAddr) -> Result<SocketAddr> {
    local.set_read_timeout(Some(Duration::from_secs(2)))?;
    for _ in 0..3 {
        local.send_to(b"AOBS", server)?;
        let mut buf = [0u8; 64];
        if let Ok((n, from)) = local.recv_from(&mut buf) {
            if from == server {
                return String::from_utf8_lossy(&buf[..n]).parse().context("parse observed addr");
            }
        }
    }
    anyhow::bail!("no observation reply from {server}")
}
```

- [ ] **Step 2: Write the failing test — observed address crosses NAT correctly**

```rust
// spike/punch/tests/observe.rs
use natlab::{Lab, NatKind};

#[test]
fn observation_reports_nat_mapping_not_local_addr() {
    let mut lab = Lab::new("obs").unwrap();
    let c = lab.ns("c").unwrap();
    let r = lab.nat_router("r", NatKind::PortRestricted).unwrap();
    let s = lab.ns("s").unwrap();
    lab.veth((&c, "eth0", "192.168.60.2/24"), (&r, "in0", "192.168.60.1/24")).unwrap();
    lab.veth((&r, "out0", "203.0.114.1/24"), (&s, "eth0", "203.0.114.10/24")).unwrap();
    c.exec(&["ip", "route", "add", "default", "via", "192.168.60.1"]).unwrap();

    let observe_bin = concat!(env!("CARGO_MANIFEST_DIR"), "/../target-note"); // see step 3
    let mut server = s.spawn(&[env!("CARGO_BIN_EXE_observe"), "203.0.114.10:7777"]).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));

    // run the client INSIDE ns c: easiest is a tiny client bin, spike/punch/src/bin/whoami.rs
    let out = c.exec(&[env!("CARGO_BIN_EXE_whoami"), "203.0.114.10:7777", "6001"]).unwrap();
    let observed = String::from_utf8_lossy(&out.stdout);
    assert!(observed.starts_with("203.0.114.1:"), "observed should be router's public ip, got {observed}");
    assert!(!observed.contains("192.168.60.2"), "must not leak the private addr");
    let _ = server.kill();
}
```

- [ ] **Step 3: Add the `whoami` client bin**

```rust
// spike/punch/src/bin/whoami.rs — bind 0.0.0.0:<port>, print observed addr via server
fn main() -> anyhow::Result<()> {
    let server: std::net::SocketAddr = std::env::args().nth(1).unwrap().parse()?;
    let port: u16 = std::env::args().nth(2).unwrap().parse()?;
    let sock = std::net::UdpSocket::bind(("0.0.0.0", port))?;
    print!("{}", punch::observe(&sock, server)?);
    Ok(())
}
```

(Remove the stray `observe_bin` line from the test.)

- [ ] **Step 4: Run to fail → green**

Run: `./dev.sh run "cd spike/punch && cargo test -- --test-threads=1 --nocapture"`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add spike/punch
git commit -m "feat(spike): UDP-native endpoint observation through NAT"
```

---

### Task 12: punch — brokered simultaneous hole punch

**Files:**
- Create: `spike/punch/src/bin/broker.rs`
- Create: `spike/punch/src/bin/puncher.rs`
- Test: `spike/punch/tests/punch.rs`

**Interfaces:**
- Consumes: Tasks 10–11.
- Produces:
  - `broker <bind_tcp>` — accepts exactly 2 TCP connections; each sends one JSON line `{"id":"A","candidates":["ip:port",...]}`; when both registered, broker sends each the other's candidates as one JSON line `{"peer":"B","candidates":[...],"go":true}` simultaneously, then exits. (Spike version of Sync-brokered punching, spec §6.1.)
  - `puncher <broker_tcp> <id> <local_udp_port> <observe_server>` — observes own mapping (Task 11 lib), registers, on "go" blasts `PING <id>` datagrams at all peer candidates for 5s while listening; prints `PUNCHED <peer_addr>` on first bidirectional confirm (receives `PONG`; replies `PONG` to any `PING`), exit 0; exit 1 on timeout.

- [ ] **Step 1: Implement broker**

```rust
// spike/punch/src/bin/broker.rs
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;

#[derive(serde::Deserialize)]
struct Reg { id: String, candidates: Vec<String> }

fn main() -> anyhow::Result<()> {
    let bind = std::env::args().nth(1).unwrap();
    let l = TcpListener::bind(&bind)?;
    eprintln!("broker: on {bind}");
    let mut conns = vec![];
    for _ in 0..2 {
        let (s, _) = l.accept()?;
        let mut line = String::new();
        BufReader::new(s.try_clone()?).read_line(&mut line)?;
        let reg: Reg = serde_json::from_str(&line)?;
        conns.push((s, reg));
    }
    let (mut s0, r0) = conns.remove(0);
    let (mut s1, r1) = conns.remove(0);
    let m0 = format!("{{\"peer\":\"{}\",\"candidates\":{},\"go\":true}}\n", r1.id, serde_json::to_string(&r1.candidates)?);
    let m1 = format!("{{\"peer\":\"{}\",\"candidates\":{},\"go\":true}}\n", r0.id, serde_json::to_string(&r0.candidates)?);
    s0.write_all(m0.as_bytes())?; s1.write_all(m1.as_bytes())?; // near-simultaneous go
    Ok(())
}
```

- [ ] **Step 2: Implement puncher**

```rust
// spike/punch/src/bin/puncher.rs
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::{Duration, Instant};

#[derive(serde::Deserialize)]
struct Go { candidates: Vec<String> }

fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    let (broker, id, port, obs) = (&a[1], &a[2], a[3].parse::<u16>()?, a[4].parse()?);
    let sock = UdpSocket::bind(("0.0.0.0", port))?;
    let observed = punch::observe(&sock, obs)?;
    let local_guess = format!("0.0.0.0:{port}"); // local candidate is low-value in the lab; observed is the real one
    let mut tcp = TcpStream::connect(broker)?;
    writeln!(tcp, "{{\"id\":\"{id}\",\"candidates\":[\"{observed}\",\"{local_guess}\"]}}")?;
    let mut line = String::new();
    BufReader::new(tcp.try_clone()?).read_line(&mut line)?;
    let go: Go = serde_json::from_str(&line)?;

    sock.set_read_timeout(Some(Duration::from_millis(50)))?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buf = [0u8; 64];
    while Instant::now() < deadline {
        for c in &go.candidates {
            if let Ok(addr) = c.parse::<std::net::SocketAddr>() {
                let _ = sock.send_to(format!("PING {id}").as_bytes(), addr);
            }
        }
        if let Ok((n, from)) = sock.recv_from(&mut buf) {
            let msg = String::from_utf8_lossy(&buf[..n]).to_string();
            if msg.starts_with("PING") { let _ = sock.send_to(b"PONG", from); }
            if msg.starts_with("PONG") { println!("PUNCHED {from}"); return Ok(()); }
        }
    }
    eprintln!("punch failed"); std::process::exit(1);
}
```

- [ ] **Step 3: Write the failing tests — positive and negative cells**

```rust
// spike/punch/tests/punch.rs
use natlab::{Lab, NatKind};

// topology: pa -- ra -- internet -- rb -- pb ; broker + observe live on "internet" ns
fn punch_cell(kind: NatKind, prefix: &str) -> (bool, bool) {
    let mut lab = Lab::new(prefix).unwrap();
    let inet = lab.ns("inet").unwrap();
    let pa = lab.ns("pa").unwrap(); let ra = lab.nat_router("ra", kind).unwrap();
    let pb = lab.ns("pb").unwrap(); let rb = lab.nat_router("rb", kind).unwrap();
    lab.veth((&pa, "eth0", "192.168.70.2/24"), (&ra, "in0", "192.168.70.1/24")).unwrap();
    lab.veth((&ra, "out0", "198.51.100.2/24"), (&inet, "ia", "198.51.100.1/24")).unwrap();
    lab.veth((&pb, "eth0", "192.168.71.2/24"), (&rb, "in0", "192.168.71.1/24")).unwrap();
    lab.veth((&rb, "out0", "198.51.100.130/25"), (&inet, "ib", "198.51.100.129/25")).unwrap();
    // NOTE: give inet forwarding + routes so ra-side and rb-side subnets reach each other via inet
    inet.exec(&["sysctl", "-w", "net.ipv4.ip_forward=1"]).unwrap();
    pa.exec(&["ip", "route", "add", "default", "via", "192.168.70.1"]).unwrap();
    pb.exec(&["ip", "route", "add", "default", "via", "192.168.71.1"]).unwrap();
    ra.exec(&["ip", "route", "add", "default", "via", "198.51.100.1"]).unwrap();
    rb.exec(&["ip", "route", "add", "default", "via", "198.51.100.129"]).unwrap();

    let mut obs = inet.spawn(&[env!("CARGO_BIN_EXE_observe"), "198.51.100.1:7777"]).unwrap();
    let mut brk = inet.spawn(&[env!("CARGO_BIN_EXE_broker"), "198.51.100.1:7000"]).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));

    let p = env!("CARGO_BIN_EXE_puncher");
    let mut ca = pa.spawn(&[p, "198.51.100.1:7000", "A", "6100", "198.51.100.1:7777"]).unwrap();
    let mut cb = pb.spawn(&[p, "198.51.100.1:7000", "B", "6100", "198.51.100.1:7777"]).unwrap();
    let ok_a = ca.wait().unwrap().success();
    let ok_b = cb.wait().unwrap().success();
    let _ = obs.kill(); let _ = brk.kill();
    (ok_a, ok_b)
}

#[test]
fn port_restricted_pair_punches() {
    let (a, b) = punch_cell(NatKind::PortRestricted, "ppr");
    assert!(a && b, "port-restricted pair must punch (a={a} b={b})");
}

#[test]
fn symmetric_pair_fails_to_punch() {
    let (a, b) = punch_cell(NatKind::Symmetric, "psy");
    assert!(!(a && b), "symmetric pair punching would be a (welcome) surprise — investigate before changing this test");
}
```

- [ ] **Step 4: Run to fail → green; record Bet 4**

Run: `./dev.sh run "cd spike/punch && cargo test -- --test-threads=1 --nocapture"`
Expected: both PASS. Record in results log Bet 4: punch success matrix, time-to-punch, and the note that the negative cell is what the relay exists for.

- [ ] **Step 5: Commit**

```bash
git add spike/punch
git commit -m "feat(spike): brokered UDP hole punch — port-restricted succeeds, symmetric fails to relay"
```

---

### Task 13: relay — QUIC datagram forwarder with mutual TLS

**Files:**
- Create: `spike/relay/Cargo.toml` (deps: `quinn = "0.11"`, `rustls = "0.23"`, `rcgen = "0.13"`, `tokio = { version = "1", features = ["full"] }`, `anyhow`, `clap = { version = "4", features = ["derive"] }`; dev-dep `natlab`)
- Create: `spike/relay/src/bin/mkcerts.rs`
- Create: `spike/relay/src/bin/relay.rs`
- Create: `spike/relay/src/lib.rs` (client)
- Test: `spike/relay/tests/bridge.rs`

**Interfaces:**
- Consumes: nothing prior (standalone bet), natlab for the netns test.
- Produces:
  - `mkcerts <dir>` — writes `ca.pem`, `relay.pem/key`, `gw-A.pem/key`, `gw-B.pem/key` (rcgen CA; leaf CN = gateway id).
  - `relay <bind_udp> <certdir>` — QUIC server, **requires client certs chaining to ca.pem**; client's first uni stream carries its 8-byte-padded id; datagrams are `[8B dest_id][payload]`, forwarded to the dest's connection as `[8B src_id][payload]`. In-memory map only.
  - `relay::Client::connect(relay_addr, certdir, my_id) -> Client` with `async send_to(dest: &str, data: &[u8])`, `async recv() -> (String, Vec<u8>)`, `fn max_datagram_size() -> Option<usize>`.

- [ ] **Step 1: mkcerts**

```rust
// spike/relay/src/bin/mkcerts.rs
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

fn main() -> anyhow::Result<()> {
    let dir = std::path::PathBuf::from(std::env::args().nth(1).unwrap());
    std::fs::create_dir_all(&dir)?;
    let ca_key = KeyPair::generate()?;
    let mut ca_p = CertificateParams::new(vec![])?;
    ca_p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_p.self_signed(&ca_key)?;
    std::fs::write(dir.join("ca.pem"), ca.pem())?;
    for name in ["relay", "gw-A", "gw-B"] {
        let key = KeyPair::generate()?;
        let mut p = CertificateParams::new(vec![name.to_string(), "203.0.113.1".into(), "198.51.100.1".into()])?;
        p.distinguished_name.push(rcgen::DnType::CommonName, name);
        let cert = p.signed_by(&key, &ca, &ca_key)?;
        std::fs::write(dir.join(format!("{name}.pem")), cert.pem())?;
        std::fs::write(dir.join(format!("{name}.key")), key.serialize_pem())?;
    }
    Ok(())
}
```

- [ ] **Step 2: relay server**

```rust
// spike/relay/src/bin/relay.rs
use anyhow::Result;
use quinn::{Endpoint, ServerConfig};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

type Registry = Arc<Mutex<HashMap<[u8; 8], quinn::Connection>>>;

#[tokio::main]
async fn main() -> Result<()> {
    let bind: std::net::SocketAddr = std::env::args().nth(1).unwrap().parse()?;
    let dir = std::path::PathBuf::from(std::env::args().nth(2).unwrap());
    let server_config = relay::server_config(&dir)?; // rustls: relay cert + REQUIRED client auth vs ca.pem
    let endpoint = Endpoint::server(server_config, bind)?;
    eprintln!("relay: on {bind}");
    let reg: Registry = Arc::new(Mutex::new(HashMap::new()));
    while let Some(incoming) = endpoint.accept().await {
        let reg = reg.clone();
        tokio::spawn(async move {
            let Ok(conn) = incoming.await else { return };
            // registration: first uni stream = 8-byte id
            let Ok(mut rs) = conn.accept_uni().await else { return };
            let Ok(idbuf) = rs.read_to_end(8).await else { return };
            let mut id = [0u8; 8];
            id[..idbuf.len().min(8)].copy_from_slice(&idbuf[..idbuf.len().min(8)]);
            reg.lock().await.insert(id, conn.clone());
            eprintln!("relay: registered {:?}", String::from_utf8_lossy(&id));
            while let Ok(dgram) = conn.read_datagram().await {
                if dgram.len() < 8 { continue; }
                let mut dest = [0u8; 8];
                dest.copy_from_slice(&dgram[..8]);
                if let Some(peer) = reg.lock().await.get(&dest) {
                    let mut fwd = Vec::with_capacity(dgram.len());
                    fwd.extend_from_slice(&id);           // src id header
                    fwd.extend_from_slice(&dgram[8..]);
                    let _ = peer.send_datagram(fwd.into());
                }
            }
            reg.lock().await.remove(&id);
        });
    }
    Ok(())
}
```

- [ ] **Step 3: client lib + TLS plumbing in `src/lib.rs`**

`server_config(dir)`: rustls `ServerConfig` with relay cert/key and `WebPkiClientVerifier` built from `ca.pem` (client auth REQUIRED); wrap in `quinn::ServerConfig` with a `TransportConfig` that sets `max_idle_timeout(30s)`, default MTU discovery (leave `MtuDiscoveryConfig::default()` — that IS DPLPMTUD), and datagrams enabled (`datagram_receive_buffer_size(Some(1<<20))`).
`Client::connect`: quinn client endpoint, `ClientConfig` with root = ca.pem AND client cert = `gw-<id>` pair; after connect, open uni stream, write 8-byte id, `finish()`. `send_to` prepends dest id. `recv` strips 8-byte src header. `max_datagram_size()` = `conn.max_datagram_size()`.

Also add a negative-auth helper: `Client::connect_no_cert(...)` identical but without client cert (for the reject test).

- [ ] **Step 4: Write the failing tests**

```rust
// spike/relay/tests/bridge.rs
use natlab::Lab;

#[tokio::test]
async fn bridges_datagrams_and_rejects_certless_clients() {
    // Runs in the root ns — no NAT needed to prove bridging + auth.
    let dir = tempdir_path(); // std::env::temp_dir().join(unique)
    run(env!("CARGO_BIN_EXE_mkcerts"), &[dir.to_str().unwrap()]);
    let relay_bin = env!("CARGO_BIN_EXE_relay");
    let mut relay = spawn(relay_bin, &["127.0.0.1:4443", dir.to_str().unwrap()]);
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let a = relay::Client::connect("127.0.0.1:4443".parse().unwrap(), &dir, "gw-A").await.unwrap();
    let b = relay::Client::connect("127.0.0.1:4443".parse().unwrap(), &dir, "gw-B").await.unwrap();
    a.send_to("gw-B\0\0\0\0", b"hello").await.unwrap();
    let (src, data) = tokio::time::timeout(std::time::Duration::from_secs(3), b.recv()).await.unwrap().unwrap();
    assert_eq!(&data, b"hello");
    assert!(src.starts_with("gw-A"));

    // datagram size: must comfortably exceed the 1280-MTU requirement (spec §6.1: WG(1280)+32 wrapped)
    let max = a.max_datagram_size().expect("datagrams enabled");
    assert!(max >= 1312 + 8, "max datagram {max} too small for tun MTU 1280 (+wg 32 +hdr 8)");

    // no client cert => handshake must FAIL
    assert!(relay::Client::connect_no_cert("127.0.0.1:4443".parse().unwrap(), &dir).await.is_err(),
        "certless client accepted — mutual TLS not enforced");
    let _ = relay.kill();
}
```

- [ ] **Step 5: Run to fail → implement lib → green; record max datagram size in results Bet 3**

Run: `./dev.sh run "cd spike/relay && cargo test -- --test-threads=1 --nocapture"`
Expected: PASS. Record `max_datagram_size` before/after DPLPMTUD settles (print both).

- [ ] **Step 6: Commit**

```bash
git add spike/relay
git commit -m "feat(spike): QUIC datagram relay with mandatory mutual TLS + size check"
```

---

### Task 14: relay — WireGuard-over-relay end to end

**Files:**
- Create: `spike/relay/src/bin/udpshim.rs`
- Test: `spike/relay/tests/wg_over_relay.rs`

**Interfaces:**
- Consumes: `spike-tunnel` (env `SPIKE_TUNNEL_BIN`), relay + client lib (Task 13), natlab.
- Produces: `udpshim <local_udp_bind> <relay_addr> <certdir> <my_id> <peer_id>` — bridges a local UDP socket to the relay: datagrams received locally → `send_to(peer_id)`; relay `recv()` → forward to the last-seen local peer address. WG's endpoint points at the shim. This is the spike stand-in for the gateway's integrated relay transport.

- [ ] **Step 1: Implement udpshim**

```rust
// spike/relay/src/bin/udpshim.rs
use std::sync::Arc;
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    let (bind, relay_addr, dir, my_id, peer_id) = (&a[1], a[2].parse()?, std::path::Path::new(&a[3]), &a[4], &a[5]);
    let sock = Arc::new(UdpSocket::bind(bind).await?);
    let client = relay::Client::connect(relay_addr, dir, my_id).await?;
    let last_peer = Arc::new(tokio::sync::Mutex::new(None::<std::net::SocketAddr>));

    let (s2, lp2, c2) = (sock.clone(), last_peer.clone(), client.clone());
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let Ok((n, from)) = s2.recv_from(&mut buf).await else { break };
            *lp2.lock().await = Some(from);
            let _ = c2.send_to(&peer_id_padded(&a4()), &buf[..n]).await; // see note below
        }
    });
    loop {
        let (_src, data) = client.recv().await?;
        if let Some(peer) = *last_peer.lock().await {
            let _ = sock.send_to(&data, peer).await;
        }
    }
}
```

(Clean up the arg-capture sketch above during implementation — `peer_id` moves into the spawned task; the plan's point is the two pump loops. `Client` must be `Clone` (wrap connection in `Arc`) — adjust lib if needed.)

- [ ] **Step 2: Write the failing end-to-end test**

```rust
// spike/relay/tests/wg_over_relay.rs
// Lab: ns A and ns B each run spike-tunnel + udpshim; relay + mkcerts run in ns R.
// Underlay: A--R and B--R veths (A and B have NO direct link — relay is the only path).
// WG peers' endpoints = 127.0.0.1:<shim port> inside their own ns.
// Assert: wg handshake completes (wg show latest-handshake != 0), overlay ping works,
// and iperf3 runs — with tun MTU 1280 per spec §6.1.
```

Full test body: build the lab exactly like Task 3's `wg_lab` but (a) A/B veths go to R (`10.9.3.1/10.9.3.2` and `10.9.4.1/10.9.4.2`), (b) `mkcerts` into a shared tmpdir, (c) spawn `relay 10.9.3.2:4443` in R (route both A/B to it), (d) spawn `udpshim 127.0.0.1:51999 10.9.3.2:4443 <dir> gw-A gw-B` in A (mirrored in B), (e) `wg set ... endpoint 127.0.0.1:51999`, (f) assert `ping -c 3 -M do -s 1232` (1232 + 28 = 1260 < 1280, DF set) succeeds AND `ping -c 1 -M do -s 1400` fails (proves the MTU boundary is real), (g) record iperf3 throughput through the relay in results Bet 3.

- [ ] **Step 3: Run to fail → implement → green**

Run: `./dev.sh run "cd spike/tunnel && cargo build --release && cd ../relay && SPIKE_TUNNEL_BIN=/work/spike/tunnel/target/release/spike-tunnel cargo test -- --test-threads=1 --nocapture"`
Expected: PASS. **This is the single most load-bearing spike result**: WireGuard handshake + traffic through the authenticated QUIC relay at MTU 1280. Record handshake time and throughput.

- [ ] **Step 4: Commit**

```bash
git add spike/relay
git commit -m "feat(spike): WireGuard over QUIC relay end-to-end at MTU 1280"
```

---

### Task 15: Phase 0 report — go/no-go per bet

**Files:**
- Create: `docs/research/phase0-report.md`
- Modify: `docs/research/phase0-results.md` (final numbers pass)

**Interfaces:**
- Consumes: all recorded results + the boringtun assessment.
- Produces: the decision artifact the MVP planning cycle (spec §12 note: plan cycle 2 of 4) starts from.

- [ ] **Step 1: Write the report**

Structure — every bet gets: what was proven (link the test), measured numbers, surprises/risks discovered, go/no-go, and implications for the MVP design. Explicitly answer:

```markdown
# Phase 0 Spike Report

## Verdicts
| Bet | Result | Evidence |
|---|---|---|
| 1. boringtun embed + throughput | go / no-go / go-with-caveats | tunnel_ping.rs, bench numbers, assessment doc |
| 2. tc-BPF stateful ACL on tun | ... | enforce.rs (5 tests) |
| 3. QUIC datagram relay | ... | bridge.rs, wg_over_relay.rs |
| 4. UDP observation + punch | ... | observe.rs, punch.rs |
| 5. NAT matrix harness | ... | nat_behavior.rs + cells used by 4 |

## Open risks carried into MVP
(e.g., G-2 cloud-VM benchmark still pending; symmetric-NAT emulation fidelity; aya API churn)

## Spec deltas discovered
(anything the spike proved wrong in the design doc — each item becomes a spec edit before MVP planning)

## What the MVP plan should reuse vs. rewrite
(natlab graduates to the real test harness; enforcer program structure carries over; udpshim logic moves into the gateway's tunnel manager; spike-tunnel is superseded by the real gateway binary)
```

- [ ] **Step 2: Verify everything is green one last time**

Run: `./dev.sh run "for c in natlab tunnel enforcer punch relay; do (cd spike/\$c && cargo test -- --test-threads=1) || exit 1; done"`
Expected: all suites PASS (build tunnel release first if needed for env-dependent suites: prefix with the `SPIKE_TUNNEL_BIN` exports as in earlier tasks).

- [ ] **Step 3: Commit**

```bash
git add docs/research/
git commit -m "docs(spike): Phase 0 report — go/no-go per bet"
```

---

## Self-Review Notes (author-run, per writing-plans skill)

- **Spec coverage:** all five §12(1) de-risk items have tasks (bet 1: T3–T5; bet 2: T6–T9; bet 3: T13–T14; bet 4: T11–T12; bet 5: T2+T10). The G-2 cloud-VM number is explicitly carried as a pending manual item (T4/T15) — it cannot run in this environment.
- **Known soft spots (deliberate, spike-appropriate):** aya and boringtun API details in code blocks may drift from published crates — Tasks 3/6 explicitly frame "fix against current docs" as spike work, and any friction feeds the assessment doc. Task 14's udpshim block is a sketch to be cleaned during implementation (flagged inline). CGNAT cell is demonstrated by chaining, not a dedicated `NatKind` (YAGNI: nothing in Phase 0 needs it as a first-class cell; the MVP harness will add it).
- **Type consistency:** `FlowKey`/`Rule`/counter indices defined once in `enforcer-common` and used consistently; natlab `Lab/Ns` signatures match across all consuming tests; relay `Client` API consistent between T13 lib and T14 shim (with the noted `Clone` adjustment).
