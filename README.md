# WireMesh

**A self-hosted, cloud-agnostic, zero-trust L3/L4 network fabric written in Rust.**

WireMesh connects network *segments* — VPCs, VNets, VLANs, bare-metal subnets — rather than individual devices, using **one gateway per segment**. There are no agents on your workloads: connectivity is a route change. The data plane is WireGuard; policy is **default-deny** with explicit L4 allow rules, distributed in real time from a central controller and enforced in-kernel via eBPF (with an nftables fallback).

Think *"AWS Transit Gateway + Twingate, but open-source, self-hosted, and cloud-agnostic."*

> **Status: pre-1.0, under active development.** The design is complete and the riskiest data-plane bets have been de-risked with a working spike; the control plane is being built cycle by cycle. It is **not yet a shippable end-to-end fabric** — see [Project status](#project-status). WireMesh ships **binaries and documentation only — never hosted infrastructure.** Apache-2.0, no monetization, no project-hosted components.

## Why

- **Segment-level, not device-level.** Join whole networks in minutes instead of installing an agent on every host. Connectivity is a route change; workloads are untouched.
- **Zero-trust by default.** 100% of inter-segment traffic is denied unless an explicit L4 allow rule (src/dst CIDR, port range, protocol) exists. Policy is code, changes are audited, and denied flows are counted.
- **Fail-static, not fail-open.** If the controller is unreachable, existing tunnels and the last-applied policy keep working indefinitely — a control-plane outage is never a network outage.
- **Cloud-agnostic & self-hosted.** Run the controller anywhere (VPS, Kubernetes, a managed platform); connect AWS, GCP, Azure, Proxmox, bare metal, homelab — you decide where everything lives.
- **No agents, no kernel modules required.** WireGuard runs in userspace (embedded boringtun); enforcement prefers eBPF but falls back to nftables where BPF privileges are withheld.

### Design goals (targets)

| Goal | Target |
|---|---|
| Time-to-connected (two segments, cold start, from the docs) | **< 30 minutes** |
| Policy propagation (controller → all gateways) | **< 5 s** p99 |
| Zero-trust posture | **default-deny**; no inter-segment flow without an explicit allow |
| Control-plane outage tolerance | **fail-static** — data plane survives indefinitely |
| Platforms | Linux x86-64 + arm64; AWS / GCP / Azure / Proxmox / bare metal / Kubernetes (node-network mode) |

## Architecture

Three single-binary components, all in Rust:

```
        ┌──────────────────────────────────────────────┐
        │  Controller  (control plane, single-tenant)   │
        │  embedded CA · SQLite · mTLS gRPC             │
        │  enrollment · Sync (desired state) · Admin    │
        └───────────────┬───────────────┬──────────────┘
              mTLS gRPC  │               │  mTLS gRPC
             (Sync/Admin)│               │
            ┌────────────▼───┐       ┌───▼────────────┐
            │    Gateway     │◄─────►│    Gateway     │   ... one per segment
            │ boringtun/WG   │  WG   │ boringtun/WG   │
            │ eBPF L4 policy │ (UDP  │ eBPF L4 policy │
            └───────┬────────┘  or   └────────┬───────┘
                    │           relayed)       │
              segment A                   segment B
                                │
                        ┌───────▼───────┐
                        │     Relay     │   stateless QUIC-datagram forwarder
                        │  (mutual TLS) │   guaranteed path when NAT defeats
                        └───────────────┘   direct hole-punching
```

- **Controller** — the single-tenant control plane. Embedded fabric CA, embedded SQLite, three mTLS gRPC services (Enrollment, Sync, Admin) plus a UDP endpoint for NAT-traversal address discovery. Computes the full-mesh topology and streams per-gateway desired state (peer keys, routes, compiled policy, revoked-cert denylist). Driven by the `fabricctl` CLI. Pluggable `SecretStore` / `CertificateIssuer` seams let an external PKI/secrets manager (Vault/OpenBao, and later AWS/GCP/Azure) own key material and rotation.
- **Gateway** — one per segment. Embeds boringtun (userspace WireGuard) for the data plane and enforces default-deny L4 policy with tc-BPF on the tunnel device (nftables fallback). Handles NAT traversal (UDP-native endpoint discovery + brokered hole-punching) and relay failover. No agent runs on the workloads behind it.
- **Relay** — stateless QUIC-datagram forwarder with mandatory mutual TLS. The guaranteed path for gateway pairs that symmetric/CGNAT defeats; carries the same WireGuard ciphertext, so switching between direct and relayed transport never rekeys.

The full engineering design lives in [`docs/superpowers/specs/2026-07-15-wiremesh-engineering-design.md`](docs/superpowers/specs/2026-07-15-wiremesh-engineering-design.md); the product requirements in [`docs/PRD.md`](docs/PRD.md).

## Project status

WireMesh is built in four plan cycles. Progress is tracked in [`docs/progress.html`](docs/progress.html) (open it in a browser).

| Cycle | Scope | Status |
|---|---|---|
| **Phase 0** | De-risk spike — 5 riskiest data-plane bets proven | ✅ **Complete** — `spike/`, 14/14 tests green |
| **Cycle 2** | Controller core — CA, data model, Enrollment / Sync / Admin, `fabricctl` | ✅ **Built** — 18 tasks, 34/34 tests green (landing via PR) |
| **Cycle 3** | Policy pipeline — YAML DSL → IR → eBPF + nftables backends | ⏳ Next |
| **Cycle 4** | Gateway + Relay binaries, NAT-traversal matrix, data-plane key rotation | ⏳ Pending |

**Phase 0** validated the hard parts with throwaway-but-test-proven crates (`spike/`): embedded boringtun, a stateful tc-BPF ACL on a WireGuard tun device, a mutual-TLS QUIC relay carrying WireGuard end-to-end at MTU 1280, UDP-native NAT observation + brokered hole-punching, and a netns NAT-matrix harness. Verdicts and measurements are in [`docs/research/phase0-report.md`](docs/research/phase0-report.md).

**Cycle 2** built the controller control plane as a 5-crate cargo workspace (`crates/`), proven end-to-end against a stub gateway: enroll → receive desired-state snapshot/deltas → ack → survive a controller restart with the same cert (fail-static). The wrap-up notes (`docs/research/cycle2-controller-notes.md`) land with the controller PR.

## Repository layout

```
docs/                     PRD, engineering design, research reports, progress tracker
  PRD.md                  product requirements
  superpowers/specs/      the approved engineering design + per-cycle designs
  superpowers/plans/      implementation plans (one per cycle)
  research/               Phase 0 / Cycle 2 findings and go/no-go reports
spike/                    Phase 0 de-risk crates (throwaway, behavior-proven)
  natlab/ tunnel/ enforcer/ punch/ relay/
crates/                   the controller workspace (Cycle 2) — lands with the controller PR
  wiremesh-proto/         gRPC wire contract (Enrollment/Sync/Admin)
  wiremesh-trust/         SecretStore/CertificateIssuer seams + embedded CA
  wiremesh-controller/    the controller binary
  fabricctl/              admin CLI
  wiremesh-testkit/       integration harness
dev/                      privileged Linux dev container (Dockerfile + doctor)
dev.sh                    container wrapper: build / shell / run
```

## Building & developing

The data-plane and spike code needs Linux (tun / eBPF / netns / nftables), so all code builds and tests inside a **privileged Linux dev container** — the host may be macOS. A wrapper drives it:

```sh
./dev.sh build                        # build the dev image
./dev.sh run "bash dev/doctor.sh"     # verify kernel/BPF/netns capabilities
./dev.sh run "<command>"              # run a command in the container (repo mounted at /work)
./dev.sh shell                        # interactive root shell in the container
```

Run a spike crate's tests (network tests are serial):

```sh
./dev.sh run "cd spike/enforcer && cargo test -- --test-threads=1"
```

The controller (Cycle 2) is pure userspace Rust and builds in the same container; always wrap long runs with a timeout:

```sh
./dev.sh run "cd /work && timeout 500 cargo test --workspace -- --test-threads=1"
```

Requirements: Docker (Desktop or Engine); the image bundles the Rust toolchain, eBPF tooling, iproute2, nftables, WireGuard tools, and iperf3.

## Roadmap

- **Cycle 3 — Policy pipeline:** the YAML policy DSL, its compilation to a versioned IR, and the two enforcement backends (eBPF primary, nftables fallback) with a conformance suite proving behavioral parity.
- **Cycle 4 — Gateway & Relay:** the production gateway and relay binaries, real WireGuard key rotation, and the NAT-traversal matrix, built on the Phase 0 crates.
- **Post-1.0 (P1):** managed-platform integration, provider drivers for AWS/GCP/Azure secrets & PKI, a read-only web UI, a Terraform provider, and controller HA.

## Contributing

WireMesh is developed with a strict, review-first workflow (see [`CLAUDE.md`](CLAUDE.md)): tests are authored independently of the code they cover, every change is reviewed by a fresh set of eyes, and no change is called done until its tests pass. Issues and pull requests are welcome.

## License

[Apache-2.0](LICENSE). WireMesh is an independent open-source project — it ships artifacts and documentation, and never hosts infrastructure or components on your behalf.
