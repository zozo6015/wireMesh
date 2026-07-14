# PRD: Cloud-Agnostic Zero-Trust L3/L4 Network Fabric

| | |
|---|---|
| **Status** | Draft v0.1 |
| **Author** | Peter |
| **Working name** | *TBD* (referred to as "the fabric" throughout; CLI examples use `fabricctl`) |
| **Last updated** | 2026-07-07 |
| **Target audience** | Platform/DevOps engineers, infrastructure teams, homelab operators, Aether tenants |

---

## 1. Problem Statement

Organizations running infrastructure across multiple clouds and on-premise environments have no good option for connecting network segments securely. AWS Transit Gateway is excellent but AWS-only and expensive at scale. Site-to-site VPN meshes (strongSwan, raw WireGuard) are operationally brittle: manual key distribution, hand-maintained routing tables, and no centralized policy. Overlay solutions like Tailscale/Netmaker solve device-level connectivity but require agents on every machine and route at the device level, not the subnet level — a poor fit for connecting whole VPCs, VLANs, and bare-metal subnets. Twingate solves zero-trust access elegantly but is a closed SaaS focused on user-to-resource access, not network-to-network routing.

The result: teams either pay per-GB cloud interconnect fees, run fragile hand-rolled WireGuard meshes with no policy layer, or accept flat, over-permissive connectivity between environments. There is no open-source, self-hosted equivalent of "Transit Gateway across any infrastructure, with zero-trust L4 policy built in."

## 2. Product Overview

A standalone, cloud-agnostic, zero-trust L3/L4 network fabric written in Rust. It connects network *segments* (VPCs, VNets, VLANs, bare-metal subnets) rather than individual devices, using one gateway per segment. No agents on workload machines — connectivity is a route change. Policy is default-deny with explicit L4 allow rules, distributed in real time from a central controller.

**Positioning in one line:** AWS Transit Gateway + Twingate — open source, self-hosted, works across any combination of clouds and on-prem.

### Architecture (3 components, Twingate-style)

1. **Controller** — control plane. Manages topology, CIDR registry, gateway peers; distributes routing tables and ACL policy; handles key exchange and rotation. Communicates with gateways over mTLS gRPC. Deployable anywhere: VPS, Kubernetes, Aether, or future SaaS.
2. **Gateway** — data plane. Single Rust binary on any Linux VM/LXC. One per network segment. Owns a CIDR block, advertises it to the controller, builds WireGuard tunnels (boringtun) to peer gateways, and enforces L4 ACLs locally via nftables (eBPF/XDP later). Transparent to workloads behind it.
3. **Relay** — stateless QUIC forwarder for NAT traversal fallback when direct UDP between gateways is blocked. Runs on any VM with a public IP. Zero payload visibility (end-to-end encrypted).

## 3. Goals

1. **Time-to-connected**: An operator can connect two network segments (e.g., an AWS VPC and a Proxmox VLAN) with working, policy-controlled routing in **under 30 minutes** from a cold start, using only the docs.
2. **Zero workload footprint**: Machines behind a gateway require **no agent, no kernel module, no configuration** beyond a route (ideally injected automatically by the platform's route table integration or the gateway itself).
3. **Zero-trust by default**: 100% of inter-segment traffic is denied unless an explicit L4 allow rule exists. Policy changes propagate controller → all gateways in **< 5 seconds** (p99).
4. **Cloud-agnostic parity**: Identical gateway behavior and operator experience across AWS, GCP, Azure, Proxmox, and generic Linux — no cloud-specific gateway builds.
5. **Operational trust**: Data plane survives control plane outages — existing tunnels and enforced policy continue to function indefinitely if the controller is unreachable (fail-static, not fail-open or fail-closed for existing flows).

## 4. Non-Goals

1. **Device/user-level access (v1)** — no per-laptop, per-user client. This is segment-to-segment routing. User-to-resource zero-trust (Twingate's core use case) is a possible future layer, but conflating the two would bloat v1. Twingate/Tailscale already serve that need.
2. **L7 policy** — no HTTP-aware rules, no identity-aware proxying, no TLS inspection. L4 (CIDR/port/protocol) only. L7 belongs to service meshes and is a different trust model.
3. **Overlapping CIDR support / NAT translation between segments** — rejected at onboarding by the controller. NAT-ing overlapping ranges is a complexity tarpit; document it as a hard constraint. (P2: evaluate 1:1 NAT for brownfield environments.)
4. **Pod/container-level networking** — this is not a CNI and does not replace Cilium. Kubernetes clusters participate as a subnet behind a gateway, not per-pod. (Running the gateway *as* a Kubernetes workload is in scope — see X-1; per-pod policy/identity is not.)
5. **Windows/BSD gateway hosts (v1)** — Linux-only gateways. Workloads behind gateways can be any OS since they're untouched.
6. **Bandwidth/QoS shaping, traffic engineering, multipath** — out of scope for v1; full mesh with relay fallback is the only topology.

## 5. Target Users & Personas

| Persona | Description | Primary need |
|---|---|---|
| **Platform engineer (multi-cloud org)** | Runs EKS + on-prem + a second cloud; today stitches VPNs by hand or pays for interconnect | Reliable segment routing with auditable policy, GitOps-friendly config |
| **Homelab / prosumer operator** | Proxmox at home, VPS in a cloud, wants lab ↔ cloud connectivity without exposing services | Simple setup, one binary, cheap relay, no SaaS dependency |
| **Aether platform tenant** | Consumes managed clusters; wants their cluster networks joined to their own infra | First-class, near-zero-config fabric attachment from the Aether portal |
| **Security/compliance engineer** | Must demonstrate segmentation and least-privilege between environments | Default-deny posture, policy-as-code, audit log of policy changes and denied flows |

## 6. User Stories

Ordered by priority.

1. As a **platform engineer**, I want to register a gateway for each VPC/VLAN and have tunnels form automatically, so that I don't hand-manage WireGuard keys and peer configs.
2. As a **platform engineer**, I want to define allow rules as declarative config (file/API), so that network policy lives in Git and goes through review.
3. As a **security engineer**, I want all inter-segment traffic denied by default with explicit allows per (src CIDR, dst CIDR, port range, protocol), so that I can prove least-privilege segmentation.
4. As a **homelab operator**, I want gateways behind NAT (double NAT, CGNAT) to connect via a relay automatically, so that connectivity works without port forwarding.
5. As a **platform engineer**, I want the controller to reject overlapping CIDRs at onboarding with a clear error, so that routing ambiguity is impossible by construction.
6. As an **operator**, I want existing tunnels and policy to keep working when the controller is down, so that a control-plane outage is not a network outage.
7. As a **security engineer**, I want an audit trail of who changed which policy and when, plus counters/logs of denied flows, so that I can investigate incidents.
8. As an **Aether tenant**, I want to attach my cluster's network to my fabric from the portal in one action, so that managed clusters feel like part of my own infrastructure.
9. As an **operator**, I want Prometheus metrics from every component (tunnel state, handshake age, policy version, relay throughput, denied-packet counters), so that I can alert on fabric health with my existing stack.
10. As an **operator**, I want to drain and remove a gateway cleanly, so that decommissioning a segment doesn't strand routes or keys.

## 7. Requirements

### 7.1 Must-Have (P0)

#### Controller

| ID | Requirement | Acceptance criteria |
|---|---|---|
| C-1 | **Gateway registration & identity.** Gateways enroll with a one-time token; controller issues mTLS client certs. | Given a valid enrollment token, when a gateway starts, then it appears as `registered` in `fabricctl gateway list` within 10s. Reused/expired tokens are rejected with a specific error. |
| C-2 | **CIDR registry with overlap rejection.** Every gateway declares its owned CIDR(s); controller is the source of truth. | Onboarding a gateway whose CIDR overlaps any registered CIDR fails atomically with an error naming the conflicting segment. No partial state. |
| C-3 | **Topology & route distribution.** Controller computes the full-mesh peer set and pushes per-gateway routing tables over mTLS gRPC (server-streaming or watch semantics). | Adding a segment results in updated routes on all gateways within 5s p99. Removing a segment withdraws its routes within the same bound. |
| C-4 | **Policy distribution.** ACL rule sets are versioned; gateways ack the applied version. | `fabricctl policy status` shows the policy version applied per gateway; a stuck gateway is visibly lagging. |
| C-5 | **WireGuard key lifecycle.** Controller coordinates public key exchange between peers and supports rotation without data-plane interruption. | Triggering rotation for a gateway pair completes with < 1s of packet loss on an active iperf flow (make-before-break). |
| C-6 | **Declarative API + CLI.** All state (segments, gateways, policies, relays) manageable via gRPC/HTTP API and `fabricctl`; config expressible as files for GitOps. | `fabricctl apply -f fabric.yaml` is idempotent: applying the same file twice yields zero changes. |
| C-7 | **State persistence.** Controller state survives restart (embedded store, e.g., SQLite/sled, with documented backup path). | Kill and restart the controller: all gateways reconnect and no re-enrollment is required. |
| C-8 | **Audit log.** Every mutating operation (policy change, gateway add/remove, key rotation) is logged with actor, timestamp, and diff. | Audit entries are queryable via API and exportable as JSON lines. |

#### Gateway

| ID | Requirement | Acceptance criteria |
|---|---|---|
| G-1 | **Single static Rust binary**, x86-64 and arm64, no runtime deps beyond a modern kernel and nftables. | Runs on Ubuntu 22.04+/Debian 12+ VM and Proxmox LXC (documented required capabilities/privileges for LXC). |
| G-2 | **WireGuard data plane via boringtun** (userspace), with kernel WireGuard as an optional accelerated mode where available. | Sustains ≥ 1 Gbps single-tunnel throughput on a 4-vCPU cloud VM (userspace); kernel mode documented with measured delta. |
| G-3 | **Full-mesh tunnel establishment** to all peer gateways, with per-pair automatic relay fallback. | With UDP blocked between two gateways, the pair converges to relay transport within 30s without operator action, and reverts to direct when possible. |
| G-4 | **L4 ACL enforcement via nftables.** Default-deny between segments; rules support src/dst CIDR, port ranges, protocol (TCP/UDP/ICMP). | Traffic matching no allow rule is dropped and counted. Rule updates are applied atomically (no enforcement gap, no transient allow-all/deny-all). |
| G-5 | **Transparent to workloads.** No agent on machines behind the gateway; only a route toward the gateway is needed. | Demo: an EC2 instance reaches a Proxmox VM's Postgres with only a VPC route-table entry added, per the allow rule. |
| G-6 | **Fail-static on controller loss.** Tunnels, routes, and the last-applied policy persist while the controller is unreachable. | Kill the controller for 1 hour: existing allowed flows continue; denied flows stay denied; gateways resync on controller return. |
| G-7 | **Graceful drain/decommission.** | `fabricctl gateway drain <name>` withdraws routes from peers before teardown; peers stop routing to it within 5s. |

#### Relay

| ID | Requirement | Acceptance criteria |
|---|---|---|
| R-1 | **Stateless QUIC forwarder** with no payload visibility (relays ciphertext only; keys never leave gateways/controller). | Code review + docs demonstrate the relay cannot decrypt forwarded traffic; relay restart loses no persistent state. |
| R-2 | **Relay registration & advertisement** via the controller; gateways learn available relays automatically. | Adding a relay makes it usable by all gateway pairs without gateway restarts. |
| R-3 | **Per-pair fallback selection** with health checking. | An unhealthy relay is evicted from selection within 15s; pairs re-path via another relay if available. |

#### Cross-cutting (P0)

| ID | Requirement | Acceptance criteria |
|---|---|---|
| X-1 | **Supported gateway platforms:** AWS VPC (EC2), GCP VPC (GCE), Azure VNet, Proxmox (VM + LXC), generic Linux VPS/bare metal, **Kubernetes** (gateway as a hostNetwork workload attaching the cluster/node network), and **local Linux workstation/PC** attaching a home or office LAN. Identical binary everywhere; per-platform docs cover route-table setup, src/dst-check disabling, and required capabilities. | A documented, tested quickstart exists per platform; CI smoke test covers at least AWS + Proxmox + Kubernetes + generic Linux. |
| X-1b | **Distribution & packaging:** static binaries (x86-64, arm64), OCI container image, and a one-line install script are P0. Helm chart and deb/rpm packages are P1. | `curl | sh`, `docker run`, and raw binary all reach a `registered` gateway using the same enrollment token flow. |
| X-2 | **Observability:** Prometheus metrics on all components (tunnel/handshake state, RTT per peer, bytes per peer, policy version, denied-packet counters, relay throughput); structured logs (JSON). | A reference Grafana dashboard ships in the repo. |
| X-3 | **Security baseline:** mTLS everywhere on the control plane; WireGuard (Noise) on the data plane; secrets never written to logs; keys stored with 0600 perms; minimal Linux capabilities documented (no blanket root requirement where avoidable). | Threat model document published (see §10). |
| X-4 | **Docs & quickstart:** end-to-end "two segments in 30 minutes" tutorial (AWS VPC ↔ Proxmox VLAN). | A new user following only the docs completes the tutorial; measured in early-adopter testing. |
| X-5 | **OSS project hygiene (day one):** chosen license, CONTRIBUTING.md, security policy (SECURITY.md + disclosure contact), versioned releases with changelogs, CI running the NAT-matrix and multi-segment integration tests publicly. No opt-out telemetry — any telemetry is opt-in and documented. | Repo passes these checks at first public release; first external PR can be reviewed and merged without process invention. |

### 7.2 Nice-to-Have (P1)

- **Aether first-class integration** — attach an Aether-managed cluster's network to a tenant fabric from the portal/API; gateway lifecycle managed by Aether. Positioned as a *reference downstream integration* — the fabric is an independent OSS project first, and Aether is one consumer of it.
- **Helm chart + deb/rpm packages** — richer packaging on top of the P0 binary/OCI/install-script distribution.
- **Web UI (read-mostly)** — topology graph, tunnel health, policy viewer. CLI/API remain the write path initially.
- **Policy dry-run / plan** — `fabricctl policy plan` shows which existing flows a proposed change would break (based on recent flow counters).
- **Flow logging** — sampled allowed-flow logs (not just denies) for audit, with rate limits to protect the gateway.
- **Controller HA** — active/standby with shared or replicated state. (v1 ships single-node + fail-static gateways + documented backup/restore, which makes controller downtime tolerable.)
- **Terraform provider** for segments, gateways, and policies.
- **kernel WireGuard auto-detection** — prefer kernel module when present, boringtun otherwise.
- **DERP-style relay mesh awareness** — latency-based relay selection when multiple relays exist.

### 7.3 Future Considerations (P2)

- **eBPF/XDP enforcement path** replacing nftables for ACLs on high-throughput gateways. *(Design constraint now: keep the policy model compiler-agnostic — an intermediate representation that can target nftables today and eBPF later.)*
- **User/device access layer** — optional client for user-to-segment access, converging on the full Twingate use case.
- **SaaS controller offering** — hosted control plane (data plane always stays customer-owned). *(Design constraint now: multi-tenancy boundaries in the controller data model from day one.)*
- **IPv6 segments** and dual-stack tunnels.
- **1:1 NAT for overlapping CIDRs** (brownfield escape hatch).
- **BGP integration** — advertise fabric routes to on-prem routers instead of static routes.
- **Policy identity extensions** — tags/labels on segments so rules can reference `env=prod` instead of raw CIDRs.

## 8. Networking & Policy Model (normative summary)

- **L3 subnet routing**, segment-level. One gateway owns one or more CIDRs.
- **Data plane:** WireGuard (boringtun). **Control plane:** mTLS gRPC. **Fallback:** QUIC relay, per gateway pair.
- **Topology:** full mesh of direct tunnels; relay only where direct fails.
- **No overlapping CIDRs**, enforced at onboarding (C-2).
- **Policy:** default deny; explicit allow rules scoped to (source CIDR, destination CIDR, port range(s), protocol). Deny rules supported for carve-outs within an allow. Evaluation order and tie-breaking must be deterministic and documented.

Example (illustrative syntax, final schema TBD — see Open Questions):

```yaml
policy:
  - from: proxmox-lab        # 192.168.0.0/16
    to: aws-prod             # 172.16.0.0/16
    rules:
      - allow: { dst: 172.16.1.50/32, ports: [5432], proto: tcp }   # Postgres
      - allow: { dst: 172.16.2.0/24, ports: [443], proto: tcp }
      - deny:  { ports: [22], proto: tcp }
```

## 9. Success Metrics

**Leading (first 60 days post-v1):**
- Time-to-connected in guided user tests: **≤ 30 min** median (stretch: 15).
- Policy propagation latency: **< 5s p99**, measured continuously in CI/soak environment.
- Tunnel establishment success rate across NAT matrix test (full cone / symmetric / CGNAT): **100% with relay available**.
- GitHub traction as an OSS proxy: **500 stars / 20 external issues** in 60 days (signal, not vanity — issues indicate real deployment attempts).

**Lagging (2 quarters):**
- **≥ 25 distinct production-ish deployments** self-reported (telemetry is opt-in only; count via discussions/issues/adopters file).
- **≥ 3 Aether tenants** using the fabric integration once P1 ships.
- Soak stability: a 3-segment reference fabric runs **30 days** with zero unplanned data-plane interruptions.
- Zero critical CVEs in the enforcement or key-handling paths post external review.

## 10. Security & Threat Model (must be published with v1)

Minimum coverage:
- **Compromised relay** — must yield ciphertext only; no key material, no metadata beyond src/dst gateway endpoints and volume.
- **Compromised controller** — can rewrite topology/policy (accepted risk of centralized control plane); cannot silently read data-plane traffic. Mitigations: audit log (C-8), gateway-side logging of applied policy versions, future policy signing (P2 candidate).
- **Compromised gateway** — blast radius is its own segment plus flows allowed to/from it; peers' keys are per-pair so lateral decryption is not possible.
- **Enrollment token theft** — tokens are single-use and expiring; enrollment binds to expected CIDR.
- **Fail posture** — explicitly fail-static (G-6); document why not fail-closed (a controller outage must not become a network outage).

## 11. Open Questions

| # | Question | Owner | Blocking? |
|---|---|---|---|
| 1 | Policy schema: custom YAML DSL vs. something interoperable (e.g., a subset of Cilium/K8s NetworkPolicy semantics)? Affects G-4 IR design. | Eng (Peter) | Yes — before G-4 |
| 2 | Controller store: SQLite vs. sled vs. Postgres-optional? Impacts HA path (P1). | Eng | Yes — before C-7 |
| 3 | Key rotation cadence and trigger model: time-based, on-demand only, or both? | Eng/Security | No |
| 4 | How are routes injected on the workload side per platform — documented manual route-table entries only (v1), or cloud-API automation (route table writes need cloud credentials on the gateway — trust implication)? | Eng | Yes — scoping X-1 |
| 5 | Does a gateway support multiple owned CIDRs in v1, or exactly one? (Multiple is likely cheap and avoids awkward workarounds.) | Eng | Yes — data model |
| 6 | Conntrack strategy for stateful TCP/UDP allow rules in nftables — per-direction rules or connection tracking with implicit return traffic? | Eng | Yes — before G-4 |
| 7 | Project name + license (Apache-2.0 vs. AGPL given future SaaS ambitions). OSS-first positioning makes this **blocking before the repo goes public** — relicensing later is painful once external contributions land (or requires a CLA from day one). | Peter | Yes — before public repo |
| 8 | Relay abuse prevention for public relays — auth tokens per fabric? Rate limits? | Eng/Security | No (relays are self-hosted in v1) |
| 9 | Kubernetes gateway mode specifics: hostNetwork pod advertising the node/pod/service CIDR? How does it coexist with the CNI (e.g., Cilium) — route injection vs. CNI-native routes? Does it need a NetworkPolicy exemption? | Eng (Peter) | Yes — before the k8s quickstart (X-1) |

## 12. Phasing & Timeline Considerations

No hard external deadlines. Suggested phases, each independently shippable:

- **Phase 0 — Spike (2–3 weeks):** boringtun tunnel between two gateways with static config; nftables rule application; QUIC relay prototype. De-risks the three riskiest technical bets before any controller work.
- **Phase 1 — MVP (P0 core):** controller with enrollment, CIDR registry, route/policy distribution; 2–3 segment mesh; relay fallback; CLI; AWS + Proxmox + generic Linux quickstarts. *Exit criterion: the 30-minute tutorial passes with an external tester.*
- **Phase 2 — Hardening:** key rotation, drain/decommission, full observability, audit log, GCP/Azure docs, threat model publication, soak testing.
- **Phase 3 — P1 wave:** Aether integration, policy plan/dry-run, web UI (read-only), Terraform provider, controller HA.
- **Phase 4 — P2 exploration:** eBPF enforcement path, user-access layer, SaaS controller.

**Dependency callouts:** Aether integration (Phase 3) depends on Aether's tenant/network APIs being stable; eBPF path depends on the policy IR decision (Open Question #1) being made *now* even though implementation is deferred.

## 13. Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| NAT traversal edge cases (symmetric NAT, CGNAT) burn disproportionate effort | High | Medium | Relay-first mentality: relay is the guaranteed path, direct is the optimization. Ship with an honest NAT compatibility matrix. |
| boringtun throughput insufficient for real workloads | Medium | High | Benchmark in Phase 0; kernel-WG mode as escape hatch (P1). |
| nftables atomic-update semantics harder than expected under churn | Medium | Medium | Use nft's native atomic ruleset replacement; policy IR keeps eBPF exit open. |
| Scope gravity toward device-level access ("just add a client") | High | High | Non-goal #1 is explicit; revisit only as P2 after segment routing is proven. |
| Single-node controller perceived as SPOF and blocks adoption | Medium | Medium | Fail-static gateways + loud documentation of the outage story; HA in P1. |

---

*Next artifacts to derive from this PRD: engineering design doc for the controller data model and policy IR (Open Questions 1, 2, 5, 6), and a Phase 0 spike plan.*
