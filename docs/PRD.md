# PRD: Cloud-Agnostic Zero-Trust L3/L4 Network Fabric

| | |
|---|---|
| **Status** | Draft v0.4 |
| **Author** | Peter |
| **Name** | **WireMesh** (CLI: `fabricctl`) |
| **Last updated** | 2026-07-18 |
| **Target audience** | Platform/DevOps engineers, infrastructure teams, homelab operators, managed-platform operators |

---

## 1. Problem Statement

Organizations running infrastructure across multiple clouds and on-premise environments have no good option for connecting network segments securely. AWS Transit Gateway is excellent but AWS-only and expensive at scale. Site-to-site VPN meshes (strongSwan, raw WireGuard) are operationally brittle: manual key distribution, hand-maintained routing tables, and no centralized policy. Overlay solutions like Tailscale/Netmaker solve device-level connectivity but require agents on every machine and route at the device level, not the subnet level — a poor fit for connecting whole VPCs, VLANs, and bare-metal subnets. Twingate solves zero-trust access elegantly but is a closed SaaS focused on user-to-resource access, not network-to-network routing.

The result: teams either pay per-GB cloud interconnect fees, run fragile hand-rolled WireGuard meshes with no policy layer, or accept flat, over-permissive connectivity between environments. There is no open-source, self-hosted equivalent of "Transit Gateway across any infrastructure, with zero-trust L4 policy built in."

## 2. Product Overview

A standalone, cloud-agnostic, zero-trust L3/L4 network fabric written in Rust. It connects network *segments* (VPCs, VNets, VLANs, bare-metal subnets) rather than individual devices, using one gateway per segment. No agents on workload machines — connectivity is a route change. Policy is default-deny with explicit L4 allow rules, distributed in real time from a central controller.

**Positioning in one line:** AWS Transit Gateway + Twingate — open source, self-hosted, works across any combination of clouds and on-prem.

**Project model:** WireMesh is a fully open-source project (Apache-2.0), built on three commitments: **(1) no feature gating** — the self-hosted version is the complete product, forever; **(2) no rug pull** — the license stays Apache-2.0; **(3) hosted offerings are downstream consumers, not the project** — any managed controller (maintainer-operated or third-party) runs the same public binaries, and the data plane always stays customer-owned. Managed platforms (e.g., Aether) and commercial services (hosting, support, sponsored development that lands upstream) are compatible with — and funded by — this model; gated features and relicensing are not.

### Architecture (3 components, Twingate-style)

1. **Controller** — control plane. Manages topology, CIDR registry, gateway peers; distributes routing tables and ACL policy; handles key exchange and rotation. Communicates with gateways over mTLS gRPC. Deployable anywhere: VPS, Kubernetes, or a managed platform.
2. **Gateway** — data plane. Single Rust binary on any Linux VM/LXC. One per network segment. Owns a CIDR block, advertises it to the controller, builds WireGuard tunnels (boringtun) to peer gateways, and enforces L4 ACLs locally in-kernel via eBPF (tc-BPF on the tunnel device), with an nftables fallback where BPF privileges are unavailable. Transparent to workloads behind it.
3. **Relay** — stateless QUIC forwarder for NAT traversal fallback when direct UDP between gateways is blocked. Runs on any VM with a public IP. Zero payload visibility (end-to-end encrypted).

## 3. Goals

1. **Time-to-connected**: An operator can connect two network segments (e.g., an AWS VPC and a Proxmox VLAN) with working, policy-controlled routing in **under 30 minutes** from a cold start, using only the docs.
2. **Zero workload footprint**: Machines behind a gateway require **no agent, no kernel module, no configuration** beyond a route (ideally injected automatically by the platform's route table integration or the gateway itself).
3. **Zero-trust by default**: 100% of inter-segment traffic is denied unless an explicit L4 allow rule exists. Policy changes propagate controller → all gateways in **< 5 seconds** (p99).
4. **Cloud-agnostic parity**: Identical gateway behavior and operator experience across AWS, GCP, Azure, Proxmox, and generic Linux — no cloud-specific gateway builds.
5. **Operational trust**: Data plane survives control plane outages — existing tunnels and enforced policy continue to function indefinitely if the controller is unreachable (fail-static, not fail-open or fail-closed for existing flows).

## 4. Non-Goals

1. **Device/user-level access (v1)** — ***PARTIALLY SUPERSEDED 2026-08-05; read the amendment below before citing this item.*** *Original text, kept for the record:* no per-laptop, per-user client. This is segment-to-segment routing. User-to-resource zero-trust (Twingate's core use case) is a possible future layer, but conflating the two would bloat v1. Twingate/Tailscale already serve that need.

   > **AMENDED 2026-08-05 (owner decision).** A **single-host client peer** is now IN scope, narrowly: a host that joins the fabric **for itself only**, does not front a network, and does not forward. It exists because the "a workstation reaches the fabric" requirement was implicitly assigned to a Kubernetes deployment that cannot carry it — see [`docs/research/macos-exclusion-premise-and-the-client-gap.md`](research/macos-exclusion-premise-and-the-client-gap.md).
   >
   > **Still excluded, and this is not a ZTNA product:** user identity, device posture, per-user policy. Policy remains segment-to-segment; a client is simply another named CIDR set to the policy pipeline, which has no concept of peer identity.
   >
   > Three constraints are ratified with this amendment:
   > - **The receive direction is unprotected in phase 1.** Enforcement is ingress-on-tun only, so `client → segment` is policed at the receiving gateway while `segment → client` is policed by nothing. Accepted, documented, and the client host's own firewall is the operator's responsibility. **Egress-side enforcement on gateways is the bar for calling the client production-grade** — until it ships, the client is explicitly not that.
   > - **Clients live in `100.64.0.0/10`**, which overlaps nothing in the fabric. A client cannot take an address inside an existing segment's CIDR: the overlap check rejects it, and a more-specific `/32` route would hijack traffic to the real host at that address.
   >   **Conflict handling is required, not optional.** `100.64.0.0/10` is carrier-grade NAT space that real ISPs, mobile tethers and other VPNs hand out, so a client can find it already in use *locally* — a case the controller cannot see, since it only validates against registered fabric CIDRs. Before applying its profile the client **must preflight its own routing table and interface addresses for an overlap with the fabric routes it is about to install, and fail closed with a message naming the conflict.** It must not install the profile and hope: the failure mode is silently capturing the user's ISP-side traffic, or losing their own connectivity, neither of which reads as a WireMesh problem. A client that cannot preflight (no route-table access) is unsupported on that platform.
   > - **Roughly a dozen clients is the v1 ceiling.** One client is one segment (no per-peer address column exists), so client count multiplies policy blocks against `MAX_RULES = 256`. Beyond that needs a per-peer address model.
   >
   > Scope and phasing: [`docs/research/client-component-scoping.md`](research/client-component-scoping.md).
2. **L7 policy** — no HTTP-aware rules, no identity-aware proxying, no TLS inspection. L4 (CIDR/port/protocol) only. L7 belongs to service meshes and is a different trust model.
3. **Overlapping CIDR support / NAT translation between segments** — rejected at onboarding by the controller. NAT-ing overlapping ranges is a complexity tarpit; document it as a hard constraint. (P2: evaluate 1:1 NAT for brownfield environments.)
4. **Pod/container-level networking** — this is not a CNI and does not replace Cilium. Kubernetes clusters participate as a subnet behind a gateway, not per-pod. (Running the gateway *as* a Kubernetes workload is in scope — see X-1; per-pod policy/identity is not.)
5. **Windows/BSD gateway hosts (v1)** — Linux-only gateways. Workloads behind gateways can be any OS since they're untouched.

   > **PREMISE CORRECTED 2026-08-05 — the exclusion STANDS, for a better reason.** This was accepted partly on the understanding that Kubernetes plus the operator would cover the workstation case end-to-end. That premise does not hold as built: the gateway's identity lives in an RWO node-local PVC, so there is no HA and an autoscaled cluster makes it worse than a single box; a gateway fronting a network still requires that network to route to it in both directions; and the operator cannot set the rotation interval or perform fabric admin.
   >
   > The exclusion is nonetheless **kept**, on its own technical merits: a non-Linux gateway needs a third enforcer backend (`pf` on macOS) proven equivalent to eBPF and nftables against a conformance suite that only runs in Linux netns.
   >
   > **Reversing it would not have fixed anything.** A gateway fronting a network requires that network to route to it because of *no agents on workloads* (§3.2), not because of Linux — so a macOS gateway inherits the same static routes and the same single point of failure. The remedy for the workstation case is the **client** in non-goal 1, not a macOS gateway. See [`docs/research/macos-exclusion-premise-and-the-client-gap.md`](research/macos-exclusion-premise-and-the-client-gap.md).
6. **Bandwidth/QoS shaping, traffic engineering, multipath** — out of scope for v1; full mesh with relay fallback is the only topology.

## 5. Target Users & Personas

| Persona | Description | Primary need |
|---|---|---|
| **Platform engineer (multi-cloud org)** | Runs EKS + on-prem + a second cloud; today stitches VPNs by hand or pays for interconnect | Reliable segment routing with auditable policy, GitOps-friendly config |
| **Homelab / prosumer operator** | Proxmox at home, VPS in a cloud, wants lab ↔ cloud connectivity without exposing services | Simple setup, one binary, cheap relay, no SaaS dependency |
| **Managed-platform tenant** | Consumes managed clusters; wants their cluster networks joined to their own infra | First-class, near-zero-config fabric attachment from the platform portal |
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
8. As a **managed-platform tenant**, I want to attach my cluster's network to my fabric from the portal in one action, so that managed clusters feel like part of my own infrastructure.
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
| C-9 | **Certificate revocation.** `fabricctl gateway revoke <name>` revokes a gateway's cert; the revoked-serial denylist is pushed to all gateways/relays via Sync and enforced locally (offline-verifiable — no CRL/OCSP dependency at verification time). Sync connections from revoked certs are rejected at handshake. | After revocation: the revoked gateway's Sync stream is terminated and re-connect rejected; all peers drop its tunnels and stop routing to it within 5s p99 of the denylist push; enforcement continues while the controller is unreachable (denylist is local state, consistent with G-6). |
| C-10 | **CA lifecycle & disaster recovery.** Embedded CA cert valid 10y; documented rotation runbook (new CA → cross-sign → push dual-root trust bundle via Sync → leaves re-issue at normal renewal → retire old root). CA-key compromise recovery = new CA + fleet re-enrollment via rebind tokens. Backup unit: SQLite + key directory (embedded mode) or SQLite alone (external SecretStore mode), with documented restore ordering. | A controller restored from backup on a fresh host: all gateways reconnect with no re-enrollment (extends C-7). The CA-rotation runbook and the compromise/rekey runbook are both executed as integration tests, not just documented. |

#### Gateway

| ID | Requirement | Acceptance criteria |
|---|---|---|
| G-1 | **Single static Rust binary**, x86-64 and arm64, no runtime deps beyond a modern kernel (BPF-capable; nftables required only for the fallback enforcement path). | Runs on Ubuntu 22.04+/Debian 12+ VM and Proxmox LXC (documented required capabilities/privileges for LXC). |
| G-2 | **WireGuard data plane via boringtun** (userspace), with kernel WireGuard as an optional accelerated mode where available. | Defined benchmark (the Phase 0 `bench.sh` harness): iperf3, TCP, tun MTU 1280, on a 4-vCPU x86-64 cloud VM (c6i.xlarge-class, performance governor), measured in both directions. Targets: **≥ 1 Gbps single flow** and **≥ 1 Gbps aggregate across 8 concurrent peer tunnels** (full-mesh realism). Kernel-WG mode measured on the same harness with the delta published. **Carried Phase 0 gate:** the in-container ~7.7 Mbit/s receive-side cap must be shown to be environmental on the first cloud run (`iperf3 -u -b 0` loss check per the Phase 0 report) — if the cap reproduces on cloud, Bet 1 reopens before any Cycle 4 gateway work. |
| G-3 | **Full-mesh tunnel establishment** to all peer gateways, with per-pair automatic relay fallback. | With UDP blocked between two gateways, the pair converges to relay transport within 30s without operator action, and reverts to direct when possible. |
| G-4 | **L4 ACL enforcement via eBPF (primary) with nftables fallback.** Both backends compile from the same policy IR and must be behaviorally identical (conformance suite). Default-deny between segments; rules support src/dst CIDR, port ranges, protocol (TCP/UDP/ICMP). Fallback engages automatically where BPF privileges are withheld (e.g., restricted LXC). **See the G-4a client carve-out below — default-deny does *not* currently hold for traffic destined to a client peer.** | Traffic matching no allow rule is dropped and counted — **for segment destinations**. Rule updates are applied atomically on both backends (no enforcement gap, no transient allow-all/deny-all). Conformance suite proves eBPF/nftables parity for every rule construct. |
| G-4a | **Client carve-out (added 2026-08-05 with the Non-Goals item 1 amendment).** Enforcement is *ingress-on-tun only*, so a **client peer** (Non-Goals item 1) is policed in the direction it initiates and **not** in the direction it receives: `client → segment` is matched at the receiving gateway; `segment → client` is matched by nothing, because the sending gateway's tun egress never drops and the client runs no enforcer. This is a **known, accepted exception to G-4's default-deny guarantee**, scoped to client destinations only — segment-to-segment default-deny is unaffected, as is backend parity, since neither backend enforces this direction. | The exception is documented wherever clients are, and the client's own host firewall is named as the operator's responsibility. **Egress-side enforcement on gateways for client-destined traffic is required before a client may be called production-grade**; until it ships, no doc, release note, or UI may imply a client is protected inbound. Closing this restores plain G-4 and must keep eBPF/nftables parity. |
| G-5 | **Transparent to workloads.** No agent on machines behind the gateway; only a route toward the gateway is needed. | Demo: an EC2 instance reaches a Proxmox VM's Postgres with only a VPC route-table entry added, per the allow rule. |
| G-6 | **Fail-static on controller loss.** Tunnels, routes, and the last-applied policy persist while the controller is unreachable. | Kill the controller for 1 hour: existing allowed flows continue; denied flows stay denied; gateways resync on controller return. |
| G-7 | **Graceful drain/decommission.** | `fabricctl gateway drain <name>` withdraws routes from peers before teardown; peers stop routing to it within 5s. |
| G-8 | **MTU & PMTUD correctness.** Fabric-wide tun MTU **1280** (relayed-path worst case; per-peer raise to 1420 on verified direct paths is P1). TCP **MSS clamping** on the tun device for workloads that ignore route MTU. **ICMP error packets (unreachable, fragmentation-needed, TTL-exceeded) are matched against the embedded flow's forward or reverse entry and forwarded when that flow is allowed** — default-deny must never black-hole PMTUD. Behavior identical on both enforcement backends. | Conformance suite includes ICMP-error cases (both backends). Integration test: bulk transfer with DF set over a *relayed* path completes without hangs; transport switch direct↔relay under load loses only in-flight packets. Every platform quickstart documents the MTU story. |

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
| X-6 | **Version skew & zero-drama upgrades.** Controller vN supports gateways/relays vN and vN-1 (one-minor skew window); Sync advertises the minimum supported component version and `fabricctl gateway list` flags out-of-window components loudly. Gateway upgrade preserves tunnels (make-before-break, same bar as C-5). **The policy IR schema is part of the skew contract:** the Sync handshake advertises each gateway's maximum supported IR schema; the controller serves IR at a schema every enrolled gateway supports, and refuses (with a loud `fabricctl` error naming the lagging gateways) any operation that would require a schema an in-window gateway cannot consume — a supported skew must never leave a gateway unable to apply policy. | Skew matrix tested in CI (vN controller ↔ vN-1 gateway). Upgrading a gateway under an active iperf flow shows < 1s packet loss. Skew CI includes an IR-schema case: a vN controller with one vN-1 gateway enrolled keeps serving schema-compatible IR and flags the constraint in `fabricctl gateway list`. "Fabric upgrade" runbook is part of the docs from the first tagged release. |
| X-7 | **Release integrity.** Every release artifact (binaries, OCI images) ships SHA-256 checksums and signatures (cosign/minisign); the one-line install script verifies the checksum before executing anything. Build provenance (SLSA-style attestation) is P1. | `curl \| sh` refuses to proceed on checksum mismatch; signature verification is documented in one command per artifact type; CI produces and publishes signatures automatically. |

### 7.2 Nice-to-Have (P1)

- **Managed-platform first-class integration** — attach a managed cluster's network to a tenant fabric from the platform portal/API; gateway lifecycle managed by the platform. Positioned as a *reference downstream integration* — the fabric is an independent OSS project first, and any managed platform is merely one consumer of it.
- **Helm chart + deb/rpm packages** — richer packaging on top of the P0 binary/OCI/install-script distribution.
- **Web UI (read-mostly)** — topology graph, tunnel health, policy viewer. CLI/API remain the write path initially.
- **Policy dry-run / plan** — `fabricctl policy plan` shows which existing flows a proposed change would break (based on recent flow counters).
- **Flow logging** — sampled allowed-flow logs (not just denies) for audit, with rate limits to protect the gateway.
- **Controller HA** — active/standby with shared or replicated state. (v1 ships single-node + fail-static gateways + documented backup/restore, which makes controller downtime tolerable.)
- **Terraform provider** for segments, gateways, and policies.
- **kernel WireGuard auto-detection** — prefer kernel module when present, boringtun otherwise.
- **DERP-style relay mesh awareness** — latency-based relay selection when multiple relays exist.

### 7.3 Future Considerations (P2)

- **XDP fast path** for high-throughput gateways, building on the P0 tc-BPF enforcement. *(The compiler-agnostic policy IR (G-4) already keeps this open.)*
- **User/device access layer** — optional client for user-to-segment access, converging on the full Twingate use case.
- **IPv6 segments** and dual-stack tunnels. *(The address-family-agnostic registry/IR/wire-protocol constraint in §8 is what keeps this additive.)*
- **1:1 NAT for overlapping CIDRs** (brownfield escape hatch).
- **Maintainer-operated hosted controller** — a paid convenience offering, run as a downstream consumer per the §2 project model: **single-tenant** (one controller instance per customer, sidestepping multi-tenancy in the data model entirely), same public binaries, data plane always customer-owned. Zero code divergence from self-hosted is a hard constraint.
- **BGP integration** — advertise fabric routes to on-prem routers instead of static routes.
- **Policy identity extensions** — tags/labels on segments so rules can reference `env=prod` instead of raw CIDRs.

## 8. Networking & Policy Model (normative summary)

- **L3 subnet routing**, segment-level. One gateway owns one or more CIDRs.
- **Data plane:** WireGuard (boringtun). **Control plane:** mTLS gRPC. **Fallback:** QUIC relay, per gateway pair.
- **Enforcement:** eBPF (tc-BPF) primary, nftables fallback; single policy IR, provably identical behavior.
- **Topology:** full mesh of direct tunnels; relay only where direct fails.
- **Scale envelope (v1):** designed and soak-tested for up to **50 segments** (≈1,225 tunnel pairs, 49 peers per gateway). Larger fabrics are out of scope for v1 — full mesh is the only topology, and O(n²) pair growth is the deliberate trade for its simplicity.
- **Address family:** IPv4-only in v1. **Design constraint now:** the CIDR registry, policy IR, and wire protocol are address-family-agnostic so IPv6/dual-stack (P2) is additive, not a rework.
- **No overlapping CIDRs**, enforced at onboarding (C-2).
- **Policy evaluation (normative, per the engineering design):** default deny — a flow matching no rule, or with no block for its (src segment, dst segment) pair, is dropped. Blocks are **directional** (`from: A, to: B` governs A→B initiation only; replies are stateful via the flow table). **First match wins** within a block, rules in written order — deny carve-outs go above the allows they carve. At most one block per ordered segment pair (compile error otherwise), so cross-block ordering cannot arise. `src`/`dst` CIDRs must be subsets of their segments' registered CIDRs (compile error otherwise).

Example (matches the engineering design’s DSL):

```yaml
policy:
  - from: proxmox-lab        # 10.10.0.0/16
    to: aws-prod             # 172.16.0.0/12
    rules:
      - deny:  { ports: [22], proto: tcp }                          # carve-out — first match wins
      - allow: { dst: 172.16.1.50/32, ports: [5432], proto: tcp }   # Postgres
      - allow: { dst: 172.16.2.0/24, ports: [443], proto: tcp }
```

## 9. Success Metrics

**Leading (first 60 days post-v1):**
- Time-to-connected in guided user tests: **≤ 30 min** median (stretch: 15).
- Policy propagation latency: **< 5s p99**, measured continuously in CI/soak environment.
- Tunnel establishment success rate across NAT matrix test (full cone / symmetric / CGNAT): **100% with relay available**.
- GitHub traction as an OSS proxy: **500 stars / 20 external issues** in 60 days (signal, not vanity — issues indicate real deployment attempts).

**Lagging (2 quarters):**
- **≥ 25 entries in `ADOPTERS.md`** (plus a pinned "who is running WireMesh" discussion) — the concrete mechanism, since telemetry is opt-in only and cannot be the counting method.
- **≥ 3 managed-platform tenants** using the fabric integration once P1 ships.
- Soak stability: a 3-segment reference fabric runs **30 days** with zero unplanned data-plane interruptions.
- **External security review of the enforcement and key-handling paths completed before 1.0** — commissioned via an OSS audit program (OSTIF / Sovereign Tech Fund application as soon as Cycle 3 lands, since queues are long); metric: review report published, all critical/high findings fixed before the 1.0 tag.

## 10. Security & Threat Model (must be published with v1)

Minimum coverage:
- **Compromised relay** — must yield ciphertext only; no key material, no metadata beyond src/dst gateway endpoints and volume.
- **Compromised controller** — can rewrite topology/policy (accepted risk of centralized control plane); cannot silently read data-plane traffic. Mitigations: audit log (C-8), gateway-side logging of applied policy versions, future policy signing (P2 candidate).
- **Compromised gateway** — blast radius is its own segment plus flows allowed to/from it. Keys are one static keypair **per gateway per epoch** (not per-pair); Noise IK's ephemeral DH already prevents a compromised gateway from decrypting other pairs' traffic, so lateral decryption is not possible.
- **Enrollment token theft** — tokens are single-use and expiring; enrollment binds to expected CIDR.
- **Fabric CA key loss or compromise** — covered by C-10: loss is a restore-from-backup event (no re-enrollment); compromise is a new CA + fleet re-enrollment via rebind tokens, with the runbook exercised as an integration test.
- **Fail posture** — explicitly fail-static (G-6); document why not fail-closed (a controller outage must not become a network outage).

## 11. Open Questions

| # | Question | Owner | Blocking? |
|---|---|---|---|
| 1 | ~~Policy schema~~ — **Resolved: custom YAML DSL** (segment-to-segment, first-match-wins, directional blocks), compiled to a backend-agnostic IR. K8s NetworkPolicy semantics rejected: pod/identity model doesn't map to segment routing. See §8 and the engineering design §5. | Eng (Peter) | Resolved |
| 2 | ~~Controller store~~ — **Resolved: embedded SQLite** (Cycle 2). HA path (P1) will build on snapshot/replication of the SQLite store. | Eng | Resolved |
| 3 | Key rotation cadence and trigger model: time-based, on-demand only, or both? | Eng/Security | No |
| 4 | ~~Route injection~~ — **Resolved: manual documented routes + published Terraform modules per cloud. No cloud credentials on gateways, ever** — a deliberate trust boundary, not a limitation: target users already drive route tables via IaC, and creds on the data plane would explode the threat model. Cloud-API automation revisited only as a separately-credentialed helper (P2 at best). | Eng | Resolved |
| 5 | ~~Multiple CIDRs~~ — **Resolved: multiple CIDRs per segment in v1** — already implemented in the Cycle 2 data model (`cidr` 1:N `segment`; `repeated string cidrs` on the wire). | Eng | Resolved |
| 6 | ~~Conntrack strategy~~ — **Resolved: stateful with implicit return traffic.** eBPF: BPF LRU flow table keyed on the 5-tuple, new-flow = direction of first packet, ICMP errors matched via the embedded flow (G-8); nftables: kernel conntrack (`established,related`). Conformance suite proves the two identical. | Eng | Resolved |
| 7 | ~~Project name + license~~ — **Resolved: WireMesh, Apache-2.0.** Fully open source under the §2 three-commitment model; a future maintainer-operated hosted controller (P2) runs the same Apache-2.0 binaries, so there is no AGPL pressure and no relicensing path. | Peter | Resolved |
| 8 | Relay abuse prevention for public relays — auth tokens per fabric? Rate limits? | Eng/Security | No (relays are self-hosted in v1) |
| 9 | ~~Kubernetes gateway mode~~ — **Resolved: node-network only in v1.** Single-replica hostNetwork Deployment advertising the node subnet; pods/services reached via NodePort/LoadBalancer like any external client. No CNI interaction, no pod/service CIDR advertisement in v1. | Eng (Peter) | Resolved |

## 12. Phasing & Timeline Considerations

No hard external deadlines. Suggested phases, each independently shippable:

- **Phase 0 — Spike (2–3 weeks):** boringtun tunnel between two gateways with static config; tc-BPF ACL on the tunnel device; QUIC relay prototype; NAT-traversal harness. De-risks the riskiest technical bets before any controller work. *(Complete — see `docs/research/phase0-report.md`.)*
- **Phase 1 — MVP (P0 core):** controller with enrollment, CIDR registry, route/policy distribution; 2–3 segment mesh; relay fallback; CLI; AWS + Proxmox + generic Linux quickstarts. *Exit criterion: the 30-minute tutorial passes with an external tester.*
- **Phase 2 — Hardening:** key rotation, drain/decommission, full observability, audit log, GCP/Azure docs, threat model publication, soak testing.
- **Phase 3 — P1 wave:** managed-platform integration, policy plan/dry-run, web UI (read-only), Terraform provider, controller HA.
- **Phase 4 — P2 exploration:** XDP fast path, user-access layer.

**Dependency callouts:** managed-platform integration (Phase 3) depends on the target platform's tenant/network APIs being stable; both enforcement backends (eBPF primary, nftables fallback) depend on the policy IR decision (Open Question #1) being made before Cycle 3.

## 13. Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| NAT traversal edge cases (symmetric NAT, CGNAT) burn disproportionate effort | High | Medium | Relay-first mentality: relay is the guaranteed path, direct is the optimization. Ship with an honest NAT compatibility matrix. |
| boringtun throughput insufficient for real workloads | Medium | High | Benchmark in Phase 0; kernel-WG mode as escape hatch (P1). |
| Atomic policy swap harder than expected under churn (eBPF map replacement / nftables ruleset replacement) | Medium | Medium | eBPF: versioned map-in-map swap; nftables: native atomic ruleset replacement. Single IR + conformance suite keeps both honest. |
| Scope gravity toward device-level access ("just add a client") | High | High | Non-goal #1 is explicit; revisit only as P2 after segment routing is proven. |
| Single-node controller perceived as SPOF and blocks adoption | Medium | Medium | Fail-static gateways + loud documentation of the outage story; HA in P1. |

---

*Next artifacts to derive from this PRD: engineering design doc for the controller data model and policy IR (Open Questions 1, 2, 5, 6), and a Phase 0 spike plan.*
