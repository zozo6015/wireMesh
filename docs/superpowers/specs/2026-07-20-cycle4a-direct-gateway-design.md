# WireMesh — Cycle 4a Design: Direct-only Gateway

> **Cycle 4 of 4** (per the master engineering design §12), sliced into three
> sub-cycles. This document covers **4a** only. Authority: the master spec
> (`docs/superpowers/specs/2026-07-15-wiremesh-engineering-design.md`, esp. §6
> gateway, §6.2 fail-static, §6.3 platform, §9 testing) governs where this
> conflicts; it elaborates §6 into an implementable design rather than restating
> it. Cycle 3 (policy pipeline) is merged (PR #6).

## 1. Cycle 4 decomposition

The master spec's Cycle 4 ("gateway transport + relay, NAT matrix") is too large
for one spec/plan. It splits into three sub-cycles, each its own spec → plan →
implementation cycle:

- **4a — Direct-only gateway (this document).** The real `wiremesh-gateway`
  binary: Sync client, enforcer wiring, fail-static state store, embedded
  boringtun tunnel manager with direct WireGuard peering, UDP endpoint
  observation, tun MTU 1280 + MSS clamp. Milestone: two gateways on routable
  addresses form an encrypted, policy-enforced mesh that survives a controller
  outage.
- **4b — NAT traversal.** Controller-brokered simultaneous hole punching, the
  `Connecting → Direct / Relayed / Degraded` path state machine, and the
  same-socket observation precision needed for symmetric NAT (see §7-B).
- **4c — Relay.** The `wiremesh-relay` binary (stateless QUIC-datagram bridge),
  the gateway's relay transport, relay advertisement (the controller currently
  always sends `relays: []`), and make-before-break failover.

**Deferred out of 4a into a fast-follow:** per-gateway per-epoch **key rotation**
(master §4.4 — make-before-break, two `Device` instances). 4a ships static
single-epoch per-gateway keys; rotation lands once the direct mesh is proven.

**Deferred out of 4a into a dedicated enforcer-hardening pass:** the two Cycle-4
carries recorded from the CodeRabbit review of PR #6
(`docs/research/cycle3-policy-notes.md`) — IPv4 fragment handling in the tc-BPF
path on both backends, and the conformance harness-error vs policy-drop
distinction — because they touch `wiremesh-enforcer` /
`wiremesh-enforcer-ebpf` / `wiremesh-testkit`, not the gateway crate.

## 2. Scope & done bar

**In scope (4a):** a new `crates/wiremesh-gateway` workspace member producing the
`wiremesh-gateway` static binary (master G-1), consuming the existing
`wiremesh-enforcer` library and the existing `Sync` stream. Its components:

1. **Sync client** — mTLS `Watch` stream to the controller; applies the initial
   `StateSnapshot` then `Delta`s; `Report`s the applied policy version;
   reconnects and re-snapshots on stream close / broadcast-lag.
2. **Reconciler + desired-state store** — holds desired state; on each
   snapshot/delta drives the tunnel manager, enforcer, and routes, then
   atomically persists.
3. **Tunnel manager** — embedded boringtun `DeviceHandle`; direct WireGuard
   peering configured through an **in-process UAPI writer**; tun MTU 1280 + TCP
   MSS clamp.
4. **Enforcer wiring** — `probe()` the backend on the tun iface; feed
   `PolicyIR::from_json(StateSnapshot.policy_ir)` to `Enforcer::apply`; read
   `counters()` / `deny_events()`.
5. **Endpoint observation** — periodic UDP probe to the controller's observation
   endpoint; the observed mapping surfaces to peers as `candidate_endpoints`.
6. **Fail-static state store** — persist-then-serve, last-state-wins.
7. **Routes** — install peer-segment-CIDR routes via the tun device; enable IP
   forwarding.
8. **Metrics/logs** — Prometheus endpoint + structured JSON logs.
9. **Throughput bench** — reusable iperf3-over-tunnel harness (measured number
   deferred, see §6).

**No proto changes.** `Peer.candidate_endpoints`, `StateSnapshot.policy_ir`, and
`Sync.Report` already exist. `relays` stays empty in 4a.

**Done bar — a controller-independent, policy-enforced direct mesh.** Two real
`wiremesh-gateway` processes on routable addresses, each fronting a workload
netns, enroll (pre-provisioned identity, §7-A), connect to an in-process
controller, and form a direct WireGuard tunnel. A netns conformance suite
(`wiremesh-testkit`, `--features netns`) proves: (1) a policy-**allowed**
workload↔workload flow passes over the encrypted tunnel; (2) a **denied** flow
is dropped and the deny counter increments; (3) **fail-static** — killing the
controller does not drop an established flow, and restarting a gateway reloads
`state.json` and rebuilds the mesh *without* the controller present; (4) a
**policy update** pushed by the controller changes enforcement. The throughput
bench exists and is documented; the ≥1 Gbps/4-vCPU number (master G-2) is a
tracked follow-up, not a 4a blocker.

## 3. Crate layout

```
crates/wiremesh-gateway/
  Cargo.toml            # workspace member; static-binary profile
  src/
    main.rs             # CLI/config parse, boot sequence, task supervision
    config.rs           # local config: controller addrs, tun/WG params, state dir
    identity.rs         # load client cert + key + CA bundle (0600) from state dir
    state.rs            # desired-state model + atomic fail-static persistence
    sync.rs             # Sync client: Watch stream + Report, reconnect/backoff
    reconcile.rs        # apply snapshot/delta -> tunnel + enforcer + routes + persist
    tunnel.rs           # boringtun DeviceHandle lifecycle, MTU, MSS clamp
    uapi.rs             # in-process WireGuard UAPI client (set key / replace_peers)
    enforce.rs          # enforcer probe + apply + counters/deny drain
    observe.rs          # UDP observation client (graduated from spike/punch)
    routes.rs           # rtnetlink: peer-CIDR routes via tun + ip_forward
    metrics.rs          # Prometheus endpoint + structured JSON logs
  tests/                # unit tests (UAPI encoding, state round-trip, reconcile diff)
```

Cargo deps: `wiremesh-proto`, `wiremesh-enforcer`, `wiremesh-policy`,
`wiremesh-trust`; `boringtun 0.6` (`device`); `tokio`, `tonic` + `rustls`
(workspace-pinned) for the mTLS Sync client; `sha2` for the observe-probe MAC;
`prost` types via `wiremesh-proto`.

**Route/link programming shells out to `ip`, and MSS clamping to `nft`**, via
`std::process::Command` — the repo's established pattern (the whole netns
harness and the nftables enforcer backend already drive `ip`/`nft`/`wg`/`sysctl`
this way; there is no netlink crate anywhere in the tree). This adds `iproute2`
and `nftables` as documented gateway runtime dependencies, alongside the
existing `conntrack-tools` requirement of the nftables enforcer backend. (The
in-process UAPI writer still stands: it avoids a `wireguard-tools` runtime
dependency, which — unlike near-universal `iproute2` — is a separate package and
is exactly what embedding boringtun exists to eliminate. Swapping route
programming to an in-process netlink crate is a later option if the `iproute2`
dependency ever becomes unacceptable.)

**Observe-probe codec.** The authenticated probe format (`MAGIC` `AOBS`, 44-byte
layout, `sha256(observe_key || MAGIC || gateway_id_be)` MAC) already exists as
`pub` `build_probe`/`compute_mac` in `wiremesh_controller::observe`, but the
gateway must not depend on the controller crate (wrong dependency direction +
binary bloat). The gateway **replicates** this ~15-line builder in its own
`observe.rs` (the controller module's own doc states 4b replaces the whole
scheme, so a shared crate for a doomed codec is premature). Correctness is
guaranteed by a cross-process **parity integration test**: the real in-process
controller must accept the gateway's probe and record the candidate endpoint. A
byte-vector unit test additionally pins the format.

Integration (netns) tests live in `wiremesh-testkit` behind `--features netns`,
building on the existing `Lab` / `Ns` / `wg_lab` harness; they run the real
gateway binary and the in-process `TestController`.

## 4. Interfaces this cycle builds against (existing, unchanged)

- **Sync proto** (`proto/wiremesh/v1/sync.proto`): `Watch(WatchRequest) ->
  stream SyncMessage`; `SyncMessage{ StateSnapshot | Delta }`;
  `StateSnapshot{ revision, self_cert_pem, peers, relays, policy_ir,
  policy_version, revoked_serials }`; `Peer{ gateway_id, segment_name, keys,
  candidate_endpoints, allowed_ips }`; `PeerKey{ epoch, pubkey, state }`;
  `Report(ReportRequest{ applied_version })`.
- **Enforcer** (`wiremesh-enforcer`): `probe(iface, EnforcerConfig) ->
  Box<dyn Enforcer>` (eBPF, nftables fallback); `Enforcer::{apply(&PolicyIR),
  counters()->Counters, flush_flows(), deny_events()->Vec<DenyEvent>}`.
- **Policy IR** (`wiremesh-policy`): `PolicyIR::from_json(bytes)` deserializes
  `StateSnapshot.policy_ir` verbatim; fed to `Enforcer::apply`.
- **Observation endpoint** (`crates/wiremesh-controller/src/observe.rs`): already
  writes `candidate_endpoint` per gateway via `Db::set_candidate_endpoint`;
  surfaces to peers as `Peer.candidate_endpoints`. 4a's observation client is the
  real counterpart to `spike/punch`'s `observe()`.

## 5. Behavior

### 5.1 Boot sequence (fail-static, G-6)

1. Parse config; load identity (client cert + key + CA bundle, 0600) from the
   state dir.
2. **If `state.json` exists**, reconstruct desired state and bring the data
   plane up from it *immediately, before contacting the controller*: create the
   boringtun device, set MTU 1280, set the private key, `probe()` the enforcer
   and `apply` the persisted IR, install peer routes and enable ip_forward.
3. Start the Sync `Watch` stream. The first message is always a full
   `StateSnapshot`; it reconciles over the persisted state (last-state-wins) and
   is persisted.
4. Start the observation loop and the metrics endpoint; `Report` the applied
   policy version.

On a **controller outage** the gateway keeps enforcing its last-known state
indefinitely (fail-static, not fail-closed). On **first boot with no state**,
the data plane waits for the first snapshot.

### 5.2 Reconcile

`StateSnapshot` replaces the whole desired state; `Delta` upserts/removes peers
and updates policy/relays/revocations. After every apply the reconciler:

1. **Tunnel:** builds the full WireGuard peer list and writes it via the UAPI
   client with `replace_peers=true` in a single config message (atomic, exactly
   as `wg syncconf` does). Each peer entry: `public_key` (the `active`-state
   `PeerKey`), `endpoint` (the single `candidate_endpoint`, if present),
   `allowed_ips` (peer segment CIDRs), `persistent_keepalive=15`.
2. **Enforcer:** only when `policy_version` changed, deserialize `policy_ir` and
   `apply`. (Verbatim bytes; no recompile — no drift.)
3. **Routes:** reconcile peer-CIDR routes via the tun device (`ip route
   add/del <cidr> dev <tun>`, shelled out).
4. **Persist:** atomically rewrite `state.json` (temp file + `rename`, mode
   0600).

### 5.3 State store (§6.2)

`state.json` (0600, temp+rename) holds: peer set + public keys/epochs +
endpoints, routes, relay list (empty in 4a), compiled policy IR + version, CA
trust bundle, own client cert. WireGuard private keys live in **separate 0600
files**, never in `state.json`. The store is the single source the boot sequence
replays.

### 5.4 Observation (4a form)

boringtun owns the WireGuard UDP socket, so 4a's observation probe is sent from a
**separate** socket bound to the WG listen port (`SO_REUSEPORT`). Under 4a's
direct-only, routable / full-cone assumption the observed mapping equals the
WireGuard socket's mapping, so this is correct for 4a. The same-socket precision
required for symmetric NAT rides with 4b (see §7-B).

### 5.5 MTU (§6.1)

The tun device is created with MTU 1280 (`ip link set <tun> mtu 1280`) and the
gateway installs an `nft` MSS-clamp rule so forwarded TCP SYNs advertise
MSS 1240 (1280 − 20 IPv4 − 20 TCP), per master §6.1 / PRD G-8 — transit MSS
clamping requires rewriting in-transit SYN options, which a route `advmss`
attribute does not do for forwarded traffic. Per-peer MTU raising (1420 direct)
stays a P1 item.

## 6. Throughput bench (G-2)

4a ships a reusable bench: iperf3 across two real gateways over the tunnel, with a
documented procedure for a 4-vCPU cloud VM. 4a's done bar does **not** block on
the measured number; the cloud run and the recorded result in
`docs/research/phase0-results.md` are a tracked follow-up. Correctness is
netns-provable in CI; the perf gate is separate.

## 7. Scope boundaries (explicit)

**A — Gateway identity.** 4a assumes a **pre-provisioned** identity bundle in the
state dir (produced by the existing Cycle-2 enrollment flow / `fabricctl` /
testkit `StubGateway::enroll`): client cert + key, CA bundle, the gateway's own
`gateway_id`, and its `observe_key` (both returned by enrollment — the
`observe_key` authenticates the observation probe, §5.4). Wiring
enrollment-token bootstrap *into the gateway process* is a small follow-up, not
4a.

**B — Observation socket precision.** As §5.4: 4a observes from a `SO_REUSEPORT`
sidecar socket, correct under routable / full-cone. Probing from the exact
WireGuard socket (symmetric-NAT correctness) is a **4b** carry, documented as a
stated 4a limitation.

## 8. Testing (§9, and CLAUDE.md agent rules)

Netns conformance suite in `wiremesh-testkit` (`--features netns`), serial
(`--test-threads=1`): two gateway netns + in-process controller + one workload
netns behind each gateway, over the graduated natlab / `wg_lab` harness. Cases:
allowed flow passes, denied flow dropped (+ counter), fail-static (controller
kill survives established flow; gateway restart rebuilds from `state.json`
without controller), policy-update propagation. Unit tests: UAPI encoding,
`state.json` round-trip, reconcile diff (peer add/remove/endpoint-change).

Per CLAUDE.md: **tests are authored, implemented, and executed by three
different agents** — the test author, the implementer, and an independent runner
that relays raw output; reviews are done by a separate reviewer agent. All code
and tests run inside the privileged Linux container via `./dev.sh`.

## 9. Non-goals (4a)

Key rotation; NAT hole punching + path state machine (4b); relay + relay
advertisement + failover (4c); enrollment-on-boot; the fragment/conformance
enforcer carries; per-peer MTU raising; the measured G-2 number; IPv6.
