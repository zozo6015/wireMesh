# Scoping a client/agent component

**Written:** 2026-08-05, after a read-only verification pass against `main` (68babec).
**Status:** a plan, not an approved design. Contains owner decisions that are not mine.

Companion to [`macos-exclusion-premise-and-the-client-gap.md`](macos-exclusion-premise-and-the-client-gap.md),
which records *why* this is being scoped. This note is *what it would take*.

## The requirement

A single host — a Mac laptop, a k8s node — joins the fabric **for itself only**, reaches
the fabric's segments, needs no routing configuration on any LAN, and is toggled on and off
like any VPN client. It does not front a network and does not forward.

## This reopens a ratified non-goal

`docs/PRD.md` **Non-Goals item 1**: *"Device/user-level access (v1) — no per-laptop, per-user client. This is
segment-to-segment routing… conflating the two would bloat v1."*

That exclusion has a technical shadow, and findings 1–3 below **are** that shadow. Whatever
is decided, it should be an explicit amendment in the engineering design's §11 rather than
arriving by accretion.

## What already works, verified

The pleasant surprise: most of the control plane is peer-agnostic.

- **The policy pipeline does not know peers exist.** The IR carries segment *names* and
  CIDRs (`wiremesh-policy/src/ir.rs:26-47`); the datapath keys on **IPv4 source/dest plus
  proto/dport only** — `SRC_LPM[src/32] & DST_LPM[dst/32]`, first-match
  (`wiremesh-enforcer-ebpf/program/src/main.rs:586-590`). **There is no peer identity
  anywhere in the datapath.** A client is just another named CIDR set.
- **WireGuard cryptokey routing makes the IP trustworthy.** The peer entry the gateway
  builds (`reconcile.rs:141`) binds the client's key to its declared CIDR on receive, so
  another peer cannot spoof the address the LPM keys on.
- **A peer need never connect.** `list_other_gateways` filters on `status='active'` only
  (`db.rs:1662-1681`); liveness is irrelevant. Enrollment stores the real WG pubkey as an
  epoch-0 `active` key (`db.rs:1506-1514`), so peers get a usable key immediately, and
  `endpoint` is `Option` (`reconcile.rs:126-144`).
- **Enrollment is already reusable.** `wiremesh_enroll::enroll()`
  (`wiremesh-enroll/src/lib.rs:188`) is binary-agnostic — keypair, CSR, dial, redeem.
- **Revocation works.** `fabricctl gateway drain --id N` removes the row and pushes
  `removed_peer_ids` to every gateway (`projection.rs:118`, `:312`).

## The three findings that shape the plan

### 1. The client is the one peer nothing protects — OWNER DECISION

Enforcement is **ingress-on-tun only**. `aeth_egress` unconditionally returns
`TC_ACT_PIPE` (`main.rs:418-420`); nft hooks only `iifname "<iface>"`
(`nft.rs:103,107`).

| direction | policed by | verdict |
|---|---|---|
| `client → segment` | receiving gateway's tun ingress | correctly policed, no new mechanism |
| `segment → client` | **nothing** | wide open on every port |

Every existing peer is protected because every existing peer runs an enforcer on its own
tun. A client would be the first peer in the fabric that nothing protects — and the
gateway installs a route to its `/32` automatically via `route_diff`
(`reconcile.rs:195-206`), so any host in any segment can reach it.

Three ways out, none free:

- **(a) Accept it, document it, require a host firewall.** Zero code. The laptop's own
  firewall is outside the fabric's control, which is a real weakening of the default-deny
  promise. Honest if stated; corrosive if silent.
- **(b) Egress-side enforcement on gateways for client-destined traffic.** Closes it
  properly, but it is a datapath change across **both** backends and re-opens the 22/22
  conformance suite. Substantial.
- **(c) An enforcer on the client.** Impossible on macOS as designed — that is the `pf`
  backend the gateway exclusion exists to avoid.

**Recommendation: (a) for a first phase, explicitly and in writing, with (b) scoped as the
condition for calling the client production-grade.** Do not let this be decided by
omission.

### 2. One client = one segment, forever — and it stops scaling at about a dozen

Three independent mechanisms combine:

- `insert_cidrs_tx` rejects any CIDR that contains or is contained by another segment's
  (`db.rs:301-318`). A Mac at `10.0.0.50/32` inside `aether 10.0.0.0/24` is **rejected**.
  Clients need their own non-overlapping space (e.g. `100.64.0.0/10`).
- One active gateway per segment (`db.rs:1466-1474`), so a client cannot join an existing
  segment as a second occupant.
- `allowed_ips` is a pure function of the segment (`routes.rs:47`, `projection.rs:441`) —
  **there is no per-peer address column.** Two peers in one segment would advertise
  identical `allowed_ips`, a cryptokey-routing collision on every gateway.

So each client is a segment. Twenty laptops is twenty segments and twenty extra WireGuard
peers on every gateway. The binding constraint is `MAX_RULES = 256` (`flatten.rs:50`),
checked **after port explosion** (`flatten.rs:147`), and the arithmetic is:

> `flat_rules ≈ clients × segments_reached × Σ over the block's rules of max(ports.len(), 1)`

Only the `client → segment` direction is worth writing (see finding 1 — a reverse block is
never enforced), so it is one block per pair, not two. A minimal block of three portless
rules (tcp / udp / icmp) flattens to 3. Twenty clients each reaching four segments is then
`20 × 4 × 3 = 240` — already at the ceiling before a single rule names a port list, and
each named port is its own flat rule.

Ten clients reaching four segments with modest port lists lands in the same place. **A
dozen is the honest number**, and it is the count of `client × segment` *reachability
pairs* that matters, not the client count alone — one client permitted everywhere costs as
much as several tightly scoped ones.

**The "client is just another gateway" model does not survive past roughly a dozen
clients.** Fine for the actual requirement (one Mac). Not a foundation.

Beyond that: full mesh is unconditional (`routes.rs:42`), and the broker's periodic sweep
is O(connected²) with a DB round-trip per pair (`broker.rs:606-624`). `routes.rs:6-9` says
outright that pruning the mesh by policy is future work. A client should almost certainly
be **hub-and-spoke** — peered with gateways only — which is a projection change.

### 3. Clients inherit the gateway's unfinished business by default

Enrolling as a `gateway` row opts a client in, automatically, to:

- **Key rotation.** `initiate_due_rotations` reads `active_gateway_ids()` —
  `WHERE status='active'`, **no exclusion mechanism of any kind** (`db.rs:1786-1793`). A
  client that connects gets a real `RotateDirective` and inherits both structural rotation
  bugs the moment rotation is re-enabled. A client that never connects burns an
  abort cycle per interval (`rotation::decide` rule 2, `ABORT_AFTER = 300s`).
- **The punch broker.** `peer_ids_of` filters only on differing segment
  (`broker.rs:630-641`); `on_gateway_connected` punches every cross-segment peer.
- **`ReportRequest`'s destruction-by-omission semantics** (`sync.proto:126-162`), which
  have already produced two live bugs at one call site. A naive client Report zeroes its
  own `applied_version` and wipes its candidates.

A `gateway.role` column plus a filter is small. **Skipping it is not optional** if rotation
is ever re-enabled.

## Phase 1 — static client, no daemon (small, days)

Delivers the actual requirement with **no proto break, no schema change, no gateway change,
and no new daemon.**

1. **`GatewayInfo.wg_pubkey` + `.endpoint`** — additive Admin proto fields
   (`admin.proto:66`). Both values are already in the DB and already read by
   `candidates_for` / `all_keys_for_gateway`; they are simply not exposed through Admin
   today, which is the *only* real gap in this phase.
2. **`fabricctl client provision --name X --address 100.64.0.7/32`** — creates the `/32`
   segment, mints a gateway-kind token, prints a ready wg-quick config.
3. **A ~50-line client binary** — generate a WG keypair, call `wiremesh_enroll::enroll()`
   with `cidrs=["100.64.0.7/32"]` and `endpoint=""`, discard the cert, emit the config.
4. **Policy blocks for `X → <segments>` only — one direction.** A reverse
   `<segment> → X` block compiles and distributes fine but **is never enforced** (finding
   1), so writing one would imply a protection that does not exist. Replies to
   client-initiated flows pass regardless, because tun egress never drops.

On macOS this drives the **official WireGuard app**, which already provides the menu-bar
toggle. No custom UI, no Network Extension entitlement, no notarization.

### What Phase 1 clients inherit, whether wanted or not

Phase 1 mints a **gateway-kind** token, so the client is a `gateway` row — and there is no
`role` column yet to distinguish it. It is therefore swept into everything a gateway is
swept into:

- **Key rotation.** `initiate_due_rotations` reads `active_gateway_ids()` with no exclusion
  of any kind (`db.rs:1786-1793`). This is **latent, not live**, only because rotation is
  currently disabled fabric-wide (`WIREMESH_ROTATION_INTERVAL=off`). **Re-enabling rotation
  before the `role` column lands would break every Phase 1 client** — a static peer cannot
  follow a rotation, and one that never connects burns an abort cycle per interval.
  Phase 2's rotation exclusion is therefore a hard prerequisite for re-enabling rotation,
  not an optional tidy-up.
- **The punch broker**, which filters only on differing segment (`broker.rs:630-641`).
  Harmless for a laptop dialling a gateway with a routable endpoint, but it is mesh traffic
  nobody asked for.

**Also not included:** no revocation propagation to the client; no relay fallback, so it
must reach a gateway with a routable endpoint; permanent `applied_version = 0` in the
roster, which the pending roster-lag alerting would fire on forever; and no automatic
learning of newly enrolled gateways.

## Phase 2 — a real client peer (medium)

Only if Phase 1 proves it gets used.

| change | where | size |
|---|---|---|
| `gateway.role` column (`'gateway'`\|`'client'`) | `db.rs:74` + migration | small |
| rotation exclusion | `db.rs:1786` | small |
| punch-broker exclusion / hub-and-spoke | `broker.rs:630`, `routes.rs:42` | small–medium |
| `enrollment_token.kind` CHECK += `'client'` | `db.rs:141`, `SCHEMA_V4` | small |
| explicit `EnrollRequest.kind` + retire the shape-based router | `enrollment.proto:13`, `enrollment.rs:112` | medium |
| client-scoped snapshot/delta | mirror `projection.rs:518`/`:573`, `sync.rs:966` | medium |
| `Peer.kind` so gateways can treat clients differently | `sync.proto:87`, additive | small |

The snapshot scoping matters for more than tidiness: shipping a laptop the full gateway
snapshot hands it **the entire compiled fabric policy**. The relay path already treats that
omission as *"the security boundary, not an optimization"* (`projection.rs:518`).

## Phase 3 — only if the client becomes a product

Per-peer address independent of segment (`db.rs:68/74`, `routes.rs:47`,
`projection.rs:441`) — **large**, and the change that unlocks finding 2. Then a native
menu-bar app with a Network Extension, which needs a paid Apple Developer account and the
notarization step that is currently *guarded pending owner secrets* in the release
pipeline.

## Owner decisions — SETTLED 2026-08-05

1. **Finding 1 — accept and document (option a).** The unprotected receive direction is
   accepted for phase 1, stated explicitly in the PRD amendment, with the client host's own
   firewall as the operator's responsibility. **Egress-side enforcement on gateways
   (option b) is the bar for calling the client production-grade** — until it ships, the
   client is explicitly not that, and no doc may imply otherwise.
2. **PRD non-goal 1 amended** to permit a single-host client peer, with the three
   constraints below ratified alongside it. User identity, device posture and per-user
   policy remain excluded — this is not a ZTNA product.
3. **Client address space: `100.64.0.0/10`.** Adopted as recommended; overlaps nothing in
   the fabric. A client may not take an address inside an existing segment's CIDR.
4. **Scale ceiling: roughly a dozen clients, documented as a v1 limit.** Adopted as
   recommended. Beyond it needs the per-peer address model in phase 3.

PRD non-goal 5 (Linux-only gateways) was **kept**, with its premise corrected: it now
stands on the `pf`-enforcer cost rather than on the Kubernetes assumption that failed.

## What is not claimed

- That Phase 1 is production-grade. It is a correctly-policed-outbound, unprotected-inbound
  client, and calling it anything else would be dishonest.
- That this makes WireMesh competitive with a ZTNA product. It reaches the fabric from a
  laptop; it has no user identity, no device posture, no per-user policy.
- That the gateway should become non-Linux. Unchanged — see the companion note.
