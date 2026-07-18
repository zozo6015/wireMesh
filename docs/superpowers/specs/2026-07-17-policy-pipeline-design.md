# WireMesh — Cycle 3 Design: Policy Pipeline

> **Plan cycle 3 of 4** (per the master engineering design §12). This document
> elaborates master-spec §5 (Policy Pipeline: DSL → IR → Backends) into an
> implementable design; it does not restate it. Authority: the master spec
> (`docs/superpowers/specs/2026-07-15-wiremesh-engineering-design.md`, esp. §5
> policy pipeline, §9 testing) governs where this conflicts. Cycle 2 (controller
> core) is merged; cycle 4 is gateway transport + relay.

## 1. Scope & done bar

**In scope (the enforcement pipeline, end to end):** the YAML policy DSL parser +
validator and the DSL→IR compiler with compile-time segment-name→CIDR resolution
(§5.1–5.2), replacing cycle 2's empty-IR-v0 stub behind its existing call site
(cycle-2 design D-C2-5); recompilation on segment-CIDR change; the eBPF
enforcement backend graduated from the Phase 0 spike to full §5.3 semantics
(map-in-map generations, LRU flow table, ICMP embedded-error handling,
per-source new-flow rate cap, sampled deny logging); the nftables fallback
backend (§5.4) plus the startup backend probe; and the conformance packet-suite
(§9) proving behavioral parity between the two backends from the same IR.

**Done bar — one IR, two backends, provably identical.** A `policy:` block
applied via `fabricctl apply -f` compiles on the controller to a versioned IR,
streams over `Sync` as real `policy_ir` bytes, and a netns conformance
packet-suite drives **both** backends from that same IR and proves identical
behavior: first-match-wins with deny carve-outs, default deny (no block / no
rule), stateful replies in both directions, ICMP echo and embedded-error
(PMTUD) handling, atomic policy update under live traffic with no enforcement
gap and live-flow survival, and per-`rule_id` counters that survive a policy
update when the rule text is unchanged.

**Ratified backend divergence (one-way UDP live-flow survival).** "Live-flow
survival across a policy update" holds for both backends for any flow the
backend can track statefully — all TCP flows and any bidirectional (replied)
UDP/ICMP flow. It does **not** hold identically for a purely *one-way* UDP
flow (sender never receives a reply): the eBPF backend's `FLOWS` map fast-paths
it and it survives a rule-removing update until `flush_flows`, whereas the
nftables backend relies on conntrack, which never promotes an unreplied UDP
flow past `ct state new`, so such a flow is re-evaluated against the live
ruleset on every packet and is dropped as soon as its rule is removed. This is
an accepted, documented limitation of the nftables *fallback* backend (owner
decision, 2026-07-18): the naive fix (`ct state new` in the accept line) is
rejected because it would let every not-yet-established flow bypass rule
evaluation, breaking the "new connections follow new policy" guarantee. The
conformance suite (§8) encodes this as its single sanctioned per-backend
expectation; every other scenario proves identical behavior. Full analysis:
`docs/research/cycle3-policy-notes.md` ("Task 13").

**Out of scope (cycle 4):** the real `wiremesh-gateway` binary and its Sync
client (the conformance suite drives the enforcer library directly); relay and
transport; CLI wiring of `fabricctl gateway flush-flows` (the library exposes
the flush API; the RPC plumbing needs a real gateway); the reference dashboard
for occupancy/eviction alerts (metrics counters exist, dashboards are later).

## 2. Decisions

- **D-C3-1 — IR encoding: canonical JSON, schema owned by `wiremesh-policy`.**
  The IR is a serde Rust model in `wiremesh-policy` with one deterministic JSON
  serialization (stable field order, no floats, sorted where the DSL doesn't
  impose order). `POLICY_VERSION.compiled_ir` stores that JSON text; Sync
  `policy_ir` carries the same bytes (proto keeps `bytes policy_ir`, opaque).
  This trivially satisfies §4.1's "reconnecting gateways receive identical
  bytes" rule (serve the cached text, never recompile), is human-inspectable in
  the DB, and avoids prost's lack of a canonical-encoding guarantee. The IR
  carries a `schema: 1` field; consumers reject unknown schemas.
- **D-C3-2 — Compiler is pure and total over its inputs.** `compile(policy_yaml,
  segments) → Result<PolicyIR, Vec<CompileError>>` — no DB access, no I/O. The
  controller supplies the segment table; all errors are collected (not
  first-error-only) and name the offending block/rule. This makes golden and
  property testing trivial and keeps `apply -f` error output useful.
- **D-C3-3 — `rule_id` = content hash of the canonicalized rule text** (action,
  src/dst CIDR lists as written, proto, ports) **plus the block's ordered
  segment-pair names** — stable across versions when the rule is unchanged
  (counters survive), distinct across blocks even for identical rule bodies.
  Hash: first 8 bytes of SHA-256, hex — collisions across a realistic policy
  are negligible and a collision's only cost is merged counters.
- **D-C3-4 — Enforcer is a library crate (`wiremesh-enforcer`), not a binary.**
  Cycle 4's gateway links it; cycle 3's conformance suite drives it directly in
  netns. Public surface: `probe() → Backend` (eBPF if kernel ≥ 5.10 + BTF +
  tc clsact attach succeeds, else nftables), `Enforcer::apply(&PolicyIR)`
  (atomic), `counters() → per-rule_id + default-deny`, `flush_flows()`,
  `deny_events() → sampled stream`. Both backends implement one trait; the IR
  is the contract.
- **D-C3-5 — eBPF program: graduate the spike, upgrade the flip.** The Phase 0
  `enforcer-ebpf`/`enforcer-common` structure (validated go, aya 0.14, TCX link
  API on ≥ 6.6 kernels) moves into the product tree, with the spike's fixed A/B
  generation flip replaced by §5.3's `BPF_MAP_TYPE_ARRAY_OF_MAPS` map-in-map
  (per-generation LPM-trie src/dst maps + rule-metadata array; one active-index
  read per packet; 10s RCU grace before old-generation teardown). The flow
  table (LRU, default 1M, configurable), counter maps, rate-cap map, and the
  deny ring buffer are generation-independent. The eBPF program crate remains a
  **standalone workspace excluded from the root workspace** (aya template
  cannot nest — Phase 0 finding); the userspace crate embeds the built BPF
  object at compile time.
- **D-C3-6 — nftables backend: dedicated table, atomic replace, conntrack.**
  IR → one nft ruleset in a dedicated table applied via a single `nft -f`
  transaction (native atomic replacement, same no-gap guarantee). Statefulness
  via `ct state established,related accept` scoped to the fabric interface —
  `related` covers ICMP errors, matching the eBPF backend's explicit embedded
  lookup. Per-rule counters are named nft counters keyed by `rule_id`.
  Generated via the `nft` binary (rules as text), not libnftables FFI — the
  ruleset text is itself a golden-testable artifact.
- **D-C3-7 — Conformance suite is backend-parameterized, not duplicated.** One
  scenario table (packet in → expected verdict/counter effects) executes
  against each backend in an identical netns topology; a scenario passes only
  if both backends agree with the expectation. Runs serial inside the dev
  container (privileged: tun/netns/eBPF/nftables), reusing/graduating the Phase
  0 natlab netns-harness patterns into `wiremesh-testkit`.
- **D-C3-8 — Controller recompiles; gateways never do.** Segment-CIDR mutations
  and `apply -f` policy changes both funnel into one controller-side
  compile-and-version path: new `POLICY_VERSION` row (source + compiled JSON) +
  `POLICY_RULE` rows, projection bump, delta fan-out. Identical source and
  identical resolved CIDRs ⇒ no new version (idempotent apply stays idempotent).

## 3. Workspace & crate structure (additions to cycle 2's layout)

```
crates/
  wiremesh-policy/            # DSL parse + validate + compile → IR (D-C3-2);
                              #   IR types + canonical JSON (D-C3-1); rule_id
                              #   hashing (D-C3-3). Pure library, no_std-free,
                              #   shared by controller (compile) and enforcer
                              #   (consume).
  wiremesh-enforcer/          # userspace enforcement library (D-C3-4):
                              #   probe, backend trait, eBPF impl (aya loader,
                              #   map-in-map generations, counters, flush),
                              #   nftables impl (ruleset codegen + nft apply).
                              #   Embeds the built BPF object.
  wiremesh-enforcer-ebpf/     # kernel program + shared #[repr(C)] types —
                              #   STANDALONE workspace, excluded from the root
                              #   workspace (aya nesting, D-C3-5).
  wiremesh-controller/        # MODIFIED: apply::compile_policy stub → real
                              #   wiremesh-policy compiler; CIDR-change
                              #   recompilation; POLICY_RULE population.
  wiremesh-testkit/           # EXTENDED: netns topology harness + conformance
                              #   scenario runner (graduated natlab patterns).
```

**Structural invariant:** `wiremesh-policy` is the only crate that defines IR
types; controller and enforcer both depend on it. The enforcer never parses
DSL; the controller never sees backend details.

## 4. DSL & compiler (§5.1, normative semantics restated only as obligations)

The compiler enforces, as compile errors that name their location: unknown
segment names; more than one block per ordered `(from, to)` pair; `src` ⊄
from-segment CIDRs or `dst` ⊄ to-segment CIDRs; `ports` without an explicit
`proto: tcp|udp`; malformed CIDRs/ports/ranges (`lo > hi`, port 0, > 65535);
non-IPv4 anything (v1 is IPv4-only). Omitted `src`/`dst` = the whole segment;
omitted `proto` = tcp+udp+icmp (and forbids `ports`, per the rule above).

Resolution and ordering are deterministic: blocks in source order, rules in
written order, segment names resolved to the segment's CIDR list sorted
lexically by `(addr, prefix)`. Two compiles of the same source against the same
segment table produce byte-identical JSON.

## 5. IR (§5.2, concretized)

```jsonc
{ "schema": 1, "version": 42,
  "blocks": [ { "from": "proxmox-lab", "to": "aws-prod",
                "src_cidrs": ["10.10.0.0/16"], "dst_cidrs": ["172.16.0.0/12"],
                "rules": [ { "rule_id": "9f3a1c20b4d8e671",
                             "action": "deny", "proto": "tcp",
                             "src": [], "dst": [],          // empty = whole segment
                             "ports": [[22,22]] } ] } ] }
```

`version` mirrors `POLICY_VERSION.version`. Ports are `[lo,hi]` pairs (a single
port is `[p,p]`); `proto` is `tcp|udp|icmp|any`. The segment *names* ride along
for observability (`fabricctl`, logs) but backends key only off CIDRs.

## 6. eBPF backend (§5.3, implementation notes beyond the spec)

- Attachment: tc clsact ingress on tun (enforce) + egress on tun (flow
  recording), TCX link API on ≥ 6.6 kernels (Phase 0 finding: legacy
  `tc filter show` shows nothing; observe via `bpftool link show`).
- Verifier budget is the main implementation risk beyond the spike: embedded
  ICMP-error parsing + LPM walks + first-match rule loop in one program. The
  spike proved each behavior; cycle 3 proves them *combined* under the
  verifier. Mitigation if needed: bounded-loop rule evaluation with a
  documented max-rules-per-block constant (compile error above it) — the
  constant, if introduced, is surfaced in `wiremesh-policy` validation so the
  controller rejects at compile time, not the gateway at load time.
- bpffs self-mount + deterministic map resolution (Phase 0 finding (b)) is the
  library's responsibility, not the caller's.
- Defaults (all configurable): flow table 1M entries; idle timeouts TCP 7200s /
  UDP 60s / ICMP 30s; rate cap 256 new flows/s per source IP; deny log sampling
  10/s per rule, 100/s aggregate.

## 7. Controller integration & fabricctl

- `apply::compile_policy(source) → "[]"` stub is replaced by the real compiler
  invoked with the current segment table; compile errors fail the `apply`
  RPC with all collected errors in the status message (nothing is stored).
- New-version path (D-C3-8) writes `POLICY_VERSION` (source_yaml + compiled_ir
  JSON) and `POLICY_RULE` rows (block_ord, rule_ord, action, src, dst, proto,
  ports — for `fabricctl` display and audit diffs), bumps projections, fans out
  deltas with the new IR bytes + version.
- `fabricctl policy show [--version N]` renders source + compiled IR;
  `fabricctl policy status` (exists since cycle 2 via `Sync.Report` acks) now
  shows real versions. `fabricctl apply -f` policy stanzas become fully live.

## 8. Testing (§9 subset for this cycle)

- **Golden tests** (`wiremesh-policy`): DSL → IR JSON fixtures, including every
  compile-error class; byte-identical recompile check.
- **Property tests** (`wiremesh-policy`): generated policies → invariants:
  deterministic output, rule_id stability under unrelated edits, subset
  validation (src/dst ⊆ segment), one-block-per-pair rejection.
- **Golden tests** (`wiremesh-enforcer`): IR → nftables ruleset text fixtures.
- **Conformance packet-suite** (`wiremesh-testkit`, serial, in-container):
  the D-C3-7 scenario table against both backends — allow/deny first-match &
  carve-outs, default deny, stateful reply both directions, ICMP echo +
  embedded-error (PMTUD) forward and reverse, policy flip under live iperf/UDP
  flood (no gap: zero spurious verdicts during flip), live-flow survival across
  update + `flush_flows` forcing re-evaluation, counter stability across
  versions, rate-cap behavior, LRU-eviction metric visibility. Every scenario
  asserts identical behavior on both backends except the single ratified
  one-way-UDP divergence (§1): that scenario's mid-step carries a per-backend
  expectation (eBPF survives, nftables re-evaluates), the suite's only
  sanctioned backend-conditional assertion.
- **Controller integration** (`wiremesh-controller` tests): `apply -f` with a
  real policy → stub gateway receives IR bytes + version over Sync; CIDR add →
  new version fans out; compile error → nothing stored, error names the rule.
- Per CLAUDE.md: tests authored, implemented, executed, and reviewed by
  separate agents; green before any done-claim; failures fix code, never tests.

## 9. Build phases (feeds the implementation plan)

1. **Compiler first** — `wiremesh-policy` complete (DSL, validation, IR,
   golden + property tests) and wired into the controller behind the stub's
   call site with integration tests. Pure userspace; no privilege needed.
2. **eBPF backend** — graduate the spike into `wiremesh-enforcer{,-ebpf}`,
   upgrade to map-in-map generations, add rate cap + sampled deny logging +
   configurable sizes/timeouts; netns tests for each behavior.
3. **nftables backend + conformance** — nft codegen + atomic apply + conntrack
   statefulness; then the backend-parameterized conformance suite proving
   parity, which is the cycle's done bar.

## 10. Deferred / carried forward

- **Cycle 2b (unchanged, still pending):** OpenBao provider driver +
  containerized provider-conformance suite.
- **Cycle 4:** real gateway consumes `wiremesh-enforcer` + the persisted IR in
  its fail-static state bundle; `fabricctl gateway flush-flows` RPC plumbing;
  backend reported in `fabricctl gateway list`; eviction/occupancy alert
  thresholds in the reference dashboard.

## 11. Next artifact

An implementation plan (via the writing-plans skill) structured on §9's three
build phases, each task carrying the CLAUDE.md agent-workflow rules.
