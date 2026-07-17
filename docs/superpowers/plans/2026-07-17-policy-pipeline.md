# WireMesh Policy Pipeline (Cycle 3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The DSL → IR → enforcement pipeline end to end: a `policy:` block applied via `fabricctl apply -f` compiles on the controller to versioned canonical-JSON IR, streams over Sync, and a netns conformance packet-suite proves behaviorally identical enforcement on both the eBPF and nftables backends driven by that same IR.

**Architecture:** New pure crate `wiremesh-policy` (DSL parse/validate/compile → IR, canonical JSON, content-hash `rule_id`) consumed by the controller (replacing cycle 2's `compile_policy` stub, D-C2-5 seam) and by the new `wiremesh-enforcer` library (backend probe + trait; eBPF impl graduated from the Phase 0 spike and upgraded to map-in-map generations + LPM-bitset matching; nftables impl via atomic `nft -f` + conntrack). `wiremesh-enforcer-ebpf` is a standalone excluded workspace (aya can't nest). `wiremesh-testkit` gains a graduated netns/WireGuard lab harness and the backend-parameterized conformance runner.

**Tech Stack:** Rust stable (userspace) + the aya toolchain (`aya 0.14`, `aya-build 0.2`, `aya-ebpf 0.2.1`, nightly + bpf-linker inside the dev container) for the kernel program; `serde`/`serde_yaml`/`serde_json`, `sha2`, `ipnet`, `proptest`; `nft` binary (dev container) for the fallback backend; existing `tonic`/`rusqlite` controller stack.

## Global Constraints

- **Design authority:** `docs/superpowers/specs/2026-07-17-policy-pipeline-design.md`; master spec `docs/superpowers/specs/2026-07-15-wiremesh-engineering-design.md` §5 (pipeline), §9 (testing) governs conflicts.
- **Build/test environment:** everything runs in the dev container: `./dev.sh run "<cmd>"` from repo root. Network/netns/eBPF/nftables tests are **serial**: `cargo test -- --test-threads=1 --nocapture`. Pure-userspace tests (wiremesh-policy, controller) need no privilege but still run in-container (host has no Rust toolchain).
- **v1 is IPv4-only** — all CIDRs are `ipnet::Ipv4Net`; non-IPv4 anything is a compile error.
- **IR encoding is canonical JSON (D-C3-1):** one deterministic serialization; `POLICY_VERSION.compiled_ir` stores the JSON text; Sync `policy_ir` carries the same bytes; proto keeps `bytes policy_ir` opaque. IR carries `"schema": 1`; consumers reject unknown schemas.
- **The compiler is pure (D-C3-2):** `compile(&PolicySource, &[SegmentDef], version) → Result<PolicyIR, Vec<CompileError>>` — no DB, no I/O, all errors collected.
- **`wiremesh-policy` is the only crate defining IR types**; controller and enforcer both depend on it. The enforcer never parses DSL; the controller never sees backend details.
- **`wiremesh-enforcer-ebpf` is a standalone cargo workspace excluded from the root workspace** (Phase 0 finding: the aya template can't nest). Root `Cargo.toml` gets `exclude = ["crates/wiremesh-enforcer-ebpf", "spike"]`.
- **aya API note:** aya 0.14 + TCX link API on ≥ 6.6 kernels (dev container kernel is 6.12.x-linuxkit); `tc filter show` shows nothing — observe via `bpftool link show`. API drift vs this plan's listings is expected implementation work: fix against current crate docs, keep the asserted behavior.
- **Enforcement defaults (all configurable via `EnforcerConfig`):** flow table 1M entries (tests use small values); idle timeouts TCP 7200s / UDP 60s / ICMP 30s; rate cap 256 new flows/s per source IP; deny-log sampling 10/s per rule, 100/s aggregate.
- **Agent workflow (CLAUDE.md):** tests are written by a different agent than the implementation; reviews by a different agent than the author; tests are *executed* by a dedicated third agent that relays raw output; tests green before any done-claim; failures fix code, never tests.
- Commit after every green test cycle. Commit messages end with `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

## File Structure (end state)

```
Cargo.toml                                  # + wiremesh-policy, wiremesh-enforcer members; exclude ebpf ws
crates/
  wiremesh-policy/
    Cargo.toml
    src/lib.rs                              # re-exports
    src/dsl.rs                              # PolicySource serde model + parse
    src/validate.rs                         # CompileError + all validation
    src/ir.rs                               # PolicyIR/IrBlock/IrRule + canonical JSON + rule_id
    src/compile.rs                          # compile(): resolve, order, hash
    tests/golden.rs                         # DSL→IR fixtures + every error class
    tests/props.rs                          # property tests
    tests/fixtures/*.yaml|*.json            # golden inputs/outputs
  wiremesh-enforcer/
    Cargo.toml
    build.rs                                # aya-build against ../wiremesh-enforcer-ebpf
    src/lib.rs                              # Backend enum, probe(), Enforcer trait obj
    src/flatten.rs                          # IR → FlatRule list (block/rule scoping, port explosion)
    src/ebpf.rs                             # aya loader, generation writer, flip, counters, flush
    src/nft.rs                              # IR → nft ruleset text + atomic apply + counter offsets
    tests/flatten.rs                        # pure unit tests
    tests/ebpf_backend.rs                   # netns behavior tests (serial)
    tests/nft_backend.rs                    # netns behavior tests (serial)
  wiremesh-enforcer-ebpf/                   # STANDALONE workspace (excluded)
    Cargo.toml                              # [workspace] members = [".", "common"] style: see Task 7
    common/{Cargo.toml,src/lib.rs}          # #[repr(C)] FlatRuleMeta, FlowKey, FlowVal, consts
    src/main.rs                             # kernel program (LPM bitset, map-in-map, flow table v2)
  wiremesh-controller/
    src/apply.rs                            # MODIFIED: real compiler entry
    src/db.rs                               # MODIFIED: apply_fabric compiles + policy_rule rows + CIDR diff
    src/projection.rs                       # MODIFIED: PolicyUpdated event, IR in snapshot
    src/services/admin.rs                   # MODIFIED: GetPolicy RPC
    tests/policy_pipeline.rs                # apply -f → Sync IR integration tests
  wiremesh-testkit/
    src/netns.rs                            # graduated natlab Lab/Ns + wg_lab
    src/conformance.rs                      # scenario table + runner
    tests/conformance.rs                    # THE done-bar suite (serial, both backends)
  fabricctl/src/main.rs                     # MODIFIED: policy show/status
proto/wiremesh/v1/admin.proto               # MODIFIED: GetPolicy
docs/research/cycle3-policy-notes.md        # wrap-up notes + measured numbers
```

---

## PHASE 1 — Compiler (`wiremesh-policy` + controller wiring)

### Task 1: `wiremesh-policy` crate — DSL model, parse, validation

**Files:**
- Create: `crates/wiremesh-policy/Cargo.toml`, `src/lib.rs`, `src/dsl.rs`, `src/validate.rs`
- Modify: `Cargo.toml` (root — add member)
- Test: `crates/wiremesh-policy/tests/golden.rs` (error-class half)

**Interfaces:**
- Consumes: nothing (pure leaf crate).
- Produces (later tasks rely on these exact names):
  ```rust
  pub struct SegmentDef { pub name: String, pub cidrs: Vec<ipnet::Ipv4Net> }
  pub struct PolicySource(/* parsed YAML, opaque */);
  pub fn parse_policy(yaml: &str) -> Result<PolicySource, Vec<CompileError>>;
  pub struct CompileError { pub block: Option<usize>, pub rule: Option<usize>, pub msg: String }
  impl Display for CompileError; // "block 2 (a→b) rule 1: ports require proto tcp|udp"
  ```

- [ ] **Step 1 (test author):** Write failing golden tests covering parse + every validation error class from design §4, one YAML fixture each, asserting the exact `CompileError` messages (block/rule indices + msg substring):
  unknown segment name in `from`/`to`; duplicate ordered `(from,to)` block pair; `src` ⊄ from-segment CIDRs; `dst` ⊄ to-segment CIDRs; `ports` with `proto: icmp`; `ports` with `proto` omitted; malformed CIDR; port 0; port > 65535; range `lo > hi`; a rule with neither `allow:` nor `deny:` key (or both); non-IPv4 CIDR (`::/0`); empty `rules:` list in a block (valid — a block of zero rules just default-denies that pair; assert it parses). Multi-error collection: one fixture with 3 independent errors asserts all 3 come back.
- [ ] **Step 2 (executor agent):** `./dev.sh run "cargo test -p wiremesh-policy"` — expected: FAIL (crate doesn't exist / functions undefined).
- [ ] **Step 3 (implementer):** Create the crate. `dsl.rs`: serde model mirroring design §4 —
  ```rust
  #[derive(Deserialize)] #[serde(deny_unknown_fields)]
  pub struct PolicyDoc { pub policy: Vec<BlockSrc> }
  #[derive(Deserialize)] #[serde(deny_unknown_fields)]
  pub struct BlockSrc { pub from: String, pub to: String, pub rules: Vec<RuleSrc> }
  // RuleSrc: exactly one of `allow`/`deny`, each a RuleBody
  #[derive(Deserialize)] #[serde(deny_unknown_fields)]
  pub struct RuleBody {
      #[serde(default)] pub src: Vec<String>,   // also accepts single string via custom de
      #[serde(default)] pub dst: Vec<String>,
      #[serde(default)] pub ports: Vec<PortSpec>, // 443 or "8000-8080"
      #[serde(default)] pub proto: Option<String>, // tcp|udp|icmp
  }
  ```
  `validate.rs`: `validate(&PolicyDoc, &[SegmentDef]) -> Vec<CompileError>` enforcing every class from Step 1. Subset check: every rule CIDR must be contained in (⊆) at least one of the segment's CIDRs (`Ipv4Net::contains` on the network+broadcast bounds — `supernet.contains(&subnet.network()) && supernet.contains(&subnet.broadcast())` or `ipnet`'s `contains(&Ipv4Net)` if available in ipnet 2).
- [ ] **Step 4 (executor agent):** `./dev.sh run "cargo test -p wiremesh-policy"` — expected: PASS.
- [ ] **Step 5:** Commit: `feat(policy): DSL model, parser and validation for the policy compiler`

### Task 2: IR types, canonical JSON, `rule_id`, `compile()`

**Files:**
- Create: `crates/wiremesh-policy/src/ir.rs`, `src/compile.rs`
- Test: `crates/wiremesh-policy/tests/golden.rs` (IR half) + `tests/fixtures/`

**Interfaces:**
- Produces (exact — the enforcer and controller consume these):
  ```rust
  #[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
  pub struct PolicyIR { pub schema: u32, pub version: u64, pub blocks: Vec<IrBlock> }
  pub struct IrBlock { pub from: String, pub to: String,
                       pub src_cidrs: Vec<String>, pub dst_cidrs: Vec<String>,
                       pub rules: Vec<IrRule> }
  pub struct IrRule { pub rule_id: String, pub action: IrAction /* "allow"|"deny" */,
                      pub proto: IrProto /* "tcp"|"udp"|"icmp"|"any" */,
                      pub src: Vec<String>, pub dst: Vec<String>,   // empty = whole segment
                      pub ports: Vec<(u16, u16)> }                  // serialized [[lo,hi],..]
  impl PolicyIR {
      pub fn to_canonical_json(&self) -> String;          // deterministic, field-ordered
      pub fn from_json(bytes: &[u8]) -> anyhow::Result<PolicyIR>; // rejects schema != 1
      pub fn blocks_fingerprint(&self) -> String;         // sha256 hex of blocks-only JSON —
                                                          // the version-independent equality key (D-C3-8)
  }
  pub fn compile(src: &PolicySource, segments: &[SegmentDef], version: u64)
      -> Result<PolicyIR, Vec<CompileError>>;
  pub fn rule_id(from: &str, to: &str, rule: &IrRule) -> String; // 16 hex chars
  ```
- Canonicalization rules (design §4/D-C3-1, copy exactly): blocks in source order; rules in written order; segment-name→CIDR lists sorted lexically by `(addr, prefix)`; rule `src`/`dst` CIDRs normalized via `Ipv4Net` display (e.g. `10.0.0.1/32`), kept in written order; a single port `p` becomes `(p,p)`; `proto` omitted in DSL ⇒ `any`.
- `rule_id` (D-C3-3): first 8 bytes of `sha256("{from}|{to}|{action}|{proto}|src={src.join(",")}|dst={dst.join(",")}|ports={lo}-{hi},...")` hex-encoded, computed over the *normalized* rule fields above.

- [ ] **Step 1 (test author):** Failing golden tests: (a) the design-§5 example DSL fixture → exact expected IR JSON fixture (byte compare against `to_canonical_json`); (b) compile twice → byte-identical; (c) `rule_id` stays identical when an *unrelated* rule in the same block changes, and differs for the same rule body placed in a different block pair; (d) `from_json` rejects `"schema": 2` with an error; (e) omitted `src`/`dst` serialize as `[]`; single port `22` → `[[22,22]]`; (f) `blocks_fingerprint` equal across two compiles with different `version` args, different when a rule changes.
- [ ] **Step 2 (executor):** `./dev.sh run "cargo test -p wiremesh-policy --test golden"` — FAIL (missing items).
- [ ] **Step 3 (implementer):** Implement `ir.rs` + `compile.rs`. Canonical JSON = `serde_json::to_string` of the structs (serde preserves declared field order; no maps, no floats — that *is* the canonical form; document this invariant on `to_canonical_json`). Add `sha2` dep.
- [ ] **Step 4 (executor):** same command — PASS.
- [ ] **Step 5:** Commit: `feat(policy): IR with canonical JSON, content-hash rule ids, DSL→IR compile`

### Task 3: compiler property tests

**Files:**
- Test: `crates/wiremesh-policy/tests/props.rs` (`proptest` dev-dep)

**Interfaces:** consumes Task 1–2's public API only.

- [ ] **Step 1 (test author):** Property tests over generated policies (strategy: 1–4 segments with 1–3 disjoint CIDRs each; 0–4 blocks over distinct ordered pairs; 0–6 rules each with valid-by-construction fields): (a) compile never panics; (b) valid-by-construction input always compiles Ok; (c) determinism: two compiles byte-equal; (d) every `rule_id` in output is unique per (block, rule) and 16 lowercase hex chars; (e) mutate one rule's ports → only that rule's `rule_id` changes; (f) injecting a duplicate ordered pair always yields a `CompileError` mentioning both block indices; (g) injecting an out-of-segment `src` CIDR always errors.
- [ ] **Step 2 (executor):** `./dev.sh run "cargo test -p wiremesh-policy --test props"` — properties (f)/(g) FAIL only if validation has holes; all must PASS. If any property fails, that is a **bug in Task 1/2 code — fix the code** (separate implementer pass), never the property.
- [ ] **Step 3:** Commit: `test(policy): property tests for compiler invariants`

### Task 4: controller — real compiler behind the D-C2-5 seam, IR over Sync

**Files:**
- Modify: `crates/wiremesh-controller/src/apply.rs` (replace `compile_policy` stub), `src/db.rs` (`apply_fabric`, new `latest_policy`), `src/projection.rs` (snapshot + `PolicyUpdated` event), `src/services/admin.rs` (broadcast after apply), `src/db_async.rs` (async wrappers), `crates/wiremesh-controller/Cargo.toml` (dep on `wiremesh-policy`)
- Test: `crates/wiremesh-controller/tests/policy_pipeline.rs`

**Interfaces:**
- Consumes: `wiremesh_policy::{parse_policy, compile, PolicyIR, SegmentDef, CompileError}`.
- Produces:
  - `Db::apply_fabric(segments, policy_yaml, actor, now)` unchanged signature; on policy change now also writes `policy_rule` rows `(version, block_ord, rule_ord, action, src, dst, proto, ports)` and stores real `compiled_ir` JSON. Compile errors → the whole apply fails (`Err`), **nothing stored**, error text = all collected errors joined with `\n`.
  - New-version rule (D-C3-8): compile candidate IR with `version = latest+1`; if a latest version exists and `blocks_fingerprint()` matches the stored one, **no new version** (and `policy_updated: false`) even if `source_yaml` text differs; store fingerprint in a new `policy_version.fingerprint TEXT` column (migration v2).
  - `Db::latest_policy() -> Result<Option<(u64 /*version*/, String /*compiled_ir*/)>>` + `DbHandle` async wrapper.
  - `projection::ChangeEvent::PolicyUpdated { version: u64, ir: Vec<u8>, revision: u64 }` — `subject_gateway_id() == 0` (every connected gateway receives it); `delta_for_change` maps it to a `Delta` with only `policy_ir`/`policy_version`/`revision` set.
  - `build_snapshot` now fills `policy_ir`/`policy_version` from `latest_policy()` (still empty/0 when no policy exists).
- Ordering constraint: compilation happens **inside `apply_fabric`'s transaction, after segment inserts**, against the segment table as of that point — a fabric.yaml declaring a new segment *and* policy referencing it applies atomically.

- [ ] **Step 1 (test author):** Failing integration tests in `tests/policy_pipeline.rs` (reuse `wiremesh-testkit` harness like `tests/apply.rs` does): (a) `apply -f` with 2 segments + the design-§5 example policy → `ApplyDiff.policy_updated == true`, and a stub gateway's next snapshot carries non-empty `policy_ir` that `PolicyIR::from_json` parses with `version == 1` and the expected 3 rules; (b) an already-connected stub gateway receives a `Delta` with `policy_version == 1` (live fan-out); (c) re-applying the identical file → `policy_updated == false`, zero new audit rows; (d) reordering two YAML keys without semantic change → still `policy_updated == false` (fingerprint, not source text); (e) policy referencing an unknown segment → RPC error whose message names the segment, and `policy_version` table is unchanged; (f) `policy_rule` rows populated with correct `(block_ord, rule_ord)` (assert via a `Db` helper or direct SQL).
- [ ] **Step 2 (executor):** `./dev.sh run "cargo test -p wiremesh-controller --test policy_pipeline"` — FAIL.
- [ ] **Step 3 (implementer):** Implement. Migration v2 adds `fingerprint` column (`ALTER TABLE policy_version ADD COLUMN fingerprint TEXT NOT NULL DEFAULT ''`). `apply.rs::compile_policy` is deleted; `apply_fabric` calls `wiremesh_policy::compile` with the in-transaction segment list. Admin service broadcasts `PolicyUpdated` after commit (same pattern as existing events; read `current_revision` after commit).
- [ ] **Step 4 (executor):** full crate: `./dev.sh run "cargo test -p wiremesh-controller"` — PASS (existing apply/admin tests must stay green; the old "stub always []" doc comments get updated).
- [ ] **Step 5:** Commit: `feat(controller): real DSL→IR compilation, policy_rule rows, IR over Sync`

### Task 5: segment-CIDR change → recompilation + peer refresh

**Files:**
- Modify: `crates/wiremesh-controller/src/db.rs` (`apply_fabric` CIDR diffing), `src/projection.rs` (`SegmentCidrsChanged` event), `src/services/admin.rs`
- Test: `crates/wiremesh-controller/tests/policy_pipeline.rs` (extend)

**Interfaces:**
- `apply_fabric` cycle-3 scope extension: a declared segment whose name exists but whose declared CIDR set differs (set compare on normalized `Ipv4Net`) has its CIDR rows **replaced** (delete + insert, inside the same transaction, same overlap guard exempting the segment's own rows). Counts into `ApplyOutcome.updated_segments`. Deletion of segments stays out of scope (unchanged).
- CIDR change triggers recompilation of the latest policy source (if any) against the new segment table — same fingerprint rule; if the resolved IR differs → new version in the same transaction.
- New `ChangeEvent::SegmentCidrsChanged { gateway_id: i64, segment_name: String, allowed_ips: Vec<String>, keys: Vec<(i64,String,String)>, revision: u64 }` (full-peer-refresh pattern, mirrors `KeyRotated`) emitted for the segment's gateway if it has one; plus `PolicyUpdated` when a new version resulted.
- A CIDR change that makes the stored policy **no longer compile** (e.g. a rule's `dst` no longer ⊆ segment) fails the whole apply with the compile errors — the fabric never ends up with segments and policy out of sync.

- [ ] **Step 1 (test author):** Failing tests: (a) apply adds a CIDR to segment B → `updated_segments == 1`, connected stub for gateway A receives a peer-upsert `Delta` with B's new `allowed_ips` AND a `PolicyUpdated` delta with `version == 2` whose IR resolves B's block `dst_cidrs` to the new set; (b) same apply where policy doesn't reference B → CIDR delta but **no** new policy version; (c) shrinking a CIDR below a rule's `dst` → apply fails, segment CIDRs unchanged (rollback proven by re-reading), error names the rule; (d) idempotence: re-apply → zero changes.
- [ ] **Step 2 (executor):** FAIL → **Step 3 (implementer):** implement → **Step 4 (executor):** `cargo test -p wiremesh-controller` PASS.
- [ ] **Step 5:** Commit: `feat(controller): segment CIDR updates recompile policy and refresh peers`

### Task 6: `Admin.GetPolicy` + `fabricctl policy show|status`

**Files:**
- Modify: `proto/wiremesh/v1/admin.proto`, `crates/wiremesh-controller/src/services/admin.rs`, `crates/wiremesh-controller/src/db.rs` (version lookup incl. by number), `crates/fabricctl/src/main.rs`
- Test: `crates/fabricctl/tests/cli.rs` (extend) or `crates/wiremesh-controller/tests/admin.rs` (follow whichever pattern the existing `Apply` CLI test uses)

**Interfaces:**
- Proto: `rpc GetPolicy(GetPolicyRequest) returns (PolicyVersionMsg);` with `message GetPolicyRequest { uint64 version = 1; } // 0 = latest` and `message PolicyVersionMsg { uint64 version = 1; string source_yaml = 2; bytes compiled_ir = 3; string created_by = 4; string created_at = 5; }`. Read-only role suffices (same auth tier as `ListSegments`).
- `fabricctl policy show [--version N]` prints source + pretty-printed IR; `fabricctl policy status` prints per-gateway `name / applied_version / latest_version` off `ListGateways` (the last-acked column exists since cycle 2).

- [ ] **Step 1 (test author):** Failing test: apply a policy, then `GetPolicy{version:0}` returns version 1 with parseable IR; `GetPolicy{version:99}` → NotFound; `policy status` output contains the gateway name and `1` after the stub gateway `Report`s version 1.
- [ ] **Step 2 (executor):** FAIL → **Step 3 (implementer):** implement → **Step 4 (executor):** `cargo test --workspace` (userspace crates) PASS.
- [ ] **Step 5:** Commit: `feat(fabricctl): policy show and status over new Admin.GetPolicy`

---

## PHASE 2 — eBPF backend

### Task 7: graduate the spike — enforcer crates, backend trait, probe

**Files:**
- Create: `crates/wiremesh-enforcer-ebpf/` (standalone workspace: `Cargo.toml` with `[workspace] members = ["common", "program"]` — copy the spike's `spike/enforcer/{enforcer-ebpf,enforcer-common}` sources as the starting point: `program/src/main.rs` from `spike/enforcer/enforcer-ebpf/src/main.rs`, `common/src/lib.rs` from `spike/enforcer/enforcer-common/src/lib.rs`; keep the spike's aya-pin versions and `[profile.release.package.*]` settings from `spike/enforcer/Cargo.toml`)
- Create: `crates/wiremesh-enforcer/{Cargo.toml,build.rs,src/lib.rs,src/flatten.rs,src/ebpf.rs}` (`build.rs` adapted from `spike/enforcer/enforcer/build.rs` — `aya_build::build_ebpf` pointed at the sibling `wiremesh-enforcer-ebpf/program` package via `cargo_metadata` on that workspace's manifest path)
- Modify: root `Cargo.toml` (add `wiremesh-enforcer` member; add `exclude = ["crates/wiremesh-enforcer-ebpf", "spike"]`)
- Test: `crates/wiremesh-enforcer/tests/flatten.rs`, `tests/ebpf_backend.rs` (smoke half)

**Interfaces:**
- Produces (the library surface, D-C3-4 — later tasks and cycle 4 rely on these exact signatures):
  ```rust
  pub enum BackendKind { Ebpf, Nftables }
  pub struct EnforcerConfig { pub flow_max: u32, pub tcp_idle_s: u32, pub udp_idle_s: u32,
      pub icmp_idle_s: u32, pub rate_cap_per_src: u32, pub log_per_rule: u32, pub log_aggregate: u32 }
  impl Default for EnforcerConfig { /* 1_048_576, 7200, 60, 30, 256, 10, 100 */ }
  pub trait Enforcer {
      fn kind(&self) -> BackendKind;
      fn apply(&mut self, ir: &PolicyIR) -> anyhow::Result<()>;          // atomic
      fn counters(&mut self) -> anyhow::Result<Counters>;                // per-rule_id + default_deny
      fn flush_flows(&mut self) -> anyhow::Result<()>;
      fn deny_events(&mut self) -> anyhow::Result<Vec<DenyEvent>>;       // drained, sampled
  }
  pub struct Counters { pub by_rule: std::collections::BTreeMap<String, u64>, pub default_deny: u64 }
  pub struct DenyEvent { pub src: std::net::Ipv4Addr, pub dst: std::net::Ipv4Addr,
      pub proto: u8, pub dport: u16, pub rule_id: Option<String> /* None = default deny */ }
  /// Probe = try eBPF (load + attach on `iface`), fall back to nftables (D-C3-4).
  pub fn probe(iface: &str, cfg: EnforcerConfig) -> anyhow::Result<Box<dyn Enforcer>>;
  ```
- `flatten.rs` (pure, unit-testable — the shared front half of both backends):
  ```rust
  pub struct FlatRule { pub idx: u32, pub rule_id: String, pub action: IrAction,
      pub proto: IrProto, pub src_cidrs: Vec<Ipv4Net>, pub dst_cidrs: Vec<Ipv4Net>,
      pub port_lo: u16, pub port_hi: u16 }   // (0,0) = any
  /// Blocks flattened in (block_ord, rule_ord) order; a rule's empty src/dst falls
  /// back to its block's src_cidrs/dst_cidrs; a rule with k port ranges explodes
  /// into k consecutive FlatRules sharing rule_id (same action ⇒ first-match
  /// semantics preserved; counters aggregate by rule_id anyway).
  pub fn flatten(ir: &PolicyIR) -> anyhow::Result<Vec<FlatRule>>; // Err if > MAX_RULES (256)
  pub const MAX_RULES: usize = 256;
  ```
- `wiremesh-policy` gains the corresponding compile-time guard: > 256 flattened rules is a `CompileError` (constant re-exported/duplicated with a cross-referencing comment — the controller must reject at compile time what the gateway would reject at load time, design §6).

- [ ] **Step 1 (test author):** Failing unit tests for `flatten` (no privilege needed): ordering across blocks, block-CIDR fallback, port explosion with shared `rule_id`, `MAX_RULES` overflow error; plus the compiler-side guard test in `wiremesh-policy`. And one privileged smoke test in `tests/ebpf_backend.rs`: in a netns with a veth-backed WireGuard pair (harness arrives fully in Task 12 — for this smoke test copy the spike's `wg_lab` helper inline as a `#[path]`-free local `mod`), `probe("wg0", ..)` returns `BackendKind::Ebpf` and `apply(&empty_ir)` succeeds.
- [ ] **Step 2 (executor):** `./dev.sh run "cargo test -p wiremesh-enforcer --test flatten"` FAIL; then after Step 3: flatten PASS, and `./dev.sh run "cargo test -p wiremesh-enforcer --test ebpf_backend -- --test-threads=1 --nocapture"` PASS.
- [ ] **Step 3 (implementer):** Create both crates. `ebpf.rs` in this task = spike-equivalent loader (load embedded object, clsact + attach ingress/egress, bpffs `ensure_bpffs` graduated verbatim from `spike/enforcer/enforcer/src/main.rs:49`), with `apply` still writing the spike's A/B tables (upgraded in Task 8) driven by `flatten` output instead of the spike's JSON rule file.
- [ ] **Step 4:** Commit: `feat(enforcer): graduate Phase 0 spike into wiremesh-enforcer{,-ebpf}`

### Task 8: kernel program v2 — LPM-bitset matching + map-in-map generations

**Files:**
- Modify: `crates/wiremesh-enforcer-ebpf/program/src/main.rs`, `common/src/lib.rs`, `crates/wiremesh-enforcer/src/ebpf.rs`
- Test: `crates/wiremesh-enforcer/tests/ebpf_backend.rs` (extend)

**Interfaces (the kernel/userspace map contract — exact):**
- `common/src/lib.rs` additions:
  ```rust
  pub const MAX_RULES: usize = 256;
  pub const BITSET_WORDS: usize = 4;                       // 256 bits
  #[repr(C)] #[derive(Clone, Copy)]
  pub struct RuleMeta { pub action: u32, pub proto: u32,   // 6/17/1/0=any
                        pub port_lo: u16, pub port_hi: u16 } // (0,0)=any
  pub type RuleBits = [u64; BITSET_WORDS];
  #[repr(C)] #[derive(Clone, Copy)]
  pub struct FlowVal { pub last_seen_ns: u64 }
  ```
- Maps (kernel side): `ACTIVE: Array<u32>` (1 entry — generation slot 0|1); outer `BPF_MAP_TYPE_ARRAY_OF_MAPS` × 4, each 2 slots: `GEN_SRC` (inner `LpmTrie<[u8;8] /*prefixlen+u32*/, RuleBits>`), `GEN_DST` (same), `GEN_RULES` (inner `Array<RuleMeta>` 256), `GEN_META` (inner `Array<u32>` 1 — flattened len). Generation-independent maps (`FLOWS`, `COUNTERS`, …) unchanged from Task 7.
- Verdict path (replaces `scan_rules`): read `ACTIVE` **once**; look up inner maps at that slot; `bits = SRC_LPM[src] & DST_LPM[dst]` (either lookup missing ⇒ default deny); iterate `i in 0..MAX_RULES` (bounded loop, `break` at `len`), first `i` with bit `i` set in `bits` AND proto/port match in `RULES[i]` wins. Per-rule counters keyed by generation-independent `Array<u64>` of 258 entries (`idx` = flattened rule index; 256 = default-deny; 257 = flow-hit).
- Userspace `apply` (in `ebpf.rs`):
  1. `flatten(ir)`; build LPM entries: for each `FlatRule` r and each src CIDR, an entry `(prefix, bit r.idx)`; **cumulative bitsets**: for every distinct prefix P, its stored bitset = union of bits of all rules having a src CIDR ⊇ P (LPM returns only the longest match, so shorter covering prefixes' bits must be folded in at build time — O(n²), n ≤ 256). Same for dst.
  2. Create *fresh inner maps*, fill them, install into all 4 outer slots at index `target = 1 - active`, then single `ACTIVE.set(0, target)` — the atomic flip (one read per packet ⇒ no straddling).
  3. Hold the old generation's inner-map handles for a 10s grace (`std::thread::sleep` in a detached scope or lazy-reap on next `apply`: **reap-on-next-apply + minimum 10s since flip** is the implementation: if the next `apply` comes sooner, it waits out the remainder — rare, simple, correct), then drop (kernel frees via refcount).
- `counters()` reads the 258-entry array and aggregates flattened indices → `rule_id` using the mapping retained from the last `apply`.

- [ ] **Step 1 (test author):** Failing netns tests (serial): (a) first-match-wins: deny-22 carve-out before allow-all-tcp → SSH SYN dropped, port-80 connect passes, counters land on the right `rule_id`s; (b) whole-segment fallback: rule with empty src/dst enforces against block CIDRs; (c) LPM correctness: allow `10.0.0.0/24` rule after deny `10.0.0.8/32` rule — packet from `.8` denied, from `.9` allowed (proves cumulative bitsets + first-match, not longest-prefix-wins); (d) **atomic flip under traffic**: continuous 1-per-10ms UDP stream allowed by both generations while `apply` flips 20× — zero drops (assert receiver count == sender count); (e) old-generation reap doesn't break an in-flight allowed flow.
- [ ] **Step 2 (executor):** FAIL → **Step 3 (implementer):** implement kernel + userspace v2. Verifier-budget note from design §6: if the combined program blows the verifier, the sanctioned fallback is splitting ICMP-error parsing into a tail call — record actual verifier instruction counts in the task report either way. → **Step 4 (executor):** `./dev.sh run "cargo test -p wiremesh-enforcer --test ebpf_backend -- --test-threads=1 --nocapture"` PASS.
- [ ] **Step 5:** Commit: `feat(enforcer): LPM-bitset first-match + map-in-map atomic generations`

### Task 9: flow table v2 — timeouts, rate cap, flush

**Files:**
- Modify: `crates/wiremesh-enforcer-ebpf/program/src/main.rs`, `common/src/lib.rs`, `crates/wiremesh-enforcer/src/ebpf.rs`
- Test: `crates/wiremesh-enforcer/tests/ebpf_backend.rs` (extend)

**Interfaces:**
- `FLOWS: LruHashMap<FlowKey, FlowVal>` (max_entries set from `EnforcerConfig.flow_max` before load — aya `EbpfLoader::set_max_entries`); hit path checks `bpf_ktime_get_ns() - last_seen_ns > timeout(proto)` → stale: delete entry, fall through to rules; fresh: update `last_seen_ns` (both directions refresh, spec §5.3). Timeouts + rate cap arrive via a `CONFIG: Array<u64>` map (indices: 0 tcp_ns, 1 udp_ns, 2 icmp_ns, 3 rate_cap) written before attach.
- Egress new-entry rate cap: `RATE: LruHashMap<u32 /*src ip*/, RateVal { window_start_ns, count }>` — creating a *new* FLOWS entry at egress over `rate_cap` per rolling 1s window skips the insert (egress never blocks traffic; the cost is that the flow's replies must pass rules — spec's documented trade). Ingress-allow entry creation (existing) is not capped.
- `flush_flows()`: userspace iterates and deletes all `FLOWS` keys.
- The spike's ICMP embedded-error lookup is kept as-is (already validated); embedded lookups consult the flow table only, so they honor timeouts automatically.

- [ ] **Step 1 (test author):** Failing netns tests (serial; use tiny config values — e.g. `udp_idle_s: 2`, `flow_max: 64`, `rate_cap_per_src: 8`): (a) UDP reply passes within idle window, is denied after it expires (sleep past timeout); (b) refresh-on-traffic: keep-alive every 1s keeps a 2s-idle flow alive for 6s; (c) `flush_flows` → established allowed flow's next reply is re-evaluated (denied after a policy flip that removed its rule); (d) rate cap: blast 64 distinct new UDP flows in <1s from one source → FLOWS gains ≤ cap+ingress-side entries and a second source's established flow still passes (anti-churn guarantee); (e) live-flow survival across `apply` (security-group semantics): allowed TCP flow keeps passing after its rule is removed, until `flush_flows`.
- [ ] **Step 2 (executor):** FAIL → **Step 3 (implementer):** implement → **Step 4 (executor):** serial suite PASS.
- [ ] **Step 5:** Commit: `feat(enforcer): flow idle timeouts, per-source rate cap, flush-flows`

### Task 10: deny-event ring buffer + config plumbing completeness

**Files:**
- Modify: `crates/wiremesh-enforcer-ebpf/program/src/main.rs`, `common/src/lib.rs` (`#[repr(C)] DenyEventRaw`), `crates/wiremesh-enforcer/src/ebpf.rs`
- Test: `crates/wiremesh-enforcer/tests/ebpf_backend.rs` (extend)

**Interfaces:**
- `DENY_RB: RingBuf` (aya `RingBuf`), event `DenyEventRaw { src: u32, dst: u32, proto: u8, _pad: [u8;1], dport: u16, rule_idx: u32 /* 256 = default deny */ }`. Sampling in-kernel per spec defaults via `CONFIG` (indices 4 per-rule/s, 5 aggregate/s): token counters in a per-rule `Array<{window_start_ns, count}>` + one aggregate slot; over-budget denies increment counters but emit no event.
- `deny_events()` drains the ring buffer, maps `rule_idx` → `rule_id` (None for 256).

- [ ] **Step 1 (test author):** Failing tests: (a) a denied SYN yields exactly one `DenyEvent` with the matching `rule_id`, src/dst/dport; (b) default-deny yields `rule_id: None`; (c) sampling: 100 denied packets in <1s with `log_per_rule: 5` → ≥5 but ≤ (5 + aggregate-slack) events while the deny *counter* still shows 100 (counters always count, spec §5.3).
- [ ] **Step 2 (executor):** FAIL → **Step 3 (implementer):** implement → **Step 4 (executor):** serial suite PASS.
- [ ] **Step 5:** Commit: `feat(enforcer): sampled deny-event ring buffer`

---

## PHASE 3 — nftables backend + conformance

### Task 11: nftables codegen (pure) + counter-offset accumulator

**Files:**
- Create: `crates/wiremesh-enforcer/src/nft.rs`
- Test: `crates/wiremesh-enforcer/tests/nft_codegen.rs` (pure, no privilege) + `tests/fixtures/*.nft`

**Interfaces:**
- ```rust
  /// IR → complete `nft -f` script: atomic replace of `table ip wiremesh_<iface>`.
  pub fn ruleset(ir: &PolicyIR, iface: &str) -> anyhow::Result<String>;
  ```
- Generated shape (golden-tested verbatim; D-C3-6):
  ```
  table ip wiremesh_wg0
  flush table ip wiremesh_wg0
  table ip wiremesh_wg0 {
    counter r_<rule_id> {}          # one per distinct rule_id
    counter default_deny {}
    chain from_fabric {
      ct state established,related counter accept
      ip saddr { 10.10.0.0/16 } ip daddr { 172.16.1.50 } tcp dport { 22 } counter name "r_<id>" drop
      ip saddr ... accept
      counter name "default_deny" drop
    }
    chain input   { type filter hook input   priority 0; policy accept; iifname "wg0" jump from_fabric }
    chain forward { type filter hook forward priority 0; policy accept; iifname "wg0" jump from_fabric }
  }
  ```
  Flattened rules in order (reuse `flatten`); multiple CIDRs = anonymous sets `{ a, b }`; `(0,0)` ports = no dport match; proto `any` = three lines... **no** — proto `any` emits one line per concrete proto (tcp/udp/icmp) sharing the rule's named counter, consecutive, preserving first-match. Default-deny only for tun-originated traffic (base chains stay `policy accept`, scoping via `iifname` jump — the gateway host's other interfaces are untouched).
- Counter persistence across `flush` (named counters reset on ruleset replace): `nft.rs` keeps `offsets: BTreeMap<String, u64>`; `apply` first reads current counters and folds them into offsets; `counters()` returns `live + offset` per `rule_id` — behavioral parity with eBPF's stable counters.

- [ ] **Step 1 (test author):** Failing golden tests: design-§5 example IR → exact fixture script; proto-any explosion shares one counter; carve-out ordering preserved; empty policy (no blocks) → just the `ct` line + default-deny.
- [ ] **Step 2 (executor):** `./dev.sh run "cargo test -p wiremesh-enforcer --test nft_codegen"` FAIL → **Step 3 (implementer):** implement → **Step 4 (executor):** PASS.
- [ ] **Step 5:** Commit: `feat(enforcer): IR→nftables ruleset codegen with stable counters`

### Task 12: nftables backend live + probe fallback + netns harness graduation

**Files:**
- Modify: `crates/wiremesh-enforcer/src/nft.rs` (apply via `nft -f -`, counter read via `nft -j list counters table ...`), `src/lib.rs` (`probe` wired: eBPF attempt → nftables fallback)
- Create: `crates/wiremesh-testkit/src/netns.rs` (graduate `spike/natlab/src/lib.rs`'s `Lab`/`Ns`/`veth` + the enforcer spike's `wg_lab` two-node WireGuard topology into the product testkit, behind `#[cfg(feature = "netns")]` so pure-userspace consumers don't pull it)
- Test: `crates/wiremesh-enforcer/tests/nft_backend.rs`

**Interfaces:**
- `wiremesh_testkit::netns::{Lab, Ns, wg_lab}` — same API shape as the spike (`Ns::exec/spawn`, `wg_lab() -> (Lab, Ns, Ns, Vec<Child>)` with `wg0` up and overlay `10.10.0.1 ⇄ 10.10.0.2`); Task 7's inline copy in `ebpf_backend.rs` is replaced by this module.
- `NftEnforcer::apply` pipes the script to `nft -f -` (one transaction = atomic, no-gap); errors keep the previous ruleset (nft transactional semantics) and surface stderr.
- `probe(iface, cfg)`: try `EbpfEnforcer::new` (full load+attach); on error, log the reason and return `NftEnforcer` — plus an env/knob-free forced choice for tests: `probe_with(BackendKind, ...)`.

- [ ] **Step 1 (test author):** Failing netns tests: (a) allow/deny/carve-out packet behavior identical in shape to Task 8's (a) but through `NftEnforcer`; (b) statefulness via conntrack: outbound UDP then inbound reply passes with no allow rule for the reply direction; (c) ICMP echo + a PMTUD-style embedded error passes via `related`; (d) atomic replace under the Task 8 (d) traffic pattern — zero drops across 20 `apply` calls; (e) counters survive a policy re-apply (offset accumulator); (f) `probe` in a netns where bpffs/eBPF is unavailable falls back to `Nftables` (simulate by `probe_with` or by denying the load — implementer picks the honest mechanism and documents it).
- [ ] **Step 2 (executor):** FAIL → **Step 3 (implementer):** implement (includes the testkit netns module graduation) → **Step 4 (executor):** `./dev.sh run "cargo test -p wiremesh-enforcer -- --test-threads=1 --nocapture"` PASS (both backend suites).
- [ ] **Step 5:** Commit: `feat(enforcer): live nftables backend, probe fallback, testkit netns lab`

### Task 13: conformance suite — one scenario table, two backends (the done bar)

**Files:**
- Create: `crates/wiremesh-testkit/src/conformance.rs`, `crates/wiremesh-testkit/tests/conformance.rs`
- Test: that file *is* the deliverable.

**Interfaces:**
- ```rust
  pub struct Scenario { pub name: &'static str,
      pub policy_yaml: &'static str, pub segments: &'static [(&'static str, &'static [&'static str])],
      pub steps: &'static [Step] }
  pub enum Step {
      Send { from: Endpoint, to: Endpoint, proto: L4, expect: Expect },  // Expect::Delivered | Dropped
      ApplyPolicy { yaml: &'static str },       // recompile + Enforcer::apply mid-scenario
      FlushFlows,
      Sleep { ms: u64 },
      ExpectCounter { rule_id_of: (&'static str, usize, usize), min: u64 }, // (pair, block, rule)
  }
  pub fn run_scenario(s: &Scenario, kind: BackendKind) -> anyhow::Result<()>;
  ```
  `run_scenario` builds the `wg_lab`, compiles `policy_yaml` with `wiremesh_policy::compile` (segments from the scenario — the *same* compiler the controller uses), instantiates the backend via `probe_with(kind, ...)`, and drives packets with `Ns::exec` (nc/ping/iperf3 as in the spike tests). **A scenario passes only if it passes on both backends** — the test file iterates `[Ebpf, Nftables] × SCENARIOS`.
- Scenario list (design §8, each a table entry): first-match allow/deny + carve-out; default deny (no block for pair; no matching rule in block); stateful reply both directions; ICMP echo allowed by rule; ICMP embedded-error (fragmentation-needed) passes for a recorded flow and is dropped otherwise; policy update under live allowed traffic (flow survives; new connections follow new policy); `FlushFlows` forces re-evaluation; flip-under-traffic zero-loss (the Task 8/12 (d) pattern, both backends); counter stability across an update that keeps one rule and changes another; ports-range edge (`lo`,`hi`, single port); proto `any` rule matches tcp+udp+icmp.

- [ ] **Step 1 (test author):** Write the whole suite as failing-first only where behavior is genuinely new — most scenarios should pass immediately if Tasks 8–12 are correct; **a red scenario here is a parity bug: fix the backend, never the scenario** (per CLAUDE.md, and record any genuine design finding in `docs/research/` first).
- [ ] **Step 2 (executor):** `./dev.sh run "cargo test -p wiremesh-testkit --test conformance -- --test-threads=1 --nocapture"` — expected: PASS 2×N scenarios. Paste the raw output into the task report.
- [ ] **Step 3:** Commit: `test(conformance): backend-parity packet suite over shared IR`

### Task 14: controller→enforcer end-to-end + cycle wrap-up

**Files:**
- Create: `crates/wiremesh-testkit/tests/end_to_end_policy.rs`, `docs/research/cycle3-policy-notes.md`
- Modify: `docs/progress.html` (+ the claude.ai Artifact per the progress-tracker memory), `CLAUDE.md` (project-state section), `docs/superpowers/specs/2026-07-17-policy-pipeline-design.md` (only if reality diverged — record deltas, mirror how Phase 0 amended the master spec)

**Interfaces:** consumes everything above; produces nothing new.

- [ ] **Step 1 (test author):** Failing end-to-end test: start a real controller (testkit harness), `apply -f` segments + policy, stub gateway receives `policy_ir` over Sync, `PolicyIR::from_json` those exact bytes, `Enforcer::apply` them in a netns lab, send one allowed and one denied packet, assert verdicts and that the stub's `Report(applied_version)` makes `fabricctl policy status` show the version — the full pipeline in one test.
- [ ] **Step 2 (executor):** FAIL → glue fixes if any (implementer) → PASS.
- [ ] **Step 3 (executor, dedicated):** Full-repo proof for the cycle done-claim:
  `./dev.sh run "cargo test --workspace -- --test-threads=1 --nocapture"` and (standalone) `./dev.sh run "cd crates/wiremesh-enforcer-ebpf && cargo check"` — raw output into `docs/research/cycle3-policy-notes.md` along with: verifier instruction counts (Task 8), flip-under-traffic loss numbers, flow-table/rate-cap measured behavior.
- [ ] **Step 4:** Update `docs/progress.html` + Artifact + `CLAUDE.md` project state (Cycle 3 done, Cycle 4 next).
- [ ] **Step 5:** Commit: `docs: cycle 3 wrap-up — policy pipeline notes, progress tracker`

---

## Self-review notes (already applied)

- Spec coverage: design §4 (all compile-error classes → Task 1), §5 IR (Task 2), D-C3-2 purity (Task 2), D-C3-3 rule_id (Task 2/3), D-C3-8 fingerprint idempotence (Task 4), CIDR-change recompile in-scope item (Task 5), `fabricctl policy show`/`status` §7 (Task 6), D-C3-4 library surface (Task 7), D-C3-5 map-in-map + graduation (Tasks 7–8), §6 defaults/flow table/rate cap (Task 9), deny sampling (Task 10), D-C3-6 nftables (Tasks 11–12), D-C3-7 parameterized conformance (Task 13), §1 done bar end-to-end (Task 14). Deferred items (§10: flush-flows RPC, dashboards, gateway binary) have no tasks — intentional.
- The `MAX_RULES = 256` load-time constant is enforced compile-time in `wiremesh-policy` (Task 7) per design §6's requirement that the controller rejects what the gateway would.
- Type consistency: `PolicyIR`/`flatten`/`FlatRule`/`Enforcer` signatures are defined once (Tasks 2, 7) and referenced verbatim afterward.
