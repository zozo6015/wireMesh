# Cycle 3 (Policy Pipeline) — Research Notes

## Cycle summary & measured numbers

14 tasks, 3 phases (compiler → eBPF backend → nftables + conformance). Full
workspace at completion: **127 tests, 0 failed** (`cargo test --workspace
--features netns`), every task test-authored / implemented / executed /
reviewed by separate agents per the CLAUDE.md workflow rules.

**Conformance (the done bar):** the backend-parity packet-suite runs 11
scenarios × 2 backends = **22/22 cells green**, plus the flip-under-traffic
zero-loss stress test. Exactly **one** sanctioned per-backend expectation — the
ratified one-way-UDP live-flow divergence (below). Everything else is proven
identical eBPF-vs-nftables from the same compiled `PolicyIR`.

**eBPF verifier budget** (tc-BPF ingress program, grew as behaviors were added,
never needed a tail-call split):

| After task | ingress insns | egress insns |
|---|---|---|
| 8 (LPM-bitset + map-in-map generations) | ~561 | ~114 |
| 9 (flow idle timeouts + rate cap) | ~798 | ~312 |
| 10 (sampled deny ring buffer) | ~935 → ~991 (peek/commit fix) | ~312 |

**Atomic policy flip:** map-in-map generation flip proven zero-loss under 20
concurrent `apply()` calls during a continuous UDP stream (`generations.rs`);
nftables `nft -f` atomic replace proven equivalently gap-free
(`nft_backend.rs`, and the conformance flip test on both backends).

**Two accepted design outcomes** (details in the sections below): (1) the
ratified one-way-UDP divergence — owner decision 2026-07-18, accept & document;
(2) the nftables `flush_flows` implementation via whole-netns `conntrack -F`
(broader blast radius than eBPF's fabric-scoped flush; narrower mechanisms
investigated and ruled out). **Deployment dependency:** the nftables backend
requires `conntrack-tools` on the gateway host.

---

## Task 12: nft named counters do NOT reset on `flush table` + redeclare

**Context:** the Task 12 brief (`.superpowers/sdd/task-12-brief.md`)
specified `NftEnforcer`'s counter-survival mechanism as: "named nft counters
reset on ruleset replace, so BEFORE each apply, read current counters and
FOLD into a `BTreeMap<String rule_id, u64>` offsets" — i.e. it assumed
`nft -f -`'s atomic `flush table` + recreate (the shape `nft.rs::ruleset`
generates, per Task 11) zeroes each `counter r_<rule_id> {}` object's raw
value on every `apply()`, the way the eBPF backend's flat `COUNTERS` array
genuinely does get zeroed by `fold_and_reset_counters` on every generation
flip (`ebpf.rs`).

**Empirically false on this kernel/nft version** (`nft` 1.0.6). Verified
directly, outside any test file, via three hand-run `nft -f -` sequences
against a throwaway table:

1. Create a table with `counter c1 {}`, generate 3 real packets through it
   (`packets: 6` — ICMP echo request + reply both counted), then re-apply
   the byte-identical script (`flush table` + redeclare the same `counter c1
   {}`): `nft -j list counters` shows the SAME object (`handle: 3`, still
   `packets: 6`) — not reset to 0. A named counter object survives a
   `flush table` + same-name redeclare with its value intact.
2. Apply a DIFFERENT script that stops declaring `c1` at all (only declares
   a new `counter c2 {}`): after the replace, `c1` is STILL present in
   `nft -j list counters` with its old value (`packets: 6`) — `flush table`
   does not delete a counter the new ruleset simply stops mentioning. It
   becomes a permanent orphan unless explicitly `delete counter`d.
3. `delete counter ip <table> c1` while a live rule still references `c1`
   fails with `EBUSY` ("Device or resource busy"); the same command
   succeeds once the referencing rule has already been replaced out (i.e.
   after step 2's kind of apply has already committed).

**Consequence for the implementation** (`crates/wiremesh-enforcer/src/nft.rs`):
the brief's offset-accumulator design, implemented literally, double-counts
— confirmed by running `tests/nft_backend.rs`'s
`counters_survive_a_policy_reapply_via_the_offset_accumulator` (RED
evidence: expected `k1+k2=5`, got `8` — the pre-reapply reading (3) got
folded into the Rust-side offset AND the raw nft counter kept counting from
3 rather than resetting, so `3 (offset) + 5 (live, 3 old + 2 new) = 8`).
`NftEnforcer` was implemented instead relying on the ACTUAL behavior:

- No Rust-side accumulator at all. A `rule_id` maps to a stable
  `counter r_<rule_id> {}` object name; as long as a policy keeps
  redeclaring the same name, nft's own object identity carries the value
  across re-applies for free (test (e) passes on this alone).
- `apply()` additionally prunes: after the atomic replace commits (only
  after — see finding 3 above), any counter in the table whose `rule_id` is
  no longer in the newly-applied policy is deleted via a follow-up
  `nft -f -` call (`prune_retired_counters` in `nft.rs`), so a removed
  rule's counter doesn't leak forever and doesn't reappear as a phantom
  `counters()` entry — this is the nftables-backend's counterpart to the
  eBPF backend's `prune_retired_counters`/`counter_accum` pair (`ebpf.rs`),
  arrived at for a different underlying reason (nft's own persistence,
  rather than the eBPF backend's flat, generation-independent, positionally
  indexed `COUNTERS` array).
- One further syntax finding along the way: `delete counter ip <table>
  <name>` rejects a quoted string for `<name>` ("syntax error, unexpected
  quoted string, expecting handle or string") — only the bare identifier
  form works, unlike a `counter <name> {}` *declaration* inside a
  `table { .. }` block, which accepts either. `rule_id`s are hex-digest
  strings (`wiremesh_policy::compile::rule_id`), so the bare form is always
  a valid nft identifier here.

**Not a blocker, not a test-weakening situation:** test (e)'s actual
assertions (`k1=3` before re-apply, `k1+k2=5` after) are satisfied by the
corrected implementation without any change to the test. This is recorded
here per `CLAUDE.md`'s "a 'failing' behavior test may be a real finding
about the design — investigate and record it" guidance, because the
brief's premise (and this module's original doc comment, before this task's
fix) was factually wrong about nft's counter-reset behavior and a future
task reasoning from that premise would be misled.

## Task 12: (c) conntrack `related` for a PMTUD-style ICMP error — WORKS

`tests/nft_backend.rs`'s
`icmp_echo_via_explicit_rule_and_pmtud_style_embedded_error_via_related`
passed on the first implementation attempt, no changes needed to `ruleset`'s
existing `ct state established,related counter accept` line (Task 11
codegen, unchanged). This kernel/nftables' conntrack ICMP-error helper
correctly classifies a crafted ICMPv4 "destination unreachable, code 4
(fragmentation needed)" message embedding a real, established UDP flow's
exact tuple as `related` to that flow — and rejects the control message
(bogus embedded tuple) as expected. No further investigation needed; see
the task-12 report for the full test run.

## Task 12: (f) `probe()`'s real eBPF-unavailable fallback — a genuine trigger exists

The Task 12 test author's report flagged (f) as exercising only the
forced-choice `probe_with(BackendKind::Nftables, ..)`, not bare `probe()`'s
real "eBPF attempt, then nftables fallback" branch, since the privileged
dev container always has a genuinely working eBPF attach path and no
env-var/knob was found to defeat it.

A real, honest trigger exists and was verified via a throwaway
`examples/probe_fallback_check.rs` (run once, then deleted — not part of
this commit, since adding a test/example wasn't required and the test
author's own file already documents this as implementer-verified by code
inspection rather than an automated test): calling
`wiremesh_enforcer::probe("does-not-exist-9000", cfg)` against a genuinely
nonexistent interface makes `EbpfEnforcer::new`'s `SchedClassifier::attach`
call fail with `ENODEV` ("No such device") — a real eBPF failure, not a
simulated one — and `probe()` correctly logs the reason and falls back,
returning a functional `BackendKind::Nftables` enforcer:

```
wiremesh-enforcer: eBPF backend failed to load/attach on does-not-exist-9000
(attaching aeth_ingress on does-not-exist-9000 (Ingress): No such device
(os error 19)); falling back to the nftables backend (design §6/D-C3-4)
probe() succeeded, kind = Nftables
```

`probe`'s implementation (`src/lib.rs`) is expressed in terms of
`probe_with`'s two arms exactly as the test author's own doc comment on the
pre-Task-12 `probe_with` scaffold suggested.

## Task 13: RATIFIED divergence — nftables does not preserve a one-way (never-replied) UDP flow across a policy update that removes its rule; eBPF does

**Status: RATIFIED (owner decision: ACCEPT & DOCUMENT).** Originally
reported here as a genuine backend divergence found by the Task 13
conformance suite (per CLAUDE.md/the Task 13 brief — NOT fixed by the test
author, scenario NOT weakened, NEITHER backend skipped). The project owner
has since reviewed the root-cause writeup below and ruled: this is an
**accepted, understood boundary of the nftables fallback backend**, not a
bug to fix. It is now encoded as the conformance suite's one sanctioned,
documented per-backend expectation (`Step::SendExpectByBackend` in
`wiremesh-testkit/src/conformance.rs`; used exactly once, in
`crates/wiremesh-testkit/tests/conformance.rs`'s
`policy_update_under_live_traffic_flow_survives_new_conns_follow_new_policy`
scenario's middle step) rather than a suite-level failure — the suite is
22/22 green with this divergence asserted explicitly, backend-by-backend,
rather than silently ignored or papered over. The design-doc language
around "live-flow survival" (design §8/§1's done bar) is being scoped
accordingly by the owner in a separate spec amendment — this note is not
itself that amendment, just the record of the finding and its ratified
disposition.

`crates/wiremesh-testkit/tests/conformance.rs`'s
`policy_update_under_live_traffic_flow_survives_new_conns_follow_new_policy`
scenario: `a` sends one UDP datagram to `b:8000` under a policy that allows
udp/8000 (delivered — matches the rule). The policy is then updated to a v2
that allows *only* tcp/8000 (the udp/8000 allow rule is gone). The SAME
5-tuple is sent again, with no `FlushFlows` in between, and is expected to
still be **Delivered** — "live-flow survival across an update, absent an
explicit flush" (design §8/§1's done bar: "atomic policy update under live
traffic with no enforcement gap and live-flow survival"). A third Send on a
*different* 5-tuple (same dest port) is expected **Dropped**, proving the
new policy genuinely governs fresh connections.

This exact shape — a one-directional UDP flow (sender never receives a
reply) surviving a policy update that removes its allow rule, absent a
flush — is not a new invention of this task: it is *verbatim* the pattern
already established and merged in Task 9's own eBPF-only
`tests/flow_table.rs::flush_flows_forces_reevaluation_of_an_established_flow_after_its_allow_rule_is_removed`
(`a` sends udp/9600 to `b`, no reply ever sent back; v2 removes the rule;
the same 5-tuple must still pass until an explicit `flush_flows()` call).
That test is already green and treated as an accepted regression guard for
exactly this behavior on eBPF. The Task 13 conformance scenario just
restates the same, already-accepted expectation as a backend-parameterized
scenario per D-C3-7.

**Original result (before ratification/encoding): PASSES on
`BackendKind::Ebpf`, FAILS on `BackendKind::Nftables`**
(`.superpowers/sdd/task-13-tests-report.md` has the raw run that surfaced
this). After ratification, the SAME divergence is now asserted explicitly
per backend via `Step::SendExpectByBackend` (Delivered on Ebpf, Dropped on
Nftables) and both backends PASS their respective, documented expectation
— the suite is 22/22 green. Root cause, traced (not guessed):

- `NftEnforcer`'s generated ruleset (`nft.rs::ruleset`) hard-codes exactly
  one unconditional survival line: `ct state established,related counter
  accept`. It does **not** include `new`.
- Linux conntrack only classifies a UDP flow's `ct state` as `established`
  once a reply packet has been observed in the *reverse* direction (i.e.
  `seen_reply` is set on the conntrack entry). A purely one-way UDP
  flow — sender only, destination never replies, exactly what this
  scenario (and Task 9's own eBPF precedent) sends — stays in conntrack
  state `new` for every packet it ever sends, indefinitely. It never
  becomes `established`, so it never matches nft's unconditional accept
  line at all.
- Consequently, on nftables, *every* packet of a one-way UDP flow is
  re-evaluated against the explicit rule list on *every* packet (not just
  the first) — there is no fast path independent of the live rule set.
  When v2 removes the udp/8000 allow rule, the very next packet of the
  already-"established" (from the scenario's perspective) flow is
  re-evaluated fresh and denied.
- eBPF's `FLOWS` map has no such bidirectionality requirement:
  `try_ingress` inserts a `FLOWS` entry on *any* packet that matched an
  explicit `ACT_ALLOW` verdict (`program/src/main.rs`, the
  `if scan_generation(..) == ACT_ALLOW { FLOWS.insert(..) }` call site,
  unconditional on reply direction), and a later packet on the same
  5-tuple hits that entry as a fast path *before* rule evaluation runs at
  all, regardless of whether the destination ever sent anything back.
  `apply()` never touches `FLOWS` (Task 7/8 design), so the entry — and
  the flow's continued passage — survives the v2 apply untouched, exactly
  as Task 9's test already demonstrated.

**Why this is reported, not "fixed" or worked around here:** this agent's
brief is test-author-only for Task 13 (neutral scenario infrastructure); a
divergence discovered by a scenario built from an already-accepted,
already-merged precedent (Task 9's own test) is a real product finding, not
a scenario bug — unlike the FlushFlows scenario's own negative-control step
(caught and fixed *before* this report), which was testing a mechanically
different fact (`ports:` matches destination port only, so varying only the
source port on the *same* covered destination port was never going to be
denied by anything, flow-table or not — a genuine test-authoring mistake,
corrected in the same commit as this suite). This one is not that: the
scenario's expectation is exactly what design §8/§1 promises ("live-flow
survival") and exactly what Task 9's own accepted eBPF test already
encodes for the identical one-way-UDP shape; nftables' behavior for it
is what's actually inconsistent with that promise.

**Candidate fix directions considered, before ratification:** (a) broaden
nft's survival line to `ct state new,established,related accept` — but
that changes nft's semantics much more broadly than just this scenario,
since it would let *every* subsequent packet of *any* not-yet-established
flow bypass rule evaluation too (including ones that should still be
freshly re-checked against a just-changed policy — a security-relevant
behavior change, not a narrow one); or (b) accept the divergence as a
documented, bounded exception specific to one-way UDP flows without a rule
matching `related`, and scope the design doc's "live-flow survival"
language to flows nft can actually track statefully (bidirectional, or
TCP).

**Ratified decision: (b).** The project owner reviewed this writeup and
chose to accept & document the divergence rather than change nft's
survival semantics (option (a) was explicitly rejected as too broad a
security-relevant behavior change for what it would buy). The design doc's
"live-flow survival" language is being scoped accordingly in a separate
spec amendment (owner's, not this agent's). The conformance suite now
encodes this as its one sanctioned per-backend expectation — see the
"Status" paragraph at the top of this section.

## Task 13 also surfaced: nft `flush_flows` is a no-op (Task 12 deferral) — being IMPLEMENTED, not ratified as a divergence

Distinct from the one-way-UDP finding above, and NOT another ratified
divergence: reviewing `FLUSH_FLOWS_SCENARIO` found it originally had no
`ApplyPolicy` step at all, so nothing ever needed re-evaluating — it
wasn't actually testing "flush forces re-evaluation," just "flush doesn't
break currently-valid traffic." Rewritten to genuinely test it with a
bidirectional (conntrack-trackable) flow: established under an allow rule,
the rule is then removed (`ApplyPolicy` to an empty policy), the same
tuple is confirmed to still pass with NO flush (live-flow survival, both
backends — this holds because the flow is bidirectional, unlike the
ratified one-way-UDP case above), then `FlushFlows` is called and the same
tuple must now be denied.

This is currently green on `BackendKind::Ebpf` (`flush_flows` genuinely
clears `FLOWS`) and RED on `BackendKind::Nftables` at the post-flush step
(`NftEnforcer::flush_flows` is still the Task 12 no-op — the established
conntrack entry survives untouched, so the post-flush send is still
Delivered instead of the required Dropped). Unlike the one-way-UDP
finding, **this is NOT being ratified as a divergence** — flush IS
implementable on nftables via a scoped conntrack flush, and design §8 and
the master spec both promise `FlushFlows` parity for both backends. This
RED cell is being left in place deliberately, as the red-first marker for
a follow-up task to implement the real nft flush (`docs/research/`
recording it here per CLAUDE.md, same as any other genuine RED finding)
— NOT encoded via `Step::SendExpectByBackend`, since that mechanism is
reserved for ratified, permanent divergences, not temporary implementation
gaps.


## Task 12 addendum: NftEnforcer::flush_flows implemented via `conntrack -F` -- scoping investigated, whole-netns flush is the only viable mechanism found

Follow-up to the RED cell above, closing the gap: `NftEnforcer::flush_flows`
(`crates/wiremesh-enforcer/src/nft.rs`) now shells out to `conntrack -F`.
`conntrack` (the `conntrack-tools` package) was not present in the dev
container image and was added to `dev/Dockerfile`, then the image was
rebuilt (`./dev.sh build`).

**Verified empirically before wiring anything up:**

- `conntrack` only starts tracking a flow once the ruleset actually
  references `ct` somewhere in the packet's path (confirmed with a bare
  veth pair + minimal nft table: zero conntrack entries with no `ct`-
  referencing rule present; one entry, correctly bidirectional, once a
  `ct state established,related ...` line -- exactly what
  `nft.rs::ruleset` always emits -- was added). This is expected/standard
  nftables lazy-hook-registration behavior, not a container-specific
  quirk, and confirms `NftEnforcer`'s existing `ct state
  established,related counter accept` line (Task 11, unchanged) is what
  makes flows conntrack-trackable at all.
- `conntrack -F` exits 0 and reports "connection tracking table has been
  emptied" both when entries exist and when the table is already empty --
  no special-casing needed for the empty case.
- End-to-end: the real `flush_flows_forces_reevaluation_of_an_established_flow`
  conformance scenario (`crates/wiremesh-testkit/tests/conformance.rs`)
  now passes on `BackendKind::Nftables` -- full 22/22 conformance matrix
  green on both backends (`./dev.sh run "cargo test -p wiremesh-testkit
  --features netns --test conformance -- --test-threads=1 --nocapture"`).

**Scoping investigated and ruled out, in order of how close each got to
"just this fabric's flows" (the eBPF backend's actual scope):**

1. **Conntrack zone** (`ct zone set <n>` in the ruleset, then `conntrack -F
   -w <n>`): the RIGHT mechanism in principle -- a zone genuinely
   partitions the conntrack table so a zoned flush only touches that
   zone's entries. Requires `nft.rs::ruleset` (Task 11) to emit a `ct zone
   set` statement, which would change every byte-for-byte-pinned golden
   fixture under `tests/fixtures/*.nft` -- out of scope for this fix (a
   test-owned artifact), left for a future task that owns a real
   requirement to revisit that codegen.
2. **Interface:** ruled out empirically, not by scope -- `conntrack -L -o
   extended` was checked directly against a live flow and carries no
   ingress/egress-interface field at all in this tool's output. There is
   nothing to filter `conntrack -D` on by `iface`.
3. **Segment CIDRs** (`conntrack -D -s <cidr> --mask-src <mask> ...`):
   ruled out on CORRECTNESS grounds, not convenience. The exact scenario
   this fix targets re-applies a policy that removes every CIDR/rule for
   the flow that must be flushed (`ApplyPolicy { yaml: "policy: []\n" }`)
   before `FlushFlows` runs -- scoping the delete to "the CURRENTLY applied
   policy's CIDRs" would scope it to nothing, silently failing to flush
   the very flow the caller needs flushed. An enforcer-lifetime UNION of
   every CIDR ever applied would dodge that specific failure but adds
   unbounded per-instance state for a narrowing that still isn't really
   fabric-scoped (a coincidentally-reused address from unrelated,
   non-fabric traffic sharing the same netns would still be swept) --
   assessed as not worth the added complexity/state for a partial win.

**Conclusion, per explicit review sign-off:** `conntrack -F` (whole
network-namespace conntrack table) is the mechanism implemented. This is
broader than the eBPF backend's `FLOWS`-map-only scope -- it flushes ANY
conntrack entry visible in the netns the gateway process is running in,
not just entries created by fabric (`wg0`) traffic. This lines up with the
design's single-purpose-gateway model (Sec 1: "one gateway per segment," no
other workload traffic expected to share that netns) but is not a
guarantee if a real deployment ever runs other stateful traffic in the
same netns as the gateway process. Documented on
`NftEnforcer::flush_flows`'s own doc comment (`nft.rs`) as well as here,
per the review instruction that the coarser blast radius must be
documented, not hidden. Behavior parity (flush forces re-evaluation) is
achieved and verified end-to-end; blast-radius parity is not, and isn't
required.
