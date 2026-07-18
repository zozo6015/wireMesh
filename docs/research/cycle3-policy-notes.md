# Cycle 3 (Policy Pipeline) — Research Notes

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

## Task 13: REAL parity bug — nftables does not preserve a one-way (never-replied) UDP flow across a policy update that removes its rule; eBPF does

**Status: genuine backend divergence, reported per CLAUDE.md/the Task 13
brief — NOT fixed here (test author scope), scenario NOT weakened, NEITHER
backend skipped.**

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

**Result: PASSES on `BackendKind::Ebpf`, FAILS on `BackendKind::Nftables`**
(`docs/superpowers/sdd/task-13-tests-report.md` has the raw run). Root
cause, traced (not guessed):

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

**Candidate fix directions (for whoever picks this up — not decided or
implemented here):** (a) broaden nft's survival line to `ct state new,
established,related accept` — but that changes nft's semantics much more
broadly than just this scenario, since it would let *every* subsequent
packet of *any* not-yet-established flow bypass rule evaluation too
(including ones that should still be freshly re-checked against a
just-changed policy — a security-relevant behavior change, not a narrow
one); or (b) accept the divergence as a documented, bounded exception
specific to one-way UDP flows without a rule matching `related`, and adjust
the design doc's "live-flow survival" language to scope it to flows nft can
actually track statefully (bidirectional, or TCP). Either way this needs a
design-level decision, not a silent backend patch.
