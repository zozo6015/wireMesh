//! Task 13: the backend-parity conformance suite -- THIS CYCLE'S DONE BAR
//! (design §8/D-C3-7, `.superpowers/sdd/task-13-brief.md`). One scenario
//! table, executed against BOTH backends in an identical netns topology; a
//! scenario passes only if BOTH backends agree with its expectation --
//! with exactly ONE sanctioned, ratified exception (owner decision: ACCEPT
//! & DOCUMENT), in `POLICY_UPDATE_LIVE_TRAFFIC_STEPS` below, via
//! `Step::SendExpectByBackend`. See that step's own comment,
//! `Step::SendExpectByBackend`'s doc comment
//! (`wiremesh-testkit/src/conformance.rs`), and
//! `docs/research/cycle3-policy-notes.md`'s "Task 13" section for the full
//! writeup. Every OTHER scenario/step in `SCENARIOS` must keep asserting a
//! single `Expect` both backends satisfy identically -- this is not a
//! precedent for casually branching on `kind` elsewhere.
//!
//! **`FLUSH_FLOWS_SCENARIO` (design §8/the master spec's "FlushFlows forces
//! re-evaluation" promise) is a regular, both-backends-must-agree
//! scenario** -- NOT a `SendExpectByBackend` exception. It was briefly
//! RED on `BackendKind::Nftables` (`NftEnforcer::flush_flows` was a Task
//! 12 no-op deferral, left as a deliberate red-first marker), and is now
//! green on both: `NftEnforcer::flush_flows` runs `conntrack -F`, forcing
//! every established fabric flow back to `ct state new` so it's
//! re-evaluated against the live ruleset on its next packet, matching
//! eBPF's `FLOWS`-clearing behavior. See that scenario's own header
//! comment and `docs/research/cycle3-policy-notes.md`'s "Task 13" section
//! for the fix's history.
//!
//! Deliberately a single `#[test]` fn (not one `#[test]` per scenario):
//! `SCENARIOS` and [`flip_under_traffic_zero_loss`] both need a fresh
//! `wg_lab` per run, and this crate's netns tests are already required to
//! run serially (`CLAUDE.md`: `--test-threads=1`) -- a single fn iterating
//! `[Ebpf, Nftables] × SCENARIOS` (plus the two
//! `flip_under_traffic_zero_loss` calls) prints one full pass/fail matrix
//! under `--nocapture` and fails loudly (via a final `assert!`) listing
//! every divergence, rather than needing 2×N separately-named `#[test]`
//! fns that `cargo test`'s summary would report individually anyway.
//!
//! Run: `./dev.sh run "cargo test -p wiremesh-testkit --features netns \
//! --test conformance -- --test-threads=1 --nocapture"`.

use wiremesh_enforcer::BackendKind;
use wiremesh_testkit::conformance::{
    ep, flip_under_traffic_zero_loss, run_scenario, Expect, L4, Node, Scenario, Step,
};

const SEG_AB: &[(&str, &[&str])] = &[("seg-a", &["10.10.0.1/32"]), ("seg-b", &["10.10.0.2/32"])];

// --- 1. first-match allow/deny + carve-out ---------------------------------

const FIRST_MATCH_STEPS: &[Step] = &[
    Step::Send {
        from: ep(Node::A, 0),
        to: ep(Node::B, 22),
        proto: L4::Tcp,
        expect: Expect::Dropped,
    },
    Step::Send {
        from: ep(Node::A, 0),
        to: ep(Node::B, 80),
        proto: L4::Tcp,
        expect: Expect::Delivered,
    },
];

const FIRST_MATCH_SCENARIO: Scenario = Scenario {
    name: "first_match_allow_deny_carve_out",
    policy_yaml: "
policy:
  - from: seg-a
    to: seg-b
    rules:
      - deny:
          proto: tcp
          ports: [22]
      - allow:
          proto: tcp
",
    segments: SEG_AB,
    steps: FIRST_MATCH_STEPS,
};

// --- 2. default deny: no block for the pair, then a block with no matching
//        rule -----------------------------------------------------------

const DEFAULT_DENY_STEPS: &[Step] = &[
    // Phase 1: policy_yaml below has ZERO blocks at all.
    Step::Send {
        from: ep(Node::A, 0),
        to: ep(Node::B, 1234),
        proto: L4::Tcp,
        expect: Expect::Dropped,
    },
    // Phase 2: a block exists for (seg-a, seg-b), but its only rule is for
    // udp/9500 -- an unrelated tcp connect still falls through to default
    // deny (proves it's genuinely "no matching rule", not "no block").
    Step::ApplyPolicy {
        yaml: "
policy:
  - from: seg-a
    to: seg-b
    rules:
      - allow:
          proto: udp
          ports: [9500]
",
    },
    Step::Send {
        from: ep(Node::A, 0),
        to: ep(Node::B, 1234),
        proto: L4::Tcp,
        expect: Expect::Dropped,
    },
];

const DEFAULT_DENY_SCENARIO: Scenario = Scenario {
    name: "default_deny_no_block_then_no_matching_rule",
    policy_yaml: "policy: []\n",
    segments: SEG_AB,
    steps: DEFAULT_DENY_STEPS,
};

// --- 3. stateful reply, both directions -------------------------------------

const STATEFUL_REPLY_STEPS: &[Step] = &[
    // b "initiates" (always-unfiltered egress from b) -- seeds a
    // conntrack/FLOWS entry for the (b:6000 -> a:7000) tuple. Trivially
    // Delivered either way (b's egress is never filtered), but its real
    // purpose is the side effect.
    Step::Send {
        from: ep(Node::B, 6000),
        to: ep(Node::A, 7000),
        proto: L4::Udp,
        expect: Expect::Delivered,
    },
    // a's reply on the EXACT reverse tuple must pass b's ingress via
    // established/related, despite the active policy (empty) having no
    // rule allowing it at all.
    Step::Send {
        from: ep(Node::A, 7000),
        to: ep(Node::B, 6000),
        proto: L4::Udp,
        expect: Expect::Delivered,
    },
    // Negative control: an unrelated tuple, never preceded by any
    // b-initiated traffic, must still be denied -- proves the pass above
    // was really about the established state, not a secretly-permissive
    // empty policy.
    Step::Send {
        from: ep(Node::A, 7001),
        to: ep(Node::B, 6001),
        proto: L4::Udp,
        expect: Expect::Dropped,
    },
];

const STATEFUL_REPLY_SCENARIO: Scenario = Scenario {
    name: "stateful_reply_both_directions",
    policy_yaml: "policy: []\n",
    segments: SEG_AB,
    steps: STATEFUL_REPLY_STEPS,
};

// --- 4. ICMP echo allowed by an explicit rule -------------------------------

const ICMP_ECHO_STEPS: &[Step] = &[
    Step::Send { from: ep(Node::A, 0), to: ep(Node::B, 0), proto: L4::Icmp, expect: Expect::Delivered },
    Step::ApplyPolicy { yaml: "policy: []\n" },
    Step::Send { from: ep(Node::A, 0), to: ep(Node::B, 0), proto: L4::Icmp, expect: Expect::Dropped },
];

const ICMP_ECHO_SCENARIO: Scenario = Scenario {
    name: "icmp_echo_allowed_by_explicit_rule",
    policy_yaml: "
policy:
  - from: seg-a
    to: seg-b
    rules:
      - allow:
          proto: icmp
",
    segments: SEG_AB,
    steps: ICMP_ECHO_STEPS,
};

// --- 5. ICMP embedded-error (frag-needed) passes for a recorded flow, and
//        is dropped for a bogus one -- despite the active policy having
//        ZERO icmp rules ------------------------------------------------

const ICMP_EMBEDDED_ERROR_STEPS: &[Step] = &[
    // Seed a real flow: b -> a on (6100, 7100). Always-unfiltered egress.
    Step::Send {
        from: ep(Node::B, 6100),
        to: ep(Node::A, 7100),
        proto: L4::Udp,
        expect: Expect::Delivered,
    },
    // A crafted frag-needed message from a to b, embedding the REAL flow's
    // tuple (b's port 6100 as embedded src, a's port 7100 as embedded dst)
    // -- must pass via `related`, despite zero icmp rules being active.
    Step::Send {
        from: ep(Node::A, 0),
        to: ep(Node::B, 0),
        proto: L4::IcmpFragNeeded { embedded_src_port: 6100, embedded_dst_port: 7100 },
        expect: Expect::Delivered,
    },
    // Same shape, but embedding a tuple that was NEVER a real flow -- must
    // be denied (default-deny still holds for anything not `related`).
    Step::Send {
        from: ep(Node::A, 0),
        to: ep(Node::B, 0),
        proto: L4::IcmpFragNeeded { embedded_src_port: 6101, embedded_dst_port: 7101 },
        expect: Expect::Dropped,
    },
];

const ICMP_EMBEDDED_ERROR_SCENARIO: Scenario = Scenario {
    name: "icmp_embedded_error_passes_for_recorded_flow_only",
    // Zero icmp rules anywhere -- proves any pass above is genuinely via
    // `related`, not an explicit rule. The tcp/9443 rule just proves the
    // policy isn't accidentally empty/default-permissive.
    policy_yaml: "
policy:
  - from: seg-a
    to: seg-b
    rules:
      - allow:
          proto: tcp
          ports: [9443]
",
    segments: SEG_AB,
    steps: ICMP_EMBEDDED_ERROR_STEPS,
};

// --- 6. policy update under live allowed traffic: the established flow
//        survives (no flush!) on eBPF; a NEW 4-tuple immediately follows
//        the new (now-denying) policy on BOTH backends -----------------
//
// RATIFIED divergence (owner decision: ACCEPT & DOCUMENT -- see
// `docs/research/cycle3-policy-notes.md`'s "Task 13" section, and
// `Step::SendExpectByBackend`'s own doc comment in
// `wiremesh-testkit/src/conformance.rs`): the middle Send below is a
// ONE-WAY UDP flow (b/A never receives any reply from b/B) -- exactly the
// shape already established and merged, eBPF-only, in Task 9's
// `tests/flow_table.rs::flush_flows_forces_reevaluation_of_an_established_flow_after_its_allow_rule_is_removed`.
// Linux conntrack only classifies a UDP flow `established` after it has
// seen a REPLY in the reverse direction; a purely one-way flow stays
// `new` forever, so nftables' unconditional `ct state established,related
// accept` line never covers it -- every packet of a one-way flow is
// re-evaluated against the LIVE rule set on nftables, while eBPF's
// `FLOWS` fast-path map records ANY previously-allowed packet
// (direction-agnostic) and is untouched by `apply()`. This is therefore
// the ONE step in this whole suite with a per-backend expectation
// (`Step::SendExpectByBackend`) -- both the first Send (Delivered on
// both) and the third Send (a genuinely different 4-tuple, Dropped on
// both) keep asserting one shared `Expect`, because "new connections
// follow new policy" holds identically on both backends and must stay
// asserted for both.
const POLICY_UPDATE_LIVE_TRAFFIC_STEPS: &[Step] = &[
    // Establish a flow under v1 (allow udp/8000).
    Step::Send {
        from: ep(Node::A, 9000),
        to: ep(Node::B, 8000),
        proto: L4::Udp,
        expect: Expect::Delivered,
    },
    // v2 removes the udp/8000 allow rule entirely (default deny for it).
    Step::ApplyPolicy {
        yaml: "
policy:
  - from: seg-a
    to: seg-b
    rules:
      - allow:
          proto: tcp
          ports: [8000]
",
    },
    // SAME 4-tuple as the first Send, no FlushFlows in between. eBPF:
    // FLOWS fast-path untouched by apply() -- still Delivered. Nftables:
    // this one-way flow never reached conntrack's `established` state (no
    // reply was ever sent back), so it's re-evaluated against v2 (which no
    // longer allows udp/8000) and Dropped. See this block's comment above
    // and `docs/research/cycle3-policy-notes.md` for the full, ratified
    // writeup -- this is the suite's single sanctioned per-backend step.
    Step::SendExpectByBackend {
        from: ep(Node::A, 9000),
        to: ep(Node::B, 8000),
        proto: L4::Udp,
        ebpf: Expect::Delivered,
        nftables: Expect::Dropped,
    },
    // A DIFFERENT 4-tuple (new source port) on the SAME dest port has no
    // established state to fall back on for EITHER backend -- it's freshly
    // evaluated against v2, which now denies udp/8000 entirely. Both
    // backends must agree here: this is what actually proves "new
    // connections follow new policy".
    Step::Send {
        from: ep(Node::A, 9001),
        to: ep(Node::B, 8000),
        proto: L4::Udp,
        expect: Expect::Dropped,
    },
];

const POLICY_UPDATE_LIVE_TRAFFIC_SCENARIO: Scenario = Scenario {
    name: "policy_update_under_live_traffic_flow_survives_new_conns_follow_new_policy",
    policy_yaml: "
policy:
  - from: seg-a
    to: seg-b
    rules:
      - allow:
          proto: udp
          ports: [8000]
",
    segments: SEG_AB,
    steps: POLICY_UPDATE_LIVE_TRAFFIC_STEPS,
};

// --- 7. FlushFlows genuinely forces re-evaluation -- NOT a ratified
//        divergence (unlike scenario #6's one-way-UDP step): design §8 and
//        the master spec promise FlushFlows parity on BOTH backends, and
//        that promise is now met -- `NftEnforcer::flush_flows` runs
//        `conntrack -F`, forcing every established fabric flow back to
//        `ct state new` so it's re-evaluated against the live ruleset on
//        its next packet, matching eBPF's `FLOWS`-clearing behavior. This
//        scenario is a regular, both-backends-must-agree scenario -- it
//        was briefly RED on `BackendKind::Nftables` at its post-flush step
//        (the no-op flush left the flow's conntrack entry untouched) as a
//        deliberate red-first marker before the real nft flush was wired
//        up; that gap is now closed and both backends pass identically.
//        See `conformance.rs`'s module doc comment and
//        `docs/research/cycle3-policy-notes.md`'s "Task 13" section for
//        the fix's history.
//
//        BIDIRECTIONAL flow, deliberately NOT one-way UDP (contrast with
//        scenario #6's `SendExpectByBackend` step, which is a RATIFIED
//        divergence specifically because it's one-way): this scenario
//        needs "the same tuple is still Delivered immediately after v2's
//        apply(), before any flush" to hold identically on BOTH backends
//        (steps 3-4 below) -- that's only true on nftables if the flow has
//        genuinely reached conntrack's `established` state, which requires
//        a reply to have been observed in the reverse direction. So: `a`
//        sends first (matches v1's explicit allow rule), THEN `b` replies
//        on the exact reverse tuple (b's egress is always unfiltered, so
//        this always succeeds -- but it's what marks the SAME conntrack
//        entry `seen_reply`, i.e. genuinely `established`, not just `new`).
//        Only once that's established does "flush is the ONLY thing that
//        can force re-evaluation" become a fair, apples-to-apples question
//        for both backends. ------------------------------------------------

const FLUSH_FLOWS_STEPS: &[Step] = &[
    // 1. `a` establishes the flow under v1's allow rule (matches the
    //    explicit rule -- not yet relying on any statefulness).
    Step::Send {
        from: ep(Node::A, 9200),
        to: ep(Node::B, 8200),
        proto: L4::Udp,
        expect: Expect::Delivered,
    },
    // 2. `b` replies on the EXACT reverse tuple. Trivially Delivered
    //    either way (b's egress is never filtered) -- its real purpose is
    //    the side effect: this is what makes the SAME conntrack entry
    //    bidirectionally-`established`, not just `new`, on nftables.
    Step::Send {
        from: ep(Node::B, 8200),
        to: ep(Node::A, 9200),
        proto: L4::Udp,
        expect: Expect::Delivered,
    },
    // 3. v2 removes udp/8200's allow rule entirely (no block at all).
    Step::ApplyPolicy { yaml: "policy: []\n" },
    // 4. SAME tuple as step 1, no flush yet: must still be Delivered on
    //    BOTH backends -- eBPF's FLOWS entry is untouched by apply(); on
    //    nftables this flow is now genuinely `ct state established`
    //    (thanks to step 2's reply), so it passes via the unconditional
    //    `ct state established,related accept` line regardless of v2
    //    having no rule for it at all. This is the "live-flow survival"
    //    guarantee, asserted identically for both backends here (contrast
    //    with scenario #6, where the flow was deliberately one-way and so
    //    this exact step is where the ratified divergence lives instead).
    Step::Send {
        from: ep(Node::A, 9200),
        to: ep(Node::B, 8200),
        proto: L4::Udp,
        expect: Expect::Delivered,
    },
    Step::FlushFlows,
    // 5. SAME tuple, AFTER flush: must now be Dropped on BOTH backends --
    //    flush forced re-evaluation against v2 (which has no rule for this
    //    traffic at all). Nftables: `NftEnforcer::flush_flows`'s
    //    `conntrack -F` drops the flow's `ct state` back to `new`, so it's
    //    re-evaluated against v2 and denied. Ebpf: `flush_flows` clears
    //    the `FLOWS` fast-path entry, forcing the same re-evaluation.
    Step::Send {
        from: ep(Node::A, 9200),
        to: ep(Node::B, 8200),
        proto: L4::Udp,
        expect: Expect::Dropped,
    },
    // Control: an unrelated, never-established tuple (different dest port,
    // never covered by any rule at any point in this scenario) stays
    // denied throughout -- flush doesn't accidentally open the gate for
    // everything.
    Step::Send {
        from: ep(Node::A, 9201),
        to: ep(Node::B, 8201),
        proto: L4::Udp,
        expect: Expect::Dropped,
    },
];

const FLUSH_FLOWS_SCENARIO: Scenario = Scenario {
    name: "flush_flows_forces_reevaluation_of_an_established_flow",
    policy_yaml: "
policy:
  - from: seg-a
    to: seg-b
    rules:
      - allow:
          proto: udp
          ports: [8200]
",
    segments: SEG_AB,
    steps: FLUSH_FLOWS_STEPS,
};

// --- 8. counter stability across an update that keeps one rule and changes
//        another --------------------------------------------------------

const COUNTER_STABILITY_STEPS: &[Step] = &[
    // Two hits on ruleA (tcp/9200, kept verbatim across the update).
    Step::Send { from: ep(Node::A, 0), to: ep(Node::B, 9200), proto: L4::Tcp, expect: Expect::Delivered },
    Step::Send { from: ep(Node::A, 0), to: ep(Node::B, 9200), proto: L4::Tcp, expect: Expect::Delivered },
    // One hit on ruleB (udp/9300, about to change in v2).
    Step::Send { from: ep(Node::A, 9310), to: ep(Node::B, 9300), proto: L4::Udp, expect: Expect::Delivered },
    Step::ExpectCounter { rule_id_of: ("seg-a->seg-b", 0, 0), min: 2 },
    Step::ExpectCounter { rule_id_of: ("seg-a->seg-b", 0, 1), min: 1 },
    // v2: ruleA's text is byte-identical (same rule_id); ruleB's port
    // changes 9300 -> 9301 (a genuinely different rule_id).
    Step::ApplyPolicy {
        yaml: "
policy:
  - from: seg-a
    to: seg-b
    rules:
      - allow:
          proto: tcp
          ports: [9200]
      - allow:
          proto: udp
          ports: [9301]
",
    },
    // ruleA hit once more post-update -- its counter must be CUMULATIVE
    // (old + new), proving it survived the update keyed by rule_id.
    Step::Send { from: ep(Node::A, 0), to: ep(Node::B, 9200), proto: L4::Tcp, expect: Expect::Delivered },
    // ruleB' (new rule_id) still functions normally on its new port.
    Step::Send { from: ep(Node::A, 9311), to: ep(Node::B, 9301), proto: L4::Udp, expect: Expect::Delivered },
    Step::ExpectCounter { rule_id_of: ("seg-a->seg-b", 0, 0), min: 3 },
    Step::ExpectCounter { rule_id_of: ("seg-a->seg-b", 0, 1), min: 1 },
];

const COUNTER_STABILITY_SCENARIO: Scenario = Scenario {
    name: "counter_stability_across_update_keeping_one_rule_changing_another",
    policy_yaml: "
policy:
  - from: seg-a
    to: seg-b
    rules:
      - allow:
          proto: tcp
          ports: [9200]
      - allow:
          proto: udp
          ports: [9300]
",
    segments: SEG_AB,
    steps: COUNTER_STABILITY_STEPS,
};

// --- 9. ports-range edge: lo, hi, single port -------------------------------

const PORTS_RANGE_EDGE_STEPS: &[Step] = &[
    Step::Send { from: ep(Node::A, 0), to: ep(Node::B, 8000), proto: L4::Tcp, expect: Expect::Delivered }, // lo
    Step::Send { from: ep(Node::A, 0), to: ep(Node::B, 8010), proto: L4::Tcp, expect: Expect::Delivered }, // hi
    Step::Send { from: ep(Node::A, 0), to: ep(Node::B, 8005), proto: L4::Tcp, expect: Expect::Delivered }, // mid
    Step::Send { from: ep(Node::A, 0), to: ep(Node::B, 7999), proto: L4::Tcp, expect: Expect::Dropped }, // just below lo
    Step::Send { from: ep(Node::A, 0), to: ep(Node::B, 8011), proto: L4::Tcp, expect: Expect::Dropped }, // just above hi
    Step::Send { from: ep(Node::A, 0), to: ep(Node::B, 9000), proto: L4::Tcp, expect: Expect::Delivered }, // single port
    Step::Send { from: ep(Node::A, 0), to: ep(Node::B, 9001), proto: L4::Tcp, expect: Expect::Dropped }, // adjacent to single port
];

const PORTS_RANGE_EDGE_SCENARIO: Scenario = Scenario {
    name: "ports_range_edge_lo_hi_and_single_port",
    policy_yaml: r#"
policy:
  - from: seg-a
    to: seg-b
    rules:
      - allow:
          proto: tcp
          ports: ["8000-8010", 9000]
"#,
    segments: SEG_AB,
    steps: PORTS_RANGE_EDGE_STEPS,
};

// --- 10. proto `any` matches EXACTLY tcp+udp+icmp -- not literally every IP
//         protocol (design §4: proto-any = "tcp+udp+icmp", a closed set,
//         not "no protocol restriction at the IP layer"). The positive half
//         (tcp/udp/icmp all Delivered) was already covered; the negative
//         half -- a non-{tcp,udp,icmp} IP protocol (GRE, 47, chosen as the
//         natural example) must still fall through to default-deny even
//         under a proto-any allow rule covering the same CIDRs -- was NOT,
//         and that gap hid a real cross-backend bug: nftables' codegen
//         explodes `any` into exactly {tcp, udp, icmp} (correct), but the
//         eBPF backend's flattened rule stores `proto == 0`, and the
//         kernel-side `meta_matches` treats a stored proto of `0` as
//         "match every IP protocol" (an eBPF-only over-match, not a shared
//         IR/compiler bug -- `wiremesh_policy::compile` produces the same
//         `IrProto::Any` either way). This is a genuine parity requirement
//         (GRE must be Dropped on BOTH backends) -- NOT expressed via
//         `Step::SendExpectByBackend`, unlike the ratified one-way-UDP
//         case. See `docs/research/cycle3-policy-notes.md`'s "Task 13"
//         section for the root-cause writeup. ------------------------------

const PROTO_ANY_STEPS: &[Step] = &[
    Step::Send { from: ep(Node::A, 0), to: ep(Node::B, 5000), proto: L4::Tcp, expect: Expect::Delivered },
    Step::Send { from: ep(Node::A, 5001), to: ep(Node::B, 5002), proto: L4::Udp, expect: Expect::Delivered },
    Step::Send { from: ep(Node::A, 0), to: ep(Node::B, 0), proto: L4::Icmp, expect: Expect::Delivered },
    // GRE (IP protocol 47): proto-any means tcp+udp+icmp ONLY -- this must
    // be denied on BOTH backends, falling through to default-deny.
    Step::Send { from: ep(Node::A, 0), to: ep(Node::B, 0), proto: L4::RawIpProto(47), expect: Expect::Dropped },
];

const PROTO_ANY_SCENARIO: Scenario = Scenario {
    name: "proto_any_matches_tcp_udp_icmp_only_not_every_ip_protocol",
    // No `proto:`/`ports:` at all -- compiles to IrProto::Any, unrestricted
    // ports (design §4: omitted proto defaults to tcp+udp+icmp).
    policy_yaml: "
policy:
  - from: seg-a
    to: seg-b
    rules:
      - allow: {}
",
    segments: SEG_AB,
    steps: PROTO_ANY_STEPS,
};

/// The full scenario table (design §8/D-C3-7). "flip-under-traffic
/// zero-loss" is deliberately NOT in this list -- see
/// [`flip_under_traffic_zero_loss`]'s doc comment for why it's a separate,
/// non-`Scenario` conformance check driven directly below instead.
static SCENARIOS: &[Scenario] = &[
    FIRST_MATCH_SCENARIO,
    DEFAULT_DENY_SCENARIO,
    STATEFUL_REPLY_SCENARIO,
    ICMP_ECHO_SCENARIO,
    ICMP_EMBEDDED_ERROR_SCENARIO,
    POLICY_UPDATE_LIVE_TRAFFIC_SCENARIO,
    FLUSH_FLOWS_SCENARIO,
    COUNTER_STABILITY_SCENARIO,
    PORTS_RANGE_EDGE_SCENARIO,
    PROTO_ANY_SCENARIO,
];

const BACKENDS: &[BackendKind] = &[BackendKind::Ebpf, BackendKind::Nftables];

/// D-C3-7: "one scenario table ... executes against each backend in an
/// identical netns topology; a scenario passes only if both backends agree
/// with the expectation." Runs the full `[Ebpf, Nftables] × SCENARIOS`
/// matrix (plus `flip_under_traffic_zero_loss` per backend), printing a
/// PASS/FAIL line per cell as it goes (`--nocapture`), and fails at the end
/// listing every cell that didn't pass -- a single failing cell for a
/// scenario that passed on the OTHER backend is exactly the "divergence"
/// this suite exists to catch.
#[test]
fn backend_parity_conformance_suite() {
    let mut failures: Vec<String> = Vec::new();

    for &kind in BACKENDS {
        for scenario in SCENARIOS {
            let result = run_scenario(scenario, kind);
            match &result {
                Ok(()) => println!("PASS  {kind:?}  {}", scenario.name),
                Err(e) => {
                    println!("FAIL  {kind:?}  {}: {e:#}", scenario.name);
                    failures.push(format!("{kind:?} / {}: {e:#}", scenario.name));
                }
            }
        }

        let flip_result = flip_under_traffic_zero_loss(kind);
        match &flip_result {
            Ok(()) => println!("PASS  {kind:?}  flip_under_traffic_zero_loss"),
            Err(e) => {
                println!("FAIL  {kind:?}  flip_under_traffic_zero_loss: {e:#}");
                failures.push(format!("{kind:?} / flip_under_traffic_zero_loss: {e:#}"));
            }
        }
    }

    let total_cells = BACKENDS.len() * (SCENARIOS.len() + 1);
    println!(
        "\n{} / {total_cells} cells passed ({} backend(s) × {} scenario(s), incl. \
         flip_under_traffic_zero_loss)",
        total_cells - failures.len(),
        BACKENDS.len(),
        SCENARIOS.len() + 1
    );

    assert!(
        failures.is_empty(),
        "backend-parity conformance suite has {} failing cell(s) -- a divergence between \
         backends on an otherwise-identical scenario is a real parity finding, not a flaky test:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
