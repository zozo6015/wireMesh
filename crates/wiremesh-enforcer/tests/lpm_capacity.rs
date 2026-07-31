//! Backlog 10 PR-A (Cycle-3 hardening trio), test author — Item 1's
//! ENFORCER half: the load-time LPM-capacity pre-check and the
//! constant-parity pin.
//!
//! Background: `ebpf.rs`'s `build_lpm_entries` inserts one LPM-trie entry
//! per DISTINCT CIDR on each side of the flattened rule list, into a trie
//! created with `LPM_MAX_ENTRIES = 1024`
//! (`crates/wiremesh-enforcer-ebpf/common/src/lib.rs:36`). Today nothing
//! pre-checks that count — entry #1025 fails inside `apply()` as an opaque
//! `trie.insert` error. The audited fix adds a pre-check with a clear
//! message; `build_lpm_entries` itself is private (and needs no privilege
//! to compute, but plenty to reach via `apply()`), so this file pins the
//! check's PURE testable surface:
//!
//! **Pinned new API (compile-red until implemented):**
//! ```ignore
//! // wiremesh-enforcer (exported from the crate root, like `flatten`):
//! pub fn check_lpm_capacity(flat: &[FlatRule]) -> anyhow::Result<()>;
//! // wiremesh-policy (exported from the crate root):
//! pub const MAX_LPM_CIDRS_PER_SIDE: usize; // = 1024
//! ```
//! `check_lpm_capacity` is `Ok(())` iff BOTH sides' distinct-CIDR counts
//! (the exact counts `build_lpm_entries` would produce) fit in
//! `LPM_MAX_ENTRIES`; `apply()`'s eBPF path must consult it (or perform
//! the identical check) before building tries — that wiring is the
//! implementer's job and is exercised by the conformance/netns suites, not
//! here (these tests are pure and unprivileged, like `tests/flatten.rs`).
//!
//! The parity test follows the established duplicated-constant pattern
//! (`tests/flatten.rs`'s MAX_RULES notes: `wiremesh-policy` cannot depend
//! on the enforcer crates, so each side fixes the number independently and
//! a test asserts they agree).
//!
//! RED status: **compile-red** — `wiremesh_enforcer::check_lpm_capacity`
//! and `wiremesh_policy::MAX_LPM_CIDRS_PER_SIDE` do not exist yet, so this
//! whole file fails `cargo check` with unresolved imports until the fix
//! lands. Kept in its own file so the sibling runtime-red files
//! (`tests/hardening.rs`, `tests/iface_validation.rs`) still compile and
//! show their genuine runtime failures today.

use ipnet::Ipv4Net;
use wiremesh_enforcer::{check_lpm_capacity, FlatRule};
use wiremesh_enforcer_common::LPM_MAX_ENTRIES;
use wiremesh_policy::{IrAction, IrProto, MAX_LPM_CIDRS_PER_SIDE};

/// `n` distinct /32s inside 10.0.0.0/16 (n ≤ 65536).
fn slash32s(n: usize) -> Vec<Ipv4Net> {
    assert!(n <= 65_536);
    (0..n)
        .map(|i| format!("10.0.{}.{}/32", i / 256, i % 256).parse().unwrap())
        .collect()
}

/// A minimal single-port FlatRule with the given sides. Struct-literal
/// construction (fields are public), same wire-input rationale as
/// `tests/flatten.rs`'s `oversized_ir`: the enforcer must not trust that
/// whatever compiled the IR upstream enforced any limit.
fn flat_rule(idx: u32, src_cidrs: Vec<Ipv4Net>, dst_cidrs: Vec<Ipv4Net>) -> FlatRule {
    FlatRule {
        idx,
        rule_id: format!("r{idx:016}"),
        action: IrAction::Allow,
        proto: IrProto::Tcp,
        src_cidrs,
        dst_cidrs,
        port_lo: 80,
        port_hi: 80,
    }
}

fn dst_one() -> Vec<Ipv4Net> {
    vec!["10.1.0.0/16".parse().unwrap()]
}

/// The compile-time (wiremesh-policy) and load-time (eBPF common) halves
/// of the guard must fix the SAME number — the established
/// duplicated-constant contract (`flatten::MAX_RULES` ==
/// `compile.rs::MAX_RULES` == `wiremesh_enforcer_common::MAX_RULES`),
/// extended to the LPM capacity pair. Also pins the audited literal 1024
/// so both sides can't silently drift together to a value that no longer
/// matches the kernel-declared trie type without this test being updated
/// deliberately.
#[test]
fn lpm_capacity_constants_agree_across_policy_and_ebpf_common() {
    assert_eq!(
        MAX_LPM_CIDRS_PER_SIDE, LPM_MAX_ENTRIES,
        "wiremesh_policy::MAX_LPM_CIDRS_PER_SIDE must equal \
         wiremesh_enforcer_common::LPM_MAX_ENTRIES — the compile-time guard \
         exists precisely to reject what the trie would reject at load time"
    );
    assert_eq!(MAX_LPM_CIDRS_PER_SIDE, 1024, "the audited eBPF trie capacity");
}

/// Boundary: exactly `LPM_MAX_ENTRIES` distinct CIDRs on a side fills the
/// trie exactly — `Ok`. Paired with the overflow test so an off-by-one
/// pre-check is caught.
#[test]
fn check_lpm_capacity_ok_at_exactly_lpm_max_entries_distinct_cidrs() {
    let flat = vec![flat_rule(0, slash32s(LPM_MAX_ENTRIES), dst_one())];
    check_lpm_capacity(&flat).unwrap_or_else(|e| {
        panic!("exactly {LPM_MAX_ENTRIES} distinct src CIDRs must be Ok, got: {e:#}")
    });
}

/// One CIDR over capacity on the src side must be a clear, pre-insert
/// `Err` naming the 1024 limit — not the opaque trie-insert failure a
/// gateway hits today on entry #1025 deep inside `apply()`.
#[test]
fn check_lpm_capacity_errs_above_lpm_max_entries_distinct_src_cidrs() {
    let flat = vec![flat_rule(0, slash32s(LPM_MAX_ENTRIES + 1), dst_one())];
    let err = check_lpm_capacity(&flat)
        .expect_err("1025 distinct src CIDRs overflow the 1024-entry LPM trie");
    let msg = format!("{err:#}").to_lowercase();
    assert!(
        msg.contains("1024") && msg.contains("lpm") && msg.contains("src"),
        "error must clearly name the 1024 LPM capacity and the offending \
         src side, got: {msg}"
    );
}

/// Dst-side twin: the tries are per side, so the check is per side too.
#[test]
fn check_lpm_capacity_errs_above_lpm_max_entries_distinct_dst_cidrs() {
    let flat = vec![flat_rule(0, dst_one(), slash32s(LPM_MAX_ENTRIES + 1))];
    let err = check_lpm_capacity(&flat)
        .expect_err("1025 distinct dst CIDRs overflow the 1024-entry LPM trie");
    let msg = format!("{err:#}").to_lowercase();
    assert!(
        msg.contains("1024") && msg.contains("lpm") && msg.contains("dst"),
        "error must clearly name the 1024 LPM capacity and the offending \
         dst side, got: {msg}"
    );
}

/// Distinct-union semantics: `build_lpm_entries` inserts one entry per
/// DISTINCT CIDR across the whole flattened list, so two rules sharing the
/// same full-capacity CIDR list still fit exactly (1024 distinct entries,
/// not 2048). A pre-check implemented as a per-rule or summed count would
/// wrongly reject this valid input — the check must mirror
/// `build_lpm_entries`' dedup exactly.
#[test]
fn check_lpm_capacity_counts_distinct_cidrs_not_the_sum_across_rules() {
    let shared = slash32s(LPM_MAX_ENTRIES);
    let flat = vec![
        flat_rule(0, shared.clone(), dst_one()),
        flat_rule(1, shared, dst_one()),
    ];
    check_lpm_capacity(&flat).unwrap_or_else(|e| {
        panic!(
            "two rules sharing the same {LPM_MAX_ENTRIES} src CIDRs are \
             {LPM_MAX_ENTRIES} DISTINCT trie entries — must be Ok, got: {e:#}"
        )
    });
}
