//! `nft` — the nftables fallback backend's pure codegen half (design §6/
//! D-C3-6; cycle 3, Task 11; `.superpowers/sdd/task-11-brief.md`).
//!
//! Task 11 Step 1 (test author): only the signature stub below exists so far
//! — [`ruleset`] is `todo!()`. The golden tests in
//! `tests/nft_codegen.rs` pin the exact generated-script shape (table/flush/
//! counters/`from_fabric` chain/base chains) that Task 11 Step 3
//! (implementer) must produce byte-for-byte against
//! `tests/fixtures/*.nft`.
//!
//! The counter-offset accumulator (`offsets: BTreeMap<String, u64>`,
//! folding live nft counters across a `flush`-and-replace `apply`) described
//! in the brief is NOT part of this pure function — it belongs to the
//! `Enforcer` trait impl (Task 12's privileged nftables backend, which
//! actually shells out to `nft -f` and reads counters back). This module's
//! only job right now is turning a [`PolicyIR`] into ruleset text.

use wiremesh_policy::PolicyIR;

/// IR → complete `nft -f` script: an atomic replace of the dedicated
/// `table ip wiremesh_<iface>` (design §6/D-C3-6). See
/// `tests/nft_codegen.rs` and `tests/fixtures/*.nft` for the exact,
/// golden-tested shape this must produce.
pub fn ruleset(ir: &PolicyIR, iface: &str) -> anyhow::Result<String> {
    let _ = (ir, iface);
    todo!("Task 11 Step 3 (implementer): IR -> nftables ruleset codegen")
}
