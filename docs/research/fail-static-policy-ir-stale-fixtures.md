# `fail_static_policy_ir` has been red since the item-23 pubkey filter — stale fixtures, not a defect

**Found:** 2026-08-26, by the first CI run that compiled `crates/wiremesh-gateway`'s
non-netns integration targets (Phase B, PR3).
**Red since:** `f4a9c87` — *"fix: filter undecodable peer pubkeys and malformed
allowed_ips (items 23, 24)"*, 2026-08-10. First release carrying it: **v0.8.0**
(2026-08-10). Still red at **v0.11.0** (2026-08-26).
**Verdict:** **fixture rot in the test, not a defect in the code.** The filter is the
ratified backlog-item-23 ingress validation and stays exactly as it is; the *fixture*
keys `"PUB2"`/`"PUB3"` were never WireGuard key material. The fix is a fixture
correction: **no assertion, tolerance, or expected value changes.**

> Recorded before touching anything, per the project rule that a failing behaviour test
> may be a real finding about the design. It is not one here — and the reason it is not
> was already written down on the day the filter landed
> (`docs/research/gateway-key-filter-placement.md`), for the six *unit* tests that broke
> the same way in the same commit. This is the seventh through tenth case of the same
> rot, in the one target nothing compiled.

## What fails

Four tests in `crates/wiremesh-gateway/tests/fail_static_policy_ir.rs`:

| Test | Line |
|---|---|
| `a_decodable_ir_is_persisted_verbatim` | :345 |
| `substitution_preserves_peers_relays_serials_and_revision` | :473 |
| `the_no_prior_good_fallback_also_preserves_the_device_half` | :498 |
| `byte_identical_resaves_are_persisted_verbatim` | :635 |

All four are whole-struct round-trip assertions: save a `DesiredState` through
`FailStaticWriter`, load `state.json` back, `assert_eq!` the loaded state against the
one that went in (with only the `(policy_version, policy_ir)` pair adjusted, where the
test is about substitution). They fail on the peer half, not on the policy half:

```text
assertion `left == right` failed: a decodable snapshot must reach disk unchanged
  left:  DesiredState { … peers: [PeerState { gateway_id: 2, …, active_pubkey_b64: None,  … },
                                 PeerState { gateway_id: 3, …, active_pubkey_b64: None,  … }] … }
  right: DesiredState { … peers: [PeerState { gateway_id: 2, …, active_pubkey_b64: Some("PUB2"), … },
                                 PeerState { gateway_id: 3, …, active_pubkey_b64: Some("PUB3"), … }] … }
```

`byte_identical_resaves_are_persisted_verbatim` fires on the first loop iteration
(`revision 12: persisted verbatim`); the two substitution tests fire on their
`expected` comparison, which clones the *input* state and so carries `Some("PUB2")`
while the loaded state carries `None`. The other 20-odd tests in the file are green —
they assert on `policy_version`/`policy_ir`/`warned_version()` only and never compare
the peer half.

## Mechanism

`f4a9c87` added to `crates/wiremesh-gateway/src/state.rs`:

```rust
/// `#[serde(deserialize_with)]` shim for [`PeerState::active_pubkey_b64`] …
fn deserialize_valid_active_pubkey<'de, D>(d: D) -> Result<Option<String>, D::Error> {
    let raw = Option::<String>::deserialize(d)?;
    Ok(raw.filter(|k| crate::uapi::pubkey_b64_to_hex(k).is_some()))
}
```

wired to the field as `#[serde(default, deserialize_with = "deserialize_valid_active_pubkey")]`
(`state.rs:283`). `uapi::pubkey_b64_to_hex` requires base64 that decodes to **exactly
32 bytes**; `"PUB2"` decodes to 3 bytes, so it is filtered to `None` on the way in.

That is the field's documented invariant, and it is deliberately enforced at **both**
doors — `PeerState::from_proto` for what the controller advertises, and
`deserialize_with` for what is read back off disk. The disk door is the load-bearing
one: `DesiredState::load` is a bare `serde_json::from_slice`, and an undecodable active
key reaching `encode_set` at boot is peer-fatal at the UAPI. Removing or relaxing the
shim to make these tests pass would reopen exactly the hole item 23 closed, in the
fail-static boot path — the worst place for it.

So the code is right. The *fixture* is wrong: `rich_state()` (:98) builds two peers with
`active_pubkey_b64: Some("PUB2")` / `Some("PUB3")`, placeholders chosen in `bfd132b`
(2026-08-04) when nothing validated key content. They were never valid WireGuard keys;
they were legible stand-ins in a test that is about **policy IR bytes**, where the peer
half exists only to prove substitution does not eat it.

## Why it went unnoticed for 12 published releases (13 tags; v0.10.0 was tagged but never published) across 16 days

Three belts, and this target is in none of them:

1. **`cargo test -p wiremesh-gateway --lib`** — what `f4a9c87` itself was verified
   against (107 passed, 6 failed → 6 fixtures corrected; see
   `gateway-key-filter-placement.md`). `--lib` compiles the crate's unit tests only.
   `tests/*.rs` integration targets are never built.
2. **`cargo test -p wiremesh-gateway --features netns-tests`** — the data-plane
   done-bars. `fail_static_policy_ir.rs` is explicitly **PURE** (its module doc:
   "no netns, no privileges, no sockets"), so it is not in this set either.
3. **CI** — `.github/workflows/` holds `codeql.yml`, `container-images.yml` and
   `release.yml`. **No workflow invokes `cargo test`** (README:81 says so outright, and
   calls it a tracked 1.0 blocker).

`cargo test -p wiremesh-gateway` with no target flag — which builds every `tests/*.rs`
— was the missing run. Between v0.8.0 and v0.11.0 that is **12 published releases
(13 tags; v0.10.0 was tagged but never published) across 16 days** in which a red test
shipped unobserved — v0.8.0, v0.9.0, v0.9.1, v0.9.2, v0.10.1–v0.10.7, v0.11.0 on
`gh release list`, with the v0.10.0 tag having no release attached. The six *unit* fixtures broken by the same commit were caught
the same afternoon, because `--lib` was run. Same rot, same day, same author — only the
belt differed.

The generalized lesson is already in the session memory as *"non-netns integration
tests were in no belt"*: run `cargo test -p <crate>` (all targets) for every crate you
touch until CI covers it.

## The fix, and why it is a correction rather than a weakening

Replace the two placeholder literals in `rich_state()` with genuinely decodable
WireGuard-shaped keys — base64 of 32 repeated bytes, the same construction the
`state.rs` unit-test module adopted in `f4a9c87` (`VALID_KEY_AA`/`_BB`/`_CC`):

| Peer | Was | Now | Constant |
|---|---|---|---|
| `gateway_id: 2` | `"PUB2"` | `"3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d0="` (0xDD ×32) | `VALID_KEY_DD` |
| `gateway_id: 3` | `"PUB3"` | `"7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u4="` (0xEE ×32) | `VALID_KEY_EE` |

Distinct keys, so the "persisted verbatim" assertions still discriminate the two peers:
swapping the peers' keys, or collapsing either to `None`, still fails every one of the
four tests. Nothing else in the file changes — not an assertion, not a message, not an
expected value, not a `save`/`load` call.

**This is not arranging the test to match the code.** The property under test —
*"a decodable snapshot must reach disk unchanged"*, and its substitution siblings — is
asserted at full strength, on a `DesiredState` whose peer half is now *more* realistic
than it was: a real gateway never holds an active pubkey that is not 32 bytes of base64,
because `from_proto` filters it at ingest. The old fixture asserted round-trip fidelity
for a state the gateway cannot be in. The new one asserts it for a state it can.

What the four tests would have to be doing for the placeholder to be load-bearing is
asserting that an *undecodable* key survives the round trip — the opposite of item 23,
and not what any of them says. They are named `*_persisted_verbatim` /
`*_preserves_peers_relays_serials_and_revision` / `*_preserves_the_device_half`; the
subject is the device half surviving policy substitution, not key content.

**Forward warning — the same rot is already staged in one more field.** `rich_state()`
still carries `revoked_serials: vec!["AA:BB".into(), "CC:DD".into()]`: the identical
placeholder shape, in a field nothing validates *yet*. This codebase adds ingest filters
field by field (item 1 `candidates`, item 23 `active_pubkey_b64`, item 24 `allowed_ips`
— three so far, two of them in one commit), so if a serial-format filter ever lands on
`revoked_serials`, these same four tests go red in exactly this way, and the fix will
again be a fixture correction rather than a change to the filter. Anyone landing that
filter should expect them and reach for realistic serials, not for the assertions.

**Where the filter's own boot-path behaviour is pinned (corrected 2026-08-26).** An
earlier revision of this paragraph claimed the fail-static path was uncovered — that
"no test pins the filter's own behaviour on the boot path". **That was wrong.** The
items-23/24 suite, `crates/wiremesh-gateway/tests/peer_key_and_allowedips_validation.rs`,
has a whole "Door C (`state.json`)" section that has covered it since `f4a9c87` itself:
`a_persisted_peer_with_an_undecodable_pubkey_does_not_block_the_fail_static_boot` and
`a_persisted_state_where_every_peers_pubkey_is_bad_still_boots_with_an_empty_device`
hand-write a `state.json`, load it through `DesiredState::load`, and assert the
boot-time encode succeeds with the peer dropped.

What was actually missing is narrower. Both Door-C tests persist a **single** peer, so
each asserts only that something is *absent* from the encoding — assertions a load that
returned a peerless `DesiredState` would satisfy just as well. The sibling-survival
case existed only for the Sync-ingest door
(`one_peers_bad_active_pubkey_does_not_cost_a_sibling_peer_its_configuration`) and had
no disk-door twin, so nothing pinned the blast radius on the door where a poisoned row
decides whether the *other* peers get a data plane at all, with the controller not in
the loop. That twin now exists —
`a_persisted_bad_pubkey_does_not_cost_a_sibling_peer_its_boot_configuration`, on
`test/fail-static-shim-boot-roundtrip` — and its healthy peer doubles as the vacuity
guard the two single-peer tests lack.

The error is worth recording next to the finding, because it is the same class the
finding itself is about: **an absence asserted from having read one file.** The claim
"nothing covers this" was made after reading `state.rs` and `fail_static_policy_ir.rs`,
without listing `crates/wiremesh-gateway/tests/`, where the covering suite sits under a
name that says so. A coverage claim is a claim about a whole directory and needs to be
checked against one.

## Verification

Per the project's agent workflow rules the runs are performed by the dedicated qa agent,
not by the test author: `cargo test -p wiremesh-gateway --test fail_static_policy_ir`
before the fixture change (expect the four failures above) and after (expect all green).
