// crates/wiremesh-relay/tests/pair_id_width.rs
//
// Item 3a — pins the properties of `wiremesh_relay::registration_key`, the
// ONE derivation both ends of a relayed pair must agree on: the relay keys
// its registry with `registration_key(my, peer)` (`my` taken from the
// authenticated client cert) and the addressing peer targets
// `registration_key(peer, my)`.
//
// ## What is wrong today
//
// `registration_key` computes `SHA-256(len(my) || my || peer)` and then
// hex-expands only the FIRST FOUR digest bytes into the 8-byte header:
// eight ASCII characters carrying **32 bits**. `src/lib.rs`'s own doc comment
// already flags the width as a fast-follow, and
// `docs/research/relay-mux-design-verification.md` §1 grades the consequence:
// a probabilistic, self-healing mutual-exclusion fault (two colliding pairs
// cannot both be registered on one relay process at the same time), sticky
// only on single-relay fabrics, with a SILENT same-owner variant (see
// `tests/relay_pair_collision.rs`).
//
// The fix is ~5 lines: use `digest[..8]` raw, keeping the header at 8 bytes.
//
// ## How the width is pinned WITHOUT contriving a collision
//
// Forcing a specific 32-bit collision would bake impl-derived constants into
// the test and go stale the moment the derivation widens. Instead two
// derivation-agnostic properties are asserted, both of which follow from
// "the 8 header bytes carry 64 bits" and neither of which can hold for a
// hex-expanded 32-bit prefix:
//
//   1. BYTE RANGE (deterministic): a hex expansion can only ever emit the 16
//      ASCII characters `0-9a-f`, so every one of the 8 byte positions is
//      confined to a 16-value alphabet no matter how many pairs are sampled.
//      A raw digest byte spans all 256. Asserting that each position takes
//      well over 16 distinct values across a large sample is therefore a
//      deterministic RED today and a near-certain GREEN after the fix (over
//      4096 samples a uniform byte position is expected to hit ~256 distinct
//      values; the assertion floor is 64).
//
//   2. NO COLLISION IN A PRACTICAL BUDGET (probabilistic, but overwhelming):
//      400k keys drawn from a 2^32 space are expected to produce ~18.6
//      birthday collisions — P(none) ~ 8e-9. Drawn from a 2^64 space the
//      expectation is ~1e-8 — P(any) ~ 1e-8. So this assertion is a reliable
//      RED before and a reliable GREEN after, with no baked constants and no
//      contrived input.
//
// The remaining tests are GREEN characterisation: order-sensitivity,
// pair-specificity, the length prefix that stops concatenation collisions,
// and determinism. They exist so that the width fix cannot quietly change
// the derivation's SHAPE while it changes its width. Live relay/gateway
// agreement on the derivation is pinned separately, end to end, in
// `tests/relay_pair_collision.rs`.
use std::collections::{HashMap, HashSet};

use wiremesh_relay::registration_key;

/// The 16 characters a hex expansion of a 4-byte digest prefix can emit —
/// exactly the alphabet the current (32-bit) derivation is confined to.
const HEX_ALPHABET: &[u8] = b"0123456789abcdef";

/// Sample size for the byte-range property. Large enough that a uniform byte
/// position is expected to hit ~256 distinct values (256*(1 - (255/256)^4096)
/// ~ 255.9), so the floor of 64 has enormous headroom.
const RANGE_SAMPLES: usize = 4096;

/// Sample size for the collision-freedom property. See the module comment
/// for the birthday arithmetic behind this number. `tests/relay_pair_
/// collision.rs` runs the same search with the same budget (integration test
/// files are separate crates, so the helper is duplicated there rather than
/// shared) to decide whether the silent-replace path is reachable at all.
const COLLISION_SEARCH_BUDGET: usize = 400_000;

#[test]
fn registration_key_header_must_carry_full_octets_not_a_hex_expanded_32_bit_prefix() {
    // 8 sets, one per byte position of the header.
    let mut seen_per_position: Vec<HashSet<u8>> = vec![HashSet::new(); 8];
    let mut any_non_hex_byte = false;

    for i in 0..RANGE_SAMPLES {
        let key = registration_key("gw-A", &format!("gw-{i}"));
        assert_eq!(
            key.len(),
            8,
            "the relay's datagram header is a fixed 8 bytes"
        );
        for (pos, b) in key.iter().enumerate() {
            seen_per_position[pos].insert(*b);
            if !HEX_ALPHABET.contains(b) {
                any_non_hex_byte = true;
            }
        }
    }

    // The headline assertion: no byte position may be confined to a 16-value
    // alphabet. A hex expansion cannot pass this no matter the sample size.
    for (pos, seen) in seen_per_position.iter().enumerate() {
        assert!(
            seen.len() >= 64,
            "byte {pos} of registration_key took only {} distinct values across {RANGE_SAMPLES} \
             pairs. A full-octet header would take ~256. This is the signature of the 8-byte \
             header being a HEX EXPANSION of a 4-byte digest prefix — 8 ASCII characters \
             carrying 32 bits. The header must carry the first 8 RAW digest bytes (64 bits).",
            seen.len()
        );
    }

    assert!(
        any_non_hex_byte,
        "every byte of every registration_key across {RANGE_SAMPLES} pairs fell inside the \
         ASCII hex alphabet `0-9a-f` — the id space is 32 bits, not the 64 bits the 8-byte \
         header can hold"
    );
}

/// Searches for two DIFFERENT peer identities that, against the same `my`
/// identity, derive the SAME registration key. Duplicated verbatim in
/// `tests/relay_pair_collision.rs` (separate test crates cannot share it).
///
/// Returns `Ok(())` when the budget is exhausted with every key distinct.
fn find_same_owner_collision(
    my_identity: &str,
    budget: usize,
) -> Result<(), (String, String, [u8; 8])> {
    let mut seen: HashMap<[u8; 8], String> = HashMap::with_capacity(budget);
    for i in 0..budget {
        let peer = format!("gw-p{i}");
        let key = registration_key(my_identity, &peer);
        if let Some(prev) = seen.insert(key, peer.clone()) {
            return Err((prev, peer, key));
        }
    }
    Ok(())
}

#[test]
fn no_registration_key_collision_may_be_findable_within_a_practical_budget() {
    match find_same_owner_collision("gw-A", COLLISION_SEARCH_BUDGET) {
        Ok(()) => {}
        Err((p1, p2, key)) => panic!(
            "found two distinct peers colliding on the SAME registration key after searching \
             at most {COLLISION_SEARCH_BUDGET} pairs: registration_key(\"gw-A\", {p1:?}) == \
             registration_key(\"gw-A\", {p2:?}) == {key:?}. With a 64-bit id space the \
             expected number of collisions at this sample size is ~1e-8; finding one means the \
             header is still a hex-expanded 32-bit digest prefix. On a single-relay fabric a \
             collision is a mutual-exclusion outage between the two pairs, and in the \
             same-owner case (this one) it is a SILENT registry replacement."
        ),
    }
}

#[test]
fn registration_key_is_order_sensitive_and_pair_specific() {
    // The whole rendezvous depends on K(my, peer) and K(peer, my) being
    // different slots: each side registers one and addresses the other.
    assert_ne!(
        registration_key("gw-A", "gw-B"),
        registration_key("gw-B", "gw-A"),
        "K(A,B) must differ from K(B,A): the two directions are separate registry slots"
    );

    // Same owner, different peer -> different slot. This is what makes a
    // gateway's several relayed peers independently addressable.
    assert_ne!(
        registration_key("gw-A", "gw-B"),
        registration_key("gw-A", "gw-C"),
        "K(A,B) must differ from K(A,C): one gateway's slots for different peers are distinct"
    );

    // Different owner, same peer -> different slot.
    assert_ne!(
        registration_key("gw-A", "gw-B"),
        registration_key("gw-C", "gw-B"),
        "K(A,B) must differ from K(C,B): different owners never share a slot"
    );
}

#[test]
fn registration_key_length_prefix_prevents_concatenation_collisions() {
    // Without the length prefix on `my`, ("gwa","b") and ("gw","ab") would
    // hash identical bytes. This is a pre-existing GREEN property that the
    // width fix must not drop while it is rewriting the tail of the function.
    assert_ne!(
        registration_key("gwa", "b"),
        registration_key("gw", "ab"),
        "identities must be length-prefixed before hashing, or two different pairs whose \
         concatenations coincide would share a registry slot"
    );
    assert_ne!(
        registration_key("gw-AB", "gw-C"),
        registration_key("gw-A", "Bgw-C"),
        "length-prefix property must hold for realistic gw-<id> shaped identities too"
    );
}

#[test]
fn registration_key_is_deterministic() {
    // Both ends of a pair — and the relay itself — recompute this
    // independently, so it must be a pure function of its two inputs.
    let a = registration_key("gw-17", "gw-4231");
    for _ in 0..8 {
        assert_eq!(
            a,
            registration_key("gw-17", "gw-4231"),
            "registration_key must be a pure function: relay and both gateways derive it \
             independently and a divergence is a silent unroutable-slot failure"
        );
    }
}
