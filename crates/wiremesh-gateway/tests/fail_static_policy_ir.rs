//! Backlog item 1, fail-static consequence: the gateway must never persist a
//! `policy_ir` it cannot decode.
//!
//! PURE — no netns, no privileges, no sockets. Only `tempfile` for the
//! `state.json` round trips.
//!
//! ```text
//! ./dev.sh run "cargo test -p wiremesh-gateway --test fail_static_policy_ir"
//! ```
//!
//! ## Why this exists
//!
//! On main the enforcer apply ran INLINE in the Sync loop and its `?` fired
//! BEFORE `ds.save`, so a snapshot carrying an undecodable IR killed the
//! process and never reached disk. This branch moved the apply into an
//! off-loop worker, which makes the save unconditional — so a schema-2 IR
//! would be written to `state.json` and replayed through the same failing
//! worker on every subsequent fail-static boot. The failure would outlive
//! reboots and outlive a controller rollback, and on a gateway with no prior
//! good policy it would come up enforcing NOTHING: still fail-closed, but
//! durable, and far quieter than the crash it replaced. That is the opposite
//! of what fail-static is for.
//!
//! [`policy_ir_is_decodable`] and [`FailStaticWriter`] are the fix. Both are
//! pure and self-contained, so everything below is behavioural: build a
//! state, save it through the writer, load the file back, assert on what
//! landed.
//!
//! ## Decodability is exact
//!
//! [`policy_ir_is_decodable`] asks the real decoder and nothing else:
//! `is_empty() || PolicyIR::from_json(..).is_ok()`. An earlier revision put
//! a 12-byte `{"schema":1,` prefix check in front of it and returned `true`
//! on a match without decoding, on the theory that "does not look like a
//! schema-1 IR" and "is broken" are the same set. They are not — the bare
//! prefix, a document truncated mid-`blocks`, and
//! `{"schema":1,"version":"four",...}` all match the prefix and all fail to
//! decode, so precisely the corruption cases this guard exists for were
//! waved through and persisted. Those three are now asserted below, both at
//! the predicate and at the save.
//!
//! The "have I already decoded these exact bytes" optimization lives in
//! [`FailStaticWriter::save`] instead, as a memcmp against the last IR that
//! decoded — exact rather than approximate, and immune to any change in the
//! canonical JSON form.

use std::path::Path;

use tempfile::TempDir;
use wiremesh_gateway::state::{policy_ir_is_decodable, DesiredState, FailStaticWriter, PeerState};
use wiremesh_policy::{IrAction, IrBlock, IrProto, IrRule, PolicyIR};
use wiremesh_proto::v1::RelayInfo;

// --- fixtures --------------------------------------------------------------

/// A non-trivial, legitimately-compiled schema-1 IR at `version`. Built as a
/// struct literal rather than through the DSL because these tests are about
/// the BYTES, not about compilation.
fn good_ir(version: u64) -> PolicyIR {
    PolicyIR {
        schema: 1,
        version,
        blocks: vec![IrBlock {
            from: "seg-a".into(),
            to: "seg-b".into(),
            src_cidrs: vec!["10.10.1.0/24".into()],
            dst_cidrs: vec!["10.10.2.0/24".into()],
            rules: vec![IrRule {
                rule_id: "r1".into(),
                action: IrAction::Allow,
                proto: IrProto::Tcp,
                src: vec![],
                dst: vec![],
                ports: vec![(8080, 8080)],
            }],
        }],
    }
}

fn good_ir_bytes(version: u64) -> Vec<u8> {
    good_ir(version).to_canonical_json().into_bytes()
}

/// The motivating hazard: an IR from a NEWER controller. Structurally
/// perfect, decodes as JSON, and is rejected by `PolicyIR::from_json`
/// purely on the `schema` tag — which is exactly the case that must never
/// reach disk.
fn schema2_ir_bytes() -> Vec<u8> {
    let mut ir = good_ir(9);
    ir.schema = 2;
    // `to_canonical_json` serializes whatever `schema` holds, so this is a
    // faithful stand-in for what a schema-2 controller would actually send.
    ir.to_canonical_json().into_bytes()
}

/// A rich desired state whose peer/device half must survive substitution
/// untouched.
fn rich_state(revision: u64, policy_version: u64, policy_ir: Vec<u8>) -> DesiredState {
    DesiredState {
        revision,
        peers: vec![
            PeerState {
                gateway_id: 2,
                segment_name: "seg-b".into(),
                active_pubkey_b64: Some("PUB2".into()),
                keys: vec![],
                candidates: vec!["203.0.113.2:51820".into(), "10.0.0.2:51820".into()],
                allowed_ips: vec!["10.10.2.0/24".into()],
            },
            PeerState {
                gateway_id: 3,
                segment_name: "seg-c".into(),
                active_pubkey_b64: Some("PUB3".into()),
                keys: vec![],
                candidates: vec!["198.51.100.3:51820".into()],
                allowed_ips: vec!["10.10.3.0/24".into()],
            },
        ],
        policy_ir,
        policy_version,
        relays: vec![RelayInfo { relay_id: 7, endpoint: "203.0.113.7:7777".into() }],
        revoked_serials: vec!["AA:BB".into(), "CC:DD".into()],
    }
}

fn load(dir: &Path) -> DesiredState {
    DesiredState::load(dir).expect("reading state.json").expect("state.json must exist")
}

// --- (a) `policy_ir_is_decodable` truth table ------------------------------

/// Empty means "no policy yet" — `apply_if_changed` synthesizes an empty
/// schema-1 IR for it, so there is nothing undecodable to keep off disk.
#[test]
fn empty_policy_ir_is_decodable() {
    assert!(policy_ir_is_decodable(b""));
}

/// A real canonical schema-1 IR.
#[test]
fn canonical_schema_1_is_decodable() {
    assert!(policy_ir_is_decodable(&good_ir_bytes(1)));
    // Including the degenerate no-blocks form the writer's `(0, empty)`
    // fallback is conceptually equivalent to.
    let empty_blocks = PolicyIR { schema: 1, version: 1, blocks: vec![] };
    assert!(policy_ir_is_decodable(empty_blocks.to_canonical_json().as_bytes()));
}

/// **The motivating case.** A newer controller's schema-2 IR is well-formed
/// JSON and deserializes into `PolicyIR` cleanly — `from_json` rejects it on
/// the `schema` tag alone. It must be reported undecodable so it never
/// reaches `state.json`, because no future boot of THIS binary can install
/// it either.
///
/// Sabotage that must turn this red: drop the `schema != 1` check in
/// `PolicyIR::from_json`, or make `policy_ir_is_decodable` key on "parses as
/// JSON" rather than on a successful `from_json`.
#[test]
fn schema_2_is_not_decodable() {
    assert!(
        !policy_ir_is_decodable(&schema2_ir_bytes()),
        "an IR this build cannot install must never be considered persistable"
    );
}

/// Valid JSON that is not an IR at all — the shape a misconfigured or
/// mismatched controller could produce. Rejected by deserialization, not by
/// the schema tag, so it exercises a different arm of `from_json`.
#[test]
fn valid_json_that_is_not_an_ir_is_not_decodable() {
    assert!(!policy_ir_is_decodable(br#"{"hello":"world"}"#));
    assert!(!policy_ir_is_decodable(b"[]"));
    assert!(!policy_ir_is_decodable(b"null"));
    assert!(!policy_ir_is_decodable(b"42"));
}

/// Not JSON at all, including bytes that are not even UTF-8. `from_json`
/// must return `Err` rather than panicking on any of these — this function
/// runs on every Sync `State` event, on attacker-adjacent input.
#[test]
fn garbage_bytes_are_not_decodable() {
    assert!(!policy_ir_is_decodable(b"not json at all"));
    assert!(!policy_ir_is_decodable(b"{"));
    assert!(!policy_ir_is_decodable(&[0xff, 0xfe, 0x00, 0x01]));
}

/// Decodability is defined by the DECODER, not by byte shape: a schema-1 IR
/// that is perfectly valid but not in canonical byte form (here, extra
/// spaces, as re-serialization by any other JSON writer would produce) is
/// accepted.
///
/// Newly load-bearing since the optimization moved into the writer: the
/// memcmp fast path is byte-exact, so an equivalent-but-differently-spelled
/// IR does NOT match it and falls through to a real decode. That decode must
/// say yes, or a controller whose JSON writer emits spaces would have every
/// one of its policies treated as corrupt.
#[test]
fn valid_but_non_canonical_schema_1_still_decodes() {
    assert!(
        policy_ir_is_decodable(br#"{"schema": 1, "version": 4, "blocks": []}"#),
        "a valid schema-1 IR in non-canonical byte form must still be persistable"
    );
    // Field order is not part of the contract either — serde accepts any.
    assert!(policy_ir_is_decodable(br#"{"blocks":[],"version":4,"schema":1}"#));
}

/// **The cases the old prefix heuristic waved through.** Each of these
/// begins with the exact 12 bytes `{"schema":1,` and each fails to decode.
/// They are the corruption shapes this guard exists for — a partial write of
/// the controller's `policy_version.compiled_ir` column, a damaged backup,
/// a truncated restore — and the previous implementation reported all three
/// as persistable.
///
/// Sabotage that must turn this red: reintroduce any "looks like schema 1"
/// short-circuit ahead of `PolicyIR::from_json`.
#[test]
fn prefix_matching_but_broken_documents_are_not_decodable() {
    const PREFIX: &[u8] = br#"{"schema":1,"#;
    for bytes in [
        // The bare prefix and nothing else.
        br#"{"schema":1,"#.as_slice(),
        // Truncated mid-document, exactly as a partial write would leave it.
        br#"{"schema":1,"version":1,"blocks":"#.as_slice(),
        // Complete, valid JSON, right field names — wrong type on `version`.
        br#"{"schema":1,"version":"four","blocks":[]}"#.as_slice(),
    ] {
        assert!(
            bytes.starts_with(PREFIX),
            "fixture sanity: this case only means something if it DOES carry the prefix \
             the old heuristic keyed on"
        );
        assert!(
            !policy_ir_is_decodable(bytes),
            "carrying the canonical prefix is not evidence of being decodable: {}",
            String::from_utf8_lossy(bytes)
        );
    }
}

/// Structurally broken without the prefix — the cases the old heuristic did
/// catch, kept so the fix is not mistaken for a wholesale rewrite of what
/// counts as broken.
#[test]
fn broken_schema_1_documents_are_not_decodable() {
    assert!(!policy_ir_is_decodable(br#"{"schema": 1, "version": 4"#));
    assert!(!policy_ir_is_decodable(br#"{"schema": 1, "version": "four", "blocks": []}"#));
    assert!(!policy_ir_is_decodable(br#"{"schema": 1, "version": 4, "blocks": {}}"#));
}

/// **The property that actually matters**: a save carrying one of those
/// prefix-matching-but-broken IRs must SUBSTITUTE, not persist. Predicate
/// tests alone would not have caught the old bug reaching disk.
///
/// Run through the writer three times over, one bad shape each, from a
/// writer holding a known-good pair — so a regression shows up as the broken
/// bytes landing in `state.json` and being replayed on every future boot,
/// which is the whole failure mode this type exists to end.
#[test]
fn a_save_carrying_a_prefix_matching_but_broken_ir_substitutes() {
    for (name, bad) in [
        ("bare prefix", br#"{"schema":1,"#.to_vec()),
        ("truncated", br#"{"schema":1,"version":1,"blocks":"#.to_vec()),
        ("wrong type", br#"{"schema":1,"version":"four","blocks":[]}"#.to_vec()),
    ] {
        let dir = TempDir::new().unwrap();
        let mut w = FailStaticWriter::default();
        w.save(&rich_state(11, 5, good_ir_bytes(5)), dir.path()).expect("save good");

        w.save(&rich_state(12, 9, bad.clone()), dir.path()).expect("save bad");

        let got = load(dir.path());
        assert_ne!(got.policy_ir, bad, "{name}: broken bytes must never reach state.json");
        assert_eq!(got.policy_version, 5, "{name}: the last good version is what is written");
        assert_eq!(got.policy_ir, good_ir_bytes(5), "{name}: with its IR");
        assert!(
            policy_ir_is_decodable(&got.policy_ir),
            "{name}: whatever lands must be installable on the next boot"
        );
    }
}

/// The invariant that makes keying `last_good` on IR BYTES sound: two
/// policies that differ only in version serialize differently, because
/// `version` is a field of the IR itself. So byte-identical IRs always carry
/// the same `policy_version`, and the memcmp fast path can never persist a
/// stale version number alongside matching bytes.
///
/// Worth pinning here (unlike the old prefix test, which the gateway no
/// longer depends on at all) because this IS a live assumption of
/// `FailStaticWriter::save`. `wiremesh-policy` owns the invariant; the
/// gateway is the consumer relying on it.
///
/// Sabotage that must turn this red: drop `version` from `PolicyIR`'s
/// serialized form, or make `to_canonical_json` emit only `blocks`.
#[test]
fn ir_bytes_encode_the_policy_version() {
    assert_ne!(
        good_ir_bytes(5),
        good_ir_bytes(6),
        "two IRs differing only in version must differ in bytes — otherwise a byte-keyed \
         `last_good` could hold a version number that does not describe its own IR"
    );
    assert_eq!(good_ir_bytes(5), good_ir_bytes(5), "and the encoding is deterministic");
}

// --- (b) the three substitution outcomes -----------------------------------

/// Decodable: written verbatim, nothing substituted.
#[test]
fn a_decodable_ir_is_persisted_verbatim() {
    let dir = TempDir::new().unwrap();
    let mut w = FailStaticWriter::default();
    let ds = rich_state(11, 5, good_ir_bytes(5));

    w.save(&ds, dir.path()).expect("save");

    assert_eq!(load(dir.path()), ds, "a decodable snapshot must reach disk unchanged");
}

/// Undecodable WITH a prior good pair: that pair is substituted, so a boot
/// from this file comes up enforcing the last policy the gateway actually
/// understood — which is what fail-static means.
///
/// Sabotage that must turn this red: save unconditionally (the pre-fix
/// behaviour) — the schema-2 bytes land on disk and every future boot
/// replays them.
#[test]
fn an_undecodable_ir_is_replaced_by_the_last_good_pair() {
    let dir = TempDir::new().unwrap();
    let mut w = FailStaticWriter::default();

    w.save(&rich_state(11, 5, good_ir_bytes(5)), dir.path()).expect("save good");
    w.save(&rich_state(12, 9, schema2_ir_bytes()), dir.path()).expect("save bad");

    let got = load(dir.path());
    assert_eq!(got.policy_version, 5, "the last DECODABLE version must be what is persisted");
    assert_eq!(got.policy_ir, good_ir_bytes(5), "and its IR bytes alongside it");
    assert!(
        policy_ir_is_decodable(&got.policy_ir),
        "whatever reaches disk must, by construction, be installable on the next boot"
    );
}

/// Undecodable with NO prior good pair — a first boot against a controller
/// that is already too new. Falls back to the "no policy yet" pair, which
/// `apply_if_changed` turns into an empty schema-1 IR: the same default-deny
/// the datapath already has, reported as version 0.
///
/// Version 0 is honest rather than merely convenient: the controller's
/// version counter is `MAX(version) + 1` seeded at 1
/// (`wiremesh-controller/src/db.rs`'s `candidate_version`), so 0 is never a
/// real policy version and reads unambiguously as "no policy" — which is
/// what makes the roster `applied_version` lag signal fire instead of
/// reporting a version that was never installed.
#[test]
fn an_undecodable_ir_with_no_prior_good_pair_falls_back_to_no_policy() {
    let dir = TempDir::new().unwrap();
    let mut w = FailStaticWriter::default();

    w.save(&rich_state(3, 9, schema2_ir_bytes()), dir.path()).expect("save bad");

    let got = load(dir.path());
    assert_eq!(got.policy_version, 0, "no prior good policy reads as version 0, never as 9");
    assert!(got.policy_ir.is_empty(), "and with no IR bytes at all");
}

/// Recovery, both directions: a good save after a bad one resumes verbatim
/// writing AND refreshes the fallback, so a LATER bad save substitutes the
/// newer good pair rather than the stale one.
///
/// Sabotage that must turn this red: only seed `last_good` once, or fail to
/// refresh it after a substitution — the second bad save writes version 5
/// instead of 6.
#[test]
fn the_fallback_pair_advances_as_new_good_policies_arrive() {
    let dir = TempDir::new().unwrap();
    let mut w = FailStaticWriter::default();

    w.save(&rich_state(11, 5, good_ir_bytes(5)), dir.path()).expect("good v5");
    w.save(&rich_state(12, 9, schema2_ir_bytes()), dir.path()).expect("bad v9");
    assert_eq!(load(dir.path()).policy_version, 5);

    // The controller is fixed and pushes a readable v6.
    w.save(&rich_state(13, 6, good_ir_bytes(6)), dir.path()).expect("good v6");
    assert_eq!(load(dir.path()).policy_version, 6, "a good save resumes writing verbatim");

    // It breaks again.
    w.save(&rich_state(14, 10, schema2_ir_bytes()), dir.path()).expect("bad v10");
    let got = load(dir.path());
    assert_eq!(got.policy_version, 6, "the fallback must be the NEWEST good pair, not the first");
    assert_eq!(got.policy_ir, good_ir_bytes(6));
}

// --- (c) the peer/device half survives substitution ------------------------

/// **The requirement that makes this a fix rather than a different
/// blackhole.** Fail-static's job is unchanged: peers, relays, revoked
/// serials and the revision must be persisted exactly as they arrived. Only
/// the policy pair is substituted.
///
/// Asserted as a whole-struct comparison against the expected result, so a
/// field added to `DesiredState` later cannot quietly escape the check the
/// way a hand-listed set of assertions would.
///
/// Sabotage that must turn this red: substitute by writing the last good
/// `DesiredState` wholesale instead of cloning the current one and replacing
/// only the pair — the newly enrolled peer 3, the relay and the revoked
/// serials all vanish from disk, and the gateway loses them across a reboot.
#[test]
fn substitution_preserves_peers_relays_serials_and_revision() {
    let dir = TempDir::new().unwrap();
    let mut w = FailStaticWriter::default();

    w.save(&rich_state(11, 5, good_ir_bytes(5)), dir.path()).expect("save good");

    let bad = rich_state(12, 9, schema2_ir_bytes());
    w.save(&bad, dir.path()).expect("save bad");

    let mut expected = bad.clone();
    expected.policy_version = 5;
    expected.policy_ir = good_ir_bytes(5);
    assert_eq!(
        load(dir.path()),
        expected,
        "everything except the (policy_version, policy_ir) pair must be persisted exactly \
         as it arrived — substituting the policy must not cost the gateway its peers"
    );
}

/// The same, for the no-prior-good path: dropping to `(0, empty)` must not
/// take the device half with it. This is the first-boot case, where losing
/// the peers would leave the gateway with neither policy nor topology.
#[test]
fn the_no_prior_good_fallback_also_preserves_the_device_half() {
    let dir = TempDir::new().unwrap();
    let mut w = FailStaticWriter::default();

    let bad = rich_state(4, 9, schema2_ir_bytes());
    w.save(&bad, dir.path()).expect("save bad");

    let mut expected = bad.clone();
    expected.policy_version = 0;
    expected.policy_ir = Vec::new();
    assert_eq!(load(dir.path()), expected);
}

// --- (d) `seeded_from` round trips -----------------------------------------

/// A restart must not lose the fallback. A `state.json` written with a good
/// IR seeds the pair, so the first undecodable snapshot after boot
/// substitutes THAT policy rather than dropping to `(0, empty)` — i.e. the
/// gateway keeps enforcing what it understood before the reboot.
///
/// Sabotage that must turn this red: make `seeded_from` ignore the persisted
/// IR (return `Default`) — the substitution drops to version 0 and the
/// fabric loses its policy on the first restart under a broken controller.
#[test]
fn seeded_from_a_good_state_json_restores_the_fallback_across_a_restart() {
    let dir = TempDir::new().unwrap();

    // Pre-restart: a good policy on disk.
    rich_state(11, 5, good_ir_bytes(5)).save(dir.path()).expect("seed state.json");

    // Restart: boot loads it, and the writer is seeded from it.
    let booted = DesiredState::load(dir.path()).expect("load").expect("present");
    let mut w = FailStaticWriter::seeded_from(Some(&booted));

    // The controller is still broken.
    w.save(&rich_state(12, 9, schema2_ir_bytes()), dir.path()).expect("save bad");

    let got = load(dir.path());
    assert_eq!(got.policy_version, 5, "the pre-restart policy must survive the reboot");
    assert_eq!(got.policy_ir, good_ir_bytes(5));
}

/// The pre-fix-binary case: a `state.json` that ALREADY carries an
/// undecodable IR (written by a build without this guard) must seed nothing.
/// Trusting it would reinstate exactly the durable failure this change
/// exists to end — and its own boot install fails loudly, which is correct.
///
/// Sabotage that must turn this red: seed unconditionally from the persisted
/// pair — the bad IR becomes the "last good" one and is written back on
/// every subsequent substitution, forever.
#[test]
fn seeded_from_a_state_json_carrying_a_bad_ir_seeds_nothing() {
    let dir = TempDir::new().unwrap();

    // What a pre-fix binary would have left behind.
    rich_state(11, 9, schema2_ir_bytes()).save(dir.path()).expect("seed bad state.json");

    let booted = DesiredState::load(dir.path()).expect("load").expect("present");
    let mut w = FailStaticWriter::seeded_from(Some(&booted));

    w.save(&rich_state(12, 10, schema2_ir_bytes()), dir.path()).expect("save bad");

    let got = load(dir.path());
    assert_eq!(got.policy_version, 0, "an undecodable persisted IR must not become the fallback");
    assert!(got.policy_ir.is_empty());
    assert!(
        policy_ir_is_decodable(&got.policy_ir),
        "and the file is now clean, so the NEXT restart is no longer poisoned"
    );
}

/// First boot ever: nothing on disk, nothing to seed.
#[test]
fn seeded_from_nothing_has_no_fallback() {
    let dir = TempDir::new().unwrap();
    let mut w = FailStaticWriter::seeded_from(None);

    w.save(&rich_state(1, 9, schema2_ir_bytes()), dir.path()).expect("save bad");

    assert_eq!(load(dir.path()).policy_version, 0);
}

/// A `state.json` whose IR is EMPTY (the "no policy yet" shape a gateway
/// persists before its first policy) seeds the `(0, empty)` pair rather than
/// `None`. Both behave identically at the next substitution, but pinning it
/// keeps `policy_ir_is_decodable`'s empty-is-decodable arm consistent
/// between the seeding path and the save path.
#[test]
fn seeded_from_an_empty_ir_state_json_is_equivalent_to_no_policy() {
    let dir = TempDir::new().unwrap();
    rich_state(2, 0, Vec::new()).save(dir.path()).expect("seed");

    let booted = DesiredState::load(dir.path()).expect("load").expect("present");
    let mut w = FailStaticWriter::seeded_from(Some(&booted));

    w.save(&rich_state(3, 9, schema2_ir_bytes()), dir.path()).expect("save bad");

    let got = load(dir.path());
    assert_eq!(got.policy_version, 0);
    assert!(got.policy_ir.is_empty());
}

// --- the memcmp fast path --------------------------------------------------

/// A byte-identical re-save is the steady-state case: peer churn, endpoint
/// observations and every reconnect snapshot re-send the same policy, and
/// the writer answers them with a memcmp instead of a parse.
///
/// **"Does not re-parse" is pinned behaviourally, not by timing.** A timing
/// assertion on a sub-microsecond memcmp against a sub-millisecond parse
/// would be noise, and would fail on a loaded container for reasons having
/// nothing to do with the property. What is asserted instead is the contract
/// the fast path has to preserve: the same bytes go out verbatim, every
/// time, with the current device half, and the fast path never becomes a
/// blanket "we have a last_good, wave it through" — different bytes that are
/// undecodable must still substitute.
#[test]
fn byte_identical_resaves_are_persisted_verbatim() {
    let dir = TempDir::new().unwrap();
    let mut w = FailStaticWriter::default();
    let ir = good_ir_bytes(5);

    // First save: the decode path.
    w.save(&rich_state(11, 5, ir.clone()), dir.path()).expect("first save");

    // Ten more State events carrying the SAME policy bytes and an advancing
    // revision — the memcmp path.
    for revision in 12..=21 {
        let ds = rich_state(revision, 5, ir.clone());
        w.save(&ds, dir.path()).expect("re-save");
        assert_eq!(load(dir.path()), ds, "revision {revision}: persisted verbatim");
    }

    // The fast path must not have become an unconditional accept: a genuinely
    // different, undecodable IR still substitutes.
    w.save(&rich_state(22, 9, schema2_ir_bytes()), dir.path()).expect("save bad");
    let got = load(dir.path());
    assert_eq!(got.policy_version, 5, "different bytes must be decoded, not waved through");
    assert_eq!(got.policy_ir, ir);
}

// --- (e) the warning dedupe ------------------------------------------------

/// `warned_version()` exposes the once-per-distinct-bad-version dedupe. The
/// CRITICAL line itself goes to `eprintln!`, which an in-process test cannot
/// capture; this accessor is the observable proxy for "would a line have
/// been emitted".
///
/// Peer churn under a broken controller is the driver: every
/// `EndpointObserved` delta is another `State` event, so without the dedupe
/// a single bad policy version would emit one CRITICAL per event for as long
/// as the controller stayed broken.
#[test]
fn the_warning_is_deduplicated_per_distinct_bad_version() {
    let dir = TempDir::new().unwrap();
    let mut w = FailStaticWriter::default();
    w.save(&rich_state(11, 5, good_ir_bytes(5)), dir.path()).expect("save good");
    assert_eq!(w.warned_version(), None, "a clean save has nothing to warn about");

    // First bad save at version 9: warned.
    w.save(&rich_state(12, 9, schema2_ir_bytes()), dir.path()).expect("bad v9");
    assert_eq!(w.warned_version(), Some(9));

    // Repeats at the SAME bad version: still 9, i.e. no new line.
    for revision in 13..=16 {
        w.save(&rich_state(revision, 9, schema2_ir_bytes()), dir.path()).expect("bad v9 again");
        assert_eq!(
            w.warned_version(),
            Some(9),
            "revision {revision}: churn at the same bad version must not re-warn"
        );
    }

    // A DIFFERENT bad version is a new fact and moves the marker.
    let mut other_bad = good_ir(10);
    other_bad.schema = 2;
    w.save(&rich_state(17, 10, other_bad.to_canonical_json().into_bytes()), dir.path())
        .expect("bad v10");
    assert_eq!(w.warned_version(), Some(10), "a new bad version must warn again");
}

/// Reset on a clean save, via the DECODE path: the controller is fixed, a
/// readable policy lands, and the marker clears — so if it breaks again
/// later at the same version, that is a new incident and warns again.
#[test]
fn a_clean_save_via_the_decode_path_resets_the_warning() {
    let dir = TempDir::new().unwrap();
    let mut w = FailStaticWriter::default();
    w.save(&rich_state(11, 5, good_ir_bytes(5)), dir.path()).expect("good v5");
    w.save(&rich_state(12, 9, schema2_ir_bytes()), dir.path()).expect("bad v9");
    assert_eq!(w.warned_version(), Some(9));

    // New, decodable bytes → decode path.
    w.save(&rich_state(13, 6, good_ir_bytes(6)), dir.path()).expect("good v6");
    assert_eq!(w.warned_version(), None, "recovery clears the marker");

    // Same bad version returns: a fresh incident, warned again.
    w.save(&rich_state(14, 9, schema2_ir_bytes()), dir.path()).expect("bad v9 again");
    assert_eq!(w.warned_version(), Some(9));
}

/// Reset on a clean save via the MEMCMP path specifically — the newer of the
/// two clean paths, and the one that runs in steady state. A gateway that
/// recovers because the controller re-sends the policy it already had (a
/// reconnect snapshot, not a new policy) takes this branch, and it must
/// clear the marker just like the decode path does. Missing the reset here
/// would silently suppress the next genuine CRITICAL.
#[test]
fn a_clean_save_via_the_memcmp_path_resets_the_warning() {
    let dir = TempDir::new().unwrap();
    let mut w = FailStaticWriter::default();
    let ir = good_ir_bytes(5);
    w.save(&rich_state(11, 5, ir.clone()), dir.path()).expect("good v5");
    w.save(&rich_state(12, 9, schema2_ir_bytes()), dir.path()).expect("bad v9");
    assert_eq!(w.warned_version(), Some(9));

    // The SAME policy bytes arrive again — the memcmp branch, no decode.
    w.save(&rich_state(13, 5, ir.clone()), dir.path()).expect("re-send of v5");
    assert_eq!(
        w.warned_version(),
        None,
        "the memcmp fast path is a clean save too and must reset the marker; otherwise a \
         later genuine CRITICAL at the same version would be swallowed"
    );

    // Proof that it would now warn again rather than staying silent.
    w.save(&rich_state(14, 9, schema2_ir_bytes()), dir.path()).expect("bad v9 again");
    assert_eq!(w.warned_version(), Some(9));
}

// --- repeated bad saves ----------------------------------------------------

/// Output correctness under sustained churn, alongside the dedupe above:
/// each pass must carry the fresh device half through with the same
/// substituted policy.
#[test]
fn repeated_saves_under_a_broken_controller_stay_correct() {
    let dir = TempDir::new().unwrap();
    let mut w = FailStaticWriter::default();
    w.save(&rich_state(11, 5, good_ir_bytes(5)), dir.path()).expect("save good");

    // Five more State events: same bad policy version, advancing revision
    // (peer churn), each of which must still land the good policy plus the
    // CURRENT device half.
    for revision in 12..=16 {
        let bad = rich_state(revision, 9, schema2_ir_bytes());
        w.save(&bad, dir.path()).expect("save bad");

        let got = load(dir.path());
        assert_eq!(got.policy_version, 5, "revision {revision}: policy stays on the last good");
        assert_eq!(got.revision, revision, "revision {revision}: device half stays current");
    }

    // A DIFFERENT bad version must still substitute correctly (the dedupe
    // must not suppress the substitution itself, only the repeated log).
    w.save(&rich_state(17, 10, schema2_ir_bytes()), dir.path()).expect("save other bad");
    let got = load(dir.path());
    assert_eq!(got.policy_version, 5);
    assert_eq!(got.revision, 17);
}
