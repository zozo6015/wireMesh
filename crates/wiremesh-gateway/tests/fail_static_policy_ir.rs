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
//! ## Coverage gap — read before trusting the truth table
//!
//! `policy_ir_is_decodable`'s 12-byte fast path returns `true` WITHOUT
//! decoding, so an IR that starts `{"schema":1,` and is then truncated or
//! structurally broken is reported decodable and gets persisted. That case
//! is deliberately NOT asserted here in either direction: asserting `false`
//! would fail, and asserting `true` would enshrine it. See my report — it is
//! a finding, not a test gap I chose.

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

/// A real canonical schema-1 IR, via the fast path.
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
    let bytes = schema2_ir_bytes();
    assert!(
        bytes.starts_with(br#"{"schema":2,"#),
        "fixture sanity: a schema-2 IR must not accidentally carry the schema-1 prefix, or \
         this test would be passing through the fast path instead of the decode"
    );
    assert!(
        !policy_ir_is_decodable(&bytes),
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

/// The slow path is a genuine fallback, not dead code: a schema-1 IR that is
/// perfectly valid but NOT in canonical byte form (here, one extra space, as
/// a re-serialization by any other JSON writer would produce) misses the
/// 12-byte prefix and is still accepted by the full decode behind it.
///
/// This is the property that makes the fast path an optimization rather than
/// a format lock-in, so it is worth pinning explicitly.
#[test]
fn valid_but_non_canonical_schema_1_still_decodes_via_the_slow_path() {
    let spaced = br#"{"schema": 1, "version": 4, "blocks": []}"#;
    assert!(
        !spaced.starts_with(br#"{"schema":1,"#),
        "fixture sanity: this input must MISS the fast path, or it proves nothing"
    );
    assert!(
        policy_ir_is_decodable(spaced),
        "a valid schema-1 IR in non-canonical byte form must still be persistable — the \
         prefix is a fast path, not the definition of decodable"
    );
}

/// Structurally broken and NOT prefix-matching: caught by the full decode.
/// (The prefix-MATCHING broken case is the gap documented in this file's
/// header; it is not asserted here.)
#[test]
fn broken_schema_1_without_the_prefix_is_not_decodable() {
    // Truncated mid-document, and the space after the colon keeps it off the
    // fast path.
    assert!(!policy_ir_is_decodable(br#"{"schema": 1, "version": 4"#));
    // Right field names, wrong types.
    assert!(!policy_ir_is_decodable(br#"{"schema": 1, "version": "four", "blocks": []}"#));
    // `blocks` is not a list.
    assert!(!policy_ir_is_decodable(br#"{"schema": 1, "version": 4, "blocks": {}}"#));
}

/// Skepticism item, made executable: the fast path is only correct if EVERY
/// legitimate schema-1 IR serializes with `{"schema":1,` as its first 12
/// bytes. `PolicyIR`'s fields are declared `schema, version, blocks` with no
/// `rename`, no `skip_serializing_if` and no map/float members, and
/// `to_canonical_json` is plain `serde_json::to_string` — so the invariant
/// holds by construction today. It is not enforced by anything, though: a
/// field reorder in `wiremesh-policy`'s `ir.rs` would silently demote every
/// healthy IR to the slow path (a full decode on every Sync `State` event),
/// and a future `#[serde(skip_serializing_if)]` on `version` with empty
/// `blocks` could drop the trailing comma outright.
///
/// Sabotage that must turn this red: reorder `PolicyIR`'s fields, rename
/// `schema`, or switch `to_canonical_json` to `to_string_pretty`.
#[test]
fn every_legitimate_schema_1_ir_carries_the_fast_path_prefix() {
    const PREFIX: &[u8] = br#"{"schema":1,"#;
    let cases = vec![
        ("no blocks, version 0", PolicyIR { schema: 1, version: 0, blocks: vec![] }),
        ("no blocks, version 1", PolicyIR { schema: 1, version: 1, blocks: vec![] }),
        ("one block", good_ir(1)),
        ("large version", good_ir(u64::MAX)),
        ("many blocks", {
            let mut ir = good_ir(12);
            let block = ir.blocks[0].clone();
            ir.blocks = vec![block.clone(), block.clone(), block];
            ir
        }),
    ];
    for (name, ir) in cases {
        let json = ir.to_canonical_json();
        assert!(
            json.as_bytes().starts_with(PREFIX),
            "{name}: a legitimate schema-1 IR must serialize with the fast-path prefix, \
             otherwise `policy_ir_is_decodable` silently full-decodes every healthy IR on \
             every Sync State event. Got: {}",
            &json[..json.len().min(40)]
        );
    }
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

// --- (e) repeated bad saves ------------------------------------------------

/// The behavioural half of the log-dedupe requirement: whatever the writer
/// logs, repeated saves under a broken controller must keep producing the
/// same correct file. Peer churn is the realistic driver — every
/// `EndpointObserved` delta is another `State` event, so this path runs
/// often while the controller is broken, and each pass must carry the fresh
/// device half through with the same substituted policy.
///
/// **The dedupe ITSELF is not observable here.** `FailStaticWriter::warned`
/// is private with no accessor and the CRITICAL line goes to `eprintln!`,
/// which an in-process integration test cannot capture. I have not faked it
/// — see my report for the one-line seam that would make it assertable.
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
