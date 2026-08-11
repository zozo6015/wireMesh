//! In-step rotation, tier 1: the ONE endpoint decision that breaks the
//! collapse deadlock — and the predicate that keeps it from firing anywhere
//! else.
//!
//! ./dev.sh run "cargo test -p wiremesh-gateway --test collapse_dial"
//!
//! # The defect this pins
//!
//! At the Role-B collapse arm (`main.rs`'s `maybe_collapse_role_b`) the unpin
//! forces an apply onto the ACTIVE tun. In the IN-STEP case — both gateways
//! rotating off the controller's one timer — our own Role-A cutover has
//! already run, so that active tun is `wg0e1`, and `device_config_pinned`
//! rebuilds the peer there from a candidate list that is base-port by
//! construction. The peer's epoch-1 key is not on its base port; it is on
//! `candidate_port + OWN_TUN_PORT_OFFSET`. Neither of
//! `device_config_pinned`'s two endpoint sources can ever produce that number
//! (`docs/research/in-step-rotation-rebaselined.md`, "MECHANISM FOUND"), so
//! `wg0e1` never handshakes, the collapse gate waits on a session it cannot
//! address, and the peer's retire is gated on that same session. Circular:
//! **in the in-step case the base-port endpoint is NEVER correct.**
//!
//! # And the non-regression it pins, which matters just as much
//!
//! In a ONE-SIDED rotation only the peer rotates; we never cut over, so our
//! overlap tun and our active tun run the SAME private key. There the
//! base-port endpoint is EVENTUALLY correct — the peer's retire is gated on
//! our overlap's session, which is live, so the peer retires,
//! `renormalize_active_listen_port` puts its active key back on base, and our
//! unchanged dial starts working. Convergence by waiting. Five green
//! one-sided netns tests depend on nothing new firing there.
//!
//! The discriminator between the two worlds is `built_at_own_epoch !=
//! own_active_epoch`: our overlap and our active tun run DIFFERENT private
//! keys exactly when our own cutover has run. It is the SAME discriminator
//! [`wiremesh_gateway::rotation::route_owner`] already uses (`==` there means
//! "the overlap still runs the key our peer's roster advertises for us"), and
//! the two must stay exact complements — see
//! `only_the_inequality_is_read_never_the_order_or_the_distance` below.
//!
//! # Production seam this file requires (does NOT exist yet — COMPILE-RED)
//!
//! In `crates/wiremesh-gateway/src/reconcile.rs`, an EXTRACTION of the
//! derivation `pending_peer_configs` already performs inline (`:89-95`), with
//! behaviour identical to it:
//!
//! ```ignore
//! /// `ip:(port + OWN_TUN_PORT_OFFSET)` for a peer candidate `ip:port` — the
//! /// one port a gateway's in-flight new epoch can be reached on, by
//! /// reservation rather than by epoch arithmetic. `None` on anything that
//! /// does not parse as `ip:port`, or whose port cannot be offset without
//! /// overflowing.
//! pub fn own_tun_endpoint(candidate: &str) -> Option<String>;
//! ```
//!
//! In `crates/wiremesh-gateway/src/rotation.rs` — a lib module, so `tests/`
//! can reach it; this must NOT live in `main.rs`, which no integration test
//! can link:
//!
//! ```ignore
//! /// The endpoint the collapse arm must pin for a peer, or `None` when it
//! /// must pin nothing and leave today's behaviour untouched.
//! pub fn collapse_dial(
//!     own_active_epoch: u32,
//!     built_at_own_epoch: u32,
//!     peer_candidate: &str,
//! ) -> Option<String>;
//! ```
//!
//! # What is deliberately NOT pinned here
//!
//! Nothing about WHERE the caller puts the result (`live_endpoints[gid]`, per
//! the plan), when it is cleared, or whether a handshake kick accompanies it.
//! Nothing about tun names or device state — that is `tests/key_rotation.rs`'s
//! done bar. This file pins one pure decision and the agreement between the
//! two functions that now answer the same question.
//!
//! # A note on hostile input
//!
//! `own_tun_endpoint` is a derivation, not a validator. Every candidate that
//! reaches it in production has already passed `uapi::is_dialable_endpoint` at
//! both ingest doors (`PeerState::from_proto` and the `deserialize_with`
//! shim), so it is guaranteed `a.b.c.d:port`. The malformed cases below are
//! defense-in-depth against a future caller with a looser source — the
//! `u16::MAX` case is the only one reachable today, and it is genuinely
//! reachable: `192.168.1.7:65535` is a candidate the ingest filter KEEPS
//! (`state.rs`'s `partition_dialable_keeps_every_valid_candidate_verbatim_and_in_order`).
use wiremesh_gateway::reconcile::{own_tun_endpoint, pending_peer_configs};
use wiremesh_gateway::rotation::collapse_dial;
use wiremesh_gateway::state::{DesiredState, PeerKeyInfo, PeerState};
use wiremesh_gateway::tunnelset::OWN_TUN_PORT_OFFSET;
use wiremesh_gateway::uapi::pubkey_b64_to_hex;

// --- Fixtures --------------------------------------------------------------

/// A real WG-shaped key (base64 of 32 bytes) that `pubkey_b64_to_hex`
/// accepts. `pending_peer_configs` runs the pending pubkey through that
/// decoder (backlog item 23) and drops the peer when it fails, so the
/// agreement test below needs a genuinely decodable one or it would compare
/// against an empty peer set and pass vacuously.
const VALID_PENDING_KEY: &str = "3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d0=";
const VALID_ACTIVE_KEY: &str = "7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c0=";

/// Split `ip:port`, the way both derivations under test do. Test-side only —
/// used to build the EXPECTED string, so a change to the production split is
/// visible as a mismatch rather than being silently mirrored.
fn split_candidate(candidate: &str) -> (&str, u16) {
    let (ip, port) = candidate.rsplit_once(':').expect("test candidate is ip:port");
    (ip, port.parse().expect("test candidate port is a u16"))
}

/// A peer mid-rotation, shaped so `pending_peer_configs` will emit for it:
/// a decodable active key AND a decodable pending key AND a parseable
/// candidate.
fn rotating_peer(gid: u64, candidate: &str) -> PeerState {
    PeerState {
        gateway_id: gid,
        segment_name: format!("seg-{gid}"),
        active_pubkey_b64: Some(VALID_ACTIVE_KEY.to_string()),
        keys: vec![
            PeerKeyInfo { epoch: 0, pubkey_b64: VALID_ACTIVE_KEY.into(), state: "active".into() },
            PeerKeyInfo { epoch: 1, pubkey_b64: VALID_PENDING_KEY.into(), state: "pending".into() },
        ],
        candidates: vec![candidate.to_string()],
        allowed_ips: vec![format!("10.10.{gid}.0/24")],
    }
}

fn ds(peers: Vec<PeerState>) -> DesiredState {
    DesiredState { revision: 1, peers, ..Default::default() }
}

/// The single endpoint `pending_peer_configs` emitted, so the agreement test
/// compares two produced ANSWERS rather than one answer against a restatement
/// of the formula that produced it.
fn pending_endpoint(state: &DesiredState) -> String {
    let cfgs = pending_peer_configs(state, 25);
    assert_eq!(cfgs.len(), 1, "expected exactly one pending peer config, got {cfgs:?}");
    cfgs[0]
        .endpoint
        .clone()
        .expect("a pending peer config carries an endpoint")
}

/// Fixture check, not a behaviour check: if the key constants ever stop
/// decoding, every test that depends on `pending_peer_configs` emitting a
/// peer would pass vacuously instead of failing loudly.
#[test]
fn the_key_fixtures_are_real_wireguard_keys() {
    for (name, k) in [("active", VALID_ACTIVE_KEY), ("pending", VALID_PENDING_KEY)] {
        assert!(
            pubkey_b64_to_hex(k).is_some(),
            "the {name} test key must decode, or `pending_peer_configs` drops the peer and the \
             agreement test below compares nothing against nothing"
        );
    }
}

// --- 1. The in-step case: a stranded overlap must dial -----------------------

/// **The dial that breaks the deadlock.** Our own cutover has run, so our
/// overlap tun and our active tun hold different keys and only the active tun
/// matches the peer's key set. The peer's active key is then at
/// `candidate_port + OWN_TUN_PORT_OFFSET` — where the allocator reserves its
/// own new-epoch tun — and that is the only address the epoch1<->epoch1
/// session can be formed at.
#[test]
fn a_stranded_overlap_dials_the_peers_reserved_own_tun_port() {
    // (own_active_epoch, built_at_own_epoch, candidate). Distances 1, 1, 5, 1
    // and 6, over three different candidate ports, so the answer is visibly
    // derived from the CANDIDATE and not from a hard-coded base.
    let cases: [(u32, u32, &str); 5] = [
        (1, 0, "10.9.0.2:51820"), // the canonical in-step shape
        (2, 1, "10.9.0.3:51820"),
        (7, 2, "10.9.0.4:40000"),
        (1, 0, "192.168.1.7:1024"),
        (9, 3, "10.9.0.5:51820"),
    ];
    for (own_active_epoch, built_at_own_epoch, candidate) in cases {
        let (ip, port) = split_candidate(candidate);
        let want = format!("{ip}:{}", port + OWN_TUN_PORT_OFFSET);

        let got = collapse_dial(own_active_epoch, built_at_own_epoch, candidate);
        assert_eq!(
            got.as_deref(),
            Some(want.as_str()),
            "our overlap was built at own epoch {built_at_own_epoch} and our active epoch is now \
             {own_active_epoch}, so our own cutover has run and the two devices hold different \
             keys. The peer's active key is at candidate_port + OWN_TUN_PORT_OFFSET ({want}); \
             anything else leaves the collapse gate waiting on a session it cannot address, and \
             the peer's retire is gated on that same session — the in-step deadlock."
        );
        assert_ne!(
            got.as_deref(),
            Some(candidate),
            "dialling the peer's BASE port {candidate} in the in-step case IS the bug: the \
             peer's epoch-0 key is there and its epoch-1 key is not, so the session never forms. \
             A run that reaches steady state while still showing the base port passed for the \
             wrong reason."
        );
        // The two derivations that now answer the same question must not
        // diverge even here, where only one of them is consulted.
        assert_eq!(
            got,
            own_tun_endpoint(candidate),
            "`collapse_dial`'s payload must BE `own_tun_endpoint`'s answer, not a second \
             derivation of it"
        );
    }
}

// --- 2. The one-sided non-regression ----------------------------------------

/// **THE ASSERTION THAT KEEPS FIVE GREEN ONE-SIDED TESTS GREEN.**
///
/// `built_at_own_epoch == own_active_epoch` means our overlap tun and our
/// active tun run the SAME private key — i.e. we never cut over, i.e. every
/// ONE-SIDED rotation. There the existing behaviour is already correct: the
/// base-port endpoint is EVENTUALLY correct, because the peer's retire is
/// gated on our overlap's session, which is live, and
/// `renormalize_active_listen_port` brings the peer's active key back to base
/// where our unchanged dial already points.
///
/// So the new path must be a literal no-op there — **by construction, not by
/// argument**. This is the test that fails first if the predicate is later
/// "simplified" away, and what it protects is concrete: fire a dial here and
/// the one-sided suite starts pinning a `:51821` endpoint at a gateway that
/// never moved off base, breaking rotations that work today.
#[test]
fn equal_epochs_never_dial_because_that_is_every_one_sided_rotation() {
    // Several epoch values, not just 0: a predicate written as `built_at != 0`
    // or `active != 0` passes at epoch 0 and is wrong everywhere else.
    for epoch in [0u32, 1, 2, 3, 7, 42, u32::MAX] {
        for candidate in ["10.9.0.2:51820", "10.9.0.3:1024", "192.168.1.7:40000"] {
            assert_eq!(
                collapse_dial(epoch, epoch, candidate),
                None,
                "epoch {epoch}: our overlap was built at the epoch our active tun still runs, so \
                 both devices hold the SAME key — this is a ONE-SIDED rotation, where only the \
                 peer is rotating and we never cut over. The base-port endpoint is EVENTUALLY \
                 correct there (the peer retires on our overlap's live session and renormalizes \
                 back to base), so the collapse arm must pin NOTHING and leave today's working \
                 behaviour alone. Returning Some here fires a rotation dial in five green \
                 one-sided netns tests that must never see one."
            );
        }
    }
}

/// The predicate is an INEQUALITY, and it must stay one.
///
/// `rotation::route_owner` gives the overlap the routes exactly when
/// `built_at_own_epoch == own_active_epoch`; everything else — including an
/// overlap stranded on an epoch we have rotated off — falls to the active
/// tun. `collapse_dial` must be that condition's exact complement, or there is
/// a state where the routes sit on the active tun with no endpoint that can
/// reach the peer: the deadlock, reopened one branch over.
///
/// A `built_at` AHEAD of `active` is not producible in a healthy fabric. It is
/// here to pin the SHAPE of the predicate, not a behaviour anyone depends on:
/// an implementation written as `built_at < active`, or as `active - built_at
/// == 1`, is an epoch-arithmetic assumption of exactly the kind that produced
/// bug 5 ("the second rotation of any gateway cannot complete",
/// `docs/research/port-authority-verification-the-shape-was-wrong.md`), and it
/// would read green against every ordinary case above.
#[test]
fn only_the_inequality_is_read_never_the_order_or_the_distance() {
    let candidate = "10.9.0.2:51820";
    let (ip, port) = split_candidate(candidate);
    let want = format!("{ip}:{}", port + OWN_TUN_PORT_OFFSET);

    // (own_active_epoch, built_at_own_epoch): distance 1 both ways, a large
    // distance, and a distance that straddles zero.
    for (active, built_at) in [(1u32, 0u32), (0, 1), (11, 5), (5, 11), (0, 9), (9, 0)] {
        assert_eq!(
            collapse_dial(active, built_at, candidate).as_deref(),
            Some(want.as_str()),
            "active {active} vs built_at {built_at}: the gate is `built_at_own_epoch != \
             own_active_epoch` — the same discriminator `rotation::route_owner` uses, so the two \
             stay exact complements. Any ordered or distance-based comparison is epoch \
             arithmetic, which this codebase has already been burned by once (bug 5)."
        );
    }
}

// --- 3. Hostile and unparseable candidates ----------------------------------

/// A candidate that is not `ip:port` yields no dial and no panic. This runs
/// inside the sync `State`-event path, so a panic here is a gateway crash, not
/// a failed rotation.
#[test]
fn an_unparseable_candidate_yields_no_dial_instead_of_a_panic() {
    let hostile = [
        ("", "empty string"),
        ("10.9.0.2", "no colon at all"),
        ("10.9.0.2:", "empty port"),
        ("10.9.0.2:abc", "non-numeric port"),
        ("10.9.0.2:-1", "negative port"),
        ("10.9.0.2:65536", "port above the u16 range"),
        ("10.9.0.2: 51820", "whitespace in the port"),
        ("10.9.0.2:51820\nendpoint=203.0.113.1:9", "UAPI line-injection payload"),
    ];
    for (candidate, why) in hostile {
        assert_eq!(
            collapse_dial(1, 0, candidate),
            None,
            "candidate {candidate:?} ({why}) has no derivable own-tun endpoint; the collapse arm \
             must pin nothing and let the existing candidate-chasing recovery run"
        );
        assert_eq!(
            own_tun_endpoint(candidate),
            None,
            "candidate {candidate:?} ({why}): `own_tun_endpoint` must agree — it is the single \
             definition `pending_peer_configs` also builds on, and a peer it cannot derive an \
             endpoint for is dropped from the overlap device rather than emitted with a \
             half-built one"
        );
    }
}

// --- 4. The u16 boundary ----------------------------------------------------

/// A peer legitimately advertising `:65535` has no reachable own-tun port —
/// `65535 + 1` does not exist. The derivation must return `None`, not wrap to
/// `:0`. This is the one hostile-looking case that is REACHABLE today:
/// `is_dialable_endpoint` accepts `:65535`, so the ingest filter keeps it.
///
/// Wrapping would be worse than useless: `:0` is a wildcard bind, so the dial
/// would silently point at nothing while every gate above it reported a
/// programmed endpoint.
#[test]
fn a_peer_on_the_last_udp_port_yields_no_dial_rather_than_wrapping_to_zero() {
    for candidate in ["10.9.0.2:65535", "192.168.1.7:65535"] {
        assert_eq!(
            collapse_dial(1, 0, candidate),
            None,
            "candidate {candidate}: port 65535 + OWN_TUN_PORT_OFFSET does not fit in a u16. The \
             offset must be a checked add — a wrapping one dials :0, a wildcard that silently \
             reaches nothing while looking programmed."
        );
        assert_eq!(own_tun_endpoint(candidate), None, "{candidate}: same, at the extraction");
    }

    // The rung immediately below, so the None above is a boundary and not a
    // whole range of ports quietly refused.
    let last_ok = format!("10.9.0.2:{}", u16::MAX - OWN_TUN_PORT_OFFSET);
    let want = format!("10.9.0.2:{}", u16::MAX);
    assert_eq!(
        collapse_dial(1, 0, &last_ok).as_deref(),
        Some(want.as_str()),
        "the highest candidate port that CAN be offset must still be dialled — the checked add \
         may reject only what genuinely overflows"
    );
}

// --- 5. Agreement: the two derivations must not drift apart again -----------

/// **THE CROSS-MODULE PIN.** Bug 5 was never a wrong number in one place: it
/// was two functions answering "which UDP port is a rotating gateway's
/// in-flight new epoch on?" with two derivations that agreed on the first
/// rotation and diverged after. v0.7.2 ended that by making the reservation
/// the single authority. This fix adds a SECOND reader of that answer, so the
/// same failure is available again — unless something compares them.
///
/// This test asks both and compares the produced strings. Neither side can
/// move without the other.
///
/// The two are asked at different moments of the same rotation, and that is
/// deliberate rather than a fixture accident: `pending_peer_configs` builds
/// the overlap while the peer still advertises a pending epoch, and
/// `collapse_dial` fires after the peer has promoted (the collapse arm
/// requires `pending_key()` to be `None`). Same question — where is the peer's
/// in-flight new epoch listening — asked on either side of the promote, and
/// the answer must not change across it, because the peer's device did not
/// move.
#[test]
fn collapse_dial_and_pending_peer_configs_emit_the_identical_string() {
    // The top of the offsettable range, exercised through BOTH derivations so
    // a `saturating_add` on one side and a `checked_add` on the other cannot
    // hide behind ordinary ports.
    let highest_offsettable = format!("10.9.0.4:{}", u16::MAX - OWN_TUN_PORT_OFFSET);
    for candidate in [
        "10.9.0.2:51820",
        "10.9.0.3:1024",
        "192.168.1.7:40000",
        "203.0.113.9:51820",
        highest_offsettable.as_str(),
    ] {
        let from_overlap_builder = pending_endpoint(&ds(vec![rotating_peer(2, candidate)]));
        let from_collapse = collapse_dial(1, 0, candidate).unwrap_or_else(|| {
            panic!("collapse_dial must produce an endpoint for the well-formed candidate {candidate}")
        });

        assert_eq!(
            from_collapse, from_overlap_builder,
            "candidate {candidate}: the Role-B overlap builder dials {from_overlap_builder} and \
             the collapse arm dials {from_collapse}. These are two readers of ONE answer — which \
             port the peer's in-flight new epoch is reachable on — and the last time two \
             derivations of that answer were allowed to drift, they agreed on rotation 0 -> 1 \
             and nothing was red until the second rotation of a real gateway (bug 5). Extract, \
             do not restate."
        );
        assert_eq!(
            own_tun_endpoint(candidate).as_deref(),
            Some(from_overlap_builder.as_str()),
            "candidate {candidate}: the extracted `own_tun_endpoint` must reproduce what \
             `pending_peer_configs` emits exactly — the extraction is behaviour-preserving or it \
             is a rewrite"
        );
    }
}

// --- 6. Agreement with the allocator that reserves the port ------------------

/// The half that makes the agreement above STRUCTURAL rather than lucky: the
/// port the collapse arm dials must be the port `tunnelset::plan_tunnel`
/// actually hands the peer's own new-epoch tun — computed under realistic
/// pressure, with the peer already carrying three Role-B overlaps toward other
/// peers, planned FIRST. (One controller timer means the in-step fabric is the
/// default case, and under the pre-piece-3 shared free list that ordering is
/// exactly what stole `base + 1`.)
///
/// The peer's candidate port and its base port are the same number at every
/// rotation because `renormalize_active_listen_port` returns the survivor to
/// base at every retire (v0.7.2, piece 2).
#[test]
fn the_port_the_collapse_arm_dials_is_the_port_the_allocator_reserves() {
    use wiremesh_gateway::tunnelset::{plan_tunnel, TunnelId, TunnelPlan};
    const BASE_TUN: &str = "wg0";

    for base_port in [51820u16, 1024, 40000] {
        for (peer_active_epoch, peer_new_epoch) in [(0u32, 1u32), (1, 2), (2, 4), (5, 11)] {
            // --- Side 1: the peer allocates the tun its new epoch lives on. ---
            let mut live = vec![TunnelPlan {
                id: TunnelId::Own { epoch: peer_active_epoch },
                ifname: BASE_TUN.to_string(),
                listen_port: base_port,
            }];
            for gid in [21u64, 22, 23] {
                let id = TunnelId::Overlap { gateway_id: gid, epoch: peer_new_epoch };
                let plan = plan_tunnel(id, BASE_TUN, base_port, &live)
                    .unwrap_or_else(|e| panic!("the peer's overlap toward {gid}: {e:#}"));
                live.push(plan);
            }
            let peer_own = plan_tunnel(TunnelId::Own { epoch: peer_new_epoch }, BASE_TUN, base_port, &live)
                .unwrap_or_else(|e| panic!("the peer's own new epoch {peer_new_epoch}: {e:#}"));

            // --- Side 2: our collapse arm decides where to dial it. ---
            let candidate = format!("10.9.0.7:{base_port}");
            let dialled = collapse_dial(1, 0, &candidate)
                .unwrap_or_else(|| panic!("no dial derived for {candidate}"));
            let (_, dialled_port) = split_candidate(&dialled);

            assert_eq!(
                dialled_port, peer_own.listen_port,
                "base {base_port}, peer epoch {peer_active_epoch} -> {peer_new_epoch}: the \
                 collapse arm dials {dialled_port} but the peer's new-epoch tun was allocated on \
                 {}. These are computed by two different functions in two different modules and \
                 MUST agree at every rotation — before the own-tun port was reserved they agreed \
                 only at the first one, and the second rotation of any gateway could not \
                 complete.",
                peer_own.listen_port,
            );
        }
    }
}
