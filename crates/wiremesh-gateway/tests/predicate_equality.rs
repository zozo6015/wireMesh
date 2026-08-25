//! (Backlog task #5) The controller's ingress filter and the gateway's UAPI
//! validator MUST be the SAME predicate. This file is the executable proof.
//!
//! # The two halves
//!
//! Backlog item 1 added a filter at each end of a candidate endpoint's
//! journey, and they are written differently:
//!
//!  - controller, `services/sync.rs::usable_local_candidates`:
//!    `ep.parse::<std::net::SocketAddrV4>().is_err()` -> drop
//!  - gateway, `uapi::is_dialable_endpoint` -> `validate_ipv4_endpoint`, i.e.
//!    `matches!(ep.parse::<std::net::SocketAddr>(), Ok(SocketAddr::V4(_)))`
//!
//! Both files' doc comments treat their equality as a CONTRACT ("the same one
//! `wiremesh_gateway::uapi::validate_ipv4_endpoint` applies at the far end of
//! this data's journey — which is the point"). The reasoning for why they
//! agree is sound — std's `FromStr for SocketAddr` tries the v4 grammar first
//! and `FromStr for SocketAddrV4` drives the same parser, both requiring the
//! whole input to be consumed — but it is REASONING. Nothing executed it.
//! This does.
//!
//! # Why the direction matters, asymmetrically
//!
//! The two failure modes are not the same size, so the failure output below
//! labels every divergence with which one it is:
//!
//!  - **controller LOOSER than the gateway** (it stores something
//!    `is_dialable_endpoint` rejects): a live CRASH-LOOP path. The stored
//!    string is re-advertised as `Peer.candidate_endpoints` to every other
//!    gateway, becomes `PeerState::primary_endpoint()`, and reaches
//!    `uapi::push_peer_block`, whose `Err` propagates to `encode_set` ->
//!    `apply_state` (called with `?` BEFORE the incremental `match delta`, so
//!    no path avoids it), unwinds out of `run()` past both loops and ends the
//!    process from `main`'s `rt.block_on(run(cfg))`. It is also written to
//!    `state.json`, so the restart dies at the same call.
//!  - **controller STRICTER than the gateway** (it drops something the
//!    gateway could have dialled): silent. A correctly-addressed gateway is
//!    stranded with fewer candidates — or none — and simply never gets a
//!    direct path, with nothing in any log saying why.
//!
//! # Corpus provenance
//!
//! The strings below are the union of the lists ALREADY in the tree, not a
//! parallel set invented here:
//!
//!  - `crates/wiremesh-gateway/src/uapi.rs`'s `mod tests` accept-list and
//!    reject-list (`validate_ipv4_endpoint_accepts_*` /
//!    `validate_ipv4_endpoint_rejects_*`)
//!  - `crates/wiremesh-gateway/tests/uapi_endpoint_validation.rs`'s `ACCEPTED`
//!    and `REJECTED`
//!  - `crates/wiremesh-controller/tests/report_local_endpoints_validation.rs`'s
//!    `REJECTED`
//!  - the known-gap list from
//!    `validate_ipv4_endpoint_is_parse_only_so_undialable_addresses_are_accepted_today`
//!    — accepted by BOTH sides today, so this file asserts they AGREE on them,
//!    never that they are rejected
//!
//! They are transcribed rather than imported because each of those lists lives
//! either in a private `mod tests` or in another crate's test BINARY, neither
//! of which is importable — the same reason `report_local_endpoints_validation.rs`
//! keeps its own copy of `candidates_for`. If you tighten or loosen either
//! predicate, this corpus is where the new shape gets added, ONCE.
//!
//! Pure test: no netns, no privileged container, no device.

use wiremesh_gateway::uapi::is_dialable_endpoint;

/// Compare the two predicates over `corpus` and return one rendered line per
/// DISAGREEMENT, each naming its direction and its consequence.
///
/// Collect-then-assert rather than assert-per-iteration, matching the idiom in
/// `uapi.rs`'s own tests: a divergence is a contract break between two crates,
/// and whoever is fixing it needs the complete list in one run, not the first
/// element of it.
fn divergences<'a>(corpus: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    corpus
        .into_iter()
        .filter_map(|ep| {
            let gateway_dials = is_dialable_endpoint(ep);
            let controller_stores = ep.parse::<std::net::SocketAddrV4>().is_ok();
            if gateway_dials == controller_stores {
                return None;
            }
            Some(if controller_stores {
                format!(
                    "{ep:?}: controller ACCEPTS (parses as SocketAddrV4) but \
                     `is_dialable_endpoint` REJECTS -> CRASH-LOOP. The controller stores \
                     and re-advertises it, the receiving gateway feeds it to the UAPI, \
                     `encode_set` errors, and the `?` in `apply_state` unwinds out of \
                     `run()` to `main` — the peer gateway process EXITS, and its \
                     `state.json` now blocks the restart too."
                )
            } else {
                format!(
                    "{ep:?}: controller DROPS it but `is_dialable_endpoint` would have \
                     dialled it -> SILENT STRANDING. A correctly-addressed gateway loses \
                     this candidate (possibly its only one) and never gets a direct path, \
                     with nothing in any log naming the cause."
                )
            })
        })
        .collect()
}

/// Every endpoint form either side of the fabric has an opinion about.
///
/// Grouped by provenance so a future edit lands in the right place; the test
/// itself does not care which group a string came from, only that both
/// predicates answer identically.
const CURATED: &[&str] = &[
    // --- accept-lists (uapi.rs `mod tests`, tests/uapi_endpoint_validation.rs
    //     `ACCEPTED`, and report_local_endpoints_validation.rs's valid set) ---
    "203.0.113.5:51820", // public, canonical WG port
    "10.0.0.1:1",        // lowest usable port
    "192.168.1.7:65535", // highest port
    "172.16.4.4:51821",  // the +1 overlap port `pending_peer_configs` derives
    "10.0.0.5:51820",
    "10.0.0.6:51820",
    "192.168.1.7:1",
    "203.0.113.9:65535",
    // --- reject-lists ---
    "",                             // sorts before every real address -> candidates[0]
    " ",                            // whitespace only
    "not-an-endpoint",              // unstructured garbage: the base case
    "!!! not an endpoint",          // the low-sorting shape used by the ingest suites
    "abc:123",                      // DNS name + port: survives the `rsplit_once(':')` half-check
    "controller.example.com:51820", // the plausible-hostname form of the same trap
    "localhost:51820",              // the most plausible one of all — still not a literal
    "10.0.0.5",                     // no port
    "10.0.0.5:",                    // present but empty port
    ":51820",                       // port with no address
    "10.0.0.5:65536",               // one past the top of u16
    "10.0.0.5:70000",               // well past the top of u16
    "10.0.0.5:-1",                  // negative port
    "10.0.0.5:0x1",                 // hex port
    "10.0.0.5:0x51820",             // the controller suite's non-decimal port
    "10.0.0.5:+1",                  // signed port
    "999.1.1.1:51820",              // out-of-range octet: dotted-quad SHAPE is not enough
    "10.0.0.5.6:51820",             // five octets
    "10.0.0:51820",                 // three octets
    "10.0.0.5:51820:51820",         // two ports
    "10.0.0.5%eth0:51820",          // IPv4 with a zone index
    "::1:51820",                    // unbracketed IPv6-shaped string
    "[::1]:51820",                  // bracketed IPv6 loopback
    "[2001:db8::1]:51820",          // routable IPv6 literal
    "[2001:0db8:0000:0000:0000:0000:0000:0001]:51820", // full-form IPv6
    "[fe80::1]:51820",              // link-local IPv6
    "[fe80::1%eth0]:51820",         // link-local IPv6 with a zone index
    // --- the awkward ones, called out by name because they are where an
    //     "obviously equivalent" pair of parsers would actually diverge ---
    //
    // IPv4-MAPPED IPv6. `is_dialable_endpoint` must send this down the IPv6
    // arm rather than unwrapping the embedded IPv4, and `SocketAddrV4`'s
    // FromStr must not accept the bracketed syntax at all. If either side
    // blinked, the bracketed form becomes a way to smuggle an address past a
    // filter that only inspects dotted quads.
    "[::ffff:10.0.0.5]:51820",
    // Leading-zero octet. `Ipv4Addr`'s FromStr refuses these precisely because
    // C's `inet_aton` reads them as OCTAL (`010` = 8, not 10) — the same
    // string naming two different hosts depending on who parses it. Both sides
    // must refuse it for the same reason.
    "010.0.0.5:51820",
    // Trailing newline: the UAPI wire format is newline-delimited key=value
    // lines, so this is a line-INJECTION vector, not merely a parse failure.
    // Both parsers must require full-input consumption or the injection lands.
    "10.0.0.5:51820\n",
    "10.0.0.5:51820\nendpoint=1.2.3.4:1", // the explicit injection payload
    " 10.0.0.5:51820",                    // leading whitespace: FromStr does not trim
    "10.0.0.5:51820 ",                    // trailing whitespace, same reason
    "\t10.0.0.5:51820",                   // the tab variant of the same
    "10.0.0.5:51820\r\n",                 // and the CRLF one
];

/// Accepted by BOTH predicates today. Listed SEPARATELY and asserted as
/// AGREEMENT, never as rejection: these are the documented known gap
/// (`uapi.rs`'s
/// `validate_ipv4_endpoint_is_parse_only_so_undialable_addresses_are_accepted_today`)
/// — undialable addresses that nonetheless parse. Whether to tighten the
/// predicate is an open decision this file does not take. What it DOES pin is
/// that if someone tightens one side, they cannot leave the other behind.
const KNOWN_GAP_ACCEPTED_BY_BOTH: &[&str] = &[
    "10.0.0.5:0",            // port 0 is not a dialable UDP port
    "0.0.0.0:51820",         // the unspecified address names no host
    "0.0.0.0:0",             // both at once
    "127.0.0.1:51820",       // loopback: on a PEER this points that peer at itself
    "169.254.1.1:51820",     // link-local
    "224.0.0.1:51820",       // multicast is not a unicast peer endpoint
    "255.255.255.255:65535", // the broadcast address
];

#[test]
fn the_controller_filter_and_the_gateway_validator_are_the_same_predicate() {
    let corpus: Vec<&str> = CURATED
        .iter()
        .chain(KNOWN_GAP_ACCEPTED_BY_BOTH.iter())
        .copied()
        .collect();

    // Positive/negative controls FIRST. Equality is trivially satisfiable by
    // two predicates that both say "no" to everything (or both say "yes"), and
    // either would be a catastrophe that this file must not report as green.
    assert!(
        corpus.iter().any(|ep| is_dialable_endpoint(ep)),
        "the corpus must contain at least one endpoint BOTH sides accept, or the equality \
         assertion below can be satisfied by a predicate that rejects everything — which \
         would strand every gateway in the fabric while this test stayed green"
    );
    assert!(
        corpus.iter().any(|ep| !is_dialable_endpoint(ep)),
        "the corpus must contain at least one endpoint BOTH sides reject, or the equality \
         assertion below can be satisfied by a predicate that accepts everything — which \
         is the crash-loop this whole item exists to close"
    );

    let diverged = divergences(corpus);
    assert!(
        diverged.is_empty(),
        "the controller's `SocketAddrV4` ingress filter and the gateway's \
         `is_dialable_endpoint` MUST answer identically for every string; they disagree \
         on {}:\n  {}\n\n\
         Both `services/sync.rs` and `uapi.rs` document this equality as a CONTRACT — the \
         controller filter exists only to keep unusable candidates away from the far end's \
         UAPI, which is not something it can do while holding a different opinion about \
         what \"usable\" means. Fix the two predicates together, and add the new shape to \
         this corpus.",
        diverged.len(),
        diverged.join("\n  ")
    );
}

/// The curated list is the shapes someone thought of. This one is the shapes
/// nobody thought of: a cross-product of address-ish and port-ish tokens, each
/// also wrapped in the whitespace/newline/bracket decorations that are exactly
/// where a full-input-consumption difference between the two parsers would
/// show up. Cheap (a few thousand string parses) and it is the part of this
/// file that could actually surprise someone.
#[test]
fn the_two_predicates_agree_across_a_generated_cross_product() {
    const ADDRS: &[&str] = &[
        "10.0.0.5",
        "0.0.0.0",
        "255.255.255.255",
        "010.0.0.5",
        "10.0.0",
        "10.0.0.5.6",
        "999.1.1.1",
        "10.0.0.05",
        "10.0.0.5.",
        ".10.0.0.5",
        "10.0.0.+5",
        "10.0.0.-5",
        "10.0.0.0x5",
        "::1",
        "[::1]",
        "[::ffff:10.0.0.5]",
        "[fe80::1%eth0]",
        "localhost",
        "abc",
        "",
    ];
    const PORTS: &[&str] = &[
        "0", "1", "51820", "65535", "65536", "70000", "-1", "+1", "0x1", "051820", " 51820",
        "51820 ", "", "abc", "1.5",
    ];
    // Each decoration is applied to the whole `addr:port` string. `{}` is the
    // undecorated control.
    const WRAPS: &[&str] = &[
        "{}", " {}", "{} ", "\t{}", "{}\n", "{}\r\n", "\n{}", "[{}]", "{}\0",
    ];

    let mut corpus: Vec<String> = Vec::new();
    for a in ADDRS {
        for p in PORTS {
            let joined = format!("{a}:{p}");
            for w in WRAPS {
                corpus.push(w.replace("{}", &joined));
            }
        }
    }

    let diverged = divergences(corpus.iter().map(String::as_str));
    assert!(
        diverged.is_empty(),
        "{} of {} generated forms are judged differently by the controller's \
         `SocketAddrV4` filter and the gateway's `is_dialable_endpoint`:\n  {}\n\n\
         These are machine-generated precisely because the hand-written corpus can only \
         contain shapes someone anticipated. A divergence here is the same contract break \
         as one in the curated list and carries the same two consequences (controller \
         looser = crash-loop; controller stricter = a silently stranded gateway).",
        diverged.len(),
        corpus.len(),
        diverged.join("\n  ")
    );
}

/// The equality above says the two agree. This says WHAT they agree on for the
/// handful of strings whose answer is load-bearing — so a future change that
/// flips both predicates in lockstep (still equal, both now wrong) cannot pass
/// silently.
#[test]
fn the_agreed_answer_is_the_right_one_for_the_load_bearing_cases() {
    let must_accept = [
        "10.0.0.5:51820",
        "203.0.113.5:51820",
        "192.168.1.7:65535",
        "10.0.0.1:1",
    ];
    let must_reject = [
        "abc:123",
        "[::ffff:10.0.0.5]:51820",
        "010.0.0.5:51820",
        "10.0.0.5:51820\n",
        "10.0.0.5:51820\nendpoint=1.2.3.4:1",
        " 10.0.0.5:51820",
        "",
    ];

    let wrongly_rejected: Vec<&str> = must_accept
        .into_iter()
        .filter(|ep| !is_dialable_endpoint(ep))
        .collect();
    assert!(
        wrongly_rejected.is_empty(),
        "these are ordinary IPv4 socket addresses and BOTH sides must accept them, but the \
         gateway now rejects {wrongly_rejected:?}. A predicate that acquired an extra \
         opinion (a port allow-range, an RFC1918-only rule) costs every gateway addressed \
         that way its direct path, and does it silently."
    );

    let wrongly_accepted: Vec<&str> = must_reject
        .into_iter()
        .filter(|ep| is_dialable_endpoint(ep))
        .collect();
    assert!(
        wrongly_accepted.is_empty(),
        "these must be rejected by BOTH sides but the gateway now accepts \
         {wrongly_accepted:?}. `abc:123` survives the only other shape check on the \
         gateway path (`reconcile::pending_peer_configs`' `rsplit_once(':')` + \
         `u16::parse`); `[::ffff:10.0.0.5]:51820` is an IPv4 address wearing IPv6 syntax, \
         so unwrapping it makes the bracketed form a way past any dotted-quad-only filter; \
         `010.0.0.5:51820` is the octal/decimal ambiguity `inet_aton` would resolve \
         differently from Rust; and the two newline payloads are UAPI line-INJECTION into \
         the boringtun `set` message, not merely parse failures."
    );
}
