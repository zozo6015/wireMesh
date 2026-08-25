//! (Backlog item 1) `Sync.Report`'s `local_endpoints` must be VALIDATED at the
//! controller's ingress before it is persisted and re-advertised.
//!
//! # Why this is a crash-loop, not a validation nicety
//!
//! `SyncSvc::report` hands `req.local_endpoints` straight to
//! `Db::set_local_candidates`, which only `sort()`+`dedup()`s and stores the
//! strings verbatim. `Db::candidates_for` reads them back unchanged, and the
//! projection re-advertises them to EVERY other gateway as
//! `Peer.candidate_endpoints`. On the receiving gateway they become
//! `PeerState.candidates`, `primary_endpoint()` returns `candidates.first()`,
//! and `uapi::push_peer_block` calls `validate_ipv4_endpoint(ep)?` — which
//! fails the parse and returns `Err`.
//!
//! That `Err` is NOT a degraded peer. `apply_state` calls
//! `uapi::encode_set(&dev)?` BEFORE the incremental `match delta`, so no path
//! avoids it; the `?` unwinds out of `run(cfg)` and `main`'s
//! `rt.block_on(run(cfg))` — **the gateway process exits non-zero**, on every
//! peer at once. The boot-time `apply_state(None, ds, ..)` is the same call,
//! so a candidate that reached `state.json` also blocks the restart.
//!
//! Reachability: `gateway.candidate_endpoint` (the controller-OBSERVED slot,
//! which sorts first in `candidates_for`) is nullable and is only ever
//! written by the observe path — so exactly when observe UDP is blocked (the
//! NAT case this fabric exists for) there is no observed value and the
//! reported local endpoint lands at `candidates[0]`. And
//! `set_local_candidates` SORTS, so a low-sorting garbage string takes index
//! 0 for free.
//!
//! A stock gateway cannot emit garbage (`netif::local_wg_endpoints` formats
//! from a parsed `Ipv4Addr`), so these tests exercise the RPC boundary
//! directly: the threat model is a compromised, modified, or version-skewed
//! gateway holding a valid fabric-CA certificate. One authenticated peer must
//! not be able to crash-loop every other gateway in the fabric.
//!
//! # The contract these pin
//!
//! FILTER-with-a-log, not hard-reject. A gateway that reports four addresses
//! of which one is malformed must keep the three good ones — costing it its
//! whole candidate set (and therefore its direct path) because one entry was
//! bad would turn a cosmetic bug into an outage. So `Sync.Report` still
//! returns `Ok`; only the unusable elements are dropped.
//!
//! Companion suites: `tests/report_local_endpoints.rs` (the Task-4/Task-8
//! persistence + empty-clears semantics these must not regress) and
//! `tests/candidates.rs` (the `Db`-level merge model).

use std::collections::BTreeSet;

/// The maximum number of locally-reported candidate endpoints the controller
/// will store for one gateway.
///
/// **Why a cap exists at all:** there was none, anywhere. The only ceiling
/// was tonic's default 4MB request limit — roughly 200k strings — and every
/// one of them is persisted, then fanned out to every other gateway on
/// every snapshot and delta, then run through `Db::candidates_for`'s O(n²)
/// `Vec::contains` dedup. One authenticated gateway could therefore make the
/// controller do quadratic work and inflate every peer's projection at will.
///
/// **Why 32:** a local candidate is one `ip:wg_port` per routable local IPv4
/// address (`netif::parse_ip_addr_output` — one line per `inet` address,
/// loopback/link-local filtered, all at the single WG port). A segment
/// gateway realistically has 1-4 of those; even a container host with extra
/// bridges is in the single digits. 32 is roughly an order of magnitude of
/// headroom over the honest worst case while staying small enough that the
/// quadratic dedup and the per-peer fanout are both free. It is also well
/// under any budget a NAT puncher could actually work through: the puncher
/// has to try candidates in sequence against a bounded punch window, so a
/// list it cannot finish is not a longer list, it is a broken one.
///
/// Deliberately an alias for the PRODUCTION constant rather than a repeated
/// literal: a cap these tests carried a private copy of could be raised in
/// the controller without a single assertion here noticing.
use wiremesh_controller::services::sync::MAX_LOCAL_CANDIDATES;

/// Reads `gw_id`'s currently STORED `source = 'local'` rows straight off the
/// controller's on-disk DB, over a second raw `rusqlite::Connection` onto the
/// same `controller.db` file — the pattern `tests/candidates.rs`'s
/// `raw_conn` helper establishes (each `tests/*.rs` is its own binary, so
/// duplicating this small helper is the established convention here rather
/// than a shared crate dependency).
///
/// Deliberately bypasses `Db::candidates_for` rather than calling it: that
/// accessor grew its own read-side validity filter (the same predicate as
/// `SyncSvc::usable_local_candidates` below, pinned separately by
/// `tests/candidates.rs`), so observing through it here would pass whether
/// or not THIS suite's actual target — the write-side ingest filter inside
/// `Sync.Report` — still exists. Reading the raw table observes STORAGE,
/// which only the ingest filter controls; `tests/candidates.rs` is what
/// pins the read-side filter, and the two must not be able to mask each
/// other.
///
/// Returns only the local rows, sorted — `candidates_for`'s prepended
/// controller-observed slot (`gateway.candidate_endpoint`) is deliberately
/// excluded. Nothing in this file ever populates that column (`Sync.Report`
/// writes only `local_endpoints`), so every assertion below observes the
/// same values it did when reading through `candidates_for`.
async fn stored_local_candidates(h: &wiremesh_testkit::TestController, gw_id: u64) -> Vec<String> {
    let db_path = h.data_dir().join("controller.db");
    tokio::task::spawn_blocking(move || {
        let conn = rusqlite::Connection::open(&db_path)
            .unwrap_or_else(|e| panic!("opening {} for raw read: {e}", db_path.display()));
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .expect("setting busy_timeout on the raw inspection connection");
        let mut stmt = conn
            .prepare(
                "SELECT endpoint FROM gateway_candidate WHERE gateway_id = ?1 AND source = \
                 'local' ORDER BY endpoint",
            )
            .expect("preparing raw local-candidate read");
        stmt.query_map(rusqlite::params![gw_id as i64], |row| {
            row.get::<_, String>(0)
        })
        .expect("querying raw local candidates")
        .collect::<Result<Vec<String>, _>>()
        .expect("collecting raw local candidate rows")
    })
    .await
    .expect("stored_local_candidates blocking task panicked")
}

/// Every non-`SocketAddrV4` shape a compromised or version-skewed gateway
/// could put on the wire, each paired with why it specifically matters.
///
/// The reference implementation of "usable" is the gateway's own
/// `uapi::validate_ipv4_endpoint`: `ep.parse::<std::net::SocketAddr>()` must
/// yield the `V4` variant. Anything else is what kills the gateway process,
/// so anything else is what the controller must refuse to store.
const REJECTED: &[(&str, &str)] = &[
    (
        "",
        "an empty string parses as nothing and reaches candidates[0] first of all — \
          it sorts before every real address",
    ),
    ("not-an-endpoint", "unstructured garbage: the base case"),
    (
        "abc:123",
        "a DNS name with a port. THIS is the dangerous one: it survives \
         `reconcile::pending_peer_configs`' own `rsplit_once(':')` + port parse, so it \
         passes the only half-check anywhere on the gateway path and then dies later \
         inside `validate_ipv4_endpoint` — v1 dial targets are IPv4 literals only, \
         resolution never happens here",
    ),
    (
        "controller.example.com:51820",
        "the plausible-looking hostname form of the same trap",
    ),
    (
        "10.0.0.5",
        "an IPv4 address with NO port: WireGuard's UAPI endpoint= needs ip:port",
    ),
    ("10.0.0.5:", "a present but empty port"),
    (":51820", "a port with no address"),
    ("10.0.0.5:70000", "port above 65535 — out of u16 range"),
    ("10.0.0.5:-1", "a negative port"),
    ("10.0.0.5:0x51820", "a non-decimal port"),
    (
        "999.1.1.1:51820",
        "an out-of-range octet: dotted-quad SHAPE is not enough",
    ),
    ("10.0.0.5.6:51820", "five octets"),
    (
        " 10.0.0.5:51820",
        "leading whitespace — `SocketAddr`'s FromStr does not trim, so \
                         this is a distinct string that fails the parse",
    ),
    ("10.0.0.5:51820 ", "trailing whitespace, same reason"),
    (
        "[::1]:51820",
        "the bracketed IPv6 literal form: parses fine as SocketAddr::V6 and \
                     is then a HARD error in `validate_ipv4_endpoint` — v1 is IPv4-only \
                     end to end (spec §1)",
    ),
    (
        "[2001:db8::1]:51820",
        "a routable IPv6 literal, same rejection",
    ),
    ("::1:51820", "an unbracketed IPv6-shaped string"),
    (
        "[fe80::1%eth0]:51820",
        "a link-local IPv6 with a zone index",
    ),
    (
        "10.0.0.5:51820\n",
        "a trailing newline: the UAPI wire protocol is newline-delimited key=value \
         lines, so an endpoint carrying one is a line-injection vector into the \
         boringtun `set` message, not merely a parse failure",
    ),
    (
        "10.0.0.5:51820\nendpoint=1.2.3.4:1",
        "the explicit UAPI line-injection payload",
    ),
];

#[tokio::test]
async fn mixed_valid_and_invalid_local_endpoints_keeps_exactly_the_valid_ones() {
    let h = wiremesh_testkit::TestController::start().await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;

    a.report(
        0,
        &[
            "!!! not an endpoint",
            "10.0.0.5:51820",
            "abc:123",
            "10.0.0.6:51820",
        ],
    )
    .await
    .expect(
        "a report carrying SOME malformed local endpoints must still SUCCEED: the fix is \
         filter-with-a-log, not hard-reject. Failing the RPC would mean a gateway that got \
         one address wrong loses its whole candidate set, and with it its direct path — \
         turning a cosmetic bug into an outage.",
    );

    assert_eq!(
        stored_local_candidates(&h, a.id()).await,
        vec!["10.0.0.5:51820".to_string(), "10.0.0.6:51820".to_string()],
        "the controller must persist exactly the two parseable IPv4 endpoints and drop \
         `!!! not an endpoint` and `abc:123`. Storing either one re-advertises it to every \
         other gateway, where `primary_endpoint()` feeds it to \
         `uapi::validate_ipv4_endpoint`, whose Err unwinds out of `apply_state` -> `run` -> \
         `main` and EXITS THE PEER GATEWAY PROCESS. `set_local_candidates` sorts, so \
         `!!! ...` would take candidates[0] outright."
    );
}

#[tokio::test]
async fn every_non_ipv4_socket_form_is_rejected_without_losing_the_valid_sibling() {
    let h = wiremesh_testkit::TestController::start().await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;

    const GOOD: &str = "10.0.0.5:51820";

    for (version, (bad, why)) in REJECTED.iter().enumerate() {
        // Report the bad form alongside a known-good one. `set_local_candidates`
        // is a full REPLACE, so each round stands alone: whatever survives IS
        // the stored set.
        a.report(version as u64, &[bad, GOOD])
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "reporting the malformed endpoint {bad:?} must not FAIL the RPC \
                 (filter-with-a-log, not hard-reject) — {why}. Got: {e}"
                )
            });

        assert_eq!(
            stored_local_candidates(&h, a.id()).await,
            vec![GOOD.to_string()],
            "{bad:?} must be dropped and {GOOD:?} must survive.\n  why it matters: {why}\n  \
             what happens if it is stored: the controller re-advertises it as a \
             `Peer.candidate_endpoints` entry to every other gateway, where \
             `uapi::validate_ipv4_endpoint` rejects it and the resulting `Err` unwinds out \
             of `apply_state` past both loops in `run()` and terminates the process — and \
             because it is also written to `state.json`, the restart hits the same call at \
             boot. One authenticated peer must not be able to crash-loop the fabric."
        );
    }
}

#[tokio::test]
async fn valid_ipv4_socket_endpoints_survive_unchanged() {
    let h = wiremesh_testkit::TestController::start().await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;

    // Deliberately spans the edges of the accepted space: a low port, the
    // maximum port, a public address, and an RFC1918 one. Validation must be
    // exactly "parses as SocketAddrV4" — the same predicate the gateway's
    // `uapi::validate_ipv4_endpoint` applies — and must NOT quietly acquire
    // extra opinions (a port range, a private-address rule) that would strand
    // a legitimately-addressed gateway with no candidates at all.
    let valid = [
        "10.0.0.5:51820",
        "192.168.1.7:1",
        "203.0.113.9:65535",
        "172.16.4.4:51821",
    ];

    a.report(0, &valid)
        .await
        .expect("a fully-valid report must succeed");

    let mut expected: Vec<String> = valid.iter().map(|s| s.to_string()).collect();
    expected.sort();
    assert_eq!(
        stored_local_candidates(&h, a.id()).await,
        expected,
        "every endpoint that parses as an IPv4 socket address must be stored VERBATIM \
         (sorted by `Db::set_local_candidates`, deduped, otherwise untouched). Validation \
         must be exactly the gateway's own accept-predicate — no narrower — or a gateway \
         with a legitimate address on an unusual port silently loses its direct path."
    );
}

#[tokio::test]
async fn a_report_of_only_invalid_endpoints_succeeds_and_clears_the_set() {
    let h = wiremesh_testkit::TestController::start().await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;

    a.report(0, &["10.0.0.5:51820"])
        .await
        .expect("baseline report");
    assert_eq!(
        stored_local_candidates(&h, a.id()).await,
        vec!["10.0.0.5:51820".to_string()]
    );

    a.report(1, &["abc:123", "[::1]:51820"]).await.expect(
        "an all-malformed report must still return Ok — the RPC also carries \
         `applied_version`, `peer_paths`, `relay_health` and `epoch_acks`, and failing it \
         would drop all of those on the floor too, wedging rotation and path state over a \
         bad address string.",
    );

    assert_eq!(
        stored_local_candidates(&h, a.id()).await,
        Vec::<String>::new(),
        "after filtering, the reported set is EMPTY, and `local_endpoints` is a full \
         REPLACE (cycle-4b Task 8: the gateway sends its complete current local-address \
         set every round). So this must clear, exactly as an explicitly-empty report does \
         — see `report_local_endpoints.rs`'s \
         `empty_local_endpoints_report_clears_previously_reported_locals`. Retaining the \
         old set here would resurrect the very staleness Task 8 removed, and would do it \
         precisely when the peer is misbehaving."
    );
}

#[tokio::test]
async fn a_local_endpoint_list_at_the_cap_is_stored_in_full() {
    let h = wiremesh_testkit::TestController::start().await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;

    let owned: Vec<String> = (1..=MAX_LOCAL_CANDIDATES)
        .map(|i| format!("10.0.{}.{}:51820", i / 256, i % 256))
        .collect();
    let refs: Vec<&str> = owned.iter().map(String::as_str).collect();

    a.report(0, &refs)
        .await
        .expect("a report exactly at the cap must succeed");

    let stored: BTreeSet<String> = stored_local_candidates(&h, a.id())
        .await
        .into_iter()
        .collect();
    let submitted: BTreeSet<String> = owned.iter().cloned().collect();
    assert_eq!(
        stored, submitted,
        "the cap is a ceiling, not a target: a gateway reporting exactly \
         {MAX_LOCAL_CANDIDATES} valid addresses must keep every one of them. A cap that \
         also trims legitimate at-limit input would silently drop a real candidate and \
         cost that gateway a direct path it could have had."
    );
}

#[tokio::test]
async fn a_local_endpoint_list_over_the_cap_is_bounded() {
    let h = wiremesh_testkit::TestController::start().await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;

    let over = MAX_LOCAL_CANDIDATES + 1;
    let owned: Vec<String> = (1..=over)
        .map(|i| format!("10.0.{}.{}:51820", i / 256, i % 256))
        .collect();
    let refs: Vec<&str> = owned.iter().map(String::as_str).collect();

    a.report(0, &refs).await.expect(
        "an oversized report must be BOUNDED, not rejected — same filter-with-a-log \
         posture as a malformed element.",
    );

    let stored = stored_local_candidates(&h, a.id()).await;
    assert_eq!(
        stored.len(),
        MAX_LOCAL_CANDIDATES,
        "one authenticated gateway must not be able to choose how much work the \
         controller and every one of its peers do. Today the ONLY ceiling on \
         `local_endpoints` is tonic's default 4MB request limit — about 200k strings — \
         each of which is persisted, re-advertised to every peer in every snapshot and \
         delta, and run through `Db::candidates_for`'s O(n^2) `Vec::contains` dedup. \
         Reported {over}, expected at most {MAX_LOCAL_CANDIDATES}, stored {}.",
        stored.len()
    );

    // Deliberately does NOT pin WHICH subset survives: truncating the reported
    // order and truncating after the sort are both defensible, and this suite
    // must not smuggle that choice in. What it does pin is that nothing was
    // invented — every stored entry is one the gateway actually reported.
    let submitted: BTreeSet<&String> = owned.iter().collect();
    for s in &stored {
        assert!(
            submitted.contains(s),
            "stored candidate {s:?} was never reported by the gateway — the cap must \
             DROP entries, never synthesize or rewrite them"
        );
    }
}

#[tokio::test]
async fn an_oversized_report_of_mixed_validity_keeps_only_valid_endpoints_within_the_cap() {
    let h = wiremesh_testkit::TestController::start().await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;

    // Interleave garbage with valid addresses and exceed the cap: the two
    // defenses must COMPOSE. In particular the cap must not be applied first
    // and then leave malformed survivors — a cap that admits one bad string
    // is not a fix, it is the same crash with a smaller list.
    let mut owned: Vec<String> = Vec::new();
    for i in 1..=(MAX_LOCAL_CANDIDATES * 2) {
        owned.push(format!("!!!garbage-{i}"));
        owned.push(format!("10.0.{}.{}:51820", i / 256, i % 256));
    }
    let refs: Vec<&str> = owned.iter().map(String::as_str).collect();

    a.report(0, &refs)
        .await
        .expect("a mixed oversized report must still succeed");

    let stored = stored_local_candidates(&h, a.id()).await;
    assert!(
        stored.len() <= MAX_LOCAL_CANDIDATES,
        "the cap must hold even when the list is mostly garbage: reported {} entries, \
         stored {}",
        owned.len(),
        stored.len()
    );
    for s in &stored {
        assert!(
            s.parse::<std::net::SocketAddr>().is_ok_and(|a| a.is_ipv4()),
            "stored candidate {s:?} is not an IPv4 socket address. The cap and the \
             element filter must COMPOSE — bounding the list while letting one malformed \
             string through is the same process-killing bug with a shorter list."
        );
    }
    assert!(
        !stored.is_empty(),
        "the valid addresses in a mixed oversized report must not all be discarded — \
         filtering is per-element, and a gateway must keep the candidates it got right"
    );
}
