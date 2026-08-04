//! T5 pin — per-peer observability metrics (mesh-convergence fix cycle,
//! plan `docs/superpowers/plans/2026-07-28-mesh-convergence-fixes.md`,
//! evidence `docs/research/ops-finding-multi-gateway-convergence.md` §6:
//! every diagnosis in the incident required UAPI spelunking via debug
//! containers because the gateway exposes no per-peer rx/tx/handshake
//! metrics).
//!
//! TDD: this file is authored AHEAD of the implementation and is EXPECTED
//! to fail to compile until T5 lands. Target API for the implementer,
//! following `metrics.rs`'s existing pure-render idiom
//! (`render_path_state(&[(String, PathState)])`):
//!
//!     // metrics.rs
//!     pub struct PeerStats {
//!         pub rx_bytes: u64,
//!         pub tx_bytes: u64,
//!         /// None for a peer that has never handshaked — the age line is
//!         /// then OMITTED (mirroring `uapi::handshake_times_from`'s
//!         /// epoch-ambiguity rule: absence, not a bogus huge/zero age).
//!         pub last_handshake_age_secs: Option<u64>,
//!     }
//!     pub fn render_peer_stats(peers: &[(String, PeerStats)]) -> String
//!
//! and the `serve_metrics` fetch tuple grows by one element (the same
//! natural extension Cycle 4b used for path-state):
//!
//!     (backend_kind, applied_policy_version, counters, peer_states,
//!      transition_counts, peer_stats: Vec<(String, PeerStats)>)
//!
//! with `render_peer_stats`'s output appended to the scrape body.
//!
//! Notes for the implementer:
//!  - The peer label is the gateway id rendered as a string — the same
//!    label `wiremesh_gateway_path_state{peer="..."}` already uses
//!    (`gid.to_string()` in `main.rs::run_path_ticks`), so the two metric
//!    families join on the label.
//!  - Plan T5: the values are "sourced from the same UAPI fetch the path
//!    SM uses" — `uapi::get_peer_liveness` / `PeerGetInfo` currently parse
//!    only `last_handshake_time_{sec,nsec}` and `rx_bytes`; `tx_bytes` is
//!    in the same `get=1` response (see `uapi.rs`'s
//!    `GET_RESPONSE_FIXTURE`) and needs to be parsed too. That parser is
//!    `pub(crate)`, so its tx pin belongs in `uapi.rs`'s own test module
//!    (implementer: extend `parse_get_response_extracts_both_peers`).
//!  - The existing unit test
//!    `metrics.rs::tests::serve_metrics_responds_with_rendered_body_over_tcp`
//!    constructs the 5-element fetch tuple and will need the mechanical
//!    +1-element update when the tuple grows (expected churn).

use std::collections::BTreeMap;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wiremesh_enforcer::Counters;
use wiremesh_gateway::metrics::{render_peer_stats, serve_metrics, PeerStats};
use wiremesh_gateway::path::PathState;

/// T5: the pure renderer emits all three per-peer gauges with TYPE
/// headers, one line per peer, labeled by peer id.
#[test]
fn t5_render_peer_stats_emits_per_peer_gauges() {
    let out = render_peer_stats(&[
        (
            "5".to_string(),
            // The incident's diagnostic shape: FI's peer showed handshake
            // "28s ago" with rx frozen — exactly what these gauges exist
            // to make visible without a debug container.
            PeerStats { rx_bytes: 12345, tx_bytes: 6789, last_handshake_age_secs: Some(28) },
        ),
        (
            "6".to_string(),
            PeerStats { rx_bytes: 0, tx_bytes: 0, last_handshake_age_secs: None },
        ),
    ]);

    assert!(out.contains("# TYPE wiremesh_gateway_peer_rx_bytes gauge"), "body: {out}");
    assert!(out.contains("# TYPE wiremesh_gateway_peer_tx_bytes gauge"), "body: {out}");
    assert!(
        out.contains("# TYPE wiremesh_gateway_peer_last_handshake_age_seconds gauge"),
        "body: {out}"
    );

    assert!(out.contains("wiremesh_gateway_peer_rx_bytes{peer=\"5\"} 12345"), "body: {out}");
    assert!(out.contains("wiremesh_gateway_peer_tx_bytes{peer=\"5\"} 6789"), "body: {out}");
    assert!(
        out.contains("wiremesh_gateway_peer_last_handshake_age_seconds{peer=\"5\"} 28"),
        "body: {out}"
    );

    // A zero-traffic peer still gets explicit rx/tx lines (0 is the
    // interesting diagnostic value — finding §4's "rx stayed 0").
    assert!(out.contains("wiremesh_gateway_peer_rx_bytes{peer=\"6\"} 0"), "body: {out}");
    assert!(out.contains("wiremesh_gateway_peer_tx_bytes{peer=\"6\"} 0"), "body: {out}");
}

/// T5: a never-handshaked peer's age line is OMITTED rather than rendered
/// as 0 or some epoch-derived huge number — absence is the codebase's
/// established way to say "no handshake yet" (`uapi::handshake_times_from`),
/// and an explicit 0 would be indistinguishable from "handshaked just now".
#[test]
fn t5_render_peer_stats_omits_age_for_never_handshaked_peer() {
    let out = render_peer_stats(&[(
        "6".to_string(),
        PeerStats { rx_bytes: 0, tx_bytes: 0, last_handshake_age_secs: None },
    )]);
    assert!(
        !out.contains("wiremesh_gateway_peer_last_handshake_age_seconds{peer=\"6\"}"),
        "never-handshaked peer must have NO age line (absence, not 0): {out}"
    );
}

/// T5: the gauges must reach the actual HTTP scrape body, not just exist
/// as a separately-tested pure renderer — the same wiring failure mode the
/// existing `serve_metrics_responds_with_rendered_body_over_tcp` unit test
/// guards for path-state. Target: the fetch tuple grows a sixth element,
/// `Vec<(String, PeerStats)>`, rendered via `render_peer_stats`.
#[tokio::test]
async fn t5_serve_metrics_scrape_includes_per_peer_gauges() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve_metrics(listener, || async {
        let counters =
            Counters { by_rule: BTreeMap::from([("r9".to_string(), 2u64)]), default_deny: 1 };
        let peer_states = vec![("5".to_string(), PathState::Direct)];
        let transitions = vec![((PathState::Connecting, PathState::Direct), 3u64)];
        let peer_stats = vec![
            (
                "5".to_string(),
                PeerStats { rx_bytes: 12345, tx_bytes: 6789, last_handshake_age_secs: Some(28) },
            ),
            (
                "6".to_string(),
                PeerStats { rx_bytes: 0, tx_bytes: 0, last_handshake_age_secs: None },
            ),
        ];
        // Trailing `0u64`: mechanical +1 tuple element (Backlog item 1's
        // policy-apply failure counter). Its own scrape assertion lives in
        // `tests/policy_apply_liveness.rs`; nothing here changes.
        Ok::<_, anyhow::Error>((
            "ebpf".to_string(),
            9u64,
            counters,
            peer_states,
            transitions,
            peer_stats,
            0u64,
        ))
    }));

    let mut stream =
        tokio::net::TcpStream::connect(addr).await.expect("connect to metrics listener");
    stream.write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf);

    // Pre-existing families still present (non-regression).
    assert!(text.contains("wiremesh_gateway_applied_policy_version 9"), "body: {text}");
    assert!(
        text.contains("wiremesh_gateway_path_state{peer=\"5\",state=\"direct\"} 1"),
        "body: {text}"
    );

    // The new per-peer gauges reach the scrape body.
    assert!(
        text.contains("wiremesh_gateway_peer_rx_bytes{peer=\"5\"} 12345"),
        "per-peer rx gauge must reach the scrape body: {text}"
    );
    assert!(
        text.contains("wiremesh_gateway_peer_tx_bytes{peer=\"5\"} 6789"),
        "per-peer tx gauge must reach the scrape body: {text}"
    );
    assert!(
        text.contains("wiremesh_gateway_peer_last_handshake_age_seconds{peer=\"5\"} 28"),
        "per-peer handshake-age gauge must reach the scrape body: {text}"
    );
    assert!(
        text.contains("wiremesh_gateway_peer_rx_bytes{peer=\"6\"} 0"),
        "zero-traffic peer's rx gauge must still be emitted: {text}"
    );
}
