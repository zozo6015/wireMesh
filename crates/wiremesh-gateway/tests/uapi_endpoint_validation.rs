//! (Backlog item 1, part D/E) Direct characterization of
//! `uapi::validate_ipv4_endpoint` — the accept/reject predicate the whole
//! candidate-validation fix is defined against — and of `encode_set`'s
//! all-or-nothing failure mode.
//!
//! # Why this file exists
//!
//! `validate_ipv4_endpoint` had NO direct test of any kind. `uapi.rs`'s own
//! `mod tests` covers only the READ side (`parse_get_response`) and the
//! happy-path `encode_set` rendering; nothing pinned which strings it
//! accepts. That is a gap out of proportion to the function's blast radius:
//! its `Err` propagates through `push_peer_block` -> `encode_set` ->
//! `apply_state`'s `uapi::encode_set(&dev).context(..)?`, unwinds out of
//! `async fn run(cfg)` past both loops, and terminates the process from
//! `main`'s `rt.block_on(run(cfg))`. It is a validator that can kill the
//! gateway, and the controller-side and ingest-side filters being added for
//! backlog item 1 are only correct insofar as they agree with it.
//!
//! Pinning it therefore does two jobs: it stops the predicate drifting
//! silently, and it gives the new filters a written definition of "usable"
//! to be checked against. If a future change loosens or tightens this
//! function without updating the filters, the two disagree — and a filter
//! that is LOOSER than this predicate is a live crash-loop path.
//!
//! # Status: green by design
//!
//! These are CHARACTERIZATION tests of behaviour that already exists. They
//! pass against the current tree and are expected to. They are not part of
//! the RED set for backlog item 1; they are the reference the RED tests in
//! `tests/candidate_ingest_validation.rs` and
//! `wiremesh-controller/tests/report_local_endpoints_validation.rs` are
//! written against.
//!
//! `validate_ipv4_endpoint` is private to `uapi`, so it is exercised through
//! the public `encode_set`/`encode_add_peers` — which is the honest boundary
//! anyway, since that is the path on which its error becomes fatal.

use wiremesh_gateway::uapi::{encode_add_peers, encode_set, DeviceConfig, PeerConfig};

const PRIV_B64: &str = "ERERERERERERERERERERERERERERERERERERERERERE=";
const PUB_B64: &str = "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=";
const PUB_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const PUB2_B64: &str = "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=";

fn peer(pubkey_b64: &str, endpoint: Option<&str>) -> PeerConfig {
    PeerConfig {
        public_key_b64: pubkey_b64.to_string(),
        endpoint: endpoint.map(str::to_string),
        allowed_ips: vec!["10.10.2.0/24".into()],
        keepalive_secs: 25,
    }
}

fn device(peers: Vec<PeerConfig>) -> DeviceConfig {
    DeviceConfig { private_key_b64: PRIV_B64.to_string(), listen_port: 51820, peers }
}

/// Endpoints that MUST encode. The predicate is exactly "parses as
/// `std::net::SocketAddr::V4`", deliberately nothing narrower — port 1 and
/// port 65535 are as legitimate as 51820, and a public address is as
/// legitimate as an RFC1918 one. Any filter added upstream that is stricter
/// than this strands a correctly-addressed gateway with no candidates.
const ACCEPTED: &[&str] = &[
    "203.0.113.5:51820",
    "10.0.0.1:1",
    "192.168.1.7:65535",
    "172.16.4.4:51821",
    "0.0.0.0:0",
    "255.255.255.255:65535",
];

/// Endpoints that MUST NOT encode, each with the reason it is dangerous
/// rather than merely wrong. Any filter added upstream that is LOOSER than
/// this list — i.e. that lets one of these through — is a live crash-loop
/// path, because reaching here means the process dies.
const REJECTED: &[(&str, &str)] = &[
    ("", "empty string: sorts before every real address, so it wins candidates[0]"),
    ("not-an-endpoint", "unstructured garbage"),
    (
        "abc:123",
        "a DNS name with a port — the trap: it survives \
         `reconcile::pending_peer_configs`' `rsplit_once(':')` + `u16::parse` half-check, \
         the only shape check anywhere else on this path, and dies HERE where the error \
         is fatal. v1 dial targets are IPv4 literals; nothing resolves names at this \
         layer",
    ),
    ("controller.example.com:51820", "the plausible-hostname form of the same trap"),
    ("10.0.0.5", "no port — the UAPI `endpoint=` line requires ip:port"),
    ("10.0.0.5:", "empty port"),
    (":51820", "no address"),
    ("10.0.0.5:70000", "port above u16 range"),
    ("10.0.0.5:-1", "negative port"),
    ("999.1.1.1:51820", "out-of-range octet: dotted-quad SHAPE is not enough"),
    ("10.0.0.5.6:51820", "five octets"),
    (" 10.0.0.5:51820", "leading whitespace — `SocketAddr`'s FromStr does not trim"),
    ("10.0.0.5:51820 ", "trailing whitespace, same reason"),
    (
        "[::1]:51820",
        "bracketed IPv6: parses as SocketAddr::V6 and is a HARD error here — v1 is \
         IPv4-only end to end (spec §1), matching `config.rs`'s IPv6-reject-at-boot",
    ),
    ("[2001:db8::1]:51820", "a routable IPv6 literal, same rejection"),
    ("[fe80::1%eth0]:51820", "link-local IPv6 with a zone index"),
    (
        "10.0.0.5:51820\nendpoint=1.2.3.4:1",
        "UAPI line injection: the wire protocol is newline-delimited key=value lines, so \
         an accepted endpoint carrying a newline would let the string author add \
         arbitrary UAPI directives to the boringtun `set` message",
    ),
];

#[test]
fn encode_set_accepts_every_ipv4_socket_address_form() {
    for ep in ACCEPTED {
        let out = encode_set(&device(vec![peer(PUB_B64, Some(ep))])).unwrap_or_else(|e| {
            panic!(
                "{ep:?} is a valid IPv4 socket address and MUST encode. The accept \
                 predicate must stay exactly `parses as SocketAddr::V4` — anything \
                 narrower (a port range, a private-address rule) silently strands a \
                 legitimately-addressed gateway, and every upstream candidate filter is \
                 defined against this predicate. Got: {e:#}"
            )
        });
        assert!(
            out.contains(&format!("endpoint={ep}\n")),
            "{ep:?} must be written to the UAPI verbatim, got:\n{out}"
        );
    }
}

#[test]
fn encode_set_rejects_every_non_ipv4_socket_address_form() {
    for (ep, why) in REJECTED {
        let result = encode_set(&device(vec![peer(PUB_B64, Some(ep))]));
        assert!(
            result.is_err(),
            "{ep:?} must be REJECTED — {why}. This predicate is the definition of \
             \"usable endpoint\" that the controller-ingress filter and the \
             `PeerState` ingest filter are both written against; a filter that admits \
             something this function rejects is a live crash-loop path, because reaching \
             here is fatal: the `Err` propagates through `push_peer_block` -> \
             `encode_set` -> `apply_state` and unwinds out of `run()` to `main`, ending \
             the process. Got Ok: {:?}",
            result.ok()
        );
    }
}

#[test]
fn encode_add_peers_applies_the_same_predicate() {
    // The incremental make-before-break add path shares `push_peer_block`, so
    // it must not be a hole: a peer added incrementally with a malformed
    // endpoint must fail the encode rather than reach the device.
    for (ep, why) in REJECTED {
        assert!(
            encode_add_peers(&[peer(PUB_B64, Some(ep))]).is_err(),
            "the incremental add path must reject {ep:?} exactly as the full encode does \
             — {why}. Two encoders with different opinions about what is dialable would \
             mean a candidate that is safe on one apply path and fatal on the other."
        );
    }
    assert!(
        encode_add_peers(&[peer(PUB_B64, Some("10.0.0.5:51820"))]).is_ok(),
        "and it must still accept a valid endpoint"
    );
}

#[test]
fn a_peer_with_no_endpoint_encodes_fine() {
    // Load-bearing for the ingest filters: once an unusable candidate is
    // dropped, a peer may legitimately have NO endpoint. That must be a
    // normal, encodable configuration — otherwise "filter the bad candidate"
    // just relocates the crash.
    let out = encode_set(&device(vec![peer(PUB_B64, None)]))
        .expect("a peer with no endpoint must encode: WireGuard peers without `endpoint=` \
                 are legal and are the correct resting state for a peer this gateway \
                 cannot dial yet");
    assert!(out.contains(&format!("public_key={PUB_HEX}\n")), "peer must be present:\n{out}");
    assert!(!out.contains("endpoint="), "no endpoint line may be emitted:\n{out}");
}

/// (Part E) **Today's behaviour, pinned as-is — the fail-open/fail-closed
/// question is OPEN.**
///
/// `encode_set` is all-or-nothing: ONE peer with an unusable endpoint fails
/// the encode for the WHOLE device, and `apply_state` treats that `Err` as
/// fatal. So a single malformed advertisement about a single peer terminates
/// the gateway for every peer it has.
///
/// Whether `encode_set` should instead SKIP the malformed peer (fail-open,
/// keeping the rest of the device applicable) or keep failing hard
/// (fail-closed, refusing to write a device that does not match the desired
/// state) is a real design decision that backlog item 1 does not settle, and
/// this suite deliberately does not decide it. The item-1 fix makes the
/// question moot for the two known routes — Sync ingest and `state.json` —
/// by ensuring an unusable endpoint never reaches a `PeerConfig` in the first
/// place. This test exists so that if someone later changes `encode_set`'s
/// blast radius, they do it on purpose and this assertion is where they say
/// so.
#[test]
fn one_malformed_peer_fails_the_whole_device_encode_today() {
    let dev = device(vec![
        peer(PUB_B64, Some("10.0.0.9:51820")),
        peer(PUB2_B64, Some("abc:123")),
    ]);
    let result = encode_set(&dev);
    assert!(
        result.is_err(),
        "CHARACTERIZATION, not a preference: `encode_set` is all-or-nothing today, so \
         one peer's unusable endpoint fails the encode for the healthy peer too — and \
         `apply_state` treats that Err as fatal to the process. Backlog item 1 removes \
         the ways an unusable endpoint can GET here rather than changing this; whether \
         this should become a per-peer skip is still open. If you are changing this \
         assertion, you are making that decision — record it. Got Ok: {:?}",
        result.ok()
    );
}
