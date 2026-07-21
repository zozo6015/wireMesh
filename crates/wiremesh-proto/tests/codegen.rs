#![allow(deprecated)] // constructing StateSnapshot/Delta requires setting deprecated_relays (field 4)
use prost::Message;
use wiremesh_proto::v1::{
    StateSnapshot, Peer, sync_message::Body, SyncMessage, PunchDirective, ReportRequest,
    RelayInfo, RelayHealth, Delta, EnrollRequest,
};

#[test]
fn snapshot_message_roundtrips() {
    let snap = StateSnapshot { revision: 7, self_cert_pem: "PEM".into(),
        peers: vec![Peer { gateway_id: 2, segment_name: "aws".into(), ..Default::default() }],
        deprecated_relays: vec![],
        relay_infos: vec![RelayInfo { relay_id: 7, endpoint: "r1:4443".into() }], policy_ir: vec![], policy_version: 0,
        revoked_serials: vec![] };
    let msg = SyncMessage { body: Some(Body::Snapshot(snap.clone())) };

    // A GENUINE wire roundtrip: encode to protobuf bytes and decode them
    // back, rather than just re-matching the same in-memory struct the
    // `msg` above already wraps (which would prove nothing about the
    // generated codec). This is what actually exercises `build.rs`'s
    // codegen.
    let bytes = msg.encode_to_vec();
    let decoded = SyncMessage::decode(bytes.as_slice()).expect("decoding the encoded SyncMessage");

    // Assert against `decoded` — the value that actually survived the
    // encode/decode roundtrip — not `snap`/`msg`, which never left memory.
    match decoded.body {
        Some(Body::Snapshot(s)) => {
            assert_eq!(s.revision, 7);
            assert_eq!(s.peers[0].gateway_id, 2);
            assert_eq!(s.peers[0].segment_name, "aws");
            assert_eq!(s.self_cert_pem, "PEM");
            assert_eq!(s.relay_infos[0].relay_id, 7);
            assert_eq!(s.relay_infos[0].endpoint, "r1:4443");
            assert!(s.deprecated_relays.is_empty());
        }
        other => panic!("wrong body: {other:?}"),
    }
}

#[test]
fn punch_directive_message_roundtrips() {
    let punch = PunchDirective {
        peer_gateway_id: 7,
        candidates: vec!["198.51.100.2:51820".into()],
        go_unix_ms: 123,
    };
    let msg = SyncMessage { body: Some(Body::Punch(punch.clone())) };

    // Genuine wire roundtrip (see rationale in snapshot_message_roundtrips
    // above): encode to protobuf bytes, decode them back, and assert
    // against the decoded value.
    let bytes = msg.encode_to_vec();
    let decoded = SyncMessage::decode(bytes.as_slice()).expect("decoding the encoded SyncMessage");

    match decoded.body {
        Some(Body::Punch(p)) => assert_eq!(p, punch),
        other => panic!("wrong body: {other:?}"),
    }
}

#[test]
fn report_request_local_endpoints_roundtrips() {
    let with_endpoints = ReportRequest {
        applied_version: 5,
        local_endpoints: vec!["10.0.0.5:51820".into()],
        relay_health: vec![],
    };
    let bytes = with_endpoints.encode_to_vec();
    let decoded = ReportRequest::decode(bytes.as_slice()).expect("decoding the encoded ReportRequest");
    assert_eq!(decoded, with_endpoints);

    // Empty local_endpoints must still roundtrip cleanly (old-client behavior,
    // pre-dating this additive field).
    let no_endpoints = ReportRequest { applied_version: 5, local_endpoints: vec![], relay_health: vec![] };
    let bytes = no_endpoints.encode_to_vec();
    let decoded = ReportRequest::decode(bytes.as_slice()).expect("decoding the encoded ReportRequest");
    assert_eq!(decoded, no_endpoints);
}

#[test]
fn state_snapshot_relay_infos_roundtrips_multiple_relay_infos() {
    // (4c review fix) The structured relay data lives in `relay_infos`
    // (field 8, `repeated RelayInfo`) — a NEW field, added rather than
    // repurposing field 4 (`deprecated_relays`, kept at its ORIGINAL
    // `repeated string` type; see `sync.proto`'s doc comment on that field
    // for why changing an existing field's wire type is a hazard). Confirm
    // two distinct relays, each with both fields set, survive a genuine
    // wire roundtrip in the new field, and that the deprecated field still
    // roundtrips cleanly as an empty (unused) `repeated string`.
    let snap = StateSnapshot {
        revision: 11,
        self_cert_pem: "PEM".into(),
        peers: vec![],
        deprecated_relays: vec![],
        relay_infos: vec![
            RelayInfo { relay_id: 1, endpoint: "relay-a.example:4443".into() },
            RelayInfo { relay_id: 2, endpoint: "relay-b.example:4443".into() },
        ],
        policy_ir: vec![],
        policy_version: 0,
        revoked_serials: vec![],
    };

    let bytes = snap.encode_to_vec();
    let decoded = StateSnapshot::decode(bytes.as_slice()).expect("decoding the encoded StateSnapshot");

    assert_eq!(decoded.relay_infos.len(), 2);
    assert_eq!(decoded.relay_infos[0].relay_id, 1);
    assert_eq!(decoded.relay_infos[0].endpoint, "relay-a.example:4443");
    assert_eq!(decoded.relay_infos[1].relay_id, 2);
    assert_eq!(decoded.relay_infos[1].endpoint, "relay-b.example:4443");
    assert!(
        decoded.deprecated_relays.is_empty(),
        "deprecated_relays (field 4, legacy repeated string) must still roundtrip as empty \
         when unused"
    );
}

#[test]
fn delta_relay_infos_roundtrips_relay_info() {
    // See `state_snapshot_relay_infos_roundtrips_multiple_relay_infos` above
    // — `Delta` gets the identical field-8 treatment as `StateSnapshot`.
    let delta = Delta {
        revision: 12,
        upserted_peers: vec![],
        removed_peer_ids: vec![],
        deprecated_relays: vec![],
        relay_infos: vec![RelayInfo { relay_id: 3, endpoint: "relay-c.example:4443".into() }],
        policy_ir: vec![],
        policy_version: 0,
        revoked_serials: vec![],
    };

    let bytes = delta.encode_to_vec();
    let decoded = Delta::decode(bytes.as_slice()).expect("decoding the encoded Delta");

    assert_eq!(decoded.relay_infos.len(), 1);
    assert_eq!(decoded.relay_infos[0].relay_id, 3);
    assert_eq!(decoded.relay_infos[0].endpoint, "relay-c.example:4443");
    assert!(decoded.deprecated_relays.is_empty());
}

#[test]
fn report_request_relay_health_roundtrips() {
    // ReportRequest gains `repeated RelayHealth relay_health = 3;` (4c Task
    // 1) so gateways can tell the controller which relays they can
    // currently reach — one healthy, one not, to prove `healthy` isn't just
    // defaulting true.
    let report = ReportRequest {
        applied_version: 9,
        local_endpoints: vec!["10.0.0.5:51820".into()],
        relay_health: vec![
            RelayHealth { relay_id: 1, healthy: true },
            RelayHealth { relay_id: 2, healthy: false },
        ],
    };

    let bytes = report.encode_to_vec();
    let decoded = ReportRequest::decode(bytes.as_slice()).expect("decoding the encoded ReportRequest");

    assert_eq!(decoded.relay_health.len(), 2);
    assert_eq!(decoded.relay_health[0].relay_id, 1);
    assert_eq!(decoded.relay_health[0].healthy, true);
    assert_eq!(decoded.relay_health[1].relay_id, 2);
    assert_eq!(decoded.relay_health[1].healthy, false);
}

#[test]
fn enroll_request_endpoint_roundtrips() {
    // EnrollRequest gains `string endpoint = 5;` (4c Task 1) so a gateway
    // can advertise a routable endpoint at enrollment time. Non-empty value
    // survives a genuine wire roundtrip.
    let with_endpoint = EnrollRequest {
        token: "tok".into(),
        csr_pem: "CSR".into(),
        cidrs: vec!["10.1.0.0/24".into()],
        wg_pubkey: "wgpubkey==".into(),
        endpoint: "203.0.113.9:51820".into(),
    };
    let bytes = with_endpoint.encode_to_vec();
    let decoded = EnrollRequest::decode(bytes.as_slice()).expect("decoding the encoded EnrollRequest");
    assert_eq!(decoded.endpoint, "203.0.113.9:51820");
    assert_eq!(decoded.token, "tok");
    assert_eq!(decoded.csr_pem, "CSR");
    assert_eq!(decoded.cidrs, vec!["10.1.0.0/24".to_string()]);
    assert_eq!(decoded.wg_pubkey, "wgpubkey==");

    // A default (empty-string) endpoint must still decode cleanly — this is
    // an additive field, so old-client requests that never set it must not
    // break.
    let no_endpoint = EnrollRequest {
        token: "tok".into(),
        csr_pem: "CSR".into(),
        cidrs: vec![],
        wg_pubkey: "wgpubkey==".into(),
        endpoint: String::new(),
    };
    let bytes = no_endpoint.encode_to_vec();
    let decoded = EnrollRequest::decode(bytes.as_slice()).expect("decoding the encoded EnrollRequest");
    assert_eq!(decoded.endpoint, "");
}
